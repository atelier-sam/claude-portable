//! `remote share` : le chemin INVERSE. Le PC (Windows) s'ouvre aux agents du Mac,
//! le temps que la fenêtre reste ouverte, sans rien installer durablement.
//! NON ÉPROUVÉ SUR WINDOWS (aucune machine de test) : voir le rapport de phase 4.
//!
//! Déroulé (PLAN, correction 6) :
//! 1. consentement explicite (texte affiché, « OUI » à taper) ;
//! 2. OpenSSH portable (Win32-OpenSSH) : le ZIP épinglé est gardé dans `tools/openssh/`
//!    et son SHA-256 est revérifié à CHAQUE usage ; on n'exécute jamais un dossier
//!    extrait qui resterait sur le portable (sshd tourne ÉLEVÉ : un fichier déposé là
//!    entre deux usages serait exécuté avec les droits d'administrateur) ;
//! 3. dossier de travail PRIVÉ `%TEMP%\ccp-share-<id>` (ACL explicite : utilisateur
//!    courant et SYSTEM seulement) : binaires OpenSSH extraits À CHAQUE usage des octets
//!    vérifiés, clé d'hôte ÉPHÉMÈRE, `sshd_config` temporaire (127.0.0.1, port libre, clés
//!    seules, `AllowUsers` = l'utilisateur courant), `authorized_keys` temporaire. Au
//!    démarrage, les `ccp-share-*` ORPHELINS d'un partage tué net sont effacés ;
//! 4. UNE connexion ssh vers le Mac (donc un seul mot de passe) qui porte `-R 0:127.0.0.1:<port>`
//!    et un script distant : il rend la clé publique des agents, attend la ligne de
//!    description du PC (avec le port alloué lu dans « Allocated port »), l'écrit dans
//!    `~/.ccp-portable/clients/<pc>.json` et la RETIRE quand la connexion tombe ;
//! 5. sshd est lancé au premier plan APRÈS réception de la clé publique ;
//! 6. sshd et ssh vivent dans un Job Object « kill-on-close » ; Ctrl+C, fermeture de la
//!    fenêtre ou mort de ccp-core : tout disparaît (fichier client côté Mac compris, par
//!    le `trap` du script distant), le dossier de travail est effacé ET l'effacement
//!    est VÉRIFIÉ : « tout a été retiré » n'est dit que si c'est vrai ;
//! 7. journal `<racine>/logs/share-<date>.log` (événements + journal de sshd).

use super::conf::Target;
use super::connect::{self, Common, Deps, Prepared};
use super::download::{extract_zip_bytes, fetch_verified};
use super::intr;
use super::net::Fetch;
use super::pins::{Asset, OPENSSH_WIN};
use super::quote::{sh_quote, ssh_path_value, Style};
use crate::env::Env;
use crate::error::{CcpError, Result};
use crate::privdir::{self, PrivateDir};
use crate::root::Root;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Texte du consentement : affiché tel quel, jamais abrégé.
pub fn consent_text(user: &str, pc: &str) -> String {
    format!(
        "PARTAGER CE PC AVEC LES AGENTS DU MAC\n\
         \n\
         Tant que cette fenêtre reste ouverte, les agents du Mac de Sam pourront EXÉCUTER DES\n\
         COMMANDES sur ce PC ({pc}), avec les droits de l'utilisateur « {user} » : lire, modifier\n\
         et effacer ses fichiers, lancer des programmes.\n\
         \n\
         - rien n'est installé durablement : serveur SSH portable, clé d'hôte éphémère, aucun\n\
           service Windows, aucune règle de pare-feu ;\n\
         - le serveur n'écoute que sur ce PC (127.0.0.1) ; l'accès passe par la connexion\n\
           ouverte vers le Mac, par clé uniquement ;\n\
         - Ctrl+C, ou la fermeture de la fenêtre, retire tout aussitôt ;\n\
         - un journal de la session est écrit dans le dossier logs du portable.\n"
    )
}

/// Seul « OUI » (en majuscules, tapé en entier) vaut consentement.
pub fn is_consent(answer: &str) -> bool {
    answer.trim() == "OUI"
}

/// Nom du PC sous forme sûre pour un nom de fichier du Mac : `[A-Za-z0-9._-]`, 40 caractères.
pub fn sanitize_pc_name(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(40)
        .collect();
    let s = s.trim_matches(['.', '-']).to_string();
    if s.is_empty() {
        "pc".to_string()
    } else {
        s
    }
}

/// `Allocated port 54123 for remote forward to 127.0.0.1:2222` (stderr de ssh).
pub fn parse_allocated_port(line: &str) -> Option<u16> {
    let rest = line.split("Allocated port ").nth(1)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let p: u16 = digits.parse().ok()?;
    (p != 0).then_some(p)
}

/// La clé publique des agents lue sur le Mac, sous forme stricte : une ligne
/// `ssh-ed25519 <base64> [commentaire]`, sans option ni caractère de contrôle. Un Mac
/// (ou un MITM) ne peut ainsi pas faire écrire `command="…"` dans l'`authorized_keys` du PC.
pub fn validate_agent_pubkey(line: &str) -> Result<String> {
    let line = line.trim();
    let mut f = line.splitn(3, ' ');
    let (ty, blob) = (f.next().unwrap_or(""), f.next().unwrap_or(""));
    let comment = f.next().unwrap_or("");
    let blob_ok = blob.len() >= 40
        && blob.len() <= 200
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    let comment_ok = comment.chars().all(|c| !c.is_control());
    if ty != "ssh-ed25519" || !blob_ok || !comment_ok {
        return Err(CcpError::Internal(
            "la clé publique des agents reçue du Mac n'a pas la forme attendue (ssh-ed25519) : refus".into(),
        ));
    }
    Ok(format!("ssh-ed25519 {blob}"))
}

/// Ligne de `authorized_keys` du PC : la clé des agents, SANS relais de port, d'agent ni d'écran.
pub fn authorized_keys_line(pubkey: &str) -> String {
    format!("no-port-forwarding,no-agent-forwarding,no-X11-forwarding {pubkey}\n")
}

#[derive(Debug, Clone)]
pub struct SshdPaths {
    pub host_key: PathBuf,
    pub authorized_keys: PathBuf,
}

/// `sshd_config` temporaire. Les chemins sont cités comme ssh_config les relit.
pub fn sshd_config(style: Style, port: u16, user: &str, p: &SshdPaths) -> Result<String> {
    if user.is_empty() || user.chars().any(|c| c.is_control() || c == '"') {
        return Err(CcpError::Internal(format!(
            "nom d'utilisateur Windows inutilisable pour AllowUsers : {user:?}"
        )));
    }
    let hk = ssh_path_value(&p.host_key, style)?;
    let ak = ssh_path_value(&p.authorized_keys, style)?;
    Ok(format!(
        "# Généré par ccp-core remote share : supprimé à la fin de la session.\n\
         Port {port}\n\
         ListenAddress 127.0.0.1\n\
         HostKey {hk}\n\
         AuthorizedKeysFile {ak}\n\
         PubkeyAuthentication yes\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         PermitEmptyPasswords no\n\
         AllowUsers \"{user}\"\n\
         AllowTcpForwarding no\n\
         X11Forwarding no\n\
         PermitTunnel no\n\
         MaxAuthTries 3\n\
         LogLevel VERBOSE\n"
    ))
}

/// Description du PC écrite côté Mac dans `~/.ccp-portable/clients/<pc>.json`.
pub fn client_json(pc: &str, user: &str, port: u16, host_key_pub: &str, started: &str) -> String {
    serde_json::json!({
        "schema": 1,
        "pc": pc,
        "windows_user": user,
        "port": port,
        "sshd_host_key": host_key_pub.trim(),
        "started": started,
        "ccp_core": env!("CARGO_PKG_VERSION"),
    })
    .to_string()
}

const PUBKEY_TAG: &str = "CCP-PUBKEY ";
const REGISTERED_TAG: &str = "CCP-REGISTERED";

/// Script exécuté sur le Mac (bash) : `$1` = nom du PC.
fn remote_script() -> String {
    format!(
        r#"umask 077
pub="$HOME/.ssh/ccp_agents_ed25519.pub"
if [ ! -r "$pub" ]; then echo "clé publique des agents introuvable sur le Mac : $pub" >&2; exit 3; fi
dir="$HOME/.ccp-portable/clients"
mkdir -p "$dir" || exit 1
f="$dir/$1.json"
trap 'rm -f "$f" "$f.tmp"' EXIT HUP INT TERM
printf '{PUBKEY_TAG}%s\n' "$(head -n 1 "$pub")"
IFS= read -r info || exit 0
printf '%s\n' "$info" > "$f.tmp" && mv "$f.tmp" "$f" || exit 1
printf '{REGISTERED_TAG}\n'
cat > /dev/null
"#
    )
}

pub fn remote_command(pc: &str) -> String {
    format!(
        "/bin/bash -c {} ccp-share {}",
        sh_quote(&remote_script()),
        sh_quote(pc)
    )
}

pub fn share_args(p: &Prepared, local_port: u16, pc: &str) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = vec!["-T".into()];
    a.extend(p.options.iter().cloned());
    a.extend([
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-R".into(),
        format!("0:127.0.0.1:{local_port}").into(),
        format!("{}@{}", p.target.user, p.target.host).into(),
        remote_command(pc).into(),
    ]);
    a
}

// ------------------------------------------------------------------ OpenSSH portable

#[derive(Debug, Clone)]
pub struct OpenSsh {
    pub sshd: PathBuf,
    pub keygen: PathBuf,
}

fn exe(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn openssh_in(dir: &Path) -> OpenSsh {
    OpenSsh {
        sshd: dir.join(exe("sshd")),
        keygen: dir.join(exe("ssh-keygen")),
    }
}

/// D'où viennent sshd et ssh-keygen de CETTE session.
pub enum OpenSshSource {
    /// Octets du zip épinglé, DÉJÀ vérifiés : extraits dans le dossier de travail privé.
    Archive(Vec<u8>),
    /// Dossier déjà prêt — `CCP_OPENSSH_DIR`, bancs d'essai hors Windows uniquement.
    Existing(OpenSsh),
}

/// Sous-dossier du zip qui contient `sshd.exe` et `ssh-keygen.exe`.
const ZIP_TOP: &str = "OpenSSH-Win64";

/// Le zip épinglé, GARDÉ sur le portable mais relu et revérifié à CHAQUE usage.
///
/// WHY : sshd tourne ÉLEVÉ. Faire confiance à un dossier extrait une fois (marqueur
/// `INSTALLED`) revient à exécuter en administrateur tout ce que quelqu'un a pu
/// déposer sur le portable depuis (clé USB prêtée, autre PC). Ici, rien de ce qui
/// s'exécute ne vient du disque du portable : seuls des octets dont le SHA-256 vient
/// d'être calculé sont extraits — et extraits depuis la MÉMOIRE, sans relecture du
/// fichier, donc sans fenêtre où on pourrait le remplacer.
pub fn load_openssh_zip(
    root: &Root,
    asset: &Asset,
    base: &str,
    fetch: &dyn Fetch,
    say: &mut dyn FnMut(&str),
) -> Result<Vec<u8>> {
    let top = root.path().join("tools").join("openssh").join(asset.tag);
    // Ancienne disposition (dossier extrait persistant + marqueur) : plus jamais
    // exécutée, retirée pour qu'elle ne soit pas prise pour de confiance.
    let _ = fs::remove_file(top.join("INSTALLED"));
    let _ = fs::remove_dir_all(top.join(ZIP_TOP));
    let zip = top.join(asset.name);
    if let Some(bytes) = read_if_pinned(&zip, asset) {
        return Ok(bytes);
    }
    if zip.exists() {
        say("L'archive OpenSSH du portable ne correspond pas à l'empreinte épinglée : elle est remplacée.");
        let _ = fs::remove_file(&zip);
    }
    say(&format!(
        "Téléchargement d'OpenSSH portable {} (vérifié par SHA-256)…",
        asset.tag
    ));
    fetch_verified(fetch, &asset.url(base), &zip, asset.sha256, asset.max_bytes)?;
    read_if_pinned(&zip, asset).ok_or_else(|| {
        CcpError::Internal("l'archive OpenSSH est illisible juste après son téléchargement".into())
    })
}

/// Contenu du fichier si, et seulement si, son SHA-256 est celui de l'épingle.
fn read_if_pinned(path: &Path, asset: &Asset) -> Option<Vec<u8>> {
    let len = fs::metadata(path).ok()?.len();
    if len > asset.max_bytes {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let got = crate::util::hex_encode(&Sha256::digest(&bytes));
    got.eq_ignore_ascii_case(asset.sha256).then_some(bytes)
}

/// Extrait les octets vérifiés dans `<dossier privé>/openssh` et rend les deux outils.
fn extract_openssh(zip_bytes: &[u8], private: &Path) -> Result<OpenSsh> {
    let dest = private.join("openssh");
    extract_zip_bytes(zip_bytes, &dest, 256 << 20)?;
    let found = openssh_in(&dest.join(ZIP_TOP));
    if !found.sshd.is_file() || !found.keygen.is_file() {
        return Err(CcpError::Internal(
            "l'archive OpenSSH ne contient pas sshd / ssh-keygen là où on les attend".into(),
        ));
    }
    Ok(found)
}

// --------------------------------------------------------------- dossier de travail

/// Préfixe des dossiers de travail de `share` (balayé au démarrage s'ils sont orphelins).
pub const STAGING_PREFIX: &str = "ccp-share-";

/// Journal de session : `<racine>/logs/share-<date>.log`, une ligne horodatée par événement.
pub struct Journal {
    file: fs::File,
    pub path: PathBuf,
}

impl Journal {
    pub fn open(root: &Root, stamp: &str) -> Result<Journal> {
        let dir = root.path().join("logs");
        fs::create_dir_all(&dir)
            .map_err(|e| CcpError::Internal(format!("dossier logs impossible à créer : {e}")))?;
        let path = dir.join(format!("share-{stamp}.log"));
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| CcpError::Internal(format!("journal impossible à ouvrir : {e}")))?;
        Ok(Journal { file, path })
    }
    pub fn log(&mut self, msg: &str) {
        let now = jiff::Timestamp::now();
        let _ = writeln!(self.file, "{now} {msg}");
    }
    pub fn clone_file(&self) -> Option<fs::File> {
        self.file.try_clone().ok()
    }
}

fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| CcpError::Internal(format!("aucun port local libre : {e}")))?;
    l.local_addr()
        .map(|a| a.port())
        .map_err(|e| CcpError::Internal(format!("port local illisible : {e}")))
}

/// Lance sshd au premier plan (config temporaire) ; son journal va dans le dossier de travail.
fn start_sshd(
    sshd: &Path,
    config: &Path,
    staging: &Path,
    job: &intr::Job,
) -> Result<(Child, PathBuf)> {
    let log_path = staging.join("sshd.log");
    let log_file = fs::File::create(&log_path)
        .map_err(|e| CcpError::Internal(format!("journal de sshd impossible à créer : {e}")))?;
    let err_file = log_file
        .try_clone()
        .map_err(|e| CcpError::Internal(format!("journal de sshd : {e}")))?;
    let mut child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .map_err(|e| CcpError::Internal(format!("sshd impossible à lancer : {e}")))?;
    if let Err(e) = job.assign(&child) {
        let _ = reap(&mut child);
        return Err(e);
    }
    Ok((child, log_path))
}

// ------------------------------------------------------------------- la session

enum Ev {
    Out(String),
    Err(String),
    SshExited,
}

fn pump<R: std::io::Read + Send + 'static>(
    r: R,
    tx: mpsc::Sender<Ev>,
    wrap: fn(String) -> Ev,
    done: Option<fn() -> Ev>,
) {
    std::thread::spawn(move || {
        for line in BufReader::new(r).lines() {
            let Ok(line) = line else { break };
            if tx.send(wrap(line)).is_err() {
                return;
            }
        }
        if let Some(d) = done {
            let _ = tx.send(d());
        }
    });
}

/// Tue un enfant et attend sa fin (≤ 5 s : un `kill` refusé ne doit pas bloquer
/// éternellement sur `wait`). `Err` = il est peut-être encore en vie.
fn reap(child: &mut Child) -> std::result::Result<(), String> {
    let kill_err = match child.kill() {
        Ok(()) => None,
        // Déjà terminé : rien à tuer.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => None,
        Err(e) => Some(e.to_string()),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                return Err(format!(
                    "toujours en vie après 5 s ({})",
                    kill_err.unwrap_or_else(|| "kill sans effet".into())
                ))
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

pub struct ShareEnv {
    pub temp: PathBuf,
    pub openssh: OpenSshSource,
    pub style: Style,
    pub pc: String,
    pub user: String,
    /// Fin de session demandée par l'appelant (tests) en plus du drapeau global.
    pub stop_after_registered: Option<Duration>,
}

/// Délais : la saisie du mot de passe peut être lente, le reste non.
const T_PUBKEY: Duration = Duration::from_secs(300);
const T_SSHD: Duration = Duration::from_secs(20);
const T_REGISTER: Duration = Duration::from_secs(30);

/// Déroule la session. Renvoie quand elle est finie (Ctrl+C = fin normale, code 0).
pub fn run_session(
    prepared: &Prepared,
    senv: &ShareEnv,
    journal: &mut Journal,
    say: &mut dyn FnMut(&str),
) -> Result<i32> {
    let staging = PrivateDir::create(&senv.temp, STAGING_PREFIX).map_err(|e| {
        CcpError::Internal(format!(
            "dossier de travail privé impossible à créer dans {} : {e}",
            senv.temp.display()
        ))
    })?;
    let job = intr::Job::new_kill_on_close()?;
    // sshd et ssh-keygen : extraits des octets vérifiés, dans le dossier privé, À CHAQUE
    // session. Si la suite échoue, le Drop du dossier privé efface tout.
    let openssh = match &senv.openssh {
        OpenSshSource::Archive(bytes) => extract_openssh(bytes, &staging.path)?,
        OpenSshSource::Existing(o) => o.clone(),
    };
    let host_key = staging.path.join("hostkey");
    let paths = SshdPaths {
        host_key: host_key.clone(),
        authorized_keys: staging.path.join("authorized_keys"),
    };
    let port = free_port()?;

    // Clé d'hôte éphémère.
    let kg = Command::new(&openssh.keygen)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "ccp-share-ephemere",
            "-f",
        ])
        .arg(&host_key)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| CcpError::Internal(format!("ssh-keygen impossible à lancer : {e}")))?;
    if !kg.status.success() {
        return Err(CcpError::Internal(format!(
            "ssh-keygen a échoué : {}",
            String::from_utf8_lossy(&kg.stderr).trim()
        )));
    }
    let host_pub = fs::read_to_string(staging.path.join("hostkey.pub")).unwrap_or_default();
    let config = sshd_config(senv.style, port, &senv.user, &paths)?;
    let config_path = staging.path.join("sshd_config");
    fs::write(&config_path, config)
        .map_err(|e| CcpError::Internal(format!("sshd_config impossible à écrire : {e}")))?;

    // La connexion vers le Mac (un seul mot de passe).
    journal.log("connexion au Mac");
    say("Connexion au Mac… (mot de passe du Mac si demandé)");
    let mut cmd = Command::new(&prepared.ssh);
    cmd.args(share_args(prepared, port, &senv.pc))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    connect::apply_proxy_env(&mut cmd, &prepared.proxy);
    let mut ssh = cmd.spawn().map_err(|e| {
        CcpError::NotFound(format!(
            "client ssh impossible à lancer ({}) : {e}",
            prepared.ssh.to_string_lossy()
        ))
    })?;
    if let Err(e) = job.assign(&ssh) {
        let _ = reap(&mut ssh);
        return Err(e);
    }
    let mut ssh_in = ssh.stdin.take();
    let (tx, rx) = mpsc::channel::<Ev>();
    if let Some(o) = ssh.stdout.take() {
        pump(o, tx.clone(), Ev::Out, None);
    }
    if let Some(e) = ssh.stderr.take() {
        pump(e, tx.clone(), Ev::Err, Some(|| Ev::SshExited));
    }
    drop(tx);

    let mut sshd: Option<Child> = None;
    let mut sshd_log_path: Option<PathBuf> = None;
    let mut remote_port: Option<u16> = None;
    let mut sent_info = false;
    let mut registered = false;
    let mut have_pubkey = false;
    let mut phase_started = Instant::now();
    let mut registered_at: Option<Instant> = None;
    let mut ssh_gone = false;
    let outcome: Result<i32> = loop {
        if intr::is_set() {
            journal.log("interruption demandée");
            break Ok(0);
        }
        if let Some(limit) = senv.stop_after_registered {
            if registered_at.is_some_and(|t| t.elapsed() >= limit) {
                break Ok(0);
            }
        }
        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(Ev::Out(line)) => {
                if let Some(k) = line.strip_prefix(PUBKEY_TAG) {
                    let started = validate_agent_pubkey(k).and_then(|key| {
                        fs::write(&paths.authorized_keys, authorized_keys_line(&key)).map_err(
                            |e| {
                                CcpError::Internal(format!(
                                    "authorized_keys temporaire impossible à écrire : {e}"
                                ))
                            },
                        )?;
                        start_sshd(&openssh.sshd, &config_path, &staging.path, &job)
                    });
                    match started {
                        Ok((child, log_path)) => {
                            have_pubkey = true;
                            phase_started = Instant::now();
                            sshd = Some(child);
                            sshd_log_path = Some(log_path);
                            journal.log(&format!("sshd lancé sur 127.0.0.1:{port}"));
                        }
                        Err(e) => break Err(e),
                    }
                } else if line == REGISTERED_TAG {
                    registered = true;
                    registered_at = Some(Instant::now());
                    journal.log(&format!(
                        "PC enregistré côté Mac (port {})",
                        remote_port.unwrap_or(0)
                    ));
                    say(&format!(
                        "PARTAGE ACTIF : les agents du Mac peuvent atteindre ce PC (port {} sur le Mac).",
                        remote_port.unwrap_or(0)
                    ));
                    say("Ctrl+C, ou fermer cette fenêtre, retire tout.");
                }
            }
            Ok(Ev::Err(line)) => {
                if let Some(p) = parse_allocated_port(&line) {
                    remote_port = Some(p);
                    journal.log(&format!("port alloué sur le Mac : {p}"));
                } else if !line.trim().is_empty() {
                    say(&format!("ssh : {line}"));
                }
            }
            Ok(Ev::SshExited) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                ssh_gone = true;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if ssh_gone {
            if intr::is_set() {
                // Ctrl+C va aussi à ssh (même groupe de processus) : fin normale, pas une panne.
                journal.log("interruption demandée");
                break Ok(0);
            }
            let code = ssh.wait().ok().and_then(|s| s.code()).unwrap_or(255);
            journal.log(&format!("connexion au Mac terminée (code {code})"));
            break if registered {
                Err(CcpError::Network(
                    "la connexion au Mac s'est interrompue : partage arrêté".into(),
                ))
            } else {
                connect::map_exit(code).and(Err(CcpError::Network(
                    "la connexion au Mac s'est terminée avant la mise en place du partage".into(),
                )))
            };
        }
        if let Some(d) = sshd.as_mut() {
            if let Ok(Some(st)) = d.try_wait() {
                let tail = sshd_log_path
                    .as_deref()
                    .and_then(|p| fs::read_to_string(p).ok())
                    .unwrap_or_default();
                let last = tail.lines().last().unwrap_or("").to_string();
                journal.log(&format!("sshd s'est arrêté ({st}) : {last}"));
                break Err(CcpError::Internal(format!(
                    "sshd s'est arrêté ({st}) : {last}"
                )));
            }
        }
        // Dès que le port est alloué ET que sshd écoute : on décrit ce PC au Mac.
        if !sent_info && have_pubkey {
            let listening = sshd_log_path
                .as_deref()
                .and_then(|p| fs::read_to_string(p).ok())
                .is_some_and(|t| t.contains("listening on 127.0.0.1 port"));
            if let (Some(rp), true) = (remote_port, listening) {
                let started = jiff::Timestamp::now().to_string();
                let json = client_json(&senv.pc, &senv.user, rp, &host_pub, &started);
                let Some(si) = ssh_in.as_mut() else {
                    break Err(CcpError::Internal("entrée de ssh fermée trop tôt".into()));
                };
                if let Err(e) = writeln!(si, "{json}").and_then(|_| si.flush()) {
                    break Err(CcpError::Network(format!("envoi au Mac impossible : {e}")));
                }
                sent_info = true;
                phase_started = Instant::now();
            }
        }
        let waited = phase_started.elapsed();
        if !have_pubkey && waited > T_PUBKEY {
            break Err(CcpError::Network(
                "pas de réponse du Mac (clé des agents) après 5 minutes".into(),
            ));
        }
        if have_pubkey && !sent_info && waited > T_SSHD {
            break Err(CcpError::Internal(
                "sshd n'écoute pas ou le port distant n'a pas été alloué après 20 s".into(),
            ));
        }
        if sent_info && !registered && waited > T_REGISTER {
            break Err(CcpError::Network(
                "le Mac n'a pas confirmé l'enregistrement du PC".into(),
            ));
        }
    };

    // Nettoyage — dans cet ordre : fermer l'entrée de ssh (le script distant retire le fichier
    // client), laisser ssh finir, puis tout ce qui reste. Chaque étape qui échoue est
    // CONSIGNÉE : on ne dit « tout a été retiré » que si rien n'est resté.
    let mut problems: Vec<String> = Vec::new();
    drop(ssh_in);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if matches!(ssh.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if let Err(e) = reap(&mut ssh) {
        problems.push(format!("ssh : {e}"));
    }
    if let Some(d) = sshd.as_mut() {
        if let Err(e) = reap(d) {
            problems.push(format!("sshd : {e}"));
        }
    }
    // sshd lance un processus FILS par connexion que `reap` ne voit pas : seul le Job
    // les atteint, et ils tournent depuis le dossier de travail qu'on va effacer.
    if let Err(e) = job.terminate_and_close() {
        problems.push(format!("processus fils de sshd : {e}"));
    }
    // Garde une trace du journal de sshd dans le journal de session.
    if let Some(p) = &sshd_log_path {
        if let Ok(t) = fs::read_to_string(p) {
            for l in t.lines().take(400) {
                journal.log(&format!("sshd: {l}"));
            }
        }
    }
    if let Err(e) = staging.finish() {
        problems.push(format!("dossier de travail non effacé : {e}"));
    }
    if problems.is_empty() {
        journal.log("nettoyage terminé : fichier client, dossier de travail, processus");
        say("Partage terminé : tout a été retiré de ce PC.");
        say("(La fiche du PC côté Mac est retirée par le Mac dès que la connexion est fermée.)");
        return outcome;
    }
    let detail = problems.join(" ; ");
    journal.log(&format!("nettoyage INCOMPLET : {detail}"));
    say(&format!(
        "Partage terminé, mais TOUT N'A PAS ÉTÉ RETIRÉ de ce PC : {detail}."
    ));
    say("Le dossier de travail peut contenir la clé d'hôte éphémère : il sera effacé au prochain partage, ou supprime-le à la main.");
    match outcome {
        Ok(_) => Err(CcpError::Internal(format!(
            "partage terminé mais nettoyage incomplet : {detail}"
        ))),
        err => err,
    }
}

/// Point d'entrée : consentement, préparation, session.
#[allow(clippy::too_many_arguments)]
pub fn run(
    env: &Env,
    root: &Root,
    deps: &Deps,
    target: Target,
    common: &Common,
    input: &mut dyn BufRead,
    say: &mut dyn FnMut(&str),
) -> Result<i32> {
    let user = env.user.clone();
    let pc = sanitize_pc_name(
        &std::env::var("COMPUTERNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(super::conf::local_hostname)
            .unwrap_or_else(|| "pc".into()),
    );
    say(&consent_text(&user, &pc));
    eprint!("Pour continuer, tape OUI en majuscules puis Entrée (autre chose = annuler) : ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    let _ = input.read_line(&mut answer);
    if !is_consent(&answer) {
        say("Annulé : rien n'a été fait.");
        return Ok(0);
    }
    let stamp = jiff::Zoned::now().strftime("%Y%m%d-%H%M%S").to_string();
    let mut journal = Journal::open(root, &stamp)?;
    journal.log(&format!(
        "consentement donné pour le PC {pc} (utilisateur {user})"
    ));

    // Orphelins d'un partage précédent tué net (clé d'hôte éphémère, binaires extraits).
    let temp = std::env::temp_dir();
    let sweep = privdir::sweep_orphans(&temp, STAGING_PREFIX);
    if sweep.removed > 0 {
        let m = format!(
            "{} dossier(s) de travail orphelin(s) d'un partage précédent effacé(s).",
            sweep.removed
        );
        journal.log(&m);
        say(&m);
    }
    for (dir, why) in &sweep.failed {
        let m = format!(
            "ATTENTION : reste d'un partage précédent impossible à effacer : {} ({why}). Supprime-le à la main.",
            dir.display()
        );
        journal.log(&m);
        say(&m);
    }

    // `CCP_OPENSSH_DIR` (bancs d'essai) n'est JAMAIS honoré sous Windows : sshd y tourne
    // élevé, une variable d'environnement ne doit pas pouvoir désigner ce qu'on exécute.
    let openssh = match (cfg!(windows), env.ovr.openssh_dir.as_deref()) {
        (false, Some(d)) => OpenSshSource::Existing(openssh_in(d)),
        (is_windows, ovr) => {
            if is_windows && ovr.is_some() {
                say("CCP_OPENSSH_DIR est ignoré sous Windows.");
            }
            OpenSshSource::Archive(load_openssh_zip(
                root,
                &OPENSSH_WIN,
                deps.download_base,
                deps.fetch,
                &mut |m| say(m),
            )?)
        }
    };
    let prepared = connect::prepare(env, root, deps, target, common, false)?;
    intr::install();
    let senv = ShareEnv {
        temp,
        openssh,
        style: deps.style,
        pc,
        user,
        stop_after_registered: None,
    };
    let r = run_session(&prepared, &senv, &mut journal, say);
    say(&format!("Journal : {}", journal.path.display()));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder12 ccp-agents-essais";

    #[test]
    fn only_a_full_uppercase_oui_is_consent() {
        assert!(is_consent("OUI\n"));
        assert!(is_consent("  OUI  \r\n"));
        for no in ["oui", "Oui", "O", "OUI.", "", "non", "y", "OUI OUI"] {
            assert!(!is_consent(no), "{no:?}");
        }
    }

    #[test]
    fn consent_text_names_the_user_the_pc_and_the_risk() {
        let t = consent_text("Jean Dupont", "PC-ATELIER");
        for needle in [
            "EXÉCUTER DES",
            "PC-ATELIER",
            "« Jean Dupont »",
            "Ctrl+C",
            "127.0.0.1",
            "journal",
        ] {
            assert!(t.contains(needle), "manque {needle}");
        }
    }

    #[test]
    fn allocated_port_is_parsed_from_ssh_stderr() {
        assert_eq!(
            parse_allocated_port("Allocated port 54123 for remote forward to 127.0.0.1:2222"),
            Some(54123)
        );
        assert_eq!(
            parse_allocated_port("debug1: Allocated port 22 for remote forward to localhost:22"),
            Some(22)
        );
        for no in [
            "",
            "Allocated port  for remote forward",
            "Allocated port 0 for remote forward",
            "Allocated port 99999 for remote forward",
            "Warning: remote port forwarding failed for listen port 0",
        ] {
            assert_eq!(parse_allocated_port(no), None, "{no:?}");
        }
    }

    #[test]
    fn pc_names_are_safe_file_names() {
        assert_eq!(sanitize_pc_name("DESKTOP-AB12"), "DESKTOP-AB12");
        assert_eq!(sanitize_pc_name("PC de l'Atelier/é"), "PC-de-l-Atelier");
        assert_eq!(sanitize_pc_name("é-é.Poste"), "Poste");
        assert_eq!(sanitize_pc_name("../../etc"), "etc");
        assert_eq!(sanitize_pc_name("..."), "pc");
        assert_eq!(sanitize_pc_name(&"a".repeat(100)).len(), 40);
    }

    #[test]
    fn agent_key_must_be_a_plain_ed25519_line() {
        assert_eq!(validate_agent_pubkey(KEY).unwrap().split(' ').count(), 2);
        for bad in [
            "command=\"rm -rf /\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder12",
            "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder12",
            "ssh-ed25519 court",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder12\nssh-rsa X",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder12 a\u{7}b",
            "",
        ] {
            assert!(validate_agent_pubkey(bad).is_err(), "{bad:?}");
        }
        let line = authorized_keys_line(&validate_agent_pubkey(KEY).unwrap());
        assert!(line
            .starts_with("no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 "));
        assert!(line.ends_with('\n') && !line.contains(" ccp-agents-essais"));
    }

    #[test]
    fn sshd_config_is_local_key_only_and_quotes_paths() {
        let p = SshdPaths {
            host_key: PathBuf::from(r"C:\Users\Jean Dupont\AppData\Local\Temp\ccp-share-1\hostkey"),
            authorized_keys: PathBuf::from(
                r"C:\Users\Jean Dupont\AppData\Local\Temp\ccp-share-1\authorized_keys",
            ),
        };
        let c = sshd_config(Style::Windows, 50022, "Jean Dupont", &p).unwrap();
        for needle in [
            "Port 50022\n",
            "ListenAddress 127.0.0.1\n",
            "HostKey \"C:/Users/Jean Dupont/AppData/Local/Temp/ccp-share-1/hostkey\"\n",
            "AuthorizedKeysFile \"C:/Users/Jean Dupont/AppData/Local/Temp/ccp-share-1/authorized_keys\"\n",
            "PasswordAuthentication no\n",
            "KbdInteractiveAuthentication no\n",
            "AllowUsers \"Jean Dupont\"\n",
            "AllowTcpForwarding no\n",
        ] {
            assert!(c.contains(needle), "manque {needle:?} dans\n{c}");
        }
        assert!(!c.contains("0.0.0.0") && !c.contains("ListenAddress ::"));
        assert!(sshd_config(Style::Windows, 1, "a\"b", &p).is_err());
        assert!(sshd_config(Style::Windows, 1, "", &p).is_err());
    }

    #[test]
    fn client_json_is_one_line_and_carries_the_port() {
        let j = client_json(
            "PC-1",
            "jean",
            54123,
            "ssh-ed25519 AAAA host\n",
            "2026-11-09T10:00:00Z",
        );
        assert!(!j.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["port"], 54123);
        assert_eq!(v["pc"], "PC-1");
        assert_eq!(v["windows_user"], "jean");
        assert_eq!(v["sshd_host_key"], "ssh-ed25519 AAAA host");
        assert_eq!(v["schema"], 1);
    }

    #[test]
    fn remote_command_quotes_the_pc_name_and_cleans_up_by_trap() {
        let c = remote_command("PC'; rm -rf ~; '");
        assert!(c.starts_with("/bin/bash -c '"));
        assert!(c.ends_with(" ccp-share 'PC'\\''; rm -rf ~; '\\'''"), "{c}");
        let s = remote_script();
        assert!(s.contains("trap 'rm -f \"$f\" \"$f.tmp\"' EXIT HUP INT TERM"));
        assert!(s.contains(".ccp-portable/clients"));
    }

    use crate::remote::download::testing::*;
    use crate::remote::pins::Packaging;

    /// Épingle de substitution pour les tests : le vrai zip est épinglé par SHA, on ne
    /// peut pas en fabriquer un qui passe.
    fn test_asset(zip: &[u8]) -> Asset {
        Asset {
            repo: "o/r",
            tag: "v1",
            name: "OpenSSH-Win64.zip",
            sha256: Box::leak(sha_of(zip).into_boxed_str()),
            packaging: Packaging::Zip,
            max_bytes: 1 << 20,
        }
    }

    fn good_zip() -> Vec<u8> {
        // `exe()` : le nom change selon l'hôte (".exe" seulement sous Windows).
        make_zip(&[
            (&format!("OpenSSH-Win64/{}", exe("sshd")), b"sshd-verifie"),
            (
                &format!("OpenSSH-Win64/{}", exe("ssh-keygen")),
                b"keygen-verifie",
            ),
        ])
    }

    fn root_in(t: &tempfile::TempDir) -> Root {
        Root::new(t.path().to_str().unwrap(), crate::root::PathStyle::Unix).unwrap()
    }

    #[test]
    fn openssh_zip_is_kept_and_reverified_at_every_use() {
        let t = tempfile::tempdir().unwrap();
        let root = root_in(&t);
        let zip = good_zip();
        let asset = test_asset(&zip);
        let mut f = FakeFetch::default();
        f.files.insert(asset.url("http://127.0.0.1:1"), zip.clone());
        let on_disk = root.path().join("tools/openssh/v1/OpenSSH-Win64.zip");

        let got = load_openssh_zip(&root, &asset, "http://127.0.0.1:1", &f, &mut |_| {}).unwrap();
        assert_eq!(got, zip);
        assert!(on_disk.is_file(), "le zip est gardé");
        assert_eq!(f.calls.lock().unwrap().len(), 1);

        // 2e usage : relu et rehashé, aucun téléchargement.
        let got = load_openssh_zip(&root, &asset, "http://127.0.0.1:1", &f, &mut |_| {}).unwrap();
        assert_eq!(got, zip);
        assert_eq!(f.calls.lock().unwrap().len(), 1);

        // Le fichier est altéré sur le portable : il n'est PAS cru sur parole.
        fs::write(&on_disk, b"PK\x03\x04 piege").unwrap();
        let mut said = Vec::new();
        let got = load_openssh_zip(&root, &asset, "http://127.0.0.1:1", &f, &mut |m| {
            said.push(m.to_string())
        })
        .unwrap();
        assert_eq!(got, zip, "on rend les octets VÉRIFIÉS, pas ceux du disque");
        assert_eq!(f.calls.lock().unwrap().len(), 2, "retéléchargé");
        assert!(said.iter().any(|m| m.contains("remplacée")), "{said:?}");
        assert_eq!(fs::read(&on_disk).unwrap(), zip);
    }

    #[test]
    fn a_download_that_does_not_match_the_pin_is_refused_and_leaves_nothing() {
        let t = tempfile::tempdir().unwrap();
        let root = root_in(&t);
        let asset = test_asset(&good_zip());
        let mut f = FakeFetch::default();
        f.files.insert(
            asset.url("http://127.0.0.1:1"),
            make_zip(&[("OpenSSH-Win64/sshd.exe", b"piege")]),
        );
        let e = load_openssh_zip(&root, &asset, "http://127.0.0.1:1", &f, &mut |_| {}).unwrap_err();
        assert!(e.to_string().contains("REFUSÉ"), "{e}");
        assert!(!root
            .path()
            .join("tools/openssh/v1/OpenSSH-Win64.zip")
            .exists());
    }

    #[test]
    fn real_pin_rejects_a_forged_openssh_zip() {
        let t = tempfile::tempdir().unwrap();
        let root = root_in(&t);
        let mut f = FakeFetch::default();
        f.files
            .insert(OPENSSH_WIN.url("http://127.0.0.1:1"), good_zip());
        let e = load_openssh_zip(&root, &OPENSSH_WIN, "http://127.0.0.1:1", &f, &mut |_| {})
            .unwrap_err();
        assert!(e.to_string().contains("REFUSÉ"), "{e}");
    }

    #[test]
    fn a_previously_extracted_folder_on_the_portable_is_never_trusted() {
        let t = tempfile::tempdir().unwrap();
        let root = root_in(&t);
        let zip = good_zip();
        let asset = test_asset(&zip);
        // Ancienne disposition : dossier extrait + marqueur, avec un sshd.exe PIÉGÉ.
        let top = root.path().join("tools/openssh/v1");
        fs::create_dir_all(top.join("OpenSSH-Win64")).unwrap();
        fs::write(top.join("OpenSSH-Win64").join(exe("sshd")), b"PIEGE").unwrap();
        fs::write(top.join("OpenSSH-Win64").join(exe("ssh-keygen")), b"PIEGE").unwrap();
        fs::write(top.join("INSTALLED"), "v1 sha\n").unwrap();
        let mut f = FakeFetch::default();
        f.files.insert(asset.url("http://127.0.0.1:1"), zip.clone());

        let bytes = load_openssh_zip(&root, &asset, "http://127.0.0.1:1", &f, &mut |_| {}).unwrap();
        assert!(
            !top.join("OpenSSH-Win64").exists(),
            "dossier persistant retiré"
        );
        assert!(!top.join("INSTALLED").exists());

        let work = tempfile::tempdir().unwrap();
        let o = extract_openssh(&bytes, work.path()).unwrap();
        assert_eq!(fs::read(&o.sshd).unwrap(), b"sshd-verifie");
        assert_eq!(fs::read(&o.keygen).unwrap(), b"keygen-verifie");
        assert!(
            o.sshd.starts_with(work.path()),
            "extrait dans le dossier privé"
        );
    }

    #[test]
    fn each_session_extracts_into_its_own_fresh_private_folder() {
        let t = tempfile::tempdir().unwrap();
        let zip = good_zip();
        let a = PrivateDir::create(t.path(), STAGING_PREFIX).unwrap();
        let b = PrivateDir::create(t.path(), STAGING_PREFIX).unwrap();
        assert_ne!(a.path, b.path);
        assert!(a
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("ccp-share-"));
        let oa = extract_openssh(&zip, &a.path).unwrap();
        let ob = extract_openssh(&zip, &b.path).unwrap();
        assert_ne!(oa.sshd, ob.sshd);
        // Une archive sans les deux outils est refusée.
        let c = PrivateDir::create(t.path(), STAGING_PREFIX).unwrap();
        let bad = make_zip(&[(&format!("OpenSSH-Win64/{}", exe("sshd")), b"s")]);
        assert!(extract_openssh(&bad, &c.path).is_err());
        a.finish().unwrap();
        assert!(!oa.sshd.exists(), "tout part avec le dossier de travail");
    }
}
