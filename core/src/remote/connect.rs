//! `remote connect` / `remote sessions` : du PC vers le Mac, par le tunnel Cloudflare.
//!
//! UNE connexion par usage, donc UN mot de passe : `connect` envoie au Mac un petit
//! script qui liste les sessions tmux, laisse choisir (menu numéroté) puis s'y attache.
//! Alternatives écartées : (a) `sessions` puis `connect --session` = deux connexions =
//! deux mots de passe ; (b) ControlMaster pour partager la connexion = absent de
//! Win32-OpenSSH, et le chemin du socket (104 octets au plus) casse sur une racine longue.
//! `sessions` reste disponible pour un wizard qui préfère choisir avec gum, au prix
//! d'un second mot de passe : à réserver à ce cas.
//!
//! ssh est celui du SYSTÈME ; seul cloudflared est apporté (version épinglée).

use super::cloudflared::{self, Installed};
use super::conf::Target;
use super::known_hosts::{self, HostKnowledge};
use super::net::Fetch;
use super::pins::{self, DEFAULT_HOST};
use super::quote::{proxy_command, proxy_env, sh_quote, ssh_path_value, ProxyEnv, Style};
use crate::env::Env;
use crate::error::{CcpError, Result};
use crate::root::Root;
use std::ffi::{OsStr, OsString};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Ce que `connect` et `sessions` partagent.
pub struct Deps<'a> {
    pub fetch: &'a dyn Fetch,
    /// `std::env::consts::OS` / `ARCH` (paramétrables pour les tests).
    pub os: &'a str,
    pub arch: &'a str,
    pub download_base: &'a str,
    pub style: Style,
}

#[derive(Debug, Clone, Default)]
pub struct Common {
    /// Clé privée à utiliser au lieu du mot de passe (essais, agents).
    pub identity: Option<PathBuf>,
    /// Autorise une clé d'hôte inconnue (première connexion à un autre Mac), après vérification humaine.
    pub accept_new_host_key: bool,
}

/// Tout ce qu'il faut pour lancer ssh, prêt et vérifié.
#[derive(Debug)]
pub struct Prepared {
    pub ssh: OsString,
    /// Options communes (avant la destination).
    pub options: Vec<OsString>,
    pub proxy: ProxyEnv,
    pub target: Target,
    pub cloudflared: Installed,
}

fn io_err(what: &str, e: std::io::Error) -> CcpError {
    CcpError::Internal(format!("{what} : {e}"))
}

/// Dossier des fichiers de ssh propres au portable : `<racine>/config/remote/`.
pub fn remote_dir(root: &Root) -> PathBuf {
    root.path().join("config").join("remote")
}

/// Client ssh du système (ou `CCP_SSH_BIN`).
pub fn find_ssh(env: &Env, root: &Root) -> OsString {
    if let Some(o) = &env.ovr.ssh {
        return o.into();
    }
    if cfg!(windows) {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(sr) = std::env::var_os("SystemRoot") {
            candidates.push(Path::new(&sr).join("System32/OpenSSH/ssh.exe"));
        }
        candidates.push(root.path().join("git-win/usr/bin/ssh.exe"));
        if let Some(found) = candidates.into_iter().find(|p| p.is_file()) {
            return found.into_os_string();
        }
    }
    "ssh".into()
}

/// Options `-o` communes. Fonction PURE : les tests lisent exactement ce que ssh recevra.
pub fn ssh_options(
    style: Style,
    ssh_config: &Path,
    known_hosts: &Path,
    host: &str,
    common: &Common,
    quiet: bool,
) -> Result<Vec<OsString>> {
    let kh = ssh_path_value(known_hosts, style)?;
    let mut o: Vec<OsString> = Vec::new();
    let mut opt = |s: String| {
        o.push("-o".into());
        o.push(s.into());
    };
    opt(format!("ProxyCommand={}", proxy_command(style)));
    // Le fichier du portable sert aussi de fichier « global » : ssh ne lit alors AUCUN
    // known_hosts du PC (ni /etc/ssh, ni ~/.ssh), sans dépendre de /dev/null (absent de Windows).
    opt(format!("UserKnownHostsFile={kh}"));
    opt(format!("GlobalKnownHostsFile={kh}"));
    opt(format!(
        "StrictHostKeyChecking={}",
        if common.accept_new_host_key {
            "accept-new"
        } else {
            "yes"
        }
    ));
    // Jamais de réécriture du fichier par ssh : il est généré par ccp-core.
    opt("UpdateHostKeys=no".into());
    opt("CheckHostIP=no".into());
    if host.eq_ignore_ascii_case(DEFAULT_HOST) {
        // La clé épinglée est de type ed25519 : ssh ne doit pas en négocier un autre.
        opt(format!("HostKeyAlgorithms={}", pins::DEFAULT_HOST_KEY_TYPE));
    }
    opt("ForwardAgent=no".into());
    opt("ForwardX11=no".into());
    opt("ServerAliveInterval=30".into());
    opt("NumberOfPasswordPrompts=3".into());
    if quiet {
        opt("LogLevel=ERROR".into());
    }
    match &common.identity {
        Some(_) => opt("IdentitiesOnly=yes".into()),
        // Pas de clé de Sam sur le PC d'un client : mot de passe du Mac, rien d'autre.
        None => opt("PubkeyAuthentication=no".into()),
    }
    let mut args: Vec<OsString> = vec!["-F".into(), ssh_config.as_os_str().to_owned()];
    args.extend(o);
    if let Some(id) = &common.identity {
        args.push("-i".into());
        // `-i` développe lui aussi les `%` : on les double.
        args.push(super::quote::percent_escape(&id.to_string_lossy()).into());
    }
    Ok(args)
}

/// Prépare une connexion : cloudflared vérifié, known_hosts en place, options prêtes.
pub fn prepare(
    env: &Env,
    root: &Root,
    deps: &Deps,
    target: Target,
    common: &Common,
    quiet: bool,
) -> Result<Prepared> {
    let asset = pins::cloudflared_asset(deps.os, deps.arch).ok_or_else(|| {
        CcpError::Usage(format!(
            "pas de cloudflared épinglé pour {}-{} : plateforme non prise en charge",
            deps.os, deps.arch
        ))
    })?;
    let dir = cloudflared::tool_dir(root, deps.os, deps.arch);
    let installed = cloudflared::ensure(
        &dir,
        cloudflared::exe_name(deps.os),
        asset,
        deps.download_base,
        deps.fetch,
        &mut |m| eprintln!("ccp-core : {m}"),
    )?;
    let installed = cloudflared::runnable(env, installed, asset)?;

    let rdir = remote_dir(root);
    std::fs::create_dir_all(&rdir)
        .map_err(|e| io_err("dossier config/remote impossible à créer", e))?;
    let kh = rdir.join("known_hosts");
    let knowledge = known_hosts::ensure_file(&kh, &target.host)?;
    if knowledge == HostKnowledge::Unknown && !common.accept_new_host_key {
        return Err(CcpError::Usage(format!(
            "la clé d'hôte de {h} n'est pas connue de ce portable. Vérifie l'empreinte de {h} \
             auprès de son propriétaire, puis relance avec --accept-new-host-key \
             (ou ajoute sa ligne dans {kh}).",
            h = target.host,
            kh = kh.display()
        )));
    }
    // Un fichier ssh_config VIDE : `-F` l'impose à la place de ~/.ssh/config et /etc/ssh.
    let cfg = rdir.join("ssh_config");
    if !cfg.exists() {
        crate::atomic::write_atomic(
            &cfg,
            b"# fichier volontairement vide : voir ccp-core remote\n",
        )
        .map_err(|e| io_err("ssh_config du portable impossible à écrire", e))?;
    }
    let options = ssh_options(deps.style, &cfg, &kh, &target.host, common, quiet)?;
    let old_path = std::env::var_os("PATH");
    let proxy = proxy_env(deps.style, &installed.exe, old_path.as_ref())?;
    Ok(Prepared {
        ssh: find_ssh(env, root),
        options,
        proxy,
        target,
        cloudflared: installed,
    })
}

// ------------------------------------------------------------ commandes distantes

/// Retrouve tmux sur le Mac : Homebrew (Apple Silicon puis Intel), puis le PATH.
/// `CCP_TMUX` n'existe que pour les tests de ce script ; il est vide en production.
const FIND_TMUX: &str = r#"T=""
for c in ${CCP_TMUX:-} /opt/homebrew/bin/tmux /usr/local/bin/tmux; do
  if [ -x "$c" ]; then T="$c"; break; fi
done
if [ -z "$T" ]; then T="$(command -v tmux 2>/dev/null)"; fi
if [ -z "$T" ]; then echo "tmux est introuvable sur le Mac." >&2; exit 127; fi
"#;

/// Script de `connect` : `$1` = session voulue (vide = choisir).
fn connect_script() -> String {
    format!(
        r##"{FIND_TMUX}if [ -n "$1" ]; then
  if "$T" has-session -t "=$1" 2>/dev/null; then exec "$T" attach-session -t "=$1"; fi
  echo "Aucune session tmux nommée « $1 » sur le Mac." >&2
  exit 3
fi
names="$("$T" list-sessions -F "#{{session_name}}" 2>/dev/null)"
if [ -z "$names" ]; then echo "Aucune session tmux ouverte sur le Mac." >&2; exit 3; fi
count="$(printf '%s\n' "$names" | wc -l | tr -d ' ')"
if [ "$count" -eq 1 ]; then exec "$T" attach-session -t "=$names"; fi
echo "Sessions tmux du Mac :"
printf '%s\n' "$names" | awk '{{ printf "  %d) %s\n", NR, $0 }}'
printf "Numéro de la session (Entrée = annuler) : "
read -r pick
case "$pick" in ''|*[!0-9]*) echo "Annulé."; exit 0 ;; esac
name="$(printf '%s\n' "$names" | sed -n "${{pick}}p")"
if [ -z "$name" ]; then echo "Numéro inconnu." >&2; exit 3; fi
exec "$T" attach-session -t "=$name"
"##
    )
}

/// Marqueur des lignes utiles : le reste (bannière, MOTD, sortie d'un .zshenv) est ignoré.
const SESSION_TAG: &str = "CCP-SESSION";

fn sessions_script() -> String {
    // Séparateur `:` et non une tabulation : tmux REMPLACE les caractères de contrôle de
    // son format par `_` (constaté sur le vrai Mac, tmux 3.x), et il interdit lui-même
    // `:` et `.` dans un nom de session, donc `:` ne peut pas se confondre avec un nom.
    let fmt = format!("{SESSION_TAG}:#{{session_windows}}:#{{session_attached}}:#{{session_name}}");
    format!(
        r#"{FIND_TMUX}out="$("$T" list-sessions -F "{fmt}" 2>/dev/null)"
if [ -z "$out" ]; then echo "Aucune session tmux ouverte sur le Mac." >&2; exit 3; fi
printf '%s\n' "$out"
"#
    )
}

/// Commande distante complète, relue par le shell de connexion du Mac (zsh) :
/// `bash -c '<script>' ccp [session]`, chaque morceau cité pour un shell POSIX.
pub fn remote_connect_command(session: Option<&str>) -> Result<String> {
    if let Some(s) = session {
        if s.is_empty() || s.chars().any(|c| c.is_control()) {
            return Err(CcpError::Usage(
                "nom de session vide ou contenant un caractère de contrôle".into(),
            ));
        }
    }
    Ok(format!(
        "/bin/bash -c {} ccp-connect {}",
        sh_quote(&connect_script()),
        sh_quote(session.unwrap_or(""))
    ))
}

pub fn remote_sessions_command() -> String {
    format!("/bin/bash -c {} ccp-sessions", sh_quote(&sessions_script()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub name: String,
    pub windows: u32,
    pub attached: u32,
}

impl Session {
    /// `nom<TAB>fenêtres<TAB>attachées` : le format de `remote sessions`.
    pub fn line(&self) -> String {
        format!("{}\t{}\t{}", self.name, self.windows, self.attached)
    }
}

/// Lit la sortie de `sessions_script`. Tout ce qui n'a pas le marqueur est ignoré.
pub fn parse_sessions(stdout: &str) -> Vec<Session> {
    stdout
        .lines()
        .filter_map(|l| {
            let l = l.trim_end_matches('\r');
            let mut f = l.splitn(4, ':');
            if f.next()? != SESSION_TAG {
                return None;
            }
            let windows = f.next()?.trim().parse().ok()?;
            let attached = f.next()?.trim().parse().ok()?;
            // Le nom est en dernier : même un `:` inattendu n'en coupe pas la fin.
            let name = f.next()?.replace(['\t', '\n'], " ");
            (!name.is_empty()).then_some(Session {
                name,
                windows,
                attached,
            })
        })
        .collect()
}

// -------------------------------------------------------------------- lancement

fn destination(t: &Target) -> OsString {
    format!("{}@{}", t.user, t.host).into()
}

pub fn connect_args(p: &Prepared, session: Option<&str>, force_tty: bool) -> Result<Vec<OsString>> {
    let mut a = vec![OsString::from(if force_tty { "-tt" } else { "-t" })];
    a.extend(p.options.iter().cloned());
    a.push(destination(&p.target));
    a.push(remote_connect_command(session)?.into());
    Ok(a)
}

pub fn sessions_args(p: &Prepared) -> Vec<OsString> {
    // Pas de `-t` : la sortie est lue par ccp-core, pas affichée dans un terminal.
    let mut a = vec![OsString::from("-T")];
    a.extend(p.options.iter().cloned());
    a.push(destination(&p.target));
    a.push(remote_sessions_command().into());
    a
}

/// Pose l'environnement qui permet au `ProxyCommand` de retrouver cloudflared.
pub fn apply_proxy_env(cmd: &mut Command, proxy: &ProxyEnv) {
    if let Some(v) = &proxy.var {
        cmd.env(super::quote::CLOUDFLARED_VAR, v);
    }
    if let Some(p) = &proxy.path {
        cmd.env("PATH", p);
    }
    if let Some(d) = &proxy.cwd {
        cmd.current_dir(d);
    }
}

fn command_for(p: &Prepared, args: &[OsString]) -> Command {
    let mut c = Command::new(&p.ssh);
    c.args(args);
    apply_proxy_env(&mut c, &p.proxy);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY : `signal` est async-signal-safe ; ssh doit recevoir Ctrl+C normalement
        // même si le wizard bash a laissé SIGINT ignoré (hérité par les enfants).
        unsafe {
            c.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                Ok(())
            });
        }
    }
    c
}

fn spawn_error(ssh: &OsStr, e: std::io::Error) -> CcpError {
    if e.kind() == std::io::ErrorKind::NotFound {
        CcpError::NotFound(format!(
            "client ssh introuvable ({}). Windows 10 et 11 l'ont (Paramètres > Applications > \
             Fonctionnalités facultatives > Client OpenSSH) ; sinon utilise le Git portable du \
             portable.",
            ssh.to_string_lossy()
        ))
    } else {
        CcpError::Internal(format!(
            "lancement de ssh impossible ({}) : {e}",
            ssh.to_string_lossy()
        ))
    }
}

/// Code de sortie de ssh -> code de ccp-core. 255 est « ssh lui-même a échoué »
/// (réseau, Access refusé, clé d'hôte, mot de passe) : c'est un échec de connexion.
pub fn map_exit(code: i32) -> Result<i32> {
    if code == 255 {
        Err(CcpError::Network(
            "connexion au Mac impossible (voir le message de ssh ci-dessus)".into(),
        ))
    } else {
        Ok(code)
    }
}

fn exit_code_of(st: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
    }
    #[cfg(not(unix))]
    {
        st.code().unwrap_or(1)
    }
}

/// Session interactive : ssh garde le terminal. Renvoie son code de sortie brut.
pub fn run_interactive(p: &Prepared, session: Option<&str>) -> Result<i32> {
    let force_tty = !std::io::stdin().is_terminal();
    let args = connect_args(p, session, force_tty)?;
    let mut cmd = command_for(p, &args);
    crate::run::sig::install();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            crate::run::sig::restore();
            return Err(spawn_error(&p.ssh, e));
        }
    };
    crate::run::sig::child_started(child.id());
    let st = child.wait();
    crate::run::sig::restore();
    st.map(exit_code_of)
        .map_err(|e| CcpError::Internal(format!("attente de ssh impossible : {e}")))
}

/// Lance ssh et renvoie (code, stdout). Le terminal reste à ssh pour le mot de passe
/// (il le lit sur /dev/tty ou la console, jamais sur stdout) et pour ses messages.
pub fn run_capture(p: &Prepared) -> Result<(i32, String)> {
    let args = sessions_args(p);
    let mut cmd = command_for(p, &args);
    cmd.stdout(Stdio::piped());
    crate::run::sig::install();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            crate::run::sig::restore();
            return Err(spawn_error(&p.ssh, e));
        }
    };
    crate::run::sig::child_started(child.id());
    let mut out = Vec::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_end(&mut out);
    }
    let st = child.wait();
    crate::run::sig::restore();
    let code = st
        .map(exit_code_of)
        .map_err(|e| CcpError::Internal(format!("attente de ssh impossible : {e}")))?;
    Ok((code, String::from_utf8_lossy(&out).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn options_are_strict_and_quote_the_known_hosts_path() {
        let o = strs(
            &ssh_options(
                Style::Unix,
                Path::new("/Volumes/Ma clé USB/Écran été/config/remote/ssh_config"),
                Path::new("/Volumes/Ma clé USB/Écran été/config/remote/known_hosts"),
                DEFAULT_HOST,
                &Common::default(),
                true,
            )
            .unwrap(),
        );
        assert_eq!(o[0], "-F");
        assert_eq!(
            o[1],
            "/Volumes/Ma clé USB/Écran été/config/remote/ssh_config"
        );
        let joined = o.join("\n");
        for needle in [
            "ProxyCommand=\"$CCP_CLOUDFLARED\" access ssh --hostname %h",
            "UserKnownHostsFile=\"/Volumes/Ma clé USB/Écran été/config/remote/known_hosts\"",
            "GlobalKnownHostsFile=\"/Volumes/Ma clé USB/Écran été/config/remote/known_hosts\"",
            "StrictHostKeyChecking=yes",
            "UpdateHostKeys=no",
            "HostKeyAlgorithms=ssh-ed25519",
            "PubkeyAuthentication=no",
            "LogLevel=ERROR",
            "ForwardAgent=no",
        ] {
            assert!(joined.contains(needle), "manque {needle:?} dans\n{joined}");
        }
        assert!(!joined.contains("accept-new"));
    }

    #[test]
    fn windows_options_use_forward_slashes_and_the_bare_proxy_command() {
        let o = strs(
            &ssh_options(
                Style::Windows,
                Path::new(r"D:\Ma clé USB\config\remote\ssh_config"),
                Path::new(r"D:\Ma clé USB\config\remote\known_hosts"),
                DEFAULT_HOST,
                &Common::default(),
                true,
            )
            .unwrap(),
        );
        let joined = o.join("\n");
        assert!(joined.contains("ProxyCommand=cloudflared access ssh --hostname %h"));
        assert!(joined.contains("UserKnownHostsFile=\"D:/Ma clé USB/config/remote/known_hosts\""));
        assert!(!joined.contains("known_hosts\\"));
    }

    #[test]
    fn identity_and_accept_new_change_the_options() {
        let c = Common {
            identity: Some(PathBuf::from("/home/a b/.ssh/ccp_agents_ed25519")),
            accept_new_host_key: true,
        };
        let o = strs(
            &ssh_options(
                Style::Unix,
                Path::new("/r/ssh_config"),
                Path::new("/r/kh"),
                "autre.example",
                &c,
                false,
            )
            .unwrap(),
        );
        let joined = o.join("\n");
        assert!(joined.contains("StrictHostKeyChecking=accept-new"));
        assert!(joined.contains("IdentitiesOnly=yes"));
        assert!(!joined.contains("PubkeyAuthentication=no"));
        assert!(!joined.contains("LogLevel=ERROR"));
        // L'algorithme n'est imposé que pour l'hôte à clé épinglée.
        assert!(!joined.contains("HostKeyAlgorithms"));
        let i = o.iter().position(|s| s == "-i").unwrap();
        assert_eq!(o[i + 1], "/home/a b/.ssh/ccp_agents_ed25519");
    }

    #[test]
    fn connect_command_quotes_the_session_name() {
        let c = remote_connect_command(Some("a'b $(rm -rf ~) c")).unwrap();
        assert!(c.starts_with("/bin/bash -c '"));
        assert!(c.ends_with(" ccp-connect 'a'\\''b $(rm -rf ~) c'"), "{c}");
        assert!(remote_connect_command(Some("")).is_err());
        assert!(remote_connect_command(Some("a\nb")).is_err());
        assert!(remote_connect_command(None)
            .unwrap()
            .ends_with(" ccp-connect ''"));
    }

    #[test]
    fn sessions_are_parsed_from_tagged_lines_only() {
        let out = "Last login: Mon Nov  9 03:00:00\r\n\
                   Bienvenue sur le Mac\n\
                   CCP-SESSION:3:1:code-ui-claude-cwd-hub\n\
                   CCP-SESSION:1:0:nom avec\ttab\n\
                   CCP-SESSION:x:0:casse\n\
                   CCP-SESSION_1_1_ancienne-sortie-aux-tabulations\n\
                   CCP-SESSION:2:0:fin\r\n";
        let s = parse_sessions(out);
        assert_eq!(
            s,
            vec![
                Session {
                    name: "code-ui-claude-cwd-hub".into(),
                    windows: 3,
                    attached: 1
                },
                Session {
                    name: "nom avec tab".into(),
                    windows: 1,
                    attached: 0
                },
                Session {
                    name: "fin".into(),
                    windows: 2,
                    attached: 0
                },
            ]
        );
        assert_eq!(s[0].line(), "code-ui-claude-cwd-hub\t3\t1");
        assert!(parse_sessions("").is_empty());
    }

    #[test]
    fn ssh_exit_255_is_a_network_failure_others_pass_through() {
        assert_eq!(map_exit(0).unwrap(), 0);
        assert_eq!(map_exit(3).unwrap(), 3);
        assert_eq!(map_exit(255).unwrap_err().exit_code(), 4);
    }

    #[cfg(unix)]
    mod remote_scripts {
        use super::super::*;
        use std::os::unix::fs::PermissionsExt;

        /// Faux tmux : `list-sessions` rend `$FAKE_SESSIONS` ; `has-session` regarde la liste ;
        /// `attach-session` écrit « ATTACHE:<cible> ».
        fn fake_tmux(dir: &Path) -> PathBuf {
            let p = dir.join("tmux");
            std::fs::write(
                &p,
                r#"#!/bin/sh
case "$1" in
  list-sessions)
    [ -n "$FAKE_SESSIONS" ] || exit 1
    # Comme le VRAI tmux : le format -F est développé, puis les caractères de contrôle
    # (tabulation comprise) deviennent « _ ». Un premier jeu de tests avait un faux tmux
    # qui recopiait les tabulations : il a laissé passer un format inutilisable en vrai.
    fmt=""; while [ $# -gt 0 ]; do if [ "$1" = "-F" ]; then fmt="$2"; fi; shift; done
    printf '%s\n' "$FAKE_SESSIONS" | while IFS= read -r n; do
      printf '%s\n' "$fmt" | sed -e 's/#{session_windows}/2/' -e 's/#{session_attached}/0/' -e "s|#{session_name}|$n|" | tr '\t' '_'
    done ;;
  has-session) t="${3#=}"; printf '%s\n' "$FAKE_SESSIONS" | grep -qx -- "$t" ;;
  attach-session) echo "ATTACHE:$3" ;;
esac
"#,
            )
            .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        }

        fn run(command: &str, tmux: &Path, sessions: &str, stdin: &str) -> (i32, String, String) {
            use std::io::Write;
            // La commande est exactement celle qu'enverrait ssh ; ici un shell la relit.
            let mut child = Command::new("/bin/sh")
                .arg("-c")
                .arg(command)
                .env("CCP_TMUX", tmux)
                .env("FAKE_SESSIONS", sessions)
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(stdin.as_bytes())
                .unwrap();
            let o = child.wait_with_output().unwrap();
            (
                o.status.code().unwrap(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        }

        #[test]
        fn named_session_is_attached_exactly_and_unknown_is_refused() {
            let t = tempfile::tempdir().unwrap();
            let tmux = fake_tmux(t.path());
            let cmd = remote_connect_command(Some("code-ui")).unwrap();
            let (c, out, _) = run(&cmd, &tmux, "code-ui\nautre", "");
            assert_eq!((c, out.trim()), (0, "ATTACHE:=code-ui"));
            let cmd = remote_connect_command(Some("absente")).unwrap();
            let (c, _, err) = run(&cmd, &tmux, "code-ui", "");
            assert_eq!(c, 3);
            assert!(
                err.contains("Aucune session tmux nommée « absente »"),
                "{err}"
            );
        }

        #[test]
        fn single_session_is_attached_without_a_menu() {
            let t = tempfile::tempdir().unwrap();
            let tmux = fake_tmux(t.path());
            let cmd = remote_connect_command(None).unwrap();
            let (c, out, _) = run(&cmd, &tmux, "seule", "");
            assert_eq!((c, out.trim()), (0, "ATTACHE:=seule"));
        }

        #[test]
        fn several_sessions_show_a_numbered_menu() {
            let t = tempfile::tempdir().unwrap();
            let tmux = fake_tmux(t.path());
            let cmd = remote_connect_command(None).unwrap();
            let (c, out, _) = run(&cmd, &tmux, "alpha\nbeta gamma\ndelta", "2\n");
            assert_eq!(c, 0);
            assert!(
                out.contains("  1) alpha") && out.contains("  2) beta gamma"),
                "{out}"
            );
            assert!(out.contains("ATTACHE:=beta gamma"), "{out}");
            // Entrée vide = annuler, sans rien attacher.
            let (c, out, _) = run(&cmd, &tmux, "alpha\nbeta", "\n");
            assert_eq!(c, 0);
            assert!(out.contains("Annulé.") && !out.contains("ATTACHE"), "{out}");
            // Numéro hors liste.
            let (c, _, err) = run(&cmd, &tmux, "alpha\nbeta", "9\n");
            assert_eq!(c, 3);
            assert!(err.contains("Numéro inconnu"), "{err}");
            // Une saisie qui n'est pas un nombre n'est jamais passée à sed.
            let (c, out, _) = run(&cmd, &tmux, "alpha\nbeta", "1;rm\n");
            assert_eq!(c, 0);
            assert!(out.contains("Annulé."), "{out}");
        }

        #[test]
        fn no_session_and_no_tmux_are_reported() {
            let t = tempfile::tempdir().unwrap();
            let tmux = fake_tmux(t.path());
            let cmd = remote_connect_command(None).unwrap();
            let (c, _, err) = run(&cmd, &tmux, "", "");
            assert_eq!(c, 3);
            assert!(err.contains("Aucune session tmux ouverte"), "{err}");
            // tmux introuvable : ni CCP_TMUX, ni Homebrew, ni PATH (hôte de test : on masque Homebrew
            // en n'exécutant que si aucun tmux n'existe aux emplacements connus).
            if !Path::new("/opt/homebrew/bin/tmux").exists()
                && !Path::new("/usr/local/bin/tmux").exists()
            {
                let (c, _, err) = run(&cmd, Path::new("/nulle/part"), "x", "");
                assert_eq!(c, 127);
                assert!(err.contains("tmux est introuvable"), "{err}");
            }
        }

        #[test]
        fn sessions_script_prints_tagged_lines_for_the_parser() {
            let t = tempfile::tempdir().unwrap();
            let tmux = fake_tmux(t.path());
            let (c, out, _) = run(&remote_sessions_command(), &tmux, "un\ndeux mots", "");
            assert_eq!(c, 0);
            let s = parse_sessions(&out);
            assert_eq!(s.len(), 2);
            assert_eq!(s[1].name, "deux mots");
            let (c, out, err) = run(&remote_sessions_command(), &tmux, "", "");
            assert_eq!((c, out.as_str()), (3, ""));
            assert!(err.contains("Aucune session"), "{err}");
        }
    }
}
