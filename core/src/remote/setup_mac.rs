//! `remote setup-mac [--check]` : état (et mise en place LOCALE) du Mac comme poste distant.
//!
//! Sortie : une ligne par contrôle, `ok|ko<TAB>contrôle<TAB>détail`, dans cet ordre :
//! `sshd`, `tunnel-launchagent`, `tunnel-journal`, `access`, `cle-agents`.
//!
//! Sans `--check`, la commande crée SEULEMENT ce qui manque ET qui est local :
//! la clé des agents, sa ligne restreinte dans `authorized_keys`, le LaunchAgent du
//! tunnel (si `~/.cloudflared/ccp-mac.token` existe). Elle ne crée JAMAIS de route DNS
//! ni d'objet Cloudflare (tunnel, application Access) : cela passe par l'API avec des
//! identifiants du coffre, hors du binaire distribué ; si le tunnel manque, elle
//! imprime la marche à suivre. Elle ne modifie jamais une ligne existante.

use super::net::Fetch;
use super::pins::DEFAULT_HOST;
use crate::error::{CcpError, Result};
use crate::util::run_bounded;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub const LABEL: &str = "fr.atelier-sam.ccp-mac-tunnel";
const KEY_NAME: &str = "ccp_agents_ed25519";
/// Restrictions posées sur la clé des agents dans `authorized_keys` : elle n'ouvre le Mac
/// que depuis lui-même (le tunnel ressort en 127.0.0.1) et sans relais d'agent / d'écran.
pub const KEY_OPTIONS: &str = "from=\"127.0.0.1,::1\",no-agent-forwarding,no-X11-forwarding";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub ok: bool,
    pub name: &'static str,
    pub detail: String,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Check {
        Check {
            ok: true,
            name,
            detail: detail.into(),
        }
    }
    fn ko(name: &'static str, detail: impl Into<String>) -> Check {
        Check {
            ok: false,
            name,
            detail: detail.into(),
        }
    }
    /// `ok|ko<TAB>contrôle<TAB>détail` (le détail tient sur une ligne, sans tabulation).
    pub fn line(&self) -> String {
        let d: String = self
            .detail
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        format!(
            "{}\t{}\t{}",
            if self.ok { "ok" } else { "ko" },
            self.name,
            d
        )
    }
}

// ----------------------------------------------------------------- dépendances

pub trait Launchd {
    /// Sortie de `launchctl print gui/<uid>/<label>` ; `Err` si le service n'existe pas.
    fn print(&self, label: &str) -> std::result::Result<String, String>;
    fn bootstrap(&self, plist: &Path) -> std::result::Result<(), String>;
}

pub trait Banner {
    /// Première ligne envoyée par ce qui écoute sur 127.0.0.1:22.
    fn first_line(&self) -> std::result::Result<String, String>;
}

pub trait KeyGen {
    /// Crée une clé ed25519 SANS phrase secrète (elle sert à des agents non interactifs).
    fn generate(&self, path: &Path, comment: &str) -> std::result::Result<(), String>;
    /// Ligne publique d'une clé privée existante.
    fn public_of(&self, private: &Path) -> std::result::Result<String, String>;
}

pub struct RealLaunchd {
    pub uid: u32,
}

impl Launchd for RealLaunchd {
    fn print(&self, label: &str) -> std::result::Result<String, String> {
        let o = run_bounded(
            Command::new("launchctl")
                .arg("print")
                .arg(format!("gui/{}/{label}", self.uid)),
            None,
            Duration::from_secs(10),
        )
        .map_err(|e| format!("launchctl illisible : {e}"))?;
        if o.code() == Some(0) {
            Ok(o.stdout_str())
        } else {
            Err(format!("{}{}", o.stdout_str(), o.stderr_str())
                .trim()
                .to_string())
        }
    }

    fn bootstrap(&self, plist: &Path) -> std::result::Result<(), String> {
        let o = run_bounded(
            Command::new("launchctl")
                .arg("bootstrap")
                .arg(format!("gui/{}", self.uid))
                .arg(plist),
            None,
            Duration::from_secs(15),
        )
        .map_err(|e| format!("launchctl illisible : {e}"))?;
        if o.code() == Some(0) {
            Ok(())
        } else {
            Err(o.stderr_str().trim().to_string())
        }
    }
}

pub struct TcpBanner {
    pub addr: &'static str,
}

impl Banner for TcpBanner {
    fn first_line(&self) -> std::result::Result<String, String> {
        use std::net::{TcpStream, ToSocketAddrs};
        let sa = self
            .addr
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("adresse introuvable")?;
        let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(2))
            .map_err(|e| format!("connexion refusée ({e})"))?;
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut buf = [0u8; 255];
        let n = s
            .read(&mut buf)
            .map_err(|e| format!("pas de bannière ({e})"))?;
        Ok(String::from_utf8_lossy(&buf[..n])
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string())
    }
}

pub struct RealKeyGen;

impl KeyGen for RealKeyGen {
    fn generate(&self, path: &Path, comment: &str) -> std::result::Result<(), String> {
        let o = run_bounded(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
                .arg(path),
            None,
            Duration::from_secs(30),
        )
        .map_err(|e| format!("ssh-keygen introuvable : {e}"))?;
        if o.code() == Some(0) {
            Ok(())
        } else {
            Err(o.stderr_str().trim().to_string())
        }
    }

    fn public_of(&self, private: &Path) -> std::result::Result<String, String> {
        let o = run_bounded(
            Command::new("ssh-keygen").arg("-y").arg("-f").arg(private),
            None,
            Duration::from_secs(15),
        )
        .map_err(|e| format!("ssh-keygen introuvable : {e}"))?;
        if o.code() == Some(0) {
            Ok(o.stdout_str().trim().to_string())
        } else {
            Err(o.stderr_str().trim().to_string())
        }
    }
}

pub struct Deps<'a> {
    pub launchd: &'a dyn Launchd,
    pub banner: &'a dyn Banner,
    pub fetch: &'a dyn Fetch,
    pub keygen: &'a dyn KeyGen,
    /// URL testée sans identité (par défaut l'hôte du tunnel).
    pub access_url: String,
}

// ------------------------------------------------------------------- chemins

#[derive(Debug, Clone)]
pub struct Paths {
    pub ssh_dir: PathBuf,
    pub key: PathBuf,
    pub key_pub: PathBuf,
    pub authorized_keys: PathBuf,
    pub plist: PathBuf,
    pub token: PathBuf,
    pub log: PathBuf,
}

impl Paths {
    pub fn new(home: &Path) -> Paths {
        let ssh_dir = home.join(".ssh");
        Paths {
            key: ssh_dir.join(KEY_NAME),
            key_pub: ssh_dir.join(format!("{KEY_NAME}.pub")),
            authorized_keys: ssh_dir.join("authorized_keys"),
            ssh_dir,
            plist: home
                .join("Library/LaunchAgents")
                .join(format!("{LABEL}.plist")),
            token: home.join(".cloudflared/ccp-mac.token"),
            log: home.join("Library/Logs/ccp/tunnel.log"),
        }
    }
}

// ------------------------------------------------------------- analyses pures

/// `state = running` et `pid = N` dans la sortie de `launchctl print`.
pub fn parse_launchd(print: &str) -> (Option<String>, Option<u32>) {
    let field = |k: &str| {
        print.lines().find_map(|l| {
            l.trim()
                .strip_prefix(k)
                .and_then(|r| r.trim_start().strip_prefix('='))
                .map(|v| v.trim().to_string())
        })
    };
    (field("state"), field("pid").and_then(|p| p.parse().ok()))
}

/// Connexions du tunnel encore enregistrées d'après le journal de cloudflared.
/// Retourne (nombre, horodatage de la dernière ligne « Registered tunnel connection »).
pub fn tunnel_connections(log: &str) -> (usize, Option<String>) {
    use std::collections::BTreeSet;
    let mut up: BTreeSet<String> = BTreeSet::new();
    let mut last_ts = None;
    for l in log.lines() {
        let Some(idx) = l
            .split_whitespace()
            .find_map(|w| w.strip_prefix("connIndex="))
        else {
            continue;
        };
        if l.contains("Registered tunnel connection") {
            up.insert(idx.to_string());
            last_ts = l.split_whitespace().next().map(str::to_string);
        } else if l.contains("Unregistered tunnel connection")
            || l.contains("Lost connection with the edge")
            || l.contains("Retrying connection")
        {
            up.remove(idx);
        }
    }
    (up.len(), last_ts)
}

/// Dernier ko de `tail_bytes` octets d'un fichier (le journal grossit sans fin).
fn read_tail(path: &Path, tail_bytes: u64) -> std::io::Result<String> {
    use std::io::{Seek, SeekFrom};
    let mut f = fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len > tail_bytes {
        f.seek(SeekFrom::Start(len - tail_bytes))?;
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Le blob base64 d'une ligne publique `type blob [commentaire]`.
fn key_blob(public_line: &str) -> Option<&str> {
    let mut it = public_line.split_whitespace();
    let ty = it.next()?;
    let blob = it.next()?;
    ty.starts_with("ssh-").then_some(blob)
}

/// Dans `authorized_keys`, la ligne de ce blob : `Some(restreinte?)`.
pub fn authorized_entry(authorized: &str, blob: &str) -> Option<bool> {
    authorized
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find(|l| l.split_whitespace().any(|w| w == blob))
        .map(|l| l.starts_with("from=\""))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Le plist du LaunchAgent du tunnel (même forme que celui posé le 09/11).
pub fn render_plist(cloudflared: &str, token: &Path, log: &Path) -> String {
    let args = [
        cloudflared,
        "tunnel",
        "--no-autoupdate",
        "run",
        "--token-file",
    ]
    .iter()
    .map(|a| format!("    <string>{}</string>\n", xml_escape(a)))
    .collect::<String>()
        + &format!(
            "    <string>{}</string>\n",
            xml_escape(&token.to_string_lossy())
        );
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
  <key>Label</key>\n  <string>{LABEL}</string>\n\
  <key>ProgramArguments</key>\n  <array>\n{args}  </array>\n\
  <key>RunAtLoad</key>\n  <true/>\n\
  <key>KeepAlive</key>\n  <true/>\n\
  <key>ThrottleInterval</key>\n  <integer>15</integer>\n\
  <key>StandardOutPath</key>\n  <string>{log}</string>\n\
  <key>StandardErrorPath</key>\n  <string>{log}</string>\n\
</dict>\n</plist>\n",
        log = xml_escape(&log.to_string_lossy())
    )
}

// ------------------------------------------------------------------ contrôles

pub fn check_sshd(banner: &dyn Banner) -> Check {
    match banner.first_line() {
        Ok(l) if l.starts_with("SSH-2.0") => {
            Check::ok("sshd", format!("écoute sur le port 22 ({l})"))
        }
        Ok(l) => Check::ko(
            "sshd",
            format!("le port 22 répond autre chose qu'un serveur SSH (« {l} »)"),
        ),
        Err(e) => Check::ko(
            "sshd",
            format!(
                "rien n'écoute sur le port 22 ({e}) : active la Session à distance \
                 (Réglages Système > Général > Partage)"
            ),
        ),
    }
}

pub fn check_launchagent(launchd: &dyn Launchd, paths: &Paths) -> Check {
    match launchd.print(LABEL) {
        Ok(out) => match parse_launchd(&out) {
            (Some(s), pid) if s == "running" => Check::ok(
                "tunnel-launchagent",
                match pid {
                    Some(p) => format!("{LABEL} actif (state = running, pid {p})"),
                    None => format!("{LABEL} actif (state = running)"),
                },
            ),
            (Some(s), _) => Check::ko(
                "tunnel-launchagent",
                format!(
                    "{LABEL} chargé mais pas actif (state = {s}) : voir {}",
                    paths.log.display()
                ),
            ),
            (None, _) => Check::ko("tunnel-launchagent", format!("{LABEL} : état illisible")),
        },
        Err(_) if paths.plist.exists() => Check::ko(
            "tunnel-launchagent",
            format!("{LABEL} n'est pas chargé : relance setup-mac sans --check pour le charger"),
        ),
        Err(_) => Check::ko(
            "tunnel-launchagent",
            format!(
                "{LABEL} absent : crée d'abord le tunnel (jeton dans {}), puis relance setup-mac",
                paths.token.display()
            ),
        ),
    }
}

pub fn check_journal(paths: &Paths) -> Check {
    match read_tail(&paths.log, 256 * 1024) {
        Ok(text) => match tunnel_connections(&text) {
            (0, _) => Check::ko(
                "tunnel-journal",
                format!(
                    "aucune connexion « Registered tunnel connection » encore active dans {}",
                    paths.log.display()
                ),
            ),
            (n, ts) => Check::ok(
                "tunnel-journal",
                format!(
                    "{n} connexion(s) enregistrée(s) auprès de Cloudflare (dernière : {})",
                    ts.unwrap_or_else(|| "?".into())
                ),
            ),
        },
        Err(e) => Check::ko(
            "tunnel-journal",
            format!("{} illisible ({e})", paths.log.display()),
        ),
    }
}

/// Une requête SANS identité doit recevoir la redirection vers la page de connexion
/// Access, jamais une bannière SSH : sinon le tunnel est exposé sans protection.
pub fn check_access(fetch: &dyn Fetch, url: &str) -> Check {
    match fetch.probe(url) {
        Err(e) => Check::ko("access", format!("{url} injoignable ({})", e.message())),
        Ok(p) => {
            if p.body_head.contains("SSH-2.0") {
                return Check::ko(
                    "access",
                    format!("DANGER : {url} répond une bannière SSH sans authentification Access"),
                );
            }
            let loc = p.location.as_deref().unwrap_or("");
            if matches!(p.status, 301 | 302 | 303 | 307 | 308)
                && loc.contains("cloudflareaccess.com")
            {
                let host = loc
                    .split("://")
                    .nth(1)
                    .and_then(|r| r.split('/').next())
                    .unwrap_or("cloudflareaccess.com");
                Check::ok(
                    "access",
                    format!(
                        "redirigé vers {host} (HTTP {}), aucune bannière SSH",
                        p.status
                    ),
                )
            } else {
                Check::ko(
                    "access",
                    format!(
                        "HTTP {} sans redirection vers cloudflareaccess.com : l'application \
                         Access ne protège pas {url}",
                        p.status
                    ),
                )
            }
        }
    }
}

pub fn check_agents_key(paths: &Paths) -> Check {
    let Ok(public) = fs::read_to_string(&paths.key_pub) else {
        return Check::ko(
            "cle-agents",
            format!(
                "{} absente : relance setup-mac sans --check",
                paths.key_pub.display()
            ),
        );
    };
    if !paths.key.exists() {
        return Check::ko(
            "cle-agents",
            format!(
                "clé privée {} absente (la publique existe seule)",
                paths.key.display()
            ),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&paths.key).map(|m| m.permissions().mode() & 0o777);
        if let Ok(m) = mode {
            if m & 0o077 != 0 {
                return Check::ko(
                    "cle-agents",
                    format!(
                        "{} est lisible par d'autres (mode {m:o}) : chmod 600",
                        paths.key.display()
                    ),
                );
            }
        }
    }
    let Some(blob) = key_blob(&public) else {
        return Check::ko(
            "cle-agents",
            format!("{} illisible", paths.key_pub.display()),
        );
    };
    let authorized = fs::read_to_string(&paths.authorized_keys).unwrap_or_default();
    match authorized_entry(&authorized, blob) {
        Some(true) => Check::ok(
            "cle-agents",
            format!("{} présente, restreinte par from= dans authorized_keys", paths.key.display()),
        ),
        Some(false) => Check::ko(
            "cle-agents",
            "la clé figure dans authorized_keys SANS restriction from= : corrige la ligne à la main",
        ),
        None => Check::ko(
            "cle-agents",
            "la clé n'est pas dans authorized_keys : relance setup-mac sans --check",
        ),
    }
}

pub fn run_checks(deps: &Deps, paths: &Paths) -> Vec<Check> {
    vec![
        check_sshd(deps.banner),
        check_launchagent(deps.launchd, paths),
        check_journal(paths),
        check_access(deps.fetch, &deps.access_url),
        check_agents_key(paths),
    ]
}

// ---------------------------------------------------------------- mise en place

fn find_cloudflared() -> Option<&'static str> {
    [
        "/opt/homebrew/bin/cloudflared",
        "/usr/local/bin/cloudflared",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists())
}

fn io_err(what: &str, e: impl std::fmt::Display) -> CcpError {
    CcpError::Internal(format!("{what} : {e}"))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// Crée ce qui manque DE LOCAL. `say` reçoit un message par geste (stderr côté appelant).
pub fn provision(deps: &Deps, paths: &Paths, say: &mut dyn FnMut(&str)) -> Result<()> {
    // 1. clé des agents
    fs::create_dir_all(&paths.ssh_dir).map_err(|e| io_err("~/.ssh impossible à créer", e))?;
    set_mode(&paths.ssh_dir, 0o700);
    if !paths.key.exists() && !paths.key_pub.exists() {
        deps.keygen
            .generate(&paths.key, "ccp-agents")
            .map_err(|e| io_err("création de la clé des agents impossible", e))?;
        say(&format!("clé des agents créée : {}", paths.key.display()));
    } else if paths.key.exists() && !paths.key_pub.exists() {
        let line = deps
            .keygen
            .public_of(&paths.key)
            .map_err(|e| io_err("clé publique des agents illisible", e))?;
        fs::write(&paths.key_pub, format!("{line}\n"))
            .map_err(|e| io_err("clé publique impossible à écrire", e))?;
        say(&format!(
            "clé publique recalculée : {}",
            paths.key_pub.display()
        ));
    }
    // 2. ligne restreinte dans authorized_keys (jamais de modification d'une ligne existante)
    if let Ok(public) = fs::read_to_string(&paths.key_pub) {
        if let Some(blob) = key_blob(&public) {
            let current = fs::read_to_string(&paths.authorized_keys).unwrap_or_default();
            if authorized_entry(&current, blob).is_none() {
                let mut next = current;
                if !next.is_empty() && !next.ends_with('\n') {
                    next.push('\n');
                }
                next.push_str(&format!("{KEY_OPTIONS} {}\n", public.trim()));
                crate::atomic::write_atomic(&paths.authorized_keys, next.as_bytes())
                    .map_err(|e| io_err("authorized_keys impossible à écrire", e))?;
                say("ligne restreinte (from=127.0.0.1,::1) ajoutée à ~/.ssh/authorized_keys");
            }
        }
    }
    // 3. LaunchAgent du tunnel
    let loaded = deps.launchd.print(LABEL).is_ok();
    if loaded {
        return Ok(());
    }
    if !paths.token.exists() {
        say(&format!(
            "tunnel Cloudflare absent (pas de {}). Marche à suivre, dans cet ordre :",
            paths.token.display()
        ));
        for step in marche_a_suivre() {
            say(&format!("  {step}"));
        }
        return Ok(());
    }
    if !paths.plist.exists() {
        let Some(cf) = find_cloudflared() else {
            say("cloudflared introuvable (brew install cloudflared) : LaunchAgent non créé");
            return Ok(());
        };
        if let Some(dir) = paths.plist.parent() {
            fs::create_dir_all(dir)
                .map_err(|e| io_err("~/Library/LaunchAgents impossible à créer", e))?;
        }
        if let Some(dir) = paths.log.parent() {
            fs::create_dir_all(dir)
                .map_err(|e| io_err("dossier du journal impossible à créer", e))?;
        }
        let mut f =
            fs::File::create(&paths.plist).map_err(|e| io_err("plist impossible à écrire", e))?;
        f.write_all(render_plist(cf, &paths.token, &paths.log).as_bytes())
            .map_err(|e| io_err("plist impossible à écrire", e))?;
        say(&format!("LaunchAgent écrit : {}", paths.plist.display()));
    }
    deps.launchd
        .bootstrap(&paths.plist)
        .map_err(|e| io_err("chargement du LaunchAgent impossible", e))?;
    say("LaunchAgent chargé");
    Ok(())
}

/// Ce que setup-mac NE fait PAS (objets Cloudflare) : à dérouler à la main ou par l'API.
pub fn marche_a_suivre() -> Vec<String> {
    vec![
        "1. Cloudflare Zero Trust > Réseaux > Tunnels : créer le tunnel « ccp-mac » et enregistrer son jeton dans ~/.cloudflared/ccp-mac.token (chmod 600).".to_string(),
        format!("2. Poser l'APPLICATION Access (connexion par code e-mail, session courte) sur {DEFAULT_HOST} AVANT toute route DNS."),
        format!("3. Seulement ensuite : nom d'hôte public {DEFAULT_HOST} -> ssh://localhost:22 sur ce tunnel."),
        "4. Relancer « ccp-core remote setup-mac » : il charge le LaunchAgent et vérifie tout.".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::NetError;
    use crate::remote::net::Probe;
    use std::cell::RefCell;

    // Sortie RÉELLE de `launchctl print` (09/11/2026), tronquée aux lignes utiles.
    const LAUNCHCTL_RUNNING: &str = "gui/501/fr.atelier-sam.ccp-mac-tunnel = {\n\
\tactive count = 1\n\tpath = /Users/s/Library/LaunchAgents/fr.atelier-sam.ccp-mac-tunnel.plist\n\
\ttype = LaunchAgent\n\tstate = running\n\n\tprogram = /opt/homebrew/bin/cloudflared\n\
\tdomain = gui/501 [100002]\n\truns = 1\n\tpid = 95109\n\timmediate reason = speculative\n}\n";

    const JOURNAL: &str = "\
2026-11-09T01:56:27Z INF Registered tunnel connection connIndex=0 connection=aaa event=0 ip=1.1.1.1 location=cdg17 protocol=quic
2026-11-09T01:56:27Z INF Registered tunnel connection connIndex=1 connection=bbb event=0 ip=1.1.1.2 location=cdg09 protocol=quic
2026-11-09T01:56:28Z INF Registered tunnel connection connIndex=2 connection=ccc event=0 ip=1.1.1.3 location=cdg10 protocol=quic
2026-11-09T01:56:29Z INF Tunnel connection curve preferences: [X25519MLKEM768] connIndex=3 event=0 ip=1.1.1.4
2026-11-09T01:56:29Z INF Registered tunnel connection connIndex=3 connection=ddd event=0 ip=1.1.1.4 location=cdg11 protocol=quic
";

    struct FakeLaunchd {
        print: std::result::Result<String, String>,
        boot: RefCell<Vec<PathBuf>>,
        loaded_after_boot: bool,
    }
    impl Launchd for FakeLaunchd {
        fn print(&self, _l: &str) -> std::result::Result<String, String> {
            if self.loaded_after_boot && !self.boot.borrow().is_empty() {
                return Ok(LAUNCHCTL_RUNNING.into());
            }
            self.print.clone()
        }
        fn bootstrap(&self, p: &Path) -> std::result::Result<(), String> {
            self.boot.borrow_mut().push(p.to_path_buf());
            Ok(())
        }
    }
    fn launchd(print: std::result::Result<String, String>) -> FakeLaunchd {
        FakeLaunchd {
            print,
            boot: RefCell::new(vec![]),
            loaded_after_boot: false,
        }
    }

    struct FakeBanner(std::result::Result<String, String>);
    impl Banner for FakeBanner {
        fn first_line(&self) -> std::result::Result<String, String> {
            self.0.clone()
        }
    }

    struct FakeKeyGen {
        made: RefCell<Vec<PathBuf>>,
    }
    impl KeyGen for FakeKeyGen {
        fn generate(&self, path: &Path, comment: &str) -> std::result::Result<(), String> {
            self.made.borrow_mut().push(path.to_path_buf());
            fs::write(path, "PRIVEE").map_err(|e| e.to_string())?;
            set_mode(path, 0o600);
            fs::write(
                path.with_file_name(format!(
                    "{}.pub",
                    path.file_name().unwrap().to_string_lossy()
                )),
                format!("ssh-ed25519 AAAAFAKEBLOB {comment}\n"),
            )
            .map_err(|e| e.to_string())
        }
        fn public_of(&self, _p: &Path) -> std::result::Result<String, String> {
            Ok("ssh-ed25519 AAAAFAKEBLOB recalcule".into())
        }
    }

    struct FakeFetch(Option<Probe>);
    impl Fetch for FakeFetch {
        fn download(
            &self,
            _u: &str,
            _s: &mut dyn Write,
            _m: u64,
        ) -> std::result::Result<u64, NetError> {
            Err(NetError::Other("non utilisé".into()))
        }
        fn probe(&self, _u: &str) -> std::result::Result<Probe, NetError> {
            self.0
                .clone()
                .ok_or(NetError::Other("hôte injoignable".into()))
        }
    }

    fn access_302() -> Probe {
        Probe {
            status: 302,
            location: Some(
                "https://atelier-sam.cloudflareaccess.com/cdn-cgi/access/login/ssh-mac.atelier-sam.fr?kid=x"
                    .into(),
            ),
            body_head: "<a href=\"https://atelier-sam.cloudflareaccess.com\">Found</a>".into(),
        }
    }

    #[test]
    fn launchctl_output_is_parsed() {
        assert_eq!(
            parse_launchd(LAUNCHCTL_RUNNING),
            (Some("running".into()), Some(95109))
        );
        assert_eq!(
            parse_launchd("state = waiting\n").0.as_deref(),
            Some("waiting")
        );
        assert_eq!(parse_launchd("rien"), (None, None));
    }

    #[test]
    fn journal_counts_live_connections_and_notices_drops() {
        let (n, ts) = tunnel_connections(JOURNAL);
        assert_eq!(n, 4);
        assert_eq!(ts.as_deref(), Some("2026-11-09T01:56:29Z"));
        let dropped = format!(
            "{JOURNAL}2026-11-09T02:00:00Z ERR Unregistered tunnel connection connIndex=0\n\
             2026-11-09T02:00:01Z ERR Lost connection with the edge connIndex=1\n\
             2026-11-09T02:00:02Z INF Retrying connection in up to 2s connIndex=2\n\
             2026-11-09T02:00:03Z INF Retrying connection in up to 2s connIndex=3\n"
        );
        assert_eq!(tunnel_connections(&dropped).0, 0);
        let back = format!(
            "{dropped}2026-11-09T02:00:09Z INF Registered tunnel connection connIndex=2 x=y\n"
        );
        assert_eq!(tunnel_connections(&back).0, 1);
        assert_eq!(tunnel_connections("").0, 0);
    }

    #[test]
    fn sshd_check_reads_the_banner() {
        let ok = check_sshd(&FakeBanner(Ok("SSH-2.0-OpenSSH_10.5".into())));
        assert_eq!(
            ok.line(),
            "ok\tsshd\técoute sur le port 22 (SSH-2.0-OpenSSH_10.5)"
        );
        assert!(!check_sshd(&FakeBanner(Ok("HTTP/1.1 400".into()))).ok);
        let ko = check_sshd(&FakeBanner(Err("connexion refusée".into())));
        assert!(!ko.ok && ko.detail.contains("Session à distance"));
    }

    #[test]
    fn access_check_demands_a_redirect_to_cloudflareaccess_and_no_ssh_banner() {
        let ok = check_access(
            &FakeFetch(Some(access_302())),
            "https://ssh-mac.atelier-sam.fr/",
        );
        assert!(ok.ok, "{ok:?}");
        assert!(ok.detail.contains("atelier-sam.cloudflareaccess.com"));

        let mut open = access_302();
        open.body_head = "SSH-2.0-OpenSSH_10.5\r\n".into();
        let c = check_access(&FakeFetch(Some(open)), "u");
        assert!(!c.ok && c.detail.contains("DANGER"));

        let plain = Probe {
            status: 200,
            location: None,
            body_head: "<html>coucou</html>".into(),
        };
        let c = check_access(&FakeFetch(Some(plain)), "u");
        assert!(!c.ok && c.detail.contains("ne protège pas"));

        let elsewhere = Probe {
            status: 302,
            location: Some("https://autre.example/".into()),
            body_head: String::new(),
        };
        assert!(!check_access(&FakeFetch(Some(elsewhere)), "u").ok);
        assert!(!check_access(&FakeFetch(None), "u").ok);
    }

    #[test]
    fn launchagent_check_distinguishes_running_loaded_and_absent() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::new(t.path());
        let c = check_launchagent(&launchd(Ok(LAUNCHCTL_RUNNING.into())), &paths);
        assert!(c.ok && c.detail.contains("pid 95109"), "{c:?}");
        let waiting = check_launchagent(&launchd(Ok("state = waiting\n".into())), &paths);
        assert!(!waiting.ok && waiting.detail.contains("state = waiting"));
        let absent = check_launchagent(&launchd(Err("Could not find service".into())), &paths);
        assert!(!absent.ok && absent.detail.contains("absent"));
        fs::create_dir_all(paths.plist.parent().unwrap()).unwrap();
        fs::write(&paths.plist, "x").unwrap();
        let unloaded = check_launchagent(&launchd(Err("Could not find service".into())), &paths);
        assert!(!unloaded.ok && unloaded.detail.contains("pas chargé"));
    }

    #[test]
    fn journal_check_reads_the_log_file() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::new(t.path());
        assert!(!check_journal(&paths).ok);
        fs::create_dir_all(paths.log.parent().unwrap()).unwrap();
        fs::write(&paths.log, JOURNAL).unwrap();
        let c = check_journal(&paths);
        assert!(c.ok && c.detail.starts_with("4 connexion(s)"), "{c:?}");
    }

    fn put_key(paths: &Paths, authorized: &str) {
        fs::create_dir_all(&paths.ssh_dir).unwrap();
        fs::write(&paths.key, "PRIVEE").unwrap();
        set_mode(&paths.key, 0o600);
        fs::write(&paths.key_pub, "ssh-ed25519 AAAAFAKEBLOB ccp\n").unwrap();
        fs::write(&paths.authorized_keys, authorized).unwrap();
    }

    #[test]
    fn agents_key_check_requires_a_from_restriction() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::new(t.path());
        assert!(!check_agents_key(&paths).ok);
        put_key(
            &paths,
            &format!("autre ssh-rsa XXXX\n{KEY_OPTIONS} ssh-ed25519 AAAAFAKEBLOB ccp\n"),
        );
        let c = check_agents_key(&paths);
        assert!(c.ok, "{c:?}");
        put_key(&paths, "ssh-ed25519 AAAAFAKEBLOB ccp\n");
        let c = check_agents_key(&paths);
        assert!(!c.ok && c.detail.contains("SANS restriction"), "{c:?}");
        put_key(&paths, "autre ssh-rsa XXXX\n");
        assert!(check_agents_key(&paths)
            .detail
            .contains("n'est pas dans authorized_keys"));
        #[cfg(unix)]
        {
            put_key(
                &paths,
                &format!("{KEY_OPTIONS} ssh-ed25519 AAAAFAKEBLOB ccp\n"),
            );
            set_mode(&paths.key, 0o644);
            assert!(check_agents_key(&paths).detail.contains("chmod 600"));
        }
    }

    #[test]
    fn plist_matches_the_one_in_production() {
        let p = render_plist(
            "/opt/homebrew/bin/cloudflared",
            Path::new("/Users/s/.cloudflared/ccp-mac.token"),
            Path::new("/Users/s/Library/Logs/ccp/tunnel.log"),
        );
        for needle in [
            "<string>fr.atelier-sam.ccp-mac-tunnel</string>",
            "<string>/opt/homebrew/bin/cloudflared</string>",
            "<string>--no-autoupdate</string>",
            "<string>--token-file</string>",
            "<string>/Users/s/.cloudflared/ccp-mac.token</string>",
            "<key>KeepAlive</key>\n  <true/>",
            "<key>ThrottleInterval</key>\n  <integer>15</integer>",
        ] {
            assert!(p.contains(needle), "manque {needle}");
        }
        // Le jeton n'est JAMAIS dans le plist, seulement son chemin.
        assert!(!p.contains("eyJ"));
        let weird = render_plist("/a&b/<cf>", Path::new("/t"), Path::new("/l"));
        assert!(weird.contains("/a&amp;b/&lt;cf&gt;"));
    }

    fn deps<'a>(
        l: &'a FakeLaunchd,
        b: &'a FakeBanner,
        f: &'a FakeFetch,
        k: &'a FakeKeyGen,
    ) -> Deps<'a> {
        Deps {
            launchd: l,
            banner: b,
            fetch: f,
            keygen: k,
            access_url: "https://ssh-mac.atelier-sam.fr/".into(),
        }
    }

    #[test]
    fn all_green_gives_five_ok_lines_in_order() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::new(t.path());
        put_key(
            &paths,
            &format!("{KEY_OPTIONS} ssh-ed25519 AAAAFAKEBLOB ccp\n"),
        );
        fs::create_dir_all(paths.log.parent().unwrap()).unwrap();
        fs::write(&paths.log, JOURNAL).unwrap();
        let (l, b, f, k) = (
            launchd(Ok(LAUNCHCTL_RUNNING.into())),
            FakeBanner(Ok("SSH-2.0-OpenSSH_10.5".into())),
            FakeFetch(Some(access_302())),
            FakeKeyGen {
                made: RefCell::new(vec![]),
            },
        );
        let lines: Vec<String> = run_checks(&deps(&l, &b, &f, &k), &paths)
            .iter()
            .map(Check::line)
            .collect();
        let names: Vec<&str> = lines
            .iter()
            .map(|l| l.split('\t').nth(1).unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "sshd",
                "tunnel-launchagent",
                "tunnel-journal",
                "access",
                "cle-agents"
            ]
        );
        assert!(lines.iter().all(|l| l.starts_with("ok\t")), "{lines:#?}");
        assert!(lines.iter().all(|l| l.split('\t').count() == 3));
    }

    #[test]
    fn provision_creates_only_what_is_missing_and_is_idempotent() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::new(t.path());
        fs::create_dir_all(&paths.ssh_dir).unwrap();
        fs::write(&paths.authorized_keys, "ancienne ssh-rsa DEJALA").unwrap();
        let (l, b, f, k) = (
            launchd(Err("Could not find service".into())),
            FakeBanner(Err("x".into())),
            FakeFetch(None),
            FakeKeyGen {
                made: RefCell::new(vec![]),
            },
        );
        let d = deps(&l, &b, &f, &k);
        let mut said = Vec::new();
        provision(&d, &paths, &mut |m| said.push(m.to_string())).unwrap();
        assert_eq!(k.made.borrow().len(), 1);
        let ak = fs::read_to_string(&paths.authorized_keys).unwrap();
        assert!(
            ak.starts_with("ancienne ssh-rsa DEJALA\n"),
            "ligne existante intacte"
        );
        assert!(ak.contains(&format!(
            "{KEY_OPTIONS} ssh-ed25519 AAAAFAKEBLOB ccp-agents"
        )));
        // Pas de jeton de tunnel : marche à suivre, rien d'écrit côté LaunchAgent.
        assert!(said.iter().any(|m| m.contains("Marche à suivre")));
        assert!(said.iter().any(|m| m.contains("AVANT toute route DNS")));
        assert!(!paths.plist.exists() && l.boot.borrow().is_empty());

        // Deuxième passage : aucune création.
        let mut again = Vec::new();
        provision(&d, &paths, &mut |m| again.push(m.to_string())).unwrap();
        assert_eq!(k.made.borrow().len(), 1);
        assert_eq!(fs::read_to_string(&paths.authorized_keys).unwrap(), ak);
        assert!(!again
            .iter()
            .any(|m| m.contains("créée") || m.contains("ajoutée")));
    }

    #[test]
    fn provision_never_rewrites_an_unrestricted_existing_line() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::new(t.path());
        put_key(&paths, "ssh-ed25519 AAAAFAKEBLOB ccp\n");
        let (l, b, f, k) = (
            launchd(Ok(LAUNCHCTL_RUNNING.into())),
            FakeBanner(Err("x".into())),
            FakeFetch(None),
            FakeKeyGen {
                made: RefCell::new(vec![]),
            },
        );
        provision(&deps(&l, &b, &f, &k), &paths, &mut |_| {}).unwrap();
        assert_eq!(
            fs::read_to_string(&paths.authorized_keys).unwrap(),
            "ssh-ed25519 AAAAFAKEBLOB ccp\n"
        );
    }

    #[test]
    fn provision_loads_the_launchagent_when_the_token_exists() {
        let t = tempfile::tempdir().unwrap();
        let paths = Paths::new(t.path());
        put_key(
            &paths,
            &format!("{KEY_OPTIONS} ssh-ed25519 AAAAFAKEBLOB ccp\n"),
        );
        fs::create_dir_all(paths.token.parent().unwrap()).unwrap();
        fs::write(&paths.token, "jeton-factice").unwrap();
        let (l, b, f, k) = (
            launchd(Err("Could not find service".into())),
            FakeBanner(Err("x".into())),
            FakeFetch(None),
            FakeKeyGen {
                made: RefCell::new(vec![]),
            },
        );
        let mut said = Vec::new();
        let r = provision(&deps(&l, &b, &f, &k), &paths, &mut |m| {
            said.push(m.to_string())
        });
        // Sur une machine sans cloudflared installé, le plist n'est pas écrit : on le dit.
        if find_cloudflared().is_some() {
            r.unwrap();
            assert!(paths.plist.exists());
            assert_eq!(
                l.boot.borrow().as_slice(),
                std::slice::from_ref(&paths.plist)
            );
            let plist = fs::read_to_string(&paths.plist).unwrap();
            assert!(
                !plist.contains("jeton-factice"),
                "le jeton ne doit jamais être copié"
            );
        } else {
            r.unwrap();
            assert!(said.iter().any(|m| m.contains("cloudflared introuvable")));
        }
    }
}
