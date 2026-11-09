//! Tests d'intégration de `ccp-core remote` : le VRAI binaire contre un FAUX ssh, un FAUX
//! cloudflared (scripts sh) et, pour les téléchargements, un faux serveur HTTP local.
//!
//! Ce que ces tests prouvent :
//! - les arguments EXACTS que ssh reçoit (options strictes, destination, commande distante) ;
//! - que le `ProxyCommand` s'exécute vraiment, avec une racine pleine d'espaces et d'accents ;
//! - le format des lignes lues par le wizard et les codes de sortie ;
//! - le refus d'un cloudflared dont l'empreinte ne correspond pas à l'épingle ;
//! - le déroulé de `share` (consentement, enregistrement côté « Mac », Ctrl+C, nettoyage).
//!
//! Ce qu'ils ne prouvent pas : le comportement d'un vrai Win32-OpenSSH, ni l'élévation UAC.
//! La connexion RÉELLE par le tunnel se joue à la main (voir le rapport de phase 4).
#![cfg(unix)]

use ccp_core::remote::{conf, pins};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ccp-core");
const HOST: &str = pins::DEFAULT_HOST;

/// Racine volontairement hostile : espaces et accents (NFC).
struct Sb {
    dir: tempfile::TempDir,
}

fn platform() -> String {
    pins::platform_dir(std::env::consts::OS, std::env::consts::ARCH)
}

impl Sb {
    fn new() -> Sb {
        let dir = tempfile::tempdir().unwrap();
        for d in ["home", "tmp", "bin", "seen", "Ma clé USB/Écran été"] {
            std::fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        Sb { dir }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn root(&self) -> PathBuf {
        self.p("Ma clé USB/Écran été")
    }
    fn home(&self) -> PathBuf {
        self.p("home")
    }
    fn tmp(&self) -> PathBuf {
        self.p("tmp")
    }
    fn script(&self, rel: &str, body: &str) -> PathBuf {
        let p = self.p(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Faux cloudflared déjà « installé » (manifeste + empreintes cohérents) : aucun
    /// téléchargement. Il journalise ses arguments quand ssh l'appelle en `ProxyCommand`.
    fn seed_cloudflared(&self) -> PathBuf {
        let log = self.p("cloudflared.calls");
        let dir = self
            .root()
            .join("tools")
            .join("cloudflared")
            .join(platform());
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("cloudflared");
        let body = format!(
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"cloudflared version {tag} (built test)\"; exit 0; fi\n\
             echo \"$*\" >> \"{log}\"\necho SSH-2.0-FAKE\n",
            tag = pins::CLOUDFLARED_VERSION,
            log = log.display()
        );
        std::fs::write(&exe, &body).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let asset = pins::cloudflared_asset(std::env::consts::OS, std::env::consts::ARCH)
            .expect("plateforme épinglée");
        let bin_sha = hex(&Sha256::digest(body.as_bytes()));
        std::fs::write(
            dir.join("INSTALLED"),
            format!(
                "version={}\nsource_sha256={}\nbinary_sha256={bin_sha}\n",
                asset.tag, asset.sha256
            ),
        )
        .unwrap();
        log
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env_clear()
            .env("HOME", self.home())
            .env("USER", "testeur")
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("NO_COLOR", "1")
            .env("TMPDIR", self.tmp())
            .env("COMPUTERNAME", "PC-TEST")
            .arg("--root")
            .arg(self.root());
        c
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn s(o: &Output) -> (String, String, i32) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code().unwrap_or(-99),
    )
}

/// Arguments journalisés par un faux ssh (un par entrée, séparés par NUL).
fn argv(p: &Path) -> Vec<String> {
    let raw = std::fs::read(p).unwrap_or_default();
    raw.split(|b| *b == 0)
        .filter(|x| !x.is_empty())
        .map(|x| String::from_utf8_lossy(x).into_owned())
        .collect()
}

fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("délai dépassé : {what}");
}

/// Faux ssh : journalise l'argv, joue le ProxyCommand comme le ferait ssh (`%h` développé,
/// `sh -c`), puis exécute `behaviour`.
fn fake_ssh(sb: &Sb, behaviour: &str) -> PathBuf {
    let argv_log = sb.p("seen/ssh.argv");
    sb.script(
        "bin/ssh",
        &format!(
            r#": > "{log}"
for a in "$@"; do printf '%s\0' "$a" >> "{log}"; done
pc=""
for a in "$@"; do case "$a" in ProxyCommand=*) pc="${{a#ProxyCommand=}}";; esac; done
pc="$(printf '%s' "$pc" | sed 's/%h/{host}/g')"
if [ -n "$pc" ]; then sh -c "$pc" > "{proxy_out}" 2>&1 < /dev/null || exit 97; fi
{behaviour}"#,
            log = argv_log.display(),
            host = HOST,
            proxy_out = sb.p("seen/proxy.out").display(),
        ),
    )
}

fn known_hosts(sb: &Sb) -> PathBuf {
    sb.root().join("config/remote/known_hosts")
}

// ------------------------------------------------------------------- sessions

#[test]
fn sessions_prints_tab_lines_and_the_proxy_command_survives_spaces_and_accents() {
    let sb = Sb::new();
    let calls = sb.seed_cloudflared();
    let ssh = fake_ssh(
        &sb,
        r"printf 'Bienvenue sur le Mac\nCCP-SESSION:3:1:code-ui\nCCP-SESSION:1:0:autre\n'",
    );
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    let (out, err, code) = s(&o);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "code-ui\t3\t1\nautre\t1\t0\n");

    // Le ProxyCommand a VRAIMENT tourné, depuis une racine à espaces et accents.
    let called = std::fs::read_to_string(&calls).unwrap();
    assert_eq!(called.trim(), format!("access ssh --hostname {HOST}"));

    let a = argv(&sb.p("seen/ssh.argv"));
    assert_eq!(a[0], "-T");
    assert_eq!(a[1], "-F");
    assert_eq!(
        a[2],
        format!("{}/config/remote/ssh_config", sb.root().display())
    );
    for needle in [
        "StrictHostKeyChecking=yes".to_string(),
        "UpdateHostKeys=no".to_string(),
        "HostKeyAlgorithms=ssh-ed25519".to_string(),
        "PubkeyAuthentication=no".to_string(),
        "ProxyCommand=\"$CCP_CLOUDFLARED\" access ssh --hostname %h".to_string(),
        format!("UserKnownHostsFile=\"{}\"", known_hosts(&sb).display()),
    ] {
        assert!(a.contains(&needle), "manque {needle:?} dans {a:#?}");
    }
    assert!(a.contains(&format!("{}@{HOST}", pins::DEFAULT_USER)));
    assert!(a.last().unwrap().starts_with("/bin/bash -c '"), "{a:#?}");
    assert!(a.last().unwrap().ends_with("ccp-sessions"));

    // Clé d'hôte épinglée écrite avant la première connexion.
    let kh = std::fs::read_to_string(known_hosts(&sb)).unwrap();
    assert!(kh.contains(&pins::default_host_line()), "{kh}");
    // Aucun secret ni jeton dans les arguments de ssh.
    assert!(!a.iter().any(|x| x.to_lowercase().contains("token")));
}

#[test]
fn sessions_exit_codes_follow_the_contract() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    // Aucune session (le script distant sort 3) : 3 sans message en double.
    let ssh = fake_ssh(
        &sb,
        "echo 'Aucune session tmux ouverte sur le Mac.' >&2; exit 3",
    );
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    let (out, _err, code) = s(&o);
    assert_eq!((out.as_str(), code), ("", 3));

    // 255 = ssh lui-même a échoué (réseau, Access, clé d'hôte) : réseau.
    let ssh = fake_ssh(
        &sb,
        "echo 'kex_exchange_identification: Connection closed' >&2; exit 255",
    );
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    let (_, err, code) = s(&o);
    assert_eq!(code, 4);
    assert!(err.contains("connexion au Mac impossible"), "{err}");

    // Autre code (tmux absent = 127) : erreur interne, jamais un succès.
    let ssh = fake_ssh(&sb, "echo 'tmux est introuvable sur le Mac.' >&2; exit 127");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 10);

    // Sortie sans aucune ligne marquée : rien à lister.
    let ssh = fake_ssh(&sb, "echo 'Bienvenue'");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 3);
}

#[test]
fn an_unknown_host_is_refused_before_ssh_runs_and_a_bad_identity_too() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "exit 0");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions", "--host", "autre.example"])
        .output()
        .unwrap();
    let (_, err, code) = s(&o);
    assert_eq!(code, 2);
    assert!(err.contains("--accept-new-host-key"), "{err}");
    assert!(!sb.p("seen/ssh.argv").exists(), "ssh ne devait pas tourner");

    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions", "--identity", "/nulle/part/cle"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 2);

    // Un hôte qui ressemble à une option ssh est refusé net.
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions", "--host=-oProxyCommand=evil"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 2);
    assert!(!sb.p("seen/ssh.argv").exists());
}

#[test]
fn identity_and_accept_new_host_key_change_the_options() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "printf 'CCP-SESSION:1:0:x\\n'");
    let key = sb.p("ma clé agents");
    std::fs::write(&key, "FAUSSE-CLE").unwrap();
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args([
            "remote",
            "sessions",
            "--host",
            "autre.example",
            "--accept-new-host-key",
            "--identity",
        ])
        .arg(&key)
        .output()
        .unwrap();
    let (_, err, code) = s(&o);
    assert_eq!(code, 0, "{err}");
    let a = argv(&sb.p("seen/ssh.argv"));
    assert!(
        a.contains(&"StrictHostKeyChecking=accept-new".to_string()),
        "{a:#?}"
    );
    assert!(a.contains(&"IdentitiesOnly=yes".to_string()));
    let i = a.iter().position(|x| x == "-i").unwrap();
    assert_eq!(a[i + 1], key.to_string_lossy());
    assert!(a.contains(&format!("{}@autre.example", pins::DEFAULT_USER)));
}

// -------------------------------------------------------------------- connect

#[test]
fn connect_passes_the_session_name_quoted_and_propagates_the_exit_code() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "exit 7");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .stdin(Stdio::null())
        .args(["remote", "connect", "--session", "mon projet d'été"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 7);
    let a = argv(&sb.p("seen/ssh.argv"));
    // stdin n'est pas un terminal : `-tt` force l'allocation côté Mac.
    assert_eq!(a[0], "-tt");
    let last = a.last().unwrap();
    assert!(
        last.ends_with(" ccp-connect 'mon projet d'\\''été'"),
        "{last}"
    );
}

#[test]
fn the_portable_conf_file_sets_host_and_user_and_bad_values_are_refused() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "exit 0");
    std::fs::create_dir_all(sb.root().join("config")).unwrap();
    let conf = sb.root().join("config/remote.conf");
    std::fs::write(
        &conf,
        format!("# Mac de l'atelier\nhost = {HOST}\nuser = \"sam2\"\n"),
    )
    .unwrap();
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .stdin(Stdio::null())
        .args(["remote", "connect"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 0);
    assert!(argv(&sb.p("seen/ssh.argv")).contains(&format!("sam2@{HOST}")));
    // Les arguments de la ligne de commande priment sur le fichier.
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .stdin(Stdio::null())
        .args(["remote", "connect", "--user", "jean"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 0);
    assert!(argv(&sb.p("seen/ssh.argv")).contains(&format!("jean@{HOST}")));

    // Une valeur invalide est refusée en nommant le fichier et la ligne, ssh n'est pas relancé.
    std::fs::remove_file(sb.p("seen/ssh.argv")).unwrap();
    std::fs::write(&conf, format!("host = {HOST}\nuser = Jean Dupont\n")).unwrap();
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .stdin(Stdio::null())
        .args(["remote", "connect"])
        .output()
        .unwrap();
    let (_, err, code) = s(&o);
    assert_eq!(code, 2, "{err}");
    assert!(
        err.contains("remote.conf") && err.contains("ligne 2"),
        "{err}"
    );
    assert!(!sb.p("seen/ssh.argv").exists());
}

#[test]
fn connect_with_ssh_255_is_a_network_error() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "exit 255");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .stdin(Stdio::null())
        .args(["remote", "connect"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 4);
}

// ----------------------------------------------- jetons Access d'un ordinateur invité

const AUD: &str = "00d26537aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn seed_tokens(sb: &Sb) -> Vec<String> {
    let dir = sb.home().join(".cloudflared");
    std::fs::create_dir_all(&dir).unwrap();
    let names = vec![
        format!("{HOST}-{AUD}-token"),
        format!("{HOST}-{AUD}-token.lock"),
        "sam.cloudflareaccess.com-org-token".to_string(),
    ];
    for n in &names {
        std::fs::write(dir.join(n), "SECRET-DE-TEST").unwrap();
    }
    // Ce qui ne doit JAMAIS être touché.
    for keep in [
        "cert.pem",
        "ccp-mac.token",
        "autre.example-00d26537aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-token",
    ] {
        std::fs::write(dir.join(keep), "A-GARDER").unwrap();
    }
    names
}

fn remaining(sb: &Sb) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(sb.home().join(".cloudflared"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn mark_guest(sb: &Sb) {
    let h = Command::new("hostname").output().unwrap();
    let name = String::from_utf8_lossy(&h.stdout).trim().to_string();
    let dir = sb.root().join("config/.hosts");
    std::fs::create_dir_all(&dir).unwrap();
    for k in conf::host_keys(&name) {
        std::fs::write(dir.join(k), "guest\n").unwrap();
    }
}

#[test]
fn a_guest_computer_loses_its_access_tokens_after_connecting_and_nothing_else() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "printf 'CCP-SESSION:1:0:x\\n'");
    let all = seed_tokens(&sb);
    mark_guest(&sb);
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    let (_, err, code) = s(&o);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("3 jeton(s)"), "{err}");
    assert_eq!(
        remaining(&sb),
        vec![
            "autre.example-00d26537aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-token".to_string(),
            "ccp-mac.token".to_string(),
            "cert.pem".to_string()
        ]
    );
    assert_eq!(all.len(), 3);
}

#[test]
fn without_the_guest_marker_tokens_stay_unless_forget_is_given() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "printf 'CCP-SESSION:1:0:x\\n'");
    seed_tokens(&sb);
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 0);
    assert_eq!(remaining(&sb).len(), 6, "{:?}", remaining(&sb));

    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions", "--forget"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 0);
    assert_eq!(remaining(&sb).len(), 3);
}

#[test]
fn tokens_are_purged_even_when_the_connection_fails() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "exit 255");
    seed_tokens(&sb);
    mark_guest(&sb);
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 4);
    assert_eq!(remaining(&sb).len(), 3);
}

// ------------------------------------------- téléchargement : le contrôle négatif

fn http_garbage() -> (
    std::sync::Arc<tiny_http::Server>,
    u16,
    std::thread::JoinHandle<usize>,
) {
    let server = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
    let port = server.server_addr().to_ip().unwrap().port();
    let s2 = server.clone();
    let j = std::thread::spawn(move || {
        let mut n = 0;
        for rq in s2.incoming_requests() {
            n += 1;
            let _ = rq.respond(tiny_http::Response::from_string(
                "ceci n'est pas cloudflared",
            ));
        }
        n
    });
    (server, port, j)
}

#[test]
fn a_download_that_does_not_match_the_pinned_sha_is_refused_and_leaves_nothing() {
    let sb = Sb::new();
    let (server, port, join) = http_garbage();
    let ssh = fake_ssh(&sb, "printf 'CCP-SESSION:1:0:x\\n'");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .env("CCP_DOWNLOAD_BASE", format!("http://127.0.0.1:{port}"))
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    let (out, err, code) = s(&o);
    server.unblock();
    let hits = join.join().unwrap();
    assert!(hits >= 1, "le faux serveur n'a pas été interrogé");
    assert_eq!(code, 10, "{err}");
    assert!(err.contains("REFUSÉ"), "{err}");
    assert_eq!(out, "");
    assert!(
        !sb.p("seen/ssh.argv").exists(),
        "ssh ne devait JAMAIS tourner"
    );
    let dir = sb.root().join("tools/cloudflared").join(platform());
    let left: Vec<String> = std::fs::read_dir(&dir)
        .map(|r| {
            r.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(left.is_empty(), "restes après refus : {left:?}");
}

#[test]
fn a_tampered_installed_binary_is_not_trusted() {
    let sb = Sb::new();
    sb.seed_cloudflared();
    let (server, port, join) = http_garbage();
    // Le binaire déjà installé a changé depuis l'écriture du manifeste : il ne vaut plus rien,
    // on retélécharge (et ici le faux serveur ne peut pas servir la bonne empreinte).
    let exe = sb
        .root()
        .join("tools/cloudflared")
        .join(platform())
        .join("cloudflared");
    std::fs::write(&exe, "#!/bin/sh\necho piege\n").unwrap();
    let ssh = fake_ssh(&sb, "exit 0");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .env("CCP_DOWNLOAD_BASE", format!("http://127.0.0.1:{port}"))
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    server.unblock();
    let _ = join.join();
    let (_, err, code) = s(&o);
    assert_eq!(code, 10, "{err}");
    assert!(err.contains("REFUSÉ"), "{err}");
    assert!(!sb.p("seen/ssh.argv").exists());
}

#[test]
fn a_non_loopback_download_base_is_ignored() {
    let sb = Sb::new();
    // Cloudflared installé d'avance : si l'ignorance de la variable échouait, le test ne doit
    // JAMAIS partir télécharger le vrai binaire ni lancer un vrai tunnel.
    sb.seed_cloudflared();
    let ssh = fake_ssh(&sb, "exit 0");
    let o = sb
        .cmd()
        .env("CCP_SSH_BIN", &ssh)
        .env("CCP_DOWNLOAD_BASE", "http://evil.example")
        .args(["remote", "sessions"])
        .output()
        .unwrap();
    let (_, err, _) = s(&o);
    assert!(err.contains("CCP_DOWNLOAD_BASE ignorée"), "{err}");
}

/// Épreuve RÉELLE (réseau) : `cargo test -- --ignored real_cloudflared`.
/// Téléchargement du vrai cloudflared épinglé, puis contrôle négatif avec une empreinte altérée.
#[test]
#[ignore = "exige le réseau (github.com)"]
fn real_cloudflared_download_is_verified_and_an_altered_sha_is_refused() {
    use ccp_core::remote::{cloudflared, net::UreqFetch};
    let t = tempfile::tempdir().unwrap();
    let asset = pins::cloudflared_asset(std::env::consts::OS, std::env::consts::ARCH).unwrap();
    let fetch = UreqFetch::new();

    let mut altered = *asset;
    altered.sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    let bad = t.path().join("altere");
    let e = cloudflared::ensure(
        &bad,
        "cloudflared",
        &altered,
        pins::DEFAULT_DOWNLOAD_BASE,
        &fetch,
        &mut |_| {},
    )
    .unwrap_err();
    assert!(e.to_string().contains("REFUSÉ"), "{e}");
    let left: Vec<_> = std::fs::read_dir(&bad).unwrap().flatten().collect();
    assert!(left.is_empty(), "restes après refus : {left:?}");

    let good = t.path().join("bon");
    let inst = cloudflared::ensure(
        &good,
        "cloudflared",
        asset,
        pins::DEFAULT_DOWNLOAD_BASE,
        &fetch,
        &mut |_| {},
    )
    .unwrap();
    assert!(inst.exe.is_file());
    let v = Command::new(&inst.exe).arg("--version").output().unwrap();
    assert!(String::from_utf8_lossy(&v.stdout).contains(pins::CLOUDFLARED_VERSION));
}

// ------------------------------------------------------------------ setup-mac

#[cfg(target_os = "macos")]
#[test]
fn setup_mac_check_prints_one_line_per_control_and_exits_6_when_any_is_ko() {
    let sb = Sb::new();
    // Le « Cloudflare » du test : un 302 vers cloudflareaccess.com, sans bannière SSH.
    let server = std::sync::Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
    let port = server.server_addr().to_ip().unwrap().port();
    let s2 = server.clone();
    let j = std::thread::spawn(move || {
        for rq in s2.incoming_requests() {
            let h = tiny_http::Header::from_bytes(
                "Location",
                "https://sam.cloudflareaccess.com/cdn-cgi/access/login/ssh-mac.atelier-sam.fr",
            )
            .unwrap();
            let _ = rq.respond(tiny_http::Response::empty(302).with_header(h));
        }
    });
    // HOME vide : ni clé des agents, ni LaunchAgent, ni journal → des « ko ».
    let o = sb
        .cmd()
        .env("CCP_ACCESS_URL", format!("http://127.0.0.1:{port}/"))
        .args(["remote", "setup-mac", "--check"])
        .output()
        .unwrap();
    server.unblock();
    let _ = j.join();
    let (out, err, code) = s(&o);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 5, "{out}\n{err}");
    let mut names = vec![];
    for l in &lines {
        let f: Vec<&str> = l.split('\t').collect();
        assert_eq!(f.len(), 3, "{l:?}");
        assert!(f[0] == "ok" || f[0] == "ko", "{l:?}");
        assert!(!f[2].is_empty());
        names.push(f[1].to_string());
    }
    names.sort();
    assert_eq!(
        names,
        [
            "access",
            "cle-agents",
            "sshd",
            "tunnel-journal",
            "tunnel-launchagent"
        ]
    );
    let access = lines.iter().find(|l| l.contains("\taccess\t")).unwrap();
    assert!(access.starts_with("ok\t"), "{access}");
    let agents = lines.iter().find(|l| l.contains("\tcle-agents\t")).unwrap();
    assert!(agents.starts_with("ko\t"), "{agents}");
    assert_eq!(code, 6);
    // --check ne crée RIEN.
    assert!(!sb.home().join(".ssh").exists());
    assert!(!sb.home().join("Library").exists());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn setup_mac_is_refused_off_macos() {
    let sb = Sb::new();
    let o = sb
        .cmd()
        .args(["remote", "setup-mac", "--check"])
        .output()
        .unwrap();
    assert_eq!(s(&o).2, 2);
}

// ---------------------------------------------------------------------- share

#[test]
fn share_is_refused_off_windows() {
    let sb = Sb::new();
    let o = sb.cmd().args(["remote", "share"]).output().unwrap();
    let (out, err, code) = s(&o);
    assert_eq!(code, 2);
    assert_eq!(out, "");
    assert!(err.contains("Windows"), "{err}");
}

/// Un Mac et un Windows pour rire : faux ssh qui se comporte comme le script distant,
/// faux sshd et faux ssh-keygen.
struct ShareRig {
    sb: Sb,
    openssh: PathBuf,
}

impl ShareRig {
    fn new(ssh_behaviour: Option<&str>) -> ShareRig {
        let sb = Sb::new();
        sb.seed_cloudflared();
        let seen = sb.p("seen");
        sb.script(
            "openssh/ssh-keygen",
            r#"while [ $# -gt 0 ]; do if [ "$1" = "-f" ]; then f="$2"; fi; shift; done
echo FAUSSE-CLE-PRIVEE > "$f"
echo "ssh-ed25519 AAAAFAUSSECLEHOTE ccp-share-ephemere" > "$f.pub""#,
        );
        sb.script(
            "openssh/sshd",
            &format!(
                r#"while [ $# -gt 0 ]; do if [ "$1" = "-f" ]; then c="$2"; fi; shift; done
cp "$c" "{seen}/sshd_config"
cp "$(dirname "$c")/authorized_keys" "{seen}/authorized_keys"
echo $$ > "{seen}/sshd.pid"
echo "Server listening on 127.0.0.1 port 54022." >&2
exec sleep 120"#,
                seen = seen.display()
            ),
        );
        let default = format!(
            r#"echo "CCP-PUBKEY ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder12 ccp-agents"
echo "Allocated port 54321 for remote forward to 127.0.0.1:54022" >&2
IFS= read -r info
printf '%s\n' "$info" > "{seen}/client.json"
echo CCP-REGISTERED
cat > /dev/null
rm -f "{seen}/client.json""#,
            seen = seen.display()
        );
        fake_ssh(&sb, ssh_behaviour.unwrap_or(&default));
        let openssh = sb.p("openssh");
        ShareRig { sb, openssh }
    }

    fn spawn(&self, consent: &str) -> Child {
        let mut c = self
            .sb
            .cmd()
            .env("CCP_FAKE_WINDOWS", "1")
            .env("CCP_SSH_BIN", self.sb.p("bin/ssh"))
            .env("CCP_OPENSSH_DIR", &self.openssh)
            .args(["remote", "share"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Fermer l'entrée après la réponse : « pas de réponse » doit valoir « non », pas bloquer.
        let mut stdin = c.stdin.take().unwrap();
        stdin.write_all(consent.as_bytes()).unwrap();
        drop(stdin);
        c
    }

    fn staging_left(&self) -> Vec<String> {
        std::fs::read_dir(self.sb.tmp())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("ccp-share-"))
            .collect()
    }

    fn journal(&self) -> String {
        let dir = self.sb.root().join("logs");
        let mut all = String::new();
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            if e.file_name().to_string_lossy().starts_with("share-") {
                all.push_str(&std::fs::read_to_string(e.path()).unwrap());
            }
        }
        all
    }
}

fn finish(mut child: Child, secs: u64) -> Output {
    let end = Instant::now() + Duration::from_secs(secs);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() > end {
            let _ = child.kill();
            panic!(
                "ccp-core ne s'est pas arrêté : {:?}",
                child.wait_with_output().map(|o| s(&o))
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn share_full_session_registers_the_pc_then_cleans_everything_on_ctrl_c() {
    let rig = ShareRig::new(None);
    let child = rig.spawn("OUI\n");
    let pid = child.id();
    let client = rig.sb.p("seen/client.json");
    wait_for("enregistrement du PC côté faux Mac", 30, || {
        client.exists()
    });

    // Ce que le faux Mac a reçu.
    let info: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&client).unwrap()).unwrap();
    assert_eq!(info["port"], 54321);
    assert_eq!(info["pc"], "PC-TEST");
    assert_eq!(info["windows_user"], "testeur");
    assert_eq!(
        info["sshd_host_key"],
        "ssh-ed25519 AAAAFAUSSECLEHOTE ccp-share-ephemere"
    );

    // La config sshd temporaire : local, clés seules, utilisateur courant seulement.
    let cfg = std::fs::read_to_string(rig.sb.p("seen/sshd_config")).unwrap();
    for needle in [
        "ListenAddress 127.0.0.1\n",
        "PasswordAuthentication no\n",
        "AllowUsers \"testeur\"\n",
        "AllowTcpForwarding no\n",
    ] {
        assert!(cfg.contains(needle), "manque {needle:?}\n{cfg}");
    }
    let port_line = cfg
        .lines()
        .find(|l| l.starts_with("Port "))
        .unwrap()
        .to_string();
    let local_port: u16 = port_line.trim_start_matches("Port ").parse().unwrap();
    // authorized_keys : la clé des agents SEULE, sans relais.
    let ak = std::fs::read_to_string(rig.sb.p("seen/authorized_keys")).unwrap();
    assert!(
        ak.starts_with(
            "no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAAC3"
        ),
        "{ak}"
    );
    assert_eq!(ak.lines().count(), 1);
    // Le tunnel retour vise le port local choisi, sur 127.0.0.1.
    let a = argv(&rig.sb.p("seen/ssh.argv"));
    assert!(a.contains(&format!("0:127.0.0.1:{local_port}")), "{a:#?}");
    assert!(a.contains(&"ExitOnForwardFailure=yes".to_string()));
    assert!(a.contains(&"-T".to_string()));
    assert!(a.last().unwrap().ends_with(" ccp-share 'PC-TEST'"));
    // Le dossier de travail existe tant que le partage vit, PRIVÉ (ACL explicite).
    assert_eq!(rig.staging_left().len(), 1);
    {
        use std::os::unix::fs::PermissionsExt;
        let d = rig.sb.tmp().join(&rig.staging_left()[0]);
        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "dossier de travail lisible par d'autres");
        assert!(d.join("hostkey").exists() && d.join(".ccp-lock").exists());
    }
    let sshd_pid: i32 = std::fs::read_to_string(rig.sb.p("seen/sshd.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    // Ctrl+C.
    let k = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .unwrap();
    assert!(k.success());
    let o = finish(child, 30);
    let (out, err, code) = s(&o);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "");
    assert!(err.contains("PARTAGE ACTIF"), "{err}");
    assert!(err.contains("tout a été retiré"), "{err}");

    // Nettoyage complet.
    assert!(
        !client.exists(),
        "le fichier client côté Mac doit disparaître"
    );
    assert!(rig.staging_left().is_empty(), "{:?}", rig.staging_left());
    assert!(!is_alive(sshd_pid), "sshd doit être mort");
    let j = rig.journal();
    for needle in [
        "consentement donné",
        "sshd lancé",
        "port alloué sur le Mac : 54321",
        "PC enregistré",
        "interruption demandée",
        "nettoyage terminé",
    ] {
        assert!(j.contains(needle), "journal sans {needle:?}\n{j}");
    }
}

fn is_alive(pid: i32) -> bool {
    // `kill -0` : simple test d'existence, sans dépendre de libc dans les tests.
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn share_without_an_explicit_oui_does_nothing() {
    let rig = ShareRig::new(None);
    for answer in ["non\n", "oui\n", "\n", ""] {
        let child = rig.spawn(answer);
        let o = finish(child, 30);
        let (out, err, code) = s(&o);
        assert_eq!(code, 0, "{err}");
        assert_eq!(out, "");
        assert!(
            err.contains("EXÉCUTER DES"),
            "le consentement doit être affiché : {err}"
        );
        assert!(err.contains("Annulé"), "{err}");
    }
    assert!(
        !rig.sb.p("seen/ssh.argv").exists(),
        "ssh ne devait jamais tourner"
    );
    assert!(
        !rig.sb.root().join("logs").exists(),
        "aucun journal sans consentement"
    );
    assert!(rig.staging_left().is_empty());
}

#[test]
fn share_fails_cleanly_when_the_connection_to_the_mac_drops_early() {
    let rig = ShareRig::new(Some("sleep 0.3; exit 255"));
    let o = finish(rig.spawn("OUI\n"), 30);
    let (_, err, code) = s(&o);
    assert_eq!(code, 4, "{err}");
    assert!(rig.staging_left().is_empty());
    assert!(
        !rig.sb.p("seen/sshd.pid").exists(),
        "sshd ne démarre qu'avec la clé des agents"
    );
}

#[test]
fn share_refuses_an_agent_key_that_carries_options_and_never_starts_sshd() {
    let rig = ShareRig::new(Some(
        r#"echo 'CCP-PUBKEY command="touch /tmp/pwned" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder12'
cat > /dev/null"#,
    ));
    let o = finish(rig.spawn("OUI\n"), 30);
    let (_, err, code) = s(&o);
    assert_eq!(code, 10, "{err}");
    assert!(err.contains("forme attendue"), "{err}");
    assert!(!rig.sb.p("seen/sshd.pid").exists());
    assert!(rig.staging_left().is_empty());
}

#[test]
fn share_with_a_dying_sshd_reports_it_and_cleans_up() {
    let rig = ShareRig::new(None);
    rig.sb.script(
        "openssh/sshd",
        r#"echo "fatal: Cannot bind any address." >&2; exit 255"#,
    );
    let o = finish(rig.spawn("OUI\n"), 30);
    let (_, err, code) = s(&o);
    assert_eq!(code, 10, "{err}");
    assert!(err.contains("sshd s'est arrêté"), "{err}");
    assert!(rig.staging_left().is_empty());
}

#[test]
fn share_sweeps_orphan_staging_of_a_killed_session_but_leaves_a_live_one_alone() {
    let rig = ShareRig::new(None);
    let tmp = rig.sb.tmp();
    // Orphelin : un partage précédent tué net a laissé sa clé d'hôte (verrou libre).
    let orphan = tmp.join("ccp-share-mort-1-0");
    std::fs::create_dir_all(&orphan).unwrap();
    std::fs::write(orphan.join(".ccp-lock"), "").unwrap();
    std::fs::write(orphan.join("hostkey"), "CLE-PRIVEE-OUBLIEE").unwrap();
    // Vivant : un autre partage, dans une autre fenêtre, tient son verrou.
    let live = tmp.join("ccp-share-vivant-2-0");
    std::fs::create_dir_all(&live).unwrap();
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(live.join(".ccp-lock"))
        .unwrap();
    held.try_lock().expect("verrou de test");

    let mut child = rig.spawn("OUI\n");
    let client = rig.sb.p("seen/client.json");
    wait_for("enregistrement du PC", 30, || client.exists());
    assert!(!orphan.exists(), "l'orphelin doit être effacé au démarrage");
    assert!(live.exists(), "un partage vivant n'est jamais touché");
    let _ = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status();
    let o = finish_child(&mut child, 30);
    let (_, err, code) = s(&o);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("1 dossier(s) de travail orphelin(s)"), "{err}");
    assert!(rig.journal().contains("orphelin"), "{}", rig.journal());
    assert!(live.exists());
    drop(held);
}

/// `finish` consomme l'enfant ; ici on a besoin de le garder pour `kill`.
fn finish_child(child: &mut Child, secs: u64) -> Output {
    let end = Instant::now() + Duration::from_secs(secs);
    while child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < end, "ccp-core ne s'est pas arrêté");
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut out = Output {
        status: child.wait().unwrap(),
        stdout: vec![],
        stderr: vec![],
    };
    use std::io::Read;
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_end(&mut out.stdout);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_end(&mut out.stderr);
    }
    out
}

#[test]
fn share_never_claims_everything_was_removed_when_the_cleanup_failed() {
    use std::os::unix::fs::PermissionsExt;
    // Root contourne les droits : le scénario n'aurait aucun sens.
    if Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
    {
        return;
    }
    let rig = ShareRig::new(None);
    let seen = rig.sb.p("seen");
    // Le faux sshd laisse dans le dossier de travail un sous-dossier non effaçable.
    rig.sb.script(
        "openssh/sshd",
        &format!(
            r#"while [ $# -gt 0 ]; do if [ "$1" = "-f" ]; then c="$2"; fi; shift; done
d="$(dirname "$c")"
mkdir "$d/verrouille" && echo x > "$d/verrouille/x" && chmod 500 "$d/verrouille"
echo "$d" > "{seen}/staging.path"
echo "Server listening on 127.0.0.1 port 54022." >&2
exec sleep 120"#,
            seen = seen.display()
        ),
    );
    let mut child = rig.spawn("OUI\n");
    let client = rig.sb.p("seen/client.json");
    wait_for("enregistrement du PC", 30, || client.exists());
    let _ = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status();
    let o = finish_child(&mut child, 30);
    let (_, err, code) = s(&o);
    let staging = PathBuf::from(
        std::fs::read_to_string(seen.join("staging.path"))
            .unwrap()
            .trim(),
    );

    assert_eq!(
        code, 10,
        "un nettoyage incomplet n'est pas un succès : {err}"
    );
    assert!(
        !err.contains("tout a été retiré"),
        "faux message de succès : {err}"
    );
    assert!(err.contains("TOUT N'A PAS ÉTÉ RETIRÉ"), "{err}");
    assert!(err.contains("dossier de travail non effacé"), "{err}");
    assert!(staging.exists(), "le dossier est bien resté");
    assert!(
        rig.journal().contains("nettoyage INCOMPLET"),
        "{}",
        rig.journal()
    );

    // Le reste est repris au prochain partage : droits rétablis, il est balayé.
    std::fs::set_permissions(
        staging.join("verrouille"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let mut child = rig.spawn("OUI\n");
    wait_for("enregistrement du PC (2e)", 30, || client.exists());
    assert!(!staging.exists(), "orphelin balayé au démarrage suivant");
    let _ = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status();
    let o = finish_child(&mut child, 30);
    let (_, err, _) = s(&o);
    assert!(err.contains("1 dossier(s) de travail orphelin(s)"), "{err}");
}
