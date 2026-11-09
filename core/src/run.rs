//! `run` : lance Claude sur un profil et en garde la responsabilité.
//!
//! - verrou de session exclusif pendant TOUTE la vie de Claude (code 5 si le
//!   profil est déjà ouvert ailleurs) : un renouvellement de jeton ne peut pas
//!   se produire sous une session, ni l'inverse ;
//! - journal de renouvellement éventuel rejoué avant le lancement ;
//! - environnement : `CLAUDE_CONFIG_DIR`, `DISABLE_AUTOUPDATER=1`, et
//!   `CLAUDE_CODE_OAUTH_TOKEN` SEULEMENT pour un profil qui n'a qu'un `oauth.token` ;
//! - Ctrl+C : le wizard bash ignore SIGINT (`trap '' INT`) et un SIGINT ignoré
//!   est HÉRITÉ par les enfants -> on le rétablit à la valeur par défaut dans
//!   l'enfant, et on l'ignore dans le parent tant que l'enfant vit (Ctrl+C va à
//!   Claude, pas au wrapper) ;
//! - SIGTERM / SIGHUP reçus par le wrapper sont transmis à Claude ;
//! - le code de sortie de Claude est propagé ;
//! - volume monté sans exécution (clé exFAT `noexec`) : copie unique du binaire
//!   dans `~/.cache/claude-portable/<version>/<plateforme>/`.

use crate::env::Env;
use crate::error::{CcpError, Result};
use crate::lock;
use crate::oauth;
#[cfg(unix)]
use crate::root::claude_platform;
use crate::root::{Profile, ProfileDir, Root};
use crate::status::{self, Deps, ProbeOpts};
use crate::{creds, timefmt};
use secrecy::ExposeSecret;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::Duration;

pub struct RunOpts {
    pub profile: Profile,
    pub claude: PathBuf,
    pub args: Vec<OsString>,
}

/// Quel jeton passer à Claude ? `Some` seulement si le profil n'a QUE `oauth.token`.
/// Un login présent prime : lui donner en plus la variable ferait ignorer le
/// login par Claude et masquerait l'état réel du compte.
fn token_for_child(env: &Env, p: &ProfileDir) -> Option<secrecy::SecretString> {
    let token = creds::read_token(p)?;
    match creds::read_login(env, p) {
        Ok(Some(l)) if l.blob.has_login() => None,
        Ok(_) => Some(token),
        Err(e) => {
            eprintln!(
                "ccp-core : magasin de ce profil illisible ({e}) : le jeton longue durée n'est pas transmis."
            );
            None
        }
    }
}

fn build_command(env: &Env, p: &ProfileDir, exe: &Path, args: &[OsString]) -> Command {
    let mut c = Command::new(exe);
    c.args(args)
        .env("CLAUDE_CONFIG_DIR", &p.cfg)
        .env("DISABLE_AUTOUPDATER", "1");
    match token_for_child(env, p) {
        Some(t) => {
            c.env("CLAUDE_CODE_OAUTH_TOKEN", t.expose_secret());
        }
        None => {
            c.env_remove("CLAUDE_CODE_OAUTH_TOKEN");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY : `signal` est async-signal-safe et n'alloue pas ; appelé entre
        // fork et exec uniquement pour rétablir SIGINT par défaut.
        unsafe {
            c.pre_exec(|| {
                libc::signal(libc::SIGINT, libc::SIG_DFL);
                Ok(())
            });
        }
    }
    c
}

/// Copie unique du binaire hors du volume `noexec` (Unix : sous Windows il n'y a pas de bit d'exécution).
#[cfg(unix)]
fn noexec_copy(env: &Env, root: &Root, src: &Path) -> std::io::Result<PathBuf> {
    let version = std::fs::read_to_string(root.path().join("VERSION"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && !v.contains(['/', '\\']))
        .unwrap_or_else(|| "inconnue".to_string());
    let dir = env
        .home
        .join(".cache")
        .join("claude-portable")
        .join(version)
        .join(claude_platform());
    let dest = dir.join(src.file_name().unwrap_or_else(|| "claude".as_ref()));
    let want = std::fs::metadata(src)?.len();
    if std::fs::metadata(&dest).is_ok_and(|m| m.len() == want) {
        return Ok(dest);
    }
    eprintln!(
        "ccp-core : ce volume interdit l'exécution — copie unique de Claude dans {} …",
        dir.display()
    );
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join(".copie-en-cours");
    std::fs::copy(src, &tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, &dest)?;
    Ok(dest)
}

#[cfg(unix)]
fn ensure_exec_bit(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(m) = std::fs::metadata(path) {
        let mode = m.permissions().mode();
        if mode & 0o111 == 0 {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o755));
        }
    }
}

fn spawn_with_fallback(env: &Env, root: &Root, p: &ProfileDir, opts: &RunOpts) -> Result<Child> {
    // `root` ne sert qu'à la copie de repli `noexec`, qui n'existe que sous Unix.
    #[cfg(not(unix))]
    let _ = root;
    #[cfg(unix)]
    ensure_exec_bit(&opts.claude);
    match build_command(env, p, &opts.claude, &opts.args).spawn() {
        Ok(c) => Ok(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(CcpError::NotFound(format!(
            "binaire Claude introuvable : {}",
            opts.claude.display()
        ))),
        #[cfg(unix)]
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            let copy = noexec_copy(env, root, &opts.claude).map_err(|e2| {
                CcpError::Internal(format!(
                    "exécution refusée ({e}) et copie de repli impossible : {e2}"
                ))
            })?;
            build_command(env, p, &copy, &opts.args)
                .spawn()
                .map_err(|e3| CcpError::Internal(format!("lancement de Claude impossible : {e3}")))
        }
        Err(e) => Err(CcpError::Internal(format!(
            "lancement de Claude impossible : {e}"
        ))),
    }
}

// ------------------------------------------------------------------ signaux

#[cfg(unix)]
pub(crate) mod sig {
    use std::sync::atomic::{AtomicI32, Ordering};

    static CHILD: AtomicI32 = AtomicI32::new(0);
    /// Signal reçu avant que l'enfant existe : retransmis dès son lancement.
    static PENDING: AtomicI32 = AtomicI32::new(0);

    extern "C" fn forward(s: libc::c_int) {
        let pid = CHILD.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY : kill est async-signal-safe.
            unsafe { libc::kill(pid, s) };
        } else {
            PENDING.store(s, Ordering::SeqCst);
        }
    }

    /// Le parent ignore Ctrl+C (il va à Claude) et transmet TERM/HUP.
    pub fn install() {
        // SAFETY : handlers minimaux, sans allocation.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGTERM, forward as *const () as libc::sighandler_t);
            libc::signal(libc::SIGHUP, forward as *const () as libc::sighandler_t);
        }
    }

    pub fn child_started(pid: u32) {
        CHILD.store(pid as i32, Ordering::SeqCst);
        let s = PENDING.swap(0, Ordering::SeqCst);
        if s != 0 {
            // SAFETY : pid d'un enfant qu'on vient de lancer.
            unsafe { libc::kill(pid as i32, s) };
        }
    }

    /// Après la mort de l'enfant : Ctrl+C redevient mortel pour le wrapper
    /// (la sonde finale ne doit pas être impossible à interrompre).
    pub fn restore() {
        CHILD.store(0, Ordering::SeqCst);
        // SAFETY : rétablit les dispositions par défaut.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
        }
    }
}

#[cfg(windows)]
pub(crate) mod sig {
    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    /// Un gestionnaire (pas `SetConsoleCtrlHandler(NULL, TRUE)`) : l'option
    /// « ignorer Ctrl+C » de cette dernière forme serait HÉRITÉE par Claude.
    /// Le gestionnaire, lui, ne l'est pas : Claude reçoit Ctrl+C normalement.
    unsafe extern "system" fn handler(ctrl: u32) -> BOOL {
        // CTRL_C_EVENT = 0, CTRL_BREAK_EVENT = 1 : traités ici = le wrapper survit.
        if ctrl <= 1 {
            1
        } else {
            0
        }
    }

    pub fn install() {
        // SAFETY : enregistre une routine `extern "system"` valide pour tout le processus.
        unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
    }
    pub fn child_started(_pid: u32) {}
    pub fn restore() {
        // SAFETY : retire la routine enregistrée par `install`.
        unsafe { SetConsoleCtrlHandler(Some(handler), 0) };
    }
}

#[cfg(unix)]
fn exit_code(st: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
}

#[cfg(not(unix))]
fn exit_code(st: ExitStatus) -> i32 {
    st.code().unwrap_or(1)
}

/// Lance Claude ; renvoie son code de sortie.
pub fn run(env: &Env, deps: &Deps, root: &Root, opts: &RunOpts) -> Result<i32> {
    let p = root.profile(&opts.profile);
    // Un nouveau profil (« Ajouter un compte ») n'a pas encore de dossier.
    std::fs::create_dir_all(&p.dir)
        .map_err(|e| CcpError::Internal(format!("dossier du profil impossible à créer : {e}")))?;

    let guard = lock::acquire_for_run(&p)?;
    // Un renouvellement interrompu avant nous (processus tué entre la réponse du
    // serveur et l'écriture) est rejoué MAINTENANT : Claude lirait sinon un
    // refresh token déjà tourné.
    if let oauth::Replay::Failed(m) = oauth::replay_pending_locked(env, &p, &guard) {
        eprintln!("ccp-core : renouvellement interrompu non rejoué ({m}) ; les jetons restent dans .ccp-pending.");
    }

    sig::install();
    let mut child = match spawn_with_fallback(env, root, &p, opts) {
        Ok(c) => c,
        Err(e) => {
            sig::restore();
            return Err(e);
        }
    };
    sig::child_started(child.id());
    let status = child.wait();
    sig::restore();
    let code = match status {
        Ok(st) => exit_code(st),
        Err(e) => {
            return Err(CcpError::Internal(format!(
                "attente de Claude impossible : {e}"
            )))
        }
    };

    // Libère le profil AVANT la sonde : un jeton expiré pendant la session peut
    // alors être renouvelé proprement, et un autre wizard peut ouvrir le compte.
    drop(guard);
    post_run_probe(deps, root, &p);
    Ok(code)
}

/// Sonde rapide après la session : l'accueil montre des quotas à jour au retour.
/// Meilleur effort, bornée, jamais bloquante pour le code de sortie.
fn post_run_probe(deps: &Deps, root: &Root, p: &ProfileDir) {
    let opts = ProbeOpts {
        refresh: true,
        offline: false,
        max_age_s: 0,
        budget: Duration::from_secs(4),
    };
    let active = root.active_profile();
    let st = status::probe_all(deps, std::slice::from_ref(p), &active, &opts);
    if let Some(s) = st.first() {
        if matches!(s.state, crate::model::State::Revoked) {
            eprintln!(
                "ccp-core : le compte « {} » doit être reconnecté ({}).",
                s.name,
                timefmt::hhmm(crate::env::now_s(), &jiff::tz::TimeZone::system())
            );
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::root::PathStyle;

    fn fx() -> (tempfile::TempDir, Env, Root, ProfileDir) {
        let t = tempfile::tempdir().unwrap();
        let root = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let p = root.profile(&Profile::parse("1").unwrap());
        std::fs::create_dir_all(&p.dir).unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        (t, env, root, p)
    }

    fn env_of(c: &Command, key: &str) -> Option<Option<String>> {
        c.get_envs()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.map(|s| s.to_string_lossy().into_owned()))
    }

    #[test]
    fn token_only_profile_gets_the_token_variable() {
        let (_t, env, _r, p) = fx();
        std::fs::write(p.token_file(), "sk-ant-oat01-abc\n").unwrap();
        let c = build_command(&env, &p, Path::new("/bin/true"), &[]);
        assert_eq!(
            env_of(&c, "CLAUDE_CODE_OAUTH_TOKEN"),
            Some(Some("sk-ant-oat01-abc".into()))
        );
        assert_eq!(env_of(&c, "DISABLE_AUTOUPDATER"), Some(Some("1".into())));
        assert_eq!(env_of(&c, "CLAUDE_CONFIG_DIR"), Some(Some(p.cfg.clone())));
    }

    #[test]
    fn a_login_wins_over_a_stray_token_file() {
        let (_t, env, _r, p) = fx();
        std::fs::write(p.token_file(), "sk-ant-oat01-abc").unwrap();
        std::fs::write(
            p.credentials_file(),
            r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"r","expiresAt":1}}"#,
        )
        .unwrap();
        let c = build_command(&env, &p, Path::new("/bin/true"), &[]);
        assert_eq!(
            env_of(&c, "CLAUDE_CODE_OAUTH_TOKEN"),
            Some(None),
            "variable RETIRÉE, pas vide"
        );
    }

    #[test]
    fn inherited_token_variable_is_removed_when_no_token_file() {
        let (_t, env, _r, p) = fx();
        let c = build_command(&env, &p, Path::new("/bin/true"), &[]);
        assert_eq!(env_of(&c, "CLAUDE_CODE_OAUTH_TOKEN"), Some(None));
    }

    #[test]
    fn noexec_copy_is_made_once_and_reused() {
        let (t, env, root, _p) = fx();
        std::fs::write(root.path().join("VERSION"), "2.1.319\n").unwrap();
        let src = t.path().join("claude");
        std::fs::write(&src, b"#!/bin/sh\necho hi\n").unwrap();
        let a = noexec_copy(&env, &root, &src).unwrap();
        assert!(a.to_string_lossy().contains("2.1.319"));
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&src).unwrap());
        let m1 = std::fs::metadata(&a).unwrap().modified().unwrap();
        let b = noexec_copy(&env, &root, &src).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            std::fs::metadata(&b).unwrap().modified().unwrap(),
            m1,
            "pas de seconde copie"
        );
    }

    #[test]
    fn exit_code_of_a_signal_is_128_plus_signal() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(exit_code(ExitStatus::from_raw(2)), 130);
        assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
    }
}
