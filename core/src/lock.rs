//! Verrou de session d'un profil (`<cfg>/.ccp-session.lock`).
//!
//! Verrou OS (flock / LockFileEx) : il disparaît tout seul à la mort du
//! processus, y compris sur une clé USB qu'on arrache (pas de pid fantôme, pas de
//! péremption par âge). `run` le tient pendant TOUTE la vie de Claude ; un
//! renouvellement de jeton prend le MÊME verrou en try-lock : jamais de
//! renouvellement pendant une session (Claude lirait un refresh token déjà
//! tourné), jamais de session lancée au milieu d'un renouvellement.
//!
//! Pour que `run` distingue « autre fenêtre ouverte » (refus, code 5) de
//! « renouvellement en cours » (on attend quelques secondes), le renouvellement
//! pose en plus un marqueur `.ccp-renewing` (simple fichier daté, informatif).

use crate::error::{CcpError, Result};
use crate::root::ProfileDir;
use std::fs::{File, OpenOptions, TryLockError};
use std::time::{Duration, SystemTime};

pub struct SessionGuard {
    // Tenu pour sa durée de vie : fermer le fichier libère le verrou.
    _file: Option<File>,
}

pub enum Acquire {
    Got(SessionGuard),
    /// Quelqu'un d'autre tient le verrou.
    Busy,
    /// Le volume ne sait pas verrouiller (certains montages réseau) : on ne
    /// peut ni protéger une session ni renouveler sans risque.
    Unsupported(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockState {
    Free,
    /// Une session `run` (ou autre détenteur) tient le verrou.
    Session,
    /// Un renouvellement de jeton est en cours.
    Renewing,
}

const RENEWING_MAX_AGE: Duration = Duration::from_secs(30);

fn open_lock(p: &ProfileDir) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(p.session_lock())
}

pub fn try_acquire(p: &ProfileDir) -> Acquire {
    let f = match open_lock(p) {
        Ok(f) => f,
        Err(e) => return Acquire::Unsupported(format!("verrou de session illisible : {e}")),
    };
    match f.try_lock() {
        Ok(()) => Acquire::Got(SessionGuard { _file: Some(f) }),
        Err(TryLockError::WouldBlock) => Acquire::Busy,
        Err(TryLockError::Error(e)) => {
            Acquire::Unsupported(format!("verrou indisponible sur ce volume : {e}"))
        }
    }
}

fn renewing_fresh(p: &ProfileDir) -> bool {
    std::fs::metadata(p.renewing_marker())
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < RENEWING_MAX_AGE)
}

/// Qui tient le verrou ? Lecture seule : ne crée aucun fichier.
pub fn state(p: &ProfileDir) -> LockState {
    let Ok(f) = OpenOptions::new().read(true).open(p.session_lock()) else {
        return LockState::Free;
    };
    // Un verrou PARTAGÉ échoue contre un exclusif et réussit contre un autre
    // partagé : deux `status` simultanés ne se voient pas comme « occupé ».
    match f.try_lock_shared() {
        Ok(()) => {
            let _ = f.unlock();
            LockState::Free
        }
        Err(TryLockError::WouldBlock) => {
            if renewing_fresh(p) {
                LockState::Renewing
            } else {
                LockState::Session
            }
        }
        Err(TryLockError::Error(_)) => LockState::Free,
    }
}

/// Marqueur « renouvellement en cours », retiré à la destruction.
pub struct RenewingMark<'a> {
    p: &'a ProfileDir,
}

impl<'a> RenewingMark<'a> {
    pub fn set(p: &'a ProfileDir) -> Self {
        let _ = std::fs::write(p.renewing_marker(), b"");
        RenewingMark { p }
    }
}

impl Drop for RenewingMark<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.p.renewing_marker());
    }
}

/// Verrou pour `run`. Un renouvellement concurrent est attendu (≤ 15 s) ; un
/// détenteur de session est refusé après une courte confirmation (un `status`
/// simultané ne tient son verrou partagé que quelques microsecondes).
pub fn acquire_for_run(p: &ProfileDir) -> Result<SessionGuard> {
    let start = std::time::Instant::now();
    let mut quick_retries = 0;
    loop {
        match try_acquire(p) {
            Acquire::Got(g) => return Ok(g),
            Acquire::Unsupported(why) => {
                eprintln!("ccp-core : {why} — session lancée sans verrou (renouvellement automatique désactivé pour ce profil).");
                return Ok(SessionGuard { _file: None });
            }
            Acquire::Busy => {
                if renewing_fresh(p) && start.elapsed() < Duration::from_secs(15) {
                    std::thread::sleep(Duration::from_millis(200));
                } else if quick_retries < 4 {
                    quick_retries += 1;
                    std::thread::sleep(Duration::from_millis(120));
                } else {
                    return Err(CcpError::SessionBusy(
                        "ce compte est déjà ouvert dans une autre fenêtre".into(),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::{PathStyle, Profile, Root};

    fn pdir(t: &tempfile::TempDir) -> ProfileDir {
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let p = r.profile(&Profile::parse("p").unwrap());
        std::fs::create_dir_all(&p.dir).unwrap();
        p
    }

    #[test]
    fn exclusive_excludes_everyone_and_releases_on_drop() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        assert_eq!(state(&p), LockState::Free);
        let Acquire::Got(g) = try_acquire(&p) else {
            panic!("verrou attendu")
        };
        assert!(matches!(try_acquire(&p), Acquire::Busy));
        assert_eq!(state(&p), LockState::Session);
        drop(g);
        assert_eq!(state(&p), LockState::Free);
        assert!(matches!(try_acquire(&p), Acquire::Got(_)));
    }

    #[test]
    fn renewing_marker_changes_the_reported_state() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        let Acquire::Got(_g) = try_acquire(&p) else {
            panic!()
        };
        {
            let _m = RenewingMark::set(&p);
            assert_eq!(state(&p), LockState::Renewing);
        }
        assert_eq!(state(&p), LockState::Session);
    }

    #[test]
    fn status_style_shared_probes_do_not_block_each_other_or_run() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        // `state` n'est pas un détenteur durable : `run` obtient le verrou juste après.
        assert_eq!(state(&p), LockState::Free);
        assert!(matches!(try_acquire(&p), Acquire::Got(_)));
    }

    #[test]
    fn run_acquire_refuses_a_held_session_with_code_5() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        let _held = match try_acquire(&p) {
            Acquire::Got(g) => g,
            _ => panic!(),
        };
        let err = acquire_for_run(&p).err().expect("refus attendu");
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("déjà ouvert"));
    }
}
