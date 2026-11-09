//! Interruption (Ctrl+C, fermeture de la fenêtre, SIGTERM) et Job Object.
//!
//! `remote share` doit TOUT retirer quoi qu'il arrive : un drapeau levé par le
//! gestionnaire de signal est lu par la boucle principale, qui exécute le nettoyage
//! normal (Drop) au lieu de mourir au milieu. Le Job Object (Windows) couvre le cas
//! où ccp-core lui-même est tué net : ses enfants (sshd, ssh) meurent avec lui.

use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

pub fn is_set() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

pub fn raise() {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
pub fn clear() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

#[cfg(unix)]
pub fn install() {
    extern "C" fn handler(_s: libc::c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }
    // SAFETY : le gestionnaire ne fait qu'une écriture atomique (async-signal-safe).
    unsafe {
        libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, handler as *const () as libc::sighandler_t);
    }
}

#[cfg(windows)]
pub fn install() {
    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn handler(ctrl: u32) -> BOOL {
        // 0 Ctrl+C · 1 Ctrl+Break · 2 fermeture de la fenêtre · 5 déconnexion · 6 arrêt du système.
        if matches!(ctrl, 0 | 1 | 2 | 5 | 6) {
            INTERRUPTED.store(true, Ordering::SeqCst);
            1
        } else {
            0
        }
    }
    // SAFETY : enregistre une routine `extern "system"` valide pour tout le processus.
    unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
}

#[cfg(not(any(unix, windows)))]
pub fn install() {}

/// Les processus enfants meurent avec ccp-core (Windows : Job Object « kill on close »).
#[cfg(windows)]
pub struct Job(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Job {
    pub fn new_kill_on_close() -> crate::error::Result<Job> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        // SAFETY : structures Win32 initialisées à zéro puis remplies ; la poignée est refermée par Drop.
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return Err(crate::error::CcpError::Internal(
                    "Job Object impossible à créer".into(),
                ));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                windows_sys::Win32::Foundation::CloseHandle(h);
                return Err(crate::error::CcpError::Internal(
                    "Job Object : kill-on-close refusé".into(),
                ));
            }
            Ok(Job(h))
        }
    }

    pub fn assign(&self, child: &std::process::Child) -> crate::error::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        // SAFETY : `child` vit pendant l'appel ; la poignée du Job est valide jusqu'au Drop.
        let ok = unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle()) };
        if ok == 0 {
            return Err(crate::error::CcpError::Internal(
                "processus impossible à rattacher au Job Object".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        // Fermer la dernière poignée tue les processus du Job (kill-on-close).
        // SAFETY : poignée créée par `new_kill_on_close`, refermée une seule fois.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

/// Hors Windows (hôte de test), pas de Job Object : le nettoyage normal suffit.
#[cfg(not(windows))]
pub struct Job;

#[cfg(not(windows))]
impl Job {
    pub fn new_kill_on_close() -> crate::error::Result<Job> {
        Ok(Job)
    }
    pub fn assign(&self, _child: &std::process::Child) -> crate::error::Result<()> {
        Ok(())
    }
}
