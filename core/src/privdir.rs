//! Dossiers de travail PRIVÉS et jetables (`ccp-share-*`, `ccp-odt-*`).
//!
//! Ils reçoivent des choses sensibles (clé d'hôte éphémère, binaires qu'on va
//! exécuter, parfois avec des droits élevés) : personne d'autre que l'utilisateur
//! ne doit pouvoir y écrire entre le moment où on y dépose un fichier et celui où
//! on l'exécute. D'où :
//!
//! - création avec une ACL EXPLICITE (Unix : mode 0700 posé à la création, sans
//!   fenêtre `mkdir` puis `chmod` ; Windows : DACL protégée, utilisateur courant et
//!   SYSTEM seulement, héritée par tout ce qu'on y crée) ;
//! - un fichier verrou `.ccp-lock` tenu pendant toute la vie du dossier : le système
//!   le libère à la mort du processus, même tué net, ce qui permet à
//!   [`sweep_orphans`] de distinguer un dossier ORPHELIN d'un dossier VIVANT (un
//!   second partage dans une autre fenêtre) sans lire de pid ;
//! - [`PrivateDir::finish`] vérifie l'effacement (avec reprises : sous Windows un
//!   processus tué libère ses fichiers avec un léger retard) et renvoie l'échec au
//!   lieu de l'avaler, pour qu'on ne prétende jamais avoir « tout retiré » à tort.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const LOCK_NAME: &str = ".ccp-lock";

/// Un dossier sans verrou plus récent que ça est peut-être en cours de création.
const FRESH_WITHOUT_LOCK: Duration = Duration::from_secs(120);

/// Reprises de l'effacement (≈ 1,5 s au total).
pub const DEFAULT_BACKOFF: &[Duration] = &[
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
];

/// Crée UN dossier (le parent doit exister) avec l'ACL privée. Échoue
/// (`AlreadyExists`) si le nom est pris : on ne réutilise jamais le dossier d'un autre.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    imp::create_private_dir(path)
}

#[cfg(unix)]
mod imp {
    use super::*;

    pub fn create_private_dir(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }

    /// Le dossier appartient-il à l'utilisateur courant ? (un `/tmp` partagé peut
    /// contenir un `ccp-share-*` posé par quelqu'un d'autre : on n'y touche pas.)
    pub fn owned_by_me(meta: &fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        // SAFETY : geteuid n'a aucun effet de bord ni précondition.
        meta.uid() == unsafe { libc::geteuid() }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// SID (texte) de l'utilisateur du processus : le MÊME que celui de ses enfants
    /// (sshd, setup.exe), y compris quand le processus a été relancé élevé.
    fn current_user_sid() -> io::Result<String> {
        // SAFETY : appels Win32 sur le jeton du processus ; chaque poignée et chaque
        // tampon alloué par le système est libéré sur tous les chemins.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let result = (|| {
                let mut len = 0u32;
                // Premier appel : on ne veut que la taille (échec attendu).
                GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
                if len == 0 {
                    return Err(io::Error::last_os_error());
                }
                // u64 : TOKEN_USER contient des pointeurs, il exige un alignement de 8.
                let mut buf = vec![0u64; (len as usize).div_ceil(8)];
                if GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len)
                    == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let user = &*(buf.as_ptr() as *const TOKEN_USER);
                let mut wide: *mut u16 = std::ptr::null_mut();
                if ConvertSidToStringSidW(user.User.Sid, &mut wide) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut n = 0usize;
                while *wide.add(n) != 0 {
                    n += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(wide, n));
                LocalFree(wide.cast());
                Ok(s)
            })();
            CloseHandle(token);
            result
        }
    }

    pub fn create_private_dir(path: &Path) -> io::Result<()> {
        let sid = current_user_sid()?;
        // D:P = DACL PROTÉGÉE (n'hérite pas du dossier parent) ; (A;OICI;FA;;;X) =
        // autoriser, héritable par fichiers et sous-dossiers, contrôle total ;
        // SY = SYSTEM. Aucun autre compte, pas même « Utilisateurs ».
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let wpath: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY : chaînes UTF-16 terminées par NUL vivantes pendant les appels ;
        // le descripteur alloué par le système est libéré après usage.
        unsafe {
            let mut psd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            };
            let ok = CreateDirectoryW(wpath.as_ptr(), &sa);
            let err = io::Error::last_os_error();
            LocalFree(psd);
            if ok == 0 {
                return Err(err);
            }
        }
        Ok(())
    }

    /// Le temp de Windows est PAR UTILISATEUR : pas de dossier d'un autre à écarter.
    pub fn owned_by_me(_meta: &fs::Metadata) -> bool {
        true
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;
    pub fn create_private_dir(path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }
    pub fn owned_by_me(_meta: &fs::Metadata) -> bool {
        true
    }
}

/// Dossier de travail privé, effacé à la fin (Drop en dernier recours, [`finish`]
/// pour un effacement vérifié).
///
/// [`finish`]: PrivateDir::finish
pub struct PrivateDir {
    pub path: PathBuf,
    lock: Option<File>,
    done: bool,
}

impl PrivateDir {
    /// `<parent>/<prefix><pid>-<nanos>-<n>` : nom neuf, ACL privée, verrou tenu.
    pub fn create(parent: &Path, prefix: &str) -> io::Result<PrivateDir> {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for attempt in 0..20u32 {
            let path = parent.join(format!(
                "{prefix}{:x}-{:x}-{attempt}",
                std::process::id(),
                nanos
            ));
            match create_private_dir(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
            let lock = (|| {
                let f = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(path.join(LOCK_NAME))?;
                f.try_lock().map_err(|e| match e {
                    fs::TryLockError::Error(e) => e,
                    fs::TryLockError::WouldBlock => {
                        io::Error::new(io::ErrorKind::WouldBlock, "verrou déjà tenu")
                    }
                })?;
                Ok::<File, io::Error>(f)
            })();
            return match lock {
                Ok(f) => Ok(PrivateDir {
                    path,
                    lock: Some(f),
                    done: false,
                }),
                Err(e) => {
                    let _ = fs::remove_dir_all(&path);
                    Err(e)
                }
            };
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "nom de dossier temporaire indisponible",
        ))
    }

    /// Efface le dossier ET vérifie qu'il a disparu. `Err` = ce qui reste et pourquoi.
    pub fn finish(self) -> Result<(), String> {
        self.finish_with(DEFAULT_BACKOFF)
    }

    pub fn finish_with(mut self, backoff: &[Duration]) -> Result<(), String> {
        // Windows : un fichier ouvert (même le verrou) empêche la suppression du dossier.
        drop(self.lock.take());
        let r = remove_verified(&self.path, backoff);
        self.done = r.is_ok();
        r
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        if !self.done {
            drop(self.lock.take());
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// `remove_dir_all` avec reprises, puis contrôle d'existence.
fn remove_verified(path: &Path, backoff: &[Duration]) -> Result<(), String> {
    let mut last: Option<io::Error> = None;
    for pause in std::iter::once(&Duration::ZERO).chain(backoff.iter()) {
        std::thread::sleep(*pause);
        match fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    if !path.exists() {
        return Ok(());
    }
    Err(format!(
        "{} : {}",
        path.display(),
        last.map(|e| e.to_string())
            .unwrap_or_else(|| "toujours présent".into())
    ))
}

#[derive(Debug, Default)]
pub struct Sweep {
    pub removed: usize,
    /// `(dossier, pourquoi)` : orphelins qu'on n'a PAS pu effacer.
    pub failed: Vec<(PathBuf, String)>,
}

/// Efface les dossiers `<prefix>*` ORPHELINS de `parent` (restes d'un partage ou
/// d'une installation tués net). Un dossier dont le verrou est tenu est VIVANT :
/// on n'y touche pas. Ne suit jamais un lien symbolique, n'efface que des dossiers
/// de l'utilisateur courant.
pub fn sweep_orphans(parent: &Path, prefix: &str) -> Sweep {
    sweep_orphans_with(parent, prefix, DEFAULT_BACKOFF)
}

pub fn sweep_orphans_with(parent: &Path, prefix: &str, backoff: &[Duration]) -> Sweep {
    let mut out = Sweep::default();
    let Ok(rd) = fs::read_dir(parent) else {
        return out;
    };
    for e in rd.flatten() {
        if !e.file_name().to_string_lossy().starts_with(prefix) {
            continue;
        }
        let path = e.path();
        // `symlink_metadata` : un lien nommé `ccp-share-x` n'est pas suivi.
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || meta.file_type().is_symlink() || !imp::owned_by_me(&meta) {
            continue;
        }
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.join(LOCK_NAME))
        {
            Ok(f) => match f.try_lock() {
                Ok(()) => Some(f),
                Err(fs::TryLockError::WouldBlock) => continue, // vivant
                Err(fs::TryLockError::Error(_)) => continue,   // volume sans verrou : prudence
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Sans verrou : en cours de création (récent) ou reste ancien.
                let fresh = meta
                    .modified()
                    .ok()
                    .and_then(|t| SystemTime::now().duration_since(t).ok())
                    .is_some_and(|age| age < FRESH_WITHOUT_LOCK);
                if fresh {
                    continue;
                }
                None
            }
            Err(_) => continue,
        };
        drop(lock);
        match remove_verified(&path, backoff) {
            Ok(()) => out.removed += 1,
            Err(why) => out.failed.push((path, why)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn directory_is_created_private_and_never_reused() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let d = PrivateDir::create(t.path(), "ccp-test-").unwrap();
        let mode = fs::metadata(&d.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        // Un nom déjà pris est refusé, pas partagé.
        assert_eq!(
            create_private_dir(&d.path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let other = PrivateDir::create(t.path(), "ccp-test-").unwrap();
        assert_ne!(d.path, other.path);
    }

    #[test]
    fn finish_removes_everything_and_drop_is_the_fallback() {
        let t = tempfile::tempdir().unwrap();
        let d = PrivateDir::create(t.path(), "ccp-test-").unwrap();
        fs::create_dir(d.path.join("sous")).unwrap();
        fs::write(d.path.join("sous").join("x"), "x").unwrap();
        let p = d.path.clone();
        d.finish().unwrap();
        assert!(!p.exists());
        let d = PrivateDir::create(t.path(), "ccp-test-").unwrap();
        let p = d.path.clone();
        drop(d);
        assert!(!p.exists());
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_deletion_failure_is_returned_not_swallowed() {
        use std::os::unix::fs::PermissionsExt;
        // Root contourne les droits : le test n'aurait aucun sens.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = PrivateDir::create(t.path(), "ccp-test-").unwrap();
        let sub = d.path.join("verrouille");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("x"), "x").unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        let p = d.path.clone();
        let err = d.finish_with(&[Duration::from_millis(1)]).unwrap_err();
        assert!(err.contains("ccp-test-"), "{err}");
        assert!(p.exists(), "le dossier est resté : l'erreur dit vrai");
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&p).unwrap();
    }

    #[test]
    fn sweep_removes_orphans_but_never_a_live_directory() {
        let t = tempfile::tempdir().unwrap();
        // Vivant : le verrou est tenu par ce processus.
        let live = PrivateDir::create(t.path(), "ccp-test-").unwrap();
        // Orphelin : verrou présent mais libre (propriétaire mort).
        let orphan = t.path().join("ccp-test-mort-1-0");
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join(LOCK_NAME), "").unwrap();
        fs::write(orphan.join("hostkey"), "CLE-PRIVEE").unwrap();
        // Étranger : autre préfixe, intact.
        let other = t.path().join("autre-dossier");
        fs::create_dir(&other).unwrap();

        let r = sweep_orphans(t.path(), "ccp-test-");
        assert_eq!(r.removed, 1, "{r:?}");
        assert!(r.failed.is_empty(), "{r:?}");
        assert!(!orphan.exists());
        assert!(live.path.exists(), "un dossier vivant n'est pas touché");
        assert!(other.exists());
        live.finish().unwrap();
    }

    #[test]
    fn sweep_spares_a_directory_still_being_created_but_not_an_old_one() {
        let t = tempfile::tempdir().unwrap();
        let fresh = t.path().join("ccp-test-frais-1-0");
        fs::create_dir(&fresh).unwrap();
        let r = sweep_orphans(t.path(), "ccp-test-");
        assert_eq!(r.removed, 0);
        assert!(fresh.exists(), "pas encore de verrou mais tout neuf");
        // Même dossier, vieilli de 10 minutes.
        let old = SystemTime::now() - Duration::from_secs(600);
        fs::File::open(&fresh).unwrap().set_modified(old).unwrap();
        let r = sweep_orphans(t.path(), "ccp-test-");
        assert_eq!(r.removed, 1);
        assert!(!fresh.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_does_not_follow_symlinks() {
        let t = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        fs::write(victim.path().join("precieux"), "x").unwrap();
        std::os::unix::fs::symlink(victim.path(), t.path().join("ccp-test-lien")).unwrap();
        let r = sweep_orphans(t.path(), "ccp-test-");
        assert_eq!(r.removed, 0);
        assert!(victim.path().join("precieux").exists());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_reports_an_orphan_it_cannot_remove() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let orphan = t.path().join("ccp-test-mort-2-0");
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join(LOCK_NAME), "").unwrap();
        let sub = orphan.join("verrouille");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("x"), "x").unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        let r = sweep_orphans_with(t.path(), "ccp-test-", &[Duration::from_millis(1)]);
        assert_eq!(r.removed, 0);
        assert_eq!(r.failed.len(), 1, "{r:?}");
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
