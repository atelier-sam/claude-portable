//! Écriture atomique (tmp + rename), mode 600 sous unix.
//!
//! Utilisée pour tout fichier qu'un autre processus (Claude, un second wizard)
//! peut lire pendant qu'on écrit : un lecteur voit l'ancien contenu OU le
//! nouveau, jamais un fichier à moitié écrit.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Compteur de processus : deux threads qui écrivent dans la même microseconde
/// (l'horloge macOS n'a pas de nanosecondes réelles) auraient le MÊME nom de
/// fichier temporaire et la création exclusive de l'un échouerait.
static SEQ: AtomicU64 = AtomicU64::new(0);

pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(
        ".{name}.ccp-tmp-{}-{nanos}-{seq}",
        std::process::id()
    ));
    let result = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_content_and_leaves_no_tmp() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a.json");
        write_atomic(&p, b"un").unwrap();
        write_atomic(&p, b"deux").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"deux");
        let n = fs::read_dir(t.path()).unwrap().count();
        assert_eq!(n, 1);
    }

    #[test]
    fn parallel_writers_never_collide_on_the_temporary_name() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("c.json");
        let hs: Vec<_> = (0..8)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        write_atomic(&p, format!("{{\"w\":{i}}}").as_bytes()).unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert!(fs::read_to_string(&p).unwrap().starts_with("{\"w\":"));
        assert_eq!(
            fs::read_dir(t.path()).unwrap().count(),
            1,
            "aucun .ccp-tmp oublié"
        );
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s");
        write_atomic(&p, b"x").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
