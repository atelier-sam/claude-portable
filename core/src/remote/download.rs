//! Téléchargement VÉRIFIÉ : jamais un octet téléchargé n'atteint son nom définitif
//! sans que son SHA-256 corresponde à l'empreinte épinglée.
//!
//! Chaîne : flux -> `<nom>.part` (empreinte calculée au fil de l'eau) -> comparaison
//! -> `fsync` -> renommage. Un téléchargement coupé, une clé débranchée ou un
//! serveur piégé laissent au pire un `.part` (effacé au passage suivant), jamais un
//! binaire tronqué qu'on prendrait pour bon. Les archives (`.tgz`, `.zip`) sont
//! extraites en Rust pur, APRÈS la vérification de l'archive entière.

use super::net::Fetch;
use crate::error::{CcpError, Result};
use crate::http::NetError;
use crate::util::hex_encode;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Écrit dans `inner` tout en calculant le SHA-256 de ce qui passe.
pub struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        HashingWriter {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }
    pub fn written(&self) -> u64 {
        self.written
    }
    /// Rend l'écrivain et l'empreinte hexadécimale de tout ce qui a été écrit.
    pub fn finish(self) -> (W, String) {
        (self.inner, hex_encode(&self.hasher.finalize()))
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// `<fichier>.part` : le nom du fichier en cours d'écriture.
pub fn part_path(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".part");
    dest.with_file_name(name)
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex_encode(&h.finalize()))
}

fn io_err(what: &str, e: io::Error) -> CcpError {
    CcpError::Internal(format!("{what} : {e}"))
}

fn net_err(url_name: &str, e: NetError) -> CcpError {
    CcpError::Network(format!(
        "téléchargement de {url_name} impossible : {}",
        e.message()
    ))
}

/// Télécharge `url` vers `dest` et refuse si le SHA-256 n'est pas `expected_sha256`.
pub fn fetch_verified(
    fetch: &dyn Fetch,
    url: &str,
    dest: &Path,
    expected_sha256: &str,
    max_bytes: u64,
) -> Result<()> {
    let label = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "fichier".into());
    if let Some(dir) = dest.parent() {
        fs::create_dir_all(dir).map_err(|e| io_err("dossier de destination impossible", e))?;
    }
    let part = part_path(dest);
    // Reste d'un téléchargement précédent interrompu.
    let _ = fs::remove_file(&part);
    let result = (|| -> Result<()> {
        let file = File::create(&part).map_err(|e| io_err("écriture impossible", e))?;
        let mut w = HashingWriter::new(io::BufWriter::new(file));
        fetch
            .download(url, &mut w, max_bytes)
            .map_err(|e| net_err(&label, e))?;
        let (buf, got) = w.finish();
        let file = buf
            .into_inner()
            .map_err(|e| io_err("écriture impossible", e.into_error()))?;
        if !got.eq_ignore_ascii_case(expected_sha256) {
            return Err(CcpError::Internal(format!(
                "{label} : empreinte SHA-256 inattendue (attendu {}…, reçu {}…) — fichier REFUSÉ, \
                 rien n'a été installé",
                &expected_sha256[..expected_sha256.len().min(12)],
                &got[..12]
            )));
        }
        file.sync_all()
            .map_err(|e| io_err("écriture impossible", e))?;
        drop(file);
        fs::rename(&part, dest).map_err(|e| io_err("renommage impossible", e))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&part);
    }
    result
}

/// Rend un fichier exécutable (Unix). Sans effet sous Windows.
pub fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|e| io_err("droit d'exécution impossible", e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Extrait UN fichier d'un `.tgz` vers `dest` (via `.part`) ; renvoie son SHA-256.
/// Le nom est comparé sur le DERNIER composant : une entrée `../cloudflared` ou
/// `x/cloudflared` ne sort jamais du dossier, car on n'utilise que ce nom.
pub fn extract_tgz_member(
    archive: &Path,
    member: &str,
    dest: &Path,
    max_bytes: u64,
) -> Result<String> {
    let f = File::open(archive).map_err(|e| io_err("archive illisible", e))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    let entries = tar
        .entries()
        .map_err(|e| io_err("archive .tgz illisible", e))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| io_err("archive .tgz illisible", e))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let matches = entry
            .path()
            .ok()
            .and_then(|p| p.file_name().map(|n| n == member))
            .unwrap_or(false);
        if !matches {
            continue;
        }
        let part = part_path(dest);
        let _ = fs::remove_file(&part);
        let result = (|| -> Result<String> {
            let file = File::create(&part).map_err(|e| io_err("écriture impossible", e))?;
            let mut w = HashingWriter::new(io::BufWriter::new(file));
            // `take` : une archive qui annonce peu et déballe beaucoup n'est pas écrite en entier.
            let copied = io::copy(&mut (&mut entry).take(max_bytes + 1), &mut w)
                .map_err(|e| io_err("extraction impossible", e))?;
            if copied > max_bytes {
                return Err(CcpError::Internal(format!(
                    "{member} dépasse {max_bytes} octets une fois extrait : archive refusée"
                )));
            }
            let (buf, sha) = w.finish();
            let file = buf
                .into_inner()
                .map_err(|e| io_err("écriture impossible", e.into_error()))?;
            file.sync_all()
                .map_err(|e| io_err("écriture impossible", e))?;
            drop(file);
            fs::rename(&part, dest).map_err(|e| io_err("renommage impossible", e))?;
            Ok(sha)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&part);
        }
        return result;
    }
    Err(CcpError::Internal(format!(
        "« {member} » est absent de l'archive téléchargée"
    )))
}

/// Extrait tout un `.zip` sous `dest_dir`. Refuse les chemins qui sortent du dossier
/// (« zip slip ») et plafonne la taille décompressée. Renvoie le nombre de fichiers.
pub fn extract_zip(archive: &Path, dest_dir: &Path, max_total: u64) -> Result<usize> {
    let f = File::open(archive).map_err(|e| io_err("archive illisible", e))?;
    let mut zip = zip::ZipArchive::new(f)
        .map_err(|e| CcpError::Internal(format!("archive .zip illisible : {e}")))?;
    fs::create_dir_all(dest_dir).map_err(|e| io_err("dossier de destination impossible", e))?;
    let mut total = 0u64;
    let mut files = 0usize;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| CcpError::Internal(format!("archive .zip illisible : {e}")))?;
        let Some(rel) = entry.enclosed_name() else {
            return Err(CcpError::Internal(format!(
                "archive .zip refusée : chemin dangereux « {} »",
                entry.name_raw().escape_ascii()
            )));
        };
        let out = dest_dir.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(|e| io_err("dossier impossible", e))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err("dossier impossible", e))?;
        }
        let mut file = File::create(&out).map_err(|e| io_err("écriture impossible", e))?;
        let copied = io::copy(
            &mut (&mut entry).take(max_total.saturating_sub(total) + 1),
            &mut file,
        )
        .map_err(|e| io_err("extraction impossible", e))?;
        total += copied;
        if total > max_total {
            return Err(CcpError::Internal(format!(
                "archive .zip refusée : plus de {max_total} octets une fois décompressée"
            )));
        }
        files += 1;
    }
    Ok(files)
}

#[cfg(test)]
pub mod testing {
    //! Faux serveur de fichiers pour les tests : pas de réseau.
    use super::*;
    use crate::remote::net::Probe;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct FakeFetch {
        pub files: HashMap<String, Vec<u8>>,
        pub probes: HashMap<String, Probe>,
        pub calls: Mutex<Vec<String>>,
    }

    impl Fetch for FakeFetch {
        fn download(
            &self,
            url: &str,
            sink: &mut dyn Write,
            max_bytes: u64,
        ) -> std::result::Result<u64, NetError> {
            self.calls.lock().unwrap().push(url.to_string());
            let Some(body) = self.files.get(url) else {
                return Err(NetError::Other("le serveur répond HTTP 404".into()));
            };
            if body.len() as u64 > max_bytes {
                return Err(NetError::Other("fichier plus gros que prévu".into()));
            }
            sink.write_all(body)
                .map_err(|e| NetError::Other(e.to_string()))?;
            Ok(body.len() as u64)
        }
        fn probe(&self, url: &str) -> std::result::Result<Probe, NetError> {
            self.probes
                .get(url)
                .cloned()
                .ok_or_else(|| NetError::Other("hôte injoignable".into()))
        }
    }

    pub fn sha_of(bytes: &[u8]) -> String {
        hex_encode(&Sha256::digest(bytes))
    }

    /// `.tgz` en mémoire contenant `files` (nom, contenu).
    pub fn make_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut tar = tar::Builder::new(gz);
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            tar.append_data(&mut h, name, *data).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    pub fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default();
            for (name, data) in files {
                z.start_file(*name, opts).unwrap();
                z.write_all(data).unwrap();
            }
            z.finish().unwrap();
        }
        buf.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn fx(url: &str, body: &[u8]) -> FakeFetch {
        let mut f = FakeFetch::default();
        f.files.insert(url.to_string(), body.to_vec());
        f
    }

    #[test]
    fn matching_sha_installs_through_part_and_renames() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("sous dossier/été").join("outil.bin");
        let f = fx("http://x/outil", b"contenu");
        fetch_verified(&f, "http://x/outil", &dest, &sha_of(b"contenu"), 1000).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"contenu");
        assert!(!part_path(&dest).exists(), "le .part doit avoir disparu");
    }

    #[test]
    fn altered_sha_is_refused_and_nothing_is_left_behind() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("outil.bin");
        let f = fx("http://x/outil", b"contenu piege");
        let wrong = sha_of(b"autre chose");
        let e = fetch_verified(&f, "http://x/outil", &dest, &wrong, 1000).unwrap_err();
        assert!(e.to_string().contains("REFUSÉ"), "{e}");
        assert_eq!(e.exit_code(), 10);
        assert!(!dest.exists());
        assert!(!part_path(&dest).exists());
    }

    #[test]
    fn existing_file_is_untouched_when_the_new_download_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("outil.bin");
        fs::write(&dest, b"ancien bon").unwrap();
        let f = fx("http://x/outil", b"piege");
        assert!(fetch_verified(&f, "http://x/outil", &dest, &sha_of(b"x"), 1000).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"ancien bon");
    }

    #[test]
    fn network_failure_is_exit_4_and_oversize_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("o.bin");
        let f = FakeFetch::default();
        let e = fetch_verified(&f, "http://x/absent", &dest, &sha_of(b""), 10).unwrap_err();
        assert_eq!(e.exit_code(), 4);
        let big = fx("http://x/gros", &[0u8; 64]);
        let e = fetch_verified(&big, "http://x/gros", &dest, &sha_of(&[0u8; 64]), 10).unwrap_err();
        assert_eq!(e.exit_code(), 4);
        assert!(!part_path(&dest).exists());
    }

    #[test]
    fn stale_part_file_is_replaced() {
        let t = tempfile::tempdir().unwrap();
        let dest = t.path().join("o.bin");
        fs::write(part_path(&dest), b"reste d'un essai coupe").unwrap();
        let f = fx("http://x/o", b"neuf");
        fetch_verified(&f, "http://x/o", &dest, &sha_of(b"neuf"), 100).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"neuf");
    }

    #[test]
    fn tgz_member_is_extracted_by_file_name_only() {
        let t = tempfile::tempdir().unwrap();
        let tgz = make_tgz(&[("LICENSE", b"mit"), ("pkg/cloudflared", b"binaire")]);
        let arch = t.path().join("a.tgz");
        fs::write(&arch, &tgz).unwrap();
        let dest = t.path().join("cloudflared");
        let sha = extract_tgz_member(&arch, "cloudflared", &dest, 1000).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"binaire");
        assert_eq!(sha, sha_of(b"binaire"));
        assert_eq!(sha256_file(&dest).unwrap(), sha);
    }

    #[test]
    fn tgz_without_the_member_or_too_big_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let arch = t.path().join("a.tgz");
        fs::write(&arch, make_tgz(&[("autre", b"x")])).unwrap();
        let dest = t.path().join("cloudflared");
        assert!(extract_tgz_member(&arch, "cloudflared", &dest, 1000).is_err());
        fs::write(&arch, make_tgz(&[("cloudflared", &[7u8; 500])])).unwrap();
        let e = extract_tgz_member(&arch, "cloudflared", &dest, 100).unwrap_err();
        assert!(e.to_string().contains("dépasse"), "{e}");
        assert!(!dest.exists());
        assert!(!part_path(&dest).exists());
    }

    #[test]
    fn zip_is_extracted_and_zip_slip_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let arch = t.path().join("a.zip");
        fs::write(
            &arch,
            make_zip(&[
                ("OpenSSH-Win64/sshd.exe", b"s"),
                ("OpenSSH-Win64/sub/x.dll", b"d"),
            ]),
        )
        .unwrap();
        let out = t.path().join("sortie été");
        assert_eq!(extract_zip(&arch, &out, 1000).unwrap(), 2);
        assert_eq!(fs::read(out.join("OpenSSH-Win64/sshd.exe")).unwrap(), b"s");
        assert_eq!(fs::read(out.join("OpenSSH-Win64/sub/x.dll")).unwrap(), b"d");

        let evil = t.path().join("evil.zip");
        fs::write(&evil, make_zip(&[("../evasion.txt", b"x")])).unwrap();
        let e = extract_zip(&evil, &t.path().join("o2"), 1000).unwrap_err();
        assert!(e.to_string().contains("dangereux"), "{e}");
        assert!(!t.path().join("evasion.txt").exists());

        let big = t.path().join("big.zip");
        fs::write(&big, make_zip(&[("a", &[1u8; 400])])).unwrap();
        assert!(extract_zip(&big, &t.path().join("o3"), 100).is_err());
    }

    #[test]
    fn hashing_writer_hashes_what_it_writes() {
        let mut w = HashingWriter::new(Vec::new());
        w.write_all(b"ab").unwrap();
        w.write_all(b"c").unwrap();
        assert_eq!(w.written(), 3);
        let (v, h) = w.finish();
        assert_eq!(v, b"abc");
        assert_eq!(h, sha_of(b"abc"));
    }
}
