//! cloudflared PORTABLE : téléchargé, vérifié et rangé dans `<racine>/tools/cloudflared/<plateforme>/`.
//!
//! - Version et SHA-256 ÉPINGLÉS (`pins.rs`). Un cloudflared du système n'est jamais
//!   utilisé : version inconnue, et rien ne prouve qu'il soit sain.
//! - Un manifeste `INSTALLED` (version, empreinte de l'archive, empreinte du binaire)
//!   permet de ne rien retélécharger quand le binaire est intact, et de tout refaire
//!   s'il a été tronqué, remplacé ou si l'épingle a changé. Il protège d'un fichier
//!   ABÎMÉ (clé débranchée en pleine écriture) ; il ne prétend pas protéger d'un
//!   attaquant qui peut écrire sur le portable : celui-là pourrait écrire n'importe quoi.
//! - Volume monté sans exécution (clé exFAT `noexec`) : copie unique dans
//!   `~/.cache/claude-portable/cloudflared/…`, comme pour le binaire de Claude.

use super::download::{self, fetch_verified, make_executable, sha256_file};
use super::net::Fetch;
use super::pins::{platform_dir, Asset, Packaging};
use crate::env::Env;
use crate::error::{CcpError, Result};
use crate::root::Root;
use crate::util::run_bounded;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const MANIFEST: &str = "INSTALLED";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub exe: PathBuf,
    pub dir: PathBuf,
}

pub fn exe_name(os: &str) -> &'static str {
    if os == "windows" {
        "cloudflared.exe"
    } else {
        "cloudflared"
    }
}

/// `<racine>/tools/cloudflared/<plateforme>` (dossier `tools/` ignoré par git).
pub fn tool_dir(root: &Root, os: &str, arch: &str) -> PathBuf {
    root.path()
        .join("tools")
        .join("cloudflared")
        .join(platform_dir(os, arch))
}

#[derive(Debug, PartialEq, Eq)]
struct Manifest {
    version: String,
    source_sha256: String,
    binary_sha256: String,
}

impl Manifest {
    fn render(&self) -> String {
        format!(
            "version={}\nsource_sha256={}\nbinary_sha256={}\n",
            self.version, self.source_sha256, self.binary_sha256
        )
    }

    fn parse(text: &str) -> Option<Manifest> {
        let get = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .map(|v| v.trim().to_string())
        };
        Some(Manifest {
            version: get("version")?,
            source_sha256: get("source_sha256")?,
            binary_sha256: get("binary_sha256")?,
        })
    }
}

fn io_err(what: &str, e: std::io::Error) -> CcpError {
    CcpError::Internal(format!("{what} : {e}"))
}

fn read_manifest(dir: &Path) -> Option<Manifest> {
    Manifest::parse(&fs::read_to_string(dir.join(MANIFEST)).ok()?)
}

/// Le binaire installé est-il celui que l'épingle actuelle désigne, et intact ?
///
/// Binaire brut (Windows, Linux) : comparé DIRECTEMENT à l'empreinte épinglée
/// compilée dans ccp-core, jamais au manifeste — celui-ci est un fichier du
/// portable qu'un tiers peut réécrire avec le binaire (revue terminale : `remote
/// share` lance cloudflared en administrateur). Archive (macOS) : le binaire
/// extrait n'a pas d'empreinte publiée ; le manifeste suffit, ce chemin n'est
/// jamais élevé.
fn is_current(dir: &Path, exe: &Path, asset: &Asset) -> bool {
    if matches!(asset.packaging, Packaging::Raw) {
        return sha256_file(exe).is_ok_and(|h| h.eq_ignore_ascii_case(asset.sha256));
    }
    let Some(m) = read_manifest(dir) else {
        return false;
    };
    m.version == asset.tag
        && m.source_sha256.eq_ignore_ascii_case(asset.sha256)
        && sha256_file(exe).is_ok_and(|h| h.eq_ignore_ascii_case(&m.binary_sha256))
}

/// Garantit que `<dir>/<exe_name>` existe, est vérifié et à jour.
/// `say` reçoit les messages d'avancement (stderr côté appelant).
pub fn ensure(
    dir: &Path,
    exe_name: &str,
    asset: &Asset,
    base: &str,
    fetch: &dyn Fetch,
    say: &mut dyn FnMut(&str),
) -> Result<Installed> {
    let exe = dir.join(exe_name);
    let installed = Installed {
        exe: exe.clone(),
        dir: dir.to_path_buf(),
    };
    if is_current(dir, &exe, asset) {
        return Ok(installed);
    }
    fs::create_dir_all(dir).map_err(|e| io_err("dossier de cloudflared impossible à créer", e))?;
    say(&format!(
        "Téléchargement de cloudflared {} (une seule fois, vérifié par empreinte SHA-256)…",
        asset.tag
    ));
    // Le manifeste ancien ne décrit plus rien : on l'efface AVANT de toucher au binaire.
    let _ = fs::remove_file(dir.join(MANIFEST));
    let url = asset.url(base);
    let binary_sha = match asset.packaging {
        Packaging::Raw => {
            fetch_verified(fetch, &url, &exe, asset.sha256, asset.max_bytes)?;
            asset.sha256.to_ascii_lowercase()
        }
        Packaging::TarGz { member } => {
            let archive = dir.join(asset.name);
            fetch_verified(fetch, &url, &archive, asset.sha256, asset.max_bytes)?;
            let sha = download::extract_tgz_member(&archive, member, &exe, asset.max_bytes);
            // L'archive a rempli son rôle, qu'elle ait été bonne ou non.
            let _ = fs::remove_file(&archive);
            sha?
        }
        Packaging::Zip => {
            return Err(CcpError::Internal(
                "cloudflared n'est pas distribué en .zip".into(),
            ))
        }
    };
    make_executable(&exe)?;
    let manifest = Manifest {
        version: asset.tag.to_string(),
        source_sha256: asset.sha256.to_ascii_lowercase(),
        binary_sha256: binary_sha,
    };
    // Écrit EN DERNIER : un manifeste présent garantit un binaire entier.
    crate::atomic::write_atomic(&dir.join(MANIFEST), manifest.render().as_bytes())
        .map_err(|e| io_err("manifeste de cloudflared impossible à écrire", e))?;
    Ok(installed)
}

/// Vérifie que le binaire démarre ET annonce la version épinglée. Sur un volume
/// `noexec` (Unix), le copie une fois dans le cache de l'utilisateur et renvoie la copie.
pub fn runnable(env: &Env, inst: Installed, asset: &Asset) -> Result<Installed> {
    match probe_version(&inst.exe, asset) {
        Ok(()) => Ok(inst),
        #[cfg(unix)]
        Err(ProbeErr::Denied(first)) => {
            let copy = noexec_copy(env, &inst, asset).map_err(|e| {
                CcpError::Internal(format!(
                    "cloudflared ne peut pas s'exécuter depuis ce volume ({first}) et la copie \
                     de repli a échoué : {e}"
                ))
            })?;
            probe_version(&copy.exe, asset).map_err(|e| e.into_error())?;
            Ok(copy)
        }
        Err(e) => {
            let _ = env;
            Err(e.into_error())
        }
    }
}

enum ProbeErr {
    /// Exécution refusée par le système (volume `noexec`).
    #[cfg_attr(not(unix), allow(dead_code))]
    Denied(String),
    Other(String),
}

impl ProbeErr {
    fn into_error(self) -> CcpError {
        match self {
            ProbeErr::Denied(m) | ProbeErr::Other(m) => CcpError::Internal(m),
        }
    }
}

fn probe_version(exe: &Path, asset: &Asset) -> std::result::Result<(), ProbeErr> {
    let out = run_bounded(
        Command::new(exe).arg("--version"),
        None,
        Duration::from_secs(20),
    )
    .map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            ProbeErr::Denied(format!("exécution refusée : {e}"))
        } else {
            ProbeErr::Other(format!("cloudflared ne démarre pas : {e}"))
        }
    })?;
    if out.timed_out() || out.code() != Some(0) {
        return Err(ProbeErr::Other(
            "cloudflared ne répond pas à --version : binaire refusé".into(),
        ));
    }
    let text = out.stdout_str();
    if !text.contains(asset.tag) {
        return Err(ProbeErr::Other(format!(
            "cloudflared annonce « {} » au lieu de la version épinglée {} : binaire refusé",
            text.lines().next().unwrap_or("").trim(),
            asset.tag
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn noexec_copy(env: &Env, inst: &Installed, asset: &Asset) -> std::io::Result<Installed> {
    let dir = env
        .home
        .join(".cache")
        .join("claude-portable")
        .join("cloudflared")
        .join(asset.tag);
    let name = inst.exe.file_name().unwrap_or_default();
    let dest = dir.join(name);
    let want = read_manifest(&inst.dir).map(|m| m.binary_sha256);
    let fresh = match (&want, sha256_file(&dest)) {
        (Some(w), Ok(h)) => h.eq_ignore_ascii_case(w),
        _ => false,
    };
    if !fresh {
        eprintln!(
            "ccp-core : ce volume interdit l'exécution — copie unique de cloudflared dans {} …",
            dir.display()
        );
        fs::create_dir_all(&dir)?;
        let tmp = dir.join(".copie-en-cours");
        fs::copy(&inst.exe, &tmp)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
        fs::rename(&tmp, &dest)?;
    }
    Ok(Installed { exe: dest, dir })
}

#[cfg(test)]
mod tests {
    use super::super::download::testing::*;
    use super::*;

    fn raw_asset(tag: &'static str, body: &[u8]) -> (Asset, String) {
        let sha: &'static str = Box::leak(sha_of(body).into_boxed_str());
        (
            Asset {
                repo: "o/r",
                tag,
                name: "cloudflared-test",
                sha256: sha,
                packaging: Packaging::Raw,
                max_bytes: 1 << 20,
            },
            format!("http://127.0.0.1:1/o/r/releases/download/{tag}/cloudflared-test"),
        )
    }

    #[test]
    fn manifest_round_trips() {
        let m = Manifest {
            version: "1".into(),
            source_sha256: "aa".into(),
            binary_sha256: "bb".into(),
        };
        assert_eq!(Manifest::parse(&m.render()), Some(m));
        assert_eq!(Manifest::parse("version=1\n"), None);
    }

    #[test]
    fn first_call_downloads_second_call_reuses() {
        let t = tempfile::tempdir().unwrap();
        // Dossier à espaces ET accents, comme une racine de clé USB.
        let dir = t.path().join("Ma clé USB/tools/cloudflared/été");
        let (asset, url) = raw_asset("9.9.9", b"binaire");
        let mut f = FakeFetch::default();
        f.files.insert(url, b"binaire".to_vec());
        let mut said = Vec::new();
        let a = ensure(
            &dir,
            "cloudflared",
            &asset,
            "http://127.0.0.1:1",
            &f,
            &mut |m| said.push(m.to_string()),
        )
        .unwrap();
        assert_eq!(fs::read(&a.exe).unwrap(), b"binaire");
        assert_eq!(said.len(), 1);
        assert_eq!(f.calls.lock().unwrap().len(), 1);
        let again = ensure(
            &dir,
            "cloudflared",
            &asset,
            "http://127.0.0.1:1",
            &f,
            &mut |_| panic!("rien à dire quand tout est déjà là"),
        )
        .unwrap();
        assert_eq!(again, a);
        assert_eq!(f.calls.lock().unwrap().len(), 1, "aucun retéléchargement");
    }

    #[test]
    fn a_tampered_binary_is_downloaded_again() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("c");
        let (asset, url) = raw_asset("9.9.9", b"binaire");
        let mut f = FakeFetch::default();
        f.files.insert(url, b"binaire".to_vec());
        let base = "http://127.0.0.1:1";
        let a = ensure(&dir, "cloudflared", &asset, base, &f, &mut |_| {}).unwrap();
        fs::write(&a.exe, b"remplace par autre chose").unwrap();
        ensure(&dir, "cloudflared", &asset, base, &f, &mut |_| {}).unwrap();
        assert_eq!(fs::read(&a.exe).unwrap(), b"binaire");
        assert_eq!(f.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_swapped_binary_with_a_forged_manifest_is_still_refused() {
        // Scénario de la revue : un tiers remplace cloudflared ET réécrit le
        // manifeste pour qu'il décrive son binaire. Un binaire brut se compare à
        // l'épingle compilée, donc il est retéléchargé quand même.
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("c");
        let (asset, url) = raw_asset("9.9.9", b"binaire");
        let mut f = FakeFetch::default();
        f.files.insert(url, b"binaire".to_vec());
        let base = "http://127.0.0.1:1";
        let a = ensure(&dir, "cloudflared", &asset, base, &f, &mut |_| {}).unwrap();
        fs::write(&a.exe, b"binaire piege").unwrap();
        let forged = Manifest {
            version: asset.tag.into(),
            source_sha256: asset.sha256.into(),
            binary_sha256: sha_of(b"binaire piege"),
        };
        fs::write(dir.join(MANIFEST), forged.render()).unwrap();
        ensure(&dir, "cloudflared", &asset, base, &f, &mut |_| {}).unwrap();
        assert_eq!(fs::read(&a.exe).unwrap(), b"binaire");
        assert_eq!(
            f.calls.lock().unwrap().len(),
            2,
            "retéléchargé malgré le manifeste"
        );
    }

    #[test]
    fn a_new_pin_replaces_the_old_install() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("c");
        let (old, old_url) = raw_asset("1.0.0", b"vieux");
        let (new, new_url) = raw_asset("2.0.0", b"neuf");
        let mut f = FakeFetch::default();
        f.files.insert(old_url, b"vieux".to_vec());
        f.files.insert(new_url, b"neuf".to_vec());
        let base = "http://127.0.0.1:1";
        ensure(&dir, "cloudflared", &old, base, &f, &mut |_| {}).unwrap();
        let a = ensure(&dir, "cloudflared", &new, base, &f, &mut |_| {}).unwrap();
        assert_eq!(fs::read(&a.exe).unwrap(), b"neuf");
    }

    #[test]
    fn altered_pin_refuses_and_installs_nothing() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("c");
        let (mut asset, url) = raw_asset("9.9.9", b"binaire");
        asset.sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
        let mut f = FakeFetch::default();
        f.files.insert(url, b"binaire".to_vec());
        let e = ensure(
            &dir,
            "cloudflared",
            &asset,
            "http://127.0.0.1:1",
            &f,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(e.to_string().contains("REFUSÉ"), "{e}");
        assert!(!dir.join("cloudflared").exists());
        assert!(!dir.join(MANIFEST).exists());
    }

    #[test]
    fn tgz_is_unpacked_and_archive_removed() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("c");
        let tgz = make_tgz(&[("cloudflared", b"mach-o")]);
        let sha: &'static str = Box::leak(sha_of(&tgz).into_boxed_str());
        let asset = Asset {
            repo: "o/r",
            tag: "9.9.9",
            name: "cf.tgz",
            sha256: sha,
            packaging: Packaging::TarGz {
                member: "cloudflared",
            },
            max_bytes: 1 << 20,
        };
        let mut f = FakeFetch::default();
        f.files.insert(asset.url("http://127.0.0.1:1"), tgz);
        let a = ensure(
            &dir,
            "cloudflared",
            &asset,
            "http://127.0.0.1:1",
            &f,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(fs::read(&a.exe).unwrap(), b"mach-o");
        assert!(!dir.join("cf.tgz").exists());
        assert_eq!(
            read_manifest(&dir).unwrap().binary_sha256,
            sha_of(b"mach-o")
        );
        // Deuxième appel : l'empreinte du BINAIRE (pas celle de l'archive) sert de repère.
        ensure(
            &dir,
            "cloudflared",
            &asset,
            "http://127.0.0.1:1",
            &f,
            &mut |_| panic!("déjà installé"),
        )
        .unwrap();
    }

    #[cfg(unix)]
    fn script(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("cloudflared");
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn runnable_accepts_the_pinned_version_only() {
        let t = tempfile::tempdir().unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        let (asset, _) = raw_asset("9.9.9", b"x");
        let good = script(t.path(), "echo 'cloudflared version 9.9.9 (built 2026)'");
        let inst = Installed {
            exe: good,
            dir: t.path().to_path_buf(),
        };
        assert_eq!(runnable(&env, inst.clone(), &asset).unwrap(), inst);

        script(t.path(), "echo 'cloudflared version 1.2.3'");
        let e = runnable(&env, inst.clone(), &asset).unwrap_err();
        assert!(e.to_string().contains("version épinglée"), "{e}");

        script(t.path(), "exit 3");
        assert!(runnable(&env, inst, &asset).is_err());
    }
}
