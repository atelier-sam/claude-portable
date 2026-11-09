//! `accounts purge` : retire du Trousseau les sessions de CE portable.
//!
//! Garde-fous : seuls les services SUFFIXÉS (`Claude Code-credentials-<8 hex>`,
//! un par `CLAUDE_CONFIG_DIR`) sont supprimés. Le service sans suffixe est la
//! session Claude Code normale de la machine : `delete_all` le refuse, quoi
//! qu'on lui passe. Sur TOUTES les plateformes, les identifiants posés en fichier
//! dans le profil (`.credentials.json`, `oauth.token`) sont aussi effacés : c'est
//! le seul magasin sous Windows/Linux, et ce que le wizard doit retirer en quittant
//! un PC client marqué « invité ».

use crate::env::Env;
use crate::error::Result;
use crate::root::{Profile, Root};

#[derive(Debug, PartialEq, Eq)]
pub struct PurgeReport {
    pub profiles: usize,
    pub removed: usize,
}

pub fn purge(env: &Env, root: &Root, only: Option<&Profile>) -> Result<PurgeReport> {
    let profiles: Vec<Profile> = match only {
        Some(p) => vec![p.clone()],
        None => root.list_profiles(),
    };
    let files = purge_files(root, &profiles)?;
    let mut r = purge_impl(env, root, &profiles)?;
    r.removed += files;
    Ok(r)
}

/// Efface les identifiants en fichier de chaque profil ; un fichier absent n'est
/// pas une erreur (purge idempotente).
fn purge_files(root: &Root, profiles: &[Profile]) -> Result<usize> {
    use crate::error::CcpError;
    let mut n = 0;
    for name in profiles {
        let pd = root.profile(name);
        for f in [pd.credentials_file(), pd.token_file()] {
            match std::fs::remove_file(&f) {
                Ok(()) => n += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(CcpError::Internal(format!(
                        "effacement de {} (profil {name}) : {e}",
                        f.display()
                    )))
                }
            }
        }
    }
    Ok(n)
}

#[cfg(target_os = "macos")]
fn purge_impl(env: &Env, root: &Root, profiles: &[Profile]) -> Result<PurgeReport> {
    use crate::creds::keychain;
    use crate::error::CcpError;
    if env.no_keychain {
        return Ok(PurgeReport {
            profiles: profiles.len(),
            removed: 0,
        });
    }
    let mut removed = 0;
    for name in profiles {
        let svc = keychain::service_name(&root.profile(name).cfg);
        removed += keychain::delete_all(env, &svc)
            .map_err(|e| CcpError::Internal(format!("Trousseau (profil {name}) : {e}")))?;
    }
    Ok(PurgeReport {
        profiles: profiles.len(),
        removed,
    })
}

#[cfg(not(target_os = "macos"))]
fn purge_impl(_env: &Env, _root: &Root, profiles: &[Profile]) -> Result<PurgeReport> {
    Ok(PurgeReport {
        profiles: profiles.len(),
        removed: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::PathStyle;

    #[test]
    fn hermetic_env_never_touches_the_keychain() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("config").join("1")).unwrap();
        let root = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        let r = purge(&env, &root, None).unwrap();
        assert_eq!(
            r,
            PurgeReport {
                profiles: 1,
                removed: 0
            }
        );
    }

    #[test]
    fn file_credentials_are_erased_and_purge_is_idempotent() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("config").join("client");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(".credentials.json"), "{}").unwrap();
        std::fs::write(d.join("oauth.token"), "sk-ant-oat-factice").unwrap();
        std::fs::write(d.join("settings.json"), "{}").unwrap();
        let root = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        assert_eq!(purge(&env, &root, None).unwrap().removed, 2);
        assert!(!d.join(".credentials.json").exists());
        assert!(!d.join("oauth.token").exists());
        assert!(d.join("settings.json").exists(), "les réglages restent");
        assert_eq!(purge(&env, &root, None).unwrap().removed, 0);
    }

    #[test]
    fn explicit_profile_is_purged_even_if_its_folder_is_gone() {
        let t = tempfile::tempdir().unwrap();
        let root = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        let p = Profile::parse("ancien").unwrap();
        assert_eq!(purge(&env, &root, Some(&p)).unwrap().profiles, 1);
    }
}
