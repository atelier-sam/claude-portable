//! Environnement du processus, lu UNE fois (surcharges de test comprises).
//!
//! Les surcharges `CCP_*` existent pour les tests d'intégration (faux serveur,
//! trousseau temporaire) ; en production elles valent leurs défauts.

use crate::root::{to_windows_path, PathStyle};
use std::path::PathBuf;

pub const DEFAULT_API_BASE: &str = "https://api.anthropic.com";
pub const DEFAULT_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";

#[derive(Clone, Debug)]
pub struct Env {
    pub api_base: String,
    pub token_url: String,
    /// Trousseau explicite (tests : trousseau temporaire). `None` = trousseaux par défaut.
    pub keychain: Option<PathBuf>,
    /// `CCP_NO_KEYCHAIN=1` : ne jamais toucher au Trousseau (tests hermétiques).
    pub no_keychain: bool,
    pub home: PathBuf,
    pub user: String,
    /// Chemin du binaire claude donné par `--claude` ou `$CCP_CLAUDE_BIN`.
    pub claude: Option<String>,
    /// Surcharges des outils de la liaison Windows / distante (tests, installations atypiques).
    pub ovr: Overrides,
}

/// Surcharges `CCP_*` des commandes `win` et `remote`. En production elles sont vides.
///
/// Aucune ne porte de secret. Celles qui visent le réseau n'acceptent que le
/// bouclage HTTP, comme `CCP_TOKEN_URL`.
#[derive(Clone, Debug, Default)]
pub struct Overrides {
    /// `CCP_FAKE_WINDOWS=1` : joue les commandes `win` hors de Windows (faux winget).
    pub fake_windows: bool,
    /// `CCP_WINGET_BIN` : binaire winget à la place de celui du PATH.
    pub winget: Option<String>,
    /// `CCP_ODT_SETUP` : `setup.exe` de l'Office Deployment Tool déjà présent.
    pub odt_setup: Option<String>,
    /// `CCP_SSH_BIN` : client ssh à la place de celui du système (tests).
    pub ssh: Option<String>,
    /// `CCP_DOWNLOAD_BASE` : serveur des téléchargements épinglés (cloudflared, OpenSSH),
    /// bouclage HTTP seulement. Le SHA-256 épinglé reste exigé : un faux serveur ne passe pas.
    pub download_base: Option<String>,
    /// `CCP_ACCESS_URL` : adresse testée par `setup-mac` à la place du tunnel (bouclage seulement).
    pub access_url: Option<String>,
    /// `CCP_OPENSSH_DIR` : dossier d'un OpenSSH déjà présent (sshd, ssh-keygen) pour `remote share`.
    pub openssh_dir: Option<PathBuf>,
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn now_s() -> i64 {
    now_ms() / 1000
}

/// Surcharge d'URL réservée aux tests : acceptée SEULEMENT vers le bouclage.
/// Pourquoi : `CCP_TOKEN_URL` reçoit un refresh token. Une variable d'environnement
/// hostile ne doit pas pouvoir l'envoyer ailleurs que sur la machine elle-même.
fn loopback_override(name: &str) -> Option<String> {
    let v = nonempty(name)?;
    if is_loopback_http(&v) {
        Some(v)
    } else {
        eprintln!(
            "ccp-core : {name} ignorée (seul http://127.0.0.1 ou http://localhost est accepté)"
        );
        None
    }
}

pub fn is_loopback_http(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let name = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    matches!(name, "127.0.0.1" | "localhost" | "::1") && !host.contains('@')
}

fn nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

impl Env {
    pub fn from_process(claude_flag: Option<&str>) -> Env {
        let style = PathStyle::native();
        let fix = |s: String| {
            if style == PathStyle::Windows {
                to_windows_path(&s)
            } else {
                s
            }
        };
        let home = nonempty("HOME")
            .or_else(|| nonempty("USERPROFILE"))
            .map(PathBuf::from)
            .or_else(std::env::home_dir)
            .unwrap_or_else(|| PathBuf::from("."));
        let user = nonempty("USER")
            .or_else(|| nonempty("LOGNAME"))
            .or_else(|| nonempty("USERNAME"))
            .or_else(whoami_fallback)
            .unwrap_or_else(|| "user".to_string());
        Env {
            api_base: loopback_override("CCP_API_BASE")
                .unwrap_or_else(|| DEFAULT_API_BASE.to_string())
                .trim_end_matches('/')
                .to_string(),
            token_url: loopback_override("CCP_TOKEN_URL")
                .unwrap_or_else(|| DEFAULT_TOKEN_URL.to_string()),
            keychain: nonempty("CCP_KEYCHAIN").map(PathBuf::from),
            no_keychain: nonempty("CCP_NO_KEYCHAIN").is_some_and(|v| v == "1"),
            home,
            user,
            claude: claude_flag
                .map(|s| fix(s.to_string()))
                .or_else(|| nonempty("CCP_CLAUDE_BIN").map(fix)),
            ovr: Overrides {
                fake_windows: nonempty("CCP_FAKE_WINDOWS").is_some_and(|v| v == "1"),
                winget: nonempty("CCP_WINGET_BIN"),
                odt_setup: nonempty("CCP_ODT_SETUP"),
                ssh: nonempty("CCP_SSH_BIN"),
                download_base: loopback_override("CCP_DOWNLOAD_BASE")
                    .map(|u| u.trim_end_matches('/').to_string()),
                access_url: loopback_override("CCP_ACCESS_URL"),
                openssh_dir: nonempty("CCP_OPENSSH_DIR").map(PathBuf::from),
            },
        }
    }
}

/// `$USER` absent (environnement épuré d'un hook) : on demande à `id`.
fn whoami_fallback() -> Option<String> {
    if cfg!(windows) {
        return None;
    }
    let out = std::process::Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
impl Env {
    /// Environnement de test sans accès au vrai HOME ni au vrai Trousseau.
    pub fn for_tests(home: PathBuf) -> Env {
        Env {
            api_base: "http://127.0.0.1:1".into(),
            token_url: "http://127.0.0.1:1/token".into(),
            keychain: None,
            no_keychain: true,
            home,
            user: "testeur".into(),
            claude: None,
            ovr: Overrides::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_http_overrides_are_accepted() {
        assert!(is_loopback_http("http://127.0.0.1:8080/token"));
        assert!(is_loopback_http("http://localhost:1234"));
        assert!(is_loopback_http("http://[::1]:9/x"));
        assert!(!is_loopback_http("https://127.0.0.1/token"));
        assert!(!is_loopback_http("http://evil.example/token"));
        assert!(!is_loopback_http("http://127.0.0.1@evil.example/token"));
        assert!(!is_loopback_http("http://127.0.0.1.evil.example/"));
        assert!(!is_loopback_http("ftp://localhost"));
    }
}
