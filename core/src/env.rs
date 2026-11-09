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
    pub home: PathBuf,
    pub user: String,
    /// Chemin du binaire claude donné par `--claude` ou `$CCP_CLAUDE_BIN`.
    pub claude: Option<String>,
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
            api_base: nonempty("CCP_API_BASE")
                .unwrap_or_else(|| DEFAULT_API_BASE.to_string())
                .trim_end_matches('/')
                .to_string(),
            token_url: nonempty("CCP_TOKEN_URL").unwrap_or_else(|| DEFAULT_TOKEN_URL.to_string()),
            keychain: nonempty("CCP_KEYCHAIN").map(PathBuf::from),
            home,
            user,
            claude: claude_flag
                .map(|s| fix(s.to_string()))
                .or_else(|| nonempty("CCP_CLAUDE_BIN").map(fix)),
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
            home,
            user: "testeur".into(),
            claude: None,
        }
    }
}
