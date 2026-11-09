//! Le binaire `claude` vu de ccp-core : où il est, sa version, et ce que dit
//! `claude auth status --json` (source OFFICIELLE de l'état local d'un login).
//!
//! `auth status` ne vérifie PAS la validité du jeton (un login expiré peut
//! afficher `loggedIn: true`) : il sert à `doctor` pour détecter une divergence
//! avec ce que ccp-core lit lui-même, et à `discover` en dernier recours pour
//! trouver un email absent de `.claude.json`.

use crate::env::Env;
use crate::root::{claude_exe_name, claude_platform, Root};
use crate::util::run_bounded;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const AUTH_STATUS_TIMEOUT: Duration = Duration::from_secs(8);

/// `--claude` / `$CCP_CLAUDE_BIN`, sinon `<racine>/bin/<plateforme>/claude[.exe]`.
pub fn resolve(env: &Env, root: &Root) -> PathBuf {
    match &env.claude {
        Some(c) => PathBuf::from(c),
        None => root
            .path()
            .join("bin")
            .join(claude_platform())
            .join(claude_exe_name()),
    }
}

/// Environnement d'un appel à claude pour `cfg` (`None` = login de la machine,
/// sans `CLAUDE_CONFIG_DIR`). Rien d'hérité qui fausserait le magasin lu.
pub fn command(claude: &std::path::Path, cfg: Option<&str>) -> Command {
    let mut c = Command::new(claude);
    c.env("DISABLE_AUTOUPDATER", "1")
        .env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    match cfg {
        Some(cfg) => {
            c.env("CLAUDE_CONFIG_DIR", cfg);
        }
        None => {
            c.env_remove("CLAUDE_CONFIG_DIR");
        }
    }
    c
}

#[derive(Debug, Clone, Default)]
pub struct AuthStatus {
    pub logged_in: bool,
    pub email: Option<String>,
    pub plan_tier: Option<String>,
    pub subscription: Option<String>,
    pub login_expires_at_ms: Option<i64>,
}

pub fn parse_auth_status(text: &str) -> Result<AuthStatus, String> {
    let v: Value = serde_json::from_str(text.trim())
        .map_err(|e| format!("sortie de `claude auth status` illisible ({e})"))?;
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|x| !x.is_empty())
    };
    Ok(AuthStatus {
        logged_in: v.get("loggedIn").and_then(Value::as_bool).unwrap_or(false),
        email: s("email"),
        plan_tier: s("planTier"),
        subscription: s("subscriptionType"),
        login_expires_at_ms: s("loginExpiresAt")
            .and_then(|t| crate::timefmt::parse_epoch(&t))
            .map(|sec| sec * 1000),
    })
}

/// `claude auth status --json` pour `cfg`. Erreur lisible si claude est absent,
/// bloque (8 s) ou répond autre chose que du JSON.
pub fn auth_status(claude: &std::path::Path, cfg: Option<&str>) -> Result<AuthStatus, String> {
    let mut c = command(claude, cfg);
    c.args(["auth", "status", "--json"]);
    let out = run_bounded(&mut c, None, AUTH_STATUS_TIMEOUT)
        .map_err(|e| format!("impossible de lancer claude ({e})"))?;
    if out.timed_out() {
        return Err("`claude auth status` n'a pas répondu en 8 s".into());
    }
    // « non connecté » sort parfois en code 1 avec un JSON valide : on lit le JSON d'abord.
    parse_auth_status(&out.stdout_str()).map_err(|e| {
        let err = out.stderr_str();
        match err.lines().next() {
            Some(l) if !l.trim().is_empty() => format!("{e} : {}", l.trim()),
            _ => e,
        }
    })
}

/// `claude --version` -> « 2.1.319 » (premier mot numérique).
pub fn version(claude: &std::path::Path) -> Result<String, String> {
    let mut c = command(claude, None);
    c.arg("--version");
    let out = run_bounded(&mut c, None, Duration::from_secs(8))
        .map_err(|e| format!("impossible de lancer claude ({e})"))?;
    if out.timed_out() {
        return Err("`claude --version` n'a pas répondu en 8 s".into());
    }
    if out.code() != Some(0) {
        return Err(format!(
            "`claude --version` a échoué (code {})",
            out.code().map_or("?".into(), |c| c.to_string())
        ));
    }
    let s = out.stdout_str();
    Ok(s.split_whitespace().next().unwrap_or("").trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_auth_status_shape() {
        let j = r#"{"loggedIn":true,"authMethod":"claude.ai","email":"contact@atelier-sam.fr",
            "subscriptionType":"max","planTier":"max_20x","loginExpiresAt":"2026-12-06T00:57:42.301Z"}"#;
        let a = parse_auth_status(j).unwrap();
        assert!(a.logged_in);
        assert_eq!(a.email.as_deref(), Some("contact@atelier-sam.fr"));
        assert_eq!(a.plan_tier.as_deref(), Some("max_20x"));
        assert_eq!(a.login_expires_at_ms, Some(1_796_518_662_000));
    }

    #[test]
    fn logged_out_has_no_fields() {
        let a = parse_auth_status(r#"{"loggedIn":false}"#).unwrap();
        assert!(!a.logged_in && a.email.is_none() && a.login_expires_at_ms.is_none());
    }

    #[test]
    fn garbage_is_a_readable_error() {
        assert!(parse_auth_status("Erreur: réseau")
            .unwrap_err()
            .contains("illisible"));
    }
}
