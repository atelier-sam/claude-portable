//! API Anthropic : profil, usage, renouvellement. Classification PURE des
//! réponses (testée sur des réponses figées) séparée du transport.
//!
//! Règles apprises à la dure (cf. ai-cluster `anthropicOauthUsage.ts`) :
//! - 429 sur `/api/oauth/usage` = limite PAR IP du point de statut, jamais un
//!   épuisement du compte : on garde la dernière bonne valeur.
//! - un 200 qui n'est pas du JSON attendu (portail captif) = hors ligne ;
//! - un 200 JSON sans champ connu = erreur de FORMAT, jamais « 0 % ».

use crate::http::{Http, HttpRequest, Method};
use crate::model::Bucket;
use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const BETA: &str = "oauth-2025-04-20";
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);
/// Un renouvellement fait tourner le jeton côté serveur : on lui laisse plus
/// de temps qu'une simple lecture, pour ne pas perdre la réponse.
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
/// Durée supposée d'un jeton si le serveur ne dit rien (8 h, mesurée).
const DEFAULT_EXPIRES_IN_S: i64 = 28_800;

#[derive(Debug, PartialEq)]
pub enum Fetch<T> {
    Ok(T),
    Unauthorized,
    Forbidden,
    RateLimited,
    /// Réseau coupé, délai, ou réponse qui n'est pas celle de l'API (portail captif).
    Unreachable(String),
    /// 200 mais JSON sans aucun champ connu.
    Format(String),
    /// Autre code HTTP (5xx, 4xx inattendu).
    Server(u16),
}

#[derive(Debug, PartialEq, Clone)]
pub struct ProfileInfo {
    pub email: Option<String>,
    pub tier: Option<String>,
    pub has_max: bool,
    pub has_pro: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub struct UsageInfo {
    pub five_hour: Option<Bucket>,
    pub seven_day: Option<Bucket>,
    pub seven_day_sonnet: Option<Bucket>,
}

pub enum RefreshResult {
    Renewed {
        access: SecretString,
        refresh: Option<SecretString>,
        expires_in_s: i64,
    },
    /// Le serveur a refusé ce refresh token : la lignée est morte.
    Revoked(String),
    /// Refus qui n'est PAS une révocation (requête mal formée…) : ne pas marquer.
    Rejected(String),
    /// Réseau, 429, 5xx : on réessaiera.
    Transient(String),
}

/// Statut HTTP commun aux sondes. `None` = c'est un 200 à analyser.
fn common<T>(status: u16, body: &str) -> Option<Fetch<T>> {
    match status {
        200 => None,
        401 => Some(Fetch::Unauthorized),
        403 => Some(Fetch::Forbidden),
        429 => Some(Fetch::RateLimited),
        511 => Some(Fetch::Unreachable("portail captif (HTTP 511)".into())),
        s => {
            let _ = body; // jamais de corps serveur dans nos messages
            Some(Fetch::Server(s))
        }
    }
}

fn json_or_unreachable<T>(body: &str) -> Result<Value, Fetch<T>> {
    match serde_json::from_str::<Value>(body) {
        Ok(v @ Value::Object(_)) => Ok(v),
        Ok(_) => Err(Fetch::Format("réponse JSON inattendue".into())),
        Err(_) => Err(Fetch::Unreachable(
            "réponse inattendue (portail captif ou proxy ?)".into(),
        )),
    }
}

pub fn classify_profile(status: u16, body: &str) -> Fetch<ProfileInfo> {
    if let Some(f) = common(status, body) {
        return f;
    }
    let v = match json_or_unreachable(body) {
        Ok(v) => v,
        Err(f) => return f,
    };
    let account = v.get("account").filter(|a| a.is_object());
    let org = v.get("organization").filter(|o| o.is_object());
    if account.is_none() && org.is_none() {
        return Fetch::Format("profil sans champ connu".into());
    }
    let s = |o: Option<&Value>, k: &str| {
        o.and_then(|o| o.get(k))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let b = |o: Option<&Value>, k: &str| {
        o.and_then(|o| o.get(k))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    Fetch::Ok(ProfileInfo {
        email: s(account, "email"),
        tier: s(org, "rate_limit_tier"),
        has_max: b(account, "has_claude_max"),
        has_pro: b(account, "has_claude_pro"),
    })
}

fn bucket(v: &Value, key: &str) -> Option<Bucket> {
    let b = v.get(key)?.as_object()?;
    let u = b.get("utilization")?.as_f64()?;
    if !u.is_finite() {
        return None;
    }
    let resets_at = b
        .get("resets_at")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(Bucket {
        pct: u.clamp(0.0, 999.0).trunc() as u32,
        resets_at,
    })
}

pub fn classify_usage(status: u16, body: &str) -> Fetch<UsageInfo> {
    if let Some(f) = common(status, body) {
        return f;
    }
    let v = match json_or_unreachable(body) {
        Ok(v) => v,
        Err(f) => return f,
    };
    let five = bucket(&v, "five_hour");
    let seven = bucket(&v, "seven_day");
    if five.is_none() && seven.is_none() {
        return Fetch::Format("usage sans fenêtre 5 h ni 7 j".into());
    }
    Fetch::Ok(UsageInfo {
        five_hour: five,
        seven_day: seven,
        seven_day_sonnet: bucket(&v, "seven_day_sonnet"),
    })
}

/// Code d'erreur d'une réponse du point de jeton, quelle que soit l'enveloppe.
fn refresh_error_code(body: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return String::new();
    };
    match v.get("error") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(o)) => o
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => String::new(),
    }
}

pub fn classify_refresh(status: u16, body: &str) -> RefreshResult {
    match status {
        200 => {
            let Ok(v) = serde_json::from_str::<Value>(body) else {
                return RefreshResult::Rejected("réponse de renouvellement illisible".into());
            };
            let Some(access) = v
                .get("access_token")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            else {
                return RefreshResult::Rejected(
                    "réponse de renouvellement sans jeton d'accès".into(),
                );
            };
            let refresh = v
                .get("refresh_token")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|s| SecretString::from(s.to_string()));
            let expires_in_s = v
                .get("expires_in")
                .and_then(|e| e.as_i64().or_else(|| e.as_f64().map(|f| f as i64)))
                .filter(|n| *n > 0)
                .unwrap_or(DEFAULT_EXPIRES_IN_S);
            RefreshResult::Renewed {
                access: SecretString::from(access.to_string()),
                refresh,
                expires_in_s,
            }
        }
        400 | 401 => {
            // MÊME règle que le Claude officiel (lue dans son binaire 2.1.319) : seul
            // `invalid_grant` en 400/401 condamne le refresh token. Le code est soit
            // `{"error":"invalid_grant"}` (OAuth), soit `{"error":{"type":"invalid_grant"}}`
            // (enveloppe Anthropic). Tout le reste (requête mal formée de NOTRE part,
            // format de jeton refusé, réponse muette…) n'est PAS une preuve de mort :
            // marquer « révoqué » sur un doute ferait perdre un compte vivant.
            let code = refresh_error_code(body);
            if code == "invalid_grant" {
                RefreshResult::Revoked(format!("renouvellement refusé : {code}"))
            } else if code.is_empty() {
                RefreshResult::Rejected(format!("renouvellement refusé (HTTP {status})"))
            } else {
                RefreshResult::Rejected(format!("renouvellement refusé (HTTP {status}, {code})"))
            }
        }
        429 => RefreshResult::Transient("renouvellement : trop de requêtes (429)".into()),
        s => RefreshResult::Transient(format!("renouvellement : réponse HTTP {s}")),
    }
}

#[derive(Clone)]
pub struct Api {
    http: Arc<dyn Http>,
    base: String,
    token_url: String,
}

impl Api {
    pub fn new(http: Arc<dyn Http>, base: &str, token_url: &str) -> Api {
        Api {
            http,
            base: base.trim_end_matches('/').to_string(),
            token_url: token_url.to_string(),
        }
    }

    fn get(&self, path: &str, access: &SecretString) -> Result<(u16, String), String> {
        let req = HttpRequest {
            method: Method::Get,
            url: format!("{}{path}", self.base),
            bearer: Some(access.clone()),
            headers: vec![("anthropic-beta", BETA.to_string())],
            body: None,
            connect_timeout: CONNECT_TIMEOUT,
            total_timeout: REQUEST_TIMEOUT,
        };
        self.http
            .send(&req)
            .map(|r| (r.status, r.body))
            .map_err(|e| e.message())
    }

    pub fn profile(&self, access: &SecretString) -> Fetch<ProfileInfo> {
        match self.get("/api/oauth/profile", access) {
            Ok((s, b)) => classify_profile(s, &b),
            Err(m) => Fetch::Unreachable(m),
        }
    }

    pub fn usage(&self, access: &SecretString) -> Fetch<UsageInfo> {
        match self.get("/api/oauth/usage", access) {
            Ok((s, b)) => classify_usage(s, &b),
            Err(m) => Fetch::Unreachable(m),
        }
    }

    pub fn refresh(&self, refresh_token: &SecretString) -> RefreshResult {
        let body = serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token.expose_secret(),
            "client_id": CLIENT_ID,
        })
        .to_string();
        let req = HttpRequest {
            method: Method::PostJson,
            url: self.token_url.clone(),
            bearer: None,
            headers: vec![],
            body: Some(SecretString::from(body)),
            connect_timeout: CONNECT_TIMEOUT,
            total_timeout: REFRESH_TIMEOUT,
        };
        match self.http.send(&req) {
            Ok(r) => classify_refresh(r.status, &r.body),
            Err(e) => {
                RefreshResult::Transient(format!("renouvellement impossible : {}", e.message()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"{"account":{"uuid":"u","email":"sam@x.fr","has_claude_max":true,"has_claude_pro":false},"organization":{"rate_limit_tier":"default_claude_max_20x","organization_type":"claude_max"}}"#;
    const USAGE: &str = r#"{"five_hour":{"utilization":12.7,"resets_at":"2026-11-09T04:00:00.123456+00:00"},"seven_day":{"utilization":40.0,"resets_at":"2026-11-12T10:00:00Z"},"seven_day_sonnet":null,"seven_day_opus":null,"extra_usage":{"is_enabled":false}}"#;

    #[test]
    fn profile_ok() {
        let Fetch::Ok(p) = classify_profile(200, PROFILE) else {
            panic!()
        };
        assert_eq!(p.email.as_deref(), Some("sam@x.fr"));
        assert_eq!(p.tier.as_deref(), Some("default_claude_max_20x"));
        assert!(p.has_max && !p.has_pro);
    }

    #[test]
    fn profile_status_mapping() {
        assert_eq!(classify_profile(401, "{}"), Fetch::Unauthorized);
        assert_eq!(classify_profile(403, "{}"), Fetch::Forbidden);
        assert_eq!(classify_profile(429, "{}"), Fetch::RateLimited);
        assert_eq!(classify_profile(503, "boum"), Fetch::Server(503));
        assert!(matches!(
            classify_profile(511, "<html>"),
            Fetch::Unreachable(_)
        ));
    }

    #[test]
    fn captive_portal_is_unreachable_not_error() {
        let html = "<html><body>Connectez-vous au Wi-Fi</body></html>";
        assert!(matches!(classify_profile(200, html), Fetch::Unreachable(_)));
        assert!(matches!(classify_usage(200, html), Fetch::Unreachable(_)));
        assert!(matches!(classify_usage(200, ""), Fetch::Unreachable(_)));
    }

    #[test]
    fn unknown_json_is_a_format_error_never_zero_percent() {
        assert!(matches!(classify_usage(200, "{}"), Fetch::Format(_)));
        assert!(matches!(
            classify_usage(200, r#"{"foo":1}"#),
            Fetch::Format(_)
        ));
        assert!(matches!(
            classify_usage(200, r#"{"five_hour":null,"seven_day":null}"#),
            Fetch::Format(_)
        ));
        assert!(matches!(
            classify_usage(200, r#"{"five_hour":{"utilization":null}}"#),
            Fetch::Format(_)
        ));
        assert!(matches!(classify_usage(200, "[1,2]"), Fetch::Format(_)));
        assert!(matches!(classify_profile(200, "{}"), Fetch::Format(_)));
    }

    #[test]
    fn usage_ok_truncates_percentages() {
        let Fetch::Ok(u) = classify_usage(200, USAGE) else {
            panic!()
        };
        assert_eq!(u.five_hour.as_ref().unwrap().pct, 12);
        assert_eq!(u.seven_day.as_ref().unwrap().pct, 40);
        assert!(u.seven_day_sonnet.is_none());
        assert_eq!(
            u.seven_day.unwrap().resets_at.as_deref(),
            Some("2026-11-12T10:00:00Z")
        );
    }

    #[test]
    fn usage_99_9_is_not_limited() {
        let body = r#"{"five_hour":{"utilization":99.9,"resets_at":null},"seven_day":{"utilization":100.0,"resets_at":null}}"#;
        let Fetch::Ok(u) = classify_usage(200, body) else {
            panic!()
        };
        assert_eq!(u.five_hour.unwrap().pct, 99);
        assert_eq!(u.seven_day.unwrap().pct, 100);
    }

    #[test]
    fn usage_429_is_rate_limited_not_exhausted() {
        assert_eq!(
            classify_usage(429, r#"{"error":"rate_limited"}"#),
            Fetch::RateLimited
        );
    }

    #[test]
    fn refresh_200_with_rotation() {
        let body = r#"{"access_token":"A2","refresh_token":"R2","expires_in":28800,"token_type":"Bearer"}"#;
        let RefreshResult::Renewed {
            access,
            refresh,
            expires_in_s,
        } = classify_refresh(200, body)
        else {
            panic!()
        };
        assert_eq!(access.expose_secret(), "A2");
        assert_eq!(refresh.unwrap().expose_secret(), "R2");
        assert_eq!(expires_in_s, 28800);
    }

    #[test]
    fn refresh_200_garbage_is_rejected_not_renewed() {
        assert!(matches!(
            classify_refresh(200, "<html>"),
            RefreshResult::Rejected(_)
        ));
        assert!(matches!(
            classify_refresh(200, "{}"),
            RefreshResult::Rejected(_)
        ));
    }

    #[test]
    fn only_invalid_grant_revokes_like_the_official_client() {
        // les deux enveloppes d'erreur
        for body in [
            r#"{"error":"invalid_grant","error_description":"Refresh token not found or invalid"}"#,
            r#"{"error":{"type":"invalid_grant","message":"x"}}"#,
        ] {
            assert!(
                matches!(classify_refresh(400, body), RefreshResult::Revoked(_)),
                "{body}"
            );
            assert!(
                matches!(classify_refresh(401, body), RefreshResult::Revoked(_)),
                "{body}"
            );
        }
        // tout le reste est un refus qui ne condamne pas le login
        for (st, body) in [
            (400, ""),
            (401, "{}"),
            (400, r#"{"error":"invalid_client"}"#),
            (400, r#"{"error":"invalid_request"}"#),
            (400, r#"{"error":"invalid_scope"}"#),
            (400, r#"{"error":{"type":"invalid_request_error"}}"#),
            (401, r#"{"error":{"type":"authentication_error"}}"#),
        ] {
            assert!(
                matches!(classify_refresh(st, body), RefreshResult::Rejected(_)),
                "{st} {body}"
            );
        }
        assert!(matches!(
            classify_refresh(429, r#"{"error":{"type":"rate_limit_error"}}"#),
            RefreshResult::Transient(_)
        ));
        assert!(matches!(
            classify_refresh(502, ""),
            RefreshResult::Transient(_)
        ));
    }
}
