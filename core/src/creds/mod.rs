//! Magasins d'identifiants de Claude Code, lus et réécrits SANS les abîmer.
//!
//! Claude range un login dans `{"claudeAiOauth":{…}, "mcpOAuth":{…}?}` : soit dans
//! le Trousseau macOS (un item par `CLAUDE_CONFIG_DIR`), soit dans
//! `<cfg>/.credentials.json` (Windows, Linux, et repli macOS). Un jeton longue
//! durée (`setup-token`) vit dans `<cfg>/oauth.token`.
//!
//! On réécrit TOUJOURS dans le magasin d'origine, en conservant toutes les
//! clés qu'on ne comprend pas (mcpOAuth…) : la moindre perte casse la vraie
//! session de Claude.

pub mod keychain;

use crate::atomic::write_atomic;
use crate::env::Env;
use crate::root::ProfileDir;
use crate::util::fingerprint;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    Keychain,
    File,
    Token,
    None,
}

/// Le JSON complet d'un magasin. Pas de `Debug` dérivé : il contient des jetons.
#[derive(Clone)]
pub struct CredBlob {
    value: Value,
}

impl std::fmt::Debug for CredBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredBlob(<masqué>)")
    }
}

impl CredBlob {
    pub fn parse(s: &str) -> Result<CredBlob, String> {
        match serde_json::from_str::<Value>(s) {
            Ok(v @ Value::Object(_)) => Ok(CredBlob { value: v }),
            Ok(_) => Err("le magasin n'est pas un objet JSON".into()),
            Err(_) => Err("JSON invalide".into()),
        }
    }

    pub fn to_json(&self) -> String {
        // serde_json ne peut pas échouer sur un Value valide.
        serde_json::to_string(&self.value).unwrap_or_default()
    }

    fn oauth(&self) -> Option<&Map<String, Value>> {
        self.value.get("claudeAiOauth")?.as_object()
    }

    fn oauth_str(&self, key: &str) -> Option<&str> {
        self.oauth()?.get(key)?.as_str().filter(|s| !s.is_empty())
    }

    pub fn access_token(&self) -> Option<SecretString> {
        self.oauth_str("accessToken")
            .map(|s| SecretString::from(s.to_string()))
    }

    pub fn refresh_token(&self) -> Option<SecretString> {
        self.oauth_str("refreshToken")
            .map(|s| SecretString::from(s.to_string()))
    }

    /// Y a-t-il un login exploitable (et pas seulement un `mcpOAuth` orphelin) ?
    pub fn has_login(&self) -> bool {
        self.oauth_str("accessToken").is_some() || self.oauth_str("refreshToken").is_some()
    }

    pub fn expires_at_ms(&self) -> Option<i64> {
        let n = self.oauth()?.get("expiresAt")?;
        n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))
    }

    pub fn scopes(&self) -> Vec<String> {
        self.oauth()
            .and_then(|o| o.get("scopes"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn subscription_type(&self) -> Option<String> {
        self.oauth_str("subscriptionType").map(str::to_string)
    }

    pub fn rate_limit_tier(&self) -> Option<String> {
        self.oauth_str("rateLimitTier").map(str::to_string)
    }

    /// Identité de la LIGNÉE de login : change quand l'utilisateur se reconnecte
    /// ou quand le jeton tourne ; sert à invalider caches et marqueurs.
    pub fn fingerprint(&self) -> String {
        match self.refresh_token().or_else(|| self.access_token()) {
            Some(t) => fingerprint(t.expose_secret()),
            None => "none".to_string(),
        }
    }

    /// Applique un renouvellement en ne touchant QUE les trois champs concernés.
    pub fn apply_renewal(&mut self, access: &str, refresh: Option<&str>, expires_at_ms: i64) {
        let Value::Object(root) = &mut self.value else {
            return;
        };
        let oauth = root
            .entry("claudeAiOauth")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(o) = oauth {
            o.insert("accessToken".into(), Value::String(access.to_string()));
            if let Some(r) = refresh {
                o.insert("refreshToken".into(), Value::String(r.to_string()));
            }
            o.insert("expiresAt".into(), Value::from(expires_at_ms));
        }
    }
}

/// Un login lu dans son magasin d'origine.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub kind: StoreKind,
    pub blob: CredBlob,
    /// Compte de l'item Trousseau (réutilisé à la réécriture).
    pub acct: Option<String>,
    /// Service du Trousseau (macOS), pour le diagnostic.
    pub service: Option<String>,
}

#[derive(Debug, Clone)]
pub enum StoreError {
    /// « Trousseau verrouillé »
    Locked(String),
    Corrupt(String),
    Io(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Locked(m) | StoreError::Corrupt(m) | StoreError::Io(m) => f.write_str(m),
        }
    }
}

fn read_file_store(p: &ProfileDir) -> Result<Option<Loaded>, StoreError> {
    let path = p.credentials_file();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(StoreError::Io(format!(
                "lecture de .credentials.json impossible : {e}"
            )))
        }
    };
    let blob = CredBlob::parse(&text)
        .map_err(|m| StoreError::Corrupt(format!("identifiants illisibles ({m})")))?;
    Ok(Some(Loaded {
        kind: StoreKind::File,
        blob,
        acct: None,
        service: None,
    }))
}

/// Lit le login du profil : Trousseau d'abord sous macOS, puis le fichier
/// (repli que Claude utilise lui-même quand le Trousseau est inutilisable).
pub fn read_login(env: &Env, p: &ProfileDir) -> Result<Option<Loaded>, StoreError> {
    #[cfg(target_os = "macos")]
    {
        let svc = keychain::service_name(&p.cfg);
        match keychain::find(env, &svc) {
            Ok(Some(item)) => {
                let blob = CredBlob::parse(&item.secret).map_err(|m| {
                    StoreError::Corrupt(format!("item du Trousseau illisible ({m})"))
                })?;
                return Ok(Some(Loaded {
                    kind: StoreKind::Keychain,
                    blob,
                    acct: Some(item.acct),
                    service: Some(svc),
                }));
            }
            Ok(None) => {}
            Err(keychain::KcError::Locked(m)) => return Err(StoreError::Locked(m)),
            Err(keychain::KcError::Failed(m)) => return Err(StoreError::Io(m)),
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = env;
    read_file_store(p)
}

/// Réécrit `blob` dans le magasin d'où `from` a été lu.
pub fn write_login(
    env: &Env,
    p: &ProfileDir,
    from: &Loaded,
    blob: &CredBlob,
) -> Result<(), StoreError> {
    match from.kind {
        StoreKind::File => write_atomic(&p.credentials_file(), blob.to_json().as_bytes())
            .map_err(|e| StoreError::Io(format!("écriture de .credentials.json impossible : {e}"))),
        #[cfg(target_os = "macos")]
        StoreKind::Keychain => {
            let svc = keychain::service_name(&p.cfg);
            let acct = from.acct.clone().unwrap_or_else(|| env.user.clone());
            keychain::upsert(env, &acct, &svc, &blob.to_json()).map_err(|e| match e {
                keychain::KcError::Locked(m) => StoreError::Locked(m),
                keychain::KcError::Failed(m) => StoreError::Io(m),
            })
        }
        _ => {
            let _ = env;
            Err(StoreError::Io(
                "magasin non inscriptible sur ce système".into(),
            ))
        }
    }
}

/// Jeton longue durée (`oauth.token`), rogné ; vide = absent.
pub fn read_token(p: &ProfileDir) -> Option<SecretString> {
    let t = std::fs::read_to_string(p.token_file()).ok()?;
    let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    (!t.is_empty()).then(|| SecretString::from(t))
}

/// Forfait déclaré à la main pour un jeton longue durée (`<cfg>/plan`, une ligne).
pub fn read_declared_plan(p: &ProfileDir) -> Option<String> {
    let t = std::fs::read_to_string(p.plan_file()).ok()?;
    let line = t.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(line.chars().take(40).collect())
}

/// Email local : `<cfg>/.claude.json` → `oauthAccount.emailAddress`.
pub fn read_local_email(dir: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(".claude.json")).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    v.get("oauthAccount")?
        .get("emailAddress")?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"claudeAiOauth":{"accessToken":"AT1","refreshToken":"RT1","expiresAt":1762650000000,"scopes":["user:inference","user:profile"],"subscriptionType":"max","rateLimitTier":"default_claude_max_20x","extraInconnu":{"a":[1,2,3]}},"mcpOAuth":{"srv|abc":{"accessToken":"MCP","expiresAt":0}},"autreCle":42}"#;

    #[test]
    fn accessors() {
        let b = CredBlob::parse(SAMPLE).unwrap();
        assert!(b.has_login());
        assert_eq!(b.expires_at_ms(), Some(1762650000000));
        assert_eq!(b.access_token().unwrap().expose_secret(), "AT1");
        assert_eq!(b.scopes(), ["user:inference", "user:profile"]);
        assert_eq!(b.subscription_type().as_deref(), Some("max"));
        assert_eq!(
            b.rate_limit_tier().as_deref(),
            Some("default_claude_max_20x")
        );
    }

    #[test]
    fn renewal_preserves_every_other_key() {
        let mut b = CredBlob::parse(SAMPLE).unwrap();
        let before_fp = b.fingerprint();
        b.apply_renewal("AT2", Some("RT2"), 1762660000000);
        let v: Value = serde_json::from_str(&b.to_json()).unwrap();
        assert_eq!(v["claudeAiOauth"]["accessToken"], "AT2");
        assert_eq!(v["claudeAiOauth"]["refreshToken"], "RT2");
        assert_eq!(v["claudeAiOauth"]["expiresAt"], 1762660000000i64);
        // tout le reste est intact
        assert_eq!(v["claudeAiOauth"]["scopes"][1], "user:profile");
        assert_eq!(v["claudeAiOauth"]["subscriptionType"], "max");
        assert_eq!(v["claudeAiOauth"]["extraInconnu"]["a"][2], 3);
        assert_eq!(v["mcpOAuth"]["srv|abc"]["accessToken"], "MCP");
        assert_eq!(v["autreCle"], 42);
        assert_ne!(before_fp, b.fingerprint());
    }

    #[test]
    fn renewal_without_new_refresh_keeps_old_one() {
        let mut b = CredBlob::parse(SAMPLE).unwrap();
        b.apply_renewal("AT2", None, 5);
        assert_eq!(b.refresh_token().unwrap().expose_secret(), "RT1");
    }

    #[test]
    fn mcp_only_blob_has_no_login() {
        let b = CredBlob::parse(r#"{"mcpOAuth":{"x":{}}}"#).unwrap();
        assert!(!b.has_login());
        assert_eq!(b.fingerprint(), "none");
    }

    #[test]
    fn rejects_non_objects_and_garbage() {
        assert!(CredBlob::parse("[]").is_err());
        assert!(CredBlob::parse("pas du json").is_err());
        assert!(CredBlob::parse("").is_err());
    }

    #[test]
    fn debug_never_leaks() {
        let b = CredBlob::parse(SAMPLE).unwrap();
        assert!(!format!("{b:?}").contains("AT1"));
    }

    fn pdir(t: &tempfile::TempDir) -> ProfileDir {
        use crate::root::{PathStyle, Profile, Root};
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let p = r.profile(&Profile::parse("p").unwrap());
        std::fs::create_dir_all(&p.dir).unwrap();
        p
    }

    #[test]
    fn file_store_read_write_roundtrip() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        std::fs::write(p.credentials_file(), SAMPLE).unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        // Sous macOS on interroge le Trousseau réel pour le service de ce chemin
        // temporaire : il n'y a rien, on retombe sur le fichier.
        let l = read_login(&env, &p).unwrap().unwrap();
        assert_eq!(l.kind, StoreKind::File);
        let mut nb = l.blob.clone();
        nb.apply_renewal("N", Some("M"), 9);
        write_login(&env, &p, &l, &nb).unwrap();
        let again = read_login(&env, &p).unwrap().unwrap();
        assert_eq!(again.blob.access_token().unwrap().expose_secret(), "N");
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_panic() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        std::fs::write(p.credentials_file(), "{ cassé").unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        assert!(matches!(read_login(&env, &p), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn token_and_declared_plan_and_local_email() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        assert!(read_token(&p).is_none());
        std::fs::write(p.token_file(), "  sk-ant-oat01-abc \n").unwrap();
        assert_eq!(read_token(&p).unwrap().expose_secret(), "sk-ant-oat01-abc");
        std::fs::write(p.plan_file(), "\n Max x5 \nautre\n").unwrap();
        assert_eq!(read_declared_plan(&p).as_deref(), Some("Max x5"));
        std::fs::write(
            p.claude_json(),
            r#"{"oauthAccount":{"emailAddress":"a@b.fr"}}"#,
        )
        .unwrap();
        assert_eq!(read_local_email(&p.dir).as_deref(), Some("a@b.fr"));
    }
}
