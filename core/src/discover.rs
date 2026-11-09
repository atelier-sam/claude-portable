//! Réindexation : inventaire EN LECTURE SEULE des logins Claude de la machine.
//!
//! Sources : `~/.claude` (service Trousseau SANS suffixe), `~/.claude-profiles/*`,
//! `~/.config/meridian/profiles/*`, `$CLAUDE_CONFIG_DIR`, et les profils du
//! portable. Aucun réseau, aucun renouvellement, aucune copie : copier un
//! refresh token dupliquerait la lignée OAuth, et la première copie qui se
//! renouvelle révoque l'autre. Un compte absent du portable se RECONNECTE
//! (nouvelle lignée), il ne se copie jamais.

use crate::claude_cli;
use crate::creds::{self, keychain, StoreError, StoreKind};
use crate::env::{now_ms, Env};
use crate::root::{Profile, ProfileDir, Root};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Machine,
    ClaudeProfiles,
    Meridian,
    Env,
    Portable,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginState {
    /// Jeton d'accès encore valide d'après sa date d'expiration locale.
    Valid,
    /// Jeton d'accès périmé mais login vivant : Claude le renouvellera à l'usage
    /// (`refreshTokenExpiresAt` dans le futur, ou `claude auth status` dit « connecté »).
    Renewable,
    /// Plus de login exploitable : refresh token périmé, ou Claude ne le voit plus connecté.
    Expired,
    /// `oauth.token` seul (jeton longue durée) : pas de date.
    LongToken,
    /// Dossier connu, aucun identifiant.
    NoLogin,
    Locked,
    Unreadable,
}

#[derive(Clone, Debug, Serialize)]
pub struct Found {
    pub origin: Origin,
    /// Libellé court pour l'écran (`~/.claude`, `meridian/sora`…).
    pub label: String,
    pub path: String,
    pub store: StoreKind,
    pub email: Option<String>,
    pub plan: Option<String>,
    /// Le forfait vient des identifiants locaux (peut être périmé) : `accounts status` le vérifie en ligne.
    pub plan_source: &'static str,
    /// Fin de vie du jeton d'accès (ms).
    pub expires_at: Option<i64>,
    /// Fin de vie du login = du refresh token (ms), connue des Claude récents seulement.
    pub refresh_expires_at: Option<i64>,
    pub state: LoginState,
    pub detail: Option<String>,
    pub in_portable: bool,
    pub portable_profile: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Inventory {
    pub schema: u32,
    pub generated_at: i64,
    pub logins: Vec<Found>,
}

struct Location {
    origin: Origin,
    label: String,
    /// Valeur EXACTE de `CLAUDE_CONFIG_DIR` pour ce profil ; `None` pour le login de la machine.
    cfg: Option<String>,
    dir: PathBuf,
    /// Fichiers `.claude.json` à essayer, dans l'ordre.
    claude_json: Vec<PathBuf>,
}

fn subdirs(parent: &Path) -> Vec<(String, PathBuf)> {
    let mut v: Vec<(String, PathBuf)> = std::fs::read_dir(parent)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| Some((e.file_name().to_str()?.to_string(), e.path())))
        .filter(|(n, _)| !n.starts_with('.'))
        .collect();
    v.sort();
    v
}

fn email_from_claude_json(files: &[PathBuf]) -> Option<String> {
    files.iter().find_map(|f| {
        let dir = f.parent()?;
        if f.file_name()? != ".claude.json" {
            return None;
        }
        creds::read_local_email(dir)
    })
}

fn locations(env: &Env, root: &Root) -> Vec<Location> {
    let mut out: Vec<Location> = Vec::new();
    let home = &env.home;
    let sep = |p: &Path| p.to_string_lossy().into_owned();

    // Login de la machine : sa config globale est ~/.claude.json (pas ~/.claude/.claude.json).
    out.push(Location {
        origin: Origin::Machine,
        label: "~/.claude".into(),
        cfg: None,
        dir: home.join(".claude"),
        claude_json: vec![
            home.join(".claude.json"),
            home.join(".claude").join(".claude.json"),
        ],
    });
    for (name, dir) in subdirs(&home.join(".claude-profiles")) {
        out.push(Location {
            origin: Origin::ClaudeProfiles,
            label: format!("profiles/{name}"),
            cfg: Some(sep(&dir)),
            claude_json: vec![dir.join(".claude.json")],
            dir,
        });
    }
    for (name, dir) in subdirs(&home.join(".config").join("meridian").join("profiles")) {
        out.push(Location {
            origin: Origin::Meridian,
            label: format!("meridian/{name}"),
            cfg: Some(sep(&dir)),
            claude_json: vec![dir.join(".claude.json")],
            dir,
        });
    }
    if let Some(v) = std::env::var("CLAUDE_CONFIG_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
    {
        let already = out
            .iter()
            .any(|l| l.cfg.as_deref() == Some(v.trim_end_matches('/')));
        if !already {
            let dir = PathBuf::from(&v);
            out.push(Location {
                origin: Origin::Env,
                label: "$CLAUDE_CONFIG_DIR".into(),
                cfg: Some(v),
                claude_json: vec![dir.join(".claude.json")],
                dir,
            });
        }
    }
    for name in root.list_profiles() {
        let p = root.profile(&name);
        out.push(Location {
            origin: Origin::Portable,
            label: format!("portable/{name}"),
            cfg: Some(p.cfg.clone()),
            claude_json: vec![p.dir.join(".claude.json")],
            dir: p.dir,
        });
    }
    out
}

/// État local d'un login d'après ses deux dates. Sans `refreshTokenExpiresAt`
/// (anciens items) et avec un jeton d'accès périmé, on ne peut pas conclure hors
/// ligne : `Expired` provisoire, affiné par `claude auth status` si disponible.
fn classify(access_exp: Option<i64>, refresh_exp: Option<i64>, now: i64) -> LoginState {
    match (access_exp, refresh_exp) {
        (Some(a), _) if a > now + 60_000 => LoginState::Valid,
        (_, Some(r)) if r > now => LoginState::Renewable,
        _ => LoginState::Expired,
    }
}

/// Lit un emplacement sans rien modifier. `keychain_locked` : une fois le Trousseau
/// vu verrouillé, on ne retente pas (8 s d'attente par appel sinon).
fn inspect(env: &Env, loc: &Location, keychain_locked: &mut bool) -> Found {
    let mut f = Found {
        origin: loc.origin,
        label: loc.label.clone(),
        path: loc.dir.to_string_lossy().into_owned(),
        store: StoreKind::None,
        email: email_from_claude_json(&loc.claude_json),
        plan: None,
        plan_source: "local",
        expires_at: None,
        refresh_expires_at: None,
        state: LoginState::NoLogin,
        detail: None,
        in_portable: false,
        portable_profile: None,
    };
    let service = match &loc.cfg {
        Some(cfg) => keychain::service_name(cfg),
        None => keychain::SERVICE_BASE.to_string(),
    };
    let read = if *keychain_locked {
        Err(StoreError::Locked("Trousseau verrouillé".into()))
    } else {
        creds::read_login_at(env, &service, &loc.dir.join(".credentials.json"))
    };
    match read {
        Ok(Some(l)) if l.blob.has_login() => {
            f.store = l.kind;
            f.expires_at = l.blob.expires_at_ms();
            f.refresh_expires_at = l.blob.refresh_expires_at_ms();
            f.state = classify(f.expires_at, f.refresh_expires_at, now_ms());
            f.plan = crate::plan::from_credentials(
                l.blob.subscription_type().as_deref(),
                l.blob.rate_limit_tier().as_deref(),
            )
            .map(|p| p.trim_end_matches(" (?)").to_string());
        }
        Ok(_) => {
            if loc.dir.join("oauth.token").is_file() {
                f.store = StoreKind::Token;
                f.state = LoginState::LongToken;
            }
        }
        Err(StoreError::Locked(m)) => {
            *keychain_locked = true;
            f.state = LoginState::Locked;
            f.detail = Some(m);
        }
        Err(e) => {
            f.state = LoginState::Unreadable;
            f.detail = Some(e.to_string());
        }
    }
    f
}

/// Complète via `claude auth status` (source officielle, locale, sans réseau) :
/// l'email manquant, et le verdict « connecté ou non » pour un login dont le jeton
/// d'accès est périmé et dont la fin de vie n'est pas écrite (anciens items).
/// En parallèle, 8 s au plus par appel. Absent si le binaire Claude est introuvable.
fn refine_with_claude(env: &Env, root: &Root, locs: &[Location], logins: &mut [Found]) {
    let claude = claude_cli::resolve(env, root);
    if !claude.is_file() {
        return;
    }
    let wanted: Vec<usize> = logins
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            let has_login = matches!(
                f.state,
                LoginState::Valid | LoginState::Renewable | LoginState::Expired
            );
            let needs_verdict = f.state == LoginState::Expired && f.refresh_expires_at.is_none();
            has_login && (f.email.is_none() || needs_verdict)
        })
        .map(|(i, _)| i)
        .collect();
    let answers: Vec<(usize, Option<claude_cli::AuthStatus>)> = std::thread::scope(|sc| {
        let handles: Vec<_> = wanted
            .iter()
            .map(|&i| {
                let claude = &claude;
                let cfg = locs[i].cfg.as_deref();
                (
                    i,
                    sc.spawn(move || claude_cli::auth_status(claude, cfg).ok()),
                )
            })
            .collect();
        handles
            .into_iter()
            .map(|(i, h)| (i, h.join().ok().flatten()))
            .collect()
    });
    for (i, a) in answers {
        let (Some(a), Some(f)) = (a, logins.get_mut(i)) else {
            continue;
        };
        if f.email.is_none() {
            f.email = a.email.clone();
        }
        if f.state == LoginState::Expired && f.refresh_expires_at.is_none() {
            if a.logged_in {
                f.state = LoginState::Renewable;
            } else {
                f.detail = Some("Claude ne voit plus ce compte connecté".into());
            }
        }
    }
}

pub fn scan(env: &Env, root: &Root) -> Inventory {
    let locs = locations(env, root);
    let mut locked = false;
    let mut logins: Vec<Found> = locs.iter().map(|l| inspect(env, l, &mut locked)).collect();
    refine_with_claude(env, root, &locs, &mut logins);

    // Emails des profils du portable ayant un login : référence de « déjà présent ».
    let mut portable: HashMap<String, String> = HashMap::new();
    for (loc, f) in locs.iter().zip(logins.iter_mut()) {
        if loc.origin != Origin::Portable {
            continue;
        }
        let name = loc.label.trim_start_matches("portable/").to_string();
        f.in_portable = true;
        f.portable_profile = Some(name.clone());
        // Le cache connaît l'email vérifié par le serveur : il prime sur `.claude.json`.
        if let Ok(pn) = Profile::parse(&name) {
            let pd: ProfileDir = root.profile(&pn);
            if let Some(e) = crate::cache::load(&pd)
                .and_then(|c| c.identity)
                .and_then(|i| i.email)
            {
                f.email = Some(e);
            }
        }
        let has_credentials = !matches!(f.state, LoginState::NoLogin);
        if has_credentials {
            if let Some(e) = &f.email {
                portable.entry(e.to_lowercase()).or_insert(name);
            }
        }
    }
    for f in logins.iter_mut().filter(|f| f.origin != Origin::Portable) {
        if let Some(name) = f
            .email
            .as_ref()
            .and_then(|e| portable.get(&e.to_lowercase()))
        {
            f.in_portable = true;
            f.portable_profile = Some(name.clone());
        }
    }
    Inventory {
        schema: 1,
        generated_at: now_ms() / 1000,
        logins,
    }
}

/// `--missing` : un email par ligne, pour les comptes de la machine absents du
/// portable (dédoublonnés, ordre de découverte). Un login sans email connu n'a
/// rien à afficher ici : il reste visible dans le tableau.
pub fn missing_emails(inv: &Inventory) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for f in &inv.logins {
        if f.origin == Origin::Portable || f.in_portable {
            continue;
        }
        let Some(e) = &f.email else { continue };
        let key = e.to_lowercase();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(e.clone());
    }
    out
}

/// Logins de la machine absents du portable dont aucun email n'est connu : ils
/// ne peuvent pas figurer sur la sortie de `--missing` (un email par ligne), mais
/// l'humain doit savoir qu'ils existent (le libellé va sur stderr).
pub fn missing_unknown_labels(inv: &Inventory) -> Vec<String> {
    inv.logins
        .iter()
        .filter(|f| f.origin != Origin::Portable && !f.in_portable && f.email.is_none())
        // La session de la machine, absente, n'est pas un compte à reconnecter.
        .filter(|f| !(f.origin == Origin::Machine && f.state == LoginState::NoLogin))
        .map(|f| f.label.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::PathStyle;

    struct Fx {
        _t: tempfile::TempDir,
        env: Env,
        root: Root,
        home: PathBuf,
    }

    fn fx() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let rootdir = t.path().join("portable");
        std::fs::create_dir_all(rootdir.join("config")).unwrap();
        let root = Root::new(rootdir.to_str().unwrap(), PathStyle::Unix).unwrap();
        let env = Env::for_tests(home.clone());
        Fx {
            _t: t,
            env,
            root,
            home,
        }
    }

    fn login_file(dir: &Path, expires_ms: i64, tier: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(".credentials.json"),
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"AT","refreshToken":"RT-{tier}","expiresAt":{expires_ms},"subscriptionType":"max","rateLimitTier":"{tier}"}}}}"#
            ),
        )
        .unwrap();
    }

    fn email_file(dir: &Path, email: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(".claude.json"),
            format!(r#"{{"oauthAccount":{{"emailAddress":"{email}"}}}}"#),
        )
        .unwrap();
    }

    #[test]
    fn finds_every_source_with_real_state() {
        let f = fx();
        // login de la machine : fichier, valide, email dans ~/.claude.json
        login_file(
            &f.home.join(".claude"),
            now_ms() + 3_600_000,
            "default_claude_max_20x",
        );
        std::fs::write(
            f.home.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"contact@atelier-sam.fr"}}"#,
        )
        .unwrap();
        let sora = f.home.join(".config/meridian/profiles/sora");
        login_file(&sora, 1_747_000_000_000, "default_claude_max_20x");
        email_file(&sora, "sam.muselet@gmail.com");
        let prim = f.home.join(".claude-profiles/primary");
        login_file(&prim, 1_750_000_000_000, "default_claude_max_5x");
        email_file(&prim, "primary@x.fr");
        // aucun identifiant, mais l'email est connu
        let ateliersam = f.home.join(".claude-profiles/ateliersam86");
        email_file(&ateliersam, "ateliersam86@gmail.com");
        std::fs::write(f.home.join(".claude-profiles/.DS_Store"), "x").unwrap();

        let inv = scan(&f.env, &f.root);
        let by = |l: &str| inv.logins.iter().find(|x| x.label == l).unwrap();
        assert_eq!(inv.logins.len(), 4, "le .DS_Store n'est pas un compte");
        let m = by("~/.claude");
        assert_eq!(m.state, LoginState::Valid);
        assert_eq!(m.email.as_deref(), Some("contact@atelier-sam.fr"));
        assert_eq!(m.plan.as_deref(), Some("Max x20"));
        assert_eq!(m.plan_source, "local");
        assert_eq!(
            by("meridian/sora").state,
            LoginState::Expired,
            "ni date de refresh ni claude : provisoire"
        );
        assert_eq!(by("profiles/primary").plan.as_deref(), Some("Max x5"));
        let a = by("profiles/ateliersam86");
        assert_eq!(a.state, LoginState::NoLogin);
        assert_eq!(a.store, StoreKind::None);
        assert_eq!(a.email.as_deref(), Some("ateliersam86@gmail.com"));
    }

    #[test]
    fn portable_match_is_by_email_and_ignores_case() {
        let f = fx();
        let sora = f.home.join(".config/meridian/profiles/sora");
        login_file(&sora, 1, "default_claude_max_20x");
        email_file(&sora, "Sam.Muselet@gmail.com");
        let other = f.home.join(".claude-profiles/autre");
        login_file(&other, 1, "default_claude_max_5x");
        email_file(&other, "autre@x.fr");
        // le portable a déjà sam.muselet
        let p1 = f.root.path().join("config").join("1");
        login_file(&p1, now_ms() + 1_000_000, "default_claude_max_20x");
        email_file(&p1, "sam.muselet@gmail.com");

        let inv = scan(&f.env, &f.root);
        let sora_f = inv
            .logins
            .iter()
            .find(|x| x.label == "meridian/sora")
            .unwrap();
        assert!(sora_f.in_portable);
        assert_eq!(sora_f.portable_profile.as_deref(), Some("1"));
        assert!(
            !inv.logins
                .iter()
                .find(|x| x.label == "profiles/autre")
                .unwrap()
                .in_portable
        );
        assert_eq!(missing_emails(&inv), vec!["autre@x.fr".to_string()]);
    }

    #[test]
    fn disconnected_portable_profile_does_not_hide_the_account() {
        let f = fx();
        let prim = f.home.join(".claude-profiles/primary");
        login_file(&prim, 1, "default_claude_max_5x");
        email_file(&prim, "primary@x.fr");
        // profil du portable avec le même email mais SANS identifiants
        email_file(&f.root.path().join("config").join("2"), "primary@x.fr");
        let inv = scan(&f.env, &f.root);
        assert_eq!(missing_emails(&inv), vec!["primary@x.fr".to_string()]);
    }

    #[test]
    fn missing_dedupes_by_email_and_skips_unknown_emails() {
        let f = fx();
        for n in ["a", "b"] {
            let d = f.home.join(".claude-profiles").join(n);
            login_file(&d, 1, "default_claude_max_5x");
            email_file(&d, "meme@x.fr");
        }
        let anon = f.home.join(".claude-profiles/zzz");
        login_file(&anon, 1, "default_claude_max_5x");
        let inv = scan(&f.env, &f.root);
        assert_eq!(missing_emails(&inv), vec!["meme@x.fr".to_string()]);
        assert_eq!(
            missing_unknown_labels(&inv),
            vec!["profiles/zzz".to_string()]
        );
    }

    #[test]
    fn long_lived_token_profile_is_reported_as_such() {
        let f = fx();
        let d = f.home.join(".claude-profiles/jeton");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("oauth.token"), "sk-ant-oat01-xyz").unwrap();
        let inv = scan(&f.env, &f.root);
        let x = inv
            .logins
            .iter()
            .find(|x| x.label == "profiles/jeton")
            .unwrap();
        assert_eq!(x.state, LoginState::LongToken);
        assert_eq!(x.store, StoreKind::Token);
    }

    #[test]
    fn corrupt_credentials_are_unreadable_not_a_panic() {
        let f = fx();
        let d = f.home.join(".claude-profiles/casse");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(".credentials.json"), "{ cassé").unwrap();
        let inv = scan(&f.env, &f.root);
        let x = inv
            .logins
            .iter()
            .find(|x| x.label == "profiles/casse")
            .unwrap();
        assert_eq!(x.state, LoginState::Unreadable);
        assert!(x.detail.as_deref().unwrap().contains("illisibles"));
    }

    #[test]
    fn scan_writes_nothing() {
        let f = fx();
        let d = f.home.join(".claude-profiles/p");
        login_file(&d, 1, "default_claude_max_5x");
        let snapshot = |p: &Path| -> Vec<String> {
            let mut v = Vec::new();
            let mut stack = vec![p.to_path_buf()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        v.push(format!(
                            "{} {}",
                            p.display(),
                            std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
                        ));
                    }
                }
            }
            v.sort();
            v
        };
        let before = (snapshot(&f.home), snapshot(f.root.path().as_path()));
        scan(&f.env, &f.root);
        assert_eq!(
            before,
            (snapshot(&f.home), snapshot(f.root.path().as_path()))
        );
    }

    #[test]
    fn classify_uses_both_dates() {
        let now = 1_000_000_000_000;
        assert_eq!(
            classify(Some(now + 3_600_000), None, now),
            LoginState::Valid
        );
        assert_eq!(
            classify(Some(now - 1), Some(now + 5_000), now),
            LoginState::Renewable
        );
        assert_eq!(
            classify(Some(now - 1), Some(now - 5_000), now),
            LoginState::Expired
        );
        assert_eq!(classify(Some(now - 1), None, now), LoginState::Expired);
        assert_eq!(classify(None, None, now), LoginState::Expired);
    }

    #[test]
    fn refresh_token_end_of_life_makes_an_expired_access_token_renewable() {
        let f = fx();
        let d = f.home.join(".claude-profiles/vivant");
        std::fs::create_dir_all(&d).unwrap();
        let future = now_ms() + 86_400_000 * 20;
        std::fs::write(
            d.join(".credentials.json"),
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"AT","refreshToken":"RT","expiresAt":1000,"refreshTokenExpiresAt":{future},"rateLimitTier":"default_claude_max_20x"}}}}"#
            ),
        )
        .unwrap();
        let inv = scan(&f.env, &f.root);
        let x = inv
            .logins
            .iter()
            .find(|x| x.label == "profiles/vivant")
            .unwrap();
        assert_eq!(x.state, LoginState::Renewable);
        assert_eq!(x.refresh_expires_at, Some(future));
    }

    /// Faux `claude` : répond selon le CLAUDE_CONFIG_DIR reçu.
    #[cfg(unix)]
    fn fake_claude(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("claude-faux");
        std::fs::write(
            &p,
            r#"#!/bin/sh
case "$CLAUDE_CONFIG_DIR" in
  *vivant*) echo '{"loggedIn":true,"email":"vivant@x.fr","planTier":"max_5x"}' ;;
  *) echo '{"loggedIn":false}' ;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    #[test]
    fn claude_auth_status_settles_old_items_without_refresh_date() {
        let mut f = fx();
        for n in ["vivant", "mort"] {
            login_file(
                &f.home.join(".claude-profiles").join(n),
                1_000,
                "default_claude_max_5x",
            );
        }
        f.env.claude = Some(
            fake_claude(f.root.path().as_path())
                .to_string_lossy()
                .into_owned(),
        );
        let inv = scan(&f.env, &f.root);
        let by = |l: &str| inv.logins.iter().find(|x| x.label == l).unwrap();
        assert_eq!(by("profiles/vivant").state, LoginState::Renewable);
        assert_eq!(
            by("profiles/vivant").email.as_deref(),
            Some("vivant@x.fr"),
            "email de repli"
        );
        assert_eq!(by("profiles/mort").state, LoginState::Expired);
        assert!(by("profiles/mort")
            .detail
            .as_deref()
            .unwrap()
            .contains("ne voit plus"));
    }
}
