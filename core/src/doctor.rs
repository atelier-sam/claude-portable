//! `doctor` : ccp-core et Claude lisent-ils la MÊME chose ?
//!
//! Tout ce que ccp-core sait du Trousseau (nom du service, format du JSON) est
//! déduit du binaire Claude, pas d'une API publique : une mise à jour de Claude
//! peut le changer sans prévenir. Ce diagnostic est le canari : il compare ce que
//! lit ccp-core avec `claude auth status --json` (source officielle) et dit
//! « indéterminé » à la moindre divergence plutôt que d'afficher un statut faux.

use crate::api::{Api, Fetch};
use crate::claude_cli::{self, AuthStatus};
use crate::creds::{self, StoreKind};
use crate::env::{now_ms, Env};
use crate::error::{CcpError, Result};
use crate::lock;
use crate::oauth;
use crate::root::{claude_platform, Profile, Root};
use crate::status::Deps;
use crate::timefmt;
use jiff::tz::TimeZone;
use secrecy::SecretString;

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Consistent,
    /// Ce que ccp-core lit n'est pas ce que Claude voit.
    Indeterminate,
    /// Pas de comparaison possible (claude absent, délai…).
    Skipped,
}

pub struct What {
    pub store: StoreKind,
    pub logged_in: bool,
    pub expired: bool,
    pub email: Option<String>,
    pub plan_tier: Option<String>,
    pub expires_at_ms: Option<i64>,
}

fn norm_tier(t: &str) -> String {
    t.to_lowercase()
        .replace("default_claude_", "")
        .replace("claude_", "")
}

/// Pure : compare ce que lit ccp-core à `claude auth status`. Renvoie les divergences.
pub fn compare(ours: &What, theirs: &AuthStatus) -> Vec<String> {
    // Les dates ne sont PAS comparées : `loginExpiresAt` n'est ni `expiresAt` ni
    // `refreshTokenExpiresAt` de l'item (mesuré sur le login de la machine : 06/12
    // contre 04/12 et 06/11). Un faux « incohérent » est pire que pas de test.
    let mut d = Vec::new();
    match (ours.logged_in, theirs.logged_in) {
        (false, true) => d.push(
            "Claude voit un login que ccp-core ne trouve pas (nom de service du Trousseau ou emplacement du fichier changé ?)"
                .to_string(),
        ),
        (true, false) if !ours.expired => d.push(
            "ccp-core lit un login valide que Claude ne voit pas (mauvais item lu ?)".to_string(),
        ),
        _ => {}
    }
    if let (Some(a), Some(b)) = (&ours.email, &theirs.email) {
        if !a.eq_ignore_ascii_case(b) {
            d.push(format!("email différent : ccp-core {a}, Claude {b}"));
        }
    }
    if let (Some(a), Some(b)) = (&ours.plan_tier, &theirs.plan_tier) {
        if norm_tier(a) != norm_tier(b) {
            d.push(format!("forfait différent : ccp-core {a}, Claude {b}"));
        }
    }
    d
}

fn mark(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "PROBLÈME"
    }
}

pub struct Report {
    pub text: String,
    pub divergent: bool,
    pub claude_missing: bool,
}

pub fn run(env: &Env, deps: &Deps, root: &Root, only: Option<&Profile>) -> Result<Report> {
    let tz = TimeZone::system();
    let mut t = String::new();
    let mut divergent = false;
    let claude = claude_cli::resolve(env, root);
    t.push_str(&format!(
        "ccp-core {} (contrat 1) — plateforme {}\nRacine : {}\n",
        env!("CARGO_PKG_VERSION"),
        claude_platform(),
        root.as_str()
    ));

    // Claude
    let mut claude_ok = false;
    if !claude.is_file() {
        t.push_str(&format!("Claude : introuvable ({})\n", claude.display()));
    } else {
        match claude_cli::version(&claude) {
            Ok(v) => {
                claude_ok = true;
                t.push_str(&format!(
                    "Claude : {} (version {v}) — exécutable ok\n",
                    claude.display()
                ));
            }
            Err(e) => t.push_str(&format!(
                "Claude : {} — NON exécutable : {e}\n",
                claude.display()
            )),
        }
    }

    // Réseau (jeton bidon : un 401 prouve que le service répond)
    let api: &Api = &deps.api;
    let net = match api.profile(&SecretString::from("diagnostic")) {
        Fetch::Unreachable(m) => format!("PROBLÈME ({m})"),
        _ => "ok (le service Anthropic répond)".to_string(),
    };
    t.push_str(&format!("Réseau : {net}\n"));

    let profiles: Vec<Profile> = match only {
        Some(p) => vec![p.clone()],
        None => root.list_profiles(),
    };
    if profiles.is_empty() {
        t.push_str("Aucun profil dans ce portable.\n");
    }
    for name in profiles {
        let p = root.profile(&name);
        t.push_str(&format!("\nProfil {name}\n"));
        let view = crate::status::read_view(env, &p);
        let (store, logged_in, expired, expires, tier) = match &view.source {
            crate::status::Source::Login(l) => (
                l.kind,
                true,
                oauth::expired(&l.blob, now_ms()),
                l.blob.expires_at_ms(),
                l.blob.rate_limit_tier(),
            ),
            crate::status::Source::Token(_) => (StoreKind::Token, true, false, None, None),
            crate::status::Source::None => (StoreKind::None, false, false, None, None),
            crate::status::Source::Broken(e) => {
                t.push_str(&format!("  magasin : ILLISIBLE — {e}\n"));
                (StoreKind::None, false, false, None, None)
            }
        };
        let svc = if cfg!(target_os = "macos") {
            format!(" (service {})", creds::keychain::service_name(&p.cfg))
        } else {
            String::new()
        };
        t.push_str(&format!("  ccp-core lit : magasin {store:?}{svc}\n"));
        t.push_str(&format!(
            "  ccp-core lit : {}{}{}\n",
            if logged_in {
                "login présent"
            } else {
                "aucun login"
            },
            match expires {
                Some(e) => format!(", expire {}", timefmt::full(e / 1000, &tz)),
                None => String::new(),
            },
            if expired { " (EXPIRÉ)" } else { "" }
        ));
        let sess = match view.lock {
            lock::LockState::Free => "libre",
            lock::LockState::Session => "ouverte dans une fenêtre",
            lock::LockState::Renewing => "renouvellement en cours",
        };
        t.push_str(&format!("  session : {sess}\n"));
        if p.pending_journal().exists() {
            t.push_str("  journal de renouvellement en attente (.ccp-pending) : sera rejoué au prochain statut\n");
        }
        if view.revoked {
            t.push_str("  renouvellement refusé par Anthropic : ce compte doit être reconnecté\n");
        }
        if !claude_ok {
            t.push_str("  comparaison avec Claude : impossible (binaire indisponible)\n");
            continue;
        }
        match claude_cli::auth_status(&claude, Some(&p.cfg)) {
            Err(e) => t.push_str(&format!("  Claude répond : erreur — {e}\n")),
            Ok(a) => {
                t.push_str(&format!(
                    "  Claude voit : {}{}{}{}\n",
                    if a.logged_in {
                        "connecté"
                    } else {
                        "non connecté"
                    },
                    a.email
                        .as_deref()
                        .map(|e| format!(", {e}"))
                        .unwrap_or_default(),
                    a.plan_tier
                        .as_deref()
                        .map(|e| format!(", {e}"))
                        .unwrap_or_default(),
                    a.login_expires_at_ms
                        .map(|e| format!(", expire {}", timefmt::full(e / 1000, &tz)))
                        .unwrap_or_default(),
                ));
                let ours = What {
                    store,
                    logged_in: logged_in && store != StoreKind::Token,
                    expired,
                    email: view.local_email.clone(),
                    plan_tier: tier,
                    expires_at_ms: expires,
                };
                let diffs = compare(&ours, &a);
                if diffs.is_empty() {
                    t.push_str(&format!("  verdict : cohérent ({})\n", mark(true)));
                } else {
                    divergent = true;
                    t.push_str("  verdict : INDÉTERMINÉ — ccp-core et Claude ne lisent pas la même chose\n");
                    for d in diffs {
                        t.push_str(&format!("    - {d}\n"));
                    }
                }
            }
        }
    }
    if divergent {
        t.push_str(
            "\nDivergence détectée : les statuts affichés peuvent être faux. Relance la mise à jour de ccp-core ou signale-le.\n",
        );
    }
    Ok(Report {
        text: t,
        divergent,
        claude_missing: !claude_ok,
    })
}

/// Traduit le rapport en code de sortie du contrat.
pub fn exit_error(r: &Report) -> Option<CcpError> {
    if r.divergent {
        Some(CcpError::Divergence(
            "ccp-core et Claude ne lisent pas le même login".into(),
        ))
    } else if r.claude_missing {
        Some(CcpError::NotFound(
            "binaire Claude indisponible : diagnostic incomplet".into(),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ours() -> What {
        What {
            store: StoreKind::Keychain,
            logged_in: true,
            expired: false,
            email: Some("a@x.fr".into()),
            plan_tier: Some("default_claude_max_20x".into()),
            expires_at_ms: Some(1_800_000_000_000),
        }
    }

    fn theirs() -> AuthStatus {
        AuthStatus {
            logged_in: true,
            email: Some("A@x.fr".into()),
            plan_tier: Some("max_20x".into()),
            subscription: Some("max".into()),
            login_expires_at_ms: Some(1_800_000_000_400),
        }
    }

    #[test]
    fn same_login_is_consistent_despite_case_and_tier_prefix() {
        assert!(compare(&ours(), &theirs()).is_empty());
    }

    #[test]
    fn claude_sees_a_login_we_cannot_find() {
        let mut o = ours();
        o.logged_in = false;
        o.store = StoreKind::None;
        let d = compare(&o, &theirs());
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("ne trouve pas"));
    }

    #[test]
    fn we_read_a_valid_login_claude_does_not_see() {
        let mut t = theirs();
        t.logged_in = false;
        assert!(compare(&ours(), &t)[0].contains("ne voit pas"));
    }

    #[test]
    fn expired_login_claude_calls_logged_out_is_expected() {
        let mut o = ours();
        o.expired = true;
        let mut t = theirs();
        t.logged_in = false;
        t.email = None;
        t.plan_tier = None;
        t.login_expires_at_ms = None;
        assert!(compare(&o, &t).is_empty());
    }

    #[test]
    fn other_email_or_plan_is_a_divergence() {
        let mut t = theirs();
        t.email = Some("autre@x.fr".into());
        t.plan_tier = Some("max_5x".into());
        assert_eq!(compare(&ours(), &t).len(), 2);
    }

    #[test]
    fn different_expiry_dates_alone_are_not_a_divergence() {
        let mut t = theirs();
        t.login_expires_at_ms = Some(1_700_000_000_000);
        assert!(compare(&ours(), &t).is_empty());
    }
}
