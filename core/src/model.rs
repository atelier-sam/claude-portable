//! Types partagés : états, quotas, statut d'un compte (contrat JSON schema 1).

use crate::creds::StoreKind;
use serde::{Deserialize, Serialize};

/// États d'un compte. Les cinq premiers sont ceux du PLAN ; `Unknown` n'existe
/// que pour `--offline` (compte jamais sondé, rien en cache).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Ok,
    Limited,
    Expired,
    Revoked,
    TokenLong,
    NotConnected,
    Unreachable,
    RateLimited,
    Error,
    Indeterminate,
    Unknown,
}

impl State {
    /// Libellé court (sans l'heure de reprise, ajoutée au rendu pour `Limited`).
    pub fn label(self) -> &'static str {
        match self {
            State::Ok => "OK",
            State::Limited => "Limité",
            State::Expired => "Expiré (au lancement)",
            State::Revoked => "À reconnecter",
            State::TokenLong => "Jeton longue durée",
            State::NotConnected => "Non connecté",
            State::Unreachable => "Hors ligne",
            State::RateLimited => "Statut limité",
            State::Error => "Erreur",
            State::Indeterminate => "Incohérent",
            State::Unknown => "Non sondé",
        }
    }

    /// Un échec de sonde : les valeurs affichées sont alors les dernières bonnes.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            State::Expired | State::Unreachable | State::RateLimited | State::Error
        )
    }

    /// Peut-on lancer ce compte maintenant avec de bonnes chances ?
    pub fn is_usable(self) -> bool {
        matches!(self, State::Ok | State::TokenLong | State::RateLimited)
    }
}

/// Une fenêtre de quota (5 h, 7 j…). `pct` est TRONQUÉ : 99,9 s'affiche 99 et
/// n'est pas « limité » ; seul 100 l'est.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Bucket {
    pub pct: u32,
    pub resets_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub email: Option<String>,
    pub plan: Option<String>,
    pub plan_tier: Option<String>,
    pub plan_declared: bool,
    pub checked_at: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub five_hour: Option<Bucket>,
    pub seven_day: Option<Bucket>,
    pub seven_day_sonnet: Option<Bucket>,
    pub checked_at: i64,
}

/// Un compte tel que le wizard le voit. Ordre des champs = contrat JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountStatus {
    pub name: String,
    pub active: bool,
    pub store: StoreKind,
    pub state: State,
    pub state_label: String,
    pub email: Option<String>,
    pub plan: Option<String>,
    pub plan_tier: Option<String>,
    pub plan_declared: bool,
    pub five_hour: Option<Bucket>,
    pub seven_day: Option<Bucket>,
    pub seven_day_sonnet: Option<Bucket>,
    pub usable: bool,
    pub running: bool,
    pub checked_at: i64,
    pub stale: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub schema: u32,
    pub generated_at: i64,
    pub active: String,
    pub recommended: Option<String>,
    /// Ajout au contrat (rétro-compatible) : compte limité dont la reprise est la plus proche.
    pub next: Option<NextAccount>,
    pub accounts: Vec<AccountStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NextAccount {
    pub name: String,
    /// Époque (secondes) de la reprise.
    pub resumes_at: i64,
}
