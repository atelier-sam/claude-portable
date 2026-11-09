//! Quel compte lancer ? Celui qui a le plus de MARGE réelle.
//!
//! Marge = (100 - fenêtre la plus pleine entre 5 h et 7 j) x multiplicateur du
//! forfait : 50 % de marge sur un Max x20 pèse quatre fois plus que 50 % sur un
//! Max x5. Seuil de prudence à 95 % : au-delà, le compte n'est plus recommandé
//! tant qu'un autre existe. À marge égale, on entame d'abord le compte dont la
//! fenêtre de 7 jours se rouvre le plus tôt (la capacité qui va être remise à
//! zéro de toute façon), puis le compte par défaut, puis l'ordre des profils.
//!
//! Un compte déjà ouvert dans une autre fenêtre n'est jamais recommandé : le
//! lancer échouerait (verrou de session).

use crate::model::{AccountStatus, State};
use crate::plan;
use crate::status::resume_epoch;
use crate::timefmt;

pub const HEADROOM_LIMIT: u32 = 95;

/// Rang d'un candidat : plus petit = meilleur. Le rang prime sur la marge.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Tier {
    /// Quota connu et sous le seuil.
    Measured = 0,
    /// Utilisable mais quota illisible (jeton longue durée, statut limité par IP).
    Unmeasured = 1,
    /// Jeton expiré : Claude le renouvellera au lancement, quota non vérifié.
    Unverified = 2,
    /// Quota connu mais au-dessus du seuil de prudence (95 à 99 %).
    NearlyFull = 3,
}

/// Fenêtre la plus pleine entre 5 h et 7 j (Sonnet 7 j n'entre pas en jeu :
/// c'est un sous-plafond qui ne bloque pas les autres modèles).
pub fn fullest_pct(st: &AccountStatus) -> Option<u32> {
    [&st.five_hour, &st.seven_day]
        .into_iter()
        .flatten()
        .map(|b| b.pct)
        .max()
}

fn tier(st: &AccountStatus) -> Option<Tier> {
    if st.running {
        return None;
    }
    match st.state {
        State::Ok => match fullest_pct(st) {
            Some(p) if p >= 100 => None,
            Some(p) if p >= HEADROOM_LIMIT => Some(Tier::NearlyFull),
            Some(_) => Some(Tier::Measured),
            None => Some(Tier::Unmeasured),
        },
        State::TokenLong | State::RateLimited => Some(Tier::Unmeasured),
        State::Expired => Some(Tier::Unverified),
        _ => None,
    }
}

fn score(st: &AccountStatus) -> f64 {
    let mult = st.plan.as_deref().map(plan::multiplier).unwrap_or(1.0);
    match fullest_pct(st) {
        Some(p) => f64::from(100u32.saturating_sub(p)) * mult,
        None => mult,
    }
}

fn seven_day_reset(st: &AccountStatus) -> i64 {
    st.seven_day
        .as_ref()
        .and_then(|b| b.resets_at.as_deref())
        .and_then(timefmt::parse_epoch)
        .unwrap_or(i64::MAX)
}

/// Index du compte recommandé, s'il y en a un.
pub fn recommend(accounts: &[AccountStatus]) -> Option<usize> {
    accounts
        .iter()
        .enumerate()
        .filter_map(|(i, st)| tier(st).map(|t| (i, st, t)))
        .min_by(|(ia, a, ta), (ib, b, tb)| {
            ta.cmp(tb)
                .then_with(|| score(b).total_cmp(&score(a)))
                .then_with(|| seven_day_reset(a).cmp(&seven_day_reset(b)))
                .then_with(|| b.active.cmp(&a.active))
                .then_with(|| ia.cmp(ib))
        })
        .map(|(i, _, _)| i)
}

/// Quand personne n'est disponible : le compte limité qui se rouvre le plus tôt.
pub fn next_resume(accounts: &[AccountStatus]) -> Option<(usize, i64)> {
    accounts
        .iter()
        .enumerate()
        .filter(|(_, st)| st.state == State::Limited)
        .filter_map(|(i, st)| resume_epoch(st).map(|t| (i, t)))
        .min_by_key(|(_, t)| *t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creds::StoreKind;
    use crate::model::Bucket;

    fn acct(
        name: &str,
        state: State,
        plan: &str,
        five: Option<u32>,
        seven: Option<u32>,
    ) -> AccountStatus {
        let b = |p: Option<u32>, r: Option<&str>| {
            p.map(|pct| Bucket {
                pct,
                resets_at: r.map(str::to_string),
            })
        };
        AccountStatus {
            name: name.into(),
            active: false,
            store: StoreKind::File,
            state,
            state_label: String::new(),
            email: None,
            plan: Some(plan.into()),
            plan_tier: None,
            plan_declared: false,
            five_hour: b(five, Some("2099-01-01T04:00:00Z")),
            seven_day: b(seven, Some("2099-01-05T10:00:00Z")),
            seven_day_sonnet: None,
            usable: state.is_usable(),
            running: false,
            checked_at: 0,
            stale: false,
            detail: None,
        }
    }

    #[test]
    fn margin_is_weighted_by_plan() {
        // x20 à 50 % : 50 x 20 = 1000 ; x5 à 10 % : 90 x 5 = 450.
        let v = vec![
            acct("a", State::Ok, "Max x5", Some(10), Some(5)),
            acct("b", State::Ok, "Max x20", Some(50), Some(20)),
        ];
        assert_eq!(recommend(&v), Some(1));
    }

    #[test]
    fn fullest_window_decides_the_margin() {
        let v = vec![
            acct("a", State::Ok, "Max x20", Some(5), Some(90)),
            acct("b", State::Ok, "Max x20", Some(60), Some(10)),
        ];
        assert_eq!(
            recommend(&v),
            Some(1),
            "7 j à 90 % pèse plus que 5 h à 60 %"
        );
    }

    #[test]
    fn limited_and_dead_accounts_are_never_recommended() {
        let v = vec![
            acct("a", State::Limited, "Max x20", Some(100), Some(10)),
            acct("b", State::Revoked, "Max x20", None, None),
            acct("c", State::NotConnected, "Max x20", None, None),
            acct("d", State::Unreachable, "Max x20", Some(1), Some(1)),
        ];
        assert_eq!(recommend(&v), None);
    }

    #[test]
    fn running_account_is_skipped() {
        let mut busy = acct("a", State::Ok, "Max x20", Some(1), Some(1));
        busy.running = true;
        let v = vec![busy, acct("b", State::Ok, "Pro", Some(80), Some(80))];
        assert_eq!(recommend(&v), Some(1));
    }

    #[test]
    fn nearly_full_account_loses_to_any_other_usable() {
        let v = vec![
            acct("a", State::Ok, "Max x20", Some(96), Some(10)),
            acct("b", State::Ok, "Pro", Some(90), Some(90)),
        ];
        assert_eq!(recommend(&v), Some(1));
    }

    #[test]
    fn nearly_full_beats_nothing() {
        let v = vec![acct("a", State::Ok, "Max x20", Some(96), Some(10))];
        assert_eq!(recommend(&v), Some(0));
    }

    #[test]
    fn measured_beats_unmeasured_beats_unverified() {
        let v = vec![
            acct("exp", State::Expired, "Max x20", None, None),
            acct("tok", State::TokenLong, "Max x20 (déclaré)", None, None),
            acct("ok", State::Ok, "Pro", Some(90), Some(90)),
        ];
        assert_eq!(recommend(&v), Some(2));
        assert_eq!(recommend(&v[..2]), Some(1));
        assert_eq!(recommend(&v[..1]), Some(0));
    }

    #[test]
    fn tie_goes_to_earliest_seven_day_reset_then_active_then_order() {
        let mut a = acct("a", State::Ok, "Max x20", Some(10), Some(10));
        let mut b = acct("b", State::Ok, "Max x20", Some(10), Some(10));
        b.seven_day.as_mut().unwrap().resets_at = Some("2098-01-01T00:00:00Z".into());
        assert_eq!(
            recommend(&[a.clone(), b.clone()]),
            Some(1),
            "7 j qui se rouvre d'abord"
        );
        b.seven_day.as_mut().unwrap().resets_at = a.seven_day.as_ref().unwrap().resets_at.clone();
        a.active = false;
        b.active = true;
        assert_eq!(
            recommend(&[a.clone(), b.clone()]),
            Some(1),
            "le défaut départage"
        );
        b.active = false;
        assert_eq!(recommend(&[a, b]), Some(0), "puis l'ordre des profils");
    }

    #[test]
    fn next_resume_is_the_earliest_full_window_reopening() {
        let mut a = acct("a", State::Limited, "Max x20", Some(100), Some(10));
        a.five_hour.as_mut().unwrap().resets_at = Some("2099-01-01T05:00:00Z".into());
        let mut b = acct("b", State::Limited, "Max x20", Some(100), Some(10));
        b.five_hour.as_mut().unwrap().resets_at = Some("2099-01-01T03:00:00Z".into());
        let v = vec![a, b, acct("c", State::Ok, "Pro", Some(1), Some(1))];
        let (i, t) = next_resume(&v).unwrap();
        assert_eq!(i, 1);
        assert_eq!(t, timefmt::parse_epoch("2099-01-01T03:00:00Z").unwrap());
    }

    #[test]
    fn limited_by_both_windows_resumes_when_the_latest_reopens() {
        let a = acct("a", State::Limited, "Max x20", Some(100), Some(100));
        let (_, t) = next_resume(&[a]).unwrap();
        assert_eq!(t, timefmt::parse_epoch("2099-01-05T10:00:00Z").unwrap());
    }

    #[test]
    fn empty_list_recommends_nothing() {
        assert_eq!(recommend(&[]), None);
        assert_eq!(next_resume(&[]), None);
    }
}
