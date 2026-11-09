//! Rendu des tableaux pour le wizard : le bash affiche, il n'analyse rien.
//!
//! Colonnes alignées par espaces (aucun caractère de tracé de cadre), couleurs
//! ANSI désactivables, repli par paliers selon la largeur du terminal :
//! colonnes optionnelles retirées d'abord, e-mail raccourci ensuite, puis
//! présentation en fiches (deux lignes par compte) sous ~60 colonnes.

use crate::creds::StoreKind;
use crate::discover::{Found, Inventory, LoginState};
use crate::model::{AccountStatus, Bucket, State, StatusReport};
use crate::timefmt;
use jiff::tz::TimeZone;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Paint {
    Plain,
    Dim,
    Bold,
    Green,
    Yellow,
    Red,
    Orange,
}

#[derive(Clone, Debug)]
pub struct Cell {
    pub text: String,
    pub paint: Paint,
}

impl Cell {
    pub fn new(text: impl Into<String>, paint: Paint) -> Cell {
        Cell {
            text: text.into(),
            paint,
        }
    }
    pub fn plain(text: impl Into<String>) -> Cell {
        Cell::new(text, Paint::Plain)
    }
}

pub struct Column {
    pub title: &'static str,
    pub cells: Vec<Cell>,
    /// Largeur plancher quand la colonne doit se raccourcir ; `cap` = plafond naturel.
    pub min: usize,
    pub cap: usize,
}

const GAP: usize = 2;

pub fn display_width(s: &str) -> usize {
    s.chars().count()
}

/// Raccourcit avec « … » (compte en caractères, pas en octets : accents).
pub fn truncate(s: &str, n: usize) -> String {
    if display_width(s) <= n {
        return s.to_string();
    }
    if n == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(n - 1).collect();
    out.push('…');
    out
}

pub fn paint(s: &str, p: Paint, color: bool) -> String {
    if !color || s.is_empty() {
        return s.to_string();
    }
    let code = match p {
        Paint::Plain => return s.to_string(),
        Paint::Dim => "2",
        Paint::Bold => "1",
        Paint::Green => "32",
        Paint::Yellow => "33",
        Paint::Red => "31",
        Paint::Orange => "38;5;208",
    };
    format!("\x1b[{code}m{s}\x1b[0m")
}

/// Largeurs retenues si le tableau tient dans `width`, sinon `None`.
pub fn layout(cols: &[Column], width: usize) -> Option<Vec<usize>> {
    let mut w: Vec<usize> = cols
        .iter()
        .map(|c| {
            let natural = c
                .cells
                .iter()
                .map(|x| display_width(&x.text))
                .chain(std::iter::once(display_width(c.title)))
                .max()
                .unwrap_or(0);
            natural.min(c.cap)
        })
        .collect();
    let total = |w: &[usize]| w.iter().sum::<usize>() + GAP * w.len().saturating_sub(1);
    let mut excess = total(&w).saturating_sub(width);
    for (i, c) in cols.iter().enumerate() {
        if excess == 0 {
            break;
        }
        let take = excess.min(w[i].saturating_sub(c.min));
        w[i] -= take;
        excess -= take;
    }
    (excess == 0).then_some(w)
}

pub fn render_table(cols: &[Column], widths: &[usize], color: bool) -> String {
    let rows = cols.first().map_or(0, |c| c.cells.len());
    let mut out = String::new();
    let line = |texts: Vec<(String, Paint)>| -> String {
        let mut s = String::new();
        for (i, (t, p)) in texts.iter().enumerate() {
            let t = truncate(t, widths[i]);
            let pad = widths[i].saturating_sub(display_width(&t));
            s.push_str(&paint(&t, *p, color));
            if i + 1 < texts.len() {
                s.push_str(&" ".repeat(pad + GAP));
            }
        }
        s
    };
    out.push_str(&line(
        cols.iter()
            .map(|c| (c.title.to_string(), Paint::Dim))
            .collect(),
    ));
    out.push('\n');
    for r in 0..rows {
        out.push_str(&line(
            cols.iter()
                .map(|c| (c.cells[r].text.clone(), c.cells[r].paint))
                .collect(),
        ));
        out.push('\n');
    }
    out
}

fn state_paint(s: State) -> Paint {
    match s {
        State::Ok | State::TokenLong => Paint::Green,
        State::Limited | State::RateLimited | State::Expired | State::Unknown => Paint::Yellow,
        State::Revoked | State::Error | State::Indeterminate => Paint::Red,
        State::Unreachable | State::NotConnected => Paint::Dim,
    }
}

fn pct_paint(pct: u32, stale: bool) -> Paint {
    if stale {
        Paint::Dim
    } else if pct >= 95 {
        Paint::Red
    } else if pct >= 70 {
        Paint::Yellow
    } else {
        Paint::Green
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Window {
    Five,
    Seven,
}

fn quota_cell(
    b: &Option<Bucket>,
    stale: bool,
    with_reset: Option<Window>,
    now: i64,
    tz: &TimeZone,
) -> Cell {
    let Some(b) = b else {
        return Cell::new("—", Paint::Dim);
    };
    let mut t = format!("{} %", b.pct);
    if stale {
        t.push('*');
    }
    if let (Some(w), Some(iso)) = (with_reset, b.resets_at.as_deref()) {
        if let Some(e) = timefmt::parse_epoch(iso) {
            let r = match w {
                Window::Five => timefmt::resume(e, now, tz),
                Window::Seven => timefmt::day(e, tz),
            };
            t.push_str(&format!(" ({r})"));
        }
    }
    Cell::new(t, pct_paint(b.pct, stale))
}

fn status_columns(
    accounts: &[AccountStatus],
    recommended: Option<&str>,
    sonnet: bool,
    resets: bool,
    squeeze: bool,
    now: i64,
    tz: &TimeZone,
) -> Vec<Column> {
    // Palier 0 : seuls COMPTE et EMAIL se raccourcissent. Palier 1 : FORFAIT et STATUT aussi.
    // Les quotas ne sont JAMAIS tronqués : « 12 % … » ne dit rien, mieux vaut retirer une colonne.
    let marker = |a: &AccountStatus| {
        let star = if a.active { '★' } else { ' ' };
        let rec = if recommended == Some(a.name.as_str()) {
            '✓'
        } else {
            ' '
        };
        Cell::new(format!("{star}{rec}"), Paint::Orange)
    };
    let dash = |o: &Option<String>| match o {
        Some(s) => Cell::plain(s.clone()),
        None => Cell::new("—", Paint::Dim),
    };
    let mut cols = vec![
        Column {
            title: "",
            cells: accounts.iter().map(marker).collect(),
            min: 2,
            cap: 2,
        },
        Column {
            title: "COMPTE",
            cells: accounts
                .iter()
                .map(|a| {
                    let t = if a.running {
                        format!("{} ●", a.name)
                    } else {
                        a.name.clone()
                    };
                    Cell::new(t, Paint::Bold)
                })
                .collect(),
            min: 6,
            cap: 16,
        },
        Column {
            title: "EMAIL",
            cells: accounts.iter().map(|a| dash(&a.email)).collect(),
            min: if squeeze { 12 } else { 16 },
            cap: 30,
        },
        Column {
            title: "FORFAIT",
            cells: accounts.iter().map(|a| dash(&a.plan)).collect(),
            min: if squeeze { 10 } else { 18 },
            cap: 18,
        },
        Column {
            title: "STATUT",
            cells: accounts
                .iter()
                .map(|a| Cell::new(a.state_label.clone(), state_paint(a.state)))
                .collect(),
            min: if squeeze { 16 } else { 26 },
            cap: 26,
        },
        Column {
            title: "5 H",
            cells: accounts
                .iter()
                .map(|a| {
                    quota_cell(
                        &a.five_hour,
                        a.stale,
                        resets.then_some(Window::Five),
                        now,
                        tz,
                    )
                })
                .collect(),
            min: 22,
            cap: 22,
        },
        Column {
            title: "7 J",
            cells: accounts
                .iter()
                .map(|a| {
                    quota_cell(
                        &a.seven_day,
                        a.stale,
                        resets.then_some(Window::Seven),
                        now,
                        tz,
                    )
                })
                .collect(),
            min: 18,
            cap: 18,
        },
    ];
    if sonnet {
        cols.push(Column {
            title: "SONNET 7 J",
            cells: accounts
                .iter()
                .map(|a| quota_cell(&a.seven_day_sonnet, a.stale, None, now, tz))
                .collect(),
            min: 10,
            cap: 10,
        });
    }
    cols
}

fn cards(
    accounts: &[AccountStatus],
    recommended: Option<&str>,
    width: usize,
    color: bool,
    now: i64,
    tz: &TimeZone,
) -> String {
    let mut out = String::new();
    for a in accounts {
        let star = if a.active { "★" } else { " " };
        let rec = if recommended == Some(a.name.as_str()) {
            "✓"
        } else {
            " "
        };
        let run = if a.running { " ●" } else { "" };
        let plan = truncate(&a.plan.clone().unwrap_or_else(|| "—".into()), 12);
        // marqueurs (2) + espace + nom + ● + deux espaces + forfait + deux espaces
        let used = 3 + display_width(&a.name) + display_width(run) + 2 + display_width(&plan) + 2;
        let state = truncate(&a.state_label, width.saturating_sub(used).max(4));
        out.push_str(&format!(
            "{}{} {}{}  {}  {}\n",
            paint(star, Paint::Orange, color),
            paint(rec, Paint::Orange, color),
            paint(&a.name, Paint::Bold, color),
            run,
            plan,
            paint(&state, state_paint(a.state), color),
        ));
        let q = |b: &Option<Bucket>, w: Window| {
            let c = quota_cell(b, a.stale, None, now, tz);
            let _ = w;
            paint(&c.text, c.paint, color)
        };
        out.push_str(&format!(
            "     5 h {}   7 j {}\n",
            q(&a.five_hour, Window::Five),
            q(&a.seven_day, Window::Seven)
        ));
    }
    out
}

/// Tableau des comptes + pied (recommandation, légende, détails).
pub fn status_table(
    report: &StatusReport,
    width: usize,
    color: bool,
    now: i64,
    tz: &TimeZone,
) -> String {
    let accounts = &report.accounts;
    if accounts.is_empty() {
        return "Aucun compte dans ce portable.\n".to_string();
    }
    let rec = report.recommended.as_deref();
    let mut out = String::new();
    let variants = [(true, true), (false, true), (false, false)];
    let mut done = false;
    'fit: for squeeze in [false, true] {
        for (sonnet, resets) in variants {
            let cols = status_columns(accounts, rec, sonnet, resets, squeeze, now, tz);
            if let Some(w) = layout(&cols, width) {
                out.push_str(&render_table(&cols, &w, color));
                done = true;
                break 'fit;
            }
        }
    }
    if !done {
        out.push_str(&cards(accounts, rec, width, color, now, tz));
    }

    let dim = |s: &str| paint(&truncate(s, width), Paint::Dim, color);
    if let Some(name) = rec {
        if let Some(a) = accounts.iter().find(|a| a.name == name) {
            let how = match crate::recommend::fullest_pct(a) {
                Some(p) => format!("{p} % de la fenêtre la plus pleine"),
                None => "quota non lisible".to_string(),
            };
            out.push_str(&dim(&format!(
                "Recommandé : {} — {}, {how}",
                a.name,
                a.plan.clone().unwrap_or_else(|| "forfait inconnu".into())
            )));
            out.push('\n');
        }
    } else if let Some(n) = &report.next {
        out.push_str(&dim(&format!(
            "Aucun compte disponible. Reprise la plus proche : {} à {}",
            n.name,
            timefmt::resume(n.resumes_at, now, tz)
        )));
        out.push('\n');
    } else {
        out.push_str(&dim("Aucun compte disponible."));
        out.push('\n');
    }
    let mut legend = vec!["★ défaut", "✓ recommandé"];
    if accounts.iter().any(|a| a.running) {
        legend.push("● ouvert dans une fenêtre");
    }
    if accounts.iter().any(|a| a.stale) {
        legend.push("* dernière valeur connue");
    }
    out.push_str(&dim(&legend.join("  ·  ")));
    out.push('\n');
    for a in accounts {
        let worth = matches!(
            a.state,
            State::Error
                | State::Revoked
                | State::Unreachable
                | State::Expired
                | State::Indeterminate
        );
        if let (true, Some(d)) = (worth, &a.detail) {
            out.push_str(&dim(&format!("{} : {d}", a.name)));
            out.push('\n');
        }
    }
    out
}

// ------------------------------------------------------------------ discover

fn store_label(s: StoreKind) -> &'static str {
    match s {
        StoreKind::Keychain => "Trousseau",
        StoreKind::File => "fichier",
        StoreKind::Token => "jeton",
        StoreKind::None => "—",
    }
}

fn login_state_cell(f: &Found, now_ms: i64, tz: &TimeZone) -> Cell {
    let date = |ms: i64| timefmt::date(ms / 1000, tz);
    match f.state {
        LoginState::Valid => {
            let left = f
                .expires_at
                .map(|t| timefmt::age((t - now_ms) / 1000))
                .unwrap_or_default();
            Cell::new(format!("valide (expire dans {left})"), Paint::Green)
        }
        LoginState::Renewable => Cell::new(
            match f.refresh_expires_at {
                Some(r) => format!("valide (jusqu'au {})", date(r)),
                None => "valide (renouvelable)".to_string(),
            },
            Paint::Green,
        ),
        LoginState::Expired => Cell::new(
            match f.expires_at {
                Some(t) => format!("expiré le {}", date(t)),
                None => "expiré".to_string(),
            },
            Paint::Yellow,
        ),
        LoginState::LongToken => Cell::new("jeton longue durée", Paint::Green),
        LoginState::NoLogin => Cell::new("aucun identifiant", Paint::Dim),
        LoginState::Locked => Cell::new("Trousseau verrouillé", Paint::Red),
        LoginState::Unreadable => Cell::new("illisible", Paint::Red),
    }
}

fn discover_columns(
    logins: &[Found],
    full: bool,
    squeeze: bool,
    now_ms: i64,
    tz: &TimeZone,
) -> Vec<Column> {
    let dash = |o: &Option<String>| match o {
        Some(s) => Cell::plain(s.clone()),
        None => Cell::new("—", Paint::Dim),
    };
    let mut cols = vec![
        Column {
            title: "ORIGINE",
            cells: logins
                .iter()
                .map(|f| Cell::new(f.label.clone(), Paint::Bold))
                .collect(),
            min: if squeeze { 12 } else { 21 },
            cap: 24,
        },
        Column {
            title: "EMAIL",
            cells: logins.iter().map(|f| dash(&f.email)).collect(),
            min: if squeeze { 14 } else { 24 },
            cap: 30,
        },
        Column {
            title: "FORFAIT",
            cells: logins.iter().map(|f| dash(&f.plan)).collect(),
            min: 12,
            cap: 12,
        },
    ];
    if full {
        cols.push(Column {
            title: "MAGASIN",
            cells: logins
                .iter()
                .map(|f| Cell::new(store_label(f.store), Paint::Plain))
                .collect(),
            min: 7,
            cap: 9,
        });
    }
    cols.push(Column {
        title: "ÉTAT",
        cells: logins
            .iter()
            .map(|f| login_state_cell(f, now_ms, tz))
            .collect(),
        min: if squeeze { 18 } else { 28 },
        cap: 28,
    });
    cols.push(Column {
        title: "PORTABLE",
        cells: logins
            .iter()
            .map(|f| {
                match (
                    &f.portable_profile,
                    f.origin == crate::discover::Origin::Portable,
                ) {
                    (_, true) => Cell::new("ici", Paint::Dim),
                    (Some(p), false) => Cell::new(format!("oui ({p})"), Paint::Green),
                    (None, false) => Cell::new("non", Paint::Yellow),
                }
            })
            .collect(),
        min: 8,
        cap: 10,
    });
    cols
}

pub fn discover_table(
    inv: &Inventory,
    width: usize,
    color: bool,
    now_ms: i64,
    tz: &TimeZone,
) -> String {
    if inv.logins.is_empty() {
        return "Aucun compte Claude trouvé sur cet ordinateur.\n".to_string();
    }
    let mut out = String::new();
    let mut done = false;
    'fit: for squeeze in [false, true] {
        for full in [true, false] {
            let cols = discover_columns(&inv.logins, full, squeeze, now_ms, tz);
            if let Some(w) = layout(&cols, width) {
                out.push_str(&render_table(&cols, &w, color));
                done = true;
                break 'fit;
            }
        }
    }
    if !done {
        for f in &inv.logins {
            let st = login_state_cell(f, now_ms, tz);
            let head = truncate(
                &format!(
                    "{}  {}",
                    f.label,
                    f.email.clone().unwrap_or_else(|| "—".into())
                ),
                width,
            );
            let tail = truncate(
                &format!(
                    "{}  ·  {}",
                    st.text,
                    if f.in_portable {
                        "dans le portable"
                    } else {
                        "hors du portable"
                    }
                ),
                width.saturating_sub(5),
            );
            out.push_str(&format!("{head}\n     {}\n", paint(&tail, st.paint, color)));
        }
    }
    let dim = |s: &str| paint(&truncate(s, width), Paint::Dim, color);
    out.push_str(&dim(
        "Forfait d'après les identifiants locaux (peut être périmé) : `accounts status` le vérifie en ligne.",
    ));
    out.push('\n');
    out.push_str(&dim("Lecture seule : rien n'est copié ni renouvelé."));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NextAccount;

    fn acct(
        name: &str,
        email: &str,
        plan: &str,
        state: State,
        five: Option<u32>,
        seven: Option<u32>,
    ) -> AccountStatus {
        let b = |p: Option<u32>, r: &str| {
            p.map(|pct| Bucket {
                pct,
                resets_at: Some(r.into()),
            })
        };
        AccountStatus {
            name: name.into(),
            active: name == "1",
            store: StoreKind::Keychain,
            state,
            state_label: state.label().into(),
            email: Some(email.into()),
            plan: Some(plan.into()),
            plan_tier: None,
            plan_declared: false,
            five_hour: b(five, "2099-01-01T04:00:00Z"),
            seven_day: b(seven, "2099-01-05T10:00:00Z"),
            seven_day_sonnet: b(Some(3), "2099-01-05T10:00:00Z").filter(|_| five.is_some()),
            usable: state.is_usable(),
            running: false,
            checked_at: 1,
            stale: false,
            detail: None,
        }
    }

    fn report() -> StatusReport {
        StatusReport {
            schema: 1,
            generated_at: 0,
            active: "1".into(),
            recommended: Some("2".into()),
            next: None::<NextAccount>,
            accounts: vec![
                acct(
                    "1",
                    "contact@atelier-sam.fr",
                    "Max x20",
                    State::Ok,
                    Some(12),
                    Some(40),
                ),
                acct(
                    "2",
                    "sam.muselet@gmail.com",
                    "Max x20",
                    State::Ok,
                    Some(3),
                    Some(5),
                ),
                acct(
                    "3",
                    "leslapinsdesamuel@gmail.com",
                    "Max x5 (déclaré)",
                    State::TokenLong,
                    None,
                    None,
                ),
            ],
        }
    }

    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars().peekable();
        while let Some(c) = it.next() {
            if c == '\x1b' {
                for d in it.by_ref() {
                    if d == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn no_line_exceeds_the_width_at_any_size() {
        let r = report();
        for w in [40, 50, 60, 70, 80, 100, 120, 160] {
            let t = strip_ansi(&status_table(&r, w, true, 0, &TimeZone::UTC));
            for l in t.lines() {
                assert!(
                    display_width(l) <= w,
                    "largeur {w} dépassée ({}) : {l:?}",
                    display_width(l)
                );
            }
        }
    }

    #[test]
    fn full_width_shows_every_column_and_no_box_drawing() {
        let t = status_table(&report(), 120, false, 0, &TimeZone::UTC);
        for h in [
            "COMPTE",
            "EMAIL",
            "FORFAIT",
            "STATUT",
            "5 H",
            "7 J",
            "SONNET 7 J",
        ] {
            assert!(t.contains(h), "colonne {h} absente :\n{t}");
        }
        assert!(
            t.contains("12 % (04:00)") || t.contains("12 % (jeu."),
            "{t}"
        );
        assert!(t.contains("Recommandé : 2"));
        assert!(
            !t.chars().any(|c| ('\u{2500}'..='\u{257F}').contains(&c)),
            "caractère de tracé de cadre"
        );
        assert!(!t.contains('\x1b'), "pas de couleur demandée");
    }

    #[test]
    fn narrow_width_drops_columns_then_falls_back_to_cards() {
        let r = report();
        let t80 = status_table(&r, 80, false, 0, &TimeZone::UTC);
        assert!(!t80.contains("SONNET"), "{t80}");
        let t50 = status_table(&r, 50, false, 0, &TimeZone::UTC);
        assert!(t50.contains("5 h 12 %"), "fiches attendues :\n{t50}");
    }

    #[test]
    fn color_is_ansi_and_optional() {
        let c = status_table(&report(), 120, true, 0, &TimeZone::UTC);
        assert!(c.contains("\x1b["));
        assert_eq!(
            strip_ansi(&c),
            status_table(&report(), 120, false, 0, &TimeZone::UTC)
        );
    }

    #[test]
    fn marks_default_and_recommended_and_running() {
        let mut r = report();
        r.accounts[1].running = true;
        let t = status_table(&r, 120, false, 0, &TimeZone::UTC);
        let l1 = t.lines().find(|l| l.contains("contact@")).unwrap();
        assert!(l1.starts_with("★ "), "{l1:?}");
        let l2 = t.lines().find(|l| l.contains("sam.muselet")).unwrap();
        assert!(l2.contains("2 ●"), "{l2:?}");
        assert!(t.contains("● ouvert dans une fenêtre"));
    }

    #[test]
    fn stale_values_are_starred_and_explained() {
        let mut r = report();
        r.accounts[0].stale = true;
        let t = status_table(&r, 120, false, 0, &TimeZone::UTC);
        assert!(t.contains("12 %*"), "{t}");
        assert!(t.contains("* dernière valeur connue"));
    }

    #[test]
    fn no_recommendation_shows_next_resume() {
        let mut r = report();
        r.recommended = None;
        r.next = Some(NextAccount {
            name: "2".into(),
            resumes_at: 4_070_908_800,
        });
        let t = status_table(&r, 120, false, 4_070_900_000, &TimeZone::UTC);
        assert!(
            t.contains("Aucun compte disponible. Reprise la plus proche : 2"),
            "{t}"
        );
    }

    #[test]
    fn failures_get_a_detail_line() {
        let mut r = report();
        r.accounts[2].state = State::Revoked;
        r.accounts[2].state_label = "À reconnecter".into();
        r.accounts[2].detail = Some("renouvellement refusé".into());
        let t = status_table(&r, 120, false, 0, &TimeZone::UTC);
        assert!(t.contains("3 : renouvellement refusé"));
    }

    #[test]
    fn empty_portable_says_so() {
        let r = StatusReport {
            schema: 1,
            generated_at: 0,
            active: "1".into(),
            recommended: None,
            next: None,
            accounts: vec![],
        };
        assert!(status_table(&r, 80, false, 0, &TimeZone::UTC).contains("Aucun compte"));
    }

    #[test]
    fn truncation_counts_characters_not_bytes() {
        assert_eq!(truncate("épée", 4), "épée");
        assert_eq!(truncate("épées", 4), "épé…");
        assert_eq!(truncate("ab", 0), "");
    }
}
