//! Dates : lecture RFC 3339 et libellés français courts en heure LOCALE.
//!
//! `jiff` plutôt que `time` : il lit le fuseau du système sans le piège d'unsoundness
//! de `time` (décalage local lisible seulement en mono-thread), or on sonde en
//! parallèle. Les libellés (jours, mois) sont écrits ici : jiff ne parle pas français.

use jiff::tz::TimeZone;
use jiff::Timestamp;

pub fn parse_epoch(iso: &str) -> Option<i64> {
    iso.parse::<Timestamp>().ok().map(|t| t.as_second())
}

const DAYS: [&str; 7] = ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."];

fn zoned(epoch: i64, tz: &TimeZone) -> Option<jiff::Zoned> {
    Timestamp::from_second(epoch)
        .ok()
        .map(|t| t.to_zoned(tz.clone()))
}

fn weekday_fr(z: &jiff::Zoned) -> &'static str {
    DAYS[z.weekday().to_monday_zero_offset() as usize]
}

pub fn hhmm(epoch: i64, tz: &TimeZone) -> String {
    zoned(epoch, tz)
        .map(|z| format!("{:02}:{:02}", z.hour(), z.minute()))
        .unwrap_or_else(|| "?".into())
}

/// « 14:00 » le jour même, « jeu. 14:00 » un autre jour.
pub fn resume(epoch: i64, now: i64, tz: &TimeZone) -> String {
    match (zoned(epoch, tz), zoned(now, tz)) {
        (Some(z), Some(n)) if z.date() == n.date() => hhmm(epoch, tz),
        (Some(z), _) => format!("{} {}", weekday_fr(&z), hhmm(epoch, tz)),
        _ => "?".into(),
    }
}

/// « jeu. 12 » : jour de reprise d'une fenêtre de 7 jours.
pub fn day(epoch: i64, tz: &TimeZone) -> String {
    zoned(epoch, tz)
        .map(|z| format!("{} {}", weekday_fr(&z), z.day()))
        .unwrap_or_else(|| "?".into())
}

/// « 04/12/2026 » : date seule, pour les fins de validité.
pub fn date(epoch: i64, tz: &TimeZone) -> String {
    zoned(epoch, tz)
        .map(|z| format!("{:02}/{:02}/{:04}", z.day(), z.month(), z.year()))
        .unwrap_or_else(|| "?".into())
}

/// « 2026-11-09 18:00 » pour le diagnostic.
pub fn full(epoch: i64, tz: &TimeZone) -> String {
    zoned(epoch, tz)
        .map(|z| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                z.year(),
                z.month(),
                z.day(),
                z.hour(),
                z.minute()
            )
        })
        .unwrap_or_else(|| "?".into())
}

/// « 3 min », « 2 h », « 5 j ».
pub fn age(secs: i64) -> String {
    let s = secs.max(0);
    if s < 90 {
        format!("{s} s")
    } else if s < 5400 {
        format!("{} min", (s + 30) / 60)
    } else if s < 129_600 {
        format!("{} h", (s + 1800) / 3600)
    } else {
        format!("{} j", (s + 43_200) / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::tz;

    fn paris_winter() -> TimeZone {
        TimeZone::fixed(tz::offset(1))
    }

    #[test]
    fn parses_python_style_microseconds_and_z() {
        let a = parse_epoch("2026-11-09T04:00:00.123456+00:00").unwrap();
        let b = parse_epoch("2026-11-09T04:00:00Z").unwrap();
        assert_eq!(a, b);
        assert!(parse_epoch("pas une date").is_none());
        assert!(parse_epoch("").is_none());
    }

    #[test]
    fn local_hour_applies_offset() {
        let e = parse_epoch("2026-11-09T13:00:00Z").unwrap();
        assert_eq!(hhmm(e, &paris_winter()), "14:00");
        assert_eq!(hhmm(e, &TimeZone::UTC), "13:00");
    }

    #[test]
    fn resume_same_day_vs_other_day() {
        let tz = paris_winter();
        let now = parse_epoch("2026-11-09T08:00:00Z").unwrap(); // lundi
        let same = parse_epoch("2026-11-09T13:00:00Z").unwrap();
        let later = parse_epoch("2026-11-12T13:00:00Z").unwrap(); // jeudi
        assert_eq!(resume(same, now, &tz), "14:00");
        assert_eq!(resume(later, now, &tz), "jeu. 14:00");
        assert_eq!(day(later, &tz), "jeu. 12");
    }

    #[test]
    fn midnight_crossing_uses_local_date() {
        let tz = paris_winter();
        let now = parse_epoch("2026-11-09T22:30:00Z").unwrap(); // 23:30 locale lundi
        let after = parse_epoch("2026-11-09T23:30:00Z").unwrap(); // 00:30 locale mardi
        assert_eq!(resume(after, now, &tz), "mar. 00:30");
    }

    #[test]
    fn ages() {
        assert_eq!(age(10), "10 s");
        assert_eq!(age(180), "3 min");
        assert_eq!(age(7200), "2 h");
        assert_eq!(age(3 * 86_400), "3 j");
        assert_eq!(age(-5), "0 s");
    }

    #[test]
    fn full_format() {
        let e = parse_epoch("2026-11-09T17:00:00Z").unwrap();
        assert_eq!(full(e, &paris_winter()), "2026-11-09 18:00");
    }
}
