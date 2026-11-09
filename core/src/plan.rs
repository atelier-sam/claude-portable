//! Forfait : libellé affiché et multiplicateur de capacité pour la recommandation.
//!
//! Le forfait se lit dans `organization.rate_limit_tier` du PROFIL, jamais dans le
//! fichier d'identifiants (qui ment : mémoire `project-forfaits-des-comptes-claude-du-cluster`).
//! Le repli sur les identifiants est marqué « (?) », un forfait écrit à la main
//! pour un jeton longue durée est marqué « (déclaré) ».

/// Libellé depuis le profil API.
pub fn from_profile(tier: Option<&str>, has_max: bool, has_pro: bool) -> String {
    let t = tier.unwrap_or("").to_lowercase();
    if t.contains("max_20x") {
        "Max x20".into()
    } else if t.contains("max_5x") {
        "Max x5".into()
    } else if t.contains("max") || has_max {
        "Max".into()
    } else if t.contains("pro") || has_pro {
        "Pro".into()
    } else if t.is_empty() || t.contains("free") || t == "default_claude_ai" {
        "Gratuit".into()
    } else {
        pretty_unknown(&t)
    }
}

/// `default_claude_team` -> « Team » : on affiche ce qu'on ne connaît pas plutôt
/// que de le faire passer pour « Gratuit ».
fn pretty_unknown(t: &str) -> String {
    let s = t
        .trim_start_matches("default_")
        .trim_start_matches("claude_")
        .replace('_', " ");
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => "Inconnu".into(),
    }
}

/// Repli : ce que dit le fichier d'identifiants, toujours suffixé « (?) ».
pub fn from_credentials(subscription: Option<&str>, tier: Option<&str>) -> Option<String> {
    let sub = subscription.unwrap_or("").to_lowercase();
    let label = if tier.is_some_and(|t| !t.is_empty()) {
        from_profile(tier, sub == "max", sub == "pro")
    } else if sub == "max" {
        "Max".into()
    } else if sub == "pro" {
        "Pro".into()
    } else {
        return None;
    };
    Some(format!("{label} (?)"))
}

pub fn declared(raw: &str) -> String {
    format!("{} (déclaré)", raw.trim())
}

/// Multiplicateur de capacité : x20 = 20, x5 = 5, Pro = 1, inconnu = 1, gratuit = 0,2.
pub fn multiplier(label: &str) -> f64 {
    let l = label.to_lowercase();
    if l.contains("x20") {
        20.0
    } else if l.contains("x5") {
        5.0
    } else if l.contains("gratuit") || l.contains("free") {
        0.2
    } else {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_from_profile() {
        assert_eq!(
            from_profile(Some("default_claude_max_20x"), true, false),
            "Max x20"
        );
        assert_eq!(
            from_profile(Some("default_claude_max_5x"), true, false),
            "Max x5"
        );
        assert_eq!(from_profile(Some("default_claude_pro"), false, true), "Pro");
        assert_eq!(from_profile(None, true, false), "Max");
        assert_eq!(from_profile(None, false, true), "Pro");
        assert_eq!(from_profile(None, false, false), "Gratuit");
        assert_eq!(
            from_profile(Some("default_claude_ai"), false, false),
            "Gratuit"
        );
        assert_eq!(
            from_profile(Some("default_claude_team"), false, false),
            "Team"
        );
    }

    #[test]
    fn credentials_fallback_is_marked() {
        assert_eq!(
            from_credentials(Some("max"), Some("default_claude_max_20x")).as_deref(),
            Some("Max x20 (?)")
        );
        assert_eq!(
            from_credentials(Some("pro"), None).as_deref(),
            Some("Pro (?)")
        );
        assert_eq!(from_credentials(None, None), None);
    }

    #[test]
    fn multipliers() {
        assert_eq!(multiplier("Max x20"), 20.0);
        assert_eq!(multiplier("Max x5"), 5.0);
        assert_eq!(multiplier("Max x5 (déclaré)"), 5.0);
        assert_eq!(multiplier("Max x20 (?)"), 20.0);
        assert_eq!(multiplier("Pro"), 1.0);
        assert_eq!(multiplier("Max"), 1.0);
        assert_eq!(multiplier("Inconnu"), 1.0);
        assert_eq!(multiplier("Gratuit"), 0.2);
    }

    #[test]
    fn declared_suffix() {
        assert_eq!(declared(" Max x5 "), "Max x5 (déclaré)");
    }
}
