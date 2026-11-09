//! Trousseau macOS, via `/usr/bin/security` (pas de crate security-framework :
//! c'est exactement la porte que Claude lui-même emprunte, donc les mêmes ACL).
//!
//! La partie « nom de service » est pure et compilée partout (testée sur le
//! vecteur réel) ; les appels à `security` ne sont compilés que sous macOS.
//!
//! MESURE (macOS, trousseau temporaire, 09/11/2026) : `security -i` lit ses
//! commandes ligne par ligne dans un tampon de 4 096 caractères. Une ligne de
//! 4 096 passe, 4 098 est coupée (« unknown command "4141… », sortie 1, rien
//! n'est écrit). L'écriture en argv (comme le fait Claude au-delà) a été
//! relue à l'identique jusqu'à 100 000 octets. On bascule donc en argv dès que
//! la ligne dépasse [`STDIN_MAX_LINE`] (4 000 : 96 caractères de marge).

use crate::util::hex_encode;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

pub const SERVICE_BASE: &str = "Claude Code-credentials";

/// Seuil de bascule stdin → argv pour `security -i` (limite mesurée : 4 096).
pub const STDIN_MAX_LINE: usize = 4000;

/// Service d'un profil : `Claude Code-credentials-` + sha256(NFC(cfg))[:8 hex].
/// Le chemin est celui donné TEL QUEL dans `CLAUDE_CONFIG_DIR`.
pub fn service_name(cfg: &str) -> String {
    let nfc: String = cfg.nfc().collect();
    let digest = Sha256::digest(nfc.as_bytes());
    format!("{SERVICE_BASE}-{}", hex_encode(&digest[..4]))
}

/// Vrai pour `Claude Code-credentials-<8 hex>` : un profil à `CLAUDE_CONFIG_DIR`.
/// Faux pour le service nu (la session de la machine) et pour tout autre nom.
pub fn is_portable_service(svc: &str) -> bool {
    svc.strip_prefix(SERVICE_BASE)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|h| h.len() == 8 && h.chars().all(|c| c.is_ascii_hexdigit()))
}

#[derive(Debug)]
pub enum KcError {
    /// Trousseau verrouillé / interaction refusée / autorisation en attente.
    Locked(String),
    Failed(String),
}

impl std::fmt::Display for KcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KcError::Locked(m) | KcError::Failed(m) => f.write_str(m),
        }
    }
}

/// Échappement des guillemets pour le mode interactif de `security`.
fn escape_i(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Ligne `add-generic-password` pour `security -i` (sans saut de ligne final).
/// L'option « trousseau » vient EN DERNIER, comme l'attend `security`.
pub fn build_add_line(
    acct: &str,
    svc: &str,
    payload: &str,
    keychain: Option<&std::path::Path>,
) -> String {
    let mut line = format!(
        "add-generic-password -U -a \"{}\" -s \"{}\" -X \"{}\"",
        escape_i(acct),
        escape_i(svc),
        hex_encode(payload.as_bytes())
    );
    if let Some(kc) = keychain {
        line.push_str(&format!(" \"{}\"", escape_i(&kc.to_string_lossy())));
    }
    line
}

/// Faut-il passer par argv plutôt que par stdin ?
pub fn needs_argv(line: &str) -> bool {
    line.len() > STDIN_MAX_LINE
}

/// Extrait `"acct"<blob>="…"` de la sortie d'attributs de `security`.
/// Gère la forme hexadécimale `0x… "texte"` des valeurs non ASCII.
pub fn parse_acct(attrs: &str) -> Option<String> {
    for line in attrs.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("\"acct\"<blob>=") else {
            continue;
        };
        let rest = rest.trim();
        if rest.starts_with("<NULL>") {
            return None;
        }
        if let Some(h) = rest.strip_prefix("0x") {
            let digits: String = h.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
            return crate::util::hex_decode(&digits).and_then(|b| String::from_utf8(b).ok());
        }
        let inner = rest.strip_prefix('"')?;
        let end = inner.rfind('"')?;
        return Some(inner[..end].to_string());
    }
    None
}

/// `-w` affiche en hexadécimal une donnée qui n'est pas du texte imprimable :
/// on rend le JSON dans les deux cas.
pub fn decode_password_output(out: &str) -> String {
    let t = out.trim_end_matches(['\n', '\r']);
    if serde_json::from_str::<serde_json::Value>(t).is_ok() {
        return t.to_string();
    }
    if let Some(bytes) = crate::util::hex_decode(t.trim()) {
        if let Ok(s) = String::from_utf8(bytes) {
            if serde_json::from_str::<serde_json::Value>(&s).is_ok() {
                return s;
            }
        }
    }
    t.to_string()
}

#[cfg(target_os = "macos")]
pub use mac::*;

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use crate::env::Env;
    use crate::util::run_bounded;
    use std::process::Command;
    use std::time::Duration;

    const SECURITY: &str = "/usr/bin/security";
    /// Au-delà, une fenêtre d'autorisation attend sans doute un clic de Sam.
    const TIMEOUT: Duration = Duration::from_secs(8);

    pub struct Item {
        pub acct: String,
        pub secret: String,
    }

    fn classify(code: Option<i32>, stderr: &str) -> KcError {
        let first = stderr.lines().next().unwrap_or("").trim().to_string();
        match code {
            // 36 = interaction non permise, 51 = trousseau absent/verrouillé selon macOS.
            Some(36) | Some(51) => KcError::Locked("Trousseau verrouillé".into()),
            None => KcError::Locked("Trousseau : autorisation en attente (délai dépassé)".into()),
            Some(c) => KcError::Failed(format!("security a échoué (code {c}) : {first}")),
        }
    }

    fn base(env: &Env, args: &[&str]) -> Command {
        let mut c = Command::new(SECURITY);
        c.args(args);
        if let Some(kc) = &env.keychain {
            c.arg(kc);
        }
        c
    }

    fn read_secret(env: &Env, acct: &str, svc: &str) -> Result<Option<String>, KcError> {
        let mut c = base(env, &["find-generic-password", "-a", acct, "-s", svc, "-w"]);
        let out = run_bounded(&mut c, None, TIMEOUT)
            .map_err(|e| KcError::Failed(format!("security : {e}")))?;
        match out.code() {
            Some(0) => Ok(Some(decode_password_output(&out.stdout_str()))),
            Some(44) => Ok(None),
            c => Err(classify(c, &out.stderr_str())),
        }
    }

    fn lookup_acct(env: &Env, svc: &str) -> Result<Option<String>, KcError> {
        let mut c = base(env, &["find-generic-password", "-s", svc]);
        let out = run_bounded(&mut c, None, TIMEOUT)
            .map_err(|e| KcError::Failed(format!("security : {e}")))?;
        match out.code() {
            Some(0) => Ok(parse_acct(&out.stdout_str())),
            Some(44) => Ok(None),
            c => Err(classify(c, &out.stderr_str())),
        }
    }

    /// Lit l'item du service. Compte attendu = `$USER` (comme Claude) ; sinon on
    /// retrouve le compte réel de l'item pour le réutiliser à la réécriture.
    pub fn find(env: &Env, svc: &str) -> Result<Option<Item>, KcError> {
        if let Some(secret) = read_secret(env, &env.user, svc)? {
            return Ok(Some(Item {
                acct: env.user.clone(),
                secret,
            }));
        }
        let Some(acct) = lookup_acct(env, svc)? else {
            return Ok(None);
        };
        Ok(read_secret(env, &acct, svc)?.map(|secret| Item { acct, secret }))
    }

    /// Écrit (ou remplace) l'item, puis RELIT pour vérifier : `security -i` peut
    /// sortir 0 sur une commande qu'il n'a pas exécutée comme prévu.
    pub fn upsert(env: &Env, acct: &str, svc: &str, payload: &str) -> Result<(), KcError> {
        if acct.contains(['\n', '\r']) || svc.contains(['\n', '\r']) {
            return Err(KcError::Failed("nom de compte Trousseau invalide".into()));
        }
        let line = build_add_line(acct, svc, payload, env.keychain.as_deref());
        let out = if needs_argv(&line) {
            // RISQUE ACCEPTÉ (coordinateur, revue terminale 09/11/2026) : au-delà
            // de la limite de `security -i` (~4 000 caractères), le secret passe
            // en argv (`-X <hex>`), donc visible quelques ms dans `ps` pour les
            // processus du même utilisateur. WHY on ne passe pas par une API
            // native (SecItemAdd/Update) : Claude Code fait EXACTEMENT ce repli
            // (même commande, même item), et une API native recréerait l'item
            // avec une autre ACL (application créatrice différente de `security`)
            // — Claude, qui relit l'item via `security`, risquerait alors de
            // déclencher des invites d'autorisation du Trousseau. Un login seul
            // (~500 caractères) ne passe JAMAIS ici : seuls les gros coffres
            // (mcpOAuth volumineux) y arrivent. Ne pas « corriger » sans accord.
            let mut args: Vec<String> = ["add-generic-password", "-U", "-a", acct, "-s", svc, "-X"]
                .iter()
                .map(|s| s.to_string())
                .collect();
            args.push(hex_encode(payload.as_bytes()));
            let mut c = Command::new(SECURITY);
            c.args(&args);
            if let Some(kc) = &env.keychain {
                c.arg(kc);
            }
            run_bounded(&mut c, None, TIMEOUT)
        } else {
            let mut c = Command::new(SECURITY);
            c.arg("-i");
            run_bounded(&mut c, Some(format!("{line}\n").as_bytes()), TIMEOUT)
        }
        .map_err(|e| KcError::Failed(format!("security : {e}")))?;
        if out.code() != Some(0) {
            return Err(classify(out.code(), &out.stderr_str()));
        }
        match read_secret(env, acct, svc)? {
            Some(back) if back == payload => Ok(()),
            _ => Err(KcError::Failed(
                "écriture Trousseau non confirmée à la relecture".into(),
            )),
        }
    }

    /// Supprime tous les items du service (un appel de `security` en retire un).
    /// Renvoie le nombre supprimé.
    pub fn delete_all(env: &Env, svc: &str) -> Result<usize, KcError> {
        // Garde-fou ABSOLU : le service SANS suffixe est la session de la machine
        // (Claude Code normal de Sam). On ne supprime que des services suffixés.
        if !is_portable_service(svc) {
            return Err(KcError::Failed(
                "refus de supprimer un service qui n'est pas celui d'un profil portable".into(),
            ));
        }
        let mut n = 0;
        for _ in 0..8 {
            let mut c = base(env, &["delete-generic-password", "-s", svc]);
            let out = run_bounded(&mut c, None, TIMEOUT)
                .map_err(|e| KcError::Failed(format!("security : {e}")))?;
            match out.code() {
                Some(0) => n += 1,
                Some(44) => break,
                c => return Err(classify(c, &out.stderr_str())),
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_suffixed_services_are_portable() {
        assert!(is_portable_service("Claude Code-credentials-72588510"));
        assert!(!is_portable_service("Claude Code-credentials"));
        assert!(!is_portable_service("Claude Code-credentials-"));
        assert!(!is_portable_service("Claude Code-credentials-zzzzzzzz"));
        assert!(!is_portable_service("Claude Code-credentials-725885100"));
        assert!(!is_portable_service("autre-72588510"));
    }

    #[test]
    fn real_vector_sora() {
        // Vecteur mesuré sur l'item réel du Trousseau de ce Mac (07/11/2026).
        assert_eq!(
            service_name("/Users/samuelmuselet/.config/meridian/profiles/sora"),
            "Claude Code-credentials-72588510"
        );
    }

    #[test]
    fn trailing_slash_changes_the_hash_so_it_is_stripped_upstream() {
        // Le hash porte sur la chaîne exacte : `Root` retire le slash final AVANT.
        assert_ne!(service_name("/a/b"), service_name("/a/b/"));
    }

    #[test]
    fn nfd_and_nfc_give_the_same_service() {
        let nfc = "/Volumes/Clé/été/config/1";
        let nfd = "/Volumes/Cle\u{301}/e\u{301}te\u{301}/config/1";
        assert_ne!(nfc, nfd);
        assert_eq!(service_name(nfc), service_name(nfd));
    }

    #[test]
    fn spaces_are_hashed_verbatim() {
        assert_ne!(service_name("/a b/c"), service_name("/a  b/c"));
        assert!(service_name("/a b/c").starts_with("Claude Code-credentials-"));
        assert_eq!(
            service_name("/a b/c").len(),
            "Claude Code-credentials-".len() + 8
        );
    }

    #[test]
    fn add_line_puts_keychain_last_and_escapes() {
        let l = build_add_line(
            "sam\"x",
            "svc",
            "{\"a\":1}",
            Some(std::path::Path::new("/tmp/t.keychain")),
        );
        assert!(l.starts_with("add-generic-password -U -a \"sam\\\"x\" -s \"svc\" -X \""));
        assert!(l.ends_with(" \"/tmp/t.keychain\""));
        assert!(!l.contains('\n'));
    }

    #[test]
    fn threshold_switches_to_argv() {
        let small = build_add_line("u", "s", &"x".repeat(1900), None);
        assert!(!needs_argv(&small));
        let big = build_add_line("u", "s", &"x".repeat(2100), None);
        assert!(needs_argv(&big));
    }

    #[test]
    fn parses_acct_plain_and_hex() {
        let plain = "class: \"genp\"\nattributes:\n    \"acct\"<blob>=\"samuelmuselet\"\n    \"svce\"<blob>=\"x\"\n";
        assert_eq!(parse_acct(plain).as_deref(), Some("samuelmuselet"));
        let hexed = "    \"acct\"<blob>=0x73616DC3A9  \"samé\"\n";
        assert_eq!(parse_acct(hexed).as_deref(), Some("samé"));
        assert_eq!(parse_acct("    \"acct\"<blob>=<NULL>\n"), None);
        assert_eq!(parse_acct("rien"), None);
    }

    #[test]
    fn decodes_hex_password_output() {
        let json = "{\"claudeAiOauth\":{\"accessToken\":\"é\"}}";
        let hex = crate::util::hex_encode(json.as_bytes());
        assert_eq!(decode_password_output(&format!("{hex}\n")), json);
        assert_eq!(decode_password_output(&format!("{json}\n")), json);
    }
}
