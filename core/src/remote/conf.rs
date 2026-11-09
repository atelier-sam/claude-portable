//! Réglages de `remote` : hôte et utilisateur (conf), confiance dans CET ordinateur
//! (marqueur du wizard) et nettoyage des jetons Cloudflare Access d'un ordinateur invité.

use super::pins::{DEFAULT_HOST, DEFAULT_USER};
use crate::error::{CcpError, Result};
use crate::root::Root;
use crate::util::run_bounded;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Fichier de réglages : `<racine>/config/remote.conf`, lignes `clé = valeur`
/// (`host`, `user`), `#` pour les commentaires, guillemets facultatifs.
pub const CONF_FILE: &str = "remote.conf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub user: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RawConf {
    pub host: Option<String>,
    pub user: Option<String>,
}

/// Nom d'hôte DNS sûr : jamais de tiret en tête (ssh y verrait une option), jamais
/// d'espace ni de métacaractère. C'est la seule barrière entre un fichier de conf
/// (ou un argument) et la ligne de commande de ssh.
pub fn valid_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with(['-', '.'])
        && !h.ends_with('.')
        && !h.contains("..")
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

pub fn valid_user(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 64
        && !u.starts_with(['-', '.'])
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

pub fn parse_conf(text: &str, source: &str) -> Result<RawConf> {
    let mut conf = RawConf::default();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(CcpError::Usage(format!(
                "{source}, ligne {} : « {line} » n'est pas de la forme clé = valeur",
                i + 1
            )));
        };
        let v = unquote(v);
        match k.trim() {
            "host" => {
                if !valid_host(v) {
                    return Err(CcpError::Usage(format!(
                        "{source}, ligne {} : « {v} » n'est pas un nom d'hôte valide",
                        i + 1
                    )));
                }
                conf.host = Some(v.to_string());
            }
            "user" => {
                if !valid_user(v) {
                    return Err(CcpError::Usage(format!(
                        "{source}, ligne {} : « {v} » n'est pas un nom d'utilisateur valide",
                        i + 1
                    )));
                }
                conf.user = Some(v.to_string());
            }
            // Clé inconnue : ignorée, pour qu'une conf plus récente reste lisible.
            _ => {}
        }
    }
    Ok(conf)
}

pub fn conf_path(root: &Root) -> PathBuf {
    root.path().join("config").join(CONF_FILE)
}

pub fn load(root: &Root) -> Result<RawConf> {
    let p = conf_path(root);
    match fs::read_to_string(&p) {
        Ok(t) => parse_conf(&t, &p.display().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RawConf::default()),
        Err(e) => Err(CcpError::Internal(format!(
            "{} illisible : {e}",
            p.display()
        ))),
    }
}

/// Argument de la ligne de commande > fichier de conf > valeurs par défaut.
pub fn resolve(cli_host: Option<&str>, cli_user: Option<&str>, conf: RawConf) -> Result<Target> {
    let host = cli_host
        .map(str::to_string)
        .or(conf.host)
        .unwrap_or_else(|| DEFAULT_HOST.to_string());
    let user = cli_user
        .map(str::to_string)
        .or(conf.user)
        .unwrap_or_else(|| DEFAULT_USER.to_string());
    if !valid_host(&host) {
        return Err(CcpError::Usage(format!(
            "« {host} » n'est pas un nom d'hôte valide"
        )));
    }
    if !valid_user(&user) {
        return Err(CcpError::Usage(format!(
            "« {user} » n'est pas un nom d'utilisateur valide"
        )));
    }
    Ok(Target { host, user })
}

// ------------------------------------------------------------ confiance (wizard)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Trusted,
    /// Ordinateur qui n'est pas à Sam : on ne laisse rien de sa session dessus.
    Guest,
    /// Aucun marqueur : le wizard n'a pas posé la question (Windows, ou lancement direct).
    Unknown,
}

/// Même calcul que `host_key()` du wizard : `hostname | tr -c 'a-zA-Z0-9_.-' '_'`.
/// Le saut de ligne final de `hostname` devient lui aussi un `_` : c'est le nom réel du
/// marqueur. Deux variantes (par caractère / par octet) car `tr` dépend de la locale.
pub fn host_keys(hostname: &str) -> Vec<String> {
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-');
    let with_nl = format!("{hostname}\n");
    let per_char: String = with_nl
        .chars()
        .map(|c| if allowed(c) { c } else { '_' })
        .collect();
    let per_byte: String = with_nl
        .bytes()
        .map(|b| {
            if b.is_ascii() && allowed(b as char) {
                b as char
            } else {
                '_'
            }
        })
        .collect();
    let mut v = vec![per_char];
    if v[0] != per_byte {
        v.push(per_byte);
    }
    v
}

pub fn read_trust(root: &Root, hostname: &str) -> Trust {
    for key in host_keys(hostname) {
        let p = root.path().join("config").join(".hosts").join(key);
        if let Ok(t) = fs::read_to_string(p) {
            return match t.trim() {
                "guest" => Trust::Guest,
                "trusted" => Trust::Trusted,
                _ => Trust::Unknown,
            };
        }
    }
    Trust::Unknown
}

/// Nom de cet ordinateur, lu comme le wizard le lit (`hostname`).
pub fn local_hostname() -> Option<String> {
    let out = run_bounded(&mut Command::new("hostname"), None, Duration::from_secs(3)).ok()?;
    let name = out.stdout_str().trim().to_string();
    (out.code() == Some(0) && !name.is_empty()).then_some(name)
}

// ------------------------------------------------------- jetons Cloudflare Access

fn is_hex(s: &str) -> bool {
    s.len() >= 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Fichier de jeton Access que cloudflared range dans `~/.cloudflared/` :
/// - `<hôte>-<aud>-token` : l'application (ici `ssh-mac.atelier-sam.fr`) ;
/// - `<équipe>.cloudflareaccess.com-org-token` : l'IDENTITÉ de l'équipe, qui ouvrirait
///   aussi les autres applications Access de Sam tant qu'elle vit.
///
/// Le suffixe `.lock` est l'ombre que cloudflared laisse à côté. Reconnaissance STRICTE :
/// rien d'autre du dossier (certificat, jeton du tunnel côté Mac) n'est jamais touché.
pub fn is_access_token_name(name: &str, host: &str) -> bool {
    let base = name.strip_suffix(".lock").unwrap_or(name);
    if let Some(mid) = base
        .strip_prefix(host)
        .and_then(|r| r.strip_prefix('-'))
        .and_then(|r| r.strip_suffix("-token"))
    {
        if is_hex(mid) {
            return true;
        }
    }
    base.strip_suffix(".cloudflareaccess.com-org-token")
        .is_some_and(|team| {
            !team.is_empty() && team.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Efface les jetons Access de `<home>/.cloudflared` ; renvoie leurs noms (jamais leur contenu).
pub fn purge_access_tokens(home: &Path, host: &str) -> Vec<String> {
    let dir = home.join(".cloudflared");
    let mut removed = Vec::new();
    let Ok(rd) = fs::read_dir(&dir) else {
        return removed;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if is_access_token_name(&name, host)
            && e.path().is_file()
            && fs::remove_file(e.path()).is_ok()
        {
            removed.push(name);
        }
    }
    removed.sort();
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::PathStyle;

    const AUD: &str = "00d26537aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn hosts_and_users_cannot_smuggle_ssh_options() {
        for ok in ["ssh-mac.atelier-sam.fr", "h", "a-b.c", "10.0.0.1"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "-oProxyCommand=x",
            ".x",
            "x.",
            "a..b",
            "a b",
            "a;b",
            "a/b",
            "é.fr",
            "a@b",
            "a:22",
        ] {
            assert!(!valid_host(bad), "{bad:?}");
        }
        assert!(valid_user("samuelmuselet") && valid_user("a.b_c-d"));
        for bad in ["", "-x", ".x", "a b", "a@b", "é", "a;b"] {
            assert!(!valid_user(bad), "{bad:?}");
        }
    }

    #[test]
    fn conf_parses_comments_quotes_and_unknown_keys() {
        let c = parse_conf(
            "# mon Mac\nhost = \"h.example\"\n\nuser='sam'\nfutur = 1\n",
            "remote.conf",
        )
        .unwrap();
        assert_eq!(c.host.as_deref(), Some("h.example"));
        assert_eq!(c.user.as_deref(), Some("sam"));
    }

    #[test]
    fn conf_errors_name_the_file_and_line() {
        let e = parse_conf(
            "host = ok.example\nhost = -oProxyCommand=x\n",
            "C:\\r\\remote.conf",
        )
        .unwrap_err();
        assert!(e.to_string().contains("remote.conf, ligne 2"), "{e}");
        assert_eq!(e.exit_code(), 2);
        assert!(parse_conf("n'importe quoi\n", "f").is_err());
    }

    #[test]
    fn precedence_is_cli_then_conf_then_defaults() {
        let conf = || RawConf {
            host: Some("conf.example".into()),
            user: Some("confuser".into()),
        };
        let t = resolve(Some("cli.example"), None, conf()).unwrap();
        assert_eq!(
            (t.host.as_str(), t.user.as_str()),
            ("cli.example", "confuser")
        );
        let d = resolve(None, None, RawConf::default()).unwrap();
        assert_eq!(
            (d.host.as_str(), d.user.as_str()),
            (DEFAULT_HOST, DEFAULT_USER)
        );
        assert!(resolve(Some("-bad"), None, RawConf::default()).is_err());
    }

    #[test]
    fn load_reads_the_file_under_config() {
        let t = tempfile::tempdir().unwrap();
        let root = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        assert_eq!(load(&root).unwrap(), RawConf::default());
        fs::create_dir_all(t.path().join("config")).unwrap();
        fs::write(t.path().join("config/remote.conf"), "host = a.example\n").unwrap();
        assert_eq!(load(&root).unwrap().host.as_deref(), Some("a.example"));
    }

    #[test]
    fn host_key_matches_the_wizard_including_the_trailing_underscore() {
        // `hostname` imprime « Mac-mini.local\n » ; tr -c remplace aussi le saut de ligne.
        assert_eq!(
            host_keys("Mac-mini.local"),
            vec!["Mac-mini.local_".to_string()]
        );
        assert_eq!(host_keys("PC de Sam")[0], "PC_de_Sam_");
        // Accent : « é » = 1 caractère mais 2 octets -> deux variantes plausibles.
        let k = host_keys("Café");
        assert_eq!(k, vec!["Caf__".to_string(), "Caf___".to_string()]);
    }

    #[test]
    fn trust_is_read_from_the_marker_written_by_the_wizard() {
        let t = tempfile::tempdir().unwrap();
        let root = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        assert_eq!(read_trust(&root, "Mac-mini.local"), Trust::Unknown);
        let dir = t.path().join("config/.hosts");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("Mac-mini.local_"), "guest\n").unwrap();
        assert_eq!(read_trust(&root, "Mac-mini.local"), Trust::Guest);
        fs::write(dir.join("Mac-mini.local_"), "trusted\n").unwrap();
        assert_eq!(read_trust(&root, "Mac-mini.local"), Trust::Trusted);
        fs::write(dir.join("Mac-mini.local_"), "??\n").unwrap();
        assert_eq!(read_trust(&root, "Mac-mini.local"), Trust::Unknown);
    }

    #[test]
    fn only_real_access_token_files_are_recognised() {
        let h = "ssh-mac.atelier-sam.fr";
        assert!(is_access_token_name(&format!("{h}-{AUD}-token"), h));
        assert!(is_access_token_name(&format!("{h}-{AUD}-token.lock"), h));
        assert!(is_access_token_name(
            "atelier-sam.cloudflareaccess.com-org-token",
            h
        ));
        assert!(is_access_token_name(
            "atelier-sam.cloudflareaccess.com-org-token.lock",
            h
        ));
        for no in [
            "cert.pem",
            "ccp-mac.token",
            "config.yml",
            "autre.example-00d26537aaaaaaaaaaaaaaaaaaaaaaaaaaaa-token",
            &format!("{h}-nonhex-token"),
            &format!("x{h}-{AUD}-token"),
            ".cloudflareaccess.com-org-token",
        ] {
            assert!(!is_access_token_name(no, h), "{no}");
        }
    }

    #[test]
    fn purge_removes_tokens_and_nothing_else() {
        let t = tempfile::tempdir().unwrap();
        let cf = t.path().join(".cloudflared");
        fs::create_dir_all(&cf).unwrap();
        let h = "ssh-mac.atelier-sam.fr";
        for (n, keep) in [
            (format!("{h}-{AUD}-token"), false),
            (
                "atelier-sam.cloudflareaccess.com-org-token.lock".to_string(),
                false,
            ),
            ("ccp-mac.token".to_string(), true),
            ("cert.pem".to_string(), true),
        ] {
            fs::write(cf.join(&n), "secret").unwrap();
            let _ = keep;
        }
        let gone = purge_access_tokens(t.path(), h);
        assert_eq!(gone.len(), 2, "{gone:?}");
        assert!(cf.join("ccp-mac.token").exists() && cf.join("cert.pem").exists());
        assert!(!cf.join(format!("{h}-{AUD}-token")).exists());
        // Dossier absent : rien, sans erreur.
        assert!(purge_access_tokens(&t.path().join("vide"), h).is_empty());
    }
}
