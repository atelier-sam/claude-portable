//! Catalogue des logiciels Windows : TOML embarqué + surcharge `config/catalog.toml`.
//!
//! Le wizard passe la sortie `lines` telle quelle à `gum choose --no-limit`, donc :
//! une ligne par logiciel, `clé<TAB>libellé<TAB>coché(0|1)`, jamais de virgule dans
//! un libellé (gum sépare `--selected` par des virgules) ni de tabulation.
//!
//! Fusion PAR CLÉ, champ par champ : Sam peut décocher `chrome` d'une ligne
//! (`default = false`) sans recopier l'entrée entière, retirer une entrée
//! (`remove = true`) ou en ajouter une (label + winget obligatoires).

use crate::error::{CcpError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Catalogue livré avec le binaire.
pub const EMBEDDED: &str = include_str!("catalog.toml");

/// Nom du fichier de surcharge, sous `<racine>/config/`.
pub const OVERRIDE_FILE: &str = "catalog.toml";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct App {
    pub key: String,
    pub label: String,
    pub category: String,
    /// Identifiant winget (`Éditeur.Paquet`).
    pub winget: String,
    pub default: bool,
}

/// Une entrée telle qu'écrite dans un fichier TOML : tout est optionnel pour
/// qu'une surcharge puisse ne changer qu'un champ.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApp {
    key: String,
    label: Option<String>,
    category: Option<String>,
    winget: Option<String>,
    default: Option<bool>,
    #[serde(default)]
    remove: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    #[serde(default)]
    app: Vec<RawApp>,
}

/// Clé de catalogue : minuscules, chiffres, `-`, `_`, `.` ; jamais d'espace ni de
/// tabulation (elle sort telle quelle sur stdout et revient en argument de `install`).
pub fn valid_key(k: &str) -> bool {
    let mut chars = k.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && k.len() <= 40
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

/// Identifiant winget : jamais de tiret initial (ce serait pris pour une option de
/// `winget`) ni d'espace. Le `+` existe (`Microsoft.VCRedist.2015+.x64`).
pub fn valid_winget_id(id: &str) -> bool {
    let mut chars = id.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && id.contains('.')
        && id.len() <= 120
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_'))
}

/// Libellé sûr pour une ligne `clé<TAB>libellé<TAB>0|1` consommée par gum.
pub fn clean_label(s: &str) -> String {
    let replaced: String = s
        .chars()
        .map(|c| if c == ',' || c.is_control() { ' ' } else { c })
        .collect();
    replaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_file(text: &str, origin: &str) -> std::result::Result<Vec<RawApp>, String> {
    let f: RawFile = toml::from_str(text).map_err(|e| format!("{origin} invalide : {e}"))?;
    Ok(f.app)
}

/// Fusionne `over` dans `base` (voir la documentation du module).
fn merge(
    base: Vec<RawApp>,
    over: Vec<RawApp>,
    origin: &str,
) -> std::result::Result<Vec<App>, String> {
    let mut out: Vec<App> = Vec::new();
    let mut apply = |raw: RawApp, is_base: bool| -> std::result::Result<(), String> {
        if !valid_key(&raw.key) {
            return Err(format!("{origin} : clé invalide « {} »", raw.key));
        }
        let pos = out.iter().position(|a| a.key == raw.key);
        if raw.remove {
            if let Some(i) = pos {
                out.remove(i);
            }
            return Ok(());
        }
        match pos {
            Some(i) => {
                let a = &mut out[i];
                if let Some(l) = raw.label {
                    a.label = clean_label(&l);
                }
                if let Some(c) = raw.category {
                    a.category = clean_label(&c);
                }
                if let Some(w) = raw.winget {
                    a.winget = w.trim().to_string();
                }
                if let Some(d) = raw.default {
                    a.default = d;
                }
            }
            None => {
                let (Some(label), Some(winget)) = (raw.label, raw.winget) else {
                    let who = if is_base {
                        "le catalogue embarqué"
                    } else {
                        origin
                    };
                    return Err(format!(
                        "{who} : « {} » est une entrée nouvelle, elle doit avoir label et winget",
                        raw.key
                    ));
                };
                out.push(App {
                    key: raw.key,
                    label: clean_label(&label),
                    category: raw
                        .category
                        .map(|c| clean_label(&c))
                        .unwrap_or_else(|| "Divers".to_string()),
                    winget: winget.trim().to_string(),
                    default: raw.default.unwrap_or(false),
                });
            }
        }
        Ok(())
    };
    for r in base {
        apply(r, true)?;
    }
    for r in over {
        apply(r, false)?;
    }
    for a in &out {
        if a.label.is_empty() {
            return Err(format!("{origin} : libellé vide pour « {} »", a.key));
        }
        if !valid_winget_id(&a.winget) {
            return Err(format!(
                "{origin} : identifiant winget invalide pour « {} » : « {} »",
                a.key, a.winget
            ));
        }
    }
    Ok(out)
}

/// Catalogue embarqué seul (celui des tests et du repli).
pub fn embedded() -> Result<Vec<App>> {
    let base = parse_file(EMBEDDED, "catalogue embarqué").map_err(CcpError::Internal)?;
    merge(base, Vec::new(), "catalogue embarqué").map_err(CcpError::Internal)
}

/// Catalogue embarqué + surcharge de la racine. Une surcharge illisible ou
/// invalide n'empêche pas le wizard de proposer le catalogue de base : on la
/// signale sur stderr et on l'ignore (`warn` reçoit le message).
pub fn load(root_dir: &Path, warn: &mut dyn FnMut(String)) -> Result<Vec<App>> {
    let base = parse_file(EMBEDDED, "catalogue embarqué").map_err(CcpError::Internal)?;
    let file = root_dir.join("config").join(OVERRIDE_FILE);
    let over = match std::fs::read_to_string(&file) {
        Ok(text) => match parse_file(&text, &file.display().to_string()) {
            Ok(v) => v,
            Err(m) => {
                warn(format!("{m} ; surcharge ignorée."));
                Vec::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            warn(format!(
                "{} illisible ({e}) ; surcharge ignorée.",
                file.display()
            ));
            Vec::new()
        }
    };
    let origin = file.display().to_string();
    // Si la fusion échoue À CAUSE de la surcharge, on retombe sur l'embarqué seul.
    let base_again = parse_file(EMBEDDED, "catalogue embarqué").map_err(CcpError::Internal)?;
    match merge(base, over, &origin) {
        Ok(v) => Ok(v),
        Err(m) => {
            warn(format!("{m} ; surcharge ignorée."));
            merge(base_again, Vec::new(), "catalogue embarqué").map_err(CcpError::Internal)
        }
    }
}

/// `clé<TAB>libellé<TAB>coché`, une ligne par logiciel.
pub fn render_lines(apps: &[App]) -> String {
    let mut s = String::new();
    for a in apps {
        s.push_str(&format!(
            "{}\t{}\t{}\n",
            a.key,
            a.label,
            if a.default { 1 } else { 0 }
        ));
    }
    s
}

pub fn render_json(apps: &[App]) -> Result<String> {
    #[derive(Serialize)]
    struct Out<'a> {
        schema: u32,
        apps: &'a [App],
    }
    serde_json::to_string(&Out { schema: 1, apps })
        .map_err(|e| CcpError::Internal(format!("sérialisation JSON : {e}")))
}

/// Résout des clés demandées ; les inconnues sont listées TOUTES d'un coup.
pub fn resolve<'a>(apps: &'a [App], keys: &[String]) -> Result<Vec<&'a App>> {
    let mut found = Vec::new();
    let mut unknown = Vec::new();
    for k in keys {
        match apps.iter().find(|a| &a.key == k) {
            Some(a) => {
                if !found.iter().any(|f: &&App| f.key == a.key) {
                    found.push(a);
                }
            }
            None => unknown.push(k.as_str()),
        }
    }
    if unknown.is_empty() {
        Ok(found)
    } else {
        Err(CcpError::Usage(format!(
            "logiciel(s) inconnu(s) du catalogue : {} (voir « win catalog »)",
            unknown.join(", ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_override(dir: &Path, text: &str) {
        std::fs::create_dir_all(dir.join("config")).unwrap();
        std::fs::write(dir.join("config").join(OVERRIDE_FILE), text).unwrap();
    }

    #[test]
    fn embedded_catalog_is_valid_and_has_the_required_entries() {
        let apps = embedded().unwrap();
        for k in [
            "chrome",
            "firefox",
            "libreoffice",
            "winrar",
            "7zip",
            "vlc",
            "acrobat-reader",
            "anydesk",
            "teamviewer",
            "notepadpp",
            "thunderbird",
            "zoom",
            "teams",
            "onedrive",
            "java",
            "dotnet-desktop",
            "vcredist",
            "powertoys",
            "keepassxc",
            "malwarebytes",
        ] {
            assert!(apps.iter().any(|a| a.key == k), "clé manquante : {k}");
        }
        // Retirés après vérification contre winget-pkgs, ou interdits par Sam.
        for k in ["rustdesk", "ccleaner", "ccleaner-free"] {
            assert!(
                !apps.iter().any(|a| a.key == k),
                "ne doit pas figurer : {k}"
            );
        }
        assert!(!apps.iter().any(|a| a.winget == "RustDesk.RustDesk"));
        assert!(!apps.iter().any(|a| a.winget == "KeePassXC.KeePassXC"));
        assert_eq!(
            apps.iter().find(|a| a.key == "chrome").unwrap().winget,
            "Google.Chrome"
        );
    }

    #[test]
    fn embedded_labels_are_gum_safe_and_keys_unique() {
        let apps = embedded().unwrap();
        let mut seen = std::collections::HashSet::new();
        for a in &apps {
            assert!(!a.label.contains(','), "virgule dans « {} »", a.label);
            assert!(!a.label.contains(['\t', '\n', '\r']));
            assert!(valid_key(&a.key), "{}", a.key);
            assert!(valid_winget_id(&a.winget), "{}", a.winget);
            assert!(seen.insert(a.key.clone()), "clé en double : {}", a.key);
        }
    }

    #[test]
    fn lines_format_is_key_label_checked() {
        let apps = embedded().unwrap();
        let out = render_lines(&apps);
        let first: Vec<&str> = out.lines().next().unwrap().split('\t').collect();
        assert_eq!(first, ["chrome", "Google Chrome", "1"]);
        for l in out.lines() {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 3, "{l}");
            assert!(f[2] == "0" || f[2] == "1");
        }
    }

    #[test]
    fn override_changes_one_field_without_copying_the_entry() {
        let t = tempfile::tempdir().unwrap();
        write_override(
            t.path(),
            "[[app]]\nkey = \"chrome\"\ndefault = false\n\n[[app]]\nkey = \"firefox\"\ndefault = true\n",
        );
        let apps = load(t.path(), &mut |_m| {}).unwrap();
        let chrome = apps.iter().find(|a| a.key == "chrome").unwrap();
        assert!(!chrome.default);
        assert_eq!(chrome.winget, "Google.Chrome");
        assert_eq!(chrome.label, "Google Chrome");
        assert!(apps.iter().find(|a| a.key == "firefox").unwrap().default);
        // L'ordre du catalogue de base est conservé.
        assert_eq!(apps[0].key, "chrome");
    }

    #[test]
    fn override_can_add_and_remove_entries() {
        let t = tempfile::tempdir().unwrap();
        write_override(
            t.path(),
            "[[app]]\nkey = \"gimp\"\nlabel = \"GIMP, retouche\"\nwinget = \"GIMP.GIMP.3\"\n\n\
             [[app]]\nkey = \"winrar\"\nremove = true\n",
        );
        let apps = load(t.path(), &mut |_m| {}).unwrap();
        assert!(!apps.iter().any(|a| a.key == "winrar"));
        let gimp = apps.iter().find(|a| a.key == "gimp").unwrap();
        // La virgule du libellé est neutralisée (gum), la catégorie par défaut posée.
        assert_eq!(gimp.label, "GIMP retouche");
        assert_eq!(gimp.category, "Divers");
        assert!(!gimp.default);
        assert_eq!(apps.last().unwrap().key, "gimp");
    }

    #[test]
    fn a_broken_override_falls_back_to_the_embedded_catalog_with_a_warning() {
        for bad in [
            "ceci n'est pas du toml [[",
            "[[app]]\nkey = \"nouveau\"\nlabel = \"Sans winget\"\n",
            "[[app]]\nkey = \"chrome\"\nwinget = \"-oEvil\"\n",
            "[[app]]\nkey = \"Majuscule\"\nlabel = \"x\"\nwinget = \"A.B\"\n",
            "[[app]]\nkey = \"chrome\"\ninconnu = 1\n",
        ] {
            let t = tempfile::tempdir().unwrap();
            write_override(t.path(), bad);
            let mut warnings = Vec::new();
            let apps = load(t.path(), &mut |m| warnings.push(m)).unwrap();
            assert_eq!(apps, embedded().unwrap(), "repli attendu pour {bad:?}");
            assert_eq!(warnings.len(), 1, "{bad:?}");
            assert!(warnings[0].contains("surcharge ignorée"), "{warnings:?}");
        }
    }

    #[test]
    fn missing_override_is_silent() {
        let t = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();
        let apps = load(t.path(), &mut |m| warnings.push(m)).unwrap();
        assert_eq!(apps, embedded().unwrap());
        assert!(warnings.is_empty());
    }

    #[test]
    fn resolve_lists_every_unknown_key_at_once() {
        let apps = embedded().unwrap();
        let keys: Vec<String> = ["chrome", "nope", "vlc", "chrome", "zzz"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let e = resolve(&apps, &keys).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        let m = e.to_string();
        assert!(
            m.contains("nope") && m.contains("zzz") && !m.contains("vlc"),
            "{m}"
        );
        let ok = resolve(&apps, &keys[..1]).unwrap();
        assert_eq!(ok.len(), 1);
        // Doublons : une seule installation.
        let dup: Vec<String> = vec!["vlc".into(), "vlc".into()];
        assert_eq!(resolve(&apps, &dup).unwrap().len(), 1);
    }

    #[test]
    fn winget_ids_cannot_look_like_options() {
        assert!(valid_winget_id("Microsoft.VCRedist.2015+.x64"));
        assert!(valid_winget_id("Notepad++.Notepad++"));
        assert!(!valid_winget_id("-oEvil.x"));
        assert!(!valid_winget_id("Sans point"));
        assert!(!valid_winget_id("A.B C"));
        assert!(!valid_winget_id(""));
    }

    #[test]
    fn json_output_has_schema_and_fields() {
        let apps = embedded().unwrap();
        let v: serde_json::Value = serde_json::from_str(&render_json(&apps).unwrap()).unwrap();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["apps"][0]["key"], "chrome");
        assert_eq!(v["apps"][0]["winget"], "Google.Chrome");
        assert_eq!(v["apps"][0]["default"], true);
    }
}
