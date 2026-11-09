//! Installation d'Office par l'Office Deployment Tool (ODT), sans clé de licence.
//!
//! Sources vérifiées le 09/11/2026 (Microsoft Learn, « Configuration options for the
//! Office Deployment Tool » et « Product IDs supported by the Office Deployment Tool
//! for Click-to-Run ») : identifiants de produit, canaux (`Current`, `PerpetualVL2024`,
//! `PerpetualVL2021`) et identifiants `ExcludeApp` (Access, Excel, Groove, Lync,
//! OneDrive, OneNote, Outlook, OutlookForWindows, PowerPoint, Publisher, Teams, Word).
//!
//! Aucune clé n'est posée : les éditions en licence en volume s'installent
//! « non activées » (libellé du catalogue) et `AUTOACTIVATE` vaut 0.
//!
//! CONFIANCE DANS `setup.exe` (revue terminale du 09/11/2026). `setup.exe` tourne
//! ÉLEVÉ. Un `tools/odt/setup.exe` déposé sur le portable (clé USB prêtée, autre PC)
//! serait donc exécuté avec les droits d'administrateur. CHOIX : on ne prend JAMAIS
//! celui du portable. L'ODT n'est cherché que sous `%ProgramFiles%` (et son pendant
//! x86), dossiers où seul un administrateur peut écrire ; absent, il est installé frais
//! par winget (`Microsoft.OfficeDeploymentTool`), dont le manifeste épingle le SHA-256
//! de l'installeur. Écarté : une vérification Authenticode (WinVerifyTrust + éditeur
//! « Microsoft Corporation ») d'un fichier du portable, car un binaire signé Microsoft
//! mais AUTRE que l'ODT (ancien, vulnérable) passerait, et ce code FFI n'est pas
//! éprouvable ici. Avant de l'exécuter, le `setup.exe` retenu est de plus COPIÉ dans le
//! dossier de travail privé (ACL utilisateur seul) et c'est la copie qui est lancée :
//! aucun remplacement possible entre la recherche et l'exécution.

use super::winget::{self, Status, Winget};
use crate::error::{CcpError, Result};
use crate::privdir::{self, PrivateDir};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Espace libre minimal sur le lecteur système avant de lancer l'installation.
pub const MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// L'ODT télécharge ~3 Go puis installe : généreux, mais borné.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(3 * 60 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edition {
    pub key: &'static str,
    /// Sans virgule (gum --selected sépare par virgule) ni tabulation.
    pub label: &'static str,
    pub product_id: &'static str,
    pub channel: &'static str,
}

pub const EDITIONS: &[Edition] = &[
    Edition {
        key: "365-apps",
        label: "Microsoft 365 Apps (abonnement)",
        product_id: "O365ProPlusRetail",
        channel: "Current",
    },
    Edition {
        key: "ltsc-2024",
        label: "Office LTSC 2024 Professionnel Plus (licence en volume - non activé)",
        product_id: "ProPlus2024Volume",
        channel: "PerpetualVL2024",
    },
    Edition {
        key: "ltsc-2021",
        label: "Office LTSC 2021 Professionnel Plus (licence en volume - non activé)",
        product_id: "ProPlus2021Volume",
        channel: "PerpetualVL2021",
    },
    Edition {
        key: "famille-pe-2024",
        label: "Office Famille et Petite Entreprise 2024 (achat unique)",
        product_id: "HomeBusiness2024Retail",
        channel: "Current",
    },
    Edition {
        key: "famille-2024",
        label: "Office Famille 2024 (achat unique)",
        product_id: "Home2024Retail",
        channel: "Current",
    },
    Edition {
        key: "proplus-2024-retail",
        label: "Office Professionnel Plus 2024 (achat unique)",
        product_id: "ProPlus2024Retail",
        channel: "Current",
    },
];

pub fn find_edition(key: &str) -> Result<&'static Edition> {
    EDITIONS.iter().find(|e| e.key == key).ok_or_else(|| {
        CcpError::Usage(format!(
            "édition Office inconnue : « {key} » (voir « win office --list »)"
        ))
    })
}

/// `clé<TAB>libellé`, une ligne par édition.
pub fn render_list() -> String {
    EDITIONS
        .iter()
        .map(|e| format!("{}\t{}\n", e.key, e.label))
        .collect()
}

/// Applications que le wizard peut décocher (`--apps`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum App {
    Word,
    Excel,
    PowerPoint,
    Outlook,
    OneNote,
    Access,
    Publisher,
    Teams,
    OneDrive,
}

pub const ALL_APPS: &[App] = &[
    App::Word,
    App::Excel,
    App::PowerPoint,
    App::Outlook,
    App::OneNote,
    App::Access,
    App::Publisher,
    App::Teams,
    App::OneDrive,
];

impl App {
    pub fn key(self) -> &'static str {
        match self {
            App::Word => "word",
            App::Excel => "excel",
            App::PowerPoint => "powerpoint",
            App::Outlook => "outlook",
            App::OneNote => "onenote",
            App::Access => "access",
            App::Publisher => "publisher",
            App::Teams => "teams",
            App::OneDrive => "onedrive",
        }
    }

    /// Identifiants `ExcludeApp` à émettre quand l'application est décochée.
    /// - Outlook : le classique ET le nouveau (`OutlookForWindows`) ;
    /// - OneDrive : la doc ODT précise « For OneDrive, use Groove » (ancien client de
    ///   synchronisation) tout en listant `OneDrive` : on exclut les deux.
    fn exclude_ids(self) -> &'static [&'static str] {
        match self {
            App::Word => &["Word"],
            App::Excel => &["Excel"],
            App::PowerPoint => &["PowerPoint"],
            App::Outlook => &["Outlook", "OutlookForWindows"],
            App::OneNote => &["OneNote"],
            App::Access => &["Access"],
            App::Publisher => &["Publisher"],
            App::Teams => &["Teams"],
            App::OneDrive => &["OneDrive", "Groove"],
        }
    }
}

/// `word,excel,…` → ensemble ; les inconnues sont toutes listées.
pub fn parse_apps(list: &str) -> Result<BTreeSet<App>> {
    let mut set = BTreeSet::new();
    let mut unknown = Vec::new();
    for raw in list.split(',') {
        let k = raw.trim().to_ascii_lowercase();
        if k.is_empty() {
            continue;
        }
        match ALL_APPS.iter().find(|a| a.key() == k) {
            Some(a) => {
                set.insert(*a);
            }
            None => unknown.push(k),
        }
    }
    if !unknown.is_empty() {
        return Err(CcpError::Usage(format!(
            "application(s) Office inconnue(s) : {} (valeurs : {})",
            unknown.join(", "),
            ALL_APPS
                .iter()
                .map(|a| a.key())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if set.is_empty() {
        return Err(CcpError::Usage(
            "--apps ne contient aucune application".into(),
        ));
    }
    Ok(set)
}

/// Langue ODT : `fr-fr`, `en-us`, `pt-br`, `zh-cn`, `sr-latn-rs`… ou `MatchOS`.
pub fn valid_lang(l: &str) -> bool {
    if l.eq_ignore_ascii_case("matchos") {
        return true;
    }
    let parts: Vec<&str> = l.split('-').collect();
    (2..=3).contains(&parts.len())
        && parts[0].len() >= 2
        && parts[0].len() <= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 8 && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            _ => o.push(c),
        }
    }
    o
}

/// `32` uniquement pour un Windows 32 bits natif ; un processus 32 bits sur un
/// Windows 64 bits (WOW64) voit `PROCESSOR_ARCHITEW6432` et reste en 64.
pub fn client_edition(arch: Option<&str>, arch_w6432: Option<&str>) -> &'static str {
    let native = arch_w6432.or(arch).unwrap_or("AMD64");
    if native.eq_ignore_ascii_case("x86") {
        "32"
    } else {
        "64"
    }
}

/// Le fichier `configuration.xml` de l'ODT. Document fixe et court : des chaînes
/// échappées plutôt qu'une crate XML (testé contre des fichiers de référence).
pub fn build_xml(edition: &Edition, lang: &str, apps: &BTreeSet<App>, bits: &str) -> String {
    let mut x = String::new();
    x.push_str("<Configuration>\n");
    x.push_str(&format!(
        "  <Add OfficeClientEdition=\"{}\" Channel=\"{}\">\n",
        xml_escape(bits),
        xml_escape(edition.channel)
    ));
    x.push_str(&format!(
        "    <Product ID=\"{}\">\n",
        xml_escape(edition.product_id)
    ));
    x.push_str(&format!("      <Language ID=\"{}\" />\n", xml_escape(lang)));
    // Ordre stable (celui de l'enum) pour que le fichier soit reproductible.
    for a in ALL_APPS {
        if !apps.contains(a) {
            for id in a.exclude_ids() {
                x.push_str(&format!("      <ExcludeApp ID=\"{}\" />\n", xml_escape(id)));
            }
        }
    }
    x.push_str("    </Product>\n");
    x.push_str("  </Add>\n");
    x.push_str("  <Property Name=\"AUTOACTIVATE\" Value=\"0\" />\n");
    x.push_str("  <Property Name=\"PinIconsToTaskbar\" Value=\"FALSE\" />\n");
    x.push_str("  <Display Level=\"None\" AcceptEULA=\"TRUE\" />\n");
    x.push_str("</Configuration>\n");
    x
}

// ------------------------------------------------------------------ installation

/// Tout ce que l'installation demande au système, derrière un trait : le déroulé
/// (espace disque, ODT absent, staging nettoyé même en échec) se teste sans Windows.
pub trait OfficeHost {
    fn free_bytes(&self, dir: &Path) -> std::io::Result<u64>;
    fn system_drive(&self) -> PathBuf;
    fn temp_dir(&self) -> PathBuf;
    /// `setup.exe` de l'ODT déjà présent dans un dossier réservé aux administrateurs
    /// (jamais sur le portable), s'il y en a un.
    fn find_setup(&self) -> Option<PathBuf>;
    /// Copie `setup.exe` dans le dossier de travail privé : c'est la COPIE qu'on exécute.
    fn stage_setup(&self, from: &Path, to: &Path) -> std::io::Result<()>;
    /// Installe l'ODT (winget `Microsoft.OfficeDeploymentTool`). `Err` = message.
    fn install_odt(&self) -> std::result::Result<(), String>;
    /// `setup.exe /configure <xml>` ; `None` = délai dépassé.
    fn run_setup(&self, setup: &Path, xml: &Path, cwd: &Path) -> std::io::Result<Option<i32>>;
    fn progress(&self, msg: &str);
}

#[derive(Debug, PartialEq, Eq)]
pub struct OfficeResult {
    pub ok: bool,
    pub detail: String,
}

impl OfficeResult {
    fn fail(detail: impl Into<String>) -> OfficeResult {
        OfficeResult {
            ok: false,
            detail: detail.into(),
        }
    }
    pub fn line(&self) -> String {
        format!(
            "{}\toffice\t{}",
            if self.ok { "ok" } else { "echec" },
            winget::one_line(&self.detail)
        )
    }
}

/// Préfixe des dossiers de travail d'`install` (balayés au démarrage s'ils sont orphelins).
pub const STAGING_PREFIX: &str = "ccp-odt-";

pub fn install(
    host: &dyn OfficeHost,
    edition: &Edition,
    lang: &str,
    apps: &BTreeSet<App>,
    bits: &str,
) -> OfficeResult {
    // 1. Espace disque AVANT tout téléchargement : l'ODT échoue tard et mal sinon.
    let drive = host.system_drive();
    match host.free_bytes(&drive) {
        Ok(free) if free < MIN_FREE_BYTES => {
            return OfficeResult::fail(format!(
                "espace disque insuffisant sur {} : {} Go libres, {} Go requis",
                drive.display(),
                free / (1024 * 1024 * 1024),
                MIN_FREE_BYTES / (1024 * 1024 * 1024)
            ))
        }
        Ok(_) => {}
        Err(e) => {
            return OfficeResult::fail(format!(
                "espace disque de {} illisible ({e}) : installation non lancée",
                drive.display()
            ))
        }
    }

    // 2. L'outil de déploiement : déjà là, sinon installé par winget.
    let setup = match host.find_setup() {
        Some(s) => s,
        None => {
            host.progress("Installation de l'Office Deployment Tool (winget)…");
            if let Err(m) = host.install_odt() {
                return OfficeResult::fail(format!("Office Deployment Tool : {m}"));
            }
            match host.find_setup() {
                Some(s) => s,
                None => {
                    return OfficeResult::fail(
                        "Office Deployment Tool installé mais setup.exe est introuvable",
                    )
                }
            }
        }
    };

    // 3. Dossier de travail PRIVÉ (ACL explicite) + configuration. Les restes d'une
    // installation tuée net (configuration, copie de setup.exe) sont balayés d'abord.
    let temp = host.temp_dir();
    let swept = privdir::sweep_orphans(&temp, STAGING_PREFIX);
    for (dir, why) in &swept.failed {
        host.progress(&format!(
            "Reste d'une installation précédente impossible à effacer : {} ({why})",
            dir.display()
        ));
    }
    let staging = match PrivateDir::create(&temp, STAGING_PREFIX) {
        Ok(s) => s,
        Err(e) => return OfficeResult::fail(format!("dossier temporaire impossible : {e}")),
    };
    let xml_path = staging.path.join("configuration.xml");
    if let Err(e) = std::fs::write(&xml_path, build_xml(edition, lang, apps, bits)) {
        return OfficeResult::fail(format!("configuration.xml impossible à écrire : {e}"));
    }
    // On n'exécute que la COPIE, posée dans un dossier où personne d'autre n'écrit.
    let local_setup = staging.path.join("setup.exe");
    if let Err(e) = host.stage_setup(&setup, &local_setup) {
        return OfficeResult::fail(format!(
            "setup.exe ({}) n'a pas pu être copié dans le dossier de travail : {e}",
            setup.display()
        ));
    }

    // 4. Installation. Le dossier de travail est effacé ensuite, succès ou non (Drop en
    // dernier recours, `finish` vérifie : un échec d'effacement se DIT).
    host.progress(&format!(
        "Installation de {} en cours (10 à 30 minutes, téléchargement compris)…",
        edition.label
    ));
    let mut result = match host.run_setup(&local_setup, &xml_path, &staging.path) {
        Ok(Some(0)) => OfficeResult {
            ok: true,
            detail: if edition.channel.starts_with("PerpetualVL") {
                format!(
                    "{} installé, non activé (licence en volume à saisir plus tard)",
                    edition.label
                )
            } else {
                format!(
                    "{} installé (connexion ou clé à saisir dans Office)",
                    edition.label
                )
            },
        },
        Ok(Some(code)) => OfficeResult::fail(format!(
            "setup.exe a échoué (code {code}) ; journaux dans le dossier %TEMP% de l'utilisateur"
        )),
        Ok(None) => OfficeResult::fail(format!(
            "setup.exe sans fin au bout de {} heures, abandonné",
            SETUP_TIMEOUT.as_secs() / 3600
        )),
        Err(e) => OfficeResult::fail(format!("setup.exe n'a pas pu être lancé : {e}")),
    };
    if let Err(why) = staging.finish() {
        result.detail = format!(
            "{} (ATTENTION : dossier de travail non effacé, {why} ; il sera retiré à la prochaine installation)",
            result.detail
        );
    }
    result
}

// ------------------------------------------------------------------ hôte réel

pub struct RealHost<'a> {
    pub env: &'a crate::env::Env,
    pub winget: &'a dyn Winget,
}

/// Dossiers où `setup.exe` de l'ODT est cherché : RÉSERVÉS aux administrateurs.
///
/// Sous Windows ils sont déduits du dossier Windows rendu par l'API (pas des variables
/// d'environnement `ProgramFiles*`, qu'un utilisateur peut redéfinir pour faire exécuter
/// SON binaire à un processus élevé). Hors Windows (bancs d'essai), les variables font foi.
#[cfg(windows)]
fn trusted_install_dirs() -> Vec<PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 260];
    // SAFETY : tampon de 260 caractères, taille passée à l'appel.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n < 3 || n > buf.len() {
        return vec![];
    }
    let win = String::from_utf16_lossy(&buf[..n]);
    // « C:\Windows » -> « C:\ »
    let drive = win.get(..3).unwrap_or("C:\\").to_string();
    ["Program Files", "Program Files (x86)"]
        .iter()
        .map(|d| PathBuf::from(format!("{drive}{d}")))
        .collect()
}

#[cfg(not(windows))]
fn trusted_install_dirs() -> Vec<PathBuf> {
    ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|v| std::env::var_os(v).map(PathBuf::from))
        .collect()
}

/// Candidats pour `setup.exe`. Le portable n'en fait JAMAIS partie : la fonction ne
/// reçoit même pas sa racine. `odt_override` (`CCP_ODT_SETUP`, bancs d'essai) est ignoré
/// sous Windows : une variable d'environnement ne désigne pas ce qu'un processus élevé exécute.
pub fn setup_candidates(odt_override: Option<&str>, program_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(not(windows))]
    if let Some(p) = odt_override {
        v.push(PathBuf::from(p));
    }
    #[cfg(windows)]
    let _ = odt_override;
    for pf in program_dirs {
        v.push(pf.join("OfficeDeploymentTool").join("setup.exe"));
    }
    v
}

impl RealHost<'_> {
    fn setup_candidates(&self) -> Vec<PathBuf> {
        setup_candidates(self.env.ovr.odt_setup.as_deref(), &trusted_install_dirs())
    }
}

impl OfficeHost for RealHost<'_> {
    fn free_bytes(&self, dir: &Path) -> std::io::Result<u64> {
        free_bytes(dir)
    }
    fn system_drive(&self) -> PathBuf {
        let d = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        PathBuf::from(format!("{}\\", d.trim_end_matches(['\\', '/'])))
    }
    fn temp_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }
    fn find_setup(&self) -> Option<PathBuf> {
        self.setup_candidates().into_iter().find(|p| p.is_file())
    }
    fn stage_setup(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        // `create_new` : jamais par-dessus un fichier qui existerait déjà dans le dossier.
        let mut src = std::fs::File::open(from)?;
        let mut dst = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(to)?;
        std::io::copy(&mut src, &mut dst)?;
        dst.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    fn install_odt(&self) -> std::result::Result<(), String> {
        let app = super::catalog::App {
            key: "odt".into(),
            label: "Office Deployment Tool".into(),
            category: "Office".into(),
            winget: "Microsoft.OfficeDeploymentTool".into(),
            default: false,
        };
        let r = winget::install_one(self.winget, &app, false);
        match r.status {
            Status::Ok | Status::Already => Ok(()),
            Status::Failed => Err(r.detail),
        }
    }
    fn run_setup(&self, setup: &Path, xml: &Path, cwd: &Path) -> std::io::Result<Option<i32>> {
        let mut cmd = std::process::Command::new(setup);
        cmd.arg("/configure").arg(xml).current_dir(cwd);
        let out = crate::util::run_bounded(&mut cmd, None, SETUP_TIMEOUT)?;
        Ok(out.code())
    }
    fn progress(&self, msg: &str) {
        eprintln!("{msg}");
    }
}

#[cfg(windows)]
fn free_bytes(dir: &Path) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut avail = 0u64;
    // SAFETY : `wide` est terminé par un zéro et vit pendant l'appel ; les autres
    // sorties sont facultatives (pointeurs nuls).
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut avail,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(avail)
    }
}

/// Hôte de test simulé (`CCP_FAKE_WINDOWS`) : `CCP_FAKE_FREE_BYTES` fixe l'espace libre.
#[cfg(not(windows))]
fn free_bytes(_dir: &Path) -> std::io::Result<u64> {
    Ok(std::env::var("CCP_FAKE_FREE_BYTES")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn all_apps() -> BTreeSet<App> {
        ALL_APPS.iter().copied().collect()
    }

    fn only(list: &[App]) -> BTreeSet<App> {
        list.iter().copied().collect()
    }

    // Fichiers de référence : le XML exact, relu par un humain, pour chaque édition.
    // Régénération volontaire : CCP_UPDATE_GOLDEN=1 cargo test office_golden
    fn golden(name: &str) -> (&'static str, PathBuf) {
        let text = match name {
            "365-apps" => include_str!("../../tests/golden/office/365-apps.xml"),
            "ltsc-2024" => include_str!("../../tests/golden/office/ltsc-2024.xml"),
            "ltsc-2021" => include_str!("../../tests/golden/office/ltsc-2021.xml"),
            "famille-pe-2024" => include_str!("../../tests/golden/office/famille-pe-2024.xml"),
            "famille-2024" => include_str!("../../tests/golden/office/famille-2024.xml"),
            "proplus-2024-retail" => {
                include_str!("../../tests/golden/office/proplus-2024-retail.xml")
            }
            other => panic!("pas de fichier de référence pour {other}"),
        };
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/golden/office")
            .join(format!("{name}.xml"));
        (text, path)
    }

    #[test]
    fn office_golden_xml_for_every_edition() {
        let apps = only(&[
            App::Word,
            App::Excel,
            App::PowerPoint,
            App::Outlook,
            App::OneNote,
        ]);
        for e in EDITIONS {
            let xml = build_xml(e, "fr-fr", &apps, "64");
            let (expected, path) = golden(e.key);
            if std::env::var("CCP_UPDATE_GOLDEN").is_ok() {
                std::fs::write(&path, &xml).unwrap();
                continue;
            }
            assert_eq!(xml, expected, "édition {}", e.key);
        }
    }

    #[test]
    fn xml_has_the_mandatory_properties_and_no_key() {
        let xml = build_xml(&EDITIONS[0], "fr-fr", &all_apps(), "64");
        assert!(xml.contains("<Display Level=\"None\" AcceptEULA=\"TRUE\" />"));
        assert!(xml.contains("<Property Name=\"AUTOACTIVATE\" Value=\"0\" />"));
        assert!(!xml.contains("PIDKEY"), "aucune clé ne doit être posée");
        assert!(
            !xml.contains("ExcludeApp"),
            "toutes les apps cochées : aucune exclusion"
        );
        assert!(xml.contains("<Language ID=\"fr-fr\" />"));
    }

    #[test]
    fn unchecked_apps_become_excludeapp_in_stable_order() {
        let xml = build_xml(&EDITIONS[0], "fr-fr", &only(&[App::Word]), "64");
        let ids: Vec<&str> = xml
            .lines()
            .filter_map(|l| l.trim().strip_prefix("<ExcludeApp ID=\""))
            .map(|l| l.split('"').next().unwrap())
            .collect();
        // Excel, PowerPoint, Outlook(+nouveau), OneNote, Access, Publisher, Teams, OneDrive(+Groove)
        assert_eq!(
            ids,
            [
                "Excel",
                "PowerPoint",
                "Outlook",
                "OutlookForWindows",
                "OneNote",
                "Access",
                "Publisher",
                "Teams",
                "OneDrive",
                "Groove"
            ]
        );
        // Tous les identifiants émis appartiennent à la liste officielle de la doc ODT.
        let official = [
            "Access",
            "Excel",
            "Groove",
            "Lync",
            "OneDrive",
            "OneNote",
            "Outlook",
            "OutlookForWindows",
            "PowerPoint",
            "Publisher",
            "Teams",
            "Word",
        ];
        for id in ids {
            assert!(official.contains(&id), "{id} hors de la doc ODT");
        }
    }

    #[test]
    fn product_ids_and_channels_match_the_documented_pairs() {
        let pairs: Vec<(&str, &str, &str)> = EDITIONS
            .iter()
            .map(|e| (e.key, e.product_id, e.channel))
            .collect();
        assert_eq!(
            pairs,
            [
                ("365-apps", "O365ProPlusRetail", "Current"),
                ("ltsc-2024", "ProPlus2024Volume", "PerpetualVL2024"),
                ("ltsc-2021", "ProPlus2021Volume", "PerpetualVL2021"),
                ("famille-pe-2024", "HomeBusiness2024Retail", "Current"),
                ("famille-2024", "Home2024Retail", "Current"),
                ("proplus-2024-retail", "ProPlus2024Retail", "Current"),
            ]
        );
    }

    #[test]
    fn list_labels_are_gum_safe_and_volume_ones_say_not_activated() {
        for l in render_list().lines() {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 2, "{l}");
            assert!(!f[1].contains(','), "virgule dans « {} »", f[1]);
        }
        for e in EDITIONS {
            assert_eq!(
                e.channel.starts_with("PerpetualVL"),
                e.label.contains("non activé"),
                "{}",
                e.key
            );
        }
    }

    #[test]
    fn apps_and_lang_are_validated() {
        let s = parse_apps("Word, excel,ONENOTE").unwrap();
        assert_eq!(s, only(&[App::Word, App::Excel, App::OneNote]));
        let e = parse_apps("word,wrod,visio").unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().contains("wrod") && e.to_string().contains("visio"));
        assert!(parse_apps(" , ").is_err());
        for ok in ["fr-fr", "en-us", "pt-br", "zh-cn", "sr-latn-rs", "MatchOS"] {
            assert!(valid_lang(ok), "{ok}");
        }
        for bad in [
            "fr",
            "fr_fr",
            "\"><x/>",
            "",
            "fr-fr-aa-bb",
            "francais-france",
        ] {
            assert!(!valid_lang(bad), "{bad:?}");
        }
    }

    #[test]
    fn xml_text_is_escaped() {
        let x = build_xml(&EDITIONS[0], "a&b<c", &all_apps(), "6\"4");
        assert!(x.contains("a&amp;b&lt;c") && x.contains("6&quot;4"));
    }

    #[test]
    fn client_edition_is_32_only_on_native_x86() {
        assert_eq!(client_edition(Some("AMD64"), None), "64");
        assert_eq!(client_edition(Some("ARM64"), None), "64");
        assert_eq!(client_edition(Some("x86"), None), "32");
        assert_eq!(client_edition(Some("x86"), Some("AMD64")), "64");
        assert_eq!(client_edition(None, None), "64");
    }

    // ---- déroulé avec un hôte simulé

    type SetupHook = Box<dyn Fn(&Path)>;

    struct FakeHost {
        free: u64,
        temp: PathBuf,
        setup_present: Cell<bool>,
        odt_install: std::result::Result<(), String>,
        setup_exit: Option<i32>,
        ran: Cell<u32>,
        odt_installs: Cell<u32>,
        xml_seen: RefCell<String>,
        staging_seen: RefCell<Option<PathBuf>>,
        setup_run: RefCell<Option<PathBuf>>,
        stage_fails: Cell<bool>,
        /// Appelé dans le dossier de travail pendant « setup.exe » (effet de bord de test).
        during_setup: RefCell<Option<SetupHook>>,
    }

    impl FakeHost {
        fn new(temp: &Path) -> FakeHost {
            FakeHost {
                free: 50 * 1024 * 1024 * 1024,
                temp: temp.to_path_buf(),
                setup_present: Cell::new(true),
                odt_install: Ok(()),
                setup_exit: Some(0),
                ran: Cell::new(0),
                odt_installs: Cell::new(0),
                xml_seen: RefCell::new(String::new()),
                staging_seen: RefCell::new(None),
                setup_run: RefCell::new(None),
                stage_fails: Cell::new(false),
                during_setup: RefCell::new(None),
            }
        }
    }

    impl OfficeHost for FakeHost {
        fn free_bytes(&self, _d: &Path) -> std::io::Result<u64> {
            Ok(self.free)
        }
        fn system_drive(&self) -> PathBuf {
            PathBuf::from("C:\\")
        }
        fn temp_dir(&self) -> PathBuf {
            self.temp.clone()
        }
        fn find_setup(&self) -> Option<PathBuf> {
            self.setup_present.get().then(|| PathBuf::from("setup.exe"))
        }
        fn stage_setup(&self, _from: &Path, to: &Path) -> std::io::Result<()> {
            if self.stage_fails.get() {
                return Err(std::io::Error::other("copie refusée"));
            }
            std::fs::write(to, b"copie-de-setup")
        }
        fn install_odt(&self) -> std::result::Result<(), String> {
            self.odt_installs.set(self.odt_installs.get() + 1);
            if self.odt_install.is_ok() {
                self.setup_present.set(true);
            }
            self.odt_install.clone()
        }
        fn run_setup(&self, s: &Path, xml: &Path, cwd: &Path) -> std::io::Result<Option<i32>> {
            self.ran.set(self.ran.get() + 1);
            *self.xml_seen.borrow_mut() = std::fs::read_to_string(xml).unwrap();
            *self.staging_seen.borrow_mut() = Some(cwd.to_path_buf());
            *self.setup_run.borrow_mut() = Some(s.to_path_buf());
            assert!(cwd.is_dir(), "le staging doit exister pendant setup.exe");
            if let Some(f) = self.during_setup.borrow().as_ref() {
                f(cwd);
            }
            Ok(self.setup_exit)
        }
        fn progress(&self, _m: &str) {}
    }

    fn leftovers(temp: &Path) -> usize {
        std::fs::read_dir(temp).unwrap().count()
    }

    #[test]
    fn success_installs_cleans_staging_and_reports_not_activated_for_volume() {
        let t = tempfile::tempdir().unwrap();
        let h = FakeHost::new(t.path());
        let ltsc = find_edition("ltsc-2024").unwrap();
        let r = install(&h, ltsc, "fr-fr", &all_apps(), "64");
        assert!(r.ok, "{r:?}");
        assert!(r.detail.contains("non activé"), "{}", r.detail);
        assert!(h.xml_seen.borrow().contains("PerpetualVL2024"));
        assert_eq!(leftovers(t.path()), 0, "staging non effacé");
        assert!(r.line().starts_with("ok\toffice\t"));
    }

    #[test]
    fn failure_still_cleans_staging() {
        let t = tempfile::tempdir().unwrap();
        let mut h = FakeHost::new(t.path());
        h.setup_exit = Some(17002);
        let r = install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64");
        assert!(!r.ok);
        assert!(r.detail.contains("17002"));
        assert!(r.line().starts_with("echec\toffice\t"));
        assert_eq!(leftovers(t.path()), 0);
        let mut h = FakeHost::new(t.path());
        h.setup_exit = None;
        assert!(!install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64").ok);
        assert_eq!(leftovers(t.path()), 0);
    }

    #[test]
    fn low_disk_space_refuses_before_downloading_anything() {
        let t = tempfile::tempdir().unwrap();
        let mut h = FakeHost::new(t.path());
        h.free = MIN_FREE_BYTES - 1;
        let r = install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64");
        assert!(!r.ok);
        assert!(
            r.detail.contains("espace disque insuffisant"),
            "{}",
            r.detail
        );
        assert_eq!(h.ran.get(), 0);
        assert_eq!(h.odt_installs.get(), 0);
        assert_eq!(leftovers(t.path()), 0);
        // Pile 5 Go : accepté.
        h.free = MIN_FREE_BYTES;
        assert!(install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64").ok);
    }

    #[test]
    fn missing_odt_is_installed_through_winget_once() {
        let t = tempfile::tempdir().unwrap();
        let h = FakeHost::new(t.path());
        h.setup_present.set(false);
        assert!(install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64").ok);
        assert_eq!(h.odt_installs.get(), 1);
    }

    #[test]
    fn odt_install_failure_is_reported_and_nothing_runs() {
        let t = tempfile::tempdir().unwrap();
        let mut h = FakeHost::new(t.path());
        h.setup_present.set(false);
        h.odt_install = Err("droits administrateur requis".into());
        let r = install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64");
        assert!(!r.ok);
        assert!(r.detail.contains("Office Deployment Tool"));
        assert_eq!(h.ran.get(), 0);
    }

    #[test]
    fn unreadable_free_space_refuses_rather_than_guessing() {
        struct NoStat(FakeHost);
        impl OfficeHost for NoStat {
            fn free_bytes(&self, _d: &Path) -> std::io::Result<u64> {
                Err(std::io::Error::other("illisible"))
            }
            fn system_drive(&self) -> PathBuf {
                self.0.system_drive()
            }
            fn temp_dir(&self) -> PathBuf {
                self.0.temp_dir()
            }
            fn find_setup(&self) -> Option<PathBuf> {
                self.0.find_setup()
            }
            fn stage_setup(&self, f: &Path, t: &Path) -> std::io::Result<()> {
                self.0.stage_setup(f, t)
            }
            fn install_odt(&self) -> std::result::Result<(), String> {
                self.0.install_odt()
            }
            fn run_setup(&self, s: &Path, x: &Path, c: &Path) -> std::io::Result<Option<i32>> {
                self.0.run_setup(s, x, c)
            }
            fn progress(&self, m: &str) {
                self.0.progress(m)
            }
        }
        let t = tempfile::tempdir().unwrap();
        let h = NoStat(FakeHost::new(t.path()));
        let r = install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64");
        assert!(!r.ok);
        assert_eq!(h.0.ran.get(), 0);
    }

    #[test]
    fn the_portable_is_never_a_place_to_look_for_setup_exe() {
        let t = tempfile::tempdir().unwrap();
        // Un setup.exe PIÉGÉ déposé sur le portable.
        let planted = t.path().join("tools/odt/setup.exe");
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, b"PIEGE").unwrap();
        let pf = vec![PathBuf::from("/pf"), PathBuf::from("/pf86")];
        let c = setup_candidates(None, &pf);
        assert_eq!(
            c,
            vec![
                PathBuf::from("/pf/OfficeDeploymentTool/setup.exe"),
                PathBuf::from("/pf86/OfficeDeploymentTool/setup.exe")
            ]
        );
        assert!(!c.contains(&planted));
        // Le même constat sur l'hôte réel, racine du portable comprise.
        let env = crate::env::Env::for_tests(t.path().to_path_buf());
        struct NoWinget;
        impl Winget for NoWinget {
            fn run(
                &self,
                _a: &[String],
                _t: Duration,
            ) -> std::io::Result<crate::win::winget::RunOut> {
                Err(std::io::Error::other("pas de winget"))
            }
        }
        let host = RealHost {
            env: &env,
            winget: &NoWinget,
        };
        assert!(!host.setup_candidates().contains(&planted));
    }

    #[cfg(not(windows))]
    #[test]
    fn the_test_override_is_honoured_off_windows_only() {
        // (Sous Windows la variable est ignorée : voir `setup_candidates`.)
        let c = setup_candidates(Some("/banc/setup.exe"), &[]);
        assert_eq!(c, vec![PathBuf::from("/banc/setup.exe")]);
    }

    #[test]
    fn what_runs_is_the_copy_in_the_private_staging_never_the_original() {
        let t = tempfile::tempdir().unwrap();
        let h = FakeHost::new(t.path());
        assert!(install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64").ok);
        let run = h.setup_run.borrow().clone().unwrap();
        let staging = h.staging_seen.borrow().clone().unwrap();
        assert_ne!(
            run,
            PathBuf::from("setup.exe"),
            "l'original n'est pas lancé"
        );
        assert_eq!(run, staging.join("setup.exe"));
        assert!(staging
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("ccp-odt-"));
    }

    #[test]
    fn a_setup_that_cannot_be_copied_is_not_run() {
        let t = tempfile::tempdir().unwrap();
        let h = FakeHost::new(t.path());
        h.stage_fails.set(true);
        let r = install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64");
        assert!(!r.ok);
        assert!(r.detail.contains("copié"), "{}", r.detail);
        assert_eq!(h.ran.get(), 0);
        assert_eq!(leftovers(t.path()), 0);
    }

    #[test]
    fn orphan_staging_of_a_killed_install_is_swept_before_a_new_one() {
        let t = tempfile::tempdir().unwrap();
        let orphan = t.path().join("ccp-odt-mort-1-0");
        std::fs::create_dir(&orphan).unwrap();
        std::fs::write(orphan.join(".ccp-lock"), "").unwrap();
        std::fs::write(orphan.join("setup.exe"), "copie oubliée").unwrap();
        let h = FakeHost::new(t.path());
        assert!(install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64").ok);
        assert!(!orphan.exists());
        assert_eq!(leftovers(t.path()), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_cleanup_failure_is_reported_in_the_result_not_swallowed() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let h = FakeHost::new(t.path());
        *h.during_setup.borrow_mut() = Some(Box::new(|cwd: &Path| {
            let d = cwd.join("verrouille");
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join("x"), "x").unwrap();
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o500)).unwrap();
        }));
        let r = install(&h, &EDITIONS[0], "fr-fr", &all_apps(), "64");
        assert!(r.ok, "l'installation a réussi : {r:?}");
        assert!(r.detail.contains("non effacé"), "{}", r.detail);
        // Nettoyage du test lui-même.
        let left = h.staging_seen.borrow().clone().unwrap();
        std::fs::set_permissions(
            left.join("verrouille"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::remove_dir_all(left).unwrap();
    }
}
