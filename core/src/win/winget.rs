//! Installation de logiciels par winget : arguments, codes de sortie, résultats.
//!
//! Sortie par paquet sur stdout (contrat avec le wizard) :
//! `ok|deja|echec<TAB>clé<TAB>détail`, une ligne, jamais de tabulation dans le détail.

use super::catalog::App;
use std::time::Duration;

/// Durée maximale d'un paquet. Un installateur qui attend une fenêtre cachée ne
/// doit pas figer le lot entier ; 30 minutes couvrent les plus gros (.NET, Java).
pub const INSTALL_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const VERSION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// Déjà présent : c'est un succès pour le wizard.
    Already,
    Failed,
}

impl Status {
    pub fn word(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Already => "deja",
            Status::Failed => "echec",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageResult {
    pub key: String,
    pub status: Status,
    pub detail: String,
}

impl PackageResult {
    /// La ligne exacte attendue par le wizard.
    pub fn line(&self) -> String {
        format!(
            "{}\t{}\t{}",
            self.status.word(),
            self.key,
            one_line(&self.detail)
        )
    }
}

/// Une ligne, sans tabulation : le format est séparé par des tabulations.
pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Interprétation d'un code de sortie de `winget install`.
///
/// Source des valeurs : microsoft/winget-cli, `doc/windows/package-manager/winget/returnCodes.md`
/// (généré par `winget error --output`, version du 13/05/2026). Les codes sont des
/// HRESULT ; le processus les renvoie en entier signé 32 bits, d'où la comparaison en
/// `u32` ci-dessous.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classified {
    pub status: Status,
    pub detail: String,
}

pub fn classify_exit(code: i32) -> Classified {
    let c = code as u32;
    let (status, msg): (Status, &str) = match c {
        0 => (Status::Ok, "installé"),
        // PACKAGE_ALREADY_INSTALLED : « Found at least one version of the package installed ».
        0x8A15_0061 => (Status::Already, "déjà installé"),
        // UPDATE_NOT_APPLICABLE : « No applicable update found » (déjà à jour).
        0x8A15_002B => (Status::Already, "déjà à jour"),
        // INSTALL_ALREADY_INSTALLED / INSTALL_DOWNGRADE : remontés par l'installateur lui-même.
        0x8A15_010D => (Status::Already, "une autre version est déjà installée"),
        0x8A15_010E => (
            Status::Already,
            "une version plus récente est déjà installée",
        ),
        // Installé mais le système doit redémarrer : le paquet EST là. 3010 et 1641 sont les
        // codes Windows Installer équivalents (ERROR_SUCCESS_REBOOT_REQUIRED / REBOOT_INITIATED).
        0x8A15_0109 | 3010 => (Status::Ok, "installé, redémarrage requis pour finir"),
        0x8A15_010B | 1641 => (Status::Ok, "installé, redémarrage en cours"),
        0x8A15_0010 => (Status::Failed, "aucun installateur adapté à cet ordinateur"),
        0x8A15_0011 => (
            Status::Failed,
            "empreinte de l'installateur invalide (téléchargement corrompu ?)",
        ),
        0x8A15_0017 => (Status::Failed, "paquet introuvable dans la source winget"),
        0x8A15_0019 => (Status::Failed, "droits administrateur requis"),
        0x8A15_003A | 0x8A15_010F => (Status::Failed, "bloqué par une stratégie de l'organisation"),
        0x8A15_0008 | 0x8A15_0086 => (
            Status::Failed,
            "téléchargement de l'installateur échoué (réseau ?)",
        ),
        0x8A15_0107 => (
            Status::Failed,
            "connexion Internet requise par l'installateur",
        ),
        0x8A15_0105 => (Status::Failed, "disque plein"),
        0x8A15_0101 | 0x8A15_0103 | 0x8A15_0111 => (
            Status::Failed,
            "l'application est en cours d'utilisation : ferme-la puis recommence",
        ),
        0x8A15_0102 => (
            Status::Failed,
            "une autre installation est en cours : recommence plus tard",
        ),
        0x8A15_0104 | 0x8A15_0110 => (Status::Failed, "dépendance manquante"),
        0x8A15_010A => (Status::Failed, "redémarre l'ordinateur puis recommence"),
        0x8A15_010C => (Status::Failed, "installation annulée"),
        0x8A15_0045 | 0x8A15_0015 | 0x8A15_000F => {
            (Status::Failed, "source winget inaccessible (réseau ?)")
        }
        0x8A15_0041 | 0x8A15_0046 => (Status::Failed, "conditions d'utilisation non acceptées"),
        0x8A15_0113 => (Status::Failed, "paquet non pris en charge par ce système"),
        _ => {
            return Classified {
                status: Status::Failed,
                detail: format!("échec (code winget 0x{c:08X})"),
            }
        }
    };
    Classified {
        status,
        detail: msg.to_string(),
    }
}

/// Arguments de `winget install` (golden test : l'ordre est figé).
pub fn install_args(id: &str, user_scope: bool) -> Vec<String> {
    let mut a: Vec<String> = [
        "install",
        "--id",
        id,
        "-e",
        "--silent",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
        "--source",
        "winget",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if user_scope {
        a.push("--scope".into());
        a.push("user".into());
    }
    a
}

/// Résultat brut d'une exécution de winget.
pub struct RunOut {
    /// `None` : tué faute de fin dans le délai.
    pub code: Option<i32>,
    pub text: String,
}

/// Exécuteur de winget derrière un trait : les arguments, les codes et les
/// verdicts se testent sans Windows.
pub trait Winget {
    fn run(&self, args: &[String], timeout: Duration) -> std::io::Result<RunOut>;
}

/// Lignes de progression de winget (barres, spinner, tailles) : du bruit pour un détail.
fn is_progress_noise(line: &str) -> bool {
    if line.is_empty() {
        return true;
    }
    if line.chars().any(|c| matches!(c, '█' | '▒' | '▓' | '░')) {
        return true;
    }
    // Spinner : un seul caractère parmi - \ | /
    if line.chars().count() <= 2
        && line
            .chars()
            .all(|c| matches!(c, '-' | '\\' | '|' | '/' | ' '))
    {
        return true;
    }
    // « 12.3 MB / 40.0 MB » ou « 85% »
    let l = line.trim();
    if l.ends_with('%') && l[..l.len() - 1].trim().parse::<f64>().is_ok() {
        return true;
    }
    l.contains(" MB / ") || l.contains(" KB / ") || l.contains(" GB / ")
}

/// Les deux dernières lignes utiles de la sortie de winget, en une ligne.
pub fn summarize_output(text: &str) -> String {
    let lines: Vec<String> = text
        .split(['\r', '\n'])
        .map(|l| {
            l.chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .collect::<String>()
                .trim()
                .to_string()
        })
        .filter(|l| !is_progress_noise(l))
        .collect();
    let tail: Vec<&str> = lines
        .iter()
        .rev()
        .take(2)
        .rev()
        .map(String::as_str)
        .collect();
    let joined = one_line(&tail.join(" / "));
    let mut out: String = joined.chars().take(200).collect();
    if joined.chars().count() > 200 {
        out.push('…');
    }
    out
}

/// Installe UN paquet. En mode utilisateur (`user_scope`), un paquet sans
/// installateur « par utilisateur » n'est pas tenté en machine : une invite UAC au
/// milieu d'un lot, sans que personne la voie, ferait croire à un blocage.
pub fn install_one(w: &dyn Winget, app: &App, user_scope: bool) -> PackageResult {
    let args = install_args(&app.winget, user_scope);
    let res = match w.run(&args, INSTALL_TIMEOUT) {
        Ok(r) => r,
        Err(e) => {
            return PackageResult {
                key: app.key.clone(),
                status: Status::Failed,
                detail: format!("winget n'a pas pu être lancé : {e}"),
            }
        }
    };
    let Some(code) = res.code else {
        return PackageResult {
            key: app.key.clone(),
            status: Status::Failed,
            detail: format!(
                "pas de fin au bout de {} minutes, abandonné",
                INSTALL_TIMEOUT.as_secs() / 60
            ),
        };
    };
    let mut c = classify_exit(code);
    if user_scope && (code as u32) == 0x8A15_0010 {
        c.detail =
            "installation pour tous les utilisateurs uniquement : relance en acceptant l'élévation administrateur".into();
    }
    if c.status == Status::Failed {
        let tail = summarize_output(&res.text);
        if !tail.is_empty() {
            c.detail = format!("{} — {tail}", c.detail);
        }
    }
    PackageResult {
        key: app.key.clone(),
        status: c.status,
        detail: c.detail,
    }
}

/// Vrai winget : `winget` du PATH (alias d'exécution de l'App Installer) ou le
/// binaire donné par `CCP_WINGET_BIN`.
pub struct RealWinget {
    bin: std::ffi::OsString,
}

impl RealWinget {
    pub fn new(bin: Option<&str>) -> RealWinget {
        RealWinget {
            bin: bin.unwrap_or("winget").into(),
        }
    }

    /// Winget répond-il ? `None` = introuvable ; `Some(version)` sinon.
    pub fn probe(&self) -> Option<String> {
        let w: &dyn Winget = self;
        match w.run(&["--version".to_string()], VERSION_TIMEOUT) {
            Ok(RunOut {
                code: Some(0),
                text,
            }) => Some(one_line(&text)),
            _ => None,
        }
    }
}

impl Winget for RealWinget {
    fn run(&self, args: &[String], timeout: Duration) -> std::io::Result<RunOut> {
        let mut cmd = std::process::Command::new(&self.bin);
        cmd.args(args);
        let out = crate::util::run_bounded(&mut cmd, None, timeout)?;
        // winget écrit sur stdout ; stderr porte rarement plus qu'une erreur de lancement.
        let mut text = out.stdout_str();
        let err = out.stderr_str();
        if !err.trim().is_empty() {
            text.push('\n');
            text.push_str(&err);
        }
        Ok(RunOut {
            code: out.code(),
            text,
        })
    }
}

pub const WINGET_MISSING: &str =
    "winget est introuvable sur cet ordinateur. Installe « Programme d'installation \
d'application » (App Installer) depuis le Microsoft Store, puis relance. \
(Windows LTSC et Windows Server n'ont pas winget d'origine.)";

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn app(key: &str, id: &str) -> App {
        App {
            key: key.into(),
            label: key.into(),
            category: "t".into(),
            winget: id.into(),
            default: false,
        }
    }

    struct Fake {
        replies: RefCell<Vec<std::io::Result<RunOut>>>,
        seen: RefCell<Vec<Vec<String>>>,
    }
    impl Fake {
        fn new(replies: Vec<std::io::Result<RunOut>>) -> Fake {
            Fake {
                replies: RefCell::new(replies),
                seen: RefCell::new(Vec::new()),
            }
        }
    }
    impl Winget for Fake {
        fn run(&self, args: &[String], _t: Duration) -> std::io::Result<RunOut> {
            self.seen.borrow_mut().push(args.to_vec());
            self.replies.borrow_mut().remove(0)
        }
    }

    fn out(code: i32, text: &str) -> std::io::Result<RunOut> {
        Ok(RunOut {
            code: Some(code),
            text: text.into(),
        })
    }

    #[test]
    fn args_are_exactly_the_documented_ones() {
        assert_eq!(
            install_args("Google.Chrome", false),
            [
                "install",
                "--id",
                "Google.Chrome",
                "-e",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--disable-interactivity",
                "--source",
                "winget"
            ]
        );
        let u = install_args("Mozilla.Firefox", true);
        assert_eq!(&u[u.len() - 2..], ["--scope", "user"]);
    }

    #[test]
    fn exit_codes_are_tabulated_from_the_official_table() {
        // Valeurs en décimal signé, telles que le processus les renvoie.
        assert_eq!(classify_exit(0).status, Status::Ok);
        assert_eq!(classify_exit(-1978335135).status, Status::Already); // 0x8A150061
        assert_eq!(classify_exit(-1978335189).status, Status::Already); // 0x8A15002B
        assert_eq!(classify_exit(-1978334963).status, Status::Already); // 0x8A15010D
        assert_eq!(classify_exit(-1978334962).status, Status::Already); // 0x8A15010E
        let reboot = classify_exit(-1978334967); // 0x8A150109
        assert_eq!(reboot.status, Status::Ok);
        assert!(reboot.detail.contains("redémarrage"));
        assert_eq!(classify_exit(3010).status, Status::Ok);
        assert_eq!(classify_exit(1641).status, Status::Ok);
        for failing in [
            -1978335216, // NO_APPLICABLE_INSTALLER
            -1978335215, // INSTALLER_HASH_MISMATCH
            -1978335209, // NO_MANIFEST_FOUND
            -1978334971, // INSTALL_DISK_FULL
            1603,        // erreur fatale MSI
            -1,
        ] {
            assert_eq!(classify_exit(failing).status, Status::Failed, "{failing}");
        }
        let unknown = classify_exit(-1978335231);
        assert!(unknown.detail.contains("0x8A150001"), "{}", unknown.detail);
    }

    #[test]
    fn result_line_has_three_tab_separated_fields_and_no_tab_in_detail() {
        let r = PackageResult {
            key: "chrome".into(),
            status: Status::Failed,
            detail: "a\tb\nc".into(),
        };
        let l = r.line();
        assert_eq!(l, "echec\tchrome\ta b c");
        assert_eq!(l.matches('\t').count(), 2);
    }

    #[test]
    fn summarize_keeps_the_last_meaningful_lines_and_drops_progress() {
        let raw = "Found Google Chrome [Google.Chrome] Version 130\r\n\
                   Downloading https://dl.google.com/x.exe\r\n\
                   \u{2588}\u{2588}\u{2588}\u{2588}\u{2592}\u{2592}  1.20 MB / 4.00 MB\r\n\
                   - \r\n\
                   \\ \r\n\
                   100%\r\n\
                   Successfully verified installer hash\r\n\
                   Starting package install...\r\n\
                   Installer failed with exit code: 1603\r\n";
        assert_eq!(
            summarize_output(raw),
            "Starting package install... / Installer failed with exit code: 1603"
        );
        assert_eq!(summarize_output("\r\n  \r\n"), "");
        let long = "x".repeat(500);
        let s = summarize_output(&long);
        assert!(s.chars().count() <= 201 && s.ends_with('…'));
    }

    #[test]
    fn install_one_maps_success_already_and_failure() {
        let w = Fake::new(vec![
            out(0, "Successfully installed"),
            out(-1978335135, "Found an existing package already installed."),
            out(
                1603,
                "Starting package install...\nInstaller failed with exit code: 1603",
            ),
        ]);
        let a = app("chrome", "Google.Chrome");
        assert_eq!(install_one(&w, &a, false).status, Status::Ok);
        let d = install_one(&w, &a, false);
        assert_eq!(d.status, Status::Already);
        assert_eq!(d.detail, "déjà installé");
        let f = install_one(&w, &a, false);
        assert_eq!(f.status, Status::Failed);
        assert!(f.detail.contains("1603"), "{}", f.detail);
        assert_eq!(w.seen.borrow().len(), 3);
        assert_eq!(w.seen.borrow()[0][2], "Google.Chrome");
    }

    #[test]
    fn user_mode_adds_scope_and_explains_machine_only_packages() {
        let w = Fake::new(vec![out(-1978335216, "No applicable installer found")]);
        let r = install_one(&w, &app("vcredist", "Microsoft.VCRedist.2015+.x64"), true);
        assert_eq!(r.status, Status::Failed);
        assert!(r.detail.contains("administrateur"), "{}", r.detail);
        let args = &w.seen.borrow()[0];
        assert_eq!(&args[args.len() - 2..], ["--scope", "user"]);
    }

    #[test]
    fn timeout_and_spawn_errors_are_failures_not_panics() {
        let w = Fake::new(vec![
            Ok(RunOut {
                code: None,
                text: String::new(),
            }),
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "introuvable",
            )),
        ]);
        let a = app("vlc", "VideoLAN.VLC");
        let t = install_one(&w, &a, false);
        assert_eq!(t.status, Status::Failed);
        assert!(t.detail.contains("minutes"));
        let e = install_one(&w, &a, false);
        assert_eq!(e.status, Status::Failed);
        assert!(e.detail.contains("introuvable"));
    }
}
