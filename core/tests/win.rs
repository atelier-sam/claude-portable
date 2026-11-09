//! Tests d'intégration de `ccp-core win` : le vrai binaire contre un FAUX winget et
//! un FAUX `setup.exe` (scripts sh), sur un hôte Windows simulé (`CCP_FAKE_WINDOWS=1`).
//!
//! Ce que ces tests prouvent : les arguments exacts passés à winget, la lecture des
//! codes de sortie, le format des lignes lues par le wizard, le nettoyage du staging
//! Office. Ce qu'ils ne prouvent pas : le comportement de vrais winget / ODT, ni
//! l'élévation UAC (aucun Windows ici).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sb {
    dir: tempfile::TempDir,
}

impl Sb {
    fn new() -> Sb {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tmp")).unwrap();
        std::fs::create_dir_all(dir.path().join("root")).unwrap();
        Sb { dir }
    }
    fn root(&self) -> PathBuf {
        self.dir.path().join("root")
    }
    fn tmp(&self) -> PathBuf {
        self.dir.path().join("tmp")
    }
    fn script(&self, name: &str, body: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
    fn cmd(&self, fake_windows: bool) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ccp-core"));
        c.env_clear()
            .env("HOME", self.dir.path())
            .env("USER", "testeur")
            .env("NO_COLOR", "1")
            .env("TMPDIR", self.tmp())
            .arg("--root")
            .arg(self.root());
        if fake_windows {
            c.env("CCP_FAKE_WINDOWS", "1");
        }
        c
    }
}

fn s(o: &Output) -> (String, String, i32) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code().unwrap_or(-99),
    )
}

/// Faux winget : `--version` répond ; `install --id X` rend le code que `plan` donne
/// pour X (clé=code, séparés par des espaces) et journalise la ligne de commande.
fn fake_winget(sb: &Sb, plan: &str) -> (PathBuf, PathBuf) {
    let log = sb.dir.path().join("winget.log");
    let body = format!(
        r#"if [ "$1" = "--version" ]; then echo v1.9.0; exit 0; fi
echo "$*" >> "{log}"
id="$3"
for kv in {plan}; do
  k="${{kv%%=*}}"; v="${{kv#*=}}"
  if [ "$k" = "$id" ]; then
    echo "Starting package install..."
    echo "Installer failed with exit code: $v"
    exit "$v"
  fi
done
echo "Successfully installed"
exit 0"#,
        log = log.display(),
        plan = plan
    );
    (sb.script("winget", &body), log)
}

#[test]
fn catalog_lines_are_gum_ready_on_a_windows_host() {
    let sb = Sb::new();
    let o = sb.cmd(true).args(["win", "catalog"]).output().unwrap();
    let (out, _, code) = s(&o);
    assert_eq!(code, 0);
    let first = out.lines().next().unwrap();
    assert_eq!(first, "chrome\tGoogle Chrome\t1");
    for l in out.lines() {
        assert_eq!(l.split('\t').count(), 3, "{l}");
        assert!(!l.split('\t').nth(1).unwrap().contains(','));
    }
    let j = sb
        .cmd(true)
        .args(["win", "catalog", "--format", "json"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&j.stdout).unwrap();
    assert_eq!(v["schema"], 1);
}

#[test]
fn catalog_override_in_the_root_is_merged() {
    let sb = Sb::new();
    std::fs::create_dir_all(sb.root().join("config")).unwrap();
    std::fs::write(
        sb.root().join("config/catalog.toml"),
        "[[app]]\nkey = \"chrome\"\ndefault = false\n[[app]]\nkey = \"vlc\"\nremove = true\n",
    )
    .unwrap();
    let o = sb.cmd(true).args(["win", "catalog"]).output().unwrap();
    let (out, _, code) = s(&o);
    assert_eq!(code, 0);
    assert!(out.contains("chrome\tGoogle Chrome\t0\n"));
    assert!(!out.contains("vlc\t"));
}

#[test]
fn every_win_command_is_refused_with_exit_2_off_windows() {
    let sb = Sb::new();
    for args in [
        vec!["win", "catalog"],
        vec!["win", "install", "chrome"],
        vec!["win", "office", "--list"],
        vec!["win", "office", "--edition", "365-apps"],
    ] {
        let o = sb.cmd(false).args(&args).output().unwrap();
        let (out, err, code) = s(&o);
        assert_eq!(code, 2, "{args:?}");
        assert!(out.is_empty(), "{args:?}: rien sur stdout");
        assert!(err.contains("Windows"), "{args:?}: {err}");
    }
}

#[test]
fn install_reports_each_package_and_exits_1_on_any_failure() {
    let sb = Sb::new();
    // Un code de sortie unix tient sur 8 bits : les HRESULT de winget (0x8A15xxxx) ne sont
    // pas rejouables ici, ils sont couverts par les tests unitaires de `win::winget`.
    let (winget, log) = fake_winget(&sb, "VideoLAN.VLC=3 7zip.7zip=1");
    let o = sb
        .cmd(true)
        .env("CCP_WINGET_BIN", &winget)
        .args(["win", "install", "chrome", "vlc", "7zip"])
        .output()
        .unwrap();
    let (out, err, code) = s(&o);
    assert_eq!(code, 1, "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(lines[0], "ok\tchrome\tinstallé");
    assert!(lines[1].starts_with("echec\tvlc\t"), "{}", lines[1]);
    assert!(lines[1].contains("0x00000003"), "{}", lines[1]);
    assert!(
        lines[1].contains("exit code: 3"),
        "dernière ligne de winget reprise : {}",
        lines[1]
    );
    assert!(lines[2].starts_with("echec\t7zip\t"), "{}", lines[2]);
    // Arguments exacts, dans l'ordre demandé, un paquet à la fois.
    let logged = std::fs::read_to_string(log).unwrap();
    let calls: Vec<&str> = logged.lines().collect();
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0],
        "install --id Google.Chrome -e --silent --accept-package-agreements \
         --accept-source-agreements --disable-interactivity --source winget"
    );
    assert!(calls[1].contains("VideoLAN.VLC") && calls[2].contains("7zip.7zip"));
    // La progression passe par stderr, pas par stdout.
    assert!(err.contains("[1/3]"), "{err}");
}

#[test]
fn install_all_ok_exits_0() {
    let sb = Sb::new();
    let (winget, _) = fake_winget(&sb, "");
    let o = sb
        .cmd(true)
        .env("CCP_WINGET_BIN", &winget)
        .args(["win", "install", "firefox", "libreoffice"])
        .output()
        .unwrap();
    let (out, _, code) = s(&o);
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 2);
    assert!(out.lines().all(|l| l.starts_with("ok\t")));
}

#[test]
fn unknown_keys_fail_before_winget_is_ever_called() {
    let sb = Sb::new();
    let (winget, log) = fake_winget(&sb, "");
    let o = sb
        .cmd(true)
        .env("CCP_WINGET_BIN", &winget)
        .args(["win", "install", "chrome", "nope"])
        .output()
        .unwrap();
    let (out, err, code) = s(&o);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(err.contains("nope"), "{err}");
    assert!(!log.exists(), "winget ne doit pas être appelé");
}

#[test]
fn missing_winget_gives_a_clear_message_and_exit_2() {
    let sb = Sb::new();
    let o = sb
        .cmd(true)
        .env("CCP_WINGET_BIN", sb.dir.path().join("absent"))
        .args(["win", "install", "chrome"])
        .output()
        .unwrap();
    let (out, err, code) = s(&o);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(
        err.contains("App Installer") && err.contains("Microsoft Store"),
        "{err}"
    );
}

#[test]
fn office_list_has_one_tab_separated_line_per_edition() {
    let sb = Sb::new();
    let o = sb
        .cmd(true)
        .args(["win", "office", "--list"])
        .output()
        .unwrap();
    let (out, _, code) = s(&o);
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 6);
    assert!(out.contains("ltsc-2024\tOffice LTSC 2024"));
    assert!(out.lines().all(|l| l.split('\t').count() == 2));
}

/// Faux setup.exe : copie le XML reçu à côté (pour l'inspecter) puis répond `code`.
fn fake_setup(sb: &Sb, code: i32) -> (PathBuf, PathBuf) {
    let seen = sb.dir.path().join("config-seen.xml");
    let body = format!(
        r#"[ "$1" = "/configure" ] || exit 64
cp "$2" "{seen}"
pwd > "{seen}.cwd"
exit {code}"#,
        seen = seen.display()
    );
    (sb.script("setup.exe", &body), seen)
}

fn dir_is_empty(p: &Path) -> bool {
    std::fs::read_dir(p).unwrap().next().is_none()
}

#[test]
fn office_installs_with_the_generated_xml_and_cleans_its_staging() {
    let sb = Sb::new();
    let (setup, seen) = fake_setup(&sb, 0);
    let o = sb
        .cmd(true)
        .env("CCP_ODT_SETUP", &setup)
        .args([
            "win",
            "office",
            "--edition",
            "ltsc-2024",
            "--lang",
            "fr-fr",
            "--apps",
            "word,excel",
        ])
        .output()
        .unwrap();
    let (out, err, code) = s(&o);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.starts_with("ok\toffice\t"), "{out}");
    assert!(out.contains("non activé"), "{out}");
    let xml = std::fs::read_to_string(seen).unwrap();
    assert!(xml.contains("Channel=\"PerpetualVL2024\"") && xml.contains("ProPlus2024Volume"));
    assert!(xml.contains("<ExcludeApp ID=\"Teams\" />") && !xml.contains("ID=\"Word\""));
    assert!(
        dir_is_empty(&sb.tmp()),
        "staging non effacé : {:?}",
        std::fs::read_dir(sb.tmp()).unwrap().count()
    );
}

#[test]
fn office_failure_exits_1_and_still_cleans_staging() {
    let sb = Sb::new();
    let (setup, _) = fake_setup(&sb, 77);
    let o = sb
        .cmd(true)
        .env("CCP_ODT_SETUP", &setup)
        .args(["win", "office", "--edition", "365-apps"])
        .output()
        .unwrap();
    let (out, _, code) = s(&o);
    assert_eq!(code, 1);
    assert!(
        out.starts_with("echec\toffice\t") && out.contains("code 77"),
        "{out}"
    );
    assert!(dir_is_empty(&sb.tmp()));
}

#[test]
fn office_refuses_a_nearly_full_disk_without_running_setup() {
    let sb = Sb::new();
    let (setup, seen) = fake_setup(&sb, 0);
    let o = sb
        .cmd(true)
        .env("CCP_ODT_SETUP", &setup)
        .env("CCP_FAKE_FREE_BYTES", "4000000000")
        .args(["win", "office", "--edition", "365-apps"])
        .output()
        .unwrap();
    let (out, _, code) = s(&o);
    assert_eq!(code, 1);
    assert!(out.contains("espace disque insuffisant"), "{out}");
    assert!(!seen.exists(), "setup.exe ne doit pas être lancé");
}

#[test]
fn office_bad_arguments_are_usage_errors() {
    let sb = Sb::new();
    for args in [
        vec!["win", "office", "--edition", "office-2003"],
        vec![
            "win",
            "office",
            "--edition",
            "365-apps",
            "--apps",
            "word,visio",
        ],
        vec![
            "win",
            "office",
            "--edition",
            "365-apps",
            "--lang",
            "\"><x/>",
        ],
        vec!["win", "office"],
    ] {
        let o = sb.cmd(true).args(&args).output().unwrap();
        assert_eq!(s(&o).2, 2, "{args:?}");
    }
}
