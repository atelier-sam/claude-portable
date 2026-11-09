//! Outils Windows : catalogue de logiciels, installation par winget, Office par ODT.
//!
//! Contrat de sortie (le wizard lit stdout ligne à ligne, jamais de JSON) :
//! - `win catalog` : `clé<TAB>libellé<TAB>coché(0|1)` ;
//! - `win install` : `ok|deja|echec<TAB>clé<TAB>détail`, une ligne par paquet ;
//! - `win office --list` : `clé<TAB>libellé` ;
//! - `win office --edition` : `ok|echec<TAB>office<TAB>détail`.
//!
//! Tout est réservé à Windows : ailleurs, refus propre (code 2). `CCP_FAKE_WINDOWS=1`
//! lève ce refus pour jouer les flux contre un faux `winget` dans les tests.

pub mod catalog;
pub mod elevate;
pub mod office;
pub mod winget;

use crate::cli::out;
use crate::env::Env;
use crate::error::{CcpError, Result};
use crate::root::Root;
use clap::{Args, Subcommand, ValueEnum};
use std::io::Write;
use std::path::PathBuf;
use winget::{PackageResult, RealWinget, Status, Winget};

#[derive(Subcommand, Debug)]
pub enum WinCmd {
    /// Liste les logiciels installables : `clé<TAB>libellé<TAB>coché`.
    Catalog(CatalogArgs),
    /// Installe des logiciels du catalogue par winget : `ok|deja|echec<TAB>clé<TAB>détail`.
    Install(InstallArgs),
    /// Office par l'Office Deployment Tool (sans clé de licence).
    Office(OfficeArgs),
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum CatalogFormat {
    Lines,
    Json,
}

#[derive(Args, Debug)]
pub struct CatalogArgs {
    #[arg(long, value_enum, default_value = "lines")]
    pub format: CatalogFormat,
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Clés du catalogue (voir `win catalog`).
    #[arg(required = true, value_name = "CLÉ")]
    pub keys: Vec<String>,
    /// Ne pas demander les droits administrateur (installation « par utilisateur »).
    #[arg(long)]
    pub no_elevate: bool,
    /// Interne : fichier où le processus élevé dépose ses lignes de résultat.
    #[arg(long, hide = true, value_name = "FICHIER")]
    pub result_file: Option<String>,
}

#[derive(Args, Debug)]
pub struct OfficeArgs {
    /// Liste les éditions : `clé<TAB>libellé`.
    #[arg(long, conflicts_with_all = ["edition", "lang", "apps"])]
    pub list: bool,
    /// Édition à installer (voir `--list`).
    #[arg(long, value_name = "CLÉ", required_unless_present = "list")]
    pub edition: Option<String>,
    /// Langue de l'installation.
    #[arg(long, default_value = "fr-fr", value_name = "LANGUE")]
    pub lang: String,
    /// Applications à installer, séparées par des virgules
    /// (word,excel,powerpoint,outlook,onenote,access,publisher,teams,onedrive).
    /// Absent : toutes, comme Microsoft les propose.
    #[arg(long, value_name = "LISTE")]
    pub apps: Option<String>,
    /// Ne pas demander les droits administrateur.
    #[arg(long)]
    pub no_elevate: bool,
    /// Interne : fichier où le processus élevé dépose ses lignes de résultat.
    #[arg(long, hide = true, value_name = "FICHIER")]
    pub result_file: Option<String>,
}

pub fn require_windows(env: &Env) -> Result<()> {
    if cfg!(windows) || env.ovr.fake_windows {
        Ok(())
    } else {
        Err(CcpError::Usage(
            "les commandes « win » ne fonctionnent que sous Windows (cet ordinateur ne l'est pas)"
                .into(),
        ))
    }
}

/// Écrit chaque ligne sur stdout ET, pour un processus élevé, dans le fichier de
/// résultat que le processus parent relaiera.
struct Sink {
    file: Option<std::fs::File>,
}

impl Sink {
    fn new(path: Option<&str>) -> Result<Sink> {
        let file = match path {
            Some(p) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| {
                        CcpError::Internal(format!("fichier de résultat illisible ({p}) : {e}"))
                    })?,
            ),
            None => None,
        };
        Ok(Sink { file })
    }

    fn emit(&mut self, line: &str) -> Result<()> {
        out(&format!("{line}\n"))?;
        if let Some(f) = &mut self.file {
            writeln!(f, "{line}")
                .and_then(|()| f.flush())
                .map_err(|e| CcpError::Internal(format!("fichier de résultat : {e}")))?;
        }
        Ok(())
    }
}

pub fn run(env: &Env, root: &Root, cmd: WinCmd) -> Result<i32> {
    require_windows(env)?;
    match cmd {
        WinCmd::Catalog(a) => cmd_catalog(root, &a),
        WinCmd::Install(a) => cmd_install(env, root, a),
        WinCmd::Office(a) => cmd_office(env, root, a),
    }
}

fn load_catalog(root: &Root) -> Result<Vec<catalog::App>> {
    catalog::load(&root.path(), &mut |m| eprintln!("ccp-core : {m}"))
}

fn cmd_catalog(root: &Root, a: &CatalogArgs) -> Result<i32> {
    let apps = load_catalog(root)?;
    match a.format {
        CatalogFormat::Lines => out(&catalog::render_lines(&apps))?,
        CatalogFormat::Json => out(&format!("{}\n", catalog::render_json(&apps)?))?,
    }
    Ok(0)
}

// ------------------------------------------------------------------ élévation

enum Relay {
    /// Le processus élevé a tout fait : son code de sortie est le nôtre.
    Done(i32),
    /// Continuer ici, en mode utilisateur.
    Continue,
}

/// Relance ce programme élevé (une fois), relaie ses lignes de résultat et rend
/// son code de sortie ; ou demande de continuer en mode utilisateur si
/// l'invite UAC est refusée.
fn relay_through_elevation(
    root: &Root,
    sub_args: Vec<String>,
    expected_keys: &[String],
) -> Result<Relay> {
    let logs = root.path().join("logs");
    std::fs::create_dir_all(&logs)
        .map_err(|e| CcpError::Internal(format!("dossier logs impossible à créer : {e}")))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let result_file: PathBuf = logs.join(format!("win-{:x}-{nanos:x}.out", std::process::id()));
    let exe = std::env::current_exe()
        .map_err(|e| CcpError::Internal(format!("exécutable courant illisible : {e}")))?;
    let mut args = vec!["--root".to_string(), root.as_str().to_string()];
    args.extend(sub_args);
    args.push("--no-elevate".into());
    args.push("--result-file".into());
    args.push(result_file.to_string_lossy().into_owned());

    eprintln!("Droits administrateur demandés (une seule invite) : une fenêtre va s'ouvrir…");
    let outcome = elevate::relaunch_elevated(&exe, &args);
    let relayed = std::fs::read_to_string(&result_file).unwrap_or_default();
    let _ = std::fs::remove_file(&result_file);
    match outcome {
        Ok(elevate::Elevation::Declined) => {
            eprintln!(
                "Élévation refusée : installation en mode utilisateur (certains logiciels \
                 demanderont les droits administrateur et seront signalés « echec »)."
            );
            Ok(Relay::Continue)
        }
        Ok(elevate::Elevation::Finished(code)) => {
            let mut printed = 0usize;
            for l in relayed.lines().filter(|l| !l.trim().is_empty()) {
                out(&format!("{l}\n"))?;
                printed += 1;
            }
            if printed == 0 {
                // Le processus élevé n'a rien dit (arrêté, fenêtre fermée) : ne pas laisser
                // le wizard croire que tout va bien.
                for k in expected_keys {
                    out(&format!(
                        "echec\t{k}\tle processus administrateur n'a rien rapporté (fenêtre fermée ?)\n"
                    ))?;
                }
                return Ok(Relay::Done(if code == 0 { 1 } else { code }));
            }
            Ok(Relay::Done(code))
        }
        Err(e) => {
            eprintln!("ccp-core : {e} ; installation en mode utilisateur.");
            Ok(Relay::Continue)
        }
    }
}

// ------------------------------------------------------------------ install

/// Installe les paquets l'un après l'autre. `emit` reçoit chaque résultat dès qu'il
/// existe (le wizard affiche la progression ligne à ligne).
pub fn install_batch(
    w: &dyn Winget,
    apps: &[&catalog::App],
    user_scope: bool,
    progress: &mut dyn FnMut(usize, usize, &catalog::App),
    emit: &mut dyn FnMut(&PackageResult) -> Result<()>,
) -> Result<Vec<PackageResult>> {
    let mut all = Vec::new();
    for (i, app) in apps.iter().enumerate() {
        progress(i + 1, apps.len(), app);
        let r = winget::install_one(w, app, user_scope);
        emit(&r)?;
        all.push(r);
    }
    Ok(all)
}

/// 0 si tout est ok/déjà, 1 si au moins un échec.
pub fn batch_exit_code(results: &[PackageResult]) -> i32 {
    if results.iter().any(|r| r.status == Status::Failed) {
        1
    } else {
        0
    }
}

fn cmd_install(env: &Env, root: &Root, a: InstallArgs) -> Result<i32> {
    // Clés vérifiées AVANT toute élévation : une faute de frappe ne doit pas coûter une invite UAC.
    let apps = load_catalog(root)?;
    let chosen = catalog::resolve(&apps, &a.keys)?;

    let real = RealWinget::new(env.ovr.winget.as_deref());
    if real.probe().is_none() {
        return Err(CcpError::Usage(winget::WINGET_MISSING.into()));
    }

    let mut user_scope = false;
    if !a.no_elevate && !elevate::is_elevated() {
        let keys: Vec<String> = chosen.iter().map(|c| c.key.clone()).collect();
        let mut sub = vec!["win".to_string(), "install".to_string()];
        sub.extend(keys.iter().cloned());
        match relay_through_elevation(root, sub, &keys)? {
            Relay::Done(code) => return Ok(code),
            Relay::Continue => user_scope = true,
        }
    } else if a.no_elevate && !elevate::is_elevated() {
        // Demandé explicitement : mode utilisateur, sans invite.
        user_scope = true;
    }

    let mut sink = Sink::new(a.result_file.as_deref())?;
    let results = install_batch(
        &real,
        &chosen,
        user_scope,
        &mut |n, total, app| eprintln!("[{n}/{total}] {}…", app.label),
        &mut |r| sink.emit(&r.line()),
    )?;
    Ok(batch_exit_code(&results))
}

// ------------------------------------------------------------------ office

fn cmd_office(env: &Env, root: &Root, a: OfficeArgs) -> Result<i32> {
    if a.list {
        out(&office::render_list())?;
        return Ok(0);
    }
    // `required_unless_present` garantit `edition` ; on reste sans unwrap.
    let Some(edition_key) = a.edition.as_deref() else {
        return Err(CcpError::Usage("--edition est requis (voir --list)".into()));
    };
    let edition = office::find_edition(edition_key)?;
    if !office::valid_lang(&a.lang) {
        return Err(CcpError::Usage(format!("langue invalide : « {} »", a.lang)));
    }
    let apps = match &a.apps {
        Some(list) => office::parse_apps(list)?,
        None => office::ALL_APPS.iter().copied().collect(),
    };

    let real = RealWinget::new(env.ovr.winget.as_deref());

    if !a.no_elevate && !elevate::is_elevated() {
        let mut sub = vec![
            "win".to_string(),
            "office".to_string(),
            "--edition".to_string(),
            edition.key.to_string(),
            "--lang".to_string(),
            a.lang.clone(),
        ];
        if let Some(list) = &a.apps {
            sub.push("--apps".into());
            sub.push(list.clone());
        }
        match relay_through_elevation(root, sub, &["office".to_string()])? {
            Relay::Done(code) => return Ok(code),
            Relay::Continue => {
                eprintln!(
                    "Office s'installe pour tous les utilisateurs : sans droits administrateur, \
                     l'installation va probablement échouer."
                );
            }
        }
    }

    let bits = office::client_edition(
        std::env::var("PROCESSOR_ARCHITECTURE").ok().as_deref(),
        std::env::var("PROCESSOR_ARCHITEW6432").ok().as_deref(),
    );
    let host = office::RealHost {
        env,
        root,
        winget: &real,
    };
    let result = office::install(&host, edition, &a.lang, &apps, bits);
    let mut sink = Sink::new(a.result_file.as_deref())?;
    sink.emit(&result.line())?;
    Ok(if result.ok { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use crate::cli::Cmd;
    use clap::Parser;

    fn parse(args: &[&str]) -> WinCmd {
        let mut v = vec!["ccp-core", "win"];
        v.extend_from_slice(args);
        match Cli::try_parse_from(v).unwrap().cmd {
            Some(Cmd::Win { action }) => action,
            _ => panic!("win attendu"),
        }
    }

    #[test]
    fn clap_surface_of_win() {
        assert!(matches!(
            parse(&["catalog"]),
            WinCmd::Catalog(CatalogArgs {
                format: CatalogFormat::Lines
            })
        ));
        assert!(matches!(
            parse(&["catalog", "--format", "json"]),
            WinCmd::Catalog(CatalogArgs {
                format: CatalogFormat::Json
            })
        ));
        match parse(&["install", "chrome", "vlc", "--no-elevate"]) {
            WinCmd::Install(i) => {
                assert_eq!(i.keys, ["chrome", "vlc"]);
                assert!(i.no_elevate);
            }
            _ => panic!(),
        }
        match parse(&["office", "--edition", "365-apps", "--apps", "word,excel"]) {
            WinCmd::Office(o) => {
                assert_eq!(o.lang, "fr-fr");
                assert_eq!(o.apps.as_deref(), Some("word,excel"));
            }
            _ => panic!(),
        }
        assert!(Cli::try_parse_from(["ccp-core", "win", "install"]).is_err());
        assert!(Cli::try_parse_from(["ccp-core", "win", "office"]).is_err());
        assert!(
            Cli::try_parse_from(["ccp-core", "win", "office", "--list", "--edition", "x"]).is_err()
        );
    }

    #[test]
    fn batch_stops_for_nobody_and_reports_each_package_in_order() {
        use std::cell::RefCell;
        struct W(RefCell<Vec<i32>>);
        impl Winget for W {
            fn run(
                &self,
                _a: &[String],
                _t: std::time::Duration,
            ) -> std::io::Result<winget::RunOut> {
                Ok(winget::RunOut {
                    code: Some(self.0.borrow_mut().remove(0)),
                    text: String::new(),
                })
            }
        }
        let apps = catalog::embedded().unwrap();
        let pick = |k: &str| apps.iter().find(|a| a.key == k).unwrap();
        let chosen = [pick("chrome"), pick("vlc"), pick("7zip")];
        let w = W(RefCell::new(vec![0, 1603, -1978335135]));
        let mut lines = Vec::new();
        let res = install_batch(&w, &chosen, false, &mut |_, _, _| {}, &mut |r| {
            lines.push(r.line());
            Ok(())
        })
        .unwrap();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("ok\tchrome\t"));
        assert!(lines[1].starts_with("echec\tvlc\t"));
        assert!(lines[2].starts_with("deja\t7zip\t"));
        // Un échec n'interrompt pas le lot, mais fait sortir en 1.
        assert_eq!(batch_exit_code(&res), 1);
        assert_eq!(batch_exit_code(&res[..1]), 0);
        assert_eq!(batch_exit_code(&res[2..]), 0);
    }

    #[test]
    fn non_windows_hosts_are_refused_with_exit_2() {
        let t = tempfile::tempdir().unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        let e = require_windows(&env);
        if cfg!(windows) {
            assert!(e.is_ok());
        } else {
            assert_eq!(e.unwrap_err().exit_code(), 2);
        }
        let mut env = env;
        env.ovr.fake_windows = true;
        assert!(require_windows(&env).is_ok());
    }
}
