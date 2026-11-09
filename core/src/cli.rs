//! Ligne de commande de ccp-core (contrat v1).
//!
//! Le wizard bash n'analyse AUCUN JSON : il appelle ces commandes et affiche ce
//! qu'elles impriment. Codes de sortie (contrat) : 0 ok · 2 usage · 3 rien
//! trouvé · 4 réseau · 5 profil déjà ouvert · 6 divergence (`doctor`) · 10 interne.
//! Les messages d'erreur sont en français sur stderr ; stdout ne porte que le
//! résultat demandé.

use crate::cache;
use crate::creds;
use crate::discover;
use crate::doctor;
use crate::env::{now_s, Env};
use crate::error::{CcpError, Result};
use crate::http::UreqHttp;
use crate::model::{NextAccount, State, StatusReport};
use crate::purge;
use crate::recommend;
use crate::render;
use crate::root::{Profile, Root};
use crate::run::{self, RunOpts};
use crate::status::{self, Deps, ProbeOpts, DEFAULT_BUDGET};
use clap::{Args, Parser, Subcommand, ValueEnum};
use jiff::tz::TimeZone;
use std::ffi::OsString;
use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Version du contrat CLI : le wizard refuse un noyau qui répond autre chose.
pub const CONTRACT: u32 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "ccp-core",
    version,
    about = "Noyau comptes de Claude Code Portable : statut, renouvellement, Trousseau, lancement",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Dossier racine du portable (sinon $CCP_ROOT, sinon le dossier qui contient bin/).
    #[arg(long, global = true, value_name = "DOSSIER")]
    pub root: Option<String>,

    /// Binaire Claude (sinon $CCP_CLAUDE_BIN, sinon <racine>/bin/<plateforme>/claude).
    #[arg(long, global = true, value_name = "CHEMIN")]
    pub claude: Option<String>,

    /// Couleurs : auto = oui sauf si NO_COLOR ou TERM=dumb.
    #[arg(long, global = true, value_enum, default_value = "auto")]
    pub color: ColorMode,

    /// Affiche la version du contrat CLI (un entier).
    #[arg(long)]
    pub contract: bool,

    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
pub enum Format {
    Table,
    Json,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Statut, recommandation, inventaire et nettoyage des comptes.
    Accounts {
        #[command(subcommand)]
        action: AccountsCmd,
    },
    /// Lance Claude sur un profil (verrou de session, environnement, code de sortie propagé).
    Run {
        /// Nom du profil.
        profile: String,
        /// Arguments passés tels quels à Claude (après `--`).
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Compare ce que lit ccp-core avec `claude auth status` (détecte une divergence).
    Doctor {
        /// Un seul profil (sinon tous).
        profile: Option<String>,
    },
    /// Logiciels Windows : catalogue, installation par winget, Office par ODT (Windows seulement).
    Win {
        #[command(subcommand)]
        action: crate::win::WinCmd,
    },
    /// Liaison avec le Mac de Sam par le tunnel Cloudflare : connexion, partage de ce PC, installation côté Mac.
    Remote {
        #[command(subcommand)]
        action: crate::remote::RemoteCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum AccountsCmd {
    /// Tableau des comptes : état, forfait, quotas 5 h / 7 j.
    Status(StatusArgs),
    /// Nom du compte recommandé (lit le cache, ne sonde jamais) ; code 3 si aucun.
    Best,
    /// Inventaire en lecture seule des logins Claude de cet ordinateur.
    Discover(DiscoverArgs),
    /// Efface les sessions de CE portable : Trousseau (macOS) et identifiants en fichier (jamais la session de la machine).
    Purge {
        /// Un seul profil (sinon tous).
        profile: Option<String>,
    },
    /// Email d'un profil (vide et code 3 s'il est inconnu).
    Email { profile: String },
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Sonde tous les comptes, sans tenir compte du cache.
    #[arg(long, conflicts_with = "offline")]
    pub refresh: bool,
    /// Aucune requête : cache et magasins seulement.
    #[arg(long)]
    pub offline: bool,
    /// Âge maximal du cache avant nouvelle sonde, en secondes.
    #[arg(long, default_value_t = 300, value_name = "SECONDES")]
    pub max_age: i64,
    #[arg(long, value_enum, default_value = "table")]
    pub format: Format,
    /// Largeur du terminal (sinon $COLUMNS, sinon 100).
    #[arg(long, value_name = "N")]
    pub width: Option<usize>,
}

#[derive(Args, Debug)]
pub struct DiscoverArgs {
    #[arg(long, value_enum, default_value = "table")]
    pub format: Format,
    /// Largeur du terminal (sinon $COLUMNS, sinon 100).
    #[arg(long, value_name = "N")]
    pub width: Option<usize>,
    /// Un email par ligne pour les comptes de la machine absents du portable.
    #[arg(long, conflicts_with = "format")]
    pub missing: bool,
}

/// stdout sans panique si le lecteur ferme le tube (`| head -1`).
pub(crate) fn out(s: &str) -> Result<()> {
    let mut so = std::io::stdout().lock();
    match so.write_all(s.as_bytes()).and_then(|()| so.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(CcpError::Internal(format!(
            "écriture sur stdout impossible : {e}"
        ))),
    }
}

fn use_color(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
                && std::env::var("TERM").map_or(true, |t| t != "dumb")
        }
    }
}

fn term_width(arg: Option<usize>) -> usize {
    arg.or_else(|| {
        std::env::var("COLUMNS")
            .ok()
            .and_then(|c| c.trim().parse().ok())
    })
    .unwrap_or(100)
    .clamp(30, 300)
}

fn parse_profile(s: &str) -> Result<Profile> {
    Profile::parse(s)
}

fn make_deps(env: &Env) -> Deps {
    Deps {
        env: Arc::new(env.clone()),
        api: crate::api::Api::new(Arc::new(UreqHttp::new()), &env.api_base, &env.token_url),
        critical: Arc::new(AtomicUsize::new(0)),
    }
}

pub fn build_report(deps: &Deps, root: &Root, opts: &ProbeOpts) -> StatusReport {
    let profiles: Vec<_> = root
        .list_profiles()
        .iter()
        .map(|n| root.profile(n))
        .collect();
    let active = root.active_profile();
    let accounts = status::probe_all(deps, &profiles, &active, opts);
    let recommended = recommend::recommend(&accounts).map(|i| accounts[i].name.clone());
    let next = if recommended.is_none() {
        recommend::next_resume(&accounts).map(|(i, t)| NextAccount {
            name: accounts[i].name.clone(),
            resumes_at: t,
        })
    } else {
        None
    };
    StatusReport {
        schema: 1,
        generated_at: now_s(),
        active,
        recommended,
        next,
        accounts,
    }
}

fn cmd_status(env: &Env, root: &Root, color: bool, a: &StatusArgs) -> Result<i32> {
    if a.max_age < 0 {
        return Err(CcpError::Usage("--max-age doit être positif".into()));
    }
    let deps = make_deps(env);
    let opts = ProbeOpts {
        refresh: a.refresh,
        offline: a.offline,
        max_age_s: a.max_age,
        budget: if a.offline {
            std::time::Duration::from_secs(3)
        } else {
            DEFAULT_BUDGET
        },
    };
    let report = build_report(&deps, root, &opts);
    match a.format {
        Format::Json => {
            let s = serde_json::to_string(&report)
                .map_err(|e| CcpError::Internal(format!("sérialisation JSON : {e}")))?;
            out(&format!("{s}\n"))?;
        }
        Format::Table => {
            let t = render::status_table(
                &report,
                term_width(a.width),
                color,
                now_s(),
                &TimeZone::system(),
            );
            out(&t)?;
        }
    }
    // Tout est injoignable : l'affichage est fait, mais l'appelant doit pouvoir le savoir.
    let all_down = !report.accounts.is_empty()
        && report
            .accounts
            .iter()
            .all(|s| s.state == State::Unreachable);
    Ok(if all_down { 4 } else { 0 })
}

fn cmd_best(env: &Env, root: &Root) -> Result<i32> {
    let deps = make_deps(env);
    let report = build_report(&deps, root, &ProbeOpts::offline());
    match report.recommended {
        Some(name) => {
            out(&format!("{name}\n"))?;
            Ok(0)
        }
        None => Err(CcpError::NotFound("aucun compte disponible".into())),
    }
}

fn cmd_discover(env: &Env, root: &Root, color: bool, a: &DiscoverArgs) -> Result<i32> {
    let inv = discover::scan(env, root);
    if a.missing {
        let mut s = String::new();
        for e in discover::missing_emails(&inv) {
            s.push_str(&e);
            s.push('\n');
        }
        out(&s)?;
        // stdout reste « un email par ligne » ; les logins sans email connu se
        // signalent à part, pour que personne ne croie la liste complète.
        for l in discover::missing_unknown_labels(&inv) {
            eprintln!("Compte sans email connu, à reconnecter aussi : {l}");
        }
        return Ok(0);
    }
    match a.format {
        Format::Json => {
            let s = serde_json::to_string(&inv)
                .map_err(|e| CcpError::Internal(format!("sérialisation JSON : {e}")))?;
            out(&format!("{s}\n"))?;
        }
        Format::Table => {
            out(&render::discover_table(
                &inv,
                term_width(a.width),
                color,
                crate::env::now_ms(),
                &TimeZone::system(),
            ))?;
        }
    }
    Ok(0)
}

fn cmd_email(root: &Root, profile: &str) -> Result<i32> {
    let p = root.profile(&parse_profile(profile)?);
    let email = cache::load(&p)
        .and_then(|c| c.identity)
        .and_then(|i| i.email)
        .or_else(|| creds::read_local_email(&p.dir));
    match email {
        Some(e) => {
            out(&format!("{e}\n"))?;
            Ok(0)
        }
        None => Err(CcpError::NotFound(format!(
            "email inconnu pour le profil « {profile} »"
        ))),
    }
}

fn cmd_purge(env: &Env, root: &Root, profile: Option<&str>) -> Result<i32> {
    let only = profile.map(parse_profile).transpose()?;
    let r = purge::purge(env, root, only.as_ref())?;
    // 1re ligne = contrat historique ; les suivantes (stdout) sont le rapport.
    let mut text = format!(
        "Trousseau : {} session(s) retirée(s) pour {} profil(s).\n",
        r.removed, r.profiles
    );
    for p in &r.session_open {
        text.push_str(&format!(
            "Attention : « {p} » est ouvert dans une session Claude ; ses identifiants sont retirés quand même, mais cette session peut les réécrire en se fermant.\n"
        ));
    }
    for p in &r.renewal_running {
        text.push_str(&format!(
            "Attention : un renouvellement de « {p} » tournait encore après 15 s ; identifiants retirés quand même, à revérifier.\n"
        ));
    }
    for (p, why) in &r.unlocked {
        text.push_str(&format!(
            "Attention : « {p} » purgé sans verrou ({why}) ; un renouvellement simultané pourrait réécrire des identifiants.\n"
        ));
    }
    for f in &r.failures {
        text.push_str(&format!("ÉCHEC : {f}\n"));
    }
    out(&text)?;
    if r.complete() {
        // 11 = tout est effacé, mais sans garantie qu'un processus encore vivant
        // (session ouverte, renouvellement bloqué, volume sans verrou) ne réécrive
        // des identifiants : le wizard ne doit pas annoncer « effacé » sans réserve.
        Ok(if r.at_risk() { 11 } else { 0 })
    } else {
        Err(CcpError::Internal(format!(
            "purge INCOMPLÈTE : {} élément(s) n'ont pas pu être effacés, des identifiants peuvent subsister (détail ci-dessus)",
            r.failures.len()
        )))
    }
}

fn cmd_run(env: &Env, root: &Root, profile: &str, args: Vec<OsString>) -> Result<i32> {
    let deps = make_deps(env);
    let opts = RunOpts {
        profile: parse_profile(profile)?,
        claude: crate::claude_cli::resolve(env, root),
        args,
    };
    run::run(env, &deps, root, &opts)
}

fn cmd_doctor(env: &Env, root: &Root, profile: Option<&str>) -> Result<i32> {
    let only = profile.map(parse_profile).transpose()?;
    let deps = make_deps(env);
    let report = doctor::run(env, &deps, root, only.as_ref())?;
    out(&report.text)?;
    match doctor::exit_error(&report) {
        Some(e) => Err(e),
        None => Ok(0),
    }
}

/// Point d'entrée testable : renvoie le code de sortie.
pub fn dispatch(cli: Cli) -> Result<i32> {
    if cli.contract {
        out(&format!("{CONTRACT}\n"))?;
        return Ok(0);
    }
    let Some(cmd) = cli.cmd else {
        return Err(CcpError::Usage("aucune commande (voir --help)".into()));
    };
    let env = Env::from_process(cli.claude.as_deref());
    let root = Root::resolve(cli.root.as_deref())?;
    let color = use_color(cli.color);
    match cmd {
        Cmd::Accounts { action } => match action {
            AccountsCmd::Status(a) => cmd_status(&env, &root, color, &a),
            AccountsCmd::Best => cmd_best(&env, &root),
            AccountsCmd::Discover(a) => cmd_discover(&env, &root, color, &a),
            AccountsCmd::Purge { profile } => cmd_purge(&env, &root, profile.as_deref()),
            AccountsCmd::Email { profile } => cmd_email(&root, &profile),
        },
        Cmd::Run { profile, args } => cmd_run(&env, &root, &profile, args),
        Cmd::Doctor { profile } => cmd_doctor(&env, &root, profile.as_deref()),
        Cmd::Win { action } => crate::win::run(&env, &root, action),
        Cmd::Remote { action } => crate::remote::run(&env, &root, action),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn global_flags_work_before_and_after_the_subcommand() {
        let a = Cli::try_parse_from(["ccp-core", "--root", "/r", "accounts", "best"]).unwrap();
        assert_eq!(a.root.as_deref(), Some("/r"));
        let b = Cli::try_parse_from([
            "ccp-core", "run", "1", "--claude", "/c", "--root", "/r", "--", "-p", "salut",
        ])
        .unwrap();
        assert_eq!(b.claude.as_deref(), Some("/c"));
        match b.cmd {
            Some(Cmd::Run { profile, args }) => {
                assert_eq!(profile, "1");
                assert_eq!(args, vec![OsString::from("-p"), OsString::from("salut")]);
            }
            _ => panic!("run attendu"),
        }
    }

    #[test]
    fn refresh_and_offline_conflict() {
        assert!(
            Cli::try_parse_from(["ccp-core", "accounts", "status", "--refresh", "--offline"])
                .is_err()
        );
    }

    #[test]
    fn missing_excludes_format() {
        assert!(Cli::try_parse_from([
            "ccp-core",
            "accounts",
            "discover",
            "--missing",
            "--format",
            "json"
        ])
        .is_err());
    }

    #[test]
    fn width_is_clamped() {
        assert_eq!(term_width(Some(5)), 30);
        assert_eq!(term_width(Some(1000)), 300);
        assert_eq!(term_width(Some(100)), 100);
    }
}
