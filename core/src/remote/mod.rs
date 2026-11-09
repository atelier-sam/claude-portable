//! `ccp-core remote` : relier un PC au Mac de Sam par le tunnel Cloudflare.
//!
//! Contrat de sortie (le wizard lit stdout ligne à ligne, jamais de JSON) :
//! - `remote sessions` : `nom<TAB>fenêtres<TAB>attachées`, une ligne par session tmux ;
//! - `remote connect` : interactif (ssh garde le terminal), le code de sortie est celui de tmux ;
//! - `remote share` : rien sur stdout, tout sur stderr ; le code de sortie dit le résultat ;
//! - `remote setup-mac` : `ok|ko<TAB>contrôle<TAB>détail`, une ligne par contrôle.
//!
//! Codes : 0 ok · 2 usage · 3 rien à lister (aucune session) · 4 réseau (Cloudflare, ssh,
//! téléchargement) · 6 un contrôle de `setup-mac` est ko · 10 interne.
//!
//! Cloudflared est celui qu'on télécharge (version épinglée, SHA-256 vérifié) dans
//! `<racine>/tools/` ; ssh est celui du système. Aucun secret en argument de commande.

pub mod cloudflared;
pub mod conf;
pub mod connect;
pub mod download;
pub mod intr;
pub mod known_hosts;
pub mod net;
pub mod pins;
pub mod quote;
pub mod setup_mac;
pub mod share;

use crate::cli::out;
use crate::env::Env;
use crate::error::{CcpError, Result};
use crate::root::Root;
use clap::{Args, Subcommand};
use conf::{Target, Trust};
use connect::{Common, Deps, Prepared};
use net::UreqFetch;
use std::io::BufRead;
use std::path::PathBuf;

/// Les options que `connect`, `sessions` et `share` ont en commun.
#[derive(Args, Debug, Clone)]
pub struct LinkArgs {
    /// Nom d'hôte du Mac (sinon `config/remote.conf`, sinon ssh-mac.atelier-sam.fr).
    #[arg(long, value_name = "HÔTE")]
    pub host: Option<String>,
    /// Utilisateur du Mac (sinon `config/remote.conf`, sinon celui de Sam).
    #[arg(long, value_name = "UTILISATEUR")]
    pub user: Option<String>,
    /// Clé privée à utiliser à la place du mot de passe du Mac (essais, agents).
    #[arg(long, value_name = "FICHIER")]
    pub identity: Option<PathBuf>,
    /// Accepte la clé d'un Mac inconnu de ce portable (première connexion à un AUTRE hôte
    /// que celui de Sam). Vérifie son empreinte auprès de son propriétaire d'abord.
    #[arg(long)]
    pub accept_new_host_key: bool,
    /// À la fin, efface les jetons Cloudflare Access de ce PC même s'il n'est pas marqué
    /// « invité » (le wizard ne pose ce marqueur que sous macOS).
    #[arg(long)]
    pub forget: bool,
}

#[derive(Args, Debug)]
pub struct ConnectArgs {
    #[command(flatten)]
    pub link: LinkArgs,
    /// Session tmux à rejoindre (sinon : menu numéroté sur le Mac, ou la seule session).
    #[arg(long, value_name = "NOM")]
    pub session: Option<String>,
}

#[derive(Args, Debug)]
pub struct ShareArgs {
    #[command(flatten)]
    pub link: LinkArgs,
    /// Ne pas demander les droits administrateur (sshd de Windows en a besoin pour
    /// authentifier un utilisateur : sans eux le partage échoue probablement).
    #[arg(long)]
    pub no_elevate: bool,
    /// Interne : ce processus est la relance élevée (il garde sa fenêtre ouverte à la fin).
    #[arg(long, hide = true)]
    pub elevated: bool,
}

#[derive(Args, Debug)]
pub struct SetupMacArgs {
    /// Contrôle seulement : ne crée rien.
    #[arg(long)]
    pub check: bool,
}

#[derive(Subcommand, Debug)]
pub enum RemoteCmd {
    /// Se connecte au Mac par le tunnel Cloudflare et rejoint une session tmux.
    Connect(ConnectArgs),
    /// Liste les sessions tmux du Mac : `nom<TAB>fenêtres<TAB>attachées`. Coûte une
    /// connexion (un mot de passe) de plus que `connect` seul : à réserver à un choix fait
    /// côté wizard.
    Sessions(LinkArgs),
    /// Ouvre ce PC aux agents du Mac tant que la fenêtre reste ouverte (Windows).
    /// NON ÉPROUVÉ SUR WINDOWS : écrit sans machine de test, à valider sur une VM avant usage.
    Share(ShareArgs),
    /// Vérifie (et crée en local ce qui manque) la liaison côté Mac : `ok|ko<TAB>contrôle<TAB>détail`.
    SetupMac(SetupMacArgs),
}

pub fn run(env: &Env, root: &Root, cmd: RemoteCmd) -> Result<i32> {
    match cmd {
        RemoteCmd::Connect(a) => cmd_connect(env, root, a),
        RemoteCmd::Sessions(a) => cmd_sessions(env, root, &a),
        RemoteCmd::Share(a) => cmd_share(env, root, a),
        RemoteCmd::SetupMac(a) => cmd_setup_mac(env, &a),
    }
}

/// Cible et options de connexion : arguments > `config/remote.conf` > défauts.
fn link(root: &Root, a: &LinkArgs) -> Result<(Target, Common)> {
    let raw = conf::load(root)?;
    let target = conf::resolve(a.host.as_deref(), a.user.as_deref(), raw)?;
    if let Some(id) = &a.identity {
        if !id.is_file() {
            return Err(CcpError::Usage(format!(
                "clé privée introuvable : {}",
                id.display()
            )));
        }
    }
    Ok((
        target,
        Common {
            identity: a.identity.clone(),
            accept_new_host_key: a.accept_new_host_key,
        },
    ))
}

fn deps<'a>(env: &'a Env, fetch: &'a UreqFetch) -> Deps<'a> {
    Deps {
        fetch,
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        download_base: env
            .ovr
            .download_base
            .as_deref()
            .unwrap_or(pins::DEFAULT_DOWNLOAD_BASE),
        style: quote::Style::native(),
    }
}

fn prepare(
    env: &Env,
    root: &Root,
    target: Target,
    common: &Common,
    quiet: bool,
) -> Result<Prepared> {
    let fetch = UreqFetch::new();
    connect::prepare(env, root, &deps(env, &fetch), target, common, quiet)
}

/// Après une connexion : sur un ordinateur marqué « invité » (ou avec `--forget`), les
/// jetons Cloudflare Access ne restent pas dans `~/.cloudflared` du PC. Les jetons de
/// l'application ET de l'équipe sont effacés : celui de l'équipe ouvrirait aussi les
/// autres applications Access de Sam tant qu'il vit.
fn after_connection(env: &Env, root: &Root, host: &str, forget: bool) {
    let guest = conf::local_hostname()
        .map(|h| conf::read_trust(root, &h) == Trust::Guest)
        .unwrap_or(false);
    if !(forget || guest) {
        return;
    }
    let removed = conf::purge_access_tokens(&env.home, host);
    if !removed.is_empty() {
        eprintln!(
            "ccp-core : {} jeton(s) Cloudflare Access effacé(s) de cet ordinateur.",
            removed.len()
        );
    }
}

fn cmd_connect(env: &Env, root: &Root, a: ConnectArgs) -> Result<i32> {
    let (target, common) = link(root, &a.link)?;
    let host = target.host.clone();
    let prepared = prepare(env, root, target, &common, false)?;
    let ran = connect::run_interactive(&prepared, a.session.as_deref());
    after_connection(env, root, &host, a.link.forget);
    connect::map_exit(ran?)
}

fn cmd_sessions(env: &Env, root: &Root, a: &LinkArgs) -> Result<i32> {
    let (target, common) = link(root, a)?;
    let host = target.host.clone();
    let prepared = prepare(env, root, target, &common, true)?;
    let ran = connect::run_capture(&prepared);
    after_connection(env, root, &host, a.forget);
    let (code, stdout) = ran?;
    match code {
        0 => {
            let sessions = connect::parse_sessions(&stdout);
            if sessions.is_empty() {
                // Le Mac a répondu sans session lisible : rien à lister (3), pas une panne.
                eprintln!("ccp-core : aucune session tmux lisible sur le Mac.");
                return Ok(3);
            }
            let mut s = String::new();
            for x in &sessions {
                s.push_str(&x.line());
                s.push('\n');
            }
            out(&s)?;
            Ok(0)
        }
        // Le script distant a déjà dit pourquoi sur stderr (« Aucune session tmux… »).
        3 => Ok(3),
        255 => connect::map_exit(255),
        n => Err(CcpError::Internal(format!(
            "le Mac a répondu avec le code {n} (voir le message ci-dessus)"
        ))),
    }
}

fn cmd_share(env: &Env, root: &Root, a: ShareArgs) -> Result<i32> {
    if !(cfg!(windows) || env.ovr.fake_windows) {
        return Err(CcpError::Usage(
            "« remote share » ne fonctionne que sous Windows (cet ordinateur ne l'est pas)".into(),
        ));
    }
    let (target, common) = link(root, &a.link)?;
    let host = target.host.clone();

    if cfg!(windows) && !a.no_elevate && !a.elevated && !crate::win::elevate::is_elevated() {
        if let Some(code) = relaunch_elevated(root, &a)? {
            return Ok(code);
        }
    }

    let fetch = UreqFetch::new();
    let d = deps(env, &fetch);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let ran = share::run(env, root, &d, target, &common, &mut input, &mut |m| {
        eprintln!("{m}")
    });
    after_connection(env, root, &host, a.link.forget);
    if a.elevated {
        // La fenêtre de la relance élevée disparaîtrait avec ses messages.
        eprint!("Appuie sur Entrée pour fermer cette fenêtre.");
        let mut l = String::new();
        let _ = input.read_line(&mut l);
    }
    ran
}

/// `Some(code)` : la relance élevée a tout fait ; `None` : l'invite a été refusée, on continue ici.
fn relaunch_elevated(root: &Root, a: &ShareArgs) -> Result<Option<i32>> {
    use crate::win::elevate::{self, Elevation};
    let exe = std::env::current_exe()
        .map_err(|e| CcpError::Internal(format!("exécutable courant illisible : {e}")))?;
    let mut args = vec![
        "--root".to_string(),
        root.as_str().to_string(),
        "remote".into(),
        "share".into(),
    ];
    let l = &a.link;
    if let Some(h) = &l.host {
        args.extend(["--host".into(), h.clone()]);
    }
    if let Some(u) = &l.user {
        args.extend(["--user".into(), u.clone()]);
    }
    if let Some(i) = &l.identity {
        args.extend(["--identity".into(), i.to_string_lossy().into_owned()]);
    }
    if l.accept_new_host_key {
        args.push("--accept-new-host-key".into());
    }
    if l.forget {
        args.push("--forget".into());
    }
    args.extend(["--no-elevate".into(), "--elevated".into()]);
    eprintln!("Droits administrateur demandés : une fenêtre va s'ouvrir pour le partage…");
    match elevate::relaunch_elevated(&exe, &args)? {
        Elevation::Finished(code) => Ok(Some(code)),
        Elevation::Declined => {
            eprintln!(
                "Élévation refusée : le partage continue sans droits administrateur, \
                 sshd refusera probablement les connexions."
            );
            Ok(None)
        }
    }
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY : getuid n'a ni argument ni effet de bord.
    unsafe { libc::getuid() }
}
#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

fn cmd_setup_mac(env: &Env, a: &SetupMacArgs) -> Result<i32> {
    if !cfg!(target_os = "macos") {
        return Err(CcpError::Usage(
            "« remote setup-mac » ne fonctionne que sur le Mac qui reçoit les connexions".into(),
        ));
    }
    let fetch = UreqFetch::new();
    let launchd = setup_mac::RealLaunchd { uid: current_uid() };
    let banner = setup_mac::TcpBanner {
        addr: "127.0.0.1:22",
    };
    let keygen = setup_mac::RealKeyGen;
    let deps = setup_mac::Deps {
        launchd: &launchd,
        banner: &banner,
        fetch: &fetch,
        keygen: &keygen,
        access_url: env
            .ovr
            .access_url
            .clone()
            .unwrap_or_else(|| format!("https://{}/", pins::DEFAULT_HOST)),
    };
    let paths = setup_mac::Paths::new(&env.home);
    if !a.check {
        setup_mac::provision(&deps, &paths, &mut |m| eprintln!("ccp-core : {m}"))?;
    }
    let checks = setup_mac::run_checks(&deps, &paths);
    let mut s = String::new();
    for c in &checks {
        s.push_str(&c.line());
        s.push('\n');
    }
    out(&s)?;
    Ok(if checks.iter().all(|c| c.ok) { 0 } else { 6 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn parse(args: &[&str]) -> RemoteCmd {
        let mut v = vec!["ccp-core", "remote"];
        v.extend(args);
        match Cli::try_parse_from(v).unwrap().cmd.unwrap() {
            crate::cli::Cmd::Remote { action } => action,
            other => panic!("pas remote : {other:?}"),
        }
    }

    #[test]
    fn connect_accepts_host_user_session_and_flags() {
        let RemoteCmd::Connect(a) = parse(&[
            "connect",
            "--host",
            "h.example",
            "--user",
            "u",
            "--session",
            "s1",
            "--forget",
            "--accept-new-host-key",
        ]) else {
            panic!()
        };
        assert_eq!(a.link.host.as_deref(), Some("h.example"));
        assert_eq!(a.link.user.as_deref(), Some("u"));
        assert_eq!(a.session.as_deref(), Some("s1"));
        assert!(a.link.forget && a.link.accept_new_host_key);
    }

    #[test]
    fn share_is_marked_untested_and_hides_its_relaunch_flag() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let remote = cmd.find_subcommand_mut("remote").unwrap();
        let share = remote.find_subcommand_mut("share").unwrap();
        let help = share.render_long_help().to_string();
        assert!(help.contains("NON ÉPROUVÉ SUR WINDOWS"), "{help}");
        assert!(!help.contains("--elevated"), "{help}");
        assert!(help.contains("--no-elevate"));
    }

    #[test]
    fn setup_mac_check_flag_parses() {
        let RemoteCmd::SetupMac(a) = parse(&["setup-mac", "--check"]) else {
            panic!()
        };
        assert!(a.check);
        let RemoteCmd::SetupMac(b) = parse(&["setup-mac"]) else {
            panic!()
        };
        assert!(!b.check);
    }

    #[test]
    fn global_root_works_after_remote() {
        let c = Cli::try_parse_from(["ccp-core", "remote", "sessions", "--root", "/r"]).unwrap();
        assert_eq!(c.root.as_deref(), Some("/r"));
    }
}
