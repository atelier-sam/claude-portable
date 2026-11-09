//! Binaire `ccp-core` : analyse la ligne de commande et traduit les erreurs en
//! codes de sortie du contrat. Aucune logique ici (voir `ccp_core::cli`).

use ccp_core::cli::{dispatch, Cli};
use clap::Parser;
use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    // `panic = "abort"` en release : sans ce hook un bug donnerait un SIGABRT
    // muet (code 134). Le wizard attend le code 10 et un message lisible.
    std::panic::set_hook(Box::new(|info| {
        let _ = writeln!(
            std::io::stderr(),
            "ccp-core : erreur interne ({info}). Lance « doctor » ou signale-le."
        );
        std::process::exit(10);
    }));

    // clap sort lui-même avec le code 2 sur un usage invalide (contrat), 0 sur --help/--version.
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => ExitCode::from(u8::try_from(code.clamp(0, 255)).unwrap_or(10)),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "ccp-core : {e}");
            ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(10))
        }
    }
}
