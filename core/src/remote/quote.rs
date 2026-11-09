//! Citations pour OpenSSH : le piège central de `remote connect` quand la racine du
//! portable contient des espaces et des accents (`D:\Ma clé USB\Écran été`).
//!
//! Trois endroits où une chaîne est RE-lue, chacun avec ses règles :
//! 1. la valeur d'un `-o Option=valeur` : découpée comme un fichier ssh_config
//!    (espaces = séparateurs, guillemets doubles, antislash d'échappement) PUIS
//!    développée (`%x`, `${VAR}`, `~`) ;
//! 2. le `ProxyCommand` : développé (`%h`…) puis donné à `$SHELL -c` sous Unix, ou
//!    à `posix_spawnp` SANS shell sous Win32-OpenSSH ;
//! 3. la commande distante : relue par le shell de connexion du Mac.
//!
//! Choix pour le point 2 : ne JAMAIS écrire de chemin dans la chaîne.
//! - Unix : `"$CCP_CLOUDFLARED" access ssh --hostname %h` — le shell développe la
//!   variable DANS des guillemets, donc aucun caractère du chemin ne peut être relu ;
//! - Windows : `cloudflared access ssh --hostname %h`, trouvé par le PATH que nous
//!   préfixons du dossier de cloudflared (un PATH n'est pas découpé sur les espaces)
//!   et par le dossier courant du processus, fixé à ce dossier.
//!
//! Le test `proxy_command_survives_spaces_and_accents` le prouve en exécutant la
//! chaîne par un vrai `sh -c`.

use crate::error::{CcpError, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    Unix,
    Windows,
}

impl Style {
    pub fn native() -> Style {
        if cfg!(windows) {
            Style::Windows
        } else {
            Style::Unix
        }
    }
}

/// Nom de la variable d'environnement qui porte le chemin de cloudflared (Unix).
pub const CLOUDFLARED_VAR: &str = "CCP_CLOUDFLARED";

/// Cite pour un shell POSIX : tout entre apostrophes, une apostrophe devient `'\''`.
pub fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// `%` est un caractère de développement dans les valeurs ssh_config : on le double.
pub fn percent_escape(s: &str) -> String {
    s.replace('%', "%%")
}

/// Valeur d'un `-o Option=…` qui désigne un fichier, citée pour ssh_config.
///
/// Refuse ce qui ne peut pas être représenté sans ambiguïté (guillemet, `${`,
/// caractère de contrôle) plutôt que de deviner : un refus clair vaut mieux qu'une
/// connexion qui lit le mauvais fichier.
pub fn ssh_path_value(path: &Path, style: Style) -> Result<String> {
    let s = path.to_str().ok_or_else(|| {
        CcpError::Usage(format!(
            "le chemin {} n'est pas de l'Unicode valide : déplace le portable",
            path.display()
        ))
    })?;
    if s.chars().any(|c| c.is_control()) || s.contains('"') || s.contains("${") {
        return Err(CcpError::Usage(format!(
            "le chemin « {s} » contient un guillemet, « ${{ » ou un caractère de contrôle, \
             qu'OpenSSH ne sait pas lire : déplace le portable dans un dossier plus simple"
        )));
    }
    let s = match style {
        // Win32-OpenSSH accepte les barres obliques ; évite toute question d'échappement.
        Style::Windows => s.replace('\\', "/"),
        // Dans une chaîne entre guillemets, `\\` se lit `\`.
        Style::Unix => s.replace('\\', "\\\\"),
    };
    Ok(format!("\"{}\"", percent_escape(&s)))
}

/// Le `ProxyCommand` (voir l'en-tête du module).
pub fn proxy_command(style: Style) -> String {
    match style {
        Style::Unix => format!("\"${CLOUDFLARED_VAR}\" access ssh --hostname %h"),
        Style::Windows => "cloudflared access ssh --hostname %h".to_string(),
    }
}

/// Ce qu'il faut poser autour du processus ssh pour que le `ProxyCommand` retrouve cloudflared.
#[derive(Debug, PartialEq, Eq)]
pub struct ProxyEnv {
    /// `PATH` complet à imposer (Windows seulement).
    pub path: Option<OsString>,
    /// `CCP_CLOUDFLARED` (Unix seulement).
    pub var: Option<PathBuf>,
    /// Dossier courant à imposer (Windows seulement).
    pub cwd: Option<PathBuf>,
}

pub fn proxy_env(
    style: Style,
    cloudflared: &Path,
    old_path: Option<&OsString>,
) -> Result<ProxyEnv> {
    match style {
        Style::Unix => Ok(ProxyEnv {
            path: None,
            var: Some(cloudflared.to_path_buf()),
            cwd: None,
        }),
        Style::Windows => {
            // Découpage à la main : `Path::parent` suit l'OS de CE binaire, or `style` peut
            // viser Windows depuis un hôte de test Unix (où `\` n'est pas un séparateur).
            let full = cloudflared.to_string_lossy();
            let dir_str = full
                .rsplit_once(['\\', '/'])
                .map(|(d, _)| d.to_string())
                .filter(|d| !d.is_empty())
                .ok_or_else(|| CcpError::Internal("chemin de cloudflared sans dossier".into()))?;
            if dir_str.contains(';') {
                return Err(CcpError::Usage(format!(
                    "le dossier {dir_str} contient un « ; », séparateur du PATH de Windows : \
                     déplace le portable"
                )));
            }
            let dir = PathBuf::from(&dir_str);
            // `join_paths` n'est pas utilisable ici : il suit l'OS de CE binaire, pas `style`.
            let mut p = OsString::from(&dir_str);
            if let Some(old) = old_path {
                if !old.is_empty() {
                    p.push(";");
                    p.push(old);
                }
            }
            Ok(ProxyEnv {
                path: Some(p),
                var: None,
                cwd: Some(dir),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_quote_handles_apostrophes_spaces_and_accents() {
        assert_eq!(sh_quote("abc"), "'abc'");
        assert_eq!(sh_quote("l'été"), "'l'\\''été'");
        assert_eq!(sh_quote("a b;rm -rf $HOME `x`"), "'a b;rm -rf $HOME `x`'");
        assert_eq!(sh_quote(""), "''");
    }

    #[test]
    fn ssh_path_value_quotes_spaces_accents_and_percent() {
        let p = Path::new("/Volumes/Ma clé USB/Écran été/config/remote/known_hosts");
        assert_eq!(
            ssh_path_value(p, Style::Unix).unwrap(),
            "\"/Volumes/Ma clé USB/Écran été/config/remote/known_hosts\""
        );
        // `%` doit être doublé, sinon ssh y verrait un jeton.
        assert_eq!(
            ssh_path_value(Path::new("/a/100% sûr/kh"), Style::Unix).unwrap(),
            "\"/a/100%% sûr/kh\""
        );
        // Windows : barres obliques, plus aucun antislash.
        assert_eq!(
            ssh_path_value(
                Path::new(r"D:\Ma clé USB\Écran été\config\remote\known_hosts"),
                Style::Windows
            )
            .unwrap(),
            "\"D:/Ma clé USB/Écran été/config/remote/known_hosts\""
        );
    }

    #[test]
    fn ssh_path_value_refuses_what_cannot_be_represented() {
        for bad in ["/a/b\"c", "/a/${HOME}/c", "/a/b\nc"] {
            let e = ssh_path_value(Path::new(bad), Style::Unix).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad}");
        }
        // Un antislash Unix est doublé, pas refusé.
        assert_eq!(
            ssh_path_value(Path::new("/a/b\\c"), Style::Unix).unwrap(),
            "\"/a/b\\\\c\""
        );
    }

    #[test]
    fn proxy_command_never_contains_a_path() {
        let unix = proxy_command(Style::Unix);
        assert_eq!(unix, "\"$CCP_CLOUDFLARED\" access ssh --hostname %h");
        let win = proxy_command(Style::Windows);
        assert_eq!(win, "cloudflared access ssh --hostname %h");
        for c in [&unix, &win] {
            assert!(
                !c.contains('/') && !c.contains('\\'),
                "aucun chemin dans la chaîne"
            );
            assert!(c.ends_with("--hostname %h"));
        }
    }

    #[test]
    fn windows_env_puts_the_tool_dir_first_and_sets_cwd() {
        let exe =
            Path::new(r"D:\Ma clé USB\Écran été\tools\cloudflared\windows-amd64\cloudflared.exe");
        let old: OsString = r"C:\Windows\system32;C:\Windows".into();
        let e = proxy_env(Style::Windows, exe, Some(&old)).unwrap();
        assert_eq!(
            e.path.unwrap(),
            OsString::from(
                r"D:\Ma clé USB\Écran été\tools\cloudflared\windows-amd64;C:\Windows\system32;C:\Windows"
            )
        );
        assert_eq!(
            e.cwd.unwrap(),
            PathBuf::from(r"D:\Ma clé USB\Écran été\tools\cloudflared\windows-amd64")
        );
        assert!(e.var.is_none());
        // Un « ; » dans le dossier casserait le PATH : refus net.
        let bad = Path::new(r"D:\a;b\cloudflared.exe");
        assert_eq!(
            proxy_env(Style::Windows, bad, None)
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[test]
    fn unix_env_carries_the_path_in_a_variable_only() {
        let exe = Path::new("/Volumes/Ma clé/tools/cloudflared/darwin-arm64/cloudflared");
        let e = proxy_env(Style::Unix, exe, None).unwrap();
        assert_eq!(e.var.as_deref(), Some(exe));
        assert!(e.path.is_none() && e.cwd.is_none());
    }

    /// LA preuve demandée : la chaîne, développée comme ssh le fait puis exécutée par
    /// un vrai shell, atteint un cloudflared rangé dans un dossier à espaces, accents,
    /// apostrophe et caractères de shell.
    #[cfg(unix)]
    #[test]
    fn proxy_command_survives_spaces_and_accents() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        for dirname in [
            "Ma clé USB/Écran été",
            "l'apostrophe $HOME `x` ; echo piege",
            "100% sûr/(parenthèses) & esperluette",
        ] {
            let dir = t.path().join(dirname);
            std::fs::create_dir_all(&dir).unwrap();
            let exe = dir.join("cloudflared");
            std::fs::write(&exe, "#!/bin/sh\necho \"arrive:$*\"\n").unwrap();
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

            let env = proxy_env(Style::Unix, &exe, None).unwrap();
            // ssh remplace %h puis passe la chaîne à `$SHELL -c`.
            let cmd = proxy_command(Style::Unix).replace("%h", "ssh-mac.example");
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(&cmd)
                .env(CLOUDFLARED_VAR, env.var.unwrap())
                // Un PATH vide prouve qu'on ne dépend pas du PATH sous Unix.
                .env("PATH", "")
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "arrive:access ssh --hostname ssh-mac.example",
                "dossier {dirname:?} : {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
