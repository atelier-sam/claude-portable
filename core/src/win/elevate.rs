//! Élévation (droits administrateur) sous Windows.
//!
//! Décision (brief, point 2) : demander l'élévation UNE fois, en amont, plutôt que
//! de laisser chaque installateur ouvrir sa propre invite UAC au milieu d'un lot
//! (invite cachée derrière d'autres fenêtres = lot qui semble figé).
//!   1. déjà administrateur : on installe tel quel ;
//!   2. sinon ccp-core se relance élevé UNE fois (`ShellExecuteExW`, verbe `runas`),
//!      attend la fin et relaie les lignes de résultat par un fichier (le processus
//!      élevé a sa propre console, son stdout n'est pas récupérable) ;
//!   3. si l'utilisateur refuse l'invite : on continue en mode utilisateur
//!      (`winget --scope user`) ; un paquet sans installation « par utilisateur »
//!      est alors rapporté `echec` avec l'explication, jamais tenté en machine.
//!
//! Les parties Windows ne peuvent pas être jouées ici (aucun Windows) : elles sont
//! compilées et passées au clippy en croisé, la logique de citation des arguments —
//! seul vrai piège — est testée sur toutes les plateformes.

use crate::error::{CcpError, Result};
use std::path::Path;

/// Cite un argument selon les règles de `CommandLineToArgvW` (le contraire de ce que
/// font la plupart des gens : voir « Everyone quotes command line arguments the
/// wrong way », Microsoft DevBlogs). Sert à fabriquer la ligne de paramètres de
/// `ShellExecuteExW`, qui n'accepte qu'une chaîne et non un tableau.
pub fn quote_windows_arg(arg: &str) -> String {
    let needs_quotes = arg.is_empty() || arg.contains([' ', '\t', '\n', '\u{b}', '"']);
    if !needs_quotes {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Les antislashs qui précèdent un guillemet sont doublés, le guillemet échappé.
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Antislashs finaux : doublés, sinon ils échapperaient le guillemet fermant.
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

pub fn quote_windows_args<S: AsRef<str>>(args: &[S]) -> String {
    args.iter()
        .map(|a| quote_windows_arg(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Elevation {
    /// L'utilisateur a refusé l'invite UAC.
    Declined,
    /// Le processus élevé a fini avec ce code.
    Finished(i32),
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
    };
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn is_elevated() -> bool {
        // SAFETY : appels Win32 sur notre propre processus ; le jeton est refermé.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elev as *mut TOKEN_ELEVATION).cast::<c_void>(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            CloseHandle(token);
            ok != 0 && elev.TokenIsElevated != 0
        }
    }

    pub fn relaunch_elevated(exe: &Path, args: &[String]) -> Result<Elevation> {
        let file = wide(exe.as_os_str());
        let params = wide(std::ffi::OsStr::new(&quote_windows_args(args)));
        let verb = wide(std::ffi::OsStr::new("runas"));
        // SAFETY : structure Win32 initialisée à zéro puis remplie ; les tampons
        // `file`, `params` et `verb` vivent plus longtemps que l'appel.
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = SW_SHOWNORMAL;
            if ShellExecuteExW(&mut info) == 0 {
                let err = GetLastError();
                if err == ERROR_CANCELLED {
                    return Ok(Elevation::Declined);
                }
                return Err(CcpError::Internal(format!(
                    "élévation impossible (erreur Windows {err})"
                )));
            }
            let h = info.hProcess;
            if h.is_null() {
                return Err(CcpError::Internal(
                    "élévation lancée sans poignée de processus".into(),
                ));
            }
            WaitForSingleObject(h, INFINITE);
            let mut code = 0u32;
            let got = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            if got == 0 {
                return Err(CcpError::Internal(
                    "code de sortie du processus élevé illisible".into(),
                ));
            }
            Ok(Elevation::Finished(code as i32))
        }
    }
}

#[cfg(windows)]
pub use imp::{is_elevated, relaunch_elevated};

/// Hors Windows (hôte de test simulé par `CCP_FAKE_WINDOWS`) : jamais d'élévation.
#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true
}

#[cfg(not(windows))]
pub fn relaunch_elevated(_exe: &Path, _args: &[String]) -> Result<Elevation> {
    Err(CcpError::Internal(
        "élévation impossible hors de Windows".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_arguments_are_left_alone() {
        assert_eq!(quote_windows_arg("win"), "win");
        assert_eq!(quote_windows_arg("--result-file"), "--result-file");
        assert_eq!(quote_windows_arg(r"C:\a\b.out"), r"C:\a\b.out");
    }

    #[test]
    fn spaces_accents_and_empty_are_quoted() {
        assert_eq!(
            quote_windows_arg(r"D:\Ma clé USB\Écran été"),
            "\"D:\\Ma clé USB\\Écran été\""
        );
        assert_eq!(quote_windows_arg(""), "\"\"");
    }

    #[test]
    fn quotes_and_trailing_backslashes_follow_commandlinetoargv() {
        // Un guillemet est précédé d'un antislash.
        assert_eq!(quote_windows_arg("a\"b"), "\"a\\\"b\"");
        // Des antislashs avant un guillemet sont doublés, plus un pour le guillemet.
        assert_eq!(quote_windows_arg("a\\\"b"), "\"a\\\\\\\"b\"");
        // Antislash final d'un chemin à espaces : doublé pour ne pas manger le guillemet fermant.
        assert_eq!(
            quote_windows_arg(r"C:\Mon dossier\"),
            "\"C:\\Mon dossier\\\\\""
        );
        // Sans espace, un antislash final reste tel quel.
        assert_eq!(quote_windows_arg(r"C:\dossier\"), r"C:\dossier\");
    }

    /// Relit la chaîne produite comme `CommandLineToArgvW` le ferait (implémentation
    /// de référence minimale) pour prouver l'aller-retour.
    fn split_like_windows(cmdline: &str) -> Vec<String> {
        let chars: Vec<char> = cmdline.chars().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < chars.len() {
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
            if i >= chars.len() {
                break;
            }
            let mut arg = String::new();
            let mut in_quotes = false;
            while i < chars.len() {
                let mut bs = 0;
                while i < chars.len() && chars[i] == '\\' {
                    bs += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    arg.extend(std::iter::repeat_n('\\', bs / 2));
                    if bs % 2 == 1 {
                        arg.push('"');
                    } else {
                        in_quotes = !in_quotes;
                    }
                    i += 1;
                    continue;
                }
                arg.extend(std::iter::repeat_n('\\', bs));
                if i >= chars.len() {
                    break;
                }
                if !in_quotes && (chars[i] == ' ' || chars[i] == '\t') {
                    break;
                }
                arg.push(chars[i]);
                i += 1;
            }
            out.push(arg);
        }
        out
    }

    #[test]
    fn quoted_arguments_round_trip() {
        let args = [
            "--root",
            r"D:\Ma clé USB\Écran été\",
            "win",
            "install",
            "--result-file",
            r"D:\Ma clé\logs\win 1.out",
            "a\"b",
            "",
            r"x\\y z\",
            "chrome",
        ];
        let line = quote_windows_args(&args);
        assert_eq!(split_like_windows(&line), args);
    }
}
