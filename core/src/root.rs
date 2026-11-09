//! Racine du portable, profils, et construction UNIQUE des chemins.
//!
//! Pourquoi un seul constructeur : sous macOS le nom de service du Trousseau est
//! un hash du chemin EXACT donné à Claude dans `CLAUDE_CONFIG_DIR`. Si le wizard,
//! `run`, `purge` et `status` fabriquaient chacun leur chaîne (slash final,
//! canonicalisation, `/c/…` contre `C:\…`), on lirait un autre item que Claude.
//! Tout passe donc par [`Root::profile`].

use crate::error::{CcpError, Result};
use std::path::{Path, PathBuf};

/// Style de chemin. `Windows` sert aussi sur les autres OS dans les tests.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathStyle {
    Unix,
    Windows,
}

impl PathStyle {
    pub fn native() -> Self {
        if cfg!(windows) {
            PathStyle::Windows
        } else {
            PathStyle::Unix
        }
    }
    pub fn sep(self) -> char {
        match self {
            PathStyle::Unix => '/',
            PathStyle::Windows => '\\',
        }
    }
}

/// Convertit les formes de chemins vues dans le bash de Git for Windows en chemin
/// Windows natif : `/c/Users/x`, `/cygdrive/c/x`, `C:/Users/x`, `C:\Users\x`,
/// `//srv/share`. Une forme inconnue est rendue inchangée (on ne devine pas).
pub fn to_windows_path(input: &str) -> String {
    let b = input.as_bytes();
    // `\\?\C:\…` et `\\srv\share` : déjà en forme Windows.
    if input.starts_with("\\\\") {
        return input.to_string();
    }
    // `C:` ou `C:/…` ou `C:\…`
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        let drive = (b[0] as char).to_ascii_uppercase();
        return format!("{drive}:{}", input[2..].replace('/', "\\"));
    }
    // `//srv/share/x` → `\\srv\share\x`
    if input.starts_with("//") {
        return input.replace('/', "\\");
    }
    // `/cygdrive/c/x` ou `/c/x` (une lettre puis `/` ou fin de chaîne)
    for prefix in ["/cygdrive", ""] {
        if let Some(rest) = input.strip_prefix(prefix) {
            let rb = rest.as_bytes();
            if rb.len() >= 2
                && rb[0] == b'/'
                && rb[1].is_ascii_alphabetic()
                && (rb.len() == 2 || rb[2] == b'/')
            {
                let drive = (rb[1] as char).to_ascii_uppercase();
                let tail = &rest[2..];
                return format!("{drive}:{}", tail.replace('/', "\\"));
            }
        }
    }
    input.to_string()
}

/// Nom de profil validé : jamais de séparateur, de `..` ni de point initial.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Profile(String);

impl Profile {
    pub fn parse(s: &str) -> Result<Profile> {
        let bad = s.is_empty()
            || s.len() > 100
            || s.starts_with('.')
            || s.contains(['/', '\\', '\0', ':'])
            || s.chars().any(|c| c.is_control());
        if bad {
            return Err(CcpError::Usage(format!("nom de profil invalide : « {s} »")));
        }
        Ok(Profile(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Dossier d'un profil et tous les fichiers qu'on y pose.
#[derive(Clone, Debug)]
pub struct ProfileDir {
    pub name: Profile,
    /// La chaîne EXACTE donnée à Claude dans `CLAUDE_CONFIG_DIR` (et hashée
    /// pour le Trousseau).
    pub cfg: String,
    pub dir: PathBuf,
}

impl ProfileDir {
    pub fn credentials_file(&self) -> PathBuf {
        self.dir.join(".credentials.json")
    }
    pub fn token_file(&self) -> PathBuf {
        self.dir.join("oauth.token")
    }
    pub fn plan_file(&self) -> PathBuf {
        self.dir.join("plan")
    }
    pub fn claude_json(&self) -> PathBuf {
        self.dir.join(".claude.json")
    }
    pub fn status_file(&self) -> PathBuf {
        self.dir.join(".status.json")
    }
    pub fn session_lock(&self) -> PathBuf {
        self.dir.join(".ccp-session.lock")
    }
    pub fn renewing_marker(&self) -> PathBuf {
        self.dir.join(".ccp-renewing")
    }
    pub fn pending_journal(&self) -> PathBuf {
        self.dir.join(".ccp-pending")
    }
    pub fn revoked_marker(&self) -> PathBuf {
        self.dir.join(".ccp-revoked")
    }
}

#[derive(Clone, Debug)]
pub struct Root {
    raw: String,
    style: PathStyle,
}

const PROFILES_DIR: &str = "config";

impl Root {
    /// `raw` est pris TEL QUEL (ni canonicalisation, ni résolution de lien) : seul
    /// le slash final est retiré, et la forme MSYS convertie sous Windows.
    pub fn new(raw: &str, style: PathStyle) -> Result<Root> {
        if raw.trim().is_empty() {
            return Err(CcpError::Usage("racine du portable vide".into()));
        }
        let converted = if style == PathStyle::Windows {
            to_windows_path(raw)
        } else {
            raw.to_string()
        };
        let trimmed = converted.trim_end_matches(['/', '\\']);
        Ok(Root {
            raw: trimmed.to_string(),
            style,
        })
    }

    /// `--root` > `$CCP_ROOT` > dossier parent du dossier `bin/` qui contient
    /// l'exécutable (`<root>/bin/<plat>/ccp-core`).
    pub fn resolve(arg: Option<&str>) -> Result<Root> {
        let style = PathStyle::native();
        if let Some(a) = arg {
            return Root::new(a, style);
        }
        if let Ok(v) = std::env::var("CCP_ROOT") {
            if !v.trim().is_empty() {
                return Root::new(&v, style);
            }
        }
        let exe = std::env::current_exe().map_err(|e| {
            CcpError::Usage(format!(
                "racine introuvable (--root absent) : exécutable illisible : {e}"
            ))
        })?;
        for anc in exe.ancestors().skip(1) {
            if anc.file_name().is_some_and(|n| n == "bin") {
                if let Some(parent) = anc.parent() {
                    return Root::new(&parent.to_string_lossy(), style);
                }
            }
        }
        Err(CcpError::Usage(
            "racine du portable introuvable : passe --root <dossier>, ou définis CCP_ROOT, \
             ou lance ccp-core depuis <racine>/bin/<plateforme>/"
                .into(),
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
    pub fn path(&self) -> PathBuf {
        PathBuf::from(&self.raw)
    }
    pub fn style(&self) -> PathStyle {
        self.style
    }

    /// LE constructeur de chemin de profil (cf. documentation du module).
    pub fn profile(&self, name: &Profile) -> ProfileDir {
        let sep = self.style.sep();
        let cfg = format!("{}{sep}{PROFILES_DIR}{sep}{}", self.raw, name.as_str());
        ProfileDir {
            name: name.clone(),
            dir: PathBuf::from(&cfg),
            cfg,
        }
    }

    /// Profils présents sur disque, triés (numérique d'abord : 1, 2, 10, puis noms).
    pub fn list_profiles(&self) -> Vec<Profile> {
        let dir = format!("{}{}{PROFILES_DIR}", self.raw, self.style.sep());
        let mut out: Vec<Profile> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| !n.starts_with('.'))
            .filter_map(|n| Profile::parse(&n).ok())
            .collect();
        out.sort_by_key(|p| match p.as_str().parse::<u64>() {
            Ok(n) => (0, n, String::new()),
            Err(_) => (1, 0, p.as_str().to_string()),
        });
        out
    }

    /// Profil actif : `$CC_PROFILE` > fichier `ACTIVE` > "1" (comme le wizard).
    pub fn active_profile(&self) -> String {
        if let Ok(v) = std::env::var("CC_PROFILE") {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_string();
            }
        }
        let f = Path::new(&self.raw).join("ACTIVE");
        if let Ok(s) = std::fs::read_to_string(f) {
            let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
            if !s.is_empty() {
                return s;
            }
        }
        "1".to_string()
    }
}

/// Nom de plateforme des binaires CLAUDE (même nomenclature que `cc_detect_platform`).
pub fn claude_platform() -> String {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(windows) {
        "win32"
    } else {
        "linux"
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let mut plat = format!("{os}-{arch}");
    if os == "linux" && is_musl_system() {
        plat.push_str("-musl");
    }
    plat
}

fn is_musl_system() -> bool {
    std::fs::read_dir("/lib")
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("ld-musl-"))
}

pub fn claude_exe_name() -> &'static str {
    if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_slash_is_removed_and_cfg_built_once() {
        let r = Root::new("/Volumes/Cle/portable/", PathStyle::Unix).unwrap();
        let p = Profile::parse("2").unwrap();
        assert_eq!(r.profile(&p).cfg, "/Volumes/Cle/portable/config/2");
        let r = Root::new("/Volumes/Cle/portable///", PathStyle::Unix).unwrap();
        assert_eq!(r.profile(&p).cfg, "/Volumes/Cle/portable/config/2");
    }

    #[test]
    fn root_slash_is_kept_logically() {
        let r = Root::new("/", PathStyle::Unix).unwrap();
        assert_eq!(r.profile(&Profile::parse("a").unwrap()).cfg, "/config/a");
    }

    #[test]
    fn spaces_and_accents_are_verbatim() {
        let r = Root::new("/Volumes/Ma clé/Écran été", PathStyle::Unix).unwrap();
        assert_eq!(
            r.profile(&Profile::parse("p").unwrap()).cfg,
            "/Volumes/Ma clé/Écran été/config/p"
        );
    }

    #[test]
    fn windows_forms_are_all_accepted() {
        assert_eq!(
            to_windows_path("/c/Users/x y/portable"),
            "C:\\Users\\x y\\portable"
        );
        assert_eq!(to_windows_path("/cygdrive/d/cle"), "D:\\cle");
        assert_eq!(to_windows_path("C:/Users/x"), "C:\\Users\\x");
        assert_eq!(to_windows_path("c:\\Users\\x"), "C:\\Users\\x");
        assert_eq!(to_windows_path("/d"), "D:");
        assert_eq!(to_windows_path("//srv/share/x"), "\\\\srv\\share\\x");
        assert_eq!(to_windows_path("\\\\srv\\share\\x"), "\\\\srv\\share\\x");
        assert_eq!(to_windows_path("/tmp/x"), "/tmp/x");
        assert_eq!(to_windows_path("/cx/y"), "/cx/y");
    }

    #[test]
    fn windows_cfg_uses_backslashes() {
        let r = Root::new("/c/Users/Sam/Claude Portable/", PathStyle::Windows).unwrap();
        assert_eq!(
            r.profile(&Profile::parse("1").unwrap()).cfg,
            "C:\\Users\\Sam\\Claude Portable\\config\\1"
        );
        let r = Root::new("C:/Users/Sam/", PathStyle::Windows).unwrap();
        assert_eq!(
            r.profile(&Profile::parse("1").unwrap()).cfg,
            "C:\\Users\\Sam\\config\\1"
        );
        let r = Root::new("D:\\", PathStyle::Windows).unwrap();
        assert_eq!(
            r.profile(&Profile::parse("1").unwrap()).cfg,
            "D:\\config\\1"
        );
    }

    #[test]
    fn profile_names_are_validated() {
        for bad in ["", ".", "..", ".x", "a/b", "a\\b", "a:b", "a\0b"] {
            assert!(Profile::parse(bad).is_err(), "{bad:?}");
        }
        for good in ["1", "leslapinsdesamuel", "mon compte", "a.b", "é"] {
            assert!(Profile::parse(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn list_profiles_sorts_numbers_first_and_skips_hidden() {
        let t = tempfile::tempdir().unwrap();
        for d in ["10", "2", "1", "zeta", "alpha", ".cache", "._junk"] {
            std::fs::create_dir_all(t.path().join("config").join(d)).unwrap();
        }
        std::fs::write(t.path().join("config").join("fichier"), b"x").unwrap();
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let names: Vec<String> = r.list_profiles().iter().map(|p| p.to_string()).collect();
        assert_eq!(names, ["1", "2", "10", "alpha", "zeta"]);
    }

    #[test]
    fn active_profile_reads_file() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("ACTIVE"), "work \n").unwrap();
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        if std::env::var("CC_PROFILE").is_err() {
            assert_eq!(r.active_profile(), "work");
        }
    }
}
