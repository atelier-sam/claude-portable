//! Valeurs ÉPINGLÉES des outils téléchargés et de l'hôte distant par défaut.
//!
//! Tout ce qui s'exécute sur le PC d'un client vient d'ici : version exacte, nom
//! de l'asset, empreinte SHA-256. Les empreintes sont celles du champ `digest` de
//! l'API GitHub des releases (vérifiées le 09/11/2026 contre
//! `repos/cloudflare/cloudflared/releases/tags/2026.10.7` et
//! `repos/PowerShell/Win32-OpenSSH/releases/tags/10.4.0.0p1-Preview`).
//! Monter une version = changer CE fichier et relire le digest, rien d'autre.

/// Version ÉPINGLÉE de cloudflared. Un cloudflared déjà installé sur le PC n'est
/// JAMAIS utilisé : sa version est inconnue et il peut être un binaire piégé.
pub const CLOUDFLARED_VERSION: &str = "2026.10.7";

/// Hôte du tunnel Cloudflare qui mène au Mac de Sam, et son utilisateur.
pub const DEFAULT_HOST: &str = "ssh-mac.atelier-sam.fr";
pub const DEFAULT_USER: &str = "samuelmuselet";

/// Clé d'hôte ed25519 du Mac, relevée côté Mac (`ssh-keyscan localhost`) : posée
/// dans le known_hosts du portable AVANT toute connexion, pour que la première
/// connexion ne repose pas sur « faire confiance au premier venu ».
pub const DEFAULT_HOST_KEY_TYPE: &str = "ssh-ed25519";
pub const DEFAULT_HOST_KEY_B64: &str =
    "AAAAC3NzaC1lZDI1NTE5AAAAIMAAM9fC7vMbxzgM9h2aj6VIGVpKTkCIDICNjQE5ArkM";

/// Serveur de téléchargement (surchargé par `CCP_DOWNLOAD_BASE` dans les tests).
pub const DEFAULT_DOWNLOAD_BASE: &str = "https://github.com";

/// Comment un asset se range sur le disque une fois téléchargé et vérifié.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packaging {
    /// Le fichier téléchargé EST le binaire.
    Raw,
    /// Archive `.tgz` qui contient le binaire sous ce nom.
    TarGz { member: &'static str },
    /// Archive `.zip` dont on extrait tout le contenu.
    Zip,
}

/// Un fichier publié sur une release GitHub, avec son empreinte attendue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asset {
    /// Dépôt GitHub `propriétaire/nom`.
    pub repo: &'static str,
    /// Étiquette (tag) de la release.
    pub tag: &'static str,
    /// Nom du fichier de la release.
    pub name: &'static str,
    /// SHA-256 du fichier téléchargé (l'archive, pas ce qu'elle contient).
    pub sha256: &'static str,
    pub packaging: Packaging,
    /// Garde-fou : un fichier plus gros que ça n'est pas celui qu'on attend.
    pub max_bytes: u64,
}

impl Asset {
    pub fn url(&self, base: &str) -> String {
        format!(
            "{}/{}/releases/download/{}/{}",
            base.trim_end_matches('/'),
            self.repo,
            self.tag,
            self.name
        )
    }
}

const CF_REPO: &str = "cloudflare/cloudflared";
const CF_MAX: u64 = 128 << 20;

const fn cf(name: &'static str, sha256: &'static str, packaging: Packaging) -> Asset {
    Asset {
        repo: CF_REPO,
        tag: CLOUDFLARED_VERSION,
        name,
        sha256,
        packaging,
        max_bytes: CF_MAX,
    }
}

const CF_WINDOWS_AMD64: Asset = cf(
    "cloudflared-windows-amd64.exe",
    "2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343",
    Packaging::Raw,
);
const CF_DARWIN_ARM64: Asset = cf(
    "cloudflared-darwin-arm64.tgz",
    "3586ccf397e98e5f437e60e7c307ca6ac463e110580503af8bb8e6f9ebf831bd",
    Packaging::TarGz {
        member: "cloudflared",
    },
);
const CF_DARWIN_AMD64: Asset = cf(
    "cloudflared-darwin-amd64.tgz",
    "02f3edfd87684dd5b705607688e4eb4b323f6e777b81e7b3a85af556aa356848",
    Packaging::TarGz {
        member: "cloudflared",
    },
);
const CF_LINUX_AMD64: Asset = cf(
    "cloudflared-linux-amd64",
    "1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872",
    Packaging::Raw,
);
const CF_LINUX_ARM64: Asset = cf(
    "cloudflared-linux-arm64",
    "3df43aedc9ff291d1735b5cb576cb97e0b157488796db2e32b28aecabb445775",
    Packaging::Raw,
);

/// OpenSSH portable pour Windows (sshd de `remote share`).
pub const OPENSSH_WIN_VERSION: &str = "10.4.0.0p1-Preview";
pub const OPENSSH_WIN: Asset = Asset {
    repo: "PowerShell/Win32-OpenSSH",
    tag: OPENSSH_WIN_VERSION,
    name: "OpenSSH-Win64.zip",
    sha256: "b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957",
    packaging: Packaging::Zip,
    max_bytes: 64 << 20,
};

/// Asset cloudflared d'une plateforme. `os` / `arch` : valeurs de `std::env::consts`.
/// Windows sur ARM exécute le binaire x64 (émulation) : il n'y a pas d'asset arm64.
pub fn cloudflared_asset(os: &str, arch: &str) -> Option<&'static Asset> {
    match (os, arch) {
        ("windows", "x86_64" | "aarch64") => Some(&CF_WINDOWS_AMD64),
        ("macos", "aarch64") => Some(&CF_DARWIN_ARM64),
        ("macos", "x86_64") => Some(&CF_DARWIN_AMD64),
        ("linux", "x86_64") => Some(&CF_LINUX_AMD64),
        ("linux", "aarch64") => Some(&CF_LINUX_ARM64),
        _ => None,
    }
}

/// Nom du dossier `<racine>/tools/cloudflared/<plateforme>/`.
pub fn platform_dir(os: &str, arch: &str) -> String {
    let os = if os == "macos" { "darwin" } else { os };
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}-{arch}")
}

/// La ligne `known_hosts` de l'hôte par défaut.
pub fn default_host_line() -> String {
    format!("{DEFAULT_HOST} {DEFAULT_HOST_KEY_TYPE} {DEFAULT_HOST_KEY_B64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pin_is_a_sha256_hex() {
        for a in [
            CF_WINDOWS_AMD64,
            CF_DARWIN_ARM64,
            CF_DARWIN_AMD64,
            CF_LINUX_AMD64,
            CF_LINUX_ARM64,
            OPENSSH_WIN,
        ] {
            assert_eq!(a.sha256.len(), 64, "{}", a.name);
            assert!(
                a.sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{}",
                a.name
            );
        }
    }

    #[test]
    fn urls_follow_the_github_release_layout() {
        let a = cloudflared_asset("macos", "aarch64").unwrap();
        assert_eq!(
            a.url(DEFAULT_DOWNLOAD_BASE),
            "https://github.com/cloudflare/cloudflared/releases/download/2026.10.7/cloudflared-darwin-arm64.tgz"
        );
        assert_eq!(
            OPENSSH_WIN.url("http://127.0.0.1:9/"),
            "http://127.0.0.1:9/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip"
        );
    }

    #[test]
    fn platforms_map_to_assets() {
        assert_eq!(
            cloudflared_asset("windows", "aarch64").unwrap().name,
            "cloudflared-windows-amd64.exe"
        );
        assert_eq!(
            cloudflared_asset("linux", "aarch64").unwrap().name,
            "cloudflared-linux-arm64"
        );
        assert!(cloudflared_asset("freebsd", "x86_64").is_none());
        assert_eq!(platform_dir("macos", "aarch64"), "darwin-arm64");
        assert_eq!(platform_dir("windows", "x86_64"), "windows-amd64");
    }

    #[test]
    fn default_host_line_is_a_valid_known_hosts_entry() {
        let l = default_host_line();
        let f: Vec<&str> = l.split(' ').collect();
        assert_eq!(f.len(), 3);
        assert_eq!(f[0], DEFAULT_HOST);
        assert_eq!(f[1], "ssh-ed25519");
        // Une clé ed25519 encodée commence par la longueur du type (11) puis « ssh-ed25519 ».
        assert!(f[2].starts_with("AAAAC3NzaC1lZDI1NTE5"));
    }
}
