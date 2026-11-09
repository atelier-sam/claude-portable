//! Réseau de `remote` : téléchargement d'outils en flux et sonde sans redirection.
//!
//! Même bibliothèque (ureq) et même réglage TLS (racines système) que le reste de
//! ccp-core ; ce qui change, c'est la FORME : un corps de plusieurs dizaines de Mo
//! passe par un flux vers le disque (le client des comptes plafonne à 1 Mo et lit
//! en mémoire), et la sonde Cloudflare doit VOIR la redirection 302, pas la suivre.
//! Le trait existe pour que les tests jouent sans réseau ni serveur réel.

use crate::http::{tls_config, user_agent, NetError};
use std::io::{Read, Write};
use std::time::Duration;

/// Ce que répond un serveur à un GET non authentifié, redirection non suivie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub status: u16,
    /// En-tête `Location` s'il existe.
    pub location: Option<String>,
    /// Début du corps (4 Ko au plus), pour y chercher une bannière.
    pub body_head: String,
}

pub trait Fetch: Send + Sync {
    /// Copie le corps de `url` dans `sink`, au plus `max_bytes` octets ; renvoie leur nombre.
    fn download(&self, url: &str, sink: &mut dyn Write, max_bytes: u64) -> Result<u64, NetError>;
    /// GET sans suivre les redirections.
    fn probe(&self, url: &str) -> Result<Probe, NetError>;
}

pub struct UreqFetch {
    download: ureq::Agent,
    probe: ureq::Agent,
}

/// Aller jusqu'au bout d'un binaire de 55 Mo sur une ligne lente prend du temps.
const DOWNLOAD_TOTAL: Duration = Duration::from_secs(15 * 60);
const CONNECT: Duration = Duration::from_secs(15);
const PROBE_TOTAL: Duration = Duration::from_secs(10);
const PROBE_BODY_MAX: u64 = 4096;

impl UreqFetch {
    pub fn new() -> UreqFetch {
        let download = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .user_agent(user_agent())
            .tls_config(tls_config())
            .timeout_connect(Some(CONNECT))
            .timeout_global(Some(DOWNLOAD_TOTAL))
            .build();
        let probe = ureq::Agent::config_builder()
            .http_status_as_error(false)
            // 0 redirection suivie, et ce n'est PAS une erreur : on lit le 302 lui-même.
            .max_redirects(0)
            .max_redirects_will_error(false)
            .user_agent(user_agent())
            .tls_config(tls_config())
            .timeout_connect(Some(CONNECT))
            .timeout_global(Some(PROBE_TOTAL))
            .build();
        UreqFetch {
            download: download.into(),
            probe: probe.into(),
        }
    }
}

impl Default for UreqFetch {
    fn default() -> Self {
        Self::new()
    }
}

fn map_err(e: ureq::Error) -> NetError {
    match e {
        ureq::Error::Timeout(_) => NetError::Timeout,
        other => NetError::Other(other.to_string()),
    }
}

impl Fetch for UreqFetch {
    fn download(&self, url: &str, sink: &mut dyn Write, max_bytes: u64) -> Result<u64, NetError> {
        let mut resp = self.download.get(url).call().map_err(map_err)?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(NetError::Other(format!("le serveur répond HTTP {status}")));
        }
        let mut reader = resp.body_mut().with_config().limit(max_bytes).reader();
        std::io::copy(&mut reader, sink)
            .map_err(|e| NetError::Other(format!("transfert interrompu : {e}")))
    }

    fn probe(&self, url: &str) -> Result<Probe, NetError> {
        let mut resp = self.probe.get(url).call().map_err(map_err)?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let mut head = Vec::new();
        let mut reader = resp.body_mut().as_reader().take(PROBE_BODY_MAX);
        // Un corps illisible ne change pas le verdict : le statut et `Location` suffisent.
        let _ = reader.read_to_end(&mut head);
        Ok(Probe {
            status,
            location,
            body_head: String::from_utf8_lossy(&head).into_owned(),
        })
    }
}
