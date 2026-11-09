//! Client HTTP derrière un trait : les sondes se testent sans réseau, le vrai
//! client (ureq + rustls + racines du SYSTÈME) ne sert que dans le binaire.
//!
//! Racines système plutôt que webpki-roots : les PC clients de l'atelier ont des
//! antivirus / proxys qui réinterceptent le TLS avec leur propre autorité.

use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Method {
    Get,
    PostJson,
}

/// Pas de `Debug` dérivé : `bearer` et `body` contiennent des jetons.
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub bearer: Option<SecretString>,
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<SecretString>,
    pub connect_timeout: Duration,
    pub total_timeout: Duration,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Debug)]
pub enum NetError {
    Timeout,
    Other(String),
}

impl NetError {
    pub fn message(&self) -> String {
        match self {
            NetError::Timeout => "délai dépassé".into(),
            NetError::Other(m) => m.clone(),
        }
    }
}

pub trait Http: Send + Sync {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, NetError>;
}

pub struct UreqHttp {
    agent: ureq::Agent,
}

/// 1 Mo suffit largement (profil, usage, jetons) ; au-delà c'est un faux serveur.
const MAX_BODY: u64 = 1 << 20;

impl UreqHttp {
    pub fn new() -> UreqHttp {
        let cfg = ureq::Agent::config_builder()
            // Les 4xx/5xx sont des réponses à classer, pas des erreurs de transport.
            .http_status_as_error(false)
            .user_agent(format!("ccp-core/{}", env!("CARGO_PKG_VERSION")))
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                    .build(),
            )
            .build();
        UreqHttp { agent: cfg.into() }
    }
}

impl Default for UreqHttp {
    fn default() -> Self {
        Self::new()
    }
}

impl Http for UreqHttp {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, NetError> {
        let map_err = |e: ureq::Error| match e {
            ureq::Error::Timeout(_) => NetError::Timeout,
            other => NetError::Other(other.to_string()),
        };
        let result = match req.method {
            Method::Get => {
                let mut b = self
                    .agent
                    .get(&req.url)
                    .config()
                    .timeout_connect(Some(req.connect_timeout))
                    .timeout_global(Some(req.total_timeout))
                    .build();
                if let Some(t) = &req.bearer {
                    b = b.header("Authorization", format!("Bearer {}", t.expose_secret()));
                }
                for (k, v) in &req.headers {
                    b = b.header(*k, v);
                }
                b.call()
            }
            Method::PostJson => {
                let mut b = self
                    .agent
                    .post(&req.url)
                    .config()
                    .timeout_connect(Some(req.connect_timeout))
                    .timeout_global(Some(req.total_timeout))
                    .build()
                    .header("Content-Type", "application/json");
                if let Some(t) = &req.bearer {
                    b = b.header("Authorization", format!("Bearer {}", t.expose_secret()));
                }
                for (k, v) in &req.headers {
                    b = b.header(*k, v);
                }
                let body = req
                    .body
                    .as_ref()
                    .map(|s| s.expose_secret().to_string())
                    .unwrap_or_default();
                b.send(body)
            }
        };
        let mut resp = result.map_err(map_err)?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_string()
            .map_err(map_err)?;
        Ok(HttpResponse { status, body })
    }
}
