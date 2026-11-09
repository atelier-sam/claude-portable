//! ccp-core : noyau « comptes » de Claude Code Portable.
//! Le wizard bash affiche, ce noyau décide (statut, renouvellement, Trousseau, lancement).

pub mod api;
pub mod atomic;
pub mod cache;
pub mod creds;
pub mod env;
pub mod error;
pub mod http;
pub mod lock;
pub mod model;
pub mod oauth;
pub mod plan;
pub mod root;
pub mod status;
pub mod timefmt;
pub mod util;
