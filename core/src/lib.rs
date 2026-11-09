//! ccp-core : noyau « comptes » de Claude Code Portable.
//! Le wizard bash affiche, ce noyau décide (statut, renouvellement, Trousseau, lancement).

pub mod api;
pub mod atomic;
pub mod cache;
pub mod claude_cli;
pub mod cli;
pub mod creds;
pub mod discover;
pub mod doctor;
pub mod env;
pub mod error;
pub mod http;
pub mod lock;
pub mod model;
pub mod oauth;
pub mod plan;
pub mod purge;
pub mod recommend;
pub mod render;
pub mod root;
pub mod run;
pub mod status;
pub mod timefmt;
pub mod util;
