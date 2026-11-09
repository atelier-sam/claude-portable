//! Erreurs du noyau et leur code de sortie.
//!
//! Les codes sont un CONTRAT avec le wizard bash (qui ne lit aucun JSON) :
//! 2 usage · 3 rien trouvé · 4 réseau · 5 profil déjà ouvert · 6 incohérence
//! détectée par `doctor` · 10 erreur interne. Les messages sont en français.

use std::fmt;

#[derive(Debug)]
pub enum CcpError {
    /// Arguments invalides (code 2).
    Usage(String),
    /// Rien à renvoyer, ce n'est pas une panne (code 3).
    NotFound(String),
    /// Réseau indisponible (code 4).
    Network(String),
    /// Le profil est déjà ouvert dans une autre fenêtre (code 5).
    SessionBusy(String),
    /// `doctor` a trouvé une divergence entre Claude et ccp-core (code 6).
    Divergence(String),
    /// Toute autre erreur interne (code 10).
    Internal(String),
}

impl CcpError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CcpError::Usage(_) => 2,
            CcpError::NotFound(_) => 3,
            CcpError::Network(_) => 4,
            CcpError::SessionBusy(_) => 5,
            CcpError::Divergence(_) => 6,
            CcpError::Internal(_) => 10,
        }
    }
}

impl fmt::Display for CcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CcpError::Usage(m)
            | CcpError::NotFound(m)
            | CcpError::Network(m)
            | CcpError::SessionBusy(m)
            | CcpError::Divergence(m)
            | CcpError::Internal(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for CcpError {}

impl From<std::io::Error> for CcpError {
    fn from(e: std::io::Error) -> Self {
        CcpError::Internal(format!("erreur d'entrée/sortie : {e}"))
    }
}

pub type Result<T> = std::result::Result<T, CcpError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_contract() {
        assert_eq!(CcpError::Usage("x".into()).exit_code(), 2);
        assert_eq!(CcpError::NotFound("x".into()).exit_code(), 3);
        assert_eq!(CcpError::Network("x".into()).exit_code(), 4);
        assert_eq!(CcpError::SessionBusy("x".into()).exit_code(), 5);
        assert_eq!(CcpError::Divergence("x".into()).exit_code(), 6);
        assert_eq!(CcpError::Internal("x".into()).exit_code(), 10);
    }
}
