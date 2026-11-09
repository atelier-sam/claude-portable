//! Cache de statut `<cfg>/.status.json` : DERNIÈRE BONNE VALEUR conservée.
//!
//! Une panne (réseau, 429) ne doit jamais effacer ce qu'on savait : le cache garde
//! séparément la dernière identité et le dernier usage valides, et le résultat de
//! la dernière tentative. Écriture atomique : deux `status` simultanés ne se
//! corrompent pas (le dernier gagne, aucun fichier à moitié écrit).

use crate::atomic::write_atomic;
use crate::creds::StoreKind;
use crate::model::{Identity, State, Usage};
use crate::root::ProfileDir;
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cache {
    pub v: u32,
    /// Empreinte du login auquel ce cache se rapporte.
    pub fp: String,
    pub store: StoreKind,
    /// Dernière tentative de sonde (secondes).
    pub checked_at: i64,
    pub state: Option<State>,
    pub detail: Option<String>,
    pub identity: Option<Identity>,
    pub usage: Option<Usage>,
}

impl Cache {
    pub fn empty(fp: &str, store: StoreKind) -> Cache {
        Cache {
            v: VERSION,
            fp: fp.to_string(),
            store,
            checked_at: 0,
            state: None,
            detail: None,
            identity: None,
            usage: None,
        }
    }
}

/// Cache illisible ou d'une autre version = pas de cache (jamais d'erreur).
pub fn load(p: &ProfileDir) -> Option<Cache> {
    let text = std::fs::read_to_string(p.status_file()).ok()?;
    let c: Cache = serde_json::from_str(&text).ok()?;
    (c.v == VERSION).then_some(c)
}

/// Meilleur effort : une clé en lecture seule ne doit pas faire échouer le statut.
pub fn store(p: &ProfileDir, c: &Cache) {
    if let Ok(s) = serde_json::to_string(c) {
        let _ = write_atomic(&p.status_file(), s.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::{PathStyle, Profile, Root};

    fn pdir(t: &tempfile::TempDir) -> ProfileDir {
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let p = r.profile(&Profile::parse("p").unwrap());
        std::fs::create_dir_all(&p.dir).unwrap();
        p
    }

    #[test]
    fn roundtrip_and_garbage_tolerance() {
        let t = tempfile::tempdir().unwrap();
        let p = pdir(&t);
        assert!(load(&p).is_none());
        let mut c = Cache::empty("abc", StoreKind::File);
        c.state = Some(State::Ok);
        store(&p, &c);
        let back = load(&p).unwrap();
        assert_eq!(back.fp, "abc");
        assert_eq!(back.state, Some(State::Ok));
        std::fs::write(p.status_file(), "{ cassé").unwrap();
        assert!(load(&p).is_none());
        std::fs::write(
            p.status_file(),
            r#"{"v":99,"fp":"x","store":"file","checked_at":0}"#,
        )
        .unwrap();
        assert!(load(&p).is_none());
    }
}
