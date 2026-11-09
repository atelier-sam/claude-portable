//! Renouvellement des jetons, conçu pour ne JAMAIS perdre un refresh token.
//!
//! Le refresh token TOURNE : dès que le serveur répond 200, l'ancien est mort. Si
//! on plante entre la réponse et l'écriture, la session de Claude est perdue.
//! D'où :
//! 1. try-lock du verrou de session (jamais pendant une session `run`) ;
//! 2. relecture du magasin APRÈS le verrou (un autre processus a pu renouveler) ;
//! 3. journal write-ahead `.ccp-pending` (nouveaux jetons, 600) écrit AVANT le
//!    magasin, rejoué au démarrage de toute commande, puis effacé. Sa place est
//!    RÉSERVÉE (créée et fsync-ée) AVANT le POST : si le volume refuse l'écriture
//!    (plein, lecture seule), on n'appelle pas le serveur, donc le refresh token
//!    n'est pas dépensé. Si le journal échoue quand même après la réponse, on
//!    tente malgré tout d'écrire le magasin avant de rendre l'erreur ;
//! 4. relecture juste avant écriture + écriture dans le MÊME magasin, clés
//!    inconnues préservées ;
//! 5. après un refus définitif (400/401), marqueur `.ccp-revoked` : plus aucune
//!    tentative tant que le login n'a pas changé (sinon on martèle un jeton mort).
//!
//! Seuls les profils du portable sont renouvelés : `discover` ne passe jamais ici.

use crate::api::{Api, RefreshResult};
use crate::atomic::{write_atomic, Reserved, RESERVE_BYTES};
use crate::creds::{read_login, write_login, CredBlob, Loaded};
use crate::env::{now_ms, Env};
use crate::lock::{self, Acquire, RenewingMark, SessionGuard};
use crate::root::ProfileDir;
use crate::util::fingerprint;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Marge avant l'expiration réelle : on renouvelle un peu avant.
pub const EXPIRY_MARGIN_MS: i64 = 60_000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trigger {
    /// `expiresAt` dépassé (ou dans moins d'une minute).
    Expired,
    /// Le serveur a répondu 401 au jeton d'accès (une seule fois par sonde).
    Unauthorized,
}

#[derive(Debug, PartialEq)]
pub enum Renewal {
    Renewed,
    /// Un autre processus a déjà renouvelé, ou le login a changé : rien à faire.
    AlreadyFresh,
    Revoked,
    /// Une session ou un autre renouvellement tient le verrou.
    SessionBusy,
    Unreachable(String),
    Failed(String),
}

pub fn expired(blob: &CredBlob, now_ms: i64) -> bool {
    blob.expires_at_ms()
        .is_some_and(|e| e <= now_ms + EXPIRY_MARGIN_MS)
}

// ---------------------------------------------------------------- marqueur

#[derive(Serialize, Deserialize)]
struct RevokedMarker {
    fp: String,
    ts: i64,
}

pub fn mark_revoked(p: &ProfileDir, fp: &str) {
    if let Ok(s) = serde_json::to_string(&RevokedMarker {
        fp: fp.to_string(),
        ts: now_ms(),
    }) {
        let _ = write_atomic(&p.revoked_marker(), s.as_bytes());
    }
}

/// Le login actuel (empreinte `fp`) est-il marqué révoqué ? Un marqueur d'un
/// ancien login (l'utilisateur s'est reconnecté depuis) est effacé.
pub fn is_revoked(p: &ProfileDir, fp: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(p.revoked_marker()) else {
        return false;
    };
    match serde_json::from_str::<RevokedMarker>(&text) {
        Ok(m) if m.fp == fp => true,
        _ => {
            let _ = std::fs::remove_file(p.revoked_marker());
            false
        }
    }
}

// ----------------------------------------------------------------- journal

#[derive(Serialize, Deserialize)]
struct Pending {
    v: u32,
    /// Empreinte de la lignée AVANT renouvellement.
    based_on: String,
    /// Empreinte du nouveau jeton d'accès (pour reconnaître « déjà appliqué »).
    new_access_fp: String,
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: i64,
    ts: i64,
}

#[derive(Debug, PartialEq)]
pub enum Replay {
    Nothing,
    Applied,
    /// Journal périmé (déjà appliqué, ou le login a changé depuis) : effacé.
    Discarded,
    /// Session en cours : on ne touche pas au magasin, on réessaiera.
    Busy,
    Failed(String),
}

/// Rejoue le journal si besoin. À appeler au démarrage de toute commande `accounts`.
pub fn replay_pending(env: &Env, p: &ProfileDir) -> Replay {
    if !p.pending_journal().exists() {
        return Replay::Nothing;
    }
    match lock::try_acquire(p) {
        Acquire::Got(g) => replay_pending_locked(env, p, &g),
        Acquire::Busy => Replay::Busy,
        Acquire::Unsupported(m) => Replay::Failed(m),
    }
}

/// Variante pour qui TIENT déjà le verrou de session (`run`) : la preuve est le
/// paramètre `_guard`.
pub fn replay_pending_locked(env: &Env, p: &ProfileDir, _guard: &SessionGuard) -> Replay {
    let Ok(text) = std::fs::read_to_string(p.pending_journal()) else {
        return Replay::Nothing;
    };
    let Ok(j) = serde_json::from_str::<Pending>(&text) else {
        // Journal illisible : le garder ne sert à rien, il ne se réparera pas.
        let _ = std::fs::remove_file(p.pending_journal());
        return Replay::Discarded;
    };
    let cur = match read_login(env, p) {
        Ok(Some(l)) => l,
        // Le login a disparu (déconnexion, Trousseau vidé) : le journal est orphelin.
        Ok(None) => {
            let _ = std::fs::remove_file(p.pending_journal());
            return Replay::Discarded;
        }
        Err(e) => return Replay::Failed(e.to_string()),
    };
    let cur_access_fp = cur
        .blob
        .access_token()
        .map(|t| fingerprint(t.expose_secret()));
    if cur_access_fp.as_deref() == Some(j.new_access_fp.as_str()) {
        let _ = std::fs::remove_file(p.pending_journal());
        return Replay::Discarded;
    }
    if cur.blob.fingerprint() != j.based_on {
        let _ = std::fs::remove_file(p.pending_journal());
        return Replay::Discarded;
    }
    let mut nb = cur.blob.clone();
    nb.apply_renewal(&j.access_token, j.refresh_token.as_deref(), j.expires_at);
    match write_login(env, p, &cur, &nb) {
        Ok(()) => {
            let _ = std::fs::remove_file(p.pending_journal());
            Replay::Applied
        }
        Err(e) => Replay::Failed(e.to_string()),
    }
}

// ------------------------------------------------------------- renouvellement

/// Incrémente le compteur « section critique » pendant le POST + l'écriture :
/// l'appelant de la sonde globale n'abandonne pas un thread à ce moment-là.
struct Critical<'a>(&'a AtomicUsize);

impl<'a> Critical<'a> {
    fn enter(c: &'a AtomicUsize) -> Self {
        c.fetch_add(1, Ordering::SeqCst);
        Critical(c)
    }
}

impl Drop for Critical<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// POINT D'INJECTION DE PANNE (tests uniquement). Si `var` contient un chemin,
/// y pose un fichier puis s'endort : le test sait que le journal est écrit, que
/// le magasin ne l'est PAS encore, et tue le processus à cet instant précis.
/// Sans la variable (production) c'est un `if` sans effet.
fn fault_point(var: &str) {
    if let Some(path) = std::env::var_os(var) {
        let _ = std::fs::write(path, b"arret");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

/// Renouvelle le login de `p`. `seen` est le login tel que la sonde l'a lu
/// (pour reconnaître qu'un autre processus a déjà fait le travail).
pub fn renew(
    env: &Env,
    api: &Api,
    p: &ProfileDir,
    seen: &Loaded,
    trigger: Trigger,
    critical: &AtomicUsize,
) -> Renewal {
    let _guard = match lock::try_acquire(p) {
        Acquire::Got(g) => g,
        Acquire::Busy => return Renewal::SessionBusy,
        Acquire::Unsupported(m) => return Renewal::Failed(m),
    };
    let _mark = RenewingMark::set(p);
    let _crit = Critical::enter(critical);

    // Un renouvellement interrompu avant nous ? On le rejoue d'abord.
    if p.pending_journal().exists() {
        replay_pending_locked(env, p, &_guard);
    }

    // 2. Relecture sous verrou.
    let cur = match read_login(env, p) {
        Ok(Some(l)) if l.blob.has_login() => l,
        Ok(_) => return Renewal::Failed("aucun login à renouveler".into()),
        Err(e) => return Renewal::Failed(e.to_string()),
    };
    let fp = cur.blob.fingerprint();
    match trigger {
        Trigger::Expired if !expired(&cur.blob, now_ms()) => return Renewal::AlreadyFresh,
        Trigger::Unauthorized => {
            let a = |l: &Loaded| {
                l.blob
                    .access_token()
                    .map(|t| fingerprint(t.expose_secret()))
            };
            if a(&cur) != a(seen) {
                return Renewal::AlreadyFresh;
            }
        }
        _ => {}
    }
    if is_revoked(p, &fp) {
        return Renewal::Revoked;
    }
    let Some(refresh) = cur.blob.refresh_token() else {
        // Pas de refresh token (jeton d'inférence seul) : rien à tenter.
        return Renewal::Revoked;
    };

    // 4bis. Place du journal, AVANT de dépenser le refresh token : le serveur le
    // tue dès qu'il répond 200, sans retour possible.
    let reservation = match Reserved::create(&p.pending_reserve(), RESERVE_BYTES) {
        Ok(r) => r,
        Err(e) => {
            return Renewal::Failed(format!(
                "journal de renouvellement impossible à réserver ({e}) : serveur NON appelé, jeton conservé"
            ))
        }
    };

    // 5. Appel au serveur.
    match api.refresh(&refresh) {
        RefreshResult::Renewed {
            access,
            refresh: new_refresh,
            expires_in_s,
        } => {
            let expires_at = now_ms() + expires_in_s * 1000;
            let journal = Pending {
                v: 1,
                based_on: fp.clone(),
                new_access_fp: fingerprint(access.expose_secret()),
                access_token: access.expose_secret().to_string(),
                refresh_token: new_refresh.as_ref().map(|r| r.expose_secret().to_string()),
                expires_at,
                ts: now_ms(),
            };
            // WAL : si l'écriture du magasin échoue ou si on meurt ici, le journal
            // contient les seuls jetons valides.
            let wrote = serde_json::to_string(&journal)
                .map_err(|e| e.to_string())
                .and_then(|s| {
                    reservation
                        .commit(s.as_bytes(), &p.pending_journal())
                        .map_err(|e| e.to_string())
                });
            // Le journal a échoué MALGRÉ la réservation (disque retiré, erreur
            // d'E/S…) : les nouveaux jetons n'existent plus qu'en mémoire. On ne
            // rend PAS la main tout de suite : le magasin est leur dernière chance.
            let journal_err = wrote.err();
            fault_point("CCP_FAULT_AFTER_JOURNAL");
            // 4. Relecture juste avant écriture.
            let latest_owned;
            let latest: &Loaded = match read_login(env, p) {
                Ok(Some(l)) => {
                    latest_owned = l;
                    &latest_owned
                }
                Ok(None) => {
                    let _ = std::fs::remove_file(p.pending_journal());
                    return Renewal::Failed("le login a disparu pendant le renouvellement".into());
                }
                // Journal absent ET relecture impossible : on écrit à partir du login
                // lu sous verrou il y a un instant plutôt que de perdre les jetons.
                Err(_) if journal_err.is_some() => &cur,
                Err(e) => return Renewal::Failed(format!("{e} (jetons gardés dans .ccp-pending)")),
            };
            if latest.blob.fingerprint() != fp {
                // Un login plus récent s'est écrit entre-temps : le nôtre est obsolète.
                let _ = std::fs::remove_file(p.pending_journal());
                return Renewal::AlreadyFresh;
            }
            let mut nb = latest.blob.clone();
            nb.apply_renewal(
                access.expose_secret(),
                new_refresh.as_ref().map(|r| r.expose_secret()),
                expires_at,
            );
            match (write_login(env, p, latest, &nb), journal_err) {
                (Ok(()), _) => {
                    let _ = std::fs::remove_file(p.pending_journal());
                    Renewal::Renewed
                }
                (Err(e), None) => Renewal::Failed(format!("{e} (jetons gardés dans .ccp-pending)")),
                (Err(e), Some(je)) => Renewal::Failed(format!(
                    "{e} ET journal impossible ({je}) : les nouveaux jetons sont PERDUS, il faut reconnecter ce compte"
                )),
            }
        }
        RefreshResult::Revoked(_) => {
            mark_revoked(p, &fp);
            Renewal::Revoked
        }
        RefreshResult::Rejected(m) => Renewal::Failed(m),
        RefreshResult::Transient(m) => Renewal::Unreachable(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Http, HttpRequest, HttpResponse, NetError};
    use crate::root::{PathStyle, Profile, Root};
    use std::sync::{Arc, Mutex};

    /// Faux transport scripté : renvoie les réponses dans l'ordre et mémorise les requêtes.
    struct Scripted {
        replies: Mutex<Vec<Result<HttpResponse, NetError>>>,
        seen: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(replies: Vec<Result<HttpResponse, NetError>>) -> Arc<Scripted> {
            Arc::new(Scripted {
                replies: Mutex::new(replies),
                seen: Mutex::new(vec![]),
            })
        }
    }

    impl Http for Scripted {
        fn send(&self, req: &HttpRequest) -> Result<HttpResponse, NetError> {
            self.seen.lock().unwrap().push(req.url.clone());
            let mut r = self.replies.lock().unwrap();
            if r.is_empty() {
                return Err(NetError::Other("plus de réponse scriptée".into()));
            }
            r.remove(0)
        }
    }

    fn ok(status: u16, body: &str) -> Result<HttpResponse, NetError> {
        Ok(HttpResponse {
            status,
            body: body.into(),
        })
    }

    const EXPIRED: &str = r#"{"claudeAiOauth":{"accessToken":"AT1","refreshToken":"RT1","expiresAt":1000,"scopes":["user:profile"],"subscriptionType":"max"},"mcpOAuth":{"s":{"accessToken":"M"}}}"#;

    struct Fx {
        _t: tempfile::TempDir,
        env: Env,
        p: ProfileDir,
    }

    fn fx(creds: &str) -> Fx {
        let t = tempfile::tempdir().unwrap();
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let p = r.profile(&Profile::parse("p").unwrap());
        std::fs::create_dir_all(&p.dir).unwrap();
        std::fs::write(p.credentials_file(), creds).unwrap();
        let env = Env::for_tests(t.path().to_path_buf());
        Fx { _t: t, env, p }
    }

    fn api(h: Arc<Scripted>) -> Api {
        Api::new(h, "http://x", "http://x/token")
    }

    fn load(f: &Fx) -> Loaded {
        read_login(&f.env, &f.p).unwrap().unwrap()
    }

    #[test]
    fn rotation_is_written_preserving_other_keys_and_journal_is_removed() {
        let f = fx(EXPIRED);
        let h = Scripted::new(vec![ok(
            200,
            r#"{"access_token":"AT2","refresh_token":"RT2","expires_in":3600}"#,
        )]);
        let seen = load(&f);
        let r = renew(
            &f.env,
            &api(h),
            &f.p,
            &seen,
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert_eq!(r, Renewal::Renewed);
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(f.p.credentials_file()).unwrap())
                .unwrap();
        assert_eq!(v["claudeAiOauth"]["accessToken"], "AT2");
        assert_eq!(v["claudeAiOauth"]["refreshToken"], "RT2");
        assert_eq!(v["claudeAiOauth"]["subscriptionType"], "max");
        assert_eq!(v["mcpOAuth"]["s"]["accessToken"], "M");
        assert!(v["claudeAiOauth"]["expiresAt"].as_i64().unwrap() > now_ms());
        assert!(!f.p.pending_journal().exists());
        assert!(!f.p.pending_reserve().exists(), "réservation oubliée");
        assert!(!f.p.renewing_marker().exists());
    }

    #[test]
    fn no_renewal_while_a_session_holds_the_lock() {
        let f = fx(EXPIRED);
        let Acquire::Got(_session) = lock::try_acquire(&f.p) else {
            panic!()
        };
        let h = Scripted::new(vec![]);
        let seen = load(&f);
        let r = renew(
            &f.env,
            &api(h.clone()),
            &f.p,
            &seen,
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert_eq!(r, Renewal::SessionBusy);
        assert!(h.seen.lock().unwrap().is_empty(), "aucune requête réseau");
    }

    #[test]
    fn revoked_writes_marker_and_stops_retrying() {
        let f = fx(EXPIRED);
        let h = Scripted::new(vec![ok(400, r#"{"error":"invalid_grant"}"#)]);
        let seen = load(&f);
        let r = renew(
            &f.env,
            &api(h),
            &f.p,
            &seen,
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert_eq!(r, Renewal::Revoked);
        assert!(f.p.revoked_marker().exists());
        // 2e tentative : aucune requête (le scripté est vide -> une requête échouerait autrement)
        let h2 = Scripted::new(vec![ok(
            200,
            r#"{"access_token":"X","refresh_token":"Y","expires_in":1}"#,
        )]);
        let r2 = renew(
            &f.env,
            &api(h2.clone()),
            &f.p,
            &load(&f),
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert_eq!(r2, Renewal::Revoked);
        assert!(h2.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn new_login_clears_the_revoked_marker() {
        let f = fx(EXPIRED);
        mark_revoked(&f.p, &load(&f).blob.fingerprint());
        assert!(is_revoked(&f.p, &load(&f).blob.fingerprint()));
        // l'utilisateur se reconnecte : nouvelle lignée
        std::fs::write(f.p.credentials_file(), EXPIRED.replace("RT1", "RT9")).unwrap();
        assert!(!is_revoked(&f.p, &load(&f).blob.fingerprint()));
        assert!(!f.p.revoked_marker().exists());
    }

    #[test]
    fn rejected_by_our_bug_does_not_mark_revoked() {
        let f = fx(EXPIRED);
        let h = Scripted::new(vec![ok(400, r#"{"error":"invalid_client"}"#)]);
        let r = renew(
            &f.env,
            &api(h),
            &f.p,
            &load(&f),
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert!(matches!(r, Renewal::Failed(_)));
        assert!(!f.p.revoked_marker().exists());
    }

    #[test]
    fn network_failure_is_unreachable_and_leaves_store_untouched() {
        let f = fx(EXPIRED);
        let h = Scripted::new(vec![Err(NetError::Timeout)]);
        let r = renew(
            &f.env,
            &api(h),
            &f.p,
            &load(&f),
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert!(matches!(r, Renewal::Unreachable(_)));
        assert_eq!(
            std::fs::read_to_string(f.p.credentials_file()).unwrap(),
            EXPIRED
        );
    }

    #[test]
    fn already_renewed_by_someone_else_makes_no_request() {
        let f = fx(EXPIRED);
        let seen = load(&f);
        // un autre processus a renouvelé entre-temps
        let fresh = EXPIRED.replace(
            "\"expiresAt\":1000",
            &format!("\"expiresAt\":{}", now_ms() + 3_600_000),
        );
        std::fs::write(f.p.credentials_file(), fresh).unwrap();
        let h = Scripted::new(vec![]);
        let r = renew(
            &f.env,
            &api(h.clone()),
            &f.p,
            &seen,
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert_eq!(r, Renewal::AlreadyFresh);
        assert!(h.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn unauthorized_trigger_skips_if_store_changed() {
        let f = fx(EXPIRED);
        let seen = load(&f);
        std::fs::write(f.p.credentials_file(), EXPIRED.replace("AT1", "AT7")).unwrap();
        let h = Scripted::new(vec![]);
        let r = renew(
            &f.env,
            &api(h),
            &f.p,
            &seen,
            Trigger::Unauthorized,
            &AtomicUsize::new(0),
        );
        assert_eq!(r, Renewal::AlreadyFresh);
    }

    #[test]
    fn crash_between_response_and_store_is_recovered_by_the_journal() {
        let f = fx(EXPIRED);
        // On simule la mort juste après l'écriture du journal : journal présent, magasin ancien.
        let j = Pending {
            v: 1,
            based_on: load(&f).blob.fingerprint(),
            new_access_fp: fingerprint("AT2"),
            access_token: "AT2".into(),
            refresh_token: Some("RT2".into()),
            expires_at: now_ms() + 3_600_000,
            ts: now_ms(),
        };
        std::fs::write(f.p.pending_journal(), serde_json::to_string(&j).unwrap()).unwrap();
        assert_eq!(replay_pending(&f.env, &f.p), Replay::Applied);
        let l = load(&f);
        assert_eq!(l.blob.refresh_token().unwrap().expose_secret(), "RT2");
        assert_eq!(l.blob.access_token().unwrap().expose_secret(), "AT2");
        assert!(!f.p.pending_journal().exists());
        // rejouer deux fois est inoffensif
        assert_eq!(replay_pending(&f.env, &f.p), Replay::Nothing);
    }

    #[test]
    fn journal_for_an_older_lineage_is_discarded_not_applied() {
        let f = fx(EXPIRED);
        let j = Pending {
            v: 1,
            based_on: "autre-lignee".into(),
            new_access_fp: fingerprint("ATZ"),
            access_token: "ATZ".into(),
            refresh_token: Some("RTZ".into()),
            expires_at: 1,
            ts: 1,
        };
        std::fs::write(f.p.pending_journal(), serde_json::to_string(&j).unwrap()).unwrap();
        assert_eq!(replay_pending(&f.env, &f.p), Replay::Discarded);
        assert_eq!(load(&f).blob.access_token().unwrap().expose_secret(), "AT1");
    }

    #[test]
    fn journal_is_left_alone_while_a_session_runs() {
        let f = fx(EXPIRED);
        std::fs::write(f.p.pending_journal(), "{}").unwrap();
        let Acquire::Got(_g) = lock::try_acquire(&f.p) else {
            panic!()
        };
        assert_eq!(replay_pending(&f.env, &f.p), Replay::Busy);
        assert!(f.p.pending_journal().exists());
    }

    #[test]
    fn corrupt_journal_is_dropped() {
        let f = fx(EXPIRED);
        std::fs::write(f.p.pending_journal(), "pas json").unwrap();
        assert_eq!(replay_pending(&f.env, &f.p), Replay::Discarded);
        assert!(!f.p.pending_journal().exists());
    }

    #[test]
    fn critical_counter_returns_to_zero() {
        let f = fx(EXPIRED);
        let c = AtomicUsize::new(0);
        let h = Scripted::new(vec![ok(500, "")]);
        let _ = renew(&f.env, &api(h), &f.p, &load(&f), Trigger::Expired, &c);
        assert_eq!(c.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expiry_margin() {
        let b =
            CredBlob::parse(r#"{"claudeAiOauth":{"accessToken":"a","expiresAt":100000}}"#).unwrap();
        assert!(expired(&b, 100_000));
        assert!(expired(&b, 40_001));
        assert!(!expired(&b, 39_000));
    }

    /// Faux transport qui exécute un effet de bord juste avant de répondre : pour
    /// simuler « le volume tombe entre la réservation et la fin du POST ».
    struct Hook {
        before_reply: Box<dyn Fn() + Send + Sync>,
        reply: String,
        calls: Mutex<usize>,
    }

    impl Http for Hook {
        fn send(&self, _req: &HttpRequest) -> Result<HttpResponse, NetError> {
            *self.calls.lock().unwrap() += 1;
            (self.before_reply)();
            Ok(HttpResponse {
                status: 200,
                body: self.reply.clone(),
            })
        }
    }

    const NEW_TOKENS: &str = r#"{"access_token":"AT2","refresh_token":"RT2","expires_in":3600}"#;

    #[test]
    fn no_request_is_sent_when_the_journal_cannot_be_reserved_first() {
        let f = fx(EXPIRED);
        // Un répertoire occupe la place du journal : le volume « refuse » l'écriture.
        std::fs::create_dir(f.p.pending_reserve()).unwrap();
        let h = Scripted::new(vec![ok(200, NEW_TOKENS)]);
        let r = renew(
            &f.env,
            &api(h.clone()),
            &f.p,
            &load(&f),
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        match r {
            Renewal::Failed(m) => assert!(m.contains("NON appelé"), "{m}"),
            autre => panic!("échec attendu, obtenu {autre:?}"),
        }
        assert!(
            h.seen.lock().unwrap().is_empty(),
            "le refresh token n'a pas à être dépensé"
        );
        assert_eq!(
            std::fs::read_to_string(f.p.credentials_file()).unwrap(),
            EXPIRED,
            "magasin intact"
        );
    }

    #[test]
    fn a_journal_that_fails_after_the_post_still_gets_the_store_written() {
        let f = fx(EXPIRED);
        // Le journal ne pourra pas prendre sa place définitive (répertoire plein).
        std::fs::create_dir(f.p.pending_journal()).unwrap();
        std::fs::write(f.p.pending_journal().join("x"), "x").unwrap();
        let h = Scripted::new(vec![ok(200, NEW_TOKENS)]);
        let r = renew(
            &f.env,
            &api(h),
            &f.p,
            &load(&f),
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert_eq!(r, Renewal::Renewed, "le magasin est la dernière chance");
        let l = load(&f);
        assert_eq!(l.blob.refresh_token().unwrap().expose_secret(), "RT2");
        assert_eq!(l.blob.access_token().unwrap().expose_secret(), "AT2");
        assert!(!f.p.pending_reserve().exists());
    }

    #[test]
    fn losing_both_the_journal_and_the_store_is_said_plainly() {
        let f = fx(EXPIRED);
        std::fs::create_dir(f.p.pending_journal()).unwrap();
        std::fs::write(f.p.pending_journal().join("x"), "x").unwrap();
        let cred = f.p.credentials_file();
        let h = Arc::new(Hook {
            // Le magasin devient inscriptible-impossible pendant le POST.
            before_reply: Box::new(move || {
                std::fs::remove_file(&cred).unwrap();
                std::fs::create_dir(&cred).unwrap();
            }),
            reply: NEW_TOKENS.into(),
            calls: Mutex::new(0),
        });
        let r = renew(
            &f.env,
            &Api::new(h.clone(), "http://x", "http://x/token"),
            &f.p,
            &load(&f),
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        match r {
            Renewal::Failed(m) => {
                assert!(m.contains("PERDUS") && m.contains("journal"), "{m}")
            }
            autre => panic!("échec attendu, obtenu {autre:?}"),
        }
        assert_eq!(*h.calls.lock().unwrap(), 1);
    }

    #[test]
    fn a_renewal_made_obsolete_during_the_post_leaves_no_journal_nor_reservation() {
        let f = fx(EXPIRED);
        let cred = f.p.credentials_file();
        let h = Arc::new(Hook {
            // Le magasin change de lignée pendant le POST : le renouvellement est
            // obsolète, mais le journal a déjà été écrit puis retiré proprement.
            before_reply: Box::new(move || {
                std::fs::write(&cred, EXPIRED.replace("RT1", "RT9")).unwrap();
            }),
            reply: NEW_TOKENS.into(),
            calls: Mutex::new(0),
        });
        let r = renew(
            &f.env,
            &Api::new(h, "http://x", "http://x/token"),
            &f.p,
            &load(&f),
            Trigger::Expired,
            &AtomicUsize::new(0),
        );
        assert_eq!(r, Renewal::AlreadyFresh);
        assert!(!f.p.pending_journal().exists());
        assert!(!f.p.pending_reserve().exists());
    }
}
