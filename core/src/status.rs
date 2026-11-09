//! Statut des comptes : lecture locale, cache, sonde réseau bornée.
//!
//! Deux étages :
//! - `status_from_view` : projection LOCALE (magasin + cache), sans réseau. C'est
//!   ce que montre `--offline` et `accounts best` ;
//! - `probe_profile` : si le cache est périmé (ou `--refresh`), sonde le réseau,
//!   RENOUVELLE le jeton si besoin, écrit le cache, puis repasse par la projection :
//!   une seule source de vérité pour ce qui est affiché.
//!
//! La sonde ne remplace jamais une bonne valeur par un échec : identité et usage
//! sont gardés séparément dans le cache (`cache.rs`).

use crate::api::{Api, Fetch};
use crate::cache::{self, Cache};
use crate::creds::{self, Loaded, StoreError, StoreKind};
use crate::env::{now_ms, Env};
use crate::lock::{self, LockState};
use crate::model::{AccountStatus, Bucket, Identity, State, Usage};
use crate::oauth::{self, Renewal, Trigger};
use crate::plan;
use crate::root::ProfileDir;
use crate::timefmt;
use crate::util::fingerprint;
use jiff::tz::TimeZone;
use secrecy::{ExposeSecret, SecretString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// L'identité (email, forfait) change presque jamais : une requête toutes les 6 h.
pub const IDENTITY_TTL_S: i64 = 6 * 3600;
/// Au-delà, un usage est affiché comme « ancien ».
pub const STALE_AFTER_S: i64 = 900;
/// Après un échec on réessaie vite, sans marteler.
const FAILURE_RETRY_S: i64 = 60;
/// Budget global de la sonde (connexion 2 s, requête 4 s par appel).
pub const DEFAULT_BUDGET: Duration = Duration::from_secs(5);
/// Un renouvellement en cours n'est JAMAIS abandonné : le refresh token a peut-être déjà tourné.
const CRITICAL_GRACE: Duration = Duration::from_secs(12);

#[derive(Clone)]
pub struct Deps {
    pub env: Arc<Env>,
    pub api: Api,
    pub critical: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
pub struct ProbeOpts {
    pub refresh: bool,
    pub offline: bool,
    pub max_age_s: i64,
    pub budget: Duration,
}

impl ProbeOpts {
    pub fn offline() -> Self {
        ProbeOpts {
            refresh: false,
            offline: true,
            max_age_s: 300,
            budget: Duration::from_secs(3),
        }
    }
}

pub enum Source {
    None,
    Login(Box<Loaded>),
    Token(SecretString),
    Broken(StoreError),
}

pub struct View {
    pub p: ProfileDir,
    pub source: Source,
    pub fp: String,
    pub revoked: bool,
    pub lock: LockState,
    /// Cache valide POUR CE LOGIN (empreinte identique).
    pub cache: Option<Cache>,
    pub local_email: Option<String>,
    pub declared_plan: Option<String>,
}

pub fn read_view(env: &Env, p: &ProfileDir) -> View {
    let (source, fp) = match creds::read_login(env, p) {
        Ok(Some(l)) if l.blob.has_login() => {
            let fp = l.blob.fingerprint();
            (Source::Login(Box::new(l)), fp)
        }
        Ok(_) => match creds::read_token(p) {
            Some(t) => {
                let fp = fingerprint(t.expose_secret());
                (Source::Token(t), fp)
            }
            None => (Source::None, "none".to_string()),
        },
        Err(e) => (Source::Broken(e), "broken".to_string()),
    };
    let revoked = matches!(source, Source::Login(_)) && oauth::is_revoked(p, &fp);
    let cache = cache::load(p).filter(|c| c.fp == fp);
    View {
        p: p.clone(),
        source,
        fp,
        revoked,
        lock: lock::state(p),
        cache,
        local_email: creds::read_local_email(&p.dir),
        declared_plan: creds::read_declared_plan(p),
    }
}

fn store_of(source: &Source) -> StoreKind {
    match source {
        Source::Login(l) => l.kind,
        Source::Token(_) => StoreKind::Token,
        _ => StoreKind::None,
    }
}

pub fn is_limited(five: &Option<Bucket>, seven: &Option<Bucket>) -> bool {
    [five, seven]
        .iter()
        .any(|b| b.as_ref().is_some_and(|b| b.pct >= 100))
}

/// Une fenêtre dont l'heure de reprise est PASSÉE est revenue à 0 : le compte
/// « limité » d'hier soir est utilisable ce matin, sans même sonder.
fn decay(u: &Usage, now_s: i64) -> (Usage, bool) {
    let mut changed = false;
    let mut fix = |b: &Option<Bucket>| -> Option<Bucket> {
        match b {
            Some(b)
                if b.resets_at
                    .as_deref()
                    .and_then(timefmt::parse_epoch)
                    .is_some_and(|t| t <= now_s) =>
            {
                changed = true;
                Some(Bucket {
                    pct: 0,
                    resets_at: None,
                })
            }
            other => other.clone(),
        }
    };
    let out = Usage {
        five_hour: fix(&u.five_hour),
        seven_day: fix(&u.seven_day),
        seven_day_sonnet: fix(&u.seven_day_sonnet),
        checked_at: u.checked_at,
    };
    (out, changed)
}

fn skeleton(view: &View, active: bool) -> AccountStatus {
    AccountStatus {
        name: view.p.name.to_string(),
        active,
        store: store_of(&view.source),
        state: State::Unknown,
        state_label: String::new(),
        email: view.local_email.clone(),
        plan: None,
        plan_tier: None,
        plan_declared: false,
        five_hour: None,
        seven_day: None,
        seven_day_sonnet: None,
        usable: false,
        running: view.lock != LockState::Free,
        checked_at: 0,
        stale: false,
        detail: None,
    }
}

fn apply_identity(st: &mut AccountStatus, id: &Identity) {
    if id.email.is_some() {
        st.email = id.email.clone();
    }
    st.plan = id.plan.clone();
    st.plan_tier = id.plan_tier.clone();
    st.plan_declared = id.plan_declared;
}

fn project_cache(st: &mut AccountStatus, c: &Cache, now_s: i64) {
    st.checked_at = c.checked_at;
    st.detail = c.detail.clone();
    if let Some(id) = &c.identity {
        apply_identity(st, id);
    }
    let mut state = c.state.unwrap_or(State::Unknown);
    let mut stale = state.is_failure();
    if let Some(u) = &c.usage {
        let (u2, decayed) = decay(u, now_s);
        st.five_hour = u2.five_hour;
        st.seven_day = u2.seven_day;
        st.seven_day_sonnet = u2.seven_day_sonnet;
        if decayed || now_s - u.checked_at > STALE_AFTER_S {
            stale = true;
        }
        if matches!(state, State::Ok | State::Limited) {
            state = if is_limited(&st.five_hour, &st.seven_day) {
                State::Limited
            } else {
                State::Ok
            };
        }
    }
    st.state = state;
    st.stale = stale;
}

/// Projection locale, sans réseau.
pub fn status_from_view(view: &View, active: bool, now_s: i64) -> AccountStatus {
    let mut st = skeleton(view, active);
    match &view.source {
        Source::None => {
            st.state = State::NotConnected;
            st.detail = Some("aucun login dans ce profil".into());
        }
        Source::Broken(e) => {
            st.state = State::Error;
            st.detail = Some(e.to_string());
        }
        Source::Login(l) => {
            if let Some(c) = &view.cache {
                project_cache(&mut st, c, now_s);
            } else if oauth::expired(&l.blob, now_ms()) {
                st.state = State::Expired;
                st.detail = Some("jeton expiré : Claude le renouvellera au lancement".into());
            } else {
                st.state = State::Unknown;
                st.detail = Some("pas encore sondé".into());
            }
            if view.revoked {
                st.state = State::Revoked;
                st.detail = Some("renouvellement refusé : reconnecte ce compte".into());
                st.five_hour = None;
                st.seven_day = None;
                st.seven_day_sonnet = None;
                st.stale = false;
            }
            if st.plan.is_none() {
                st.plan = plan::from_credentials(
                    l.blob.subscription_type().as_deref(),
                    l.blob.rate_limit_tier().as_deref(),
                );
                st.plan_tier = l.blob.rate_limit_tier();
            }
        }
        Source::Token(_) => {
            if let Some(c) = &view.cache {
                project_cache(&mut st, c, now_s);
            } else {
                st.state = State::TokenLong;
                st.detail = Some("jeton longue durée : quota illisible".into());
            }
            if st.plan.is_none() {
                if let Some(d) = &view.declared_plan {
                    st.plan = Some(plan::declared(d));
                    st.plan_declared = true;
                }
            }
        }
    }
    st
}

/// Heure de reprise (époque) d'un compte limité : il faut que TOUTES les fenêtres
/// pleines se rouvrent, donc la plus tardive.
pub fn resume_epoch(st: &AccountStatus) -> Option<i64> {
    let full = [&st.five_hour, &st.seven_day]
        .into_iter()
        .flatten()
        .filter(|b| b.pct >= 100);
    let mut max = None;
    for b in full {
        let t = b.resets_at.as_deref().and_then(timefmt::parse_epoch)?;
        max = Some(max.map_or(t, |m: i64| m.max(t)));
    }
    max
}

pub fn label_for(st: &AccountStatus, now_s: i64, tz: &TimeZone) -> String {
    if st.state == State::Limited {
        if let Some(t) = resume_epoch(st) {
            return format!(
                "{} → {}",
                State::Limited.label(),
                timefmt::resume(t, now_s, tz)
            );
        }
    }
    st.state.label().to_string()
}

pub fn finalize(st: &mut AccountStatus, now_s: i64, tz: &TimeZone) {
    st.usable = st.state.is_usable();
    st.state_label = label_for(st, now_s, tz);
}

// ------------------------------------------------------------------ réseau

fn jitter_s(name: &str, max_age_s: i64) -> i64 {
    let h = u64::from_str_radix(&fingerprint(name)[..8], 16).unwrap_or(0);
    (h % (max_age_s / 5 + 1) as u64) as i64
}

fn fresh_enough(view: &View, opts: &ProbeOpts, now_s: i64) -> bool {
    let Some(c) = &view.cache else { return false };
    if let Source::Login(l) = &view.source {
        if oauth::expired(&l.blob, now_ms()) {
            return false;
        }
    }
    let ttl = if c.state.is_some_and(|s| s.is_failure()) {
        FAILURE_RETRY_S.min(opts.max_age_s)
    } else {
        opts.max_age_s + jitter_s(&view.p.name.to_string(), opts.max_age_s)
    };
    now_s - c.checked_at < ttl
}

struct Outcome {
    state: State,
    detail: Option<String>,
    identity: Option<Identity>,
    usage: Option<Usage>,
    fp: String,
}

impl Outcome {
    fn fail(state: State, detail: impl Into<String>, fp: &str) -> Outcome {
        Outcome {
            state,
            detail: Some(detail.into()),
            identity: None,
            usage: None,
            fp: fp.to_string(),
        }
    }
}

struct Run<'a> {
    d: &'a Deps,
    p: &'a ProfileDir,
    login: Option<Loaded>,
    token: Option<SecretString>,
    fp: String,
    renewed_once: bool,
}

impl Run<'_> {
    fn access(&self) -> Option<SecretString> {
        self.login
            .as_ref()
            .and_then(|l| l.blob.access_token())
            .or_else(|| self.token.clone())
    }

    /// Renouvelle (une seule fois par sonde) et recharge le login.
    fn renew(&mut self, trigger: Trigger) -> Result<(), Box<Outcome>> {
        let Some(seen) = self.login.clone() else {
            return Err(Box::new(Outcome::fail(
                State::Revoked,
                "jeton longue durée refusé",
                &self.fp,
            )));
        };
        match oauth::renew(
            &self.d.env,
            &self.d.api,
            self.p,
            &seen,
            trigger,
            &self.d.critical,
        ) {
            Renewal::Renewed | Renewal::AlreadyFresh => {
                match creds::read_login(&self.d.env, self.p) {
                    Ok(Some(l)) if l.blob.has_login() => {
                        self.fp = l.blob.fingerprint();
                        self.login = Some(l);
                        self.renewed_once = true;
                        Ok(())
                    }
                    _ => Err(Box::new(Outcome::fail(
                        State::Error,
                        "identifiants illisibles après renouvellement",
                        &self.fp,
                    ))),
                }
            }
            Renewal::Revoked => Err(Box::new(Outcome::fail(
                State::Revoked,
                "renouvellement refusé : reconnecte ce compte",
                &self.fp,
            ))),
            Renewal::SessionBusy => Err(Box::new(Outcome::fail(
                State::Expired,
                "session ouverte ou renouvellement en cours : Claude renouvellera le jeton",
                &self.fp,
            ))),
            Renewal::Unreachable(m) => Err(Box::new(Outcome::fail(
                State::Unreachable,
                format!("jeton expiré — {m}"),
                &self.fp,
            ))),
            Renewal::Failed(m) => Err(Box::new(Outcome::fail(State::Error, m, &self.fp))),
        }
    }

    /// Appel authentifié ; un 401 déclenche UN renouvellement puis UN nouvel essai.
    fn call<T>(&mut self, f: impl Fn(&SecretString) -> Fetch<T>) -> Result<Fetch<T>, Box<Outcome>> {
        let Some(access) = self.access() else {
            return Err(Box::new(Outcome::fail(
                State::NotConnected,
                "aucun jeton d'accès",
                &self.fp,
            )));
        };
        let r = f(&access);
        if matches!(r, Fetch::Unauthorized) && self.login.is_some() && !self.renewed_once {
            self.renew(Trigger::Unauthorized)?;
            let Some(access2) = self.access() else {
                return Err(Box::new(Outcome::fail(
                    State::NotConnected,
                    "aucun jeton d'accès",
                    &self.fp,
                )));
            };
            return Ok(f(&access2));
        }
        Ok(r)
    }
}

fn server_outcome(code: u16, fp: &str) -> Outcome {
    if code >= 500 {
        Outcome::fail(
            State::Unreachable,
            format!("service Anthropic indisponible (HTTP {code})"),
            fp,
        )
    } else {
        Outcome::fail(
            State::Error,
            format!("réponse inattendue du service (HTTP {code})"),
            fp,
        )
    }
}

fn network_probe(d: &Deps, view: &View, now_s: i64) -> Outcome {
    let mut run = Run {
        d,
        p: &view.p,
        login: match &view.source {
            Source::Login(l) => Some((**l).clone()),
            _ => None,
        },
        token: match &view.source {
            Source::Token(t) => Some(t.clone()),
            _ => None,
        },
        fp: view.fp.clone(),
        renewed_once: false,
    };
    let is_token = run.token.is_some();

    // 1. Jeton expiré : on le renouvelle AVANT de s'en servir.
    if run
        .login
        .as_ref()
        .is_some_and(|l| oauth::expired(&l.blob, now_ms()))
    {
        if let Err(o) = run.renew(Trigger::Expired) {
            return *o;
        }
    }

    // 2. Identité (email, forfait) : au plus toutes les 6 h, sauf jeton longue durée
    //    (la requête sert aussi de test de validité : 403 = valide, 401 = mort).
    let cached_id = view.cache.as_ref().and_then(|c| c.identity.clone());
    let id_fresh = cached_id
        .as_ref()
        .is_some_and(|i| now_s - i.checked_at < IDENTITY_TTL_S);
    let cached_state = view.cache.as_ref().and_then(|c| c.state);
    let need_identity =
        !id_fresh || matches!(cached_state, Some(State::TokenLong | State::Revoked)) || is_token;

    let mut forbidden = false;
    let mut identity: Option<Identity> = None;
    if need_identity {
        match run.call(|a| d.api.profile(a)) {
            Err(o) => return *o,
            Ok(Fetch::Ok(info)) => {
                identity = Some(Identity {
                    email: info.email.or_else(|| view.local_email.clone()),
                    plan: Some(plan::from_profile(
                        info.tier.as_deref(),
                        info.has_max,
                        info.has_pro,
                    )),
                    plan_tier: info.tier,
                    plan_declared: false,
                    checked_at: now_s,
                });
            }
            Ok(Fetch::Unauthorized) => {
                return if is_token {
                    Outcome::fail(
                        State::Revoked,
                        "jeton longue durée refusé (401) : à régénérer",
                        &run.fp,
                    )
                } else {
                    Outcome::fail(
                        State::Error,
                        "jeton refusé (401) malgré le renouvellement",
                        &run.fp,
                    )
                };
            }
            Ok(Fetch::Forbidden) => forbidden = true,
            Ok(Fetch::RateLimited) => {}
            Ok(Fetch::Unreachable(m)) => return Outcome::fail(State::Unreachable, m, &run.fp),
            Ok(Fetch::Format(m)) => {
                return Outcome::fail(State::Error, format!("profil : {m}"), &run.fp)
            }
            Ok(Fetch::Server(c)) => return server_outcome(c, &run.fp),
        }
    }

    // 3. Usage.
    let mut usage: Option<Usage> = None;
    let mut state = State::Ok;
    let mut detail: Option<String> = None;
    if !forbidden {
        match run.call(|a| d.api.usage(a)) {
            Err(o) => return *o,
            Ok(Fetch::Ok(u)) => {
                state = if is_limited(&u.five_hour, &u.seven_day) {
                    State::Limited
                } else {
                    State::Ok
                };
                usage = Some(Usage {
                    five_hour: u.five_hour,
                    seven_day: u.seven_day,
                    seven_day_sonnet: u.seven_day_sonnet,
                    checked_at: now_s,
                });
            }
            Ok(Fetch::Unauthorized) => {
                return Outcome::fail(
                    State::Error,
                    "jeton refusé (401) malgré le renouvellement",
                    &run.fp,
                )
            }
            Ok(Fetch::Forbidden) => forbidden = true,
            Ok(Fetch::RateLimited) => {
                // 429 = limite par IP du point de statut, PAS épuisement du compte :
                // l'état reste `rate_limited` (le wizard sait que le chiffre est vieux,
                // `stale` est vrai) mais on garde les dernières bonnes valeurs. Seule
                // une fenêtre déjà pleine et non encore reprise reste « limité ».
                detail =
                    Some("limite du point de statut (429) : dernières valeurs conservées".into());
                state = State::RateLimited;
                if let Some(old) = view.cache.as_ref().and_then(|c| c.usage.as_ref()) {
                    let (o, _) = decay(old, now_s);
                    if is_limited(&o.five_hour, &o.seven_day) {
                        state = State::Limited;
                    }
                }
            }
            Ok(Fetch::Unreachable(m)) => return Outcome::fail(State::Unreachable, m, &run.fp),
            Ok(Fetch::Format(m)) => {
                return Outcome::fail(State::Error, format!("usage : {m}"), &run.fp)
            }
            Ok(Fetch::Server(c)) => return server_outcome(c, &run.fp),
        }
    }

    if forbidden {
        // Profil/usage refusés : valide mais quota illisible, ou portée insuffisante.
        let scopes = run
            .login
            .as_ref()
            .map(|l| l.blob.scopes())
            .unwrap_or_default();
        let limited_scope =
            is_token || (!scopes.is_empty() && !scopes.iter().any(|s| s == "user:profile"));
        if !limited_scope {
            return Outcome::fail(State::Error, "accès refusé (403) par le service", &run.fp);
        }
        let declared = view.declared_plan.clone();
        let id = Identity {
            email: view
                .local_email
                .clone()
                .or_else(|| cached_id.as_ref().and_then(|i| i.email.clone())),
            plan: declared.as_deref().map(plan::declared),
            plan_tier: None,
            plan_declared: declared.is_some(),
            checked_at: now_s,
        };
        return Outcome {
            state: State::TokenLong,
            detail: Some(if is_token {
                "jeton longue durée : valide, quota illisible".into()
            } else {
                "portée limitée (inférence seule) : valide, quota illisible".into()
            }),
            identity: Some(id),
            usage: None,
            fp: run.fp,
        };
    }

    Outcome {
        state,
        detail,
        identity,
        usage,
        fp: run.fp,
    }
}

/// Sonde un profil (réseau si le cache est périmé) et renvoie son statut.
pub fn probe_profile(d: &Deps, p: &ProfileDir, active: bool, opts: &ProbeOpts) -> AccountStatus {
    let now_s = now_ms() / 1000;
    // Un renouvellement interrompu AVANT nous doit être rejoué avant toute lecture.
    let _ = oauth::replay_pending(&d.env, p);
    let view = read_view(&d.env, p);
    let local = status_from_view(&view, active, now_s);
    if opts.offline || matches!(view.source, Source::None | Source::Broken(_)) || view.revoked {
        return local;
    }
    if !opts.refresh && fresh_enough(&view, opts, now_s) {
        return local;
    }

    let out = network_probe(d, &view, now_s);

    let mut c = view
        .cache
        .clone()
        .unwrap_or_else(|| Cache::empty(&out.fp, store_of(&view.source)));
    c.fp = out.fp.clone();
    c.store = store_of(&view.source);
    c.checked_at = now_s;
    c.state = Some(out.state);
    c.detail = out.detail;
    if let Some(id) = out.identity {
        c.identity = Some(id);
    }
    if let Some(u) = out.usage {
        c.usage = Some(u);
    }
    if out.state == State::Revoked {
        c.usage = None;
    }
    cache::store(p, &c);

    // Projection du cache qu'on vient d'écrire. `running` et le magasin viennent de la vue.
    let mut v2 = view;
    v2.fp = out.fp;
    v2.revoked = out.state == State::Revoked && matches!(v2.source, Source::Login(_));
    v2.cache = Some(c);
    status_from_view(&v2, active, now_s)
}

/// Sonde tous les profils en parallèle sous un budget global. Un thread par compte ;
/// un thread qui n'a pas répondu à l'échéance est abandonné SAUF s'il est en plein
/// renouvellement (section critique) : on lui laisse jusqu'à `CRITICAL_GRACE`.
pub fn probe_all(
    d: &Deps,
    profiles: &[ProfileDir],
    active: &str,
    opts: &ProbeOpts,
) -> Vec<AccountStatus> {
    let (tx, rx) = mpsc::channel::<(usize, AccountStatus)>();
    for (i, p) in profiles.iter().enumerate() {
        let (d, p, opts, tx) = (d.clone(), p.clone(), opts.clone(), tx.clone());
        let is_active = p.name.as_str() == active;
        std::thread::spawn(move || {
            let st = probe_profile(&d, &p, is_active, &opts);
            let _ = tx.send((i, st));
        });
    }
    drop(tx);
    let start = Instant::now();
    let mut slots: Vec<Option<AccountStatus>> = vec![None; profiles.len()];
    let mut pending = profiles.len();
    while pending > 0 {
        let elapsed = start.elapsed();
        let limit = if d.critical.load(Ordering::SeqCst) > 0 {
            opts.budget + CRITICAL_GRACE
        } else {
            opts.budget
        };
        if elapsed >= limit {
            break;
        }
        match rx.recv_timeout(limit - elapsed) {
            Ok((i, st)) => {
                slots[i] = Some(st);
                pending -= 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let now_s = now_ms() / 1000;
    let tz = TimeZone::system();
    slots
        .into_iter()
        .zip(profiles)
        .map(|(slot, p)| {
            let mut st =
                slot.unwrap_or_else(|| timeout_status(p, p.name.as_str() == active, opts, now_s));
            finalize(&mut st, now_s, &tz);
            st
        })
        .collect()
}

/// Statut de repli d'un compte dont la sonde n'a pas répondu à temps : le cache,
/// marqué ancien (sans relire le magasin, qui est peut-être la cause du blocage).
fn timeout_status(p: &ProfileDir, active: bool, opts: &ProbeOpts, now_s: i64) -> AccountStatus {
    let mut st = AccountStatus {
        name: p.name.to_string(),
        active,
        store: StoreKind::None,
        state: State::Unreachable,
        state_label: String::new(),
        email: creds::read_local_email(&p.dir),
        plan: None,
        plan_tier: None,
        plan_declared: false,
        five_hour: None,
        seven_day: None,
        seven_day_sonnet: None,
        usable: false,
        running: false,
        checked_at: 0,
        stale: true,
        detail: Some(format!(
            "délai dépassé ({} s) : dernières valeurs connues",
            opts.budget.as_secs()
        )),
    };
    if let Some(c) = cache::load(p) {
        st.store = c.store;
        project_cache(&mut st, &c, now_s);
        st.state = State::Unreachable;
        st.stale = true;
        st.detail = Some(format!(
            "délai dépassé ({} s) : dernières valeurs connues",
            opts.budget.as_secs()
        ));
    }
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Http, HttpRequest, HttpResponse, NetError};
    use crate::root::{PathStyle, Profile, Root};
    use std::sync::Mutex;

    struct Scripted {
        replies: Mutex<Vec<Result<HttpResponse, NetError>>>,
        urls: Mutex<Vec<String>>,
    }

    impl Http for Scripted {
        fn send(&self, req: &HttpRequest) -> Result<HttpResponse, NetError> {
            self.urls.lock().unwrap().push(req.url.clone());
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

    const PROFILE: &str = r#"{"account":{"email":"sam@x.fr","has_claude_max":true},"organization":{"rate_limit_tier":"default_claude_max_20x"}}"#;
    const USAGE_LOW: &str = r#"{"five_hour":{"utilization":12.5,"resets_at":"2099-01-01T04:00:00Z"},"seven_day":{"utilization":40.0,"resets_at":"2099-01-05T10:00:00Z"},"seven_day_sonnet":{"utilization":3.0,"resets_at":null}}"#;
    const USAGE_FULL: &str = r#"{"five_hour":{"utilization":100.0,"resets_at":"2099-01-01T04:00:00Z"},"seven_day":{"utilization":40.0,"resets_at":"2099-01-05T10:00:00Z"}}"#;

    fn creds_json(expires_ms: i64) -> String {
        format!(
            r#"{{"claudeAiOauth":{{"accessToken":"AT1","refreshToken":"RT1","expiresAt":{expires_ms},"scopes":["user:inference","user:profile"],"subscriptionType":"max","rateLimitTier":"default_claude_max_5x"}}}}"#
        )
    }

    struct Fx {
        _t: tempfile::TempDir,
        d: Deps,
        p: ProfileDir,
        http: Arc<Scripted>,
    }

    fn fx(creds: Option<&str>, replies: Vec<Result<HttpResponse, NetError>>) -> Fx {
        let t = tempfile::tempdir().unwrap();
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let p = r.profile(&Profile::parse("p").unwrap());
        std::fs::create_dir_all(&p.dir).unwrap();
        if let Some(c) = creds {
            std::fs::write(p.credentials_file(), c).unwrap();
        }
        let env = Env::for_tests(t.path().to_path_buf());
        let http = Arc::new(Scripted {
            replies: Mutex::new(replies),
            urls: Mutex::new(vec![]),
        });
        let d = Deps {
            env: Arc::new(env),
            api: Api::new(http.clone(), "http://x", "http://x/token"),
            critical: Arc::new(AtomicUsize::new(0)),
        };
        Fx { _t: t, d, p, http }
    }

    fn opts() -> ProbeOpts {
        ProbeOpts {
            refresh: true,
            offline: false,
            max_age_s: 300,
            budget: Duration::from_secs(5),
        }
    }

    fn fin(mut st: AccountStatus) -> AccountStatus {
        finalize(&mut st, now_ms() / 1000, &TimeZone::UTC);
        st
    }

    fn future() -> i64 {
        now_ms() + 3_600_000
    }

    #[test]
    fn healthy_login_is_ok_with_identity_and_percentages() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, USAGE_LOW)],
        );
        let st = fin(probe_profile(&f.d, &f.p, true, &opts()));
        assert_eq!(st.state, State::Ok);
        assert_eq!(st.email.as_deref(), Some("sam@x.fr"));
        assert_eq!(
            st.plan.as_deref(),
            Some("Max x20"),
            "le forfait vient du profil, pas des identifiants (x5)"
        );
        assert_eq!(st.five_hour.as_ref().unwrap().pct, 12);
        assert_eq!(st.seven_day.as_ref().unwrap().pct, 40);
        assert_eq!(st.seven_day_sonnet.as_ref().unwrap().pct, 3);
        assert!(st.usable && !st.stale && st.active);
        assert_eq!(st.state_label, "OK");
        assert_eq!(st.store, StoreKind::File);
    }

    #[test]
    fn full_five_hour_window_is_limited_with_resume_label() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, USAGE_FULL)],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Limited);
        assert!(!st.usable);
        assert!(
            st.state_label.starts_with("Limité → "),
            "{}",
            st.state_label
        );
    }

    #[test]
    fn fresh_cache_means_no_network() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, USAGE_LOW)],
        );
        probe_profile(&f.d, &f.p, false, &opts());
        let n = f.http.urls.lock().unwrap().len();
        let o = ProbeOpts {
            refresh: false,
            ..opts()
        };
        let st = fin(probe_profile(&f.d, &f.p, false, &o));
        assert_eq!(
            f.http.urls.lock().unwrap().len(),
            n,
            "aucune requête sur cache frais"
        );
        assert_eq!(st.state, State::Ok);
        assert_eq!(st.five_hour.unwrap().pct, 12);
    }

    #[test]
    fn identity_is_not_refetched_within_ttl() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, USAGE_LOW), ok(200, USAGE_LOW)],
        );
        probe_profile(&f.d, &f.p, false, &opts());
        probe_profile(&f.d, &f.p, false, &opts()); // --refresh : usage seulement
        let urls = f.http.urls.lock().unwrap().clone();
        assert_eq!(urls.iter().filter(|u| u.ends_with("/profile")).count(), 1);
        assert_eq!(urls.iter().filter(|u| u.ends_with("/usage")).count(), 2);
    }

    #[test]
    fn rate_limit_keeps_last_good_values_and_is_not_exhaustion() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, USAGE_LOW), ok(429, "{}")],
        );
        probe_profile(&f.d, &f.p, false, &opts());
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::RateLimited, "429 n'est jamais « épuisé »");
        assert!(st.stale, "le chiffre affiché est vieux");
        assert!(st.usable);
        assert_eq!(st.five_hour.unwrap().pct, 12);
        assert!(st.detail.unwrap().contains("429"));
    }

    #[test]
    fn rate_limit_without_history_is_neutral_state() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(429, "{}")],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::RateLimited);
        assert_eq!(st.state_label, "Statut limité");
        assert!(st.five_hour.is_none());
        assert_eq!(st.email.as_deref(), Some("sam@x.fr"));
        assert!(st.usable);
    }

    #[test]
    fn network_down_keeps_stale_values_as_unreachable() {
        let f = fx(
            Some(&creds_json(future())),
            vec![
                ok(200, PROFILE),
                ok(200, USAGE_LOW),
                Err(NetError::Other("dns".into())),
            ],
        );
        probe_profile(&f.d, &f.p, false, &opts());
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Unreachable);
        assert!(st.stale);
        assert_eq!(st.five_hour.unwrap().pct, 12);
        assert_eq!(st.state_label, "Hors ligne");
    }

    #[test]
    fn captive_portal_html_is_unreachable() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, "<html>Wi-Fi</html>")],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Unreachable);
        assert!(st.five_hour.is_none());
    }

    #[test]
    fn unknown_usage_shape_is_error_not_zero() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, r#"{"truc":1}"#)],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Error);
        assert!(st.five_hour.is_none(), "jamais 0 %");
    }

    #[test]
    fn expired_token_is_renewed_then_probed() {
        let f = fx(
            Some(&creds_json(1000)),
            vec![
                ok(
                    200,
                    r#"{"access_token":"AT2","refresh_token":"RT2","expires_in":3600}"#,
                ),
                ok(200, PROFILE),
                ok(200, USAGE_LOW),
            ],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Ok);
        let urls = f.http.urls.lock().unwrap().clone();
        assert_eq!(urls[0], "http://x/token");
        let stored = std::fs::read_to_string(f.p.credentials_file()).unwrap();
        assert!(stored.contains("RT2") && !stored.contains("RT1"));
    }

    #[test]
    fn revoked_refresh_gives_reconnect_state_and_stops_calling() {
        let f = fx(
            Some(&creds_json(1000)),
            vec![ok(400, r#"{"error":"invalid_grant"}"#)],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Revoked);
        assert_eq!(st.state_label, "À reconnecter");
        let n = f.http.urls.lock().unwrap().len();
        let st2 = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st2.state, State::Revoked);
        assert_eq!(
            f.http.urls.lock().unwrap().len(),
            n,
            "plus aucune tentative"
        );
    }

    #[test]
    fn running_session_blocks_renewal_and_says_so() {
        let f = fx(Some(&creds_json(1000)), vec![]);
        let lock::Acquire::Got(_g) = lock::try_acquire(&f.p) else {
            panic!()
        };
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Expired);
        assert!(st.running);
        assert_eq!(st.state_label, "Expiré (au lancement)");
        assert!(f.http.urls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_401_triggers_exactly_one_renewal_then_retry() {
        let f = fx(
            Some(&creds_json(future())),
            vec![
                ok(401, "{}"),
                ok(
                    200,
                    r#"{"access_token":"AT2","refresh_token":"RT2","expires_in":3600}"#,
                ),
                ok(200, PROFILE),
                ok(200, USAGE_LOW),
            ],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Ok);
        assert_eq!(
            f.http
                .urls
                .lock()
                .unwrap()
                .iter()
                .filter(|u| u.ends_with("/token"))
                .count(),
            1
        );
    }

    #[test]
    fn persistent_401_after_renewal_is_an_error_not_a_loop() {
        let f = fx(
            Some(&creds_json(future())),
            vec![
                ok(401, "{}"),
                ok(
                    200,
                    r#"{"access_token":"AT2","refresh_token":"RT2","expires_in":3600}"#,
                ),
                ok(401, "{}"),
            ],
        );
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Error);
        assert_eq!(f.http.urls.lock().unwrap().len(), 3);
    }

    #[test]
    fn long_lived_token_403_is_valid_with_declared_plan() {
        let f = fx(None, vec![ok(403, "{}")]);
        std::fs::write(f.p.token_file(), "sk-ant-oat01-xyz").unwrap();
        std::fs::write(f.p.plan_file(), "Max x5\n").unwrap();
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::TokenLong);
        assert_eq!(st.store, StoreKind::Token);
        assert_eq!(st.plan.as_deref(), Some("Max x5 (déclaré)"));
        assert!(st.plan_declared && st.usable);
        assert!(st.five_hour.is_none());
    }

    #[test]
    fn long_lived_token_401_is_dead() {
        let f = fx(None, vec![ok(401, "{}")]);
        std::fs::write(f.p.token_file(), "sk-ant-oat01-xyz").unwrap();
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Revoked);
    }

    #[test]
    fn empty_profile_is_not_connected_without_network() {
        let f = fx(None, vec![]);
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::NotConnected);
        assert_eq!(st.store, StoreKind::None);
        assert!(f.http.urls.lock().unwrap().is_empty());
    }

    #[test]
    fn corrupt_credentials_are_a_readable_error() {
        let f = fx(Some("{ cassé"), vec![]);
        let st = fin(probe_profile(&f.d, &f.p, false, &opts()));
        assert_eq!(st.state, State::Error);
        assert!(st.detail.unwrap().contains("illisibles"));
    }

    #[test]
    fn offline_projection_never_hits_network_and_decays_passed_windows() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, USAGE_FULL)],
        );
        probe_profile(&f.d, &f.p, false, &opts());
        // On réécrit le cache comme si la fenêtre 5 h s'était rouverte hier.
        let mut c = cache::load(&f.p).unwrap();
        c.usage
            .as_mut()
            .unwrap()
            .five_hour
            .as_mut()
            .unwrap()
            .resets_at = Some("2001-01-01T00:00:00Z".into());
        cache::store(&f.p, &c);
        let n = f.http.urls.lock().unwrap().len();
        let st = fin(probe_profile(&f.d, &f.p, false, &ProbeOpts::offline()));
        assert_eq!(f.http.urls.lock().unwrap().len(), n);
        assert_eq!(
            st.state,
            State::Ok,
            "la fenêtre de reprise est passée : plus limité"
        );
        assert_eq!(st.five_hour.unwrap().pct, 0);
        assert!(st.stale);
    }

    #[test]
    fn offline_without_cache_says_not_probed() {
        let f = fx(Some(&creds_json(future())), vec![]);
        let st = fin(probe_profile(&f.d, &f.p, false, &ProbeOpts::offline()));
        assert_eq!(st.state, State::Unknown);
        assert_eq!(
            st.plan.as_deref(),
            Some("Max x5 (?)"),
            "repli identifiants marqué (?)"
        );
    }

    #[test]
    fn cache_of_another_login_is_ignored() {
        let f = fx(
            Some(&creds_json(future())),
            vec![ok(200, PROFILE), ok(200, USAGE_LOW)],
        );
        probe_profile(&f.d, &f.p, false, &opts());
        // reconnexion : nouvelle lignée
        std::fs::write(
            f.p.credentials_file(),
            creds_json(future()).replace("RT1", "RT9"),
        )
        .unwrap();
        let st = fin(probe_profile(&f.d, &f.p, false, &ProbeOpts::offline()));
        assert_eq!(st.state, State::Unknown);
        assert!(st.five_hour.is_none());
    }

    #[test]
    fn concurrent_writers_never_leave_a_corrupt_cache() {
        let f = fx(Some(&creds_json(future())), vec![]);
        let mut hs = vec![];
        for i in 0..8 {
            let p = f.p.clone();
            hs.push(std::thread::spawn(move || {
                for _ in 0..40 {
                    let mut c = Cache::empty(&format!("fp{i}"), StoreKind::File);
                    c.state = Some(State::Ok);
                    cache::store(&p, &c);
                    assert!(cache::load(&p).is_some(), "lecture d'un cache cassé");
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
    }

    #[test]
    fn probe_all_runs_in_parallel_and_keeps_profile_order() {
        let t = tempfile::tempdir().unwrap();
        let r = Root::new(t.path().to_str().unwrap(), PathStyle::Unix).unwrap();
        let mut profiles = vec![];
        for n in ["1", "2", "3"] {
            let p = r.profile(&Profile::parse(n).unwrap());
            std::fs::create_dir_all(&p.dir).unwrap();
            profiles.push(p);
        }
        std::fs::write(profiles[1].credentials_file(), creds_json(future())).unwrap();
        let http = Arc::new(Scripted {
            replies: Mutex::new(vec![ok(200, PROFILE), ok(200, USAGE_LOW)]),
            urls: Mutex::new(vec![]),
        });
        let d = Deps {
            env: Arc::new(Env::for_tests(t.path().to_path_buf())),
            api: Api::new(http, "http://x", "http://x/token"),
            critical: Arc::new(AtomicUsize::new(0)),
        };
        let out = probe_all(&d, &profiles, "2", &opts());
        let names: Vec<_> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["1", "2", "3"]);
        assert_eq!(out[0].state, State::NotConnected);
        assert_eq!(out[1].state, State::Ok);
        assert!(out[1].active && !out[0].active);
        assert_eq!(out[2].state, State::NotConnected);
    }

    #[test]
    fn jitter_is_stable_and_bounded() {
        let a = jitter_s("compte", 300);
        assert_eq!(a, jitter_s("compte", 300));
        assert!((0..=60).contains(&a));
    }
}
