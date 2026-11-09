//! Tests d'intégration : le VRAI binaire `ccp-core` contre un faux serveur HTTP
//! local (tiny_http), un HOME jetable et, sous macOS, un trousseau TEMPORAIRE.
//!
//! Garde-fous de ces tests :
//! - l'environnement du binaire est vidé (`env_clear`) puis reconstruit : aucun
//!   jeton, HOME ni Trousseau réel n'est atteignable ;
//! - `CCP_API_BASE` / `CCP_TOKEN_URL` pointent vers 127.0.0.1 (seules valeurs
//!   acceptées par le binaire) ;
//! - les essais Trousseau passent TOUS par `CCP_KEYCHAIN=<fichier temporaire>`,
//!   détruit en fin de test ; le Trousseau par défaut n'est jamais ouvert.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_ccp-core");

// ------------------------------------------------------------- faux serveur

#[derive(Clone, Debug)]
struct Hit {
    method: String,
    path: String,
    bearer: Option<String>,
}

type Handler = dyn Fn(&Hit, usize) -> (u16, String) + Send + Sync;

struct Fake {
    server: Arc<tiny_http::Server>,
    hits: Arc<Mutex<Vec<Hit>>>,
    join: Option<JoinHandle<()>>,
    port: u16,
}

impl Fake {
    /// `handler(requête, rang de cette requête dans la même route)`.
    fn start(handler: impl Fn(&Hit, usize) -> (u16, String) + Send + Sync + 'static) -> Fake {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("port local"));
        let port = server.server_addr().to_ip().expect("adresse IP").port();
        let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(vec![]));
        let handler: Arc<Handler> = Arc::new(handler);
        let (s2, h2) = (server.clone(), hits.clone());
        let join = std::thread::spawn(move || {
            for mut req in s2.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let bearer = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("authorization"))
                    .map(|h| h.value.as_str().trim_start_matches("Bearer ").to_string());
                let hit = Hit {
                    method: req.method().as_str().to_string(),
                    path: req.url().split('?').next().unwrap_or("").to_string(),
                    bearer,
                };
                let rank = {
                    let mut g = h2.lock().unwrap();
                    let n = g
                        .iter()
                        .filter(|x| x.method == hit.method && x.path == hit.path)
                        .count();
                    g.push(hit.clone());
                    n
                };
                let (code, out) = handler(&hit, rank);
                let resp = tiny_http::Response::from_string(out)
                    .with_status_code(code)
                    .with_header(
                        tiny_http::Header::from_bytes("Content-Type", "application/json").unwrap(),
                    );
                let _ = req.respond(resp);
            }
        });
        Fake {
            server,
            hits,
            join: Some(join),
            port,
        }
    }

    fn api(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn token_url(&self) -> String {
        format!("http://127.0.0.1:{}/token", self.port)
    }

    fn count(&self, method: &str, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.method == method && h.path == path)
            .count()
    }

    fn token_hits(&self) -> usize {
        self.count("POST", "/token")
    }

    fn bearers(&self, path: &str) -> Vec<Option<String>> {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.path == path)
            .map(|h| h.bearer.clone())
            .collect()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

const PROFILE_OK: &str = r#"{"account":{"uuid":"u","email":"sam@x.fr","has_claude_max":true,"has_claude_pro":false},"organization":{"rate_limit_tier":"default_claude_max_20x"}}"#;
const USAGE_OK: &str = r#"{"five_hour":{"utilization":12.7,"resets_at":"2099-11-09T04:00:00+00:00"},"seven_day":{"utilization":40.0,"resets_at":"2099-11-12T10:00:00Z"},"seven_day_sonnet":{"utilization":3.0,"resets_at":"2099-11-12T10:00:00Z"}}"#;
const RENEWED: &str = r#"{"access_token":"NEW-AT","refresh_token":"NEW-RT","expires_in":28800}"#;

/// Serveur sain : profil, quotas, renouvellement qui réussit.
fn healthy(h: &Hit, _rank: usize) -> (u16, String) {
    match (h.method.as_str(), h.path.as_str()) {
        ("GET", "/api/oauth/profile") => (200, PROFILE_OK.into()),
        ("GET", "/api/oauth/usage") => (200, USAGE_OK.into()),
        ("POST", "/token") => (200, RENEWED.into()),
        _ => (404, "{}".into()),
    }
}

// ----------------------------------------------------------------- bac à sable

struct Sandbox {
    _t: tempfile::TempDir,
    home: PathBuf,
    root: String,
    keychain: Option<PathBuf>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Magasin de login : jetons factices, clés inconnues à préserver.
fn creds_json(access: &str, refresh: &str, expires_ms: i64, padding: usize) -> String {
    json!({
        "claudeAiOauth": {
            "accessToken": access,
            "refreshToken": refresh,
            "expiresAt": expires_ms,
            "scopes": ["user:inference", "user:profile"],
            "subscriptionType": "max",
            "rateLimitTier": "default_claude_max_20x",
            "extraInconnu": {"a": [1, 2, 3]}
        },
        "mcpOAuth": {"srv|abc": {"accessToken": "MCPTOK", "pad": "x".repeat(padding)}},
        "autreCle": 42
    })
    .to_string()
}

impl Sandbox {
    fn new() -> Sandbox {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        let root = t.path().join("portable");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        Sandbox {
            home,
            root: root.to_string_lossy().into_owned(),
            keychain: None,
            _t: t,
        }
    }

    fn profile_dir(&self, name: &str) -> PathBuf {
        let d = Path::new(&self.root).join("config").join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Chaîne exacte que ccp-core donnerait à `CLAUDE_CONFIG_DIR`.
    #[cfg_attr(not(any(unix, target_os = "macos")), allow(dead_code))]
    fn cfg(&self, name: &str) -> String {
        format!("{}/config/{name}", self.root)
    }

    fn put_file_login(&self, name: &str, json: &str) {
        std::fs::write(self.profile_dir(name).join(".credentials.json"), json).unwrap();
    }

    fn read_file_login(&self, name: &str) -> Value {
        let s = std::fs::read_to_string(self.profile_dir(name).join(".credentials.json")).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    fn journal(&self, name: &str) -> PathBuf {
        self.profile_dir(name).join(".ccp-pending")
    }

    fn cmd(&self, fake: Option<&Fake>) -> Command {
        let mut c = Command::new(BIN);
        c.env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &self.home)
            .env("USER", "testeur")
            .env("NO_COLOR", "1")
            .env("CCP_CLAUDE_BIN", "/nonexistent/claude");
        if let Some(f) = fake {
            c.env("CCP_API_BASE", f.api())
                .env("CCP_TOKEN_URL", f.token_url());
        } else {
            // Aucune requête réseau ne doit partir : port fermé.
            c.env("CCP_API_BASE", "http://127.0.0.1:1")
                .env("CCP_TOKEN_URL", "http://127.0.0.1:1/token");
        }
        match &self.keychain {
            Some(k) => {
                c.env("CCP_KEYCHAIN", k);
            }
            None => {
                c.env("CCP_NO_KEYCHAIN", "1");
            }
        }
        c.arg("--root").arg(&self.root);
        c
    }

    fn run(&self, fake: Option<&Fake>, args: &[&str]) -> Output {
        self.cmd(fake)
            .args(args)
            .output()
            .expect("lancement de ccp-core")
    }

    fn status_json(&self, fake: &Fake, extra: &[&str]) -> Value {
        let mut args = vec!["accounts", "status", "--format", "json"];
        args.extend_from_slice(extra);
        let o = self.run(Some(fake), &args);
        assert!(
            o.status.success(),
            "status a échoué : {}",
            String::from_utf8_lossy(&o.stderr)
        );
        serde_json::from_slice(&o.stdout).expect("JSON de status")
    }
}

fn account<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == name)
        .unwrap_or_else(|| panic!("compte {name} absent"))
}

fn wait_for(path: &Path, secs: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

// ------------------------------------------------------------------ contrat

#[test]
fn contract_and_version() {
    let sb = Sandbox::new();
    let o = sb.run(None, &["--contract"]);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o), "1\n");
    let o = Command::new(BIN).arg("--version").output().unwrap();
    assert_eq!(code(&o), 0);
    assert!(
        stdout(&o).starts_with("ccp-core "),
        "version : {}",
        stdout(&o)
    );
}

#[test]
fn usage_errors_exit_2_and_nothing_found_exits_3() {
    let sb = Sandbox::new();
    assert_eq!(
        code(&sb.run(None, &["accounts", "status", "--format", "xml"])),
        2
    );
    assert_eq!(code(&sb.run(None, &["accounts", "email", "../evil"])), 2);
    assert_eq!(
        code(&sb.run(
            None,
            &["accounts", "discover", "--missing", "--format", "json"]
        )),
        2
    );
    // `best` ne lit que le cache : rien en cache -> 3, sans réseau.
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    assert_eq!(code(&sb.run(None, &["accounts", "best"])), 3);
    // email inconnu -> 3
    assert_eq!(code(&sb.run(None, &["accounts", "email", "1"])), 3);
}

// -------------------------------------------------------------------- status

#[test]
fn status_json_schema_1_for_a_healthy_account() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OK", "RT-OK", now_ms() + 3_600_000, 0));
    let fake = Fake::start(healthy);
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(r["schema"], 1);
    assert_eq!(r["recommended"], "1");
    let a = account(&r, "1");
    assert_eq!(a["state"], "ok");
    assert_eq!(a["usable"], true);
    assert_eq!(a["email"], "sam@x.fr");
    assert_eq!(a["plan"], "Max x20");
    assert_eq!(a["five_hour"]["pct"], 12);
    assert_eq!(a["seven_day"]["pct"], 40);
    assert_eq!(a["seven_day_sonnet"]["pct"], 3);
    assert_eq!(a["store"], "file");
    assert_eq!(a["stale"], false);
    // jeton valide : AUCUN renouvellement
    assert_eq!(fake.token_hits(), 0);
    // le jeton d'accès est celui du magasin
    assert!(fake
        .bearers("/api/oauth/usage")
        .contains(&Some("AT-OK".to_string())));
    // le JSON ne contient aucun jeton
    let raw = serde_json::to_string(&r).unwrap();
    assert!(!raw.contains("AT-OK") && !raw.contains("RT-OK"));
}

#[test]
fn status_table_has_no_box_drawing_and_respects_width() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    let fake = Fake::start(healthy);
    for width in ["60", "100", "140"] {
        let o = sb.run(
            Some(&fake),
            &["accounts", "status", "--refresh", "--width", width],
        );
        assert_eq!(code(&o), 0);
        let out = stdout(&o);
        assert!(out.contains("Max x20"), "forfait absent :\n{out}");
        assert!(out.contains("12 %"), "quota absent :\n{out}");
        let w: usize = width.parse().unwrap();
        for line in out.lines() {
            assert!(
                line.chars().count() <= w,
                "ligne trop large ({w}) : {line:?}"
            );
            assert!(
                !line.chars().any(|c| ('\u{2500}'..='\u{257f}').contains(&c)),
                "caractère de tracé de boîte : {line:?}"
            );
        }
    }
}

#[test]
fn rate_limit_429_keeps_last_good_values_and_flags_the_state() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    let ok = Fake::start(healthy);
    let first = sb.status_json(&ok, &["--refresh"]);
    assert_eq!(account(&first, "1")["state"], "ok");
    drop(ok);

    let limited = Fake::start(|h, _| match h.path.as_str() {
        "/api/oauth/usage" => (429, "{}".into()),
        _ => healthy(h, 0),
    });
    let r = sb.status_json(&limited, &["--refresh"]);
    let a = account(&r, "1");
    assert_eq!(a["state"], "rate_limited");
    assert_eq!(a["state_label"], "Statut limité");
    assert_eq!(a["usable"], true, "un 429 n'est pas un épuisement");
    assert_eq!(a["five_hour"]["pct"], 12, "dernière bonne valeur conservée");
    assert_eq!(a["stale"], true);
    assert_eq!(r["recommended"], "1");
    assert_eq!(
        limited.token_hits(),
        0,
        "un 429 ne déclenche jamais de renouvellement"
    );
}

#[test]
fn long_lived_token_403_is_valid_not_dead() {
    let sb = Sandbox::new();
    let d = sb.profile_dir("jeton");
    std::fs::write(d.join("oauth.token"), "sk-ant-oat01-factice\n").unwrap();
    std::fs::write(d.join("plan"), "Max x20\n").unwrap();
    let fake = Fake::start(|_, _| (403, "{}".into()));
    let r = sb.status_json(&fake, &["--refresh"]);
    let a = account(&r, "jeton");
    assert_eq!(a["state"], "token_long");
    assert_eq!(a["plan"], "Max x20 (déclaré)");
    assert_eq!(a["plan_declared"], true);
    assert_eq!(fake.token_hits(), 0);
}

#[test]
fn long_lived_token_401_is_dead() {
    let sb = Sandbox::new();
    let d = sb.profile_dir("jeton");
    std::fs::write(d.join("oauth.token"), "sk-ant-oat01-mort").unwrap();
    let fake = Fake::start(|_, _| (401, "{}".into()));
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_ne!(account(&r, "jeton")["state"], "ok");
    assert_eq!(
        fake.token_hits(),
        0,
        "un jeton longue durée ne se renouvelle pas"
    );
}

#[test]
fn profile_without_login_is_not_connected_and_makes_no_request() {
    let sb = Sandbox::new();
    sb.profile_dir("vide");
    let fake = Fake::start(healthy);
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&r, "vide")["state"], "not_connected");
    assert_eq!(
        fake.count("GET", "/api/oauth/profile") + fake.count("GET", "/api/oauth/usage"),
        0
    );
}

#[test]
fn network_down_is_unreachable_exit_4_when_everything_is_down() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    // sans faux serveur : 127.0.0.1:1 refuse la connexion
    let o = sb.run(
        None,
        &["accounts", "status", "--refresh", "--format", "json"],
    );
    assert_eq!(code(&o), 4, "stderr : {}", stderr(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(account(&r, "1")["state"], "unreachable");
}

#[test]
fn offline_and_best_use_the_cache_without_network() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    {
        let fake = Fake::start(healthy);
        sb.status_json(&fake, &["--refresh"]);
    }
    // plus aucun serveur : --offline et best répondent depuis le cache
    let o = sb.run(
        None,
        &["accounts", "status", "--offline", "--format", "json"],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(account(&r, "1")["state"], "ok");
    assert_eq!(account(&r, "1")["five_hour"]["pct"], 12);
    let b = sb.run(None, &["accounts", "best"]);
    assert_eq!(code(&b), 0);
    assert_eq!(stdout(&b), "1\n");
}

#[test]
fn best_picks_the_valid_account_with_the_most_margin() {
    let sb = Sandbox::new();
    for n in ["1", "2", "3"] {
        sb.put_file_login(
            n,
            &creds_json(
                &format!("AT-{n}"),
                &format!("RT-{n}"),
                now_ms() + 3_600_000,
                0,
            ),
        );
    }
    // 1 : 90 % de 5 h ; 2 : 10 % ; 3 : limité (100 %)
    let fake = Fake::start(|h, _| {
        if h.path == "/api/oauth/usage" {
            let pct = match h.bearer.as_deref() {
                Some("AT-1") => 90.0,
                Some("AT-2") => 10.0,
                _ => 100.0,
            };
            return (
                200,
                json!({"five_hour": {"utilization": pct, "resets_at": "2099-11-09T04:00:00Z"},
                       "seven_day": {"utilization": pct, "resets_at": "2099-11-12T10:00:00Z"}})
                .to_string(),
            );
        }
        healthy(h, 0)
    });
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&r, "3")["state"], "limited");
    assert_eq!(r["recommended"], "2");
    let b = sb.run(None, &["accounts", "best"]);
    assert_eq!(stdout(&b), "2\n");
}

// ------------------------------------------------------------------ renouvellement

#[test]
fn expired_token_is_renewed_once_and_the_store_keeps_every_other_key() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(healthy);
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&r, "1")["state"], "ok");
    assert_eq!(fake.token_hits(), 1);

    let v = sb.read_file_login("1");
    assert_eq!(v["claudeAiOauth"]["accessToken"], "NEW-AT");
    assert_eq!(v["claudeAiOauth"]["refreshToken"], "NEW-RT");
    assert!(v["claudeAiOauth"]["expiresAt"].as_i64().unwrap() > now_ms());
    // tout le reste est intact
    assert_eq!(v["claudeAiOauth"]["extraInconnu"], json!({"a": [1, 2, 3]}));
    assert_eq!(
        v["claudeAiOauth"]["rateLimitTier"],
        "default_claude_max_20x"
    );
    assert_eq!(v["mcpOAuth"]["srv|abc"]["accessToken"], "MCPTOK");
    assert_eq!(v["autreCle"], 42);
    assert!(!sb.journal("1").exists(), "journal effacé après écriture");
    // la sonde a utilisé le NOUVEAU jeton
    assert!(fake
        .bearers("/api/oauth/usage")
        .contains(&Some("NEW-AT".to_string())));

    // un second passage n'appelle plus le serveur de jetons
    sb.status_json(&fake, &["--refresh"]);
    assert_eq!(fake.token_hits(), 1);
}

#[test]
fn a_single_401_triggers_exactly_one_renewal() {
    let sb = Sandbox::new();
    sb.put_file_login(
        "1",
        &creds_json("AT-OLD", "RT-OLD", now_ms() + 3_600_000, 0),
    );
    // l'ancien jeton d'accès est refusé, le nouveau accepté
    let fake = Fake::start(|h, _| {
        if h.path.starts_with("/api/oauth") && h.bearer.as_deref() == Some("AT-OLD") {
            return (401, "{}".into());
        }
        healthy(h, 0)
    });
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&r, "1")["state"], "ok");
    assert_eq!(fake.token_hits(), 1);
    assert_eq!(
        sb.read_file_login("1")["claudeAiOauth"]["refreshToken"],
        "NEW-RT"
    );
}

#[test]
fn persistent_401_never_loops() {
    let sb = Sandbox::new();
    sb.put_file_login(
        "1",
        &creds_json("AT-OLD", "RT-OLD", now_ms() + 3_600_000, 0),
    );
    let fake = Fake::start(|h, _| {
        if h.path.starts_with("/api/oauth") {
            return (401, "{}".into());
        }
        healthy(h, 0)
    });
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_ne!(account(&r, "1")["state"], "ok");
    assert_eq!(
        fake.token_hits(),
        1,
        "UN renouvellement par sonde, pas de boucle"
    );
}

#[test]
fn invalid_grant_marks_the_account_to_reconnect_and_is_never_retried() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(|h, _| {
        if h.path == "/token" {
            return (400, r#"{"error":"invalid_grant"}"#.into());
        }
        healthy(h, 0)
    });
    for _ in 0..3 {
        let r = sb.status_json(&fake, &["--refresh"]);
        let a = account(&r, "1");
        assert_eq!(a["state"], "revoked");
        assert_eq!(a["state_label"], "À reconnecter");
        assert_eq!(a["usable"], false);
    }
    assert_eq!(
        fake.token_hits(),
        1,
        "le refus définitif n'est jamais retenté"
    );
    assert!(sb.profile_dir("1").join(".ccp-revoked").exists());
    // le magasin n'a pas bougé
    assert_eq!(
        sb.read_file_login("1")["claudeAiOauth"]["refreshToken"],
        "RT-OLD"
    );
}

#[test]
fn nested_invalid_grant_envelope_also_revokes() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(|h, _| {
        if h.path == "/token" {
            return (
                400,
                r#"{"error":{"type":"invalid_grant","message":"x"}}"#.into(),
            );
        }
        healthy(h, 0)
    });
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&r, "1")["state"], "revoked");
    assert!(sb.profile_dir("1").join(".ccp-revoked").exists());
}

#[test]
fn any_other_refusal_is_an_error_but_never_condemns_the_login() {
    // Même règle que le Claude officiel : sans `invalid_grant`, pas de marqueur.
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(|h, _| {
        if h.path == "/token" {
            return (400, r#"{"error":{"type":"invalid_request_error"}}"#.into());
        }
        healthy(h, 0)
    });
    let r = sb.status_json(&fake, &["--refresh"]);
    let a = account(&r, "1");
    assert_eq!(a["state"], "error");
    assert!(!sb.profile_dir("1").join(".ccp-revoked").exists());
    assert_eq!(
        sb.read_file_login("1")["claudeAiOauth"]["refreshToken"],
        "RT-OLD"
    );
}

#[test]
fn a_new_login_lifts_the_revoked_marker() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(|h, rank| {
        if h.path == "/token" && rank == 0 {
            return (400, r#"{"error":"invalid_grant"}"#.into());
        }
        healthy(h, 0)
    });
    assert_eq!(
        account(&sb.status_json(&fake, &["--refresh"]), "1")["state"],
        "revoked"
    );
    // l'utilisateur se reconnecte : autre lignée, expirée elle aussi
    sb.put_file_login("1", &creds_json("AT-2", "RT-2", 1_000, 0));
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&r, "1")["state"], "ok");
    assert_eq!(fake.token_hits(), 2);
}

#[test]
fn rate_limited_refresh_is_not_a_revocation() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(|h, rank| {
        if h.path == "/token" && rank == 0 {
            return (429, "{}".into());
        }
        healthy(h, 0)
    });
    // le seul compte est injoignable : l'affichage est fait, le code de sortie vaut 4
    let o = sb.run(
        Some(&fake),
        &["accounts", "status", "--refresh", "--format", "json"],
    );
    assert_eq!(code(&o), 4, "{}", stderr(&o));
    let r: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_ne!(account(&r, "1")["state"], "revoked");
    assert!(!sb.profile_dir("1").join(".ccp-revoked").exists());
    // le coup suivant réussit : la lignée était vivante
    let r = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&r, "1")["state"], "ok");
}

#[test]
fn two_simultaneous_probes_renew_only_once() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    // /token lent : élargit la fenêtre où les deux processus se croisent
    let fake = Fake::start(|h, _| {
        if h.path == "/token" {
            std::thread::sleep(Duration::from_millis(400));
        }
        healthy(h, 0)
    });
    let spawn = |sb: &Sandbox| -> Child {
        sb.cmd(Some(&fake))
            .args(["accounts", "status", "--refresh", "--format", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let (a, b) = (spawn(&sb), spawn(&sb));
    let (oa, ob) = (a.wait_with_output().unwrap(), b.wait_with_output().unwrap());
    assert!(oa.status.success() && ob.status.success());
    assert_eq!(
        fake.token_hits(),
        1,
        "un refresh token qui tourne ne se présente qu'une fois"
    );
    assert_eq!(
        sb.read_file_login("1")["claudeAiOauth"]["refreshToken"],
        "NEW-RT"
    );
}

// ------------------------------------------------------- journal write-ahead

/// LA preuve exigée : on tue le processus entre « le serveur a répondu » et
/// « le magasin est écrit » ; le renouvellement suivant retrouve les jetons.
fn crash_between_token_and_write(sb: &Sandbox, fake: &Fake, read_refresh: &dyn Fn() -> String) {
    let marker = sb.home.join("point-d-arret");
    let mut child = sb
        .cmd(Some(fake))
        .env("CCP_FAULT_AFTER_JOURNAL", &marker)
        .args(["accounts", "status", "--refresh", "--format", "json"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for(&marker, 15),
        "le point d'arrêt n'a pas été atteint"
    );
    // À cet instant : le serveur a tourné le jeton, le journal existe, le magasin non.
    assert_eq!(fake.token_hits(), 1);
    assert!(
        sb.journal("1").exists(),
        "le journal doit exister AVANT l'écriture du magasin"
    );
    assert_eq!(
        read_refresh(),
        "RT-OLD",
        "le magasin n'est pas encore écrit"
    );
    child.kill().expect("kill -9");
    child.wait().unwrap();

    // Sans le journal, RT-OLD serait mort côté serveur et NEW-RT perdu.
    let r = sb.status_json(fake, &["--refresh"]);
    assert_eq!(account(&r, "1")["state"], "ok");
    assert_eq!(read_refresh(), "NEW-RT", "le journal a été rejoué");
    assert!(!sb.journal("1").exists(), "journal effacé après rejeu");
    assert_eq!(
        fake.token_hits(),
        1,
        "le rejeu ne rappelle PAS le serveur de jetons"
    );
    assert!(fake
        .bearers("/api/oauth/usage")
        .contains(&Some("NEW-AT".to_string())));
}

#[test]
fn kill_between_new_token_and_write_loses_nothing_file_store() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(healthy);
    let read = || {
        sb.read_file_login("1")["claudeAiOauth"]["refreshToken"]
            .as_str()
            .unwrap()
            .to_string()
    };
    crash_between_token_and_write(&sb, &fake, &read);
    let v = sb.read_file_login("1");
    assert_eq!(v["mcpOAuth"]["srv|abc"]["accessToken"], "MCPTOK");
    assert_eq!(v["autreCle"], 42);
}

#[cfg(unix)]
#[test]
fn run_replays_a_pending_journal_before_launching_claude() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT-OLD", "RT-OLD", 1_000, 0));
    let fake = Fake::start(healthy);
    let marker = sb.home.join("point-d-arret");
    let mut child = sb
        .cmd(Some(&fake))
        .env("CCP_FAULT_AFTER_JOURNAL", &marker)
        .args(["accounts", "status", "--refresh", "--format", "json"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_for(&marker, 15));
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(sb.journal("1").exists());

    // Claude (faux) lit le magasin AU LANCEMENT : il doit y trouver NEW-RT.
    let seen = sb.home.join("vu-par-claude");
    let claude = fake_claude(
        &sb,
        &format!(
            "grep -o '\"refreshToken\":\"[A-Z-]*\"' \"$CLAUDE_CONFIG_DIR/.credentials.json\" > '{}'\nexit 0\n",
            seen.display()
        ),
    );
    let o = sb.run(
        Some(&fake),
        &["run", "1", "--claude", claude.to_str().unwrap()],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        std::fs::read_to_string(&seen).unwrap().trim(),
        "\"refreshToken\":\"NEW-RT\""
    );
    assert!(!sb.journal("1").exists());
    assert_eq!(fake.token_hits(), 1);
}

// --------------------------------------------------------------------- discover

#[test]
fn discover_lists_machine_logins_read_only_and_missing_prints_emails_only() {
    let sb = Sandbox::new();
    // login de la machine
    let machine = sb.home.join(".claude");
    std::fs::create_dir_all(&machine).unwrap();
    std::fs::write(
        machine.join(".credentials.json"),
        creds_json("AT", "RT", now_ms() + 3_600_000, 0),
    )
    .unwrap();
    std::fs::write(
        sb.home.join(".claude.json"),
        r#"{"oauthAccount":{"emailAddress":"contact@atelier-sam.fr"}}"#,
    )
    .unwrap();
    // un profil ancien (expiré) et un profil vide
    let old = sb.home.join(".claude-profiles/primary");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(
        old.join(".credentials.json"),
        creds_json("AT", "RT", 1_000, 0),
    )
    .unwrap();
    std::fs::write(
        old.join(".claude.json"),
        r#"{"oauthAccount":{"emailAddress":"primary@x.fr"}}"#,
    )
    .unwrap();
    let empty = sb.home.join(".claude-profiles/ateliersam86");
    std::fs::create_dir_all(&empty).unwrap();

    let before = tree(&sb.home);
    let o = sb.run(None, &["accounts", "discover", "--width", "100"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let t = stdout(&o);
    assert!(
        t.contains("contact@atelier-sam.fr") && t.contains("Max x20"),
        "{t}"
    );
    assert!(t.contains("aucun identifiant"), "{t}");
    for line in t.lines() {
        assert!(line.chars().count() <= 100, "ligne trop large : {line:?}");
    }

    let m = sb.run(None, &["accounts", "discover", "--missing"]);
    assert_eq!(code(&m), 0);
    // stdout : UN email par ligne et rien d'autre ; le login sans email passe par stderr
    let lines: Vec<String> = stdout(&m).lines().map(str::to_string).collect();
    assert_eq!(lines, ["contact@atelier-sam.fr", "primary@x.fr"]);
    assert!(stderr(&m).contains("ateliersam86"), "{}", stderr(&m));

    let j = sb.run(None, &["accounts", "discover", "--format", "json"]);
    let v: Value = serde_json::from_slice(&j.stdout).unwrap();
    assert_eq!(v["schema"], 1);
    assert!(v["logins"].as_array().unwrap().len() >= 3);
    assert!(
        !String::from_utf8_lossy(&j.stdout).contains("\"RT\""),
        "aucun jeton dans le JSON"
    );

    assert_eq!(before, tree(&sb.home), "discover n'écrit rien");
}

fn tree(dir: &Path) -> Vec<String> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let m = std::fs::metadata(&p).unwrap();
                out.push(format!("{} {}", p.display(), m.len()));
            }
        }
    }
    out.sort();
    out
}

// -------------------------------------------------------------------------- run

#[cfg(unix)]
fn fake_claude(sb: &Sandbox, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let n = std::fs::read_dir(&sb.home).unwrap().count();
    let p = sb.home.join(format!("claude-faux-{n}"));
    std::fs::write(&p, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[cfg(unix)]
#[test]
fn run_sets_the_environment_propagates_the_exit_code_and_probes_after() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    let out = sb.home.join("env.txt");
    let claude = fake_claude(
        &sb,
        &format!(
            "{{ echo \"cfg=$CLAUDE_CONFIG_DIR\"; echo \"upd=$DISABLE_AUTOUPDATER\"; echo \"tok=${{CLAUDE_CODE_OAUTH_TOKEN:-absent}}\"; echo \"args=$*\"; }} > '{}'\nexit 7\n",
            out.display()
        ),
    );
    let fake = Fake::start(healthy);
    let o = sb
        .cmd(Some(&fake))
        // un jeton hérité de l'environnement ne doit pas atteindre un profil à login
        .env("CLAUDE_CODE_OAUTH_TOKEN", "HERITE")
        .args([
            "run",
            "1",
            "--claude",
            claude.to_str().unwrap(),
            "--",
            "--resume",
            "x y",
        ])
        .output()
        .unwrap();
    assert_eq!(
        code(&o),
        7,
        "le code de Claude est propagé : {}",
        stderr(&o)
    );
    let seen = std::fs::read_to_string(&out).unwrap();
    assert!(seen.contains(&format!("cfg={}\n", sb.cfg("1"))), "{seen}");
    assert!(seen.contains("upd=1"));
    assert!(seen.contains("tok=absent"), "{seen}");
    assert!(seen.contains("args=--resume x y"));
    // sonde rapide après la session
    assert!(fake.count("GET", "/api/oauth/usage") >= 1);
}

#[cfg(unix)]
#[test]
fn run_gives_the_long_lived_token_only_to_token_only_profiles() {
    let sb = Sandbox::new();
    std::fs::write(
        sb.profile_dir("jeton").join("oauth.token"),
        "sk-ant-oat01-LONG\n",
    )
    .unwrap();
    let out = sb.home.join("tok.txt");
    let claude = fake_claude(
        &sb,
        &format!(
            "echo \"${{CLAUDE_CODE_OAUTH_TOKEN:-absent}}\" > '{}'\n",
            out.display()
        ),
    );
    let fake = Fake::start(|_, _| (403, "{}".into()));
    let o = sb.run(
        Some(&fake),
        &["run", "jeton", "--claude", claude.to_str().unwrap()],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap().trim(),
        "sk-ant-oat01-LONG"
    );

    // même profil, mais avec un login : le jeton n'est plus transmis
    sb.put_file_login("jeton", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    let o = sb.run(
        Some(&fake),
        &["run", "jeton", "--claude", claude.to_str().unwrap()],
    );
    assert_eq!(code(&o), 0);
    assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "absent");
}

#[cfg(unix)]
#[test]
fn a_second_run_on_an_open_profile_exits_5() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    let started = sb.home.join("demarre");
    let release = sb.home.join("fin");
    let claude = fake_claude(
        &sb,
        &format!(
            "touch '{}'\nwhile [ ! -e '{}' ]; do sleep 0.05; done\nexit 0\n",
            started.display(),
            release.display()
        ),
    );
    let fake = Fake::start(healthy);
    let first = sb
        .cmd(Some(&fake))
        .args(["run", "1", "--claude", claude.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_for(&started, 10));

    let second = sb.run(
        Some(&fake),
        &["run", "1", "--claude", claude.to_str().unwrap()],
    );
    assert_eq!(code(&second), 5, "{}", stderr(&second));
    assert!(stderr(&second).contains("déjà ouvert"));

    // pendant la session : un renouvellement ne peut pas se faire (verrou tenu)
    let st = sb.status_json(&fake, &["--refresh"]);
    assert_eq!(account(&st, "1")["running"], true);

    std::fs::write(&release, "").unwrap();
    let o = first.wait_with_output().unwrap();
    assert_eq!(code(&o), 0);
}

#[cfg(unix)]
#[test]
fn run_restores_sigint_for_claude_even_when_the_wizard_ignores_it() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    // Claude (faux) s'envoie SIGINT : avec SIGINT hérité « ignoré » il survivrait.
    let claude = fake_claude(&sb, "kill -INT $$\nsleep 2\nexit 0\n");
    let fake = Fake::start(healthy);
    // `trap '' INT` comme le wizard bash, puis exec : SIG_IGN est hérité par ccp-core.
    let o = Command::new("/bin/sh")
        .arg("-c")
        .arg("trap '' INT; exec \"$0\" \"$@\"")
        .arg(BIN)
        .args([
            "--root",
            &sb.root,
            "run",
            "1",
            "--claude",
            claude.to_str().unwrap(),
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &sb.home)
        .env("USER", "testeur")
        .env("CCP_NO_KEYCHAIN", "1")
        .env("CCP_API_BASE", fake.api())
        .env("CCP_TOKEN_URL", fake.token_url())
        .output()
        .unwrap();
    assert_eq!(
        code(&o),
        130,
        "Claude doit mourir de SIGINT (128+2) : {}",
        stderr(&o)
    );
}

#[cfg(unix)]
#[test]
fn run_on_a_missing_claude_binary_exits_3() {
    let sb = Sandbox::new();
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    let o = sb.run(None, &["run", "1", "--claude", "/nonexistent/claude"]);
    assert_eq!(code(&o), 3, "{}", stderr(&o));
}

// -------------------------------------------------------------------- doctor

#[cfg(unix)]
#[test]
fn doctor_flags_a_divergence_with_claude_auth_status() {
    let sb = Sandbox::new();
    // ccp-core lit un login ; le faux claude jure qu'il n'y en a pas
    sb.put_file_login("1", &creds_json("AT", "RT", now_ms() + 3_600_000, 0));
    let claude = fake_claude(&sb, "echo '{\"loggedIn\":false}'\n");
    let o = sb.run(None, &["doctor", "1", "--claude", claude.to_str().unwrap()]);
    assert_eq!(code(&o), 6, "{}{}", stdout(&o), stderr(&o));
    assert!(
        stdout(&o).to_lowercase().contains("indéterminé"),
        "{}",
        stdout(&o)
    );

    // accord : même verdict des deux côtés
    let claude = fake_claude(
        &sb,
        "echo '{\"loggedIn\":true,\"email\":\"sam@x.fr\",\"planTier\":\"max_20x\"}'\n",
    );
    let o = sb.run(None, &["doctor", "1", "--claude", claude.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}{}", stdout(&o), stderr(&o));
}

/// Canari de contrat avec le VRAI Claude (aucun réseau, aucun vrai jeton) : sur un
/// dossier de config neuf, ccp-core et `claude auth status` doivent lire la même
/// chose. Casse si une mise à jour de Claude change le magasin ou son nom de service.
/// Lancement : `CCP_REAL_CLAUDE=$(whence -p claude) cargo test -- --ignored real_claude`
#[test]
#[ignore = "exige CCP_REAL_CLAUDE=<chemin du vrai claude>"]
fn real_claude_reads_the_same_store_as_ccp_core() {
    let Some(claude) = std::env::var_os("CCP_REAL_CLAUDE") else {
        panic!("CCP_REAL_CLAUDE absent");
    };
    let sb = Sandbox::new();
    sb.put_file_login(
        "faux",
        &creds_json(
            "sk-ant-oat01-FACTICE",
            "sk-ant-ort01-FACTICE",
            now_ms() + 3_600_000,
            0,
        ),
    );
    sb.profile_dir("vide");
    let o = sb
        .cmd(None)
        .env_remove("CCP_CLAUDE_BIN")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .args(["doctor", "--claude"])
        .arg(&claude)
        .output()
        .unwrap();
    let out = stdout(&o);
    assert_eq!(code(&o), 0, "{out}{}", stderr(&o));
    assert_eq!(out.matches("verdict : cohérent").count(), 2, "{out}");
}

// ------------------------------------------------------- Trousseau (macOS)

#[cfg(target_os = "macos")]
mod keychain {
    use super::*;
    use ccp_core::creds::keychain::service_name;

    const SECURITY: &str = "/usr/bin/security";

    /// Trousseau temporaire détruit à la fin du test.
    struct TempKeychain {
        path: PathBuf,
    }

    impl TempKeychain {
        fn create(dir: &Path) -> TempKeychain {
            let path = dir.join("essai.keychain");
            let st = Command::new(SECURITY)
                .args(["create-keychain", "-p", "pw-essai"])
                .arg(&path)
                .status()
                .unwrap();
            assert!(st.success(), "création du trousseau temporaire");
            // pas de verrouillage automatique pendant le test
            let _ = Command::new(SECURITY)
                .args(["set-keychain-settings"])
                .arg(&path)
                .status();
            let _ = Command::new(SECURITY)
                .args(["unlock-keychain", "-p", "pw-essai"])
                .arg(&path)
                .status();
            TempKeychain { path }
        }

        fn add(&self, acct: &str, svc: &str, secret: &str) {
            let st = Command::new(SECURITY)
                .args(["add-generic-password", "-a", acct, "-s", svc, "-w", secret])
                .arg(&self.path)
                .status()
                .unwrap();
            assert!(st.success(), "ajout de l'item d'essai");
        }

        /// `None` = absent (code 44).
        fn read(&self, acct: &str, svc: &str) -> Option<String> {
            let o = Command::new(SECURITY)
                .args(["find-generic-password", "-a", acct, "-s", svc, "-w"])
                .arg(&self.path)
                .output()
                .unwrap();
            match o.status.code() {
                Some(0) => Some(ccp_core::creds::keychain::decode_password_output(
                    &String::from_utf8_lossy(&o.stdout),
                )),
                Some(44) => None,
                c => panic!("lecture Trousseau : code {c:?}"),
            }
        }
    }

    impl Drop for TempKeychain {
        fn drop(&mut self) {
            let _ = Command::new(SECURITY)
                .arg("delete-keychain")
                .arg(&self.path)
                .status();
        }
    }

    fn sandbox_with_keychain() -> (Sandbox, TempKeychain) {
        let mut sb = Sandbox::new();
        let kc = TempKeychain::create(&sb.home);
        sb.keychain = Some(kc.path.clone());
        (sb, kc)
    }

    fn refresh_of(blob: &str) -> String {
        let v: Value = serde_json::from_str(blob).unwrap();
        v["claudeAiOauth"]["refreshToken"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn the_temp_keychain_is_the_only_one_touched() {
        let (sb, kc) = sandbox_with_keychain();
        let svc = service_name(&sb.cfg("1"));
        kc.add(
            "compte-origine",
            &svc,
            &creds_json("AT-OLD", "RT-OLD", 1_000, 0),
        );
        sb.profile_dir("1");
        let fake = Fake::start(healthy);
        let r = sb.status_json(&fake, &["--refresh"]);
        let a = account(&r, "1");
        assert_eq!(a["state"], "ok");
        assert_eq!(a["store"], "keychain");
        // réécrit dans le MÊME item (compte d'origine réutilisé, aucun doublon)
        let after = kc.read("compte-origine", &svc).expect("item conservé");
        assert_eq!(refresh_of(&after), "NEW-RT");
        assert!(
            kc.read("testeur", &svc).is_none(),
            "pas d'item sous un autre compte"
        );
        let v: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(v["mcpOAuth"]["srv|abc"]["accessToken"], "MCPTOK");
        assert_eq!(v["autreCle"], 42);
        // pas de .credentials.json créé à côté
        assert!(!sb.profile_dir("1").join(".credentials.json").exists());
    }

    #[test]
    fn kill_between_new_token_and_write_loses_nothing_keychain() {
        let (sb, kc) = sandbox_with_keychain();
        let svc = service_name(&sb.cfg("1"));
        kc.add(
            "compte-origine",
            &svc,
            &creds_json("AT-OLD", "RT-OLD", 1_000, 0),
        );
        sb.profile_dir("1");
        let fake = Fake::start(healthy);
        let read = || refresh_of(&kc.read("compte-origine", &svc).unwrap());
        crash_between_token_and_write(&sb, &fake, &read);
        assert!(kc.read("testeur", &svc).is_none());
    }

    #[test]
    fn a_payload_beyond_the_security_stdin_limit_is_written_and_read_back() {
        let (sb, kc) = sandbox_with_keychain();
        let svc = service_name(&sb.cfg("1"));
        // 6 Ko de mcpOAuth : au-delà des 4 096 caractères que `security -i` accepte par ligne
        let big = creds_json("AT-OLD", "RT-OLD", 1_000, 6000);
        assert!(big.len() > 6000);
        kc.add("compte-origine", &svc, &big);
        sb.profile_dir("1");
        let fake = Fake::start(healthy);
        let r = sb.status_json(&fake, &["--refresh"]);
        assert_eq!(account(&r, "1")["state"], "ok");
        let after = kc.read("compte-origine", &svc).unwrap();
        assert_eq!(refresh_of(&after), "NEW-RT");
        let v: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(
            v["mcpOAuth"]["srv|abc"]["pad"].as_str().unwrap().len(),
            6000
        );
    }

    #[test]
    fn purge_removes_portable_services_and_never_the_unsuffixed_machine_one() {
        let (sb, kc) = sandbox_with_keychain();
        let svc1 = service_name(&sb.cfg("1"));
        let svc2 = service_name(&sb.cfg("2"));
        sb.profile_dir("1");
        sb.profile_dir("2");
        kc.add("testeur", &svc1, &creds_json("A", "R", 1, 0));
        kc.add("testeur", &svc2, &creds_json("A", "R", 1, 0));
        kc.add(
            "testeur",
            "Claude Code-credentials",
            &creds_json("MACHINE", "MACHINE", 1, 0),
        );

        let o = sb.run(None, &["accounts", "purge", "1"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(kc.read("testeur", &svc1).is_none());
        assert!(
            kc.read("testeur", &svc2).is_some(),
            "seul le profil demandé est purgé"
        );

        let o = sb.run(None, &["accounts", "purge"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(kc.read("testeur", &svc2).is_none());
        assert!(
            kc.read("testeur", "Claude Code-credentials").is_some(),
            "la session de la machine (service sans suffixe) n'est JAMAIS supprimée"
        );
    }

    #[test]
    fn discover_reads_the_keychain_without_writing_it() {
        let (sb, kc) = sandbox_with_keychain();
        let svc = service_name(&sb.cfg("1"));
        let blob = creds_json("AT", "RT", now_ms() + 3_600_000, 0);
        kc.add("testeur", &svc, &blob);
        sb.profile_dir("1");
        let o = sb.run(None, &["accounts", "discover", "--format", "json"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert_eq!(kc.read("testeur", &svc).as_deref(), Some(blob.as_str()));
    }
}
