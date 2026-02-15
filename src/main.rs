use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Deserialize;
use sha2::Sha256;
use std::{
    collections::HashMap,
    env,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::RwLock, time};
use tracing::{error, info, warn};

// ── Types ────────────────────────────────────────────────────────────────────

type VoterStore = Arc<RwLock<HashMap<String, Instant>>>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    store: VoterStore,
    config: AppConfig,
}

#[derive(Clone)]
struct AppConfig {
    topgg_secret: String,
    topgg_project_id: Option<String>,
    rolelogic_token: String,
    rolelogic_guild_id: String,
    rolelogic_role_id: String,
    sync_interval: Duration,
    vote_ttl: Duration,
}

// ── Top.gg Webhook Payload ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct WebhookPayload {
    #[serde(rename = "type")]
    event_type: String,
    data: Option<VoteData>,
}

#[derive(Deserialize)]
struct VoteData {
    project: Option<ProjectInfo>,
    user: UserInfo,
}

#[derive(Deserialize)]
struct ProjectInfo {
    id: Option<String>,
    platform_id: Option<String>,
}

#[derive(Deserialize)]
struct UserInfo {
    platform_id: String,
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let _ = dotenvy::dotenv();

    let config = AppConfig {
        topgg_secret: required_env("TOPGG_WEBHOOK_SECRET"),
        topgg_project_id: optional_env("TOPGG_PROJECT_ID"),
        rolelogic_token: required_env("ROLELOGIC_TOKEN"),
        rolelogic_guild_id: required_env("ROLELOGIC_GUILD_ID"),
        rolelogic_role_id: required_env("ROLELOGIC_ROLE_ID"),
        sync_interval: Duration::from_secs(env_or("SYNC_INTERVAL_SECS", 86400)),
        vote_ttl: Duration::from_secs(env_or("VOTE_TTL_SECS", 86400)),
    };

    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        config: config.clone(),
    };

    // Spawn background sync task
    let sync_state = state.clone();
    tokio::spawn(async move { sync_loop(sync_state).await });

    let app = Router::new()
        .route("/webhook/topgg", post(topgg_webhook))
        .route("/health", get(health))
        .with_state(state);

    let host = env_or_str("HOST", "0.0.0.0");
    let port: u16 = env_or("PORT", 3000);
    let addr = format!("{host}:{port}");

    info!("Listening on {addr}");
    if let Some(ref project_id) = config.topgg_project_id {
        info!("Filtering votes for project {project_id}");
    }

    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

// ── Webhook Handler ──────────────────────────────────────────────────────────

async fn topgg_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // 1. Verify HMAC signature
    if let Err(e) = verify_signature(&headers, &body, &state.config.topgg_secret) {
        warn!("Webhook signature verification failed: {e}");
        return StatusCode::UNAUTHORIZED;
    }

    // 2. Parse payload
    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!("Invalid webhook payload: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // 3. Handle event type
    match payload.event_type.as_str() {
        "vote.create" => {
            let data = match payload.data {
                Some(d) => d,
                None => return StatusCode::BAD_REQUEST,
            };

            // Filter by project ID if configured (matches against project.id or project.platform_id)
            if let Some(ref expected) = state.config.topgg_project_id {
                let matches = data.project.as_ref().is_some_and(|p| {
                    p.id.as_deref() == Some(expected.as_str())
                        || p.platform_id.as_deref() == Some(expected.as_str())
                });
                if !matches {
                    return StatusCode::OK; // Silently ignore votes for other projects
                }
            }

            let user_id = data.user.platform_id;
            info!("Vote received from user {user_id}");

            state.store.write().await.insert(user_id, Instant::now());

            // Immediately sync to RoleLogic
            let sync_state = state.clone();
            tokio::spawn(async move { sync_to_rolelogic(&sync_state).await });

            StatusCode::OK
        }
        "webhook.test" => {
            info!("Test webhook received");
            StatusCode::OK
        }
        other => {
            warn!("Unknown webhook event type: {other}");
            StatusCode::OK
        }
    }
}

// ── Signature Verification ───────────────────────────────────────────────────

fn verify_signature(headers: &HeaderMap, body: &[u8], secret: &str) -> Result<(), String> {
    let sig_header = headers
        .get("x-topgg-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing x-topgg-signature header")?;

    // Parse "t={timestamp},v1={hex}"
    let mut timestamp = None;
    let mut signature = None;
    for part in sig_header.split(',') {
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(v) = part.strip_prefix("v1=") {
            signature = Some(v);
        }
    }

    let timestamp = timestamp.ok_or("missing timestamp in signature")?;
    let signature = signature.ok_or("missing v1 in signature")?;

    // Compute expected HMAC
    let message = format!("{timestamp}.{}", String::from_utf8_lossy(body));
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| format!("hmac init: {e}"))?;
    mac.update(message.as_bytes());

    let expected = hex::encode(mac.finalize().into_bytes());

    if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
        return Err("signature mismatch".into());
    }

    Ok(())
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ── Background Sync ──────────────────────────────────────────────────────────

async fn sync_loop(state: AppState) {
    let mut interval = time::interval(state.config.sync_interval);
    loop {
        interval.tick().await;
        sync_to_rolelogic(&state).await;
    }
}

async fn sync_to_rolelogic(state: &AppState) {
    // Purge expired entries and collect active user IDs
    let user_ids: Vec<String> = {
        let mut store = state.store.write().await;
        store.retain(|_, ts| ts.elapsed() < state.config.vote_ttl);
        store.keys().cloned().collect()
    };

    info!("Syncing {} voter(s) to RoleLogic", user_ids.len());

    let url = format!(
        "https://apirolelogic.faizo.net/api/role-link/{}/{}/users",
        state.config.rolelogic_guild_id, state.config.rolelogic_role_id
    );

    let res = Client::new()
        .put(&url)
        .header("Authorization", format!("Token {}", state.config.rolelogic_token))
        .json(&user_ids)
        .send()
        .await;

    match res {
        Ok(resp) if resp.status().is_success() => {
            info!("RoleLogic sync OK");
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            error!("RoleLogic sync failed ({status}): {text}");
        }
        Err(e) => {
            error!("RoleLogic sync request error: {e}");
        }
    }
}

// ── Health ────────────────────────────────────────────────────────────────────

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let count = state.store.read().await.len();
    (StatusCode::OK, format!("{{\"voters\":{count}}}"))
}

// ── Env Helpers ──────────────────────────────────────────────────────────────

fn required_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

fn optional_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_or_str(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}
