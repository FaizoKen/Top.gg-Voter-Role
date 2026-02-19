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
use chrono::{SecondsFormat, Utc};
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
    topgg_token: String,
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
    user: UserInfo,
}

#[derive(Deserialize)]
struct UserInfo {
    platform_id: String,
}

// ── Top.gg API Response ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TopggVotesResponse {
    cursor: Option<String>,
    data: Vec<TopggVoteEntry>,
}

#[derive(Deserialize)]
struct TopggVoteEntry {
    platform_id: String,
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let _ = dotenvy::dotenv();

    let config = AppConfig {
        topgg_secret: required_env("TOPGG_WEBHOOK_SECRET"),
        topgg_token: required_env("TOPGG_TOKEN"),
        rolelogic_token: required_env("ROLELOGIC_TOKEN"),
        rolelogic_guild_id: required_env("ROLELOGIC_GUILD_ID"),
        rolelogic_role_id: required_env("ROLELOGIC_ROLE_ID"),
        sync_interval: Duration::from_secs(env_or("SYNC_INTERVAL_SECS", 43200)),
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

            let user_id = data.user.platform_id;
            info!("Vote received from user {user_id}");

            let voted_at = Instant::now();
            state.store.write().await.insert(user_id.clone(), voted_at);

            // Add single member to RoleLogic
            let add_state = state.clone();
            let add_user_id = user_id.clone();
            tokio::spawn(async move { add_member(&add_state, &add_user_id).await });

            // Schedule removal after TTL expires
            schedule_removal(&state, user_id, voted_at);

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

// ── Single Member API ────────────────────────────────────────────────────────

async fn add_member(state: &AppState, user_id: &str) {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/{}",
        state.config.rolelogic_guild_id, state.config.rolelogic_role_id, user_id
    );

    let res = Client::new()
        .post(&url)
        .header(
            "Authorization",
            format!("Token {}", state.config.rolelogic_token),
        )
        .send()
        .await;

    match res {
        Ok(resp) if resp.status().is_success() => {
            info!("RoleLogic add member OK: {user_id}");
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            error!("RoleLogic add member failed ({status}): {text}");
        }
        Err(e) => {
            error!("RoleLogic add member request error: {e}");
        }
    }
}

async fn remove_member(state: &AppState, user_id: &str) {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/{}",
        state.config.rolelogic_guild_id, state.config.rolelogic_role_id, user_id
    );

    let res = Client::new()
        .delete(&url)
        .header(
            "Authorization",
            format!("Token {}", state.config.rolelogic_token),
        )
        .send()
        .await;

    match res {
        Ok(resp) if resp.status().is_success() => {
            info!("RoleLogic remove member OK: {user_id}");
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            error!("RoleLogic remove member failed ({status}): {text}");
        }
        Err(e) => {
            error!("RoleLogic remove member request error: {e}");
        }
    }
}

fn schedule_removal(state: &AppState, user_id: String, voted_at: Instant) {
    let state = state.clone();
    let ttl = state.config.vote_ttl;
    tokio::spawn(async move {
        time::sleep(ttl).await;

        // Check if this vote is still the active one (user hasn't re-voted)
        let should_remove = {
            let mut store = state.store.write().await;
            if let Some(&stored_at) = store.get(&user_id) {
                if stored_at == voted_at {
                    store.remove(&user_id);
                    true
                } else {
                    false // User re-voted; the newer timer will handle removal
                }
            } else {
                false // Already removed
            }
        };

        if should_remove {
            info!("TTL expired for user {user_id}, removing from RoleLogic");
            remove_member(&state, &user_id).await;
        }
    });
}

// ── Top.gg Vote Fetching ─────────────────────────────────────────────────────

async fn fetch_topgg_votes(config: &AppConfig) -> Result<Vec<String>, String> {
    let vote_ttl_secs = config.vote_ttl.as_secs() as i64;
    let start_date =
        (Utc::now() - chrono::TimeDelta::seconds(vote_ttl_secs)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let client = Client::new();
    let mut seen = std::collections::HashSet::new();
    let mut cursor: Option<String> = None;

    loop {
        let mut request = client
            .get("https://top.gg/api/v1/projects/@me/votes")
            .header("Authorization", format!("Bearer {}", config.topgg_token))
            .query(&[("startDate", start_date.as_str())]);

        if let Some(ref c) = cursor {
            request = request.query(&[("cursor", c.as_str())]);
        }

        let resp = request
            .send()
            .await
            .map_err(|e| format!("top.gg request error: {e}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("top.gg API error ({status}): {text}"));
        }

        let page: TopggVotesResponse = resp
            .json()
            .await
            .map_err(|e| format!("top.gg parse error: {e}"))?;

        if page.data.is_empty() {
            break;
        }

        let mut new_entries = false;
        for entry in page.data {
            if seen.insert(entry.platform_id.clone()) {
                new_entries = true;
            }
        }

        if !new_entries {
            break; // All entries already seen, stop paginating
        }

        match page.cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Ok(seen.into_iter().collect())
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
    // 1. Fetch recent votes from top.gg
    let user_ids = match fetch_topgg_votes(&state.config).await {
        Ok(ids) => {
            info!("Fetched {} voter(s) from top.gg", ids.len());
            ids
        }
        Err(e) => {
            error!("Failed to fetch votes from top.gg: {e}");
            return;
        }
    };

    // 2. Update in-memory store with fetched votes
    {
        let mut store = state.store.write().await;
        store.clear();
        let now = Instant::now();
        for id in &user_ids {
            store.insert(id.clone(), now);
        }
    }

    // 3. Sync to RoleLogic
    info!("Syncing {} voter(s) to RoleLogic", user_ids.len());

    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users",
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

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_or_str(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}
