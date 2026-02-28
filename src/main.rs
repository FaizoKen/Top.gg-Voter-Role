use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
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
    runtime: Arc<RwLock<RuntimeConfig>>,
    rolelogic_token: Arc<RwLock<String>>,
}

#[derive(Clone)]
struct AppConfig {
    topgg_secret: String,
    topgg_token: String,
    rolelogic_guild_id: String,
    rolelogic_role_id: String,
}

#[derive(Clone)]
struct RuntimeConfig {
    vote_ttl: Duration,
    sync_interval: Duration,
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
        rolelogic_guild_id: required_env("ROLELOGIC_GUILD_ID"),
        rolelogic_role_id: required_env("ROLELOGIC_ROLE_ID"),
    };

    let runtime = Arc::new(RwLock::new(RuntimeConfig {
        vote_ttl: Duration::from_secs(env_or("VOTE_TTL_SECS", 86400)),
        sync_interval: Duration::from_secs(env_or("SYNC_INTERVAL_SECS", 43200)),
    }));

    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        config: config.clone(),
        runtime,
        rolelogic_token: Arc::new(RwLock::new(String::new())),
    };

    // Spawn background sync task
    let sync_state = state.clone();
    tokio::spawn(async move { sync_loop(sync_state).await });

    let app = Router::new()
        .route("/webhook/topgg", post(topgg_webhook))
        .route("/health", get(health))
        .route("/register", post(plugin_register))
        .route("/schema", get(plugin_schema))
        .route("/config", post(plugin_config_update).delete(plugin_config_delete))
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

// ── Plugin Server Endpoints ──────────────────────────────────────────────────

fn extract_rolelogic_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Token "))
        .map(|t| t.to_string())
}

async fn save_rolelogic_token(state: &AppState, headers: &HeaderMap) {
    if let Some(token) = extract_rolelogic_token(headers) {
        let mut current = state.rolelogic_token.write().await;
        if *current != token {
            info!("Updated RoleLogic token from incoming request");
            *current = token;
        }
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    guild_id: String,
    role_id: String,
}

async fn plugin_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    save_rolelogic_token(&state, &headers).await;

    info!(
        "Registered with RoleLogic for guild={} role={}",
        payload.guild_id, payload.role_id
    );

    Ok(Json(serde_json::json!({ "success": true })))
}

#[derive(Serialize)]
struct SchemaResponse {
    version: u32,
    name: String,
    description: String,
    sections: Vec<SchemaSection>,
    values: serde_json::Value,
}

#[derive(Serialize)]
struct SchemaSection {
    title: String,
    fields: Vec<SchemaField>,
}

#[derive(Serialize)]
struct SchemaField {
    #[serde(rename = "type")]
    field_type: String,
    key: String,
    label: String,
    description: String,
    validation: serde_json::Value,
}

#[derive(Deserialize)]
struct PluginConfigRequest {
    guild_id: String,
    role_id: String,
    config: PluginConfigValues,
}

#[derive(Deserialize)]
struct PluginConfigValues {
    vote_ttl_hours: Option<f64>,
    sync_interval_hours: Option<f64>,
}


async fn plugin_schema(
    State(state): State<AppState>,
) -> Json<SchemaResponse> {
    let runtime = state.runtime.read().await;
    let vote_ttl_hours = runtime.vote_ttl.as_secs_f64() / 3600.0;
    let sync_interval_hours = runtime.sync_interval.as_secs_f64() / 3600.0;

    Json(SchemaResponse {
        version: 1,
        name: "VoterRole".to_string(),
        description: "Assigns a Discord role to users who vote on Top.gg. The role is automatically removed when the vote expires.".to_string(),
        sections: vec![SchemaSection {
            title: "Timing".to_string(),
            fields: vec![
                SchemaField {
                    field_type: "number".to_string(),
                    key: "vote_ttl_hours".to_string(),
                    label: "Vote Duration (hours)".to_string(),
                    description: "How long a vote lasts before the role is removed".to_string(),
                    validation: serde_json::json!({"required": true, "min": 1, "max": 168}),
                },
                SchemaField {
                    field_type: "number".to_string(),
                    key: "sync_interval_hours".to_string(),
                    label: "Sync Interval (hours)".to_string(),
                    description: "How often to re-sync all voters with RoleLogic".to_string(),
                    validation: serde_json::json!({"required": true, "min": 1, "max": 168}),
                },
            ],
        }],
        values: serde_json::json!({
            "vote_ttl_hours": vote_ttl_hours,
            "sync_interval_hours": sync_interval_hours,
        }),
    })
}

async fn plugin_config_update(
    State(state): State<AppState>,
    Json(payload): Json<PluginConfigRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {

    if payload.guild_id != state.config.rolelogic_guild_id
        || payload.role_id != state.config.rolelogic_role_id
    {
        warn!(
            "Config update for unknown guild/role: {}/{}",
            payload.guild_id, payload.role_id
        );
        return Err(StatusCode::NOT_FOUND);
    }

    let mut runtime = state.runtime.write().await;
    if let Some(hours) = payload.config.vote_ttl_hours {
        runtime.vote_ttl = Duration::from_secs_f64(hours * 3600.0);
        info!("Updated vote_ttl to {} hours", hours);
    }
    if let Some(hours) = payload.config.sync_interval_hours {
        runtime.sync_interval = Duration::from_secs_f64(hours * 3600.0);
        info!("Updated sync_interval to {} hours", hours);
    }

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Deserialize)]
struct PluginDeleteRequest {
    guild_id: String,
    role_id: String,
}

async fn plugin_config_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PluginDeleteRequest>,
) -> Result<StatusCode, StatusCode> {
    save_rolelogic_token(&state, &headers).await;

    info!(
        "Received config delete notification for guild={} role={}",
        payload.guild_id, payload.role_id
    );

    Ok(StatusCode::OK)
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
            format!("Token {}", state.rolelogic_token.read().await),
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
            format!("Token {}", state.rolelogic_token.read().await),
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
    tokio::spawn(async move {
        let ttl = state.runtime.read().await.vote_ttl;
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

async fn fetch_topgg_votes(config: &AppConfig, vote_ttl: Duration) -> Result<Vec<String>, String> {
    let vote_ttl_secs = vote_ttl.as_secs() as i64;
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
    loop {
        let interval_duration = state.runtime.read().await.sync_interval;
        time::sleep(interval_duration).await;
        sync_to_rolelogic(&state).await;
    }
}

async fn sync_to_rolelogic(state: &AppState) {
    // 1. Fetch recent votes from top.gg
    let vote_ttl = state.runtime.read().await.vote_ttl;
    let user_ids = match fetch_topgg_votes(&state.config, vote_ttl).await {
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
        .header("Authorization", format!("Token {}", state.rolelogic_token.read().await))
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
