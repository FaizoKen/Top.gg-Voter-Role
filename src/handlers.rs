use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tracing::{error, info, warn};

use crate::{
    AppState, crypto, db,
    models::*,
    sync::sync_single_registration,
};

// ── Webhook Handler ─────────────────────────────────────────────────────────

pub async fn topgg_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // 1. Fetch all registrations that have a topgg_secret
    let registrations = match db::get_registrations_with_secret(&state.db).await {
        Ok(r) => r,
        Err(e) => {
            error!("DB error fetching registrations: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // 2. Find registrations whose secret matches the HMAC signature
    let matched: Vec<_> = registrations
        .into_iter()
        .filter(|reg| {
            let secret = reg.topgg_secret.as_deref().unwrap_or_default();
            crypto::verify_signature(&headers, &body, secret).is_ok()
        })
        .collect();

    if matched.is_empty() {
        warn!("Webhook signature did not match any registration");
        return StatusCode::UNAUTHORIZED;
    }

    // 3. Parse payload
    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!("Invalid webhook payload: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // 4. Handle event type
    match payload.event_type.as_str() {
        "vote.create" => {
            let data = match payload.data {
                Some(d) => d,
                None => return StatusCode::BAD_REQUEST,
            };

            let user_id = data.user.platform_id;

            for reg in &matched {
                info!("Vote received from user {user_id} for reg {}", reg.id);

                if let Err(e) = db::upsert_voter(&state.db, reg.id, &user_id).await {
                    error!("Failed to store voter for reg {}: {e}", reg.id);
                    continue;
                }

                let s = state.clone();
                let uid = user_id.clone();
                let r = reg.clone();
                tokio::spawn(async move { add_member(&s, &r, &uid).await });
            }

            StatusCode::OK
        }
        "webhook.test" => {
            info!(
                "Test webhook received, matched {} registration(s)",
                matched.len()
            );
            StatusCode::OK
        }
        other => {
            warn!("Unknown webhook event type: {other}");
            StatusCode::OK
        }
    }
}

// ── Plugin Endpoints ────────────────────────────────────────────────────────

pub async fn plugin_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = extract_auth_token(&headers)?;

    let reg = db::upsert_registration(
        &state.db,
        &payload.guild_id,
        &payload.role_id,
        token,
        payload.topgg_secret.as_deref(),
        payload.topgg_token.as_deref(),
    )
    .await
    .map_err(|e| {
        error!("DB error on registration: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        "Registered for guild={} role={} (id={})",
        payload.guild_id, payload.role_id, reg.id
    );

    let registration_id = reg.id;

    // Trigger initial sync if TOP.gg credentials are configured
    if reg.has_topgg_credentials() {
        let s = state.clone();
        tokio::spawn(async move { sync_single_registration(&s, &reg).await });
    }

    Ok(Json(serde_json::json!({
        "success": true,
        "webhook_path": "/webhook/topgg",
        "registration_id": registration_id
    })))
}

pub async fn plugin_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ConfigResponse>, StatusCode> {
    let token = extract_auth_token(&headers)?;

    let reg = db::get_registration_by_token(&state.db, token)
        .await
        .map_err(|e| {
            error!("DB error fetching registration: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let vote_ttl_hours = reg.vote_ttl_secs as f64 / 3600.0;
    let topgg_secret = reg.topgg_secret.clone().unwrap_or_default();
    let topgg_token = reg.topgg_token.clone().unwrap_or_default();

    let webhook_url = format!("{}/webhook/topgg", state.public_url);

    Ok(Json(ConfigResponse {
        version: 1,
        name: "Top.gg Voter Role".to_string(),
        description: "Assigns a Discord role to users who vote on Top.gg. The role is automatically removed when the vote expires.".to_string(),
        sections: vec![
            ConfigSection {
                title: "Webhook URL".to_string(),
                description: Some("Copy this URL and paste it into your Top.gg Webhooks settings.".to_string()),
                fields: vec![ConfigField {
                    field_type: "display".to_string(),
                    key: "webhook_url".to_string(),
                    label: "Your Webhook URL".to_string(),
                    description: String::new(),
                    placeholder: None,
                    validation: None,
                    value: Some(webhook_url),
                }],
            },
            ConfigSection {
                title: "Setup Guide".to_string(),
                description: None,
                fields: vec![ConfigField {
                    field_type: "display".to_string(),
                    key: "guide".to_string(),
                    label: "How to connect Top.gg".to_string(),
                    description: String::new(),
                    placeholder: None,
                    validation: None,
                    value: Some(
                        "1. Go to your Top.gg dashboard and find the Webhooks section.\n\
                         2. Paste the Webhook URL shown above into the webhook URL field on Top.gg.\n\
                         3. Copy the Webhook Secret from Top.gg and paste it below.\n\
                         4. Go to the API section on Top.gg and generate an API Token, then paste it below.\n\
                         5. Click Save to activate vote tracking."
                            .to_string(),
                    ),
                }],
            },
            ConfigSection {
                title: "Top.gg Credentials".to_string(),
                description: Some("Enter the credentials from your Top.gg dashboard.".to_string()),
                fields: vec![
                    ConfigField {
                        field_type: "secret".to_string(),
                        key: "topgg_secret".to_string(),
                        label: "Webhook Secret".to_string(),
                        description: "Found in your Top.gg dashboard under Webhooks.".to_string(),
                        placeholder: Some("Paste your Top.gg webhook secret here".to_string()),
                        validation: Some(serde_json::json!({"required": true})),
                        value: None,
                    },
                    ConfigField {
                        field_type: "secret".to_string(),
                        key: "topgg_token".to_string(),
                        label: "API Token".to_string(),
                        description: "Found in your Top.gg dashboard under API.".to_string(),
                        placeholder: Some("Paste your Top.gg API token here".to_string()),
                        validation: Some(serde_json::json!({"required": true})),
                        value: None,
                    },
                ],
            },
            ConfigSection {
                title: "Timing".to_string(),
                description: None,
                fields: vec![ConfigField {
                    field_type: "number".to_string(),
                    key: "vote_ttl_hours".to_string(),
                    label: "Vote Duration (hours)".to_string(),
                    description: "How long a user keeps the role after voting. Minimum 1 hour, maximum 168 hours (7 days).".to_string(),
                    placeholder: Some("12".to_string()),
                    validation: Some(serde_json::json!({"required": true, "min": 1, "max": 168})),
                    value: None,
                }],
            },
        ],
        values: serde_json::json!({
            "topgg_secret": topgg_secret,
            "topgg_token": topgg_token,
            "vote_ttl_hours": vote_ttl_hours,
        }),
    }))
}

pub async fn plugin_config_update(
    State(state): State<AppState>,
    Json(payload): Json<PluginConfigRequest>,
) -> impl IntoResponse {
    // Validate Top.gg token if provided
    if let Some(ref token) = payload.config.topgg_token {
        if token.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "API Token cannot be empty" })),
            );
        }
        if let Err(e) = validate_topgg_token(&state, token).await {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            );
        }
    }

    // Validate Top.gg secret if provided
    if let Some(ref secret) = payload.config.topgg_secret {
        if secret.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Webhook Secret cannot be empty" })),
            );
        }
    }

    let vote_ttl_secs = payload
        .config
        .vote_ttl_hours
        .map(|h| (h * 3600.0) as i32);

    let updated = match db::update_registration_config(
        &state.db,
        &payload.guild_id,
        &payload.role_id,
        vote_ttl_secs,
        payload.config.topgg_secret.as_deref(),
        payload.config.topgg_token.as_deref(),
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            error!("DB error on config update: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Internal server error" })),
            );
        }
    };

    if !updated {
        warn!(
            "Config update for unknown guild/role: {}/{}",
            payload.guild_id, payload.role_id
        );
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Registration not found" })),
        );
    }

    if let Some(hours) = payload.config.vote_ttl_hours {
        info!("Updated vote_ttl to {} hours for guild={}", hours, payload.guild_id);
    }

    // Trigger sync after config update
    if let Ok(Some(reg)) =
        db::get_registration_by_guild_role(&state.db, &payload.guild_id, &payload.role_id).await
    {
        if reg.has_topgg_credentials() {
            let s = state.clone();
            tokio::spawn(async move { sync_single_registration(&s, &reg).await });
        }
    }

    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

pub async fn plugin_config_delete(
    State(state): State<AppState>,
    Json(payload): Json<PluginDeleteRequest>,
) -> Result<StatusCode, StatusCode> {
    info!(
        "Received config delete for guild={} role={}",
        payload.guild_id, payload.role_id
    );

    db::delete_registration(&state.db, &payload.guild_id, &payload.role_id)
        .await
        .map_err(|e| {
            error!("DB error on delete: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::OK)
}

// ── Health ───────────────────────────────────────────────────────────────────

pub async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    let start = std::time::Instant::now();
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();
    let db_latency = start.elapsed().as_millis() as u64;

    let status = if db_ok { "healthy" } else { "degraded" };

    Json(serde_json::json!({
        "status": status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "database": {
                "status": if db_ok { "up" } else { "down" },
                "latency_ms": db_latency
            }
        },
    }))
}

// ── RoleLogic Member API ────────────────────────────────────────────────────

pub async fn add_member(state: &AppState, reg: &Registration, user_id: &str) {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/{}",
        reg.guild_id, reg.role_id, user_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let res = state.http.post(&url).header("Authorization", auth).send().await;

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

#[allow(dead_code)]
pub async fn remove_member(state: &AppState, reg: &Registration, user_id: &str) {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/{}",
        reg.guild_id, reg.role_id, user_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let res = state.http.delete(&url).header("Authorization", auth).send().await;

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

// ── Validation ───────────────────────────────────────────────────────────────

async fn validate_topgg_token(state: &AppState, token: &str) -> Result<(), String> {
    let resp = state
        .http
        .get("https://top.gg/api/v1/projects/@me")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| format!("Failed to verify token: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!("Top.gg token validation failed ({status}): {body}");
        Err("Invalid Top.gg API Token. Check your token in the Top.gg dashboard.".to_string())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn extract_auth_token(headers: &HeaderMap) -> Result<&str, StatusCode> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Token "))
        .ok_or_else(|| {
            warn!("Request missing Authorization token");
            StatusCode::UNAUTHORIZED
        })
}
