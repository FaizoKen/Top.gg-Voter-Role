use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    AppState, crypto, db,
    models::*,
    sync::sync_single_registration,
};

// ── Webhook Handler ─────────────────────────────────────────────────────────

pub async fn topgg_webhook(
    State(state): State<AppState>,
    Path(registration_id): Path<Uuid>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // 1. Look up registration
    let reg = match db::get_registration(&state.db, registration_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            warn!("Webhook for unknown registration {registration_id}");
            return StatusCode::NOT_FOUND;
        }
        Err(e) => {
            error!("DB error looking up registration: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    // 2. Check credentials exist
    let topgg_secret = match &reg.topgg_secret {
        Some(s) => s,
        None => {
            warn!("Webhook received but no topgg_secret configured for reg {registration_id}");
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };

    // 3. Verify HMAC signature
    if let Err(e) = crypto::verify_signature(&headers, &body, topgg_secret) {
        warn!("Webhook signature verification failed for reg {registration_id}: {e}");
        return StatusCode::UNAUTHORIZED;
    }

    // 4. Parse payload
    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            warn!("Invalid webhook payload: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // 5. Handle event type
    match payload.event_type.as_str() {
        "vote.create" => {
            let data = match payload.data {
                Some(d) => d,
                None => return StatusCode::BAD_REQUEST,
            };

            let user_id = data.user.platform_id;
            info!("Vote received from user {user_id} for reg {registration_id}");

            // Store in DB
            if let Err(e) = db::upsert_voter(&state.db, reg.id, &user_id).await {
                error!("Failed to store voter: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }

            // Add member to RoleLogic
            let s = state.clone();
            let uid = user_id.clone();
            let r = reg.clone();
            tokio::spawn(async move { add_member(&s, &r, &uid).await });

            StatusCode::OK
        }
        "webhook.test" => {
            info!("Test webhook received for reg {registration_id}");
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
        "webhook_path": format!("/webhook/topgg/{}", registration_id),
        "registration_id": registration_id
    })))
}

pub async fn plugin_schema(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SchemaResponse>, StatusCode> {
    // Token is optional - use it to look up current values if present
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Token "));

    let mut vote_ttl_hours = 24.0;
    let mut topgg_secret = String::new();
    let mut topgg_token = String::new();
    let mut webhook_path = String::new();

    if let Some(token) = token {
        if let Ok(registrations) = db::get_all_registrations(&state.db).await {
            if let Some(reg) = registrations.iter().find(|r| r.rolelogic_token == token) {
                vote_ttl_hours = reg.vote_ttl_secs as f64 / 3600.0;
                topgg_secret = reg.topgg_secret.clone().unwrap_or_default();
                topgg_token = reg.topgg_token.clone().unwrap_or_default();
                webhook_path = format!("/webhook/topgg/{}", reg.id);
            }
        }
    }

    Ok(Json(SchemaResponse {
        version: 1,
        name: "VoterRole".to_string(),
        description: "Assigns a Discord role to users who vote on Top.gg. The role is automatically removed when the vote expires.".to_string(),
        sections: vec![
            SchemaSection {
                title: "Setup Guide".to_string(),
                fields: vec![SchemaField {
                    field_type: "display".to_string(),
                    key: "guide".to_string(),
                    label: "How to connect Top.gg".to_string(),
                    description: String::new(),
                    validation: None,
                    value: Some(format!(
                        "1. Go to your bot's Top.gg dashboard and find the Webhooks section.\n\
                         2. Set the webhook URL to: {}{}\n\
                         3. Copy the Webhook Secret from Top.gg and paste it below.\n\
                         4. Go to the API section on Top.gg and generate an API Token, then paste it below.\n\
                         5. Click Save to activate vote tracking.",
                        state.public_url,
                        if webhook_path.is_empty() { "/webhook/topgg/<registration_id>".to_string() } else { webhook_path }
                    )),
                }],
            },
            SchemaSection {
                title: "Top.gg Credentials".to_string(),
                fields: vec![
                    SchemaField {
                        field_type: "text".to_string(),
                        key: "topgg_secret".to_string(),
                        label: "Webhook Secret".to_string(),
                        description: "Found in your Top.gg bot dashboard under Webhooks".to_string(),
                        validation: Some(serde_json::json!({"required": true})),
                        value: None,
                    },
                    SchemaField {
                        field_type: "text".to_string(),
                        key: "topgg_token".to_string(),
                        label: "API Token".to_string(),
                        description: "Found in your Top.gg bot dashboard under API".to_string(),
                        validation: Some(serde_json::json!({"required": true})),
                        value: None,
                    },
                ],
            },
            SchemaSection {
                title: "Timing".to_string(),
                fields: vec![SchemaField {
                    field_type: "number".to_string(),
                    key: "vote_ttl_hours".to_string(),
                    label: "Vote Duration (hours)".to_string(),
                    description: "How long a user keeps the role after voting (1-168 hours)".to_string(),
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

pub async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let count = db::get_all_registrations(&state.db)
        .await
        .map(|r| r.len())
        .unwrap_or(0);

    (StatusCode::OK, format!("{{\"registrations\":{count}}}"))
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
