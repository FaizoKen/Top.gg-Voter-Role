use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Database Models ─────────────────────────────────────────────────────────

#[derive(Clone, sqlx::FromRow)]
pub struct Registration {
    pub id: Uuid,
    pub guild_id: String,
    pub role_id: String,
    pub rolelogic_token: String,
    pub topgg_secret: Option<String>,
    pub topgg_token: Option<String>,
    pub vote_ttl_secs: i32,
    #[allow(dead_code)]
    pub created_at: DateTime<Utc>,
}

impl Registration {
    pub fn has_topgg_credentials(&self) -> bool {
        self.topgg_secret.is_some() && self.topgg_token.is_some()
    }
}

// ── Top.gg Webhook Payload ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WebhookPayload {
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: Option<VoteData>,
}

#[derive(Deserialize)]
pub struct VoteData {
    pub user: UserInfo,
}

#[derive(Deserialize)]
pub struct UserInfo {
    pub platform_id: String,
}

// ── Top.gg API Response ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TopggVotesResponse {
    pub cursor: Option<String>,
    pub data: Vec<TopggVoteEntry>,
}

#[derive(Deserialize)]
pub struct TopggVoteEntry {
    pub platform_id: String,
}

// ── Request / Response Types ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub guild_id: String,
    pub role_id: String,
    pub topgg_secret: Option<String>,
    pub topgg_token: Option<String>,
}

#[derive(Serialize)]
pub struct SchemaResponse {
    pub version: u32,
    pub name: String,
    pub description: String,
    pub sections: Vec<SchemaSection>,
    pub values: serde_json::Value,
}

#[derive(Serialize)]
pub struct SchemaSection {
    pub title: String,
    pub fields: Vec<SchemaField>,
}

#[derive(Serialize)]
pub struct SchemaField {
    #[serde(rename = "type")]
    pub field_type: String,
    pub key: String,
    pub label: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Deserialize)]
pub struct PluginConfigRequest {
    pub guild_id: String,
    pub role_id: String,
    pub config: PluginConfigValues,
}

#[derive(Deserialize)]
pub struct PluginConfigValues {
    pub vote_ttl_hours: Option<f64>,
    pub topgg_secret: Option<String>,
    pub topgg_token: Option<String>,
}

#[derive(Deserialize)]
pub struct PluginDeleteRequest {
    pub guild_id: String,
    pub role_id: String,
}
