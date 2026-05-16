use std::collections::HashSet;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use reqwest::StatusCode;
use tracing::{error, info, warn};

use crate::{AppState, db, handlers, models::*};

/// Hard cap for a single `PUT /users` request (server-side limit).
const PUT_MAX_USERS: usize = 100_000;
/// Per-chunk cap for the chunked upload flow.
const CHUNK_SIZE: usize = 100_000;
/// Per-request timeout for a single chunk POST.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-request timeout for the commit POST (server may take ~30 minutes).
const COMMIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Body substring RoleLogic returns when our token isn't found server-side.
/// Reliably signals the role link has been deleted upstream.
const RL_LINK_GONE_ERROR_MSG: &str = "Invalid or revoked token";

// ── Background Loops ────────────────────────────────────────────────────────

pub async fn sync_loop(state: AppState) {
    loop {
        tokio::time::sleep(state.sync_interval).await;

        let registrations = match db::get_all_registrations(&state.db).await {
            Ok(regs) => regs,
            Err(e) => {
                error!("Failed to load registrations for sync: {e}");
                continue;
            }
        };

        for reg in &registrations {
            sync_single_registration(&state, reg).await;
        }
    }
}

pub async fn ttl_cleanup_loop(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;

        let expired = match db::delete_all_expired_voters(&state.db).await {
            Ok(rows) => rows,
            Err(e) => {
                error!("Failed to delete expired voters: {e}");
                continue;
            }
        };

        if expired.is_empty() {
            continue;
        }

        info!("Removed {} expired voter(s)", expired.len());

        // Fire all remove_member calls concurrently
        let http = &state.http;
        let futures: Vec<_> = expired
            .iter()
            .map(|(_, guild_id, role_id, token, user_id)| async move {
                let gone = remove_member_raw(http, guild_id, role_id, token, user_id).await;
                (guild_id.clone(), role_id.clone(), gone)
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        // For any role link reported as gone, drop the local registration once.
        let mut dropped: HashSet<(String, String)> = HashSet::new();
        for (gid, rid, gone) in results {
            if gone && dropped.insert((gid.clone(), rid.clone())) {
                warn!(guild_id = %gid, role_id = %rid, "Role link gone on RoleLogic; deleting orphan registration");
                if let Err(e) = db::delete_registration(&state.db, &gid, &rid).await {
                    error!(guild_id = %gid, role_id = %rid, "Failed to delete orphan registration: {e}");
                }
            }
        }
    }
}

/// Lightweight remove_member that takes raw fields instead of a full Registration.
/// Returns true if the role link is gone upstream (caller should drop the
/// registration), false otherwise.
async fn remove_member_raw(
    http: &reqwest::Client,
    guild_id: &str,
    role_id: &str,
    token: &str,
    user_id: &str,
) -> bool {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{guild_id}/{role_id}/users/{user_id}"
    );
    let auth = format!("Token {token}");

    match http.delete(&url).header("Authorization", auth).send().await {
        Ok(resp) if resp.status().is_success() => {
            info!("RoleLogic remove member OK: {user_id}");
            false
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status == StatusCode::FORBIDDEN && text.contains(RL_LINK_GONE_ERROR_MSG) {
                return true;
            }
            error!("RoleLogic remove member failed ({status}): {text}");
            false
        }
        Err(e) => {
            error!("RoleLogic remove member request error: {e}");
            false
        }
    }
}

// ── Sync Single Registration ────────────────────────────────────────────────

pub async fn sync_single_registration(state: &AppState, reg: &Registration) {
    let topgg_token = match &reg.topgg_token {
        Some(t) => t,
        None => {
            info!("Skipping sync for reg {}: no Top.gg token configured", reg.id);
            return;
        }
    };

    let vote_ttl = Duration::from_secs(reg.vote_ttl_secs as u64);

    // 1. Fetch votes from Top.gg
    let user_ids = match fetch_topgg_votes(state, topgg_token, vote_ttl).await {
        Ok(ids) => {
            info!("Fetched {} voter(s) from Top.gg for reg {}", ids.len(), reg.id);
            ids
        }
        Err(e) => {
            error!("Failed to fetch votes for reg {}: {e}", reg.id);
            return;
        }
    };

    // 2. Replace voters in DB
    if let Err(e) = db::replace_voters(&state.db, reg.id, &user_ids).await {
        error!("Failed to replace voters for reg {}: {e}", reg.id);
        return;
    }

    // 3. Sync to RoleLogic — uses chunked upload for sets > 100k voters.
    info!("Syncing {} voter(s) to RoleLogic for reg {}", user_ids.len(), reg.id);

    if let Err(SyncError::RoleLinkGone) = upload_voters(state, reg, &user_ids).await {
        handlers::delete_orphan_registration(state, reg).await;
    }
}

#[derive(Debug)]
enum SyncError {
    /// RoleLogic reported 403 + "Invalid or revoked token" — link is gone.
    RoleLinkGone,
    /// Any other RoleLogic / network failure (already logged at source).
    Other,
}

/// Pushes the user list to RoleLogic, picking the right transport:
/// - `len <= 100_000`: single atomic `PUT /users`.
/// - `len > 100_000`: chunked flow (init → chunks → commit).
async fn upload_voters(state: &AppState, reg: &Registration, user_ids: &[String]) -> Result<(), SyncError> {
    if user_ids.len() <= PUT_MAX_USERS {
        return replace_voters_put(state, reg, user_ids).await;
    }

    info!(
        reg_id = %reg.id,
        total = user_ids.len(),
        "Bulk voter set exceeds PUT cap; using chunked upload"
    );

    let upload_id = start_upload(state, reg).await?;
    let chunk_count = user_ids.chunks(CHUNK_SIZE).count();

    for (i, chunk) in user_ids.chunks(CHUNK_SIZE).enumerate() {
        if let Err(e) = upload_chunk(state, reg, &upload_id, chunk).await {
            error!(
                reg_id = %reg.id,
                upload_id,
                chunk_idx = i,
                chunk_count,
                "Chunk upload failed; cancelling session"
            );
            let _ = cancel_upload(state, reg, &upload_id).await;
            return Err(e);
        }
    }

    commit_upload(state, reg, &upload_id).await?;
    info!(reg_id = %reg.id, upload_id, chunks = chunk_count, "Chunked upload committed");
    Ok(())
}

async fn replace_voters_put(state: &AppState, reg: &Registration, user_ids: &[String]) -> Result<(), SyncError> {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users",
        reg.guild_id, reg.role_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let res = state
        .http
        .put(&url)
        .header("Authorization", auth)
        .json(user_ids)
        .send()
        .await;

    match res {
        Ok(resp) if resp.status().is_success() => {
            info!("RoleLogic sync OK for reg {}", reg.id);
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status == StatusCode::FORBIDDEN && text.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(SyncError::RoleLinkGone);
            }
            error!("RoleLogic sync failed for reg {} ({status}): {text}", reg.id);
            Err(SyncError::Other)
        }
        Err(e) => {
            error!("RoleLogic sync request error for reg {}: {e}", reg.id);
            Err(SyncError::Other)
        }
    }
}

async fn start_upload(state: &AppState, reg: &Registration) -> Result<String, SyncError> {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/upload",
        reg.guild_id, reg.role_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let res = state.http.post(&url).header("Authorization", auth).send().await;
    match res {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp.json().await.map_err(|e| {
                error!("Start upload parse error for reg {}: {e}", reg.id);
                SyncError::Other
            })?;
            body["data"]["upload_id"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| {
                    error!("Start upload missing upload_id for reg {}", reg.id);
                    SyncError::Other
                })
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status == StatusCode::FORBIDDEN && text.contains(RL_LINK_GONE_ERROR_MSG) {
                return Err(SyncError::RoleLinkGone);
            }
            error!("Start upload failed for reg {} ({status}): {text}", reg.id);
            Err(SyncError::Other)
        }
        Err(e) => {
            error!("Start upload request error for reg {}: {e}", reg.id);
            Err(SyncError::Other)
        }
    }
}

async fn upload_chunk(
    state: &AppState,
    reg: &Registration,
    upload_id: &str,
    chunk: &[String],
) -> Result<(), SyncError> {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/upload/{}/chunk",
        reg.guild_id, reg.role_id, upload_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let res = state
        .http
        .post(&url)
        .header("Authorization", auth)
        .timeout(CHUNK_TIMEOUT)
        .json(chunk)
        .send()
        .await;
    match res {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            error!("Upload chunk failed for reg {} ({status}): {text}", reg.id);
            Err(SyncError::Other)
        }
        Err(e) => {
            error!("Upload chunk request error for reg {}: {e}", reg.id);
            Err(SyncError::Other)
        }
    }
}

async fn commit_upload(state: &AppState, reg: &Registration, upload_id: &str) -> Result<(), SyncError> {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/upload/{}/commit",
        reg.guild_id, reg.role_id, upload_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let res = state
        .http
        .post(&url)
        .header("Authorization", auth)
        .timeout(COMMIT_TIMEOUT)
        .send()
        .await;
    match res {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            error!("Commit upload failed for reg {} ({status}): {text}", reg.id);
            Err(SyncError::Other)
        }
        Err(e) => {
            error!("Commit upload request error for reg {}: {e}", reg.id);
            Err(SyncError::Other)
        }
    }
}

async fn cancel_upload(state: &AppState, reg: &Registration, upload_id: &str) -> Result<(), SyncError> {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users/upload/{}",
        reg.guild_id, reg.role_id, upload_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let _ = state.http.delete(&url).header("Authorization", auth).send().await;
    Ok(())
}

// ── Top.gg Vote Fetching ────────────────────────────────────────────────────

async fn fetch_topgg_votes(
    state: &AppState,
    topgg_token: &str,
    vote_ttl: Duration,
) -> Result<Vec<String>, String> {
    let vote_ttl_secs = vote_ttl.as_secs() as i64;
    let start_date = (Utc::now() - chrono::TimeDelta::seconds(vote_ttl_secs))
        .to_rfc3339_opts(SecondsFormat::Secs, true);

    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;

    loop {
        let mut request = state
            .http
            .get("https://top.gg/api/v1/projects/@me/votes")
            .header("Authorization", format!("Bearer {topgg_token}"))
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
            if seen.insert(entry.platform_id) {
                new_entries = true;
            }
        }

        if !new_entries {
            break;
        }

        match page.cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    Ok(seen.into_iter().collect())
}
