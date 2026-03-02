use std::collections::HashSet;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use tracing::{error, info};

use crate::{AppState, db, models::*};

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
        let futures: Vec<_> = expired
            .iter()
            .map(|(_, guild_id, role_id, token, user_id)| {
                remove_member_raw(&state.http, guild_id, role_id, token, user_id)
            })
            .collect();

        futures::future::join_all(futures).await;
    }
}

/// Lightweight remove_member that takes raw fields instead of a full Registration.
async fn remove_member_raw(
    http: &reqwest::Client,
    guild_id: &str,
    role_id: &str,
    token: &str,
    user_id: &str,
) {
    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{guild_id}/{role_id}/users/{user_id}"
    );
    let auth = format!("Token {token}");

    match http.delete(&url).header("Authorization", auth).send().await {
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

    // 3. Sync to RoleLogic
    info!("Syncing {} voter(s) to RoleLogic for reg {}", user_ids.len(), reg.id);

    let url = format!(
        "https://api-rolelogic.faizo.net/api/role-link/{}/{}/users",
        reg.guild_id, reg.role_id
    );
    let auth = format!("Token {}", reg.rolelogic_token);

    let res = state
        .http
        .put(&url)
        .header("Authorization", auth)
        .json(&user_ids)
        .send()
        .await;

    match res {
        Ok(resp) if resp.status().is_success() => {
            info!("RoleLogic sync OK for reg {}", reg.id);
        }
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            error!("RoleLogic sync failed for reg {} ({status}): {text}", reg.id);
        }
        Err(e) => {
            error!("RoleLogic sync request error for reg {}: {e}", reg.id);
        }
    }
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
