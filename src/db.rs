use sqlx::PgPool;
use uuid::Uuid;

use crate::models::Registration;

pub async fn get_registration_by_guild_role(
    pool: &PgPool,
    guild_id: &str,
    role_id: &str,
) -> Result<Option<Registration>, sqlx::Error> {
    sqlx::query_as::<_, Registration>(
        "SELECT * FROM registrations WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await
}

pub async fn upsert_registration(
    pool: &PgPool,
    guild_id: &str,
    role_id: &str,
    rolelogic_token: &str,
    topgg_secret: Option<&str>,
    topgg_token: Option<&str>,
) -> Result<Registration, sqlx::Error> {
    sqlx::query_as::<_, Registration>(
        r#"INSERT INTO registrations (guild_id, role_id, rolelogic_token, topgg_secret, topgg_token)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (guild_id, role_id) DO UPDATE SET
             rolelogic_token = EXCLUDED.rolelogic_token,
             topgg_secret = COALESCE(EXCLUDED.topgg_secret, registrations.topgg_secret),
             topgg_token = COALESCE(EXCLUDED.topgg_token, registrations.topgg_token)
           RETURNING *"#,
    )
    .bind(guild_id)
    .bind(role_id)
    .bind(rolelogic_token)
    .bind(topgg_secret)
    .bind(topgg_token)
    .fetch_one(pool)
    .await
}

pub async fn update_registration_config(
    pool: &PgPool,
    guild_id: &str,
    role_id: &str,
    vote_ttl_secs: Option<i32>,
    topgg_secret: Option<&str>,
    topgg_token: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"UPDATE registrations SET
             vote_ttl_secs = COALESCE($3, vote_ttl_secs),
             topgg_secret = COALESCE($4, topgg_secret),
             topgg_token = COALESCE($5, topgg_token)
           WHERE guild_id = $1 AND role_id = $2"#,
    )
    .bind(guild_id)
    .bind(role_id)
    .bind(vote_ttl_secs)
    .bind(topgg_secret)
    .bind(topgg_token)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn delete_registration(
    pool: &PgPool,
    guild_id: &str,
    role_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM registrations WHERE guild_id = $1 AND role_id = $2")
        .bind(guild_id)
        .bind(role_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_all_registrations(pool: &PgPool) -> Result<Vec<Registration>, sqlx::Error> {
    sqlx::query_as::<_, Registration>("SELECT * FROM registrations")
        .fetch_all(pool)
        .await
}

pub async fn get_registrations_with_secret(pool: &PgPool) -> Result<Vec<Registration>, sqlx::Error> {
    sqlx::query_as::<_, Registration>("SELECT * FROM registrations WHERE topgg_secret IS NOT NULL")
        .fetch_all(pool)
        .await
}

pub async fn upsert_voter(
    pool: &PgPool,
    registration_id: Uuid,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"INSERT INTO voters (registration_id, user_id, voted_at)
           VALUES ($1, $2, now())
           ON CONFLICT (registration_id, user_id) DO UPDATE SET voted_at = now()"#,
    )
    .bind(registration_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn get_active_voters(
    pool: &PgPool,
    registration_id: Uuid,
    vote_ttl_secs: i32,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT user_id FROM voters WHERE registration_id = $1 AND voted_at > now() - make_interval(secs => $2::double precision)",
    )
    .bind(registration_id)
    .bind(vote_ttl_secs as f64)
    .fetch_all(pool)
    .await
}

pub async fn delete_expired_voters(
    pool: &PgPool,
    registration_id: Uuid,
    vote_ttl_secs: i32,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "DELETE FROM voters WHERE registration_id = $1 AND voted_at <= now() - make_interval(secs => $2::double precision) RETURNING user_id",
    )
    .bind(registration_id)
    .bind(vote_ttl_secs as f64)
    .fetch_all(pool)
    .await
}

pub async fn replace_voters(
    pool: &PgPool,
    registration_id: Uuid,
    user_ids: &[String],
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM voters WHERE registration_id = $1")
        .bind(registration_id)
        .execute(&mut *tx)
        .await?;

    for uid in user_ids {
        sqlx::query(
            "INSERT INTO voters (registration_id, user_id, voted_at) VALUES ($1, $2, now())",
        )
        .bind(registration_id)
        .bind(uid)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await
}
