mod crypto;
mod db;
mod handlers;
mod models;
mod sync;

use axum::{
    Router,
    routing::{get, post},
};
use sqlx::postgres::PgPoolOptions;
use std::{env, time::Duration};
use tokio::net::TcpListener;
use tracing::info;

// ── AppState ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub http: reqwest::Client,
    pub sync_interval: Duration,
    pub public_url: String,
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let _ = dotenvy::dotenv();

    let database_url = required_env("DATABASE_URL");
    let sync_interval = Duration::from_secs(env_or("SYNC_INTERVAL_SECS", 43200));

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("failed to run migrations");

    let public_url = env_or_str("PUBLIC_URL", "https://example.com");

    let state = AppState {
        db: pool,
        http: reqwest::Client::new(),
        sync_interval,
        public_url,
    };

    // Spawn background tasks
    let sync_state = state.clone();
    tokio::spawn(async move { sync::sync_loop(sync_state).await });

    let cleanup_state = state.clone();
    tokio::spawn(async move { sync::ttl_cleanup_loop(cleanup_state).await });

    let app = Router::new()
        .route("/webhook/topgg", post(handlers::topgg_webhook))
        .route("/health", get(handlers::health))
        .route("/register", post(handlers::plugin_register))
        .route(
            "/config",
            get(handlers::plugin_config)
                .post(handlers::plugin_config_update)
                .delete(handlers::plugin_config_delete),
        )
        .with_state(state);

    let host = env_or_str("HOST", "0.0.0.0");
    let port: u16 = env_or("PORT", 3000);
    let addr = format!("{host}:{port}");

    info!("Listening on {addr}");

    let listener = TcpListener::bind(&addr).await.expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

// ── Env Helpers ─────────────────────────────────────────────────────────────

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
