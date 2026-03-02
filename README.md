# VoterRole

Lightweight Rust backend that receives [Top.gg](https://top.gg) vote webhooks and syncs voter Discord user IDs to [RoleLogic](https://rolelogic.faizo.net) for automatic role assignment. Designed as a RoleLogic plugin with multi-guild support.

## How it works

1. **Registers** guild/role pairs via the RoleLogic plugin API
2. **Receives** Top.gg webhook events with HMAC-SHA256 signature verification
3. **Stores** voter records in PostgreSQL with a configurable per-registration TTL
4. **Syncs** the active voter list to RoleLogic's Role Link API on a configurable interval
5. **Cleans up** expired voters every 60 seconds and removes their roles automatically

RoleLogic then automatically assigns/removes Discord roles based on the synced list.

## Setup

```bash
cp .env.example .env
# Edit .env with your values
```

### Environment Variables

| Variable             | Required | Default               | Description                                |
| -------------------- | -------- | --------------------- | ------------------------------------------ |
| `DATABASE_URL`       | Yes      | —                     | PostgreSQL connection string               |
| `HOST`               | No       | `0.0.0.0`             | Bind address                               |
| `PORT`               | No       | `3000`                | Bind port                                  |
| `PUBLIC_URL`         | No       | `https://example.com` | Public URL shown in plugin config          |
| `SYNC_INTERVAL_SECS` | No       | `43200`               | Full sync frequency to RoleLogic (seconds) |

## Run

### Docker (recommended)

```bash
docker compose up -d
```

### From source

```bash
cargo run              # development
cargo build --release  # production
```

## Endpoints

| Method   | Path             | Description                    |
| -------- | ---------------- | ------------------------------ |
| `POST`   | `/webhook/topgg` | Top.gg webhook receiver        |
| `GET`    | `/health`        | Returns `{"registrations": N}` |
| `POST`   | `/register`      | Register a guild/role pair     |
| `GET`    | `/config`        | Get plugin configuration       |
| `POST`   | `/config`        | Update plugin configuration    |
| `DELETE` | `/config`        | Delete a registration          |

## Top.gg Configuration

1. Register your guild/role via the `/register` endpoint (handled by RoleLogic)
2. In your Top.gg dashboard, set the webhook URL shown in the plugin config
3. Copy the webhook secret and API token into the plugin config
4. Votes are tracked automatically with configurable TTL (1–168 hours)

## API Reference

- [RoleLogic Role Link API](https://docs-rolelogic.faizo.net/reference/role-link-api)
- [Top.gg API v1 — Introduction](https://docs.top.gg/docs/API/v1/@introduction)
- [Top.gg API v1 — Webhooks](https://docs.top.gg/docs/API/v1/webhooks)

## License

[MIT](LICENSE)
