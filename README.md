# VoterRole

Lightweight Rust backend that receives [Top.gg](https://top.gg) vote webhooks and syncs voter Discord user IDs to [RoleLogic](https://rolelogic.faizo.net) for automatic role assignment.

## How it works

1. **Receives** Top.gg V2 webhook events with HMAC-SHA256 signature verification
2. **Stores** voter user IDs in memory for a configurable TTL (default 24h)
3. **Syncs** the active voter list to RoleLogic's Role Link API on a configurable interval

RoleLogic then automatically assigns/removes Discord roles based on the synced list.

## Setup

```bash
cp .env.example .env
# Edit .env with your values
```

### Environment Variables

| Variable               | Required | Default   | Description                               |
| ---------------------- | -------- | --------- | ----------------------------------------- |
| `HOST`                 | No       | `0.0.0.0` | Bind address                              |
| `PORT`                 | No       | `3000`    | Bind port                                 |
| `TOPGG_WEBHOOK_SECRET` | Yes      | —         | Top.gg webhook secret (`whs_...`)         |
| `TOPGG_PROJECT_ID`     | No       | —         | Filter votes by project ID or platform ID |
| `ROLELOGIC_TOKEN`      | Yes      | —         | RoleLogic API token (`rl_...`)            |
| `ROLELOGIC_GUILD_ID`   | Yes      | —         | Discord server ID                         |
| `ROLELOGIC_ROLE_ID`    | Yes      | —         | Discord role ID to assign to voters       |
| `SYNC_INTERVAL_SECS`   | No       | `60`      | Sync frequency to RoleLogic (seconds)     |
| `VOTE_TTL_SECS`        | No       | `86400`   | How long votes stay valid (seconds)       |

## Run

### Docker (recommended)

```bash
docker build -t voter-role .
docker compose up -d
```

### From source

```bash
cargo run              # development
cargo build --release  # production (~3MB binary)
```

## Endpoints

| Method | Path             | Description             |
| ------ | ---------------- | ----------------------- |
| `POST` | `/webhook/topgg` | Top.gg webhook receiver |
| `GET`  | `/health`        | Returns `{"voters": N}` |

## Top.gg Configuration

In your Top.gg dashboard, set the webhook URL to:

```
https://your-domain.com/webhook/topgg
```

## License

[MIT](LICENSE)
