CREATE TABLE registrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    guild_id        TEXT NOT NULL,
    role_id         TEXT NOT NULL,
    rolelogic_token TEXT NOT NULL,
    topgg_secret    TEXT,
    topgg_token     TEXT,
    vote_ttl_secs   INTEGER NOT NULL DEFAULT 86400,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (guild_id, role_id)
);

CREATE TABLE voters (
    registration_id UUID NOT NULL REFERENCES registrations(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL,
    voted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (registration_id, user_id)
);

CREATE INDEX idx_voters_expiry ON voters (registration_id, voted_at);
