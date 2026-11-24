-- 10. BASELINES (Hippocampus)
CREATE TABLE baselines (
    agent_id       TEXT NOT NULL,
    metric_name    TEXT NOT NULL,
    bucket         TEXT NOT NULL,                    -- 'dow:hour:1:14' or 'hour:14'
    median_value   DOUBLE PRECISION NOT NULL,
    mad_value      DOUBLE PRECISION NOT NULL,
    sample_count   INTEGER NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, metric_name, bucket)
);

-- 11. FLEET IP REPUTATION
CREATE TABLE ip_reputation (
    ip             INET PRIMARY KEY,
    offense_count  INTEGER NOT NULL DEFAULT 0,
    agents_seen    TEXT[] NOT NULL DEFAULT '{}',
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    current_ban_until TIMESTAMPTZ
);

-- 12. CTI INDICATORS (Midbrain)
CREATE TABLE ioc_indicators (
    id             BIGSERIAL PRIMARY KEY,
    indicator_type TEXT NOT NULL,                    -- SHA256, IPV4, IPV6, CIDR
    value          TEXT NOT NULL,
    threat_family  TEXT,
    source_feed    TEXT NOT NULL,
    first_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ,
    UNIQUE (indicator_type, value)
);

-- 13. CORRELATION STATE SNAPSHOTS
CREATE TABLE correlation_state (
    entity_key     TEXT PRIMARY KEY,
    state          JSONB NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL
);

