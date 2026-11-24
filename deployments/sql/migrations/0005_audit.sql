-- 14. AUDIT LOG (append-only, hash-chained)
CREATE TABLE audit_logs (
    id             BIGSERIAL PRIMARY KEY,
    time           TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor          TEXT NOT NULL,                    -- 'core', 'admin:<key_id>', 'agent:<id>'
    action_type    TEXT NOT NULL,
    target         TEXT,
    detail         JSONB,
    prev_hash      BYTEA NOT NULL,
    entry_hash     BYTEA NOT NULL                    -- SHA-256(prev_hash || canonical(entry))
);

