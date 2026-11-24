-- 6. INCIDENTS
CREATE TABLE incidents (
    id             UUID PRIMARY KEY,
    opened_at      TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    closed_at      TIMESTAMPTZ,
    score          NUMERIC(8,2) NOT NULL,
    tier           SMALLINT NOT NULL,                -- 0..3
    score_breakdown JSONB NOT NULL,
    entity_keys    TEXT[] NOT NULL,
    agent_ids      TEXT[] NOT NULL,
    ai_assessment  JSONB,
    status         TEXT NOT NULL DEFAULT 'OPEN'      -- OPEN, CONTAINED, CLOSED, FALSE_POSITIVE
);

-- 7. RESPONSE ACTIONS (every action, automated or approved)
CREATE TABLE response_actions (
    command_id     UUID PRIMARY KEY,
    incident_id    UUID REFERENCES incidents(id),
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    action         TEXT NOT NULL,
    target         TEXT NOT NULL,
    ttl_seconds    INTEGER,
    origin         TEXT NOT NULL,                    -- REFLEX, AUTOMATION, ADMIN
    signer_key_id  TEXT,
    issued_at      TIMESTAMPTZ NOT NULL,
    acked_at       TIMESTAMPTZ,
    result         TEXT                              -- APPLIED, REFUSED_SAFETY, REFUSED_SIGNATURE, FAILED
);

-- 8. PENDING APPROVALS (destructive actions)
CREATE TABLE pending_approvals (
    id             UUID PRIMARY KEY,
    incident_id    UUID NOT NULL REFERENCES incidents(id),
    agent_id       TEXT NOT NULL REFERENCES agents(id),
    action         TEXT NOT NULL,                    -- KILL_PROCESS, ISOLATE_HOST, RELEASE_HOST, BAN_PERM
    target         TEXT NOT NULL,
    target_exec    TEXT,
    target_start_time BIGINT,
    command_payload BYTEA NOT NULL,                  -- exact bytes the admin will sign
    status         TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING, APPROVED, REJECTED, EXPIRED
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    decided_by_key TEXT,
    decided_at     TIMESTAMPTZ
);

-- 9. ADMIN APPROVAL KEYS (public keys only)
CREATE TABLE admin_keys (
    key_id         TEXT PRIMARY KEY,                 -- SHA-256 of the public key, hex
    owner          TEXT NOT NULL,
    algorithm      TEXT NOT NULL,                    -- 'ed25519' | 'webauthn-es256'
    public_key     BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ
);

