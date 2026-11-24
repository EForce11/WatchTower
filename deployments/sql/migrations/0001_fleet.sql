-- 1. AGENTS
CREATE TYPE agent_status AS ENUM ('PENDING', 'ALIVE', 'STALE', 'DEAD', 'ISOLATED', 'REVOKED');

CREATE TABLE agents (
    id              TEXT PRIMARY KEY,                -- e.g. UUIDv7
    hostname        TEXT NOT NULL,
    ip_address      INET,
    version         TEXT NOT NULL,
    collector_tier  CHAR(1) NOT NULL DEFAULT 'C',    -- 'A' | 'B' | 'C'
    rule_version    BIGINT NOT NULL DEFAULT 0,
    ioc_version     BIGINT NOT NULL DEFAULT 0,
    status          agent_status NOT NULL DEFAULT 'PENDING',
    last_seen       TIMESTAMPTZ,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. ENROLLMENT TOKENS (only hashes stored)
CREATE TABLE enrollment_tokens (
    token_sha256    BYTEA PRIMARY KEY,
    name            TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    used_by_agent   TEXT REFERENCES agents(id)
);

-- 3. CERTIFICATES (public material only; private keys never leave the agent)
CREATE TABLE certificates (
    serial_number      TEXT PRIMARY KEY,
    agent_id           TEXT NOT NULL REFERENCES agents(id),
    cert_pem           TEXT NOT NULL,
    fingerprint_sha256 BYTEA NOT NULL,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    revocation_reason  TEXT
);
CREATE INDEX idx_certs_agent ON certificates(agent_id);   -- multiple certs per agent across renewals
