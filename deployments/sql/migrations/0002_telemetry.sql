-- 4. EVENTS (hypertable, WES flattened)
CREATE TABLE events (
    time          TIMESTAMPTZ NOT NULL,
    event_id      UUID NOT NULL,
    agent_id      TEXT NOT NULL,
    class         TEXT NOT NULL,
    severity      SMALLINT NOT NULL,
    src_ip        INET,
    dst_ip        INET,
    dst_port      INTEGER,
    user_name     TEXT,
    process_pid   INTEGER,
    process_exe   TEXT,
    process_cmdline TEXT,
    file_path     TEXT,
    file_sha256   BYTEA,
    attrs         JSONB,
    raw_excerpt   TEXT,
    PRIMARY KEY (time, event_id)
);
SELECT create_hypertable('events', 'time', chunk_time_interval => INTERVAL '1 day');
ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'agent_id');
SELECT add_compression_policy('events', INTERVAL '7 days');
SELECT add_retention_policy('events', INTERVAL '90 days');
CREATE INDEX idx_events_agent_time ON events(agent_id, time DESC);
CREATE INDEX idx_events_src_time   ON events(src_ip, time DESC) WHERE src_ip IS NOT NULL;

-- 5. DETECTIONS (rule hits; kept longer than raw events)
CREATE TABLE detections (
    time          TIMESTAMPTZ NOT NULL,
    detection_id  UUID NOT NULL,
    agent_id      TEXT,                              -- NULL for fleet-level detections
    rule_id       UUID NOT NULL,
    rule_title    TEXT NOT NULL,
    level         SMALLINT NOT NULL,
    entity_keys   TEXT[] NOT NULL,                   -- e.g. {'ip:45.1.2.3','user:web-1/www-data'}
    event_ids     UUID[] NOT NULL,
    incident_id   UUID,
    PRIMARY KEY (time, detection_id)
);
SELECT create_hypertable('detections', 'time');
SELECT add_retention_policy('detections', INTERVAL '365 days');

