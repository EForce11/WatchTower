-- Bootstrap: run once as a superuser. Idempotent. Sets no passwords
-- (set them out of band, e.g. ALTER ROLE wt_core PASSWORD '...').
CREATE EXTENSION IF NOT EXISTS timescaledb;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wt_owner') THEN
        CREATE ROLE wt_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wt_core') THEN
        CREATE ROLE wt_core LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wt_grafana') THEN
        CREATE ROLE wt_grafana LOGIN;
    END IF;
END
$$;

-- TimescaleDB refuses to create background policy jobs (compression/retention)
-- owned by a role that cannot log in ("permission denied to start background
-- process"). wt_owner therefore needs LOGIN; it has no password, so it cannot
-- authenticate by password. pg_hba.conf must not allow any passwordless method
-- (trust, peer, ident, cert) for wt_owner. Add explicit first-match lines:
--   host  all  wt_owner  0.0.0.0/0  reject
--   host  all  wt_owner  ::/0       reject
--   local all  wt_owner             reject
-- Background workers (policy jobs) do not go through pg_hba, so these lines do
-- not break compression/retention jobs. Migrations reach wt_owner via SET ROLE
-- from an administrative connection.
ALTER ROLE wt_owner LOGIN;

-- PostgreSQL <= 14 grants CREATE on schema public to PUBLIC. Without this
-- revoke, wt_core/wt_grafana could plant functions (e.g. public.create_hypertable)
-- that a later migration would execute as wt_owner (CVE-2018-1058 pattern).
-- No-op on PostgreSQL 15+.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT CREATE, USAGE ON SCHEMA public TO wt_owner;
GRANT USAGE ON SCHEMA public TO wt_core, wt_grafana;

-- Lets the migrating user SET ROLE wt_owner (guarded to stay idempotent).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_auth_members m
        JOIN pg_roles r ON r.oid = m.roleid
        JOIN pg_roles u ON u.oid = m.member
        WHERE r.rolname = 'wt_owner' AND u.rolname = CURRENT_USER
    ) THEN
        EXECUTE 'GRANT wt_owner TO ' || quote_ident(CURRENT_USER);
    END IF;
END
$$;
