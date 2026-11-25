package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	sqlmigrations "github.com/EForce11/WatchTower/deployments/sql"
)

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// newTestDB creates a fresh database and returns its URL and an admin
// (superuser) connection to it. The database is dropped on cleanup.
func newTestDB(t *testing.T) (dbURL string, conn *pgx.Conn) {
	t.Helper()
	base := os.Getenv("WT_TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("WT_REQUIRE_DB") == "1" {
			t.Fatal("WT_REQUIRE_DB=1 but WT_TEST_DATABASE_URL is not set")
		}
		t.Skip("WT_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	name := "wt_test_" + randSuffix(t)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	dbURL = u.String()

	conn, err = pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	t.Cleanup(func() {
		conn.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database: %v", err)
		}
		admin.Close(ctx)
	})
	return dbURL, conn
}

func migrated(t *testing.T) *pgx.Conn {
	t.Helper()
	_, conn := newTestDB(t)
	ctx := context.Background()
	if err := Bootstrap(ctx, conn); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := Migrate(ctx, conn, sqlmigrations.FS); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return conn
}

func queryStrings(t *testing.T, conn *pgx.Conn, sql string) []string {
	t.Helper()
	rows, err := conn.Query(context.Background(), sql)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func TestMigrateFreshDatabase(t *testing.T) {
	_, conn := newTestDB(t)
	ctx := context.Background()
	if err := Bootstrap(ctx, conn); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	// Bootstrap must be idempotent.
	if err := Bootstrap(ctx, conn); err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	applied, err := Migrate(ctx, conn, sqlmigrations.FS)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	wantVersions := []string{"0001_fleet", "0002_telemetry", "0003_response", "0004_analytics", "0005_audit", "0006_grants"}
	if !reflect.DeepEqual(applied, wantVersions) {
		t.Fatalf("applied = %v, want %v", applied, wantVersions)
	}

	got := queryStrings(t, conn, "SELECT tablename FROM pg_tables WHERE schemaname='public'")
	want := []string{"admin_keys", "agents", "audit_logs", "baselines", "certificates", "correlation_state",
		"detections", "enrollment_tokens", "events", "incidents", "ioc_indicators", "ip_reputation",
		"pending_approvals", "response_actions", "schema_migrations"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}

	hyper := queryStrings(t, conn, "SELECT hypertable_name FROM timescaledb_information.hypertables")
	if !reflect.DeepEqual(hyper, []string{"detections", "events"}) {
		t.Fatalf("hypertables = %v", hyper)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	conn := migrated(t)
	applied, err := Migrate(context.Background(), conn, sqlmigrations.FS)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("second Migrate applied %v, want none", applied)
	}
}

func TestTablesOwnedByWtOwner(t *testing.T) {
	conn := migrated(t)
	rows := queryStrings(t, conn, "SELECT tablename || ':' || tableowner FROM pg_tables WHERE schemaname='public'")
	if len(rows) == 0 {
		t.Fatal("no tables")
	}
	for _, r := range rows {
		if !strings.HasSuffix(r, ":wt_owner") {
			t.Errorf("table not owned by wt_owner: %s", r)
		}
	}
}

func TestAuditLogAppendOnly(t *testing.T) {
	conn := migrated(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, "SET ROLE wt_core"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO audit_logs (actor, action_type, prev_hash, entry_hash)
		VALUES ('core', 'test', '\x00', '\x01')`); err != nil {
		t.Fatalf("insert as wt_core: %v", err)
	}
	for _, stmt := range []string{
		"UPDATE audit_logs SET actor = 'x'",
		"DELETE FROM audit_logs",
		"TRUNCATE audit_logs",
	} {
		_, err := conn.Exec(ctx, stmt)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: err = %v, want SQLSTATE 42501", stmt, err)
		}
	}
}

func TestPublicSchemaCreateRevoked(t *testing.T) {
	conn := migrated(t)
	ctx := context.Background()
	for _, role := range []string{"wt_core", "wt_grafana"} {
		if _, err := conn.Exec(ctx, "SET ROLE "+role); err != nil {
			t.Fatal(err)
		}
		_, err := conn.Exec(ctx, "CREATE TABLE public.x()")
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s CREATE TABLE: err = %v, want SQLSTATE 42501", role, err)
		}
		if _, err := conn.Exec(ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMigrateNoMigrationFiles(t *testing.T) {
	_, conn := newTestDB(t)
	ctx := context.Background()
	if err := Bootstrap(ctx, conn); err != nil {
		t.Fatal(err)
	}
	// A missing or misnamed migrations directory must not report success.
	fsys := fstest.MapFS{"migration/0001_typo_dir.sql": {Data: []byte("CREATE TABLE a (id int);")}}
	_, err := Migrate(ctx, conn, fsys)
	if !errors.Is(err, ErrNoMigrations) {
		t.Fatalf("err = %v, want ErrNoMigrations", err)
	}
	if tables := queryStrings(t, conn, "SELECT tablename FROM pg_tables WHERE schemaname='public'"); len(tables) != 0 {
		t.Fatalf("tables = %v, want none", tables)
	}
}

func TestBootstrapConcurrent(t *testing.T) {
	dbURL, _ := newTestDB(t)
	ctx := context.Background()
	const n = 4
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			c, err := pgx.Connect(ctx, dbURL)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = c.Close(ctx) }()
			errs <- Bootstrap(ctx, c)
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent Bootstrap: %v", err)
		}
	}
}

func TestMigrateFailedFileRollsBack(t *testing.T) {
	_, conn := newTestDB(t)
	ctx := context.Background()
	if err := Bootstrap(ctx, conn); err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"migrations/0001_ok.sql":  {Data: []byte("CREATE TABLE a (id int);")},
		"migrations/0002_bad.sql": {Data: []byte("CREATE TABLE b (id int);\nTHIS IS NOT SQL;")},
	}
	if _, err := Migrate(ctx, conn, fsys); err == nil {
		t.Fatal("expected error")
	}
	tables := queryStrings(t, conn, "SELECT tablename FROM pg_tables WHERE schemaname='public'")
	if !reflect.DeepEqual(tables, []string{"a", "schema_migrations"}) {
		t.Fatalf("tables = %v", tables)
	}
	versions := queryStrings(t, conn, "SELECT version FROM schema_migrations")
	if !reflect.DeepEqual(versions, []string{"0001_ok"}) {
		t.Fatalf("versions = %v", versions)
	}
}

func TestMigrateWithoutOwnerRole(t *testing.T) {
	dbURL, admin := newTestDB(t)
	ctx := context.Background()
	if err := Bootstrap(ctx, admin); err != nil {
		t.Fatal(err)
	}
	role := "wt_test_role_" + randSuffix(t)
	const pw = "throwaway-pw"
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+pw+"'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Runs before the database drop; revoke grants so the role can be dropped.
		c := context.Background()
		_, _ = admin.Exec(c, "REVOKE ALL ON SCHEMA public FROM "+role)
		_, _ = admin.Exec(c, "REVOKE ALL ON DATABASE "+dbName(t, dbURL)+" FROM "+role)
		if _, err := admin.Exec(c, "DROP ROLE IF EXISTS "+role); err != nil {
			t.Errorf("drop role: %v", err)
		}
	})
	if _, err := admin.Exec(ctx, "GRANT CONNECT, CREATE ON DATABASE "+dbName(t, dbURL)+" TO "+role); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "GRANT CREATE, USAGE ON SCHEMA public TO "+role); err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse(dbURL)
	u.User = url.UserPassword(role, pw)
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	defer conn.Close(ctx)

	_, err = Migrate(ctx, conn, sqlmigrations.FS)
	if err == nil || !strings.Contains(err.Error(), "wt_owner") {
		t.Fatalf("err = %v, want mention of wt_owner", err)
	}
	if n := queryStrings(t, admin, "SELECT tablename FROM pg_tables WHERE schemaname='public'"); len(n) != 0 {
		t.Fatalf("created tables: %v", n)
	}
}

func dbName(t *testing.T, dbURL string) string {
	t.Helper()
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(u.Path, "/")
}
