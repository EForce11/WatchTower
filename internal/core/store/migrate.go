// Package store holds the Core's PostgreSQL access layer.
package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	sqlmigrations "github.com/EForce11/WatchTower/deployments/sql"
)

// migrationLockKey is the fixed pg_advisory_lock key serializing Bootstrap
// and Migrate across concurrent Core startups.
const migrationLockKey = 727274

// ErrNoMigrations is returned when fsys contains no migrations/*.sql files,
// so a missing or misnamed directory cannot look like "nothing to apply".
var ErrNoMigrations = errors.New("no migrations/*.sql files found")

// withMigrationLock holds the session-level advisory lock while fn runs.
func withMigrationLock(ctx context.Context, conn *pgx.Conn, fn func() error) error {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// Use a fresh context so unlock still runs if ctx was canceled.
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrationLockKey)
	}()
	return fn()
}

// Bootstrap runs bootstrap.sql (extension, roles, schema grants). It requires
// a superuser, is idempotent, and is serialized with other Bootstrap/Migrate
// callers by the migration lock.
func Bootstrap(ctx context.Context, conn *pgx.Conn) error {
	sql, err := sqlmigrations.FS.ReadFile("bootstrap.sql")
	if err != nil {
		return fmt.Errorf("read bootstrap.sql: %w", err)
	}
	return withMigrationLock(ctx, conn, func() error {
		// No arguments: simple protocol, so multi-statement scripts are allowed.
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
		return nil
	})
}

// Migrate applies pending migrations/*.sql files from fsys in lexical order,
// each in its own transaction running as role wt_owner. It returns the
// versions applied by this call, or ErrNoMigrations if fsys has none.
func Migrate(ctx context.Context, conn *pgx.Conn, fsys fs.FS) (applied []string, err error) {
	files, err := fs.Glob(fsys, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if len(files) == 0 {
		return nil, ErrNoMigrations
	}
	sort.Strings(files)

	err = withMigrationLock(ctx, conn, func() error {
		var applyErr error
		applied, applyErr = applyPending(ctx, conn, fsys, files)
		return applyErr
	})
	return applied, err
}

// applyPending creates schema_migrations if needed and applies every file
// not yet recorded there. The caller holds the migration lock.
func applyPending(ctx context.Context, conn *pgx.Conn, fsys fs.FS, files []string) ([]string, error) {
	if err := inOwnerTx(ctx, conn, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`)
		return err
	}); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	done, err := appliedVersions(ctx, conn)
	if err != nil {
		return nil, err
	}

	applied := make([]string, 0, len(files))
	for _, f := range files {
		version := strings.TrimSuffix(path.Base(f), ".sql")
		if done[version] {
			continue
		}
		body, err := fs.ReadFile(fsys, f)
		if err != nil {
			return applied, fmt.Errorf("read %s: %w", f, err)
		}
		if err := inOwnerTx(ctx, conn, func(tx pgx.Tx) error {
			// No arguments: simple protocol (multi-statement files, DO blocks).
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version)
			return err
		}); err != nil {
			return applied, fmt.Errorf("apply migration %s: %w", version, err)
		}
		applied = append(applied, version)
	}
	return applied, nil
}

func appliedVersions(ctx context.Context, conn *pgx.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	done := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		done[v] = true
	}
	return done, rows.Err()
}

// inOwnerTx runs fn in a transaction after SET LOCAL ROLE wt_owner.
func inOwnerTx(ctx context.Context, conn *pgx.Conn, fn func(pgx.Tx) error) (err error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE wt_owner"); err != nil {
		return fmt.Errorf("set role wt_owner: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
