// Package sqlmigrations embeds the Core's SQL bootstrap script and migrations.
package sqlmigrations

import "embed"

// FS holds bootstrap.sql and migrations/*.sql.
//
//go:embed bootstrap.sql migrations/*.sql
var FS embed.FS
