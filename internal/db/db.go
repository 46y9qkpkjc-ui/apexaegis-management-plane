// Package db provides CockroachDB Cloud connection pooling, migration support,
// and SQL-backed store implementations.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // CockroachDB uses PostgreSQL wire protocol
	"go.uber.org/zap"
)

// Config holds CockroachDB Cloud connection configuration.
type Config struct {
	// DSN is a CockroachDB Cloud connection string.
	// Example: "postgresql://user:pass@cluster-name-1234.cockroachlabs.cloud:26257/apexaegis?sslmode=verify-full"
	DSN             string
	TenantOrgID     string        // required when RLS is enabled; sets app.current_org_id
	MaxOpenConns    int           // default 10 (cloud serverless friendly)
	MaxIdleConns    int           // default 5
	ConnMaxLifetime time.Duration // default 30m
}

// DB wraps a *sql.DB with context-aware helpers.
type DB struct {
	*sql.DB
	logger *zap.Logger
}

// Open creates a CockroachDB Cloud connection pool.
// Uses cloud-optimized defaults: lower connection count and longer lifetimes
// to handle serverless cold starts gracefully.
func Open(cfg Config, logger *zap.Logger) (*DB, error) {
	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 10
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 5
	}
	if cfg.ConnMaxLifetime == 0 {
		cfg.ConnMaxLifetime = 30 * time.Minute
	}

	dsn := cfg.DSN
	if cfg.TenantOrgID != "" {
		var dsnErr error
		dsn, dsnErr = withTenantSessionOption(cfg.DSN, cfg.TenantOrgID)
		if dsnErr != nil {
			return nil, fmt.Errorf("db tenant session config: %w", dsnErr)
		}
	}

	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}

	pool.SetMaxOpenConns(cfg.MaxOpenConns)
	pool.SetMaxIdleConns(cfg.MaxIdleConns)
	pool.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Cloud serverless can take a few seconds to wake; allow 30s for first connect
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db ping (is DATABASE_URL pointing to a running CockroachDB Cloud cluster?): %w", err)
	}

	logger.Info("CockroachDB Cloud connected",
		zap.Int("max_open", cfg.MaxOpenConns),
		zap.Int("max_idle", cfg.MaxIdleConns),
		zap.String("tenant_org_id", cfg.TenantOrgID),
	)

	return &DB{DB: pool, logger: logger}, nil
}

func withTenantSessionOption(dsn, tenantOrgID string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}

	q := u.Query()
	existing := strings.TrimSpace(q.Get("options"))
	tenantOpt := fmt.Sprintf("-c app.current_org_id=%s", tenantOrgID)
	if existing != "" {
		q.Set("options", existing+" "+tenantOpt)
	} else {
		q.Set("options", tenantOpt)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Migrate reads all .sql files from the given directory and applies them
// sequentially (sorted by filename). Uses a tracking table to skip
// already-applied migrations, making it safe to call on every startup.
func (d *DB) Migrate(migrationsDir string) error {
	// Try creating tracking table. On a fresh DB the system_mgmt schema
	// does not exist yet, so this may fail — 001_init.sql creates the schema.
	d.ensureMigrationTable()

	entries, readErr := os.ReadDir(migrationsDir)
	if readErr != nil {
		return fmt.Errorf("read migrations dir: %w", readErr)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	applied := 0
	for _, fname := range files {
		// Check if already applied
		if d.migrationApplied(fname) {
			d.logger.Debug("Migration already applied, skipping", zap.String("file", fname))
			continue
		}

		path := filepath.Join(migrationsDir, fname)
		body, fileErr := os.ReadFile(path)
		if fileErr != nil {
			return fmt.Errorf("read %s: %w", fname, fileErr)
		}

		// CockroachDB cannot create a table and reference it in the same
		// implicit transaction (SQLSTATE 55000). Split migration files on
		// semicolons and execute each statement individually so each DDL
		// runs in its own transaction.
		stmts := splitStatements(string(body))
		for i, stmt := range stmts {
			execCtx, execCancel := context.WithTimeout(context.Background(), 120*time.Second)
			_, execErr := d.DB.ExecContext(execCtx, stmt)
			execCancel()
			if execErr != nil {
				return fmt.Errorf("migrate %s (statement %d): %w", fname, i+1, execErr)
			}
		}

		// After each migration, re-try creating the tracking table.
		// 001_init.sql creates the system_mgmt schema, so the table
		// creation will succeed once 001 has been applied.
		d.ensureMigrationTable()

		d.recordMigration(fname)
		applied++
		d.logger.Info("Migration applied", zap.String("file", fname))
	}

	d.logger.Info("Migrations complete", zap.Int("applied", applied), zap.Int("total", len(files)))
	return nil
}

// ensureMigrationTable creates the schema_migrations tracking table if possible.
// Silently ignores errors (e.g. when system_mgmt schema does not yet exist).
func (d *DB) ensureMigrationTable() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := d.DB.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS system_mgmt.schema_migrations (
			filename VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMPTZ DEFAULT now()
		)
	`)
	if err != nil {
		d.logger.Debug("Migration tracking table deferred (schema may not exist yet)", zap.Error(err))
	}
}

func (d *DB) migrationApplied(filename string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var exists bool
	err := d.DB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM system_mgmt.schema_migrations WHERE filename = $1)`,
		filename,
	).Scan(&exists)
	return err == nil && exists
}

func (d *DB) recordMigration(filename string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = d.DB.ExecContext(ctx,
		`INSERT INTO system_mgmt.schema_migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING`,
		filename,
	)
}

// Close shuts down the connection pool.
func (d *DB) Close() error {
	d.logger.Info("Closing CockroachDB Cloud connection pool")
	return d.DB.Close()
}

// splitStatements splits a SQL migration file into individual statements
// by semicolons, correctly handling dollar-quoted strings ($$ ... $$),
// single-quoted strings, and SQL comments. This is required for CockroachDB
// which cannot run multi-DDL implicit transactions (SQLSTATE 55000).
func splitStatements(raw string) []string {
	var out []string
	var cur strings.Builder
	i, n := 0, len(raw)

	for i < n {
		ch := raw[i]

		// ── line comment ──
		if ch == '-' && i+1 < n && raw[i+1] == '-' {
			end := strings.Index(raw[i:], "\n")
			if end == -1 {
				cur.WriteString(raw[i:])
				i = n
			} else {
				cur.WriteString(raw[i : i+end+1])
				i += end + 1
			}
			continue
		}

		// ── block comment ──
		if ch == '/' && i+1 < n && raw[i+1] == '*' {
			end := strings.Index(raw[i+2:], "*/")
			if end == -1 {
				cur.WriteString(raw[i:])
				i = n
			} else {
				cur.WriteString(raw[i : i+2+end+2])
				i += 2 + end + 2
			}
			continue
		}

		// ── single-quoted string (handles '' escapes) ──
		if ch == '\'' {
			cur.WriteByte(ch)
			i++
			for i < n {
				if raw[i] == '\'' {
					cur.WriteByte(raw[i])
					i++
					if i < n && raw[i] == '\'' {
						cur.WriteByte(raw[i])
						i++
					} else {
						break
					}
				} else {
					cur.WriteByte(raw[i])
					i++
				}
			}
			continue
		}

		// ── dollar-quoted string ($$ ... $$ or $tag$ ... $tag$) ──
		if ch == '$' {
			tagEnd := i + 1
			for tagEnd < n && (raw[tagEnd] == '_' ||
				(raw[tagEnd] >= 'a' && raw[tagEnd] <= 'z') ||
				(raw[tagEnd] >= 'A' && raw[tagEnd] <= 'Z') ||
				(raw[tagEnd] >= '0' && raw[tagEnd] <= '9')) {
				tagEnd++
			}
			if tagEnd < n && raw[tagEnd] == '$' {
				tag := raw[i : tagEnd+1] // e.g. "$$" or "$tag$"
				cur.WriteString(tag)
				i = tagEnd + 1
				closeIdx := strings.Index(raw[i:], tag)
				if closeIdx == -1 {
					cur.WriteString(raw[i:])
					i = n
				} else {
					cur.WriteString(raw[i : i+closeIdx])
					cur.WriteString(tag)
					i += closeIdx + len(tag)
				}
				continue
			}
			cur.WriteByte(ch)
			i++
			continue
		}

		// ── semicolon → statement boundary ──
		if ch == ';' {
			stmt := strings.TrimSpace(cur.String())
			if stmt != "" && stmtHasSQL(stmt) {
				out = append(out, stmt)
			}
			cur.Reset()
			i++
			continue
		}

		cur.WriteByte(ch)
		i++
	}

	// trailing statement without semicolon
	if stmt := strings.TrimSpace(cur.String()); stmt != "" && stmtHasSQL(stmt) {
		out = append(out, stmt)
	}
	return out
}

// stmtHasSQL returns true if s contains at least one non-comment, non-empty line.
func stmtHasSQL(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		l := strings.TrimSpace(line)
		if l != "" && !strings.HasPrefix(l, "--") {
			return true
		}
	}
	return false
}
