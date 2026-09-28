package migrate

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationsTable keeps the tracking table in the auth schema, so auth_admin
// needs no access to public.
const migrationsTable = "auth.schema_migrations"

// Run applies all pending UP migrations over the tenant's own pool, so they
// authenticate exactly as the pool does (client certificate included).
func Run(ctx context.Context, pool *pgxpool.Pool) error {
	if err := ensureAuthSchema(ctx, pool); err != nil {
		return fmt.Errorf("ensure auth schema: %w", err)
	}
	return withMigrate(pool, func(runner *migrate.Migrate) error {
		if err := runner.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("migrate up: %w", err)
		}
		return nil
	})
}

// Down rolls back all migrations.
func Down(_ context.Context, pool *pgxpool.Pool) error {
	return withMigrate(pool, func(runner *migrate.Migrate) error {
		if err := runner.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("migrate down: %w", err)
		}
		return nil
	})
}

// ensureAuthSchema must run before golang-migrate: the pgx5 driver reads
// CURRENT_SCHEMA(), which is NULL while the search_path schema is missing.
func ensureAuthSchema(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS auth")
	return err
}

func withMigrate(pool *pgxpool.Pool, action func(*migrate.Migrate) error) error {
	runner, err := newMigrate(pool)
	if err != nil {
		return err
	}
	actionErr := action(runner)
	sourceErr, driverErr := runner.Close()
	return errors.Join(actionErr, sourceErr, driverErr)
}

// newMigrate borrows connections from the pool; closing the runner releases
// them without closing the pool.
func newMigrate(pool *pgxpool.Pool) (*migrate.Migrate, error) {
	subFS, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sub fs: %w", err)
	}
	source, err := iofs.New(subFS, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs source: %w", err)
	}
	driver, err := pgx.WithInstance(stdlib.OpenDBFromPool(pool), &pgx.Config{
		SchemaName:      "auth",
		MigrationsTable: migrationsTable,
	})
	if err != nil {
		return nil, fmt.Errorf("migration driver: %w", err)
	}
	runner, err := migrate.NewWithInstance("iofs", source, "pgx5", driver)
	if err != nil {
		return nil, fmt.Errorf("new migrate: %w", err)
	}
	return runner, nil
}
