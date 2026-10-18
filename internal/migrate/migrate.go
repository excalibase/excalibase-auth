package migrate

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	migratemysql "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Each engine has its own tree, versioned separately (ADR 0041).
//
//go:embed migrations/postgres/*.sql migrations/mysql/*.sql
var migrationsFS embed.FS

const (
	postgresMigrations = "migrations/postgres"
	mysqlMigrations    = "migrations/mysql"
	// mysqlMigrationsTable lives in the auth database auth_admin works in.
	mysqlMigrationsTable = "schema_migrations"
)

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
	return runAndClose(runner, action)
}

func runAndClose(runner *migrate.Migrate, action func(*migrate.Migrate) error) error {
	actionErr := action(runner)
	sourceErr, driverErr := runner.Close()
	return errors.Join(actionErr, sourceErr, driverErr)
}

// RunMySQL applies pending MySQL migrations as the project's auth login. The
// files hold several statements, so they run on a short-lived connection of
// their own with multiStatements on; the query pool never has it.
func RunMySQL(_ context.Context, config *mysqldriver.Config) error {
	migrationConfig := config.Clone()
	migrationConfig.MultiStatements = true
	connector, err := mysqldriver.NewConnector(migrationConfig)
	if err != nil {
		return errors.New("mysql migration connection could not be configured")
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	driver, err := migratemysql.WithInstance(db, &migratemysql.Config{
		MigrationsTable: mysqlMigrationsTable,
		DatabaseName:    config.DBName,
	})
	if err != nil {
		return fmt.Errorf("migration driver: %w", err)
	}
	runner, err := newRunner(mysqlMigrations, "mysql", driver)
	if err != nil {
		return err
	}
	return runAndClose(runner, func(runner *migrate.Migrate) error {
		if err := runner.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("migrate up: %w", err)
		}
		return nil
	})
}

func newRunner(dir, driverName string, driver database.Driver) (*migrate.Migrate, error) {
	subFS, err := fs.Sub(migrationsFS, dir)
	if err != nil {
		return nil, fmt.Errorf("sub fs: %w", err)
	}
	source, err := iofs.New(subFS, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs source: %w", err)
	}
	runner, err := migrate.NewWithInstance("iofs", source, driverName, driver)
	if err != nil {
		return nil, fmt.Errorf("new migrate: %w", err)
	}
	return runner, nil
}

// newMigrate borrows connections from the pool; closing the runner releases
// them without closing the pool.
func newMigrate(pool *pgxpool.Pool) (*migrate.Migrate, error) {
	driver, err := pgx.WithInstance(stdlib.OpenDBFromPool(pool), &pgx.Config{
		SchemaName:      "auth",
		MigrationsTable: migrationsTable,
	})
	if err != nil {
		return nil, fmt.Errorf("migration driver: %w", err)
	}
	return newRunner(postgresMigrations, "pgx5", driver)
}
