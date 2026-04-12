package migrate

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Run applies all pending UP migrations.
func Run(connStr string) error {
	if err := ensureAuthSchema(connStr); err != nil {
		return fmt.Errorf("ensure auth schema: %w", err)
	}

	m, err := newMigrate(connStr)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// ensureAuthSchema creates the auth schema if it doesn't exist.
// Must run before golang-migrate because the pgx5 driver checks CURRENT_SCHEMA()
// which returns NULL if the search_path schema doesn't exist.
func ensureAuthSchema(connStr string) error {
	params := parseKV(connStr)
	host := params["host"]
	port := params["port"]
	user := params["username"]
	if user == "" {
		user = params["user"]
	}
	password := params["password"]
	dbname := params["dbname"]
	if dbname == "" {
		dbname = params["database"]
	}

	pgURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, pgURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(ctx)

	_, err = conn.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS auth")
	return err
}


// Down rolls back all migrations.
func Down(connStr string) error {
	m, err := newMigrate(connStr)
	if err != nil {
		return err
	}

	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

func newMigrate(connStr string) (*migrate.Migrate, error) {
	subFS, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sub fs: %w", err)
	}

	source, err := iofs.New(subFS, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs source: %w", err)
	}

	dbURL, err := connStrToURL(connStr)
	if err != nil {
		return nil, err
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, dbURL)
	if err != nil {
		return nil, fmt.Errorf("new migrate: %w", err)
	}
	return m, nil
}

// connStrToURL converts a pgx key=value connection string to a pgx5:// URL,
// or passes through if already a URL.
func connStrToURL(connStr string) (string, error) {
	// If already a URL format, just ensure pgx5 scheme
	if len(connStr) > 5 && (connStr[:5] == "pgx5:" || connStr[:8] == "postgres") {
		if connStr[:8] == "postgres" {
			return "pgx5" + connStr[8:], nil
		}
		return connStr, nil
	}

	// Parse key=value format: host=x port=y user=u password=p dbname=d ...
	params := parseKV(connStr)
	host := params["host"]
	port := params["port"]
	user := params["username"]
	if user == "" {
		user = params["user"]
	}
	password := params["password"]
	dbname := params["dbname"]
	if dbname == "" {
		dbname = params["database"]
	}
	sslmode := params["sslmode"]
	if sslmode == "" {
		sslmode = "disable"
	}

	// Use auth schema for the migrations tracking table so auth_admin doesn't need public schema access
	return fmt.Sprintf("pgx5://%s:%s@%s:%s/%s?sslmode=%s&search_path=auth&x-migrations-table=auth.schema_migrations", user, password, host, port, dbname, sslmode), nil
}

func parseKV(s string) map[string]string {
	result := make(map[string]string)
	key := ""
	val := ""
	inKey := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inKey {
			if c == '=' {
				inKey = false
			} else if c != ' ' {
				key += string(c)
			}
		} else {
			if c == ' ' || i == len(s)-1 {
				if c != ' ' {
					val += string(c)
				}
				result[key] = val
				key = ""
				val = ""
				inKey = true
			} else {
				val += string(c)
			}
		}
	}
	return result
}
