package migrate

import (
	"embed"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Run applies all pending UP migrations.
func Run(connStr string) error {
	m, err := newMigrate(connStr)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
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

	// Intentionally omit search_path — migrations handle schema creation and SET search_path themselves.
	return fmt.Sprintf("pgx5://%s:%s@%s:%s/%s?sslmode=%s", user, password, host, port, dbname, sslmode), nil
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
