package pgstore_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/store/pgstore"
	"github.com/excalibase/auth/internal/store/storetest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestIntegration_PostgresStoreKeepsTheStoreContract(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	container, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"), postgres.WithUsername("testuser"), postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(30*time.Second)),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	host, _ := container.Host(ctx)
	port, _ := container.MappedPort(ctx, "5432/tcp")
	pool, err := pgxpool.New(ctx, fmt.Sprintf("postgres://testuser:testpass@%s:%s/testdb?sslmode=disable&search_path=auth", host, port.Port()))
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Run(ctx, pool); err != nil {
		t.Fatal(err)
	}
	db := pgstore.New(pool)
	t.Cleanup(db.Close)
	storetest.Run(t, storetest.Fixture{
		Store: db,
		Grandfather: func(t *testing.T, email string) {
			if _, err := pool.Exec(ctx, "UPDATE auth.users SET email_verified = true WHERE email = $1", email); err != nil {
				t.Fatal(err)
			}
		},
		Disable: func(t *testing.T, email string) {
			if _, err := pool.Exec(ctx, "UPDATE auth.users SET enabled = false WHERE email = $1", email); err != nil {
				t.Fatal(err)
			}
		},
		SetEmail: func(t *testing.T, id int64, email string) {
			if _, err := pool.Exec(ctx, "UPDATE auth.users SET email = $2 WHERE id = $1", id, email); err != nil {
				t.Fatal(err)
			}
		},
		Reference: func(t *testing.T, id int64) {
			for _, statement := range []string{
				"CREATE TABLE IF NOT EXISTS public.app_owners (user_id BIGINT REFERENCES auth.users(id))",
				fmt.Sprintf("INSERT INTO public.app_owners (user_id) VALUES (%d)", id),
			} {
				if _, err := pool.Exec(ctx, statement); err != nil {
					t.Fatal(err)
				}
			}
		},
		Count: func(t *testing.T, table string) int {
			var n int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM auth."+table).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		},
	})
	t.Run("users.password and users.email accept NULL", func(t *testing.T) {
		assertNullable(t, pool, "password", "email")
	})
}

func assertNullable(t *testing.T, pool *pgxpool.Pool, columns ...string) {
	t.Helper()
	for _, column := range columns {
		var nullable string
		if err := pool.QueryRow(context.Background(),
			`SELECT is_nullable FROM information_schema.columns WHERE table_schema = 'auth' AND table_name = 'users' AND column_name = $1`,
			column).Scan(&nullable); err != nil || nullable != "YES" {
			t.Fatalf("auth.users.%s nullable = %q err=%v", column, nullable, err)
		}
	}
}
