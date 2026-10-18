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
		Count: func(t *testing.T, table string) int {
			var n int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM auth."+table).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		},
	})
}
