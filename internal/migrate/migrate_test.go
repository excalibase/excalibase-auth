package migrate

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestDB(t *testing.T) (string, func()) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	pgContainer, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	host, err := pgContainer.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	port, err := pgContainer.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("get port: %v", err)
	}

	connStr := fmt.Sprintf("host=%s port=%s user=testuser password=testpass dbname=testdb sslmode=disable",
		host, port.Port())

	cleanup := func() {
		pgContainer.Terminate(ctx)
	}
	return connStr, cleanup
}

func tableExists(t *testing.T, connStr, schema, table string) bool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("connect for table check: %v", err)
	}
	defer pool.Close()

	var exists bool
	err = pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2)",
		schema, table,
	).Scan(&exists)
	if err != nil {
		t.Fatalf("query table existence: %v", err)
	}
	return exists
}

func TestMigrate_Up(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()

	err := Run(connStr)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	if !tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table to exist after migration")
	}
	if !tableExists(t, connStr, "auth", "refresh_tokens") {
		t.Error("expected auth.refresh_tokens table to exist after migration")
	}
}

func TestMigrate_Up_Idempotent(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()

	if err := Run(connStr); err != nil {
		t.Fatalf("first Run() error: %v", err)
	}
	if err := Run(connStr); err != nil {
		t.Fatalf("second Run() should be idempotent, got error: %v", err)
	}

	if !tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table to exist after idempotent migration")
	}
}

func TestMigrate_Down(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()

	if err := Run(connStr); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if err := Down(connStr); err != nil {
		t.Fatalf("Down() returned error: %v", err)
	}

	if tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table to NOT exist after down migration")
	}
	if tableExists(t, connStr, "auth", "refresh_tokens") {
		t.Error("expected auth.refresh_tokens table to NOT exist after down migration")
	}
}

func TestMigrate_UpDown_Roundtrip(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()

	if err := Run(connStr); err != nil {
		t.Fatalf("first Up error: %v", err)
	}
	if err := Down(connStr); err != nil {
		t.Fatalf("Down error: %v", err)
	}
	if err := Run(connStr); err != nil {
		t.Fatalf("second Up error: %v", err)
	}

	if !tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table after roundtrip")
	}
	if !tableExists(t, connStr, "auth", "refresh_tokens") {
		t.Error("expected auth.refresh_tokens table after roundtrip")
	}
}
