package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// poolFor opens the kind of pool the manager hands the migrator.
func poolFor(t *testing.T, connStr string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(connStr + " search_path=auth")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
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

	err := Run(context.Background(), poolFor(t, connStr))
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}

	if !tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table to exist after migration")
	}
	if !tableExists(t, connStr, "auth", "refresh_tokens") {
		t.Error("expected auth.refresh_tokens table to exist after migration")
	}
	if !tableExists(t, connStr, "auth", "api_keys") {
		t.Error("expected auth.api_keys table to exist after migration")
	}
	if !tableExists(t, connStr, "auth", "role_changes") {
		t.Error("expected auth.role_changes table to exist after migration")
	}
}

// An account's allowed roles default to NULL, which reads as [role].
func TestMigrate_UsersHoldRoleNamesAndAllowedRoles(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()
	db := poolFor(t, connStr)
	if err := Run(context.Background(), db); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var dataType, nullable string
	if err := db.QueryRow(context.Background(),
		`SELECT data_type, is_nullable FROM information_schema.columns
		 WHERE table_schema = 'auth' AND table_name = 'users' AND column_name = 'allowed_roles'`,
	).Scan(&dataType, &nullable); err != nil {
		t.Fatalf("allowed_roles column: %v", err)
	}
	if dataType != "ARRAY" || nullable != "YES" {
		t.Errorf("allowed_roles: type %s nullable %s, want ARRAY YES", dataType, nullable)
	}

	var roleLength int
	if err := db.QueryRow(context.Background(),
		`SELECT character_maximum_length FROM information_schema.columns
		 WHERE table_schema = 'auth' AND table_name = 'users' AND column_name = 'role'`,
	).Scan(&roleLength); err != nil || roleLength < 63 {
		t.Errorf("users.role holds %d characters (%v), want a 63-character role name", roleLength, err)
	}
}

func TestMigrate_Up_Idempotent(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()

	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("first Run() error: %v", err)
	}
	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("second Run() should be idempotent, got error: %v", err)
	}

	if !tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table to exist after idempotent migration")
	}
}

func TestMigrate_Down(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()

	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if err := Down(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("Down() returned error: %v", err)
	}

	if tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table to NOT exist after down migration")
	}
	if tableExists(t, connStr, "auth", "refresh_tokens") {
		t.Error("expected auth.refresh_tokens table to NOT exist after down migration")
	}
	if tableExists(t, connStr, "auth", "api_keys") {
		t.Error("expected auth.api_keys table to NOT exist after down migration")
	}
}

func TestMigrate_UpDown_Roundtrip(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()

	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("first Up error: %v", err)
	}
	if err := Down(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("Down error: %v", err)
	}
	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("second Up error: %v", err)
	}

	if !tableExists(t, connStr, "auth", "users") {
		t.Error("expected auth.users table after roundtrip")
	}
	if !tableExists(t, connStr, "auth", "refresh_tokens") {
		t.Error("expected auth.refresh_tokens table after roundtrip")
	}
}

func TestMigrate_RefreshTokensHashedInPlace(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	if err := ensureAuthSchema(ctx, poolFor(t, connStr)); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	m, err := newMigrate(poolFor(t, connStr))
	if err != nil {
		t.Fatalf("newMigrate: %v", err)
	}
	// The runner holds a pooled connection until closed; the pool's cleanup waits for it.
	defer m.Close()
	if err := m.Migrate(4); err != nil {
		t.Fatalf("migrate to 4: %v", err)
	}
	db, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `
		INSERT INTO auth.users (id, email, password, full_name) VALUES (1, 'a@test.com', 'x', 'A');
		INSERT INTO auth.refresh_tokens (token, user_id, expiry_date) VALUES ('legacy-token', 1, NOW() + INTERVAL '1 day');
	`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("Run: %v", err)
	}

	sum := sha256.Sum256([]byte("legacy-token"))
	var familyID string
	if err := db.QueryRow(ctx,
		"SELECT family_id::text FROM auth.refresh_tokens WHERE token_hash = $1", hex.EncodeToString(sum[:]),
	).Scan(&familyID); err != nil {
		t.Fatalf("legacy token must be findable by its hash: %v", err)
	}
	if familyID == "" {
		t.Error("legacy token must be given a family")
	}
}

func TestMigrate_OnlyARedeemedLinkCountsAsProofOfAddress(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	if err := ensureAuthSchema(ctx, poolFor(t, connStr)); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	m, err := newMigrate(poolFor(t, connStr))
	if err != nil {
		t.Fatalf("newMigrate: %v", err)
	}
	defer m.Close()
	if err := m.Migrate(7); err != nil {
		t.Fatalf("migrate to 7: %v", err)
	}
	db, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `
		INSERT INTO auth.users (id, email, password, full_name, email_verified) VALUES
			(1, 'proven@test.com', 'x', 'P', true), (2, 'grandfathered@test.com', 'x', 'G', true);
		INSERT INTO auth.email_verification_tokens (token_hash, user_id, expires_at, consumed_at)
			VALUES (repeat('a', 64), 1, NOW(), NOW());
	`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := Run(ctx, poolFor(t, connStr)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for id, wantProof := range map[int]bool{1: true, 2: false} {
		var proven bool
		if err := db.QueryRow(ctx, "SELECT email_verified_at IS NOT NULL FROM auth.users WHERE id = $1", id).Scan(&proven); err != nil || proven != wantProof {
			t.Errorf("user %d proven = %v (err %v), want %v", id, proven, err, wantProof)
		}
	}
}

func TestMigrate_EmailSignInTablesComeAndGo(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	if err := Run(ctx, poolFor(t, connStr)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	tables := []string{"email_otps", "email_otp_lock", "audit_log"}
	for _, table := range tables {
		if !tableExists(t, connStr, "auth", table) {
			t.Errorf("auth.%s missing after migration", table)
		}
	}
	m, err := newMigrate(poolFor(t, connStr))
	if err != nil {
		t.Fatalf("newMigrate: %v", err)
	}
	defer m.Close()
	if err := m.Migrate(9); err != nil {
		t.Fatalf("migrate down to 9: %v", err)
	}
	for _, table := range tables {
		if tableExists(t, connStr, "auth", table) {
			t.Errorf("auth.%s left after the down migration", table)
		}
	}
}

func columnExists(t *testing.T, connStr, table, column string) bool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("connect for column check: %v", err)
	}
	defer pool.Close()
	var exists bool
	if err := pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema = 'auth' AND table_name = $1 AND column_name = $2)",
		table, column).Scan(&exists); err != nil {
		t.Fatalf("query column existence: %v", err)
	}
	return exists
}

func TestMigrate_IdentityLinkingColumnsComeAndGo(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()
	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	columns := map[string][]string{
		"refresh_tokens": {"last_auth_at"},
		"auth_codes":     {"link_provider", "link_subject", "link_email"},
		"email_otps":     {"link_user_id"},
	}
	for table, names := range columns {
		for _, column := range names {
			if !columnExists(t, connStr, table, column) {
				t.Errorf("auth.%s.%s missing after migration", table, column)
			}
		}
	}
	m, err := newMigrate(poolFor(t, connStr))
	if err != nil {
		t.Fatalf("newMigrate: %v", err)
	}
	defer m.Close()
	if err := m.Migrate(10); err != nil {
		t.Fatalf("migrate down to 10: %v", err)
	}
	for table, names := range columns {
		for _, column := range names {
			if columnExists(t, connStr, table, column) {
				t.Errorf("auth.%s.%s left after the down migration", table, column)
			}
		}
	}
}

func TestMigrate_AccountSelfServiceColumnsComeAndGo(t *testing.T) {
	connStr, cleanup := setupTestDB(t)
	defer cleanup()
	if err := Run(context.Background(), poolFor(t, connStr)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, column := range []string{"user_metadata", "app_metadata"} {
		if !columnExists(t, connStr, "users", column) {
			t.Errorf("auth.users.%s missing after migration", column)
		}
	}
	if !tableExists(t, connStr, "auth", "email_change_tokens") {
		t.Error("auth.email_change_tokens missing after migration")
	}
	m, err := newMigrate(poolFor(t, connStr))
	if err != nil {
		t.Fatalf("newMigrate: %v", err)
	}
	defer m.Close()
	if err := m.Migrate(11); err != nil {
		t.Fatalf("migrate down to 11: %v", err)
	}
	for _, column := range []string{"user_metadata", "app_metadata"} {
		if columnExists(t, connStr, "users", column) {
			t.Errorf("auth.users.%s left after the down migration", column)
		}
	}
	if tableExists(t, connStr, "auth", "email_change_tokens") {
		t.Error("auth.email_change_tokens left after the down migration")
	}
}
