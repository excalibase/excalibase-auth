package pool

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/testmysql"
	"github.com/excalibase/auth/internal/token"
)

// The record provisioning files for a MySQL project reaches its auth database
// as auth_admin over verified TLS, migrated with only auth_admin's grant.
func TestIntegration_AMySQLProjectsRecordReachesItsMigratedAuthDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	server := testmysql.Start(t)
	record := server.ProvisionAuth(t, "auth-admin-pw")
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(record)
	}))
	t.Cleanup(vault.Close)

	mgr := NewManager(vault.URL, token.Literal("pat"), time.Hour)
	mgr.SetMySQLMigrator(migrate.RunMySQL)
	db, err := mgr.GetStore(context.Background(), "org", "mysql-project")
	if err != nil {
		t.Fatalf("GetStore: %v", err)
	}
	id, created, err := db.InsertUser(context.Background(), "first@mysql.test", "hash", "First")
	if err != nil || !created || id <= 0 {
		t.Fatalf("insert over the project's store: %d %v %v", id, created, err)
	}
}
