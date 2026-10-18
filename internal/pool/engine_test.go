package pool

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgxpool"
)

func mysqlRecord(t *testing.T) credentialRecord {
	t.Helper()
	return credentialRecord{
		Engine: "mysql",
		Host: "moco-p1-mysql-primary.p1.svc", Port: "3306", Database: "auth",
		Username: "auth_admin", Password: "pw", SSLRootCert: newTestPKI(t).caPEM,
	}
}

type fakeStore struct{ store.Store }

func (fakeStore) Close() {}

// A MySQL record opens a MySQL store, migrated first, over TLS verified
// against the record's CA and host; the Postgres path is never taken.
func TestMySQLRecordOpensAMigratedMySQLStoreVerifiedAgainstItsCA(t *testing.T) {
	record := mysqlRecord(t)
	mgr := NewManager(recordServer(t, record).URL, token.Literal("pat"), time.Hour)
	mgr.SetSSLMode("disable") // Postgres-only; a MySQL login is TLS regardless
	mgr.poolCreator = func(context.Context, *pgxpool.Config) (*pgxpool.Pool, error) {
		t.Fatal("a MySQL record must not open a Postgres pool")
		return nil, nil
	}
	var steps []string
	var opened *mysql.Config
	mgr.SetMySQLMigrator(func(_ context.Context, config *mysql.Config) error {
		steps = append(steps, "migrate")
		return nil
	})
	mgr.mysqlOpener = func(config *mysql.Config) (store.Store, error) {
		steps = append(steps, "open")
		opened = config
		return fakeStore{}, nil
	}
	got, err := mgr.GetStore(context.Background(), "org", "p1")
	if err != nil {
		t.Fatalf("GetStore: %v", err)
	}
	if _, ok := got.(fakeStore); !ok {
		t.Fatalf("store = %T", got)
	}
	if strings.Join(steps, ",") != "migrate,open" {
		t.Fatalf("steps = %v", steps)
	}
	if opened.TLS == nil || opened.TLS.ServerName != record.Host || opened.TLS.RootCAs == nil || opened.TLS.InsecureSkipVerify {
		t.Fatalf("tls = %+v", opened.TLS)
	}
	if opened.DBName != "auth" || opened.User != "auth_admin" || opened.MultiStatements {
		t.Fatalf("config = %+v", opened)
	}
}

func TestMySQLRecordWithoutACAIsRefused(t *testing.T) {
	record := mysqlRecord(t)
	record.SSLRootCert = ""
	mgr := NewManager(recordServer(t, record).URL, token.Literal("pat"), time.Hour)
	mgr.mysqlOpener = func(*mysql.Config) (store.Store, error) {
		t.Fatal("opened without a CA")
		return nil, nil
	}
	if _, err := mgr.GetStore(context.Background(), "org", "p1"); err == nil || !strings.Contains(err.Error(), "sslrootcert") {
		t.Fatalf("err = %v", err)
	}
}

func TestARecordOfAnUnknownEngineIsRefused(t *testing.T) {
	record := mysqlRecord(t)
	record.Engine = "mariadb"
	mgr := NewManager(recordServer(t, record).URL, token.Literal("pat"), time.Hour)
	mgr.mysqlOpener = func(*mysql.Config) (store.Store, error) {
		t.Fatal("opened an unknown engine as MySQL")
		return nil, nil
	}
	if _, err := mgr.GetStore(context.Background(), "org", "p1"); err == nil || !strings.Contains(err.Error(), "engine") {
		t.Fatalf("err = %v", err)
	}
}

func TestAChangedMySQLRecordOpensANewStore(t *testing.T) {
	first, rotated := mysqlRecord(t), mysqlRecord(t)
	rotated.Password = "rotated"
	mgr := NewManager(recordServer(t, first, rotated).URL, token.Literal("pat"), time.Millisecond)
	opened := 0
	mgr.mysqlOpener = func(*mysql.Config) (store.Store, error) {
		opened++
		return fakeStore{}, nil
	}
	ctx := context.Background()
	if _, err := mgr.GetStore(ctx, "org", "p1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := mgr.GetStore(ctx, "org", "p1"); err != nil {
		t.Fatal(err)
	}
	if opened != 2 {
		t.Fatalf("opened %d stores, want 2", opened)
	}
}
