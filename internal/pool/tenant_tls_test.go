package pool

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
)

// recordingCreator captures every pool config the manager builds.
func recordingCreator(mgr *Manager) *[]*pgxpool.Config {
	var configs []*pgxpool.Config
	mgr.poolCreator = func(_ context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
		configs = append(configs, config)
		return nil, nil
	}
	return &configs
}

func recordServer(t *testing.T, records ...credentialRecord) *httptest.Server {
	t.Helper()
	var served atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		index := int(served.Add(1)) - 1
		if index >= len(records) {
			index = len(records) - 1
		}
		json.NewEncoder(w).Encode(records[index])
	}))
	t.Cleanup(server.Close)
	return server
}

func certRecord(t *testing.T, pki *testPKI) credentialRecord {
	t.Helper()
	client := pki.issueClient(t, "auth_admin")
	return credentialRecord{
		Host: "demo-postgres-rw.tenant.svc.cluster.local", Port: "5432",
		Database: "app", Username: "auth_admin", Password: "secret",
		SSLCert: client.certPEM, SSLKey: client.keyPEM, SSLRootCert: pki.caPEM,
	}
}

func buildOne(t *testing.T, mode string, record credentialRecord) (*pgxpool.Config, error) {
	t.Helper()
	mgr := NewManager(recordServer(t, record).URL, token.Literal("pat"), time.Hour)
	if mode != "" {
		mgr.SetSSLMode(mode)
	}
	configs := recordingCreator(mgr)
	_, err := mgr.GetPool(context.Background(), "org", "project-1")
	if err != nil {
		return nil, err
	}
	return (*configs)[0], nil
}

func TestTenantPoolAuthenticatesWithTheRecordsClientCertificateByDefault(t *testing.T) {
	pki := newTestPKI(t)
	record := certRecord(t, pki)
	config, err := buildOne(t, "", record)
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	tlsConfig := config.ConnConfig.TLSConfig
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify {
		t.Fatal("tenant connection must verify the server over TLS")
	}
	if tlsConfig.ServerName != record.Host {
		t.Errorf("ServerName: got %q, want %q (verify-full)", tlsConfig.ServerName, record.Host)
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected the record's client certificate, got %d", len(tlsConfig.Certificates))
	}
	leaf, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil || leaf.Subject.CommonName != "auth_admin" {
		t.Errorf("client certificate CN: got %v, %v", leaf, err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("RootCAs must be the record's sslrootcert: %v", err)
	}
	if len(config.ConnConfig.Fallbacks) != 0 {
		t.Errorf("a cert-authenticated connection must have no plaintext fallback, got %d", len(config.ConnConfig.Fallbacks))
	}
	if config.ConnConfig.RuntimeParams["search_path"] != "auth" {
		t.Errorf("search_path: got %q", config.ConnConfig.RuntimeParams["search_path"])
	}
}

func TestTenantPoolUsesTheClientCertificateForEveryTLSMode(t *testing.T) {
	pki := newTestPKI(t)
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		config, err := buildOne(t, mode, certRecord(t, pki))
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		tlsConfig := config.ConnConfig.TLSConfig
		if tlsConfig == nil || len(tlsConfig.Certificates) != 1 || tlsConfig.ServerName == "" {
			t.Errorf("%s: expected verify-full with the client certificate", mode)
		}
	}
}

func TestTenantPoolRefusesARecordMissingAnyTLSField(t *testing.T) {
	pki := newTestPKI(t)
	for field, strip := range map[string]func(*credentialRecord){
		"sslcert":     func(record *credentialRecord) { record.SSLCert = "" },
		"sslkey":      func(record *credentialRecord) { record.SSLKey = "" },
		"sslrootcert": func(record *credentialRecord) { record.SSLRootCert = "" },
	} {
		record := certRecord(t, pki)
		strip(&record)
		_, err := buildOne(t, "", record)
		if err == nil || !strings.Contains(err.Error(), field) {
			t.Errorf("record without %s: expected a refusal naming it, got %v", field, err)
		}
	}
}

func TestTenantPoolRefusesUnparsableTLSMaterial(t *testing.T) {
	pki := newTestPKI(t)
	other := newTestPKI(t).issueClient(t, "auth_admin")
	for name, corrupt := range map[string]func(*credentialRecord){
		"garbage cert":        func(record *credentialRecord) { record.SSLCert = "not a pem" },
		"key of another cert": func(record *credentialRecord) { record.SSLKey = other.keyPEM },
		"garbage root":        func(record *credentialRecord) { record.SSLRootCert = "not a pem" },
	} {
		record := certRecord(t, pki)
		corrupt(&record)
		_, err := buildOne(t, "", record)
		if err == nil {
			t.Errorf("%s: expected the project's connection to be refused", name)
			continue
		}
		if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "secret") {
			t.Errorf("%s: error leaks key material or password: %v", name, err)
		}
	}
}

func TestTenantPoolWithTLSDisabledUsesThePasswordAndNoCertificate(t *testing.T) {
	record := credentialRecord{Host: "postgres", Port: "5432", Database: "app", Username: "auth_admin", Password: "p@ss word"}
	config, err := buildOne(t, "disable", record)
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	if config.ConnConfig.TLSConfig != nil {
		t.Error("sslmode=disable must not negotiate TLS")
	}
	if config.ConnConfig.Password != "p@ss word" || config.ConnConfig.User != "auth_admin" {
		t.Errorf("password login lost the record's credentials: user=%q", config.ConnConfig.User)
	}
}

func TestTenantPoolPicksUpARenewedCertificateOnRefresh(t *testing.T) {
	first := certRecord(t, newTestPKI(t))
	renewed := certRecord(t, newTestPKI(t)) // new CA as well as new leaf
	mgr := NewManager(recordServer(t, first, renewed).URL, token.Literal("pat"), time.Millisecond)
	var leaves []string
	mgr.poolCreator = func(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
		leaves = append(leaves, string(config.ConnConfig.TLSConfig.Certificates[0].Certificate[0]))
		config.MinConns = 0
		return pgxpool.NewWithConfig(ctx, config)
	}
	ctx := context.Background()
	firstPool, err := mgr.GetPool(ctx, "org", "project-1")
	if err != nil {
		t.Fatalf("first GetPool: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	renewedPool, err := mgr.GetPool(ctx, "org", "project-1")
	if err != nil {
		t.Fatalf("GetPool after refresh: %v", err)
	}
	t.Cleanup(renewedPool.Close)
	if len(leaves) != 2 || leaves[0] == leaves[1] || firstPool == renewedPool {
		t.Fatalf("renewed record must open a new pool with the new certificate, got %d pools", len(leaves))
	}
}

func TestTenantPoolKeepsThePoolWhileTheRecordIsUnchanged(t *testing.T) {
	record := certRecord(t, newTestPKI(t))
	mgr := NewManager(recordServer(t, record).URL, token.Literal("pat"), time.Millisecond)
	created := 0
	mgr.poolCreator = func(ctx context.Context, config *pgxpool.Config) (*pgxpool.Pool, error) {
		created++
		config.MinConns = 0
		return pgxpool.NewWithConfig(ctx, config)
	}
	ctx := context.Background()
	pool, err := mgr.GetPool(ctx, "org", "project-1")
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	t.Cleanup(pool.Close)
	time.Sleep(5 * time.Millisecond)
	if _, err := mgr.GetPool(ctx, "org", "project-1"); err != nil {
		t.Fatalf("GetPool after refresh: %v", err)
	}
	if created != 1 {
		t.Errorf("an unchanged record must keep the existing pool, created %d", created)
	}
}

func TestCredentialRefreshIsBoundedToAnHour(t *testing.T) {
	for _, ttl := range []time.Duration{0, 24 * time.Hour} {
		if got := NewManager("http://vault", token.Literal("pat"), ttl).ttl; got != time.Hour {
			t.Errorf("ttl %v: got %v, want the one-hour ceiling so renewed certificates are picked up", ttl, got)
		}
	}
	if got := NewManager("http://vault", token.Literal("pat"), time.Minute).ttl; got != time.Minute {
		t.Errorf("a shorter ttl must be kept, got %v", got)
	}
}
