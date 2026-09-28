package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/migrate"
	"github.com/excalibase/auth/internal/token"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const tlsDir = "/var/lib/postgresql/tls"

// certOnlyHBA mirrors what provisioning writes for platform roles: TLS plus a
// client certificate, no password path at all.
const certOnlyHBA = "local all all trust\nhostssl all all all cert\n"

func vaultServing(t *testing.T, record credentialRecord) string {
	t.Helper()
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(record)
	}))
	t.Cleanup(vault.Close)
	return vault.URL
}

func startPostgres(t *testing.T, opts ...testcontainers.ContainerCustomizer) (host, port string) {
	t.Helper()
	ctx := context.Background()
	base := []testcontainers.ContainerCustomizer{
		postgres.WithDatabase("app"), postgres.WithUsername("auth_admin"), postgres.WithPassword("secret"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).WithStartupTimeout(60 * time.Second)),
	}
	pg, err := postgres.Run(ctx, "postgres:16-alpine", append(base, opts...)...)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	host, err = pg.Host(ctx)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	mapped, err := pg.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, mapped.Port()
}

// withCertOnlyTLS starts Postgres with ssl on, the given server certificate and
// a cert-only pg_hba. The key is copied and chowned first: Postgres refuses a
// key file the postgres user does not own.
func withCertOnlyTLS(server issuedCert, caPEM string) testcontainers.ContainerCustomizer {
	file := func(name, content string) testcontainers.ContainerFile {
		return testcontainers.ContainerFile{Reader: strings.NewReader(content), ContainerFilePath: "/tls-src/" + name, FileMode: 0o644}
	}
	script := fmt.Sprintf("mkdir -p %[1]s && cp /tls-src/* %[1]s/ && chown -R postgres:postgres %[1]s && chmod 600 %[1]s/server.key && "+
		"exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=%[1]s/server.crt -c ssl_key_file=%[1]s/server.key "+
		"-c ssl_ca_file=%[1]s/ca.crt -c hba_file=%[1]s/pg_hba.conf", tlsDir)
	return testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Files: []testcontainers.ContainerFile{
				file("server.crt", server.certPEM), file("server.key", server.keyPEM),
				file("ca.crt", caPEM), file("pg_hba.conf", certOnlyHBA),
			},
			Entrypoint: []string{"sh", "-c", script},
		},
	})
}

func TestIntegration_TenantPoolConnectsToACertOnlyDatabaseWithTheRecordsCertificate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pki := newTestPKI(t)
	server := pki.issueServer(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	host, port := startPostgres(t, withCertOnlyTLS(server, pki.caPEM))

	record := certRecord(t, pki)
	record.Host, record.Port = host, port
	mgr := NewManager(vaultServing(t, record), token.Literal("pat"), time.Hour)
	mgr.SetMigrator(migrate.Run)
	pool, err := mgr.GetPool(ctx, "org", "tenant-a")
	if err != nil {
		t.Fatalf("GetPool: %v", err)
	}
	var user string
	var encrypted bool
	var usersTable *string
	err = pool.QueryRow(ctx, `SELECT current_user, (SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), to_regclass('auth.users')::text`).
		Scan(&user, &encrypted, &usersTable)
	if err != nil {
		t.Fatalf("query over the cert-authenticated pool: %v", err)
	}
	if user != "auth_admin" || !encrypted {
		t.Errorf("got user=%q ssl=%v; want auth_admin over TLS", user, encrypted)
	}
	if usersTable == nil {
		t.Error("migrations must run over the same cert-authenticated connection")
	}

	withoutCert := record
	withoutCert.SSLCert, withoutCert.SSLKey = "", ""
	_, err = NewManager(vaultServing(t, withoutCert), token.Literal("pat"), time.Hour).GetPool(ctx, "org", "tenant-a")
	if err == nil || !strings.Contains(err.Error(), "sslcert") {
		t.Fatalf("a record without a client certificate must be refused, got %v", err)
	}
}

// Proves the database above really is cert-only, so the success is the certificate's doing.
func TestIntegration_CertOnlyDatabaseRejectsAPasswordLogin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pki := newTestPKI(t)
	server := pki.issueServer(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	host, port := startPostgres(t, withCertOnlyTLS(server, pki.caPEM))

	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://auth_admin:secret@%s:%s/app?sslmode=require", host, port))
	if err == nil {
		conn.Close(ctx)
		t.Fatal("a password login without a client certificate must be rejected")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected pg_hba's certificate requirement to reject the login, got %v", err)
	}
}

// A tenant database that cannot encrypt is refused, not dialled in plaintext.
func TestIntegration_TenantPoolRefusesADatabaseThatCannotEncrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	host, port := startPostgres(t)
	record := certRecord(t, newTestPKI(t))
	record.Host, record.Port = host, port
	vaultURL := vaultServing(t, record)

	mgr := NewManager(vaultURL, token.Literal("pat"), time.Hour)
	pool, err := mgr.GetPool(ctx, "org", "tenant-a")
	if err == nil {
		err = pool.Ping(ctx)
		pool.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "refused TLS") {
		t.Fatalf("expected the plaintext-only database to be refused for TLS, got %v", err)
	}

	plain := NewManager(vaultURL, token.Literal("pat"), time.Hour)
	plain.SetSSLMode("disable")
	pool, err = plain.GetPool(ctx, "org", "tenant-a")
	if err != nil {
		t.Fatalf("GetPool with disable: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("the same database with sslmode=disable should answer, so the refusal above was TLS: %v", err)
	}
}
