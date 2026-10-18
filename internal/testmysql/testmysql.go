// Package testmysql starts a MySQL 8.4 server for tests the way a project's
// MOCO cluster is set up for auth: TLS required, a server certificate from the
// project's own CA, and an auth_admin login granted only on the auth database.
// Only test files import it.
package testmysql

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	image        = "mysql:8.4"
	rootPassword = "root-test-password"
	certDir      = "/etc/mysql/project-tls"
	// AuthDatabase and AuthUser are what provisioning creates on every MySQL
	// project (excalibase server-go internal/provisioner/mysql_users.go).
	AuthDatabase = "auth"
	AuthUser     = "auth_admin"
	// AuthGrants mirrors provisioning's grant to auth_admin on the auth database.
	AuthGrants = "SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES"
)

// Server is a running MySQL whose certificate is signed by CAPEM for Host.
type Server struct {
	Host  string
	Port  string
	CAPEM string
}

// Start runs the server for the test and stops it afterwards.
func Start(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	pki := newPKI(t)
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        image,
			ExposedPorts: []string{"3306/tcp"},
			Env:          map[string]string{"MYSQL_ROOT_PASSWORD": rootPassword},
			Cmd: []string{
				"--ssl-ca=" + certDir + "/ca.pem", "--ssl-cert=" + certDir + "/server.pem",
				"--ssl-key=" + certDir + "/server-key.pem", "--require-secure-transport=ON",
				// MOCO runs every project at READ-COMMITTED.
				"--transaction-isolation=READ-COMMITTED",
				// A lenient server, so auth's own strict session mode is what is tested.
				"--sql-mode=",
			},
			Files: []testcontainers.ContainerFile{
				{Reader: strings.NewReader(pki.caPEM), ContainerFilePath: certDir + "/ca.pem", FileMode: 0o644},
				{Reader: strings.NewReader(pki.serverPEM), ContainerFilePath: certDir + "/server.pem", FileMode: 0o644},
				{Reader: strings.NewReader(pki.serverKeyPEM), ContainerFilePath: certDir + "/server-key.pem", FileMode: 0o644},
			},
			WaitingFor: wait.ForAll(
				wait.ForLog("port: 3306  MySQL Community Server"),
				wait.ForListeningPort("3306/tcp"),
			).WithDeadline(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start mysql: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Host: host, Port: port.Port(), CAPEM: pki.caPEM}
}

// TLS verifies the server against the test CA and the host name.
func (s *Server) TLS(t *testing.T) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(s.CAPEM)) {
		t.Fatal("test CA does not parse")
	}
	return &tls.Config{RootCAs: roots, ServerName: s.Host, MinVersion: tls.VersionTLS12}
}

// Root opens the server as root over verified TLS.
func (s *Server) Root(t *testing.T) *sql.DB {
	t.Helper()
	config := mysql.NewConfig()
	config.User, config.Passwd = "root", rootPassword
	config.Net, config.Addr = "tcp", net.JoinHostPort(s.Host, s.Port)
	config.TLS = s.TLS(t)
	connector, err := mysql.NewConnector(config)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	return db
}

// ProvisionAuth creates the auth database and auth_admin as provisioning does
// and returns the vault record provisioning files for it.
func (s *Server) ProvisionAuth(t *testing.T, password string) map[string]string {
	t.Helper()
	root := s.Root(t)
	statements := []string{
		"CREATE DATABASE IF NOT EXISTS `" + AuthDatabase + "`",
		"CREATE USER IF NOT EXISTS '" + AuthUser + "'@'%' IDENTIFIED BY '" + password + "' REQUIRE SSL",
		"GRANT " + AuthGrants + " ON `" + AuthDatabase + "`.* TO '" + AuthUser + "'@'%'",
	}
	for _, statement := range statements {
		if _, err := root.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("provision auth: %v", err)
		}
	}
	return map[string]string{
		"engine": "mysql", "tls": "required",
		"host": s.Host, "port": s.Port, "database": AuthDatabase,
		"username": AuthUser, "password": password, "sslrootcert": s.CAPEM,
	}
}

type pki struct {
	caPEM, serverPEM, serverKeyPEM string
}

func newPKI(t *testing.T) pki {
	t.Helper()
	caKey := newKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test project CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	serverKey := newKey(t)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return pki{
		caPEM:        encode("CERTIFICATE", caDER),
		serverPEM:    encode("CERTIFICATE", serverDER),
		serverKeyPEM: encode("PRIVATE KEY", keyDER),
	}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encode(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}
