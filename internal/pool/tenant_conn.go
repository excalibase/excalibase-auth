package pool

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// sslModeDisable is the docker AIO mode: password login, no TLS.
const sslModeDisable = "disable"

// credentialRecord is the vault record provisioning writes for auth_admin.
// The ssl* fields are PEM and present for every Kubernetes tenant.
type credentialRecord struct {
	Host        string `json:"host"`
	Port        string `json:"port"`
	Database    string `json:"database"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	SSLCert     string `json:"sslcert"`
	SSLKey      string `json:"sslkey"`
	SSLRootCert string `json:"sslrootcert"`
}

// fingerprint changes whenever any field does, a renewed certificate included.
func (record credentialRecord) fingerprint() string {
	encoded, _ := json.Marshal(record)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// tenantPoolConfig builds the pool config for one tenant. Any TLS mode means
// verify-full with the record's client certificate; a record that cannot
// supply one is refused rather than dialled with its password alone.
func tenantPoolConfig(record credentialRecord, sslMode string) (*pgxpool.Config, error) {
	if sslMode == sslModeDisable {
		return parseTenantURL(record, sslModeDisable)
	}
	tlsConfig, err := clientTLSConfig(record)
	if err != nil {
		return nil, err
	}
	config, err := parseTenantURL(record, "verify-full")
	if err != nil {
		return nil, err
	}
	config.ConnConfig.TLSConfig = tlsConfig
	config.ConnConfig.Fallbacks = nil
	return config, nil
}

func parseTenantURL(record credentialRecord, sslMode string) (*pgxpool.Config, error) {
	connURL := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(record.Username, record.Password),
		Host:     net.JoinHostPort(record.Host, record.Port),
		Path:     "/" + record.Database,
		RawQuery: url.Values{"sslmode": {sslMode}, "search_path": {"auth"}}.Encode(),
	}
	config, err := pgxpool.ParseConfig(connURL.String())
	if err != nil {
		// pgx echoes the connection string in some parse errors, password included.
		return nil, errors.New("credential record does not form a valid connection")
	}
	return config, nil
}

// clientTLSConfig never wraps parse errors with the PEM input, so key material
// cannot reach a log line.
func clientTLSConfig(record credentialRecord) (*tls.Config, error) {
	if missing := missingTLSFields(record); len(missing) > 0 {
		return nil, fmt.Errorf("credential record lacks %s; tenant connections authenticate by client certificate",
			strings.Join(missing, ", "))
	}
	certificate, err := tls.X509KeyPair([]byte(record.SSLCert), []byte(record.SSLKey))
	if err != nil {
		return nil, fmt.Errorf("sslcert/sslkey do not form a client certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(record.SSLRootCert)) {
		return nil, errors.New("sslrootcert holds no PEM certificate")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ServerName:   record.Host,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func missingTLSFields(record credentialRecord) []string {
	fields := []struct{ name, value string }{
		{"sslcert", record.SSLCert}, {"sslkey", record.SSLKey}, {"sslrootcert", record.SSLRootCert},
	}
	var missing []string
	for _, field := range fields {
		if strings.TrimSpace(field.value) == "" {
			missing = append(missing, field.name)
		}
	}
	return missing
}
