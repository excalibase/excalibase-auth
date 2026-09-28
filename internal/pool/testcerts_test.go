package pool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// testPKI is a throwaway CA with helpers to issue server and client leaves.
type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  string
}

type issuedCert struct {
	certPEM string
	keyPEM  string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key := newKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	return &testPKI{caCert: caCert, caKey: key, caPEM: encodePEM("CERTIFICATE", der)}
}

func (pki *testPKI) issueServer(t *testing.T, dnsNames []string, ips []net.IP) issuedCert {
	t.Helper()
	return pki.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "postgres"},
		DNSNames:    dnsNames,
		IPAddresses: ips,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

func (pki *testPKI) issueClient(t *testing.T, role string) issuedCert {
	t.Helper()
	return pki.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: role},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}

func (pki *testPKI) issue(t *testing.T, template *x509.Certificate) issuedCert {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template.SerialNumber = serial
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(24 * time.Hour)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	key := newKey(t)
	der, err := x509.CreateCertificate(rand.Reader, template, pki.caCert, &key.PublicKey, pki.caKey)
	if err != nil {
		t.Fatalf("issue %s: %v", template.Subject.CommonName, err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return issuedCert{certPEM: encodePEM("CERTIFICATE", der), keyPEM: encodePEM("PRIVATE KEY", pkcs8)}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func encodePEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}
