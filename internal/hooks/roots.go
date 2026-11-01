package hooks

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// RootsWith is the system roots plus the PEM certificates in caFile; nil
// (the system roots) when caFile is empty.
func RootsWith(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	bundle, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read the hook CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(bundle) {
		return nil, errors.New("the hook CA bundle holds no PEM certificate")
	}
	return roots, nil
}
