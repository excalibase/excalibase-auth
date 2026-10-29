package hooks

import (
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRootsWith(t *testing.T) {
	if roots, err := RootsWith(""); err != nil || roots != nil {
		t.Fatalf("no file: %v, %v", roots, err)
	}
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	dir := t.TempDir()
	good := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(good, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	if roots, err := RootsWith(good); err != nil || roots == nil {
		t.Fatalf("good file: %v, %v", roots, err)
	}
	empty := filepath.Join(dir, "empty.crt")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o600)
	for _, bad := range []string{empty, filepath.Join(dir, "missing.crt")} {
		if _, err := RootsWith(bad); err == nil {
			t.Errorf("RootsWith(%s) accepted", bad)
		}
	}
}
