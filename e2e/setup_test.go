//go:build e2e

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var (
	authServerURL string
	mockVault     *httptest.Server
	authProcess   *exec.Cmd
)

// TestMain starts real PG (docker-compose), mock vault, and real auth binary
func TestMain(m *testing.M) {
	// 1. Generate EC key for JWT signing
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))

	// 2. Start mock vault (returns PG creds + signing key)
	mockVault = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/vault/secrets/pki/signing/private":
			json.NewEncoder(w).Encode(map[string]string{
				"key":       privPEM,
				"algorithm": "EC-P256",
			})
		default:
			// Return PG credentials for any project
			json.NewEncoder(w).Encode(map[string]string{
				"host":     "localhost",
				"port":     "5433",
				"database": "auth_test",
				"username": "auth_admin",
				"password": "testpass123",
			})
		}
	}))

	// 3. Build auth binary
	fmt.Println("Building auth server...")
	tmpBin := os.TempDir() + "/excalibase-auth-e2e"
	gobin := "go"
	if v := os.Getenv("GO_BIN"); v != "" {
		gobin = v
	}
	build := exec.Command(gobin, "build", "-o", tmpBin, "./cmd/server/")
	build.Dir = findModuleRoot()
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Printf("Build failed: %s\n%s\n", err, out)
		os.Exit(1)
	}

	// 4. Start auth server as subprocess
	fmt.Println("Starting auth server...")
	authProcess = exec.Command(tmpBin)
	authProcess.Env = append(os.Environ(),
		"PORT=24100",
		"PROVISIONING_URL="+mockVault.URL,
		"PROVISIONING_PAT=e2e-test-pat",
		"JWT_EXPIRATION=3600",
		"REFRESH_EXPIRATION=604800",
	)
	authProcess.Stdout = os.Stdout
	authProcess.Stderr = os.Stderr
	if err := authProcess.Start(); err != nil {
		fmt.Printf("Failed to start auth server: %v\n", err)
		os.Exit(1)
	}

	authServerURL = "http://localhost:24100"

	// 5. Wait for server to be ready
	ready := false
	for i := 0; i < 30; i++ {
		resp, err := http.Get(authServerURL + "/healthz")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		fmt.Println("Auth server failed to start")
		cleanup()
		os.Exit(1)
	}
	fmt.Println("Auth server ready")

	// 6. Run tests
	code := m.Run()

	// 7. Cleanup
	cleanup()
	os.Exit(code)
}

func findModuleRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func cleanup() {
	if authProcess != nil && authProcess.Process != nil {
		authProcess.Process.Kill()
		authProcess.Wait()
	}
	if mockVault != nil {
		mockVault.Close()
	}
}
