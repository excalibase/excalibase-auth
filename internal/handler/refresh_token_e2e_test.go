package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
)

func refreshWith(srv *httptest.Server, refreshToken string) *http.Response {
	return postJSON(srv, "/auth/test-org/test-project/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": refreshToken,
	})
}

func registerForRefreshToken(t *testing.T, srv *httptest.Server, email string) string {
	t.Helper()
	resp := postJSON(srv, "/auth/test-org/test-project/register", map[string]string{
		"email": email, "password": "password123", "fullName": "Test",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("register %s: got %d", email, resp.StatusCode)
	}
	var out map[string]interface{}
	decodeJSON(resp, &out)
	return out["refreshToken"].(string)
}

func loginForRefreshToken(t *testing.T, srv *httptest.Server, email string) string {
	t.Helper()
	resp := postJSON(srv, "/auth/test-org/test-project/login", map[string]string{
		"email": email, "password": "password123",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("login %s: got %d", email, resp.StatusCode)
	}
	var out map[string]interface{}
	decodeJSON(resp, &out)
	return out["refreshToken"].(string)
}

func rotate(t *testing.T, srv *httptest.Server, refreshToken string) string {
	t.Helper()
	resp := refreshWith(srv, refreshToken)
	if resp.StatusCode != 200 {
		t.Fatalf("rotate: got %d", resp.StatusCode)
	}
	var out map[string]interface{}
	decodeJSON(resp, &out)
	return out["refreshToken"].(string)
}

func directDB(t *testing.T, fx *integrationFixture) *pgxpool.Pool {
	t.Helper()
	db, err := pgxpool.New(context.Background(), fx.connStr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestIntegration_RefreshToken_StoredOnlyAsHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	plaintext := registerForRefreshToken(t, fx.srv, "hash@test.com")
	db := directDB(t, fx)

	var plaintextColumns int
	if err := db.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM information_schema.columns
		 WHERE table_schema = 'auth' AND table_name = 'refresh_tokens' AND column_name = 'token'`,
	).Scan(&plaintextColumns); err != nil {
		t.Fatalf("columns: %v", err)
	}
	if plaintextColumns != 0 {
		t.Error("auth.refresh_tokens must not keep a plaintext token column")
	}

	var byHash int
	if err := db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM auth.refresh_tokens WHERE token_hash = $1", token.Hash(plaintext),
	).Scan(&byHash); err != nil {
		t.Fatalf("lookup by hash: %v", err)
	}
	if byHash != 1 {
		t.Errorf("rows holding the token's hash: got %d, want 1", byHash)
	}
}

// Replaying a rotated refresh token means it leaked: the whole session it
// belongs to is revoked, while the user's other sessions are untouched.
func TestIntegration_RefreshToken_ReuseRevokesFamily(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	first := registerForRefreshToken(t, fx.srv, "reuse@test.com")
	otherSession := loginForRefreshToken(t, fx.srv, "reuse@test.com")
	second := rotate(t, fx.srv, first)

	expectStatus(t, refreshWith(fx.srv, first), 401, "replay of the rotated token")
	expectStatus(t, refreshWith(fx.srv, second), 401, "successor after the replay")
	expectStatus(t, refreshWith(fx.srv, otherSession), 200, "the user's other session")
}

func TestIntegration_RefreshToken_ConcurrentUseSucceedsOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	refreshToken := registerForRefreshToken(t, fx.srv, "race@test.com")

	const attempts = 8
	var wg sync.WaitGroup
	statuses := make(chan int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := refreshWith(fx.srv, refreshToken)
			resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)

	successes := 0
	for status := range statuses {
		if status == 200 {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("concurrent refreshes with one token: %d succeeded, want exactly 1", successes)
	}
}

// Rotation must not extend the session: every token in a family keeps the
// expiry of the login that started it.
func TestIntegration_RefreshToken_RotationKeepsSessionExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	first := registerForRefreshToken(t, fx.srv, "cap@test.com")
	time.Sleep(1100 * time.Millisecond)
	second := rotate(t, fx.srv, first)

	db := directDB(t, fx)
	expiryOf := func(plaintext string) time.Time {
		var expiry time.Time
		if err := db.QueryRow(context.Background(),
			"SELECT expiry_date FROM auth.refresh_tokens WHERE token_hash = $1", token.Hash(plaintext),
		).Scan(&expiry); err != nil {
			t.Fatalf("expiry lookup: %v", err)
		}
		return expiry
	}
	if a, b := expiryOf(first), expiryOf(second); !a.Equal(b) {
		t.Errorf("rotated token expiry %v must equal the session's %v", b, a)
	}
}

func TestIntegration_RefreshToken_LogoutRevokes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	refreshToken := registerForRefreshToken(t, fx.srv, "logout@test.com")
	resp := postJSON(fx.srv, "/auth/test-org/test-project/logout", map[string]string{"refreshToken": refreshToken})
	expectStatus(t, resp, 200, "logout")
	expectStatus(t, refreshWith(fx.srv, refreshToken), 401, "refresh after logout")
}

func TestIntegration_RefreshToken_UnknownAndExpiredRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()

	refreshToken := registerForRefreshToken(t, fx.srv, "expired@test.com")
	expectStatus(t, refreshWith(fx.srv, "not-a-real-token"), 401, "unknown token")

	if _, err := directDB(t, fx).Exec(context.Background(),
		"UPDATE auth.refresh_tokens SET expiry_date = NOW() - INTERVAL '1 minute' WHERE token_hash = $1",
		token.Hash(refreshToken),
	); err != nil {
		t.Fatalf("expire token: %v", err)
	}
	resp := refreshWith(fx.srv, refreshToken)
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("expired token: got %d, want 401", resp.StatusCode)
	}
	var body map[string]interface{}
	decodeJSON(resp, &body)
	if body["error"] != errRefreshTokenExpired.Error() {
		t.Errorf("expired token error: got %v", body["error"])
	}
}
