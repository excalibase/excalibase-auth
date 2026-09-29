package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"testing"
)

const integrationUsersPath = "/auth/test-org/test-project/users"

func userAdminRequest(t *testing.T, fx *integrationFixture, method, path, bearer string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, fx.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	var out map[string]any
	decodeJSON(resp, &out)
	return resp, out
}

func registerUser(t *testing.T, fx *integrationFixture, email string) int64 {
	t.Helper()
	body := tokenResponse(t, postJSON(fx.srv, "/auth/test-org/test-project/register", map[string]string{
		"email": email, "password": "password123", "fullName": "Test",
	}), "register "+email)
	user := body["user"].(map[string]any)
	return int64(user["id"].(float64))
}

func stringList(raw any) []string {
	items, _ := raw.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, _ := item.(string)
		out = append(out, s)
	}
	return out
}

func rolePath(userID int64) string {
	return integrationUsersPath + "/" + strconv.FormatInt(userID, 10) + "/role"
}

// One database serves every case; the listing runs first, on an empty project.
func TestIntegration_Users(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	fx, cleanup := setupIntegrationFixture(t)
	defer cleanup()
	cases := []struct {
		name string
		run  func(*testing.T, *integrationFixture)
	}{
		{"ListIsOrderedAndPaged", usersListIsOrderedAndPaged},
		{"SetRoleRevokesSessionsAndAudits", usersSetRoleRevokesSessionsAndAudits},
		{"ServiceKeyCallerIsAudited", usersServiceKeyCallerIsAudited},
		{"UnknownUserIs404", usersUnknownUserIs404},
		{"EndUserTokenIsRefused", usersEndUserTokenIsRefused},
		{"InvalidStoredAllowedRolesRefuseSignIn", usersInvalidStoredAllowedRolesRefuseSignIn},
		{"AuditRowsFollowTheUser", usersAuditRowsFollowTheUser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, fx) })
	}
}

func usersListIsOrderedAndPaged(t *testing.T, fx *integrationFixture) {
	aliceID := registerUser(t, fx, "alice@test.com")
	bobID := registerUser(t, fx, "bob@test.com")
	bearer := signUserAdmin(t, fx.signingKey, validUserAdmin("test-project"))

	resp, body := userAdminRequest(t, fx, http.MethodGet, integrationUsersPath, bearer, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: got %d %v", resp.StatusCode, body)
	}
	users, _ := body["users"].([]any)
	if len(users) != 2 {
		t.Fatalf("users: got %v", body)
	}
	first := users[0].(map[string]any)
	if int64(first["id"].(float64)) != aliceID || first["email"] != "alice@test.com" || first["role"] != "user" ||
		!slices.Equal(stringList(first["allowedRoles"]), []string{"user"}) || first["enabled"] != true || first["emailVerified"] != false {
		t.Errorf("first user: %v", first)
	}

	resp, body = userAdminRequest(t, fx, http.MethodGet, integrationUsersPath+"?limit=1&offset=1", bearer, nil)
	users, _ = body["users"].([]any)
	if resp.StatusCode != 200 || len(users) != 1 || int64(users[0].(map[string]any)["id"].(float64)) != bobID {
		t.Errorf("page 2: got %d %v", resp.StatusCode, body)
	}
}

func usersSetRoleRevokesSessionsAndAudits(t *testing.T, fx *integrationFixture) {
	firstSession := registerForRefreshToken(t, fx.srv, "ed@test.com")
	secondSession := loginForRefreshToken(t, fx.srv, "ed@test.com")
	var edID int64
	directDB(t, fx).QueryRow(context.Background(), "SELECT id FROM auth.users WHERE email = 'ed@test.com'").Scan(&edID)
	bystander := registerForRefreshToken(t, fx.srv, "other@test.com")

	resp, body := userAdminRequest(t, fx, http.MethodPut, rolePath(edID),
		signUserAdmin(t, fx.signingKey, validUserAdmin("test-project")),
		map[string]any{"role": "editor", "allowedRoles": []string{"editor", "user"}})
	if resp.StatusCode != 200 {
		t.Fatalf("set role: got %d %v", resp.StatusCode, body)
	}
	if body["role"] != "editor" || !slices.Equal(stringList(body["allowedRoles"]), []string{"editor", "user"}) ||
		body["email"] != "ed@test.com" || int64(body["id"].(float64)) != edID {
		t.Errorf("answer: %v", body)
	}

	for name, session := range map[string]string{"first": firstSession, "second": secondSession} {
		if resp := refreshWith(fx.srv, session); resp.StatusCode != 401 {
			t.Errorf("%s session refresh after role change: got %d, want 401", name, resp.StatusCode)
		}
	}
	if resp := refreshWith(fx.srv, bystander); resp.StatusCode != 200 {
		t.Errorf("another user's session: got %d, want 200", resp.StatusCode)
	}

	var actor, oldRole, newRole string
	var oldAllowed, newAllowed []string
	if err := directDB(t, fx).QueryRow(context.Background(),
		`SELECT actor, old_role, new_role, old_allowed_roles, new_allowed_roles
		 FROM auth.role_changes WHERE user_id = $1`, edID,
	).Scan(&actor, &oldRole, &newRole, &oldAllowed, &newAllowed); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if actor != "studio:plat-user-9" || oldRole != "user" || newRole != "editor" ||
		!slices.Equal(oldAllowed, []string{"user"}) || !slices.Equal(newAllowed, []string{"editor", "user"}) {
		t.Errorf("audit: %s %s→%s %v→%v", actor, oldRole, newRole, oldAllowed, newAllowed)
	}

	loggedIn := tokenResponse(t, postJSON(fx.srv, "/auth/test-org/test-project/login", map[string]string{
		"email": "ed@test.com", "password": "password123",
	}), "login after role change")
	claims := jwtPayload(t, loggedIn["accessToken"].(string))
	if claims["role"] != "editor" || !slices.Equal(stringList(claims["allowed_roles"]), []string{"editor", "user"}) {
		t.Errorf("login claims: role %v allowed %v", claims["role"], claims["allowed_roles"])
	}
	refreshed := tokenResponse(t, refreshWith(fx.srv, loggedIn["refreshToken"].(string)), "refresh after role change")
	claims = jwtPayload(t, refreshed["accessToken"].(string))
	if claims["role"] != "editor" || !slices.Equal(stringList(claims["allowed_roles"]), []string{"editor", "user"}) {
		t.Errorf("refresh claims: role %v allowed %v", claims["role"], claims["allowed_roles"])
	}
}

func usersServiceKeyCallerIsAudited(t *testing.T, fx *integrationFixture) {
	userID := registerUser(t, fx, "svc@test.com")

	resp, body := userAdminRequest(t, fx, http.MethodPut, rolePath(userID),
		mintServiceToken(t, fx.jwtSvc, "test-project", 77), map[string]any{"role": "manager"})
	if resp.StatusCode != 200 || !slices.Equal(stringList(body["allowedRoles"]), []string{"manager"}) {
		t.Fatalf("set role: got %d %v", resp.StatusCode, body)
	}

	db := directDB(t, fx)
	var actor string
	var stored []string
	db.QueryRow(context.Background(), "SELECT actor FROM auth.role_changes WHERE user_id = $1", userID).Scan(&actor)
	if actor != "service-key:77" {
		t.Errorf("actor: got %q, want service-key:77", actor)
	}
	// Omitted allowedRoles is stored as NULL, which reads as [role].
	if err := db.QueryRow(context.Background(), "SELECT allowed_roles FROM auth.users WHERE id = $1", userID).Scan(&stored); err != nil || stored != nil {
		t.Errorf("allowed_roles: got %v %v, want NULL", stored, err)
	}
}

func usersUnknownUserIs404(t *testing.T, fx *integrationFixture) {

	resp, body := userAdminRequest(t, fx, http.MethodPut, rolePath(999),
		signUserAdmin(t, fx.signingKey, validUserAdmin("test-project")), map[string]any{"role": "editor"})
	if resp.StatusCode != 404 || body["error"] != "user_not_found" {
		t.Errorf("unknown user: got %d %v", resp.StatusCode, body)
	}
	var changes int
	directDB(t, fx).QueryRow(context.Background(), "SELECT COUNT(*) FROM auth.role_changes WHERE user_id = 999").Scan(&changes)
	if changes != 0 {
		t.Errorf("audit rows for a refused change: %d", changes)
	}
}

func usersEndUserTokenIsRefused(t *testing.T, fx *integrationFixture) {
	registered := tokenResponse(t, postJSON(fx.srv, "/auth/test-org/test-project/register", map[string]string{
		"email": "self@test.com", "password": "password123", "fullName": "Self",
	}), "register")
	userID := int64(registered["user"].(map[string]any)["id"].(float64))

	resp, _ := userAdminRequest(t, fx, http.MethodPut, rolePath(userID),
		registered["accessToken"].(string), map[string]any{"role": "admin_user"})
	if resp.StatusCode != 403 {
		t.Errorf("self-promotion with an end-user token: got %d, want 403", resp.StatusCode)
	}
}

func usersInvalidStoredAllowedRolesRefuseSignIn(t *testing.T, fx *integrationFixture) {
	refreshToken := registerForRefreshToken(t, fx.srv, "bad@test.com")
	db := directDB(t, fx)

	for name, allowed := range map[string][]string{
		"role missing":   {"editor"},
		"reserved entry": {"user", "postgres"},
	} {
		if _, err := db.Exec(context.Background(),
			"UPDATE auth.users SET allowed_roles = $1 WHERE email = 'bad@test.com'", allowed); err != nil {
			t.Fatalf("seed: %v", err)
		}
		assertRefusedForRole(t, postJSON(fx.srv, "/auth/test-org/test-project/login", map[string]string{
			"email": "bad@test.com", "password": "password123",
		}), "login with "+name)
		assertRefusedForRole(t, refreshWith(fx.srv, refreshToken), "refresh with "+name)
	}

	setAccountRole(t, fx, "bad@test.com", "postgres")
	db.Exec(context.Background(), "UPDATE auth.users SET allowed_roles = NULL WHERE email = 'bad@test.com'")
	assertRefusedForRole(t, postJSON(fx.srv, "/auth/test-org/test-project/login", map[string]string{
		"email": "bad@test.com", "password": "password123",
	}), "login as a platform role")
}

func usersAuditRowsFollowTheUser(t *testing.T, fx *integrationFixture) {
	userID := registerUser(t, fx, "gone@test.com")
	resp, _ := userAdminRequest(t, fx, http.MethodPut, rolePath(userID),
		signUserAdmin(t, fx.signingKey, validUserAdmin("test-project")), map[string]any{"role": "editor"})
	if resp.StatusCode != 200 {
		t.Fatalf("set role: got %d", resp.StatusCode)
	}

	db := directDB(t, fx)
	if _, err := db.Exec(context.Background(), "DELETE FROM auth.users WHERE id = $1", userID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var changes int
	db.QueryRow(context.Background(), "SELECT COUNT(*) FROM auth.role_changes WHERE user_id = $1", userID).Scan(&changes)
	if changes != 0 {
		t.Errorf("audit rows after the user was deleted: %d", changes)
	}
}
