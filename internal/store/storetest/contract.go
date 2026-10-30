// Package storetest is the behaviour every store.Store must show, run by each
// engine's tests against a real database so the engines cannot drift apart.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/excalibase/auth/internal/token"
	"github.com/google/uuid"
)

// Fixture is one migrated, empty auth database. Count reads a table's row
// count straight from the database, for effects the interface does not read.
type Fixture struct {
	Store store.Store
	Count func(t *testing.T, table string) int
	// Grandfather marks an account verified with no proof, as Postgres
	// migration 000003 did for every account it found.
	Grandfather func(t *testing.T, email string)
	// Disable switches an account off, as an admin does.
	Disable func(t *testing.T, email string)
	// SetEmail changes an account's address straight in the database.
	SetEmail func(t *testing.T, id int64, email string)
	// Reference makes an app table row reference the account.
	Reference func(t *testing.T, id int64)
	// Backdate makes the account, its last sign-in and its refresh tokens age old.
	Backdate func(t *testing.T, id int64, age time.Duration)
}

var sequence atomic.Int64

func uniqueEmail(name string) string {
	return fmt.Sprintf("%s-%d@contract.test", name, sequence.Add(1))
}

func newUser(t *testing.T, db store.Store, name string) (int64, string) {
	t.Helper()
	email := uniqueEmail(name)
	id, created, err := db.InsertUser(context.Background(), email, "hash-"+name, "Full "+name)
	if err != nil || !created || id <= 0 {
		t.Fatalf("insert %s: id=%d created=%v err=%v", name, id, created, err)
	}
	return id, email
}

func session(expiry time.Duration) store.RefreshSession {
	return store.RefreshSession{FamilyID: uuid.New(), Expiry: time.Now().Add(expiry).Truncate(time.Microsecond)}
}

func hash(t *testing.T) string {
	t.Helper()
	_, digest, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func acceptAll(store.Account) error { return nil }

// Run runs the whole contract against the fixture.
func Run(t *testing.T, fx Fixture) {
	t.Run("users", func(t *testing.T) { runUsers(t, fx) })
	t.Run("refresh tokens", func(t *testing.T) { runRefresh(t, fx) })
	t.Run("single-use tokens", func(t *testing.T) { runSingleUse(t, fx) })
	t.Run("roles", func(t *testing.T) { runRoles(t, fx) })
	t.Run("api keys", func(t *testing.T) { runAPIKeys(t, fx) })
	t.Run("identities", func(t *testing.T) { runIdentities(t, fx) })
	t.Run("sign-in flows", func(t *testing.T) { runSignInFlows(t, fx) })
	t.Run("email codes", func(t *testing.T) { runEmailOTPs(t, fx) })
	t.Run("email sign-in", func(t *testing.T) { runEmailSignIn(t, fx) })
	t.Run("identity linking", func(t *testing.T) { runLinking(t, fx) })
	t.Run("account self-service", func(t *testing.T) { runAccount(t, fx) })
	t.Run("guest accounts", func(t *testing.T) { runGuests(t, fx) })
	t.Run("multi-factor", func(t *testing.T) { runMFA(t, fx) })
}

func runUsers(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store

	t.Run("an address is taken once, and its case makes a different address", func(t *testing.T) {
		id, email := newUser(t, db, "Case")
		again, created, err := db.InsertUser(ctx, email, "other", "Other")
		if err != nil || created || again != 0 {
			t.Fatalf("taken address: id=%d created=%v err=%v", again, created, err)
		}
		upper, created, err := db.InsertUser(ctx, strings.ToUpper(email), "h", "U")
		if err != nil || !created || upper == id {
			t.Fatalf("differently cased address: id=%d created=%v err=%v", upper, created, err)
		}
		if account, err := db.AccountByEmail(ctx, strings.ToUpper(email)); err != nil || account.ID != upper {
			t.Fatalf("lookup is case-sensitive: %+v %v", account, err)
		}
	})

	t.Run("trailing spaces make a different address, as on Postgres", func(t *testing.T) {
		id, email := newUser(t, db, "pad")
		padded, created, err := db.InsertUser(ctx, email+" ", "h", "Padded")
		if err != nil || !created || padded == id {
			t.Fatalf("padded address: id=%d created=%v err=%v", padded, created, err)
		}
		if account, err := db.AccountByEmail(ctx, email+"  "); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a differently padded address found %+v %v", account, err)
		}
		if replaced, err := db.ReplaceUnverified(ctx, email+"  ", "x", "y"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a padded sign-up took over account %d: %v", replaced, err)
		}
	})

	t.Run("an address longer than the column is refused, not cut short", func(t *testing.T) {
		long := strings.Repeat("a", 120) + "@contract.test"
		if _, created, err := db.InsertUser(ctx, long, "h", "Long"); err == nil || created {
			t.Fatalf("over-long address stored: created=%v err=%v", created, err)
		}
	})

	t.Run("an account reads back as stored", func(t *testing.T) {
		id, email := newUser(t, db, "read")
		account, err := db.AccountByEmail(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		want := store.Account{ID: id, Email: email, PasswordHash: "hash-read", FullName: "Full read", Role: "user", Enabled: true}
		if account.ID != want.ID || account.Email != want.Email || account.PasswordHash != want.PasswordHash ||
			account.FullName != want.FullName || account.Role != want.Role || !account.Enabled ||
			account.EmailVerified || account.AllowedRoles != nil {
			t.Fatalf("account = %+v, want %+v", account, want)
		}
		if _, err := db.AccountByEmail(ctx, uniqueEmail("nobody")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown address: err=%v", err)
		}
		if err := db.TouchLastLogin(ctx, id); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("an unverified account is taken over, a verified one is not", func(t *testing.T) {
		id, email := newUser(t, db, "takeover")
		got, err := db.ReplaceUnverified(ctx, email, "new-hash", "New Name")
		if err != nil || got != id {
			t.Fatalf("replace: id=%d err=%v", got, err)
		}
		account, _ := db.AccountByEmail(ctx, email)
		if account.PasswordHash != "new-hash" || account.FullName != "New Name" {
			t.Fatalf("not replaced: %+v", account)
		}
		if _, err := db.MarkVerified(ctx, id, true, "!marker"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ReplaceUnverified(ctx, email, "x", "y"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("verified account replaced: err=%v", err)
		}
	})

	t.Run("verifying ends every session and keeps or replaces the password", func(t *testing.T) {
		id, email := newUser(t, db, "verify")
		live := hash(t)
		if err := db.InsertRefreshToken(ctx, live, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		address, err := db.MarkVerified(ctx, id, false, "!marker")
		if err != nil || address != email {
			t.Fatalf("mark verified: %q %v", address, err)
		}
		account, _ := db.AccountByEmail(ctx, email)
		if !account.EmailVerified || account.PasswordHash != "!marker" {
			t.Fatalf("after verify: %+v", account)
		}
		if state, _ := db.RefreshTokenState(ctx, live); !state.Revoked {
			t.Fatal("refresh token survived verification")
		}

		kept, keptEmail := newUser(t, db, "verify-keep")
		if _, err := db.MarkVerified(ctx, kept, true, "!marker"); err != nil {
			t.Fatal(err)
		}
		if account, _ := db.AccountByEmail(ctx, keptEmail); account.PasswordHash != "hash-verify-keep" || !account.EmailVerified {
			t.Fatalf("kept password replaced: %+v", account)
		}
		if _, err := db.MarkVerified(ctx, 1<<50, true, "!marker"); err == nil {
			t.Fatal("unknown account verified")
		}
	})

	t.Run("a new password is stored", func(t *testing.T) {
		id, email := newUser(t, db, "password")
		if err := db.SetPassword(ctx, id, "reset-hash"); err != nil {
			t.Fatal(err)
		}
		if account, _ := db.AccountByEmail(ctx, email); account.PasswordHash != "reset-hash" {
			t.Fatalf("password = %q", account.PasswordHash)
		}
	})
}

func runRefresh(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store

	t.Run("rotation consumes the token and keeps the session", func(t *testing.T) {
		id, email := newUser(t, db, "rotate")
		first, successor := hash(t), hash(t)
		login := session(time.Hour)
		if err := db.InsertRefreshToken(ctx, first, id, login); err != nil {
			t.Fatal(err)
		}
		account, rotated, err := db.RotateRefreshToken(ctx, first, successor, acceptAll)
		if err != nil {
			t.Fatal(err)
		}
		if account.ID != id || account.Email != email || account.Role != "user" || account.FullName != "Full rotate" {
			t.Fatalf("account = %+v", account)
		}
		if rotated.FamilyID != login.FamilyID || !rotated.Expiry.Equal(login.Expiry.Truncate(time.Microsecond)) {
			t.Fatalf("session = %+v, want %+v", rotated, login)
		}
		if _, _, err := db.RotateRefreshToken(ctx, first, hash(t), acceptAll); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("used token rotated again: %v", err)
		}
		state, err := db.RefreshTokenState(ctx, first)
		if err != nil || !state.Revoked || state.FamilyID != login.FamilyID {
			t.Fatalf("used token state = %+v %v", state, err)
		}
		if _, next, err := db.RotateRefreshToken(ctx, successor, hash(t), acceptAll); err != nil || next.FamilyID != login.FamilyID {
			t.Fatalf("successor: %+v %v", next, err)
		}
	})

	t.Run("a refused account rolls the rotation back", func(t *testing.T) {
		id, _ := newUser(t, db, "refused")
		presented := hash(t)
		if err := db.InsertRefreshToken(ctx, presented, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		refusal := errors.New("refused")
		if _, _, err := db.RotateRefreshToken(ctx, presented, hash(t), func(store.Account) error { return refusal }); !errors.Is(err, refusal) {
			t.Fatalf("err = %v", err)
		}
		if state, _ := db.RefreshTokenState(ctx, presented); state.Revoked {
			t.Fatal("refused rotation consumed the token")
		}
	})

	t.Run("an expired or unknown token does not rotate", func(t *testing.T) {
		id, _ := newUser(t, db, "expired")
		expired := hash(t)
		if err := db.InsertRefreshToken(ctx, expired, id, session(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.RotateRefreshToken(ctx, expired, hash(t), acceptAll); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired: %v", err)
		}
		if state, err := db.RefreshTokenState(ctx, expired); err != nil || state.Revoked {
			t.Fatalf("expired state = %+v %v", state, err)
		}
		if _, err := db.RefreshTokenState(ctx, hash(t)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown state: %v", err)
		}
	})

	t.Run("of concurrent rotations exactly one succeeds", func(t *testing.T) {
		id, _ := newUser(t, db, "race")
		presented := hash(t)
		if err := db.InsertRefreshToken(ctx, presented, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		const racers = 8
		var wins, losses atomic.Int32
		var wg sync.WaitGroup
		for range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := db.RotateRefreshToken(ctx, presented, hash(t), acceptAll)
				switch {
				case err == nil:
					wins.Add(1)
				case errors.Is(err, store.ErrNotFound):
					losses.Add(1)
				default:
					t.Errorf("racer: %v", err)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 || losses.Load() != racers-1 {
			t.Fatalf("wins=%d losses=%d", wins.Load(), losses.Load())
		}
	})

	t.Run("revocation by family, by user and by token", func(t *testing.T) {
		id, _ := newUser(t, db, "revoke")
		login := session(time.Hour)
		a, b, other := hash(t), hash(t), hash(t)
		for _, h := range []string{a, b} {
			if err := db.InsertRefreshToken(ctx, h, id, login); err != nil {
				t.Fatal(err)
			}
		}
		if err := db.InsertRefreshToken(ctx, other, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := db.RevokeRefreshFamily(ctx, login.FamilyID); err != nil {
			t.Fatal(err)
		}
		for _, h := range []string{a, b} {
			if state, _ := db.RefreshTokenState(ctx, h); !state.Revoked {
				t.Fatal("family member survived")
			}
		}
		if state, _ := db.RefreshTokenState(ctx, other); state.Revoked {
			t.Fatal("another family was revoked")
		}
		if err := db.RevokeRefreshToken(ctx, other); err != nil {
			t.Fatal(err)
		}
		if state, _ := db.RefreshTokenState(ctx, other); !state.Revoked {
			t.Fatal("logout left the token live")
		}
		last := hash(t)
		if err := db.InsertRefreshToken(ctx, last, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := db.RevokeUserRefreshTokens(ctx, id); err != nil {
			t.Fatal(err)
		}
		if state, _ := db.RefreshTokenState(ctx, last); !state.Revoked {
			t.Fatal("user revocation left a token live")
		}
	})
}

func runSingleUse(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	for _, kind := range []store.TokenKind{store.EmailVerification, store.PasswordReset} {
		t.Run(fmt.Sprintf("kind %d", kind), func(t *testing.T) {
			id, _ := newUser(t, db, "link")
			first, second := hash(t), hash(t)
			if err := db.IssueToken(ctx, kind, id, first, time.Now().Add(time.Hour), true); err != nil {
				t.Fatal(err)
			}
			found, err := db.LookupToken(ctx, kind, first)
			if err != nil || found.UserID != id || found.Hash != first || found.RowID <= 0 {
				t.Fatalf("lookup = %+v %v", found, err)
			}
			if found.ConfirmsPassword != (kind == store.EmailVerification) {
				t.Fatalf("confirmsPassword = %v for kind %d", found.ConfirmsPassword, kind)
			}
			if err := db.IssueToken(ctx, kind, id, second, time.Now().Add(time.Hour), false); err != nil {
				t.Fatal(err)
			}
			if _, err := db.LookupToken(ctx, kind, first); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("older link still live: %v", err)
			}
			newest, err := db.LookupToken(ctx, kind, second)
			if err != nil || newest.ConfirmsPassword {
				t.Fatalf("newest = %+v %v", newest, err)
			}
			if claimed, err := db.ClaimToken(ctx, kind, newest.RowID); err != nil || !claimed {
				t.Fatalf("first claim: %v %v", claimed, err)
			}
			if claimed, err := db.ClaimToken(ctx, kind, newest.RowID); err != nil || claimed {
				t.Fatalf("second claim: %v %v", claimed, err)
			}
			expired := hash(t)
			if err := db.IssueToken(ctx, kind, id, expired, time.Now().Add(-time.Minute), false); err != nil {
				t.Fatal(err)
			}
			if _, err := db.LookupToken(ctx, kind, expired); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expired link live: %v", err)
			}
		})
	}
}

func runRoles(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store

	t.Run("a role change is stored, audited and ends every session", func(t *testing.T) {
		id, email := newUser(t, db, "roles")
		live := hash(t)
		if err := db.InsertRefreshToken(ctx, live, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		before := fx.Count(t, "role_changes")
		change := store.RoleChange{UserID: id, Role: "editor", Allowed: []string{"editor", "viewer"},
			Stored: []string{"editor", "viewer"}, Actor: "studio:u1"}
		user, err := db.ApplyRoleChange(ctx, change)
		if err != nil || user.Role != "editor" || !slices.Equal(user.AllowedRoles, change.Allowed) || user.Email != email {
			t.Fatalf("change = %+v %v", user, err)
		}
		account, _ := db.AccountByEmail(ctx, email)
		if account.Role != "editor" || !slices.Equal(account.AllowedRoles, change.Stored) {
			t.Fatalf("stored = %+v", account)
		}
		if fx.Count(t, "role_changes") != before+1 {
			t.Fatal("no audit row")
		}
		if state, _ := db.RefreshTokenState(ctx, live); !state.Revoked {
			t.Fatal("session survived a role change")
		}

		cleared := store.RoleChange{UserID: id, Role: "user", Allowed: []string{"user"}, Actor: "service-key:3"}
		if _, err := db.ApplyRoleChange(ctx, cleared); err != nil {
			t.Fatal(err)
		}
		if account, _ := db.AccountByEmail(ctx, email); account.AllowedRoles != nil {
			t.Fatalf("no list given, allowed_roles = %v", account.AllowedRoles)
		}
		if _, err := db.ApplyRoleChange(ctx, store.RoleChange{UserID: 1 << 50, Role: "x", Actor: "a"}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown account: %v", err)
		}
	})

	t.Run("users list by id with paging", func(t *testing.T) {
		first, _ := newUser(t, db, "list-a")
		second, _ := newUser(t, db, "list-b")
		users, err := db.ListUsers(ctx, 500, 0)
		if err != nil {
			t.Fatal(err)
		}
		var ids []int64
		for _, user := range users {
			ids = append(ids, user.ID)
			if user.AllowedRoles == nil {
				t.Fatalf("allowedRoles nil for %d", user.ID)
			}
		}
		if !slices.IsSorted(ids) || !slices.Contains(ids, first) || !slices.Contains(ids, second) {
			t.Fatalf("ids = %v", ids)
		}
		page, err := db.ListUsers(ctx, 1, 1)
		if err != nil || len(page) != 1 || page[0].ID != ids[1] {
			t.Fatalf("page = %+v %v", page, err)
		}
	})
}

func runAPIKeys(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	keyHash := hash(t)
	id, createdAt, err := db.CreateAPIKey(ctx, keyHash, "esk_pub_abc", "publishable", "")
	if err != nil || id <= 0 || time.Since(createdAt) > time.Minute || time.Since(createdAt) < -time.Minute {
		t.Fatalf("create: %d %v %v", id, createdAt, err)
	}
	key, err := db.APIKeyByHash(ctx, keyHash)
	if err != nil || key.ID != id || key.Type != "publishable" || key.CreatedBy != nil {
		t.Fatalf("by hash = %+v %v", key, err)
	}
	if err := db.TouchAPIKey(ctx, id); err != nil {
		t.Fatal(err)
	}
	newer, _, err := db.CreateAPIKey(ctx, hash(t), "esk_sec_def", "secret", "ci")
	if err != nil {
		t.Fatal(err)
	}
	listing, err := db.ListAPIKeys(ctx)
	if err != nil || len(listing) < 2 {
		t.Fatalf("list = %+v %v", listing, err)
	}
	byID := map[int64]store.APIKeyListing{}
	for _, row := range listing {
		byID[row.ID] = row
	}
	if row := byID[id]; row.Name != "" || row.LastUsedAt == nil || row.Prefix != "esk_pub_abc" {
		t.Fatalf("listed key = %+v", row)
	}
	if row := byID[newer]; row.Name != "ci" || row.LastUsedAt != nil || row.Type != "secret" {
		t.Fatalf("listed key = %+v", row)
	}
	if _, _, err := db.CreateAPIKey(ctx, hash(t), "p", "neither", ""); err == nil {
		t.Fatal("an unknown key type was stored")
	}
	if revoked, err := db.RevokeAPIKey(ctx, id); err != nil || !revoked {
		t.Fatalf("revoke: %v %v", revoked, err)
	}
	if revoked, err := db.RevokeAPIKey(ctx, id); err != nil || revoked {
		t.Fatalf("revoke again: %v %v", revoked, err)
	}
	if _, err := db.APIKeyByHash(ctx, keyHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("revoked key found: %v", err)
	}
	for _, row := range mustList(t, db) {
		if row.ID == id {
			t.Fatal("revoked key listed")
		}
	}
}

func mustList(t *testing.T, db store.Store) []store.APIKeyListing {
	t.Helper()
	listing, err := db.ListAPIKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return listing
}
