package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
)

func claimFor(provider, email string) store.IdentityClaim {
	return store.IdentityClaim{Provider: provider, Subject: fmt.Sprintf("sub-%d", sequence.Add(1)), Email: email, FullName: "Provider Name"}
}

func signIn(t *testing.T, db store.Store, claim store.IdentityClaim, allowCreate bool, want store.IdentityOutcome) store.Account {
	t.Helper()
	account, outcome, err := db.SignInWithIdentity(context.Background(), claim, allowCreate)
	if err != nil || outcome != want {
		t.Fatalf("sign in %+v: outcome=%d err=%v, want outcome %d", claim, outcome, err, want)
	}
	return account
}

func runIdentities(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store

	t.Run("a provider account signs up once and then signs in to the same account", func(t *testing.T) {
		claim := claimFor("github", uniqueEmail("oauth-new"))
		created := signIn(t, db, claim, true, store.IdentityCreated)
		if created.ID <= 0 || created.Email != claim.Email || created.FullName != claim.FullName ||
			created.Role != "user" || !created.Enabled || !created.EmailVerified || created.PasswordHash != "" {
			t.Fatalf("created = %+v", created)
		}
		again := signIn(t, db, claim, false, store.IdentityKnown)
		if again.ID != created.ID {
			t.Fatalf("second sign-in reached account %d, want %d", again.ID, created.ID)
		}
		byEmail, err := db.AccountByEmail(ctx, claim.Email)
		if err != nil || byEmail.ID != created.ID || byEmail.PasswordHash != "" || !byEmail.EmailVerified {
			t.Fatalf("an account without a password reads back as %+v %v", byEmail, err)
		}
		byID, err := db.AccountByID(ctx, created.ID)
		if err != nil || byID.Email != claim.Email || byID.PasswordHash != "" {
			t.Fatalf("by id = %+v %v", byID, err)
		}
		if _, err := db.AccountByID(ctx, 1<<50); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown id: %v", err)
		}
	})

	t.Run("the same subject at another provider is another identity", func(t *testing.T) {
		github := claimFor("github", uniqueEmail("oauth-subject"))
		signIn(t, db, github, true, store.IdentityCreated)
		google := github
		google.Provider = "google"
		if account := signIn(t, db, google, true, store.IdentityLinked); account.Email != github.Email {
			t.Fatalf("google sign-in reached %+v", account)
		}
	})

	t.Run("a verified account with the address is linked and keeps its password", func(t *testing.T) {
		id, email := newUser(t, db, "oauth-link")
		if _, err := db.MarkVerified(ctx, id, true, "!marker"); err != nil {
			t.Fatal(err)
		}
		live := hash(t)
		if err := db.InsertRefreshToken(ctx, live, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		linked := signIn(t, db, claimFor("google", email), false, store.IdentityLinked)
		if linked.ID != id || linked.PasswordHash != "hash-oauth-link" {
			t.Fatalf("linked = %+v", linked)
		}
		if state, _ := db.RefreshTokenState(ctx, live); state.Revoked {
			t.Fatal("linking a verified account ended its sessions")
		}
	})

	t.Run("an unverified account is replaced by a new one: its sessions, links and password go", func(t *testing.T) {
		id, email := newUser(t, db, "oauth-squat")
		live, link, reset := hash(t), hash(t), hash(t)
		if err := db.InsertRefreshToken(ctx, live, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := db.IssueToken(ctx, store.EmailVerification, id, link, time.Now().Add(time.Hour), true); err != nil {
			t.Fatal(err)
		}
		if err := db.IssueToken(ctx, store.PasswordReset, id, reset, time.Now().Add(time.Hour), false); err != nil {
			t.Fatal(err)
		}
		owner := signIn(t, db, claimFor("github", email), false, store.IdentityTookOver)
		if owner.ID == id || owner.PasswordHash != "" || !owner.EmailVerified || owner.Email != email {
			t.Fatalf("taken over = %+v (squatted id %d)", owner, id)
		}
		if _, err := db.AccountByID(ctx, id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the squatted account survived: %v", err)
		}
		if _, err := db.RefreshTokenState(ctx, live); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the squatter's session survived the takeover: %v", err)
		}
		for kind, digest := range map[store.TokenKind]string{store.EmailVerification: link, store.PasswordReset: reset} {
			if _, err := db.LookupToken(ctx, kind, digest); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("link of kind %d survived the takeover: %v", kind, err)
			}
		}
	})

	t.Run("an account marked verified without proof is taken over, not linked", func(t *testing.T) {
		id, email := newUser(t, db, "oauth-grandfathered")
		fx.Grandfather(t, email)
		owner := signIn(t, db, claimFor("google", email), false, store.IdentityTookOver)
		if owner.ID == id || owner.PasswordHash != "" {
			t.Fatalf("a grandfathered account was linked: %+v", owner)
		}
	})

	t.Run("the address matches whatever its case", func(t *testing.T) {
		id, email := newUser(t, db, "Oauth-Case")
		if _, err := db.MarkVerified(ctx, id, true, "!marker"); err != nil {
			t.Fatal(err)
		}
		if linked := signIn(t, db, claimFor("google", strings.ToUpper(email)), false, store.IdentityLinked); linked.ID != id {
			t.Fatalf("an upper-case address reached %+v, want account %d", linked, id)
		}
		squatID, squatted := newUser(t, db, "Oauth-Case-Squat")
		if owner := signIn(t, db, claimFor("github", strings.ToLower(squatted)), false, store.IdentityTookOver); owner.ID == squatID {
			t.Fatalf("a lower-case address did not take over the unverified account: %+v", owner)
		}
	})

	t.Run("an exact address wins over one differing in case, and two such without it are refused", func(t *testing.T) {
		email := uniqueEmail("oauth-twins")
		exact, _, err := db.InsertUser(ctx, email, "hash-exact", "Exact")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.InsertUser(ctx, strings.ToUpper(email), "hash-upper", "Upper"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.MarkVerified(ctx, exact, true, "!marker"); err != nil {
			t.Fatal(err)
		}
		if linked := signIn(t, db, claimFor("google", email), false, store.IdentityLinked); linked.ID != exact {
			t.Fatalf("exact address reached %+v, want %d", linked, exact)
		}
		users, identities := fx.Count(t, "users"), fx.Count(t, "identities")
		mixed := strings.ToUpper(email[:1]) + email[1:]
		_, _, err = db.SignInWithIdentity(ctx, claimFor("github", mixed), true)
		if !errors.Is(err, store.ErrAmbiguousEmail) {
			t.Fatalf("err = %v, want ErrAmbiguousEmail", err)
		}
		if fx.Count(t, "users") != users || fx.Count(t, "identities") != identities {
			t.Fatal("an ambiguous sign-in wrote rows")
		}
	})

	t.Run("closed sign-ups refuse a new account and write nothing", func(t *testing.T) {
		users, identities := fx.Count(t, "users"), fx.Count(t, "identities")
		_, _, err := db.SignInWithIdentity(ctx, claimFor("github", uniqueEmail("oauth-closed")), false)
		if !errors.Is(err, store.ErrSignupsDisabled) {
			t.Fatalf("err = %v, want ErrSignupsDisabled", err)
		}
		if fx.Count(t, "users") != users || fx.Count(t, "identities") != identities {
			t.Fatal("a refused sign-up wrote rows")
		}
	})
}

func runSignInFlows(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store

	t.Run("a flow state is consumed once", func(t *testing.T) {
		state := store.FlowState{
			StateHash: hash(t), Provider: "github", IDPCodeVerifier: "verifier", Nonce: "nonce",
			ClientCodeChallenge: "challenge", RedirectTo: "https://app.test/cb?x=1", ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		if err := db.SaveFlowState(ctx, state); err != nil {
			t.Fatal(err)
		}
		got, err := db.ConsumeFlowState(ctx, state.StateHash)
		if err != nil || got.Provider != state.Provider || got.IDPCodeVerifier != state.IDPCodeVerifier ||
			got.Nonce != state.Nonce || got.ClientCodeChallenge != state.ClientCodeChallenge || got.RedirectTo != state.RedirectTo {
			t.Fatalf("consumed = %+v %v", got, err)
		}
		if _, err := db.ConsumeFlowState(ctx, state.StateHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("second consume: %v", err)
		}
	})

	t.Run("an expired flow state is refused and later swept", func(t *testing.T) {
		expired := store.FlowState{StateHash: hash(t), Provider: "google", IDPCodeVerifier: "v", ClientCodeChallenge: "c",
			RedirectTo: "https://app.test", ExpiresAt: time.Now().Add(-time.Minute)}
		if err := db.SaveFlowState(ctx, expired); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ConsumeFlowState(ctx, expired.StateHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired state consumed: %v", err)
		}
		if err := db.SaveFlowState(ctx, store.FlowState{StateHash: hash(t), Provider: "google", IDPCodeVerifier: "v",
			ClientCodeChallenge: "c", RedirectTo: "https://app.test", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if err := db.SaveFlowState(ctx, store.FlowState{StateHash: hash(t), Provider: "google", IDPCodeVerifier: "v",
			ClientCodeChallenge: "c", RedirectTo: "https://app.test", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if n := fx.Count(t, "flow_states"); n != 1 {
			t.Fatalf("flow_states = %d rows, want only the live one", n)
		}
	})

	t.Run("an auth code is redeemed once and not after it expires", func(t *testing.T) {
		id, _ := newUser(t, db, "code")
		code := store.AuthCode{CodeHash: hash(t), UserID: id, CodeChallenge: "challenge", ExpiresAt: time.Now().Add(5 * time.Minute)}
		if err := db.SaveAuthCode(ctx, code); err != nil {
			t.Fatal(err)
		}
		got, err := db.RedeemAuthCode(ctx, code.CodeHash)
		if err != nil || got.UserID != id || got.CodeChallenge != "challenge" {
			t.Fatalf("redeemed = %+v %v", got, err)
		}
		if _, err := db.RedeemAuthCode(ctx, code.CodeHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("second redeem: %v", err)
		}
		stale := store.AuthCode{CodeHash: hash(t), UserID: id, CodeChallenge: "c", ExpiresAt: time.Now().Add(-time.Second)}
		if err := db.SaveAuthCode(ctx, stale); err != nil {
			t.Fatal(err)
		}
		if _, err := db.RedeemAuthCode(ctx, stale.CodeHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired code redeemed: %v", err)
		}
	})
}
