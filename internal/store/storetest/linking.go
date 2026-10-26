package storetest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
)

func provenUser(t *testing.T, db store.Store, name string) (int64, string) {
	t.Helper()
	id, email := newUser(t, db, name)
	if _, err := db.MarkVerified(context.Background(), id, true, "!marker"); err != nil {
		t.Fatal(err)
	}
	return id, email
}

func emailClaim(address string) store.IdentityClaim {
	return store.IdentityClaim{Provider: store.EmailProvider, Subject: strings.ToLower(address), Email: address}
}

func link(t *testing.T, db store.Store, userID int64, claim store.IdentityClaim) {
	t.Helper()
	if err := db.LinkIdentity(context.Background(), userID, claim); err != nil {
		t.Fatalf("link %+v to %d: %v", claim, userID, err)
	}
}

func identitiesOf(t *testing.T, db store.Store, userID int64) []store.Identity {
	t.Helper()
	identities, err := db.ListIdentities(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return identities
}

func runLinking(t *testing.T, fx Fixture) {
	t.Run("a provider identity links to a proven account, is listed and then signs in to it", func(t *testing.T) {
		linkProviderIdentity(t, fx.Store)
	})
	t.Run("an identity cannot be linked twice, to another account or the same", func(t *testing.T) {
		linkTakenIdentity(t, fx)
	})
	t.Run("only an enabled account with a proven address links", func(t *testing.T) {
		linkRefusedAccounts(t, fx)
	})
	t.Run("a linked address reaches the account by mail and by provider", func(t *testing.T) {
		linkedAddressSignsIn(t, fx.Store)
	})
	t.Run("an address a proven account answers to stays its own; an unproven one is replaced", func(t *testing.T) {
		linkAddressConflicts(t, fx.Store)
	})
	t.Run("unlinking keeps at least one way to sign in", func(t *testing.T) {
		unlinkKeepsAWayIn(t, fx.Store)
	})
	t.Run("sign-ins in flight carry the account they link to", func(t *testing.T) {
		linkInFlight(t, fx.Store)
	})
	t.Run("a session keeps when its owner signed in across rotations", func(t *testing.T) {
		sessionKeepsAuthTime(t, fx.Store)
	})
}

func linkProviderIdentity(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, _ := provenUser(t, db, "link-provider")
	claim := claimFor("google", uniqueEmail("link-google"))
	link(t, db, id, claim)
	listed := identitiesOf(t, db, id)
	if len(listed) != 1 || listed[0].Provider != "google" || listed[0].Email != claim.Email || listed[0].ID <= 0 ||
		listed[0].CreatedAt.IsZero() {
		t.Fatalf("identities = %+v", listed)
	}
	account, outcome, err := db.SignInWithIdentity(ctx, claim, false)
	if err != nil || outcome != store.IdentityKnown || account.ID != id {
		t.Fatalf("sign-in with the linked identity: %+v outcome=%d %v", account, outcome, err)
	}
	if listed := identitiesOf(t, db, id); listed[0].LastSignInAt == nil {
		t.Fatal("a sign-in left last_sign_in_at empty")
	}
}

func linkTakenIdentity(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	owner, _ := provenUser(t, db, "link-owner")
	other, _ := provenUser(t, db, "link-other")
	claim := claimFor("github", uniqueEmail("link-taken"))
	link(t, db, owner, claim)
	before := fx.Count(t, "identities")
	for _, userID := range []int64{other, owner} {
		if err := db.LinkIdentity(ctx, userID, claim); !errors.Is(err, store.ErrIdentityExists) {
			t.Fatalf("link to %d: %v, want ErrIdentityExists", userID, err)
		}
	}
	if fx.Count(t, "identities") != before {
		t.Fatal("a refused link wrote a row")
	}
	if account, _, err := db.SignInWithIdentity(ctx, claim, false); err != nil || account.ID != owner {
		t.Fatalf("the identity moved: %+v %v", account, err)
	}
}

func linkRefusedAccounts(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	unproven, _ := newUser(t, db, "link-unproven")
	grandfathered, address := newUser(t, db, "link-grandfathered")
	fx.Grandfather(t, address)
	for _, userID := range []int64{unproven, grandfathered} {
		if err := db.LinkIdentity(ctx, userID, claimFor("google", uniqueEmail("x"))); !errors.Is(err, store.ErrAddressUnproven) {
			t.Fatalf("account %d: %v, want ErrAddressUnproven", userID, err)
		}
	}
	disabled, disabledAddress := provenUser(t, db, "link-disabled")
	fx.Disable(t, disabledAddress)
	if err := db.LinkIdentity(ctx, disabled, claimFor("google", uniqueEmail("x"))); !errors.Is(err, store.ErrAccountDisabled) {
		t.Fatalf("disabled account: %v", err)
	}
	if err := db.LinkIdentity(ctx, 1<<50, claimFor("google", uniqueEmail("x"))); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
}

func linkedAddressSignsIn(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, _ := provenUser(t, db, "link-mail")
	address := uniqueEmail("Link-Second")
	link(t, db, id, emailClaim(address))
	if listed := identitiesOf(t, db, id); len(listed) != 1 || listed[0].Provider != store.EmailProvider || listed[0].Email != address {
		t.Fatalf("identities = %+v", listed)
	}
	account, outcome, err := db.SignInWithEmail(ctx, strings.ToUpper(address), "Name", true)
	if err != nil || outcome != store.IdentityKnown || account.ID != id {
		t.Fatalf("mail sign-in with the linked address: %+v outcome=%d %v", account, outcome, err)
	}
	if found, err := db.AccountByAddress(ctx, address); err != nil || found.ID != id {
		t.Fatalf("the linked address reaches %+v %v", found, err)
	}
	account, outcome, err = db.SignInWithIdentity(ctx, claimFor("github", address), false)
	if err != nil || outcome != store.IdentityLinked || account.ID != id {
		t.Fatalf("provider sign-in with the linked address: %+v outcome=%d %v", account, outcome, err)
	}
}

func linkAddressConflicts(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, own := provenUser(t, db, "link-conflict")
	_, proven := provenUser(t, db, "link-proven-elsewhere")
	for _, address := range []string{own, strings.ToUpper(own), proven} {
		if err := db.LinkIdentity(ctx, id, emailClaim(address)); !errors.Is(err, store.ErrIdentityExists) {
			t.Fatalf("link %s: %v, want ErrIdentityExists", address, err)
		}
	}
	squatter, squatted := newUser(t, db, "link-squatted")
	link(t, db, id, emailClaim(squatted))
	if _, err := db.AccountByID(ctx, squatter); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the unproven account holding the address survived: %v", err)
	}
	other, _ := provenUser(t, db, "link-second-owner")
	if err := db.LinkIdentity(ctx, other, emailClaim(strings.ToUpper(squatted))); !errors.Is(err, store.ErrIdentityExists) {
		t.Fatalf("an address linked elsewhere: %v", err)
	}
}

func unlinkKeepsAWayIn(t *testing.T, db store.Store) {
	ctx := context.Background()
	providerMade := signIn(t, db, claimFor("google", uniqueEmail("unlink-only")), true, store.IdentityCreated)
	only := identitiesOf(t, db, providerMade.ID)[0]
	if _, err := db.UnlinkIdentity(ctx, providerMade.ID, only.ID); !errors.Is(err, store.ErrLastSignInMethod) {
		t.Fatalf("unlink the only way in: %v", err)
	}
	link(t, db, providerMade.ID, claimFor("github", uniqueEmail("unlink-second")))
	removed, err := db.UnlinkIdentity(ctx, providerMade.ID, only.ID)
	if err != nil || removed.ID != only.ID || removed.Provider != "google" {
		t.Fatalf("unlink = %+v %v", removed, err)
	}
	if listed := identitiesOf(t, db, providerMade.ID); len(listed) != 1 || listed[0].Provider != "github" {
		t.Fatalf("left = %+v", listed)
	}

	withPassword, _ := provenUser(t, db, "unlink-password")
	link(t, db, withPassword, claimFor("google", uniqueEmail("unlink-pw")))
	if _, err := db.UnlinkIdentity(ctx, withPassword, identitiesOf(t, db, withPassword)[0].ID); err != nil {
		t.Fatalf("a password is a way in: %v", err)
	}
	stranger, _ := provenUser(t, db, "unlink-stranger")
	theirs := identitiesOf(t, db, providerMade.ID)[0]
	if _, err := db.UnlinkIdentity(ctx, stranger, theirs.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unlink another account's identity: %v", err)
	}
}

func linkInFlight(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, address := provenUser(t, db, "link-flight")
	state := store.FlowState{StateHash: hash(t), Provider: "google", IDPCodeVerifier: "v", ClientCodeChallenge: "c",
		RedirectTo: "https://app.test", LinkUserID: id, ExpiresAt: time.Now().Add(time.Minute)}
	if err := db.SaveFlowState(ctx, state); err != nil {
		t.Fatal(err)
	}
	if got, err := db.ConsumeFlowState(ctx, state.StateHash); err != nil || got.LinkUserID != id {
		t.Fatalf("flow = %+v %v", got, err)
	}
	claim := claimFor("github", uniqueEmail("link-code"))
	code := store.AuthCode{CodeHash: hash(t), UserID: id, CodeChallenge: "c", Link: claim, ExpiresAt: time.Now().Add(time.Minute)}
	if err := db.SaveAuthCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	if got, err := db.RedeemAuthCode(ctx, code.CodeHash); err != nil || got.Link.Provider != "github" ||
		got.Link.Subject != claim.Subject || got.Link.Email != claim.Email {
		t.Fatalf("code = %+v %v", got, err)
	}
	plain := store.AuthCode{CodeHash: hash(t), UserID: id, CodeChallenge: "c", ExpiresAt: time.Now().Add(time.Minute)}
	if err := db.SaveAuthCode(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if got, err := db.RedeemAuthCode(ctx, plain.CodeHash); err != nil || got.Link != (store.IdentityClaim{}) {
		t.Fatalf("a sign-in code carries a link: %+v %v", got, err)
	}
	otp := codeOTP(t, uniqueEmail("link-otp"))
	otp.LinkUserID = id
	save(t, db, otp)
	got, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: otp.Email, CodeChallenge: otp.CodeChallenge}, perCode(5), accept)
	if err != nil || got.LinkUserID != id {
		t.Fatalf("otp = %+v %v (account %s)", got, err, address)
	}
}

func sessionKeepsAuthTime(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, _ := newUser(t, db, "auth-time")
	signedIn := session(time.Hour)
	signedIn.AuthTime = time.Now().Add(-time.Minute).Truncate(time.Second)
	first, second := hash(t), hash(t)
	if err := db.InsertRefreshToken(ctx, first, id, signedIn); err != nil {
		t.Fatal(err)
	}
	if _, rotated, err := db.RotateRefreshToken(ctx, first, second, acceptAll); err != nil || !rotated.AuthTime.Equal(signedIn.AuthTime) {
		t.Fatalf("rotated = %+v %v, want auth time %v", rotated, err, signedIn.AuthTime)
	}
	if _, again, err := db.RotateRefreshToken(ctx, second, hash(t), acceptAll); err != nil || !again.AuthTime.Equal(signedIn.AuthTime) {
		t.Fatalf("second rotation = %+v %v", again, err)
	}
	unknown := hash(t)
	if err := db.InsertRefreshToken(ctx, unknown, id, session(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, rotated, err := db.RotateRefreshToken(ctx, unknown, hash(t), acceptAll); err != nil || !rotated.AuthTime.IsZero() {
		t.Fatalf("a session with no sign-in time got %v %v", rotated.AuthTime, err)
	}
}
