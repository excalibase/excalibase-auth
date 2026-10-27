package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/google/uuid"
)

var testChangeLimits = store.EmailChangeLimits{MinInterval: time.Millisecond, PerAccountDay: 5, PerProjectDay: 100}

func runAccount(t *testing.T, fx Fixture) {
	t.Run("a new account reads empty metadata", func(t *testing.T) { profileStartsEmpty(t, fx.Store) })
	t.Run("metadata merges by top-level key and null removes one", func(t *testing.T) { profileMerges(t, fx.Store) })
	t.Run("a merge past the limit changes nothing", func(t *testing.T) { profileLimit(t, fx.Store) })
	t.Run("a password change ends every session and reset link", func(t *testing.T) { passwordChangeEnds(t, fx.Store) })
	t.Run("signing out the others keeps one session", func(t *testing.T) { revokeOthersKeepsOne(t, fx.Store) })
	t.Run("a refresh token's state names its account", func(t *testing.T) { refreshStateNamesAccount(t, fx.Store) })
	t.Run("an address change moves the account once its link is spent", func(t *testing.T) { emailChangeMoves(t, fx.Store) })
	t.Run("an address a proven account holds is not mailed nor taken", func(t *testing.T) { emailChangeTaken(t, fx) })
	t.Run("an unproven account on the new address is replaced, not merged", func(t *testing.T) { emailChangeReplaces(t, fx) })
	t.Run("address changes are paced per account and capped per project", func(t *testing.T) { emailChangeBudgets(t, fx.Store) })
	t.Run("only an enabled account with a proven address asks for a change", func(t *testing.T) { emailChangeRefused(t, fx) })
	t.Run("deleting an account removes it and its sessions", func(t *testing.T) { deleteUser(t, fx) })
	t.Run("ending the sessions or changing the roles ends a pending change", func(t *testing.T) { pendingChangeEnds(t, fx.Store) })
	t.Run("only the account that asked confirms its change", func(t *testing.T) { confirmNeedsTheRequester(t, fx.Store) })
	t.Run("an unproven holder an app table references blocks the change", func(t *testing.T) { referencedSquatter(t, fx) })
}

func patch(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	parsed, err := store.ParseMetadataPatch([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func sameJSON(t *testing.T, got json.RawMessage, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("stored %s: %v", got, err)
	}
	_ = json.Unmarshal([]byte(want), &wantValue)
	gotText, _ := json.Marshal(gotValue)
	wantText, _ := json.Marshal(wantValue)
	if string(gotText) != string(wantText) {
		t.Fatalf("metadata = %s, want %s", gotText, wantText)
	}
}

func profileStartsEmpty(t *testing.T, db store.Store) {
	id, email := newUser(t, db, "profile-empty")
	profile, err := db.Profile(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Email != email || profile.CreatedAt.IsZero() {
		t.Fatalf("profile = %+v", profile)
	}
	sameJSON(t, profile.UserMetadata, `{}`)
	sameJSON(t, profile.AppMetadata, `{}`)
	if _, err := db.Profile(context.Background(), id+100000); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
}

func profileMerges(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, _ := newUser(t, db, "profile-merge")
	name := "New Name"
	if _, err := db.UpdateProfile(ctx, id, store.ProfileChange{FullName: &name,
		UserMetadata: patch(t, `{"theme":"dark","nested":{"a":[1,2]}}`), AppMetadata: patch(t, `{"plan":"free"}`)}); err != nil {
		t.Fatal(err)
	}
	profile, err := db.UpdateProfile(ctx, id, store.ProfileChange{UserMetadata: patch(t, `{"theme":null,"lang":"vi"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if profile.FullName != name {
		t.Fatalf("name = %q", profile.FullName)
	}
	sameJSON(t, profile.UserMetadata, `{"nested":{"a":[1,2]},"lang":"vi"}`)
	sameJSON(t, profile.AppMetadata, `{"plan":"free"}`)
	if _, err := db.UpdateProfile(ctx, id+100000, store.ProfileChange{FullName: &name}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
}

func profileLimit(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, _ := newUser(t, db, "profile-limit")
	half := `{"a":"` + strings.Repeat("x", store.MaxMetadataBytes/2) + `"}`
	if _, err := db.UpdateProfile(ctx, id, store.ProfileChange{UserMetadata: patch(t, half)}); err != nil {
		t.Fatal(err)
	}
	name := "Never Stored"
	other := `{"b":"` + strings.Repeat("y", store.MaxMetadataBytes/2) + `"}`
	_, err := db.UpdateProfile(ctx, id, store.ProfileChange{FullName: &name, UserMetadata: patch(t, other)})
	if !errors.Is(err, store.ErrMetadataTooLarge) {
		t.Fatalf("err = %v, want ErrMetadataTooLarge", err)
	}
	profile, _ := db.Profile(ctx, id)
	if profile.FullName == name || strings.Contains(string(profile.UserMetadata), `"b"`) {
		t.Fatal("a refused change was partly stored")
	}
}

func liveSession(t *testing.T, db store.Store, userID int64) (string, store.RefreshSession) {
	t.Helper()
	digest, current := hash(t), session(time.Hour)
	if err := db.InsertRefreshToken(context.Background(), digest, userID, current); err != nil {
		t.Fatal(err)
	}
	return digest, current
}

func revoked(t *testing.T, db store.Store, digest string) bool {
	t.Helper()
	state, err := db.RefreshTokenState(context.Background(), digest)
	if err != nil {
		t.Fatal(err)
	}
	return state.Revoked
}

func passwordChangeEnds(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, email := newUser(t, db, "password-change")
	first, _ := liveSession(t, db, id)
	second, _ := liveSession(t, db, id)
	reset := hash(t)
	if err := db.IssueToken(ctx, store.PasswordReset, id, reset, time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if err := db.ChangePassword(ctx, id, "new-hash"); err != nil {
		t.Fatal(err)
	}
	if !revoked(t, db, first) || !revoked(t, db, second) {
		t.Fatal("a session survived the password change")
	}
	if _, err := db.LookupToken(ctx, store.PasswordReset, reset); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a reset link survived the password change: %v", err)
	}
	if account, _ := db.AccountByEmail(ctx, email); account.PasswordHash != "new-hash" {
		t.Fatalf("password = %q", account.PasswordHash)
	}
}

func revokeOthersKeepsOne(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, _ := newUser(t, db, "revoke-others")
	other, _ := newUser(t, db, "revoke-others-bystander")
	kept, keptSession := liveSession(t, db, id)
	ended, _ := liveSession(t, db, id)
	bystander, _ := liveSession(t, db, other)
	if err := db.RevokeOtherSessions(ctx, id, keptSession.FamilyID); err != nil {
		t.Fatal(err)
	}
	if revoked(t, db, kept) || !revoked(t, db, ended) || revoked(t, db, bystander) {
		t.Fatal("revoking the others ended the wrong sessions")
	}
	if err := db.RevokeOtherSessions(ctx, id, uuid.New()); err != nil || !revoked(t, db, kept) {
		t.Fatalf("keeping an unknown session left one live: %v", err)
	}
}

func refreshStateNamesAccount(t *testing.T, db store.Store) {
	id, _ := newUser(t, db, "refresh-owner")
	digest, current := liveSession(t, db, id)
	state, err := db.RefreshTokenState(context.Background(), digest)
	if err != nil || state.UserID != id || state.FamilyID != current.FamilyID {
		t.Fatalf("state = %+v %v", state, err)
	}
}

func requestChange(t *testing.T, db store.Store, userID int64, address string) (string, bool) {
	t.Helper()
	digest := hash(t)
	mail, err := db.SaveEmailChange(context.Background(), store.EmailChange{UserID: userID, NewEmail: address,
		TokenHash: digest, ExpiresAt: time.Now().Add(time.Hour)}, testChangeLimits)
	if err != nil {
		t.Fatalf("request change of %d to %s: %v", userID, address, err)
	}
	if mail.Link && !mail.Notice {
		t.Fatalf("a link mailed without the notice: %+v", mail)
	}
	return digest, mail.Link
}

func confirm(db store.Store, userID int64, digest string) (store.ChangedEmail, error) {
	return db.ConfirmEmailChange(context.Background(), userID, digest)
}

func emailChangeMoves(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, old := provenUser(t, db, "change-moves")
	reset := hash(t)
	if err := db.IssueToken(ctx, store.PasswordReset, id, reset, time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	stale, _ := requestChange(t, db, id, uniqueEmail("change-stale"))
	time.Sleep(2 * time.Millisecond)
	target := uniqueEmail("change-target")
	digest, mailed := requestChange(t, db, id, target)
	if !mailed {
		t.Fatal("a free address was not mailed")
	}
	if _, err := confirm(db, id, stale); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an earlier request stayed live: %v", err)
	}
	changed, err := confirm(db, id, digest)
	if err != nil || changed.UserID != id || changed.OldEmail != old || changed.NewEmail != target {
		t.Fatalf("confirm = %+v %v", changed, err)
	}
	account, err := db.AccountByEmail(ctx, target)
	if err != nil || account.ID != id || !account.EmailVerified {
		t.Fatalf("account at the new address = %+v %v", account, err)
	}
	if _, err := db.AccountByEmail(ctx, old); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the old address still reaches an account: %v", err)
	}
	if err := db.LinkableAccount(ctx, id); err != nil {
		t.Fatalf("the moved account's address is not proven: %v", err)
	}
	if _, err := db.LookupToken(ctx, store.PasswordReset, reset); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a reset link sent to the old address survived: %v", err)
	}
	if _, err := confirm(db, id, digest); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a link spent twice: %v", err)
	}
}

func emailChangeTaken(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	id, _ := provenUser(t, db, "change-taken")
	_, holder := provenUser(t, db, "change-holder")
	mail, err := db.SaveEmailChange(ctx, store.EmailChange{UserID: id, NewEmail: strings.ToUpper(holder[:1]) + holder[1:],
		TokenHash: hash(t), ExpiresAt: time.Now().Add(time.Hour)}, testChangeLimits)
	if err != nil || mail.Link || !mail.Notice {
		t.Fatalf("an address a proven account holds: %+v %v; want only the notice", mail, err)
	}
	time.Sleep(2 * time.Millisecond)
	linker, _ := provenUser(t, db, "change-linker")
	linked := uniqueEmail("change-linked")
	link(t, db, linker, emailClaim(linked))
	if _, mailed := requestChange(t, db, id, linked); mailed {
		t.Fatal("an address linked to another account was mailed")
	}
	time.Sleep(2 * time.Millisecond)
	free := uniqueEmail("change-raced")
	digest, _ := requestChange(t, db, id, free)
	racer, _ := newUser(t, db, "change-racer")
	fx.SetEmail(t, racer, free)
	if _, err := db.MarkVerified(ctx, racer, true, "!marker"); err != nil {
		t.Fatal(err)
	}
	if _, err := confirm(db, id, digest); !errors.Is(err, store.ErrIdentityExists) {
		t.Fatalf("confirming onto a proven account's address: %v", err)
	}
	if account, _ := db.AccountByEmail(ctx, free); account.ID != racer {
		t.Fatalf("the address moved off its proven holder to %d", account.ID)
	}
}

func emailChangeReplaces(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	id, _ := provenUser(t, db, "change-replaces")
	squatter, address := newUser(t, db, "change-squatter")
	ownLinked := uniqueEmail("change-own-linked")
	link(t, db, id, emailClaim(ownLinked))
	digest, mailed := requestChange(t, db, id, address)
	if !mailed {
		t.Fatal("an address only an unproven account holds was not mailed")
	}
	changed, err := confirm(db, id, digest)
	if err != nil || len(changed.Replaced) != 1 || changed.Replaced[0] != squatter {
		t.Fatalf("confirm = %+v %v", changed, err)
	}
	if _, err := db.AccountByID(ctx, squatter); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the unproven account was kept: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	digest, _ = requestChange(t, db, id, ownLinked)
	if _, err := confirm(db, id, digest); err != nil {
		t.Fatalf("moving to an address the account already links: %v", err)
	}
	for _, identity := range identitiesOf(t, db, id) {
		if identity.Provider == store.EmailProvider && identity.Email == ownLinked {
			t.Fatal("the new address is still listed as a linked one")
		}
	}
}

func emailChangeBudgets(t *testing.T, db store.Store) {
	ctx := context.Background()
	id, _ := provenUser(t, db, "change-budget")
	limits := store.EmailChangeLimits{MinInterval: time.Hour, PerAccountDay: 5, PerProjectDay: 100}
	change := func(address string) error {
		_, err := db.SaveEmailChange(ctx, store.EmailChange{UserID: id, NewEmail: address, TokenHash: hash(t),
			ExpiresAt: time.Now().Add(time.Hour)}, limits)
		return err
	}
	if err := change(uniqueEmail("budget-a")); err != nil {
		t.Fatal(err)
	}
	if err := change(uniqueEmail("budget-b")); !errors.Is(err, store.ErrRateLimited) {
		t.Fatalf("a second request within the interval: %v", err)
	}
	limits = store.EmailChangeLimits{MinInterval: time.Millisecond, PerAccountDay: 2, PerProjectDay: 100}
	time.Sleep(2 * time.Millisecond)
	if err := change(uniqueEmail("budget-c")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := change(uniqueEmail("budget-d")); !errors.Is(err, store.ErrRateLimited) {
		t.Fatalf("a request past the day's budget: %v", err)
	}
	other, _ := provenUser(t, db, "change-project-cap")
	mail, err := db.SaveEmailChange(ctx, store.EmailChange{UserID: other, NewEmail: uniqueEmail("cap"), TokenHash: hash(t),
		ExpiresAt: time.Now().Add(time.Hour)}, store.EmailChangeLimits{MinInterval: time.Millisecond, PerAccountDay: 5, PerProjectDay: 1})
	if err != nil || mail.Link || mail.Notice {
		t.Fatalf("a request past the project's budget: %+v err=%v", mail, err)
	}
}

func emailChangeRefused(t *testing.T, fx Fixture) {
	db := fx.Store
	unproven, _ := newUser(t, db, "change-unproven")
	if _, err := db.SaveEmailChange(context.Background(), store.EmailChange{UserID: unproven, NewEmail: uniqueEmail("x"),
		TokenHash: hash(t), ExpiresAt: time.Now().Add(time.Hour)}, testChangeLimits); !errors.Is(err, store.ErrAddressUnproven) {
		t.Fatalf("unproven: %v", err)
	}
	disabled, email := provenUser(t, db, "change-disabled")
	digest, _ := requestChange(t, db, disabled, uniqueEmail("change-disabled-target"))
	fx.Disable(t, email)
	if _, err := db.SaveEmailChange(context.Background(), store.EmailChange{UserID: disabled, NewEmail: uniqueEmail("y"),
		TokenHash: hash(t), ExpiresAt: time.Now().Add(time.Hour)}, testChangeLimits); !errors.Is(err, store.ErrAccountDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := confirm(db, disabled, digest); !errors.Is(err, store.ErrAccountDisabled) {
		t.Fatalf("confirming for a disabled account: %v", err)
	}
	expired := hash(t)
	id, _ := provenUser(t, db, "change-expired")
	if _, err := db.SaveEmailChange(context.Background(), store.EmailChange{UserID: id, NewEmail: uniqueEmail("z"),
		TokenHash: expired, ExpiresAt: time.Now().Add(-time.Second)}, testChangeLimits); err != nil {
		t.Fatal(err)
	}
	if _, err := confirm(db, id, expired); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired link: %v", err)
	}
}

func deleteUser(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	id, email := provenUser(t, db, "delete-me")
	digest, _ := liveSession(t, db, id)
	link(t, db, id, store.IdentityClaim{Provider: "github", Subject: "delete-" + email, Email: email})
	if err := db.DeleteUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AccountByID(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted account still reads: %v", err)
	}
	if _, err := db.RefreshTokenState(ctx, digest); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a deleted account's session survived: %v", err)
	}
	if err := db.DeleteUser(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleting twice: %v", err)
	}
	if fx.Reference == nil {
		return
	}
	referenced, _ := newUser(t, db, "delete-referenced")
	fx.Reference(t, referenced)
	if err := db.DeleteUser(ctx, referenced); !errors.Is(err, store.ErrUserReferenced) {
		t.Fatalf("deleting an account an app table references: %v", err)
	}
}

func pendingChangeEnds(t *testing.T, db store.Store) {
	ctx := context.Background()
	for name, end := range map[string]func(int64) error{
		"password": func(id int64) error { return db.ChangePassword(ctx, id, "other-hash") },
		"sessions": func(id int64) error { return db.RevokeUserRefreshTokens(ctx, id) },
		"roles": func(id int64) error {
			_, err := db.ApplyRoleChange(ctx, store.RoleChange{UserID: id, Role: "editor", Allowed: []string{"editor"}, Actor: "test"})
			return err
		},
	} {
		id, _ := provenUser(t, db, "pending-"+name)
		digest, _ := requestChange(t, db, id, uniqueEmail("pending-"+name))
		if err := end(id); err != nil {
			t.Fatal(err)
		}
		if _, err := confirm(db, id, digest); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a change survived ending the %s: %v", name, err)
		}
	}
}

func confirmNeedsTheRequester(t *testing.T, db store.Store) {
	id, _ := provenUser(t, db, "confirm-owner")
	other, _ := provenUser(t, db, "confirm-other")
	digest, _ := requestChange(t, db, id, uniqueEmail("confirm-target"))
	if _, err := confirm(db, other, digest); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another account confirmed the change: %v", err)
	}
	if _, err := confirm(db, id, digest); err != nil {
		t.Fatalf("the requester could not confirm after a refused try: %v", err)
	}
}

func referencedSquatter(t *testing.T, fx Fixture) {
	if fx.Reference == nil {
		return
	}
	db := fx.Store
	id, _ := provenUser(t, db, "change-referenced")
	squatter, address := newUser(t, db, "change-referenced-squatter")
	fx.Reference(t, squatter)
	digest, _ := requestChange(t, db, id, address)
	if _, err := confirm(db, id, digest); !errors.Is(err, store.ErrUserReferenced) {
		t.Fatalf("replacing a referenced account: %v", err)
	}
}
