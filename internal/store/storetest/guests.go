package storetest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
)

var roomyGuestLimits = store.GuestLimits{PerClientHour: 1000, PerProjectDay: 1_000_000}

func runGuests(t *testing.T, fx Fixture) {
	t.Run("a guest has no address, no password and the guest role", func(t *testing.T) { guestShape(t, fx.Store) })
	t.Run("guests are capped per client and per project", func(t *testing.T) { guestBudgets(t, fx) })
	t.Run("a guest refreshes, is listed and reads its profile", func(t *testing.T) { guestReads(t, fx.Store) })
	t.Run("linking an address makes a guest a full account with the same id", func(t *testing.T) { guestLinksAddress(t, fx.Store) })
	t.Run("linking a provider gives a guest the provider's address", func(t *testing.T) { guestLinksProvider(t, fx.Store) })
	t.Run("a guest cannot take an address a proven account holds", func(t *testing.T) { guestAddressTaken(t, fx.Store) })
	t.Run("a guest cannot take an address linked to another account", func(t *testing.T) { guestLinkedAddressTaken(t, fx.Store) })
	t.Run("an address change makes a guest a full account", func(t *testing.T) { guestChangesAddress(t, fx.Store) })
	t.Run("guest address changes are capped per client and per project", func(t *testing.T) { guestChangeBudgets(t, fx.Store) })
	t.Run("a role the project gave a guest is kept on upgrade", func(t *testing.T) { guestKeepsGivenRole(t, fx.Store) })
	t.Run("only inactive, unreferenced guests are deleted", func(t *testing.T) { guestCleanup(t, fx) })
	t.Run("the cleanup is claimed once per interval", func(t *testing.T) { guestCleanupClaim(t, fx.Store) })
}

func newClient() string {
	return fmt.Sprintf("client-%d", sequence.Add(1))
}

func newGuest(t *testing.T, db store.Store) store.Account {
	t.Helper()
	guest, err := db.CreateGuest(context.Background(), newClient(), roomyGuestLimits)
	if err != nil {
		t.Fatalf("create guest: %v", err)
	}
	return guest
}

func guestShape(t *testing.T, db store.Store) {
	guest := newGuest(t, db)
	if guest.ID <= 0 || guest.Email != "" || guest.PasswordHash != "" || guest.Role != store.GuestRole ||
		guest.AllowedRoles != nil || !guest.Enabled || guest.EmailVerified || !guest.IsGuest {
		t.Fatalf("guest = %+v", guest)
	}
	read, err := db.AccountByID(context.Background(), guest.ID)
	if err != nil || read.Email != "" || read.Role != store.GuestRole || !read.IsGuest || read.EmailVerified {
		t.Fatalf("read back = %+v %v", read, err)
	}
	if other := newGuest(t, db); other.ID == guest.ID {
		t.Fatal("two guests share an id")
	}
	if _, email := newUser(t, db, "not-guest"); email != "" {
		if account, _ := db.AccountByEmail(context.Background(), email); account.IsGuest {
			t.Fatal("a registered account reads as a guest")
		}
	}
}

func guestBudgets(t *testing.T, fx Fixture) {
	ctx := context.Background()
	limits := store.GuestLimits{PerClientHour: 2, PerProjectDay: 1_000_000}
	client := newClient()
	for i := 0; i < 2; i++ {
		if _, err := fx.Store.CreateGuest(ctx, client, limits); err != nil {
			t.Fatalf("sign-up %d: %v", i, err)
		}
	}
	before := fx.Count(t, "users")
	if _, err := fx.Store.CreateGuest(ctx, client, limits); !errors.Is(err, store.ErrRateLimited) {
		t.Fatalf("third sign-up from one client: %v, want ErrRateLimited", err)
	}
	if fx.Count(t, "users") != before {
		t.Fatal("a refused sign-up made an account")
	}
	if _, err := fx.Store.CreateGuest(ctx, newClient(), limits); err != nil {
		t.Fatalf("another client: %v", err)
	}
	limits.PerProjectDay = fx.Count(t, "guest_sign_ups") + 1
	if _, err := fx.Store.CreateGuest(ctx, newClient(), limits); err != nil {
		t.Fatalf("the last sign-up under the project cap: %v", err)
	}
	if _, err := fx.Store.CreateGuest(ctx, newClient(), limits); !errors.Is(err, store.ErrRateLimited) {
		t.Fatalf("past the project cap: %v, want ErrRateLimited", err)
	}
}

func guestReads(t *testing.T, db store.Store) {
	ctx := context.Background()
	guest := newGuest(t, db)
	first := hash(t)
	if err := db.InsertRefreshToken(ctx, first, guest.ID, session(time.Hour)); err != nil {
		t.Fatal(err)
	}
	account, _, err := db.RotateRefreshToken(ctx, first, hash(t), acceptAll)
	if err != nil || account.ID != guest.ID || !account.IsGuest || account.Email != "" || account.Role != store.GuestRole {
		t.Fatalf("rotate a guest's token: %+v %v", account, err)
	}
	profile, err := db.Profile(ctx, guest.ID)
	if err != nil || !profile.IsGuest || profile.Email != "" {
		t.Fatalf("profile = %+v %v", profile, err)
	}
	for offset := 0; ; offset += 500 {
		users, err := db.ListUsers(ctx, 500, offset)
		if err != nil {
			t.Fatal(err)
		}
		for _, user := range users {
			if user.ID == guest.ID {
				if !user.IsGuest || user.Email != "" || user.Role != store.GuestRole {
					t.Fatalf("listed as %+v", user)
				}
				return
			}
		}
		if len(users) < 500 {
			t.Fatal("the guest is not listed")
		}
	}
}

func assertUpgraded(t *testing.T, db store.Store, id int64, address string) {
	t.Helper()
	account, err := db.AccountByID(context.Background(), id)
	if err != nil || account.IsGuest || account.Email != address || !account.EmailVerified || account.Role != "user" {
		t.Fatalf("after the upgrade = %+v %v", account, err)
	}
	if err := db.LinkableAccount(context.Background(), id); err != nil {
		t.Fatalf("an upgraded account cannot link: %v", err)
	}
}

func guestLinksAddress(t *testing.T, db store.Store) {
	ctx := context.Background()
	guest := newGuest(t, db)
	if err := db.LinkableAccount(ctx, guest.ID); err != nil {
		t.Fatalf("a guest may not link: %v", err)
	}
	address := uniqueEmail("guest-address")
	result, err := db.LinkIdentity(ctx, guest.ID, emailClaim(address))
	if err != nil || !result.Upgraded || len(result.Deleted) != 0 {
		t.Fatalf("link = %+v %v", result, err)
	}
	assertUpgraded(t, db, guest.ID, address)
	if found, err := db.AccountByAddress(ctx, address); err != nil || found.ID != guest.ID {
		t.Fatalf("the address reaches %+v %v", found, err)
	}
	if again, err := db.LinkIdentity(ctx, guest.ID, claimFor("google", address)); err != nil || again.Upgraded {
		t.Fatalf("a second link upgrades again: %+v %v", again, err)
	}
}

func guestLinksProvider(t *testing.T, db store.Store) {
	ctx := context.Background()
	guest := newGuest(t, db)
	squatter, address := newUser(t, db, "guest-provider-squatted")
	result, err := db.LinkIdentity(ctx, guest.ID, claimFor("github", address))
	if err != nil || !result.Upgraded || len(result.Deleted) != 1 || result.Deleted[0] != squatter {
		t.Fatalf("link = %+v %v", result, err)
	}
	assertUpgraded(t, db, guest.ID, address)
	if _, err := db.AccountByID(ctx, squatter); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the unproven account on the address survived: %v", err)
	}
	if identities := identitiesOf(t, db, guest.ID); len(identities) != 1 || identities[0].Provider != "github" {
		t.Fatalf("identities = %+v", identities)
	}
}

func guestAddressTaken(t *testing.T, db store.Store) {
	ctx := context.Background()
	guest := newGuest(t, db)
	_, proven := provenUser(t, db, "guest-taken")
	for _, claim := range []store.IdentityClaim{emailClaim(proven), claimFor("google", proven)} {
		if _, err := db.LinkIdentity(ctx, guest.ID, claim); !errors.Is(err, store.ErrIdentityExists) {
			t.Fatalf("link %s: %v, want ErrIdentityExists", claim.Provider, err)
		}
	}
	account, err := db.AccountByID(ctx, guest.ID)
	if err != nil || !account.IsGuest || account.Email != "" {
		t.Fatalf("the refused guest changed: %+v %v", account, err)
	}
	if identities := identitiesOf(t, db, guest.ID); len(identities) != 0 {
		t.Fatalf("identities = %+v", identities)
	}
}

func guestChangesAddress(t *testing.T, db store.Store) {
	ctx := context.Background()
	guest := newGuest(t, db)
	address := uniqueEmail("guest-change")
	tokenHash := hash(t)
	mail, err := db.SaveEmailChange(ctx, store.EmailChange{UserID: guest.ID, NewEmail: address, TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(time.Hour)}, testChangeLimits)
	if err != nil || !mail.Link {
		t.Fatalf("save = %+v %v", mail, err)
	}
	changed, err := db.ConfirmEmailChange(ctx, guest.ID, tokenHash)
	if err != nil || changed.OldEmail != "" || changed.NewEmail != address {
		t.Fatalf("confirm = %+v %v", changed, err)
	}
	assertUpgraded(t, db, guest.ID, address)
}

func guestKeepsGivenRole(t *testing.T, db store.Store) {
	ctx := context.Background()
	guest := newGuest(t, db)
	if _, err := db.ApplyRoleChange(ctx, store.RoleChange{UserID: guest.ID, Role: "trial", Allowed: []string{"trial"},
		Actor: "studio:1"}); err != nil {
		t.Fatal(err)
	}
	address := uniqueEmail("guest-trial")
	if _, err := db.LinkIdentity(ctx, guest.ID, emailClaim(address)); err != nil {
		t.Fatal(err)
	}
	account, err := db.AccountByID(ctx, guest.ID)
	if err != nil || account.IsGuest || account.Role != "trial" {
		t.Fatalf("after the upgrade = %+v %v", account, err)
	}
}

func guestCleanup(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	month := 30 * 24 * time.Hour
	idle := newGuest(t, db)
	fx.Backdate(t, idle.ID, 40*24*time.Hour)
	refreshed := newGuest(t, db)
	fx.Backdate(t, refreshed.ID, 40*24*time.Hour)
	if err := db.InsertRefreshToken(ctx, hash(t), refreshed.ID, session(time.Hour)); err != nil {
		t.Fatal(err)
	}
	fresh := newGuest(t, db)
	referenced := newGuest(t, db)
	fx.Backdate(t, referenced.ID, 40*24*time.Hour)
	fx.Reference(t, referenced.ID)
	member, _ := newUser(t, db, "guest-cleanup-member")
	fx.Backdate(t, member, 40*24*time.Hour)

	deleted, err := db.DeleteInactiveGuests(ctx, time.Now().Add(-month), 100)
	if err != nil || deleted < 1 {
		t.Fatalf("cleanup deleted %d: %v", deleted, err)
	}
	if _, err := db.AccountByID(ctx, idle.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the idle guest survived: %v", err)
	}
	for name, id := range map[string]int64{"refreshed": refreshed.ID, "fresh": fresh.ID, "referenced": referenced.ID, "member": member} {
		if _, err := db.AccountByID(ctx, id); err != nil {
			t.Fatalf("the %s account was deleted: %v", name, err)
		}
	}
	if again, err := db.DeleteInactiveGuests(ctx, time.Now().Add(-month), 100); err != nil || again != 0 {
		t.Fatalf("a second pass deleted %d: %v", again, err)
	}
}

func guestCleanupClaim(t *testing.T, db store.Store) {
	ctx := context.Background()
	first, err := db.ClaimGuestCleanup(ctx, time.Hour)
	if err != nil || !first {
		t.Fatalf("first claim = %v %v", first, err)
	}
	if again, err := db.ClaimGuestCleanup(ctx, time.Hour); err != nil || again {
		t.Fatalf("second claim = %v %v", again, err)
	}
	if soon, err := db.ClaimGuestCleanup(ctx, time.Nanosecond); err != nil || !soon {
		t.Fatalf("claim after the interval = %v %v", soon, err)
	}
}

func guestLinkedAddressTaken(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := provenUser(t, db, "guest-linked-owner")
	second := uniqueEmail("guest-linked-second")
	if _, err := db.LinkIdentity(ctx, owner, emailClaim(second)); err != nil {
		t.Fatalf("link the second address: %v", err)
	}
	guest := newGuest(t, db)
	if _, err := db.LinkIdentity(ctx, guest.ID, claimFor("google", second)); !errors.Is(err, store.ErrIdentityExists) {
		t.Fatalf("a guest took a linked address by a provider: %v", err)
	}
	if account, err := db.AccountByID(ctx, guest.ID); err != nil || !account.IsGuest || account.Email != "" {
		t.Fatalf("the refused guest changed: %+v %v", account, err)
	}
	if found, err := db.AccountByAddress(ctx, second); err != nil || found.ID != owner {
		t.Fatalf("the linked address now reaches %+v %v", found, err)
	}
}

func guestChangeBudgets(t *testing.T, db store.Store) {
	ctx := context.Background()
	limits := store.EmailChangeLimits{PerAccountDay: 100, PerProjectDay: 1_000_000, PerGuestClientDay: 2, GuestPerProjectDay: 1_000_000}
	save := func(account int64, client string, limits store.EmailChangeLimits) error {
		_, err := db.SaveEmailChange(ctx, store.EmailChange{UserID: account, NewEmail: uniqueEmail("guest-budget"),
			TokenHash: hash(t), ExpiresAt: time.Now().Add(time.Hour), GuestClient: client}, limits)
		return err
	}
	client := newClient()
	for i := 0; i < 2; i++ {
		if err := save(newGuest(t, db).ID, client, limits); err != nil {
			t.Fatalf("change %d: %v", i, err)
		}
	}
	if err := save(newGuest(t, db).ID, client, limits); !errors.Is(err, store.ErrRateLimited) {
		t.Fatalf("third change from one client: %v, want ErrRateLimited", err)
	}
	if err := save(newGuest(t, db).ID, newClient(), limits); err != nil {
		t.Fatalf("another client: %v", err)
	}
	// Guests share a part of the project's budget; past it they are refused.
	tight := limits
	tight.GuestPerProjectDay = 0
	if err := save(newGuest(t, db).ID, newClient(), tight); !errors.Is(err, store.ErrRateLimited) {
		t.Fatalf("past the guests' project share: %v, want ErrRateLimited", err)
	}
	user, _ := provenUser(t, db, "guest-budget-full")
	if err := save(user, "", tight); err != nil {
		t.Fatalf("a full account is held to the guests' share: %v", err)
	}
}
