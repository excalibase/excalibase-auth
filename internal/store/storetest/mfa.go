package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
	"github.com/google/uuid"
)

var roomyMFALimits = store.MFALimits{MaxFactors: 10, MaxFailures: 5, FailureWindow: 5 * time.Minute,
	MaxDailyFailures: 1000, StaleUnverified: 24 * time.Hour}

func runMFA(t *testing.T, fx Fixture) {
	t.Run("a factor is stored unverified and listed only for its account", func(t *testing.T) { factorRoundTrip(t, fx.Store) })
	t.Run("factor names are unique per account and factors are capped", func(t *testing.T) { factorBounds(t, fx.Store) })
	t.Run("a stale unverified factor is dropped on the next enrolment", func(t *testing.T) { factorStaleDropped(t, fx.Store) })
	t.Run("a matching code verifies the factor once and spends the challenge", func(t *testing.T) { factorVerifies(t, fx) })
	t.Run("a challenge must be live and the factor's", func(t *testing.T) { factorChallengeRules(t, fx.Store) })
	t.Run("wrong codes are budgeted per factor across callers", func(t *testing.T) { factorFailureBudget(t, fx.Store) })
	t.Run("of concurrent checks of one step only one is accepted", func(t *testing.T) { factorStepRace(t, fx.Store) })
	t.Run("removing the last verified factor removes the recovery codes", func(t *testing.T) { factorDelete(t, fx) })
	t.Run("a recovery code is spent once and budgeted per account", func(t *testing.T) { recoveryCodes(t, fx.Store) })
	t.Run("elevation keeps the session and raises its level", func(t *testing.T) { elevateSession(t, fx.Store) })
	t.Run("a reset removes factors and codes and ends sessions", func(t *testing.T) { resetMFA(t, fx) })
	t.Run("a factor planted before MFA was on cannot lift an aal1 session", func(t *testing.T) { plantedFactor(t, fx.Store) })
	t.Run("a stale unverified factor cannot be verified", func(t *testing.T) { staleFactorRefused(t, fx.Store) })
	t.Run("wrong codes are capped per account per day across factors", func(t *testing.T) { dailyFailureCap(t, fx.Store) })
}

func plantedFactor(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-planted")
	planted := enroll(t, db, owner, "Planted")
	other := enroll(t, db, owner, "Other")
	verifyNew(t, db, owner, "Phone", 5)
	for _, factor := range []store.Factor{planted, other} {
		if err := db.CreateChallenge(ctx, owner, factor.ID, uuid.NewString(), "ip", time.Now().Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an unverified factor outlived the first verified one: %v", err)
		}
	}
	late := enroll(t, db, owner, "Late")
	attempt := store.FactorAttempt{UserID: owner, FactorID: late.ID, ChallengeID: challengeFor(t, db, owner, late.ID)}
	if _, err := db.VerifyFactor(ctx, attempt, roomyMFALimits, matchStep(6)); !errors.Is(err, store.ErrInsufficientAAL) {
		t.Fatalf("aal1 verified a second factor: %v", err)
	}
	attempt.CallerAAL2 = true
	if verified, err := db.VerifyFactor(ctx, attempt, roomyMFALimits, matchStep(6)); err != nil || verified.FirstForAccount {
		t.Fatalf("aal2 verify of a second factor: %+v %v", verified, err)
	}
}

func staleFactorRefused(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-stale-verify")
	factor := enroll(t, db, owner, "Phone")
	challenge := challengeFor(t, db, owner, factor.ID)
	time.Sleep(20 * time.Millisecond)
	short := roomyMFALimits
	short.StaleUnverified = 10 * time.Millisecond
	if _, err := db.VerifyFactor(ctx, store.FactorAttempt{UserID: owner, FactorID: factor.ID, ChallengeID: challenge},
		short, matchStep(1)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a stale factor was verified: %v", err)
	}
}

func dailyFailureCap(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-daily")
	limits := roomyMFALimits
	limits.MaxDailyFailures = 3
	phone := verifyNew(t, db, owner, "Phone", 1).Factor
	tablet := verifyNew(t, db, owner, "Tablet", 1).Factor
	try := func(factorID string, check store.FactorCheck) error {
		_, err := db.VerifyFactor(ctx, store.FactorAttempt{UserID: owner, FactorID: factorID, CallerAAL2: true,
			ChallengeID: challengeFor(t, db, owner, factorID)}, limits, check)
		return err
	}
	for _, factorID := range []string{phone.ID, phone.ID, tablet.ID} {
		if err := try(factorID, wrongCode); !errors.Is(err, store.ErrInvalidCode) {
			t.Fatalf("wrong code: %v", err)
		}
	}
	if err := try(tablet.ID, matchStep(9)); !errors.Is(err, store.ErrTooManyAttempts) {
		t.Fatalf("past the day's cap: %v", err)
	}
	if err := db.RedeemRecoveryCode(ctx, owner, recoveryHash(1), limits); !errors.Is(err, store.ErrTooManyAttempts) {
		t.Fatalf("recovery past the day's cap: %v", err)
	}
}

func enroll(t *testing.T, db store.Store, userID int64, name string) store.Factor {
	t.Helper()
	factor, err := db.CreateFactor(context.Background(), store.NewFactor{ID: uuid.NewString(), UserID: userID,
		FriendlyName: name, SecretSealed: []byte("sealed-" + name)}, roomyMFALimits)
	if err != nil {
		t.Fatalf("enroll %s: %v", name, err)
	}
	return factor
}

func challengeFor(t *testing.T, db store.Store, userID int64, factorID string) string {
	t.Helper()
	id := uuid.NewString()
	if err := db.CreateChallenge(context.Background(), userID, factorID, id, "203.0.113.9", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("challenge: %v", err)
	}
	return id
}

func matchStep(step int64) store.FactorCheck {
	return func(store.FactorSecret) (int64, bool, error) { return step, true, nil }
}

func wrongCode(store.FactorSecret) (int64, bool, error) { return 0, false, nil }

// verifyNew enrols, challenges and verifies a factor with the given step.
func verifyNew(t *testing.T, db store.Store, userID int64, name string, step int64) store.VerifiedFactor {
	t.Helper()
	factor := enroll(t, db, userID, name)
	verified, err := db.VerifyFactor(context.Background(), store.FactorAttempt{UserID: userID, FactorID: factor.ID,
		ChallengeID: challengeFor(t, db, userID, factor.ID), CallerAAL2: true}, roomyMFALimits, matchStep(step))
	if err != nil {
		t.Fatalf("verify %s: %v", name, err)
	}
	return verified
}

func factorRoundTrip(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-owner")
	other, _ := newUser(t, db, "mfa-other")
	factor := enroll(t, db, owner, "Phone")
	if factor.ID == "" || factor.UserID != owner || factor.Status != store.FactorUnverified ||
		factor.FactorType != store.FactorTOTP || factor.FriendlyName != "Phone" || factor.CreatedAt.IsZero() {
		t.Fatalf("factor = %+v", factor)
	}
	listing, err := db.ListFactors(ctx, owner)
	if err != nil || len(listing.Factors) != 1 || listing.Factors[0].ID != factor.ID || listing.RecoveryCodesRemaining != 0 {
		t.Fatalf("listing = %+v %v", listing, err)
	}
	if theirs, _ := db.ListFactors(ctx, other); len(theirs.Factors) != 0 {
		t.Fatalf("another account lists %+v", theirs)
	}
	if verified, err := db.HasVerifiedFactor(ctx, owner); err != nil || verified {
		t.Fatalf("unverified factor counts: %v %v", verified, err)
	}
}

func factorBounds(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-bounds")
	enroll(t, db, owner, "Phone")
	if _, err := db.CreateFactor(ctx, store.NewFactor{ID: uuid.NewString(), UserID: owner, FriendlyName: "Phone",
		SecretSealed: []byte("x")}, roomyMFALimits); !errors.Is(err, store.ErrFactorNameTaken) {
		t.Fatalf("same name: %v", err)
	}
	other, _ := newUser(t, db, "mfa-bounds-other")
	enroll(t, db, other, "Phone")
	capped := roomyMFALimits
	capped.MaxFactors = 2
	enroll(t, db, owner, "Tablet")
	if _, err := db.CreateFactor(ctx, store.NewFactor{ID: uuid.NewString(), UserID: owner, FriendlyName: "Laptop",
		SecretSealed: []byte("x")}, capped); !errors.Is(err, store.ErrTooManyFactors) {
		t.Fatalf("third factor past a cap of two: %v", err)
	}
}

func factorStaleDropped(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-stale")
	kept := verifyNew(t, db, owner, "Kept", 100)
	stale := enroll(t, db, owner, "Old")
	time.Sleep(20 * time.Millisecond)
	short := roomyMFALimits
	short.StaleUnverified = 10 * time.Millisecond
	if _, err := db.CreateFactor(ctx, store.NewFactor{ID: uuid.NewString(), UserID: owner, FriendlyName: "New",
		SecretSealed: []byte("x")}, short); err != nil {
		t.Fatal(err)
	}
	listing, _ := db.ListFactors(ctx, owner)
	var ids []string
	for _, factor := range listing.Factors {
		ids = append(ids, factor.ID)
	}
	if slices.Contains(ids, stale.ID) || !slices.Contains(ids, kept.Factor.ID) || len(ids) != 2 {
		t.Fatalf("after enrolment ids = %v (stale %s, kept %s)", ids, stale.ID, kept.Factor.ID)
	}
}

func factorVerifies(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	owner, _ := newUser(t, db, "mfa-verify")
	factor := enroll(t, db, owner, "Phone")
	challenge := challengeFor(t, db, owner, factor.ID)
	attempt := store.FactorAttempt{UserID: owner, FactorID: factor.ID, ChallengeID: challenge}
	var seen store.FactorSecret
	verified, err := db.VerifyFactor(ctx, attempt, roomyMFALimits, func(secret store.FactorSecret) (int64, bool, error) {
		seen = secret
		return 500, true, nil
	})
	if err != nil || !verified.FirstForAccount || verified.Factor.Status != store.FactorVerified {
		t.Fatalf("verify = %+v %v", verified, err)
	}
	if string(seen.SecretSealed) != "sealed-Phone" || seen.LastUsedStep != 0 || seen.UserID != owner || seen.ID != factor.ID {
		t.Fatalf("check saw %+v", seen)
	}
	if _, err := db.VerifyFactor(ctx, attempt, roomyMFALimits, matchStep(501)); !errors.Is(err, store.ErrInvalidChallenge) {
		t.Fatalf("spent challenge reused: %v", err)
	}
	again := store.FactorAttempt{UserID: owner, FactorID: factor.ID, ChallengeID: challengeFor(t, db, owner, factor.ID)}
	if _, err := db.VerifyFactor(ctx, again, roomyMFALimits, func(secret store.FactorSecret) (int64, bool, error) {
		seen = secret
		return 501, true, nil
	}); err != nil || seen.LastUsedStep != 500 {
		t.Fatalf("second verify saw last step %d: %v", seen.LastUsedStep, err)
	}
	if ok, _ := db.HasVerifiedFactor(ctx, owner); !ok {
		t.Fatal("a verified factor does not count")
	}
	if second := verifyNew(t, db, owner, "Tablet", 9); second.FirstForAccount {
		t.Fatal("a second factor reads as the account's first")
	}
	other, _ := newUser(t, db, "mfa-verify-other")
	if _, err := db.VerifyFactor(ctx, store.FactorAttempt{UserID: other, FactorID: factor.ID,
		ChallengeID: challenge}, roomyMFALimits, matchStep(900)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another account's factor: %v", err)
	}
}

func factorChallengeRules(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-challenge")
	other, _ := newUser(t, db, "mfa-challenge-other")
	phone := enroll(t, db, owner, "Phone")
	tablet := enroll(t, db, owner, "Tablet")
	if err := db.CreateChallenge(ctx, other, phone.ID, uuid.NewString(), "ip", time.Now().Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("challenge for another account's factor: %v", err)
	}
	expired := uuid.NewString()
	if err := db.CreateChallenge(ctx, owner, phone.ID, expired, "ip", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{"expired": expired, "unknown": uuid.NewString(),
		"another factor's": challengeFor(t, db, owner, tablet.ID), "malformed": "not-a-uuid"}
	for name, challenge := range cases {
		_, err := db.VerifyFactor(ctx, store.FactorAttempt{UserID: owner, FactorID: phone.ID, ChallengeID: challenge},
			roomyMFALimits, matchStep(1))
		if !errors.Is(err, store.ErrInvalidChallenge) {
			t.Errorf("%s challenge: %v", name, err)
		}
	}
}

func factorFailureBudget(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-budget")
	// A verified factor first, so verifying the others ends none of them.
	verifyNew(t, db, owner, "Anchor", 1)
	phone := enroll(t, db, owner, "Phone")
	tablet := enroll(t, db, owner, "Tablet")
	limits := roomyMFALimits
	limits.MaxFailures = 2
	limits.FailureWindow = time.Second
	attempt := func(factorID string, check store.FactorCheck) error {
		_, err := db.VerifyFactor(ctx, store.FactorAttempt{UserID: owner, FactorID: factorID, CallerAAL2: true,
			ChallengeID: challengeFor(t, db, owner, factorID)}, limits, check)
		return err
	}
	for range 2 {
		if err := attempt(phone.ID, wrongCode); !errors.Is(err, store.ErrInvalidCode) {
			t.Fatalf("wrong code: %v", err)
		}
	}
	checked := false
	if err := attempt(phone.ID, func(store.FactorSecret) (int64, bool, error) { checked = true; return 1, true, nil }); !errors.Is(err, store.ErrTooManyAttempts) || checked {
		t.Fatalf("past the budget: %v, checked=%v", err, checked)
	}
	unreadable := errors.New("unreadable secret")
	if err := attempt(tablet.ID, func(store.FactorSecret) (int64, bool, error) { return 0, false, unreadable }); !errors.Is(err, unreadable) {
		t.Fatalf("an unreadable secret: %v", err)
	}
	if err := attempt(tablet.ID, matchStep(1)); err != nil {
		t.Fatalf("another factor's budget is its own, and an unreadable secret counted nothing: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := attempt(phone.ID, matchStep(2)); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

func factorStepRace(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-race")
	factor := enroll(t, db, owner, "Phone")
	const racers = 6
	challenges := make([]string, racers)
	for index := range challenges {
		challenges[index] = challengeFor(t, db, owner, factor.ID)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for _, challenge := range challenges {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := db.VerifyFactor(ctx, store.FactorAttempt{UserID: owner, FactorID: factor.ID, ChallengeID: challenge},
				roomyMFALimits, func(secret store.FactorSecret) (int64, bool, error) { return 77, secret.LastUsedStep < 77, nil })
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrInvalidCode):
			default:
				t.Errorf("racer: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("one step was accepted %d times", wins.Load())
	}
}

func factorDelete(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	owner, _ := newUser(t, db, "mfa-delete")
	other, _ := newUser(t, db, "mfa-delete-other")
	phone := verifyNew(t, db, owner, "Phone", 1).Factor
	tablet := verifyNew(t, db, owner, "Tablet", 1).Factor
	if err := db.ReplaceRecoveryCodes(ctx, owner, []string{recoveryHash(1), recoveryHash(2)}); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteFactor(ctx, other, phone.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another account deleted the factor: %v", err)
	}
	if err := db.DeleteFactor(ctx, owner, phone.ID); err != nil {
		t.Fatal(err)
	}
	if listing, _ := db.ListFactors(ctx, owner); listing.RecoveryCodesRemaining != 2 {
		t.Fatalf("codes went while a verified factor is left: %+v", listing)
	}
	if err := db.DeleteFactor(ctx, owner, tablet.ID); err != nil {
		t.Fatal(err)
	}
	if listing, _ := db.ListFactors(ctx, owner); listing.RecoveryCodesRemaining != 0 || len(listing.Factors) != 0 {
		t.Fatalf("after the last factor: %+v", listing)
	}
	if err := db.DeleteFactor(ctx, owner, tablet.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}
	if err := db.DeleteFactor(ctx, owner, "not-a-uuid"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
	withFactor, email := newUser(t, db, "mfa-delete-user")
	verifyNew(t, db, withFactor, "Phone", 1)
	if err := db.DeleteUser(ctx, withFactor); err != nil {
		t.Fatalf("an account with a factor cannot be deleted: %v", err)
	}
	if _, err := db.AccountByEmail(ctx, email); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("account left")
	}
}

func recoveryHash(index int) string {
	return fmt.Sprintf("%064d", int(sequence.Add(1))*100+index)
}

func recoveryCodes(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-recovery")
	first, second := recoveryHash(1), recoveryHash(2)
	if err := db.ReplaceRecoveryCodes(ctx, owner, []string{first, second}); err != nil {
		t.Fatal(err)
	}
	if err := db.RedeemRecoveryCode(ctx, owner, first, roomyMFALimits); !errors.Is(err, store.ErrInvalidCode) {
		t.Fatalf("a code spent with no verified factor: %v", err)
	}
	verifyNew(t, db, owner, "Phone", 1)
	if err := db.RedeemRecoveryCode(ctx, owner, first, roomyMFALimits); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if err := db.RedeemRecoveryCode(ctx, owner, first, roomyMFALimits); !errors.Is(err, store.ErrInvalidCode) {
		t.Fatalf("spent twice: %v", err)
	}
	if listing, _ := db.ListFactors(ctx, owner); listing.RecoveryCodesRemaining != 1 {
		t.Fatalf("remaining = %d", listing.RecoveryCodesRemaining)
	}
	other, _ := newUser(t, db, "mfa-recovery-other")
	verifyNew(t, db, other, "Phone", 1)
	if err := db.RedeemRecoveryCode(ctx, other, second, roomyMFALimits); !errors.Is(err, store.ErrInvalidCode) {
		t.Fatalf("another account spent the code: %v", err)
	}
	fresh := recoveryHash(3)
	if err := db.ReplaceRecoveryCodes(ctx, owner, []string{fresh}); err != nil {
		t.Fatal(err)
	}
	if err := db.RedeemRecoveryCode(ctx, owner, second, roomyMFALimits); !errors.Is(err, store.ErrInvalidCode) {
		t.Fatalf("a replaced code still works: %v", err)
	}
	limits := roomyMFALimits
	limits.MaxFailures = 3
	if err := db.RedeemRecoveryCode(ctx, owner, fresh, limits); !errors.Is(err, store.ErrTooManyAttempts) {
		t.Fatalf("past the account's budget: %v", err)
	}
	if listing, _ := db.ListFactors(ctx, owner); listing.RecoveryCodesRemaining != 1 {
		t.Fatal("a refused attempt spent the code")
	}
}

func elevateSession(t *testing.T, db store.Store) {
	ctx := context.Background()
	owner, _ := newUser(t, db, "mfa-elevate")
	other, _ := newUser(t, db, "mfa-elevate-other")
	login := session(time.Hour)
	login.AuthTime = time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	login.AMR = []string{"password"}
	presented := hash(t)
	if err := db.InsertRefreshToken(ctx, presented, owner, login); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ElevateRefreshToken(ctx, other, presented, hash(t), "totp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another account elevated the session: %v", err)
	}
	if state, _ := db.RefreshTokenState(ctx, presented); state.Revoked {
		t.Fatal("a refused elevation spent the token")
	}
	successor := hash(t)
	account, elevated, err := db.ElevateRefreshToken(ctx, owner, presented, successor, "totp")
	if err != nil || account.ID != owner {
		t.Fatalf("elevate: %+v %v", account, err)
	}
	if elevated.FamilyID != login.FamilyID || elevated.AAL != store.AAL2 || !slices.Equal(elevated.AMR, []string{"password", "totp"}) ||
		!elevated.AuthTime.Equal(login.AuthTime) {
		t.Fatalf("elevated session = %+v", elevated)
	}
	if _, _, err := db.ElevateRefreshToken(ctx, owner, presented, hash(t), "totp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("spent token elevated again: %v", err)
	}
	again := hash(t)
	if _, twice, err := db.ElevateRefreshToken(ctx, owner, successor, again, "totp"); err != nil || !slices.Equal(twice.AMR, []string{"password", "totp"}) {
		t.Fatalf("a second step-up grew the methods: %+v %v", twice, err)
	}
	successor = again
	_, rotated, err := db.RotateRefreshToken(ctx, successor, hash(t), acceptAll)
	if err != nil || rotated.AAL != store.AAL2 || !slices.Equal(rotated.AMR, []string{"password", "totp"}) {
		t.Fatalf("refresh lost the level: %+v %v", rotated, err)
	}
	plain := hash(t)
	if err := db.InsertRefreshToken(ctx, plain, owner, session(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, fresh, err := db.RotateRefreshToken(ctx, plain, hash(t), acceptAll); err != nil || store.LevelOf(fresh.AAL) != store.AAL1 || fresh.AMR != nil {
		t.Fatalf("a plain session = %+v %v", fresh, err)
	}
}

func resetMFA(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store
	owner, _ := newUser(t, db, "mfa-reset")
	verifyNew(t, db, owner, "Phone", 1)
	if err := db.ReplaceRecoveryCodes(ctx, owner, []string{recoveryHash(1)}); err != nil {
		t.Fatal(err)
	}
	live := hash(t)
	if err := db.InsertRefreshToken(ctx, live, owner, session(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := db.ResetMFA(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if listing, _ := db.ListFactors(ctx, owner); len(listing.Factors) != 0 || listing.RecoveryCodesRemaining != 0 {
		t.Fatalf("after reset: %+v", listing)
	}
	if state, _ := db.RefreshTokenState(ctx, live); !state.Revoked {
		t.Fatal("a session survived the reset")
	}
	if err := db.ResetMFA(ctx, 1<<50); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
}
