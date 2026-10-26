package storetest

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/excalibase/auth/internal/store"
)

var roomyLimits = store.OTPLimits{MinInterval: 0, PerAddressHour: 1000, PerProjectDay: 1_000_000, PerIPDay: 1_000_000}

func linkOTP(t *testing.T, email string) store.EmailOTP {
	return store.EmailOTP{Email: email, Kind: store.OTPMagicLink, LinkHash: hash(t), CodeChallenge: "challenge",
		CreateUser: true, Mailed: true, IP: "192.0.2.1", ExpiresAt: time.Now().Add(10 * time.Minute)}
}

func codeOTP(t *testing.T, email string) store.EmailOTP {
	return store.EmailOTP{Email: email, Kind: store.OTPEmailCode, CodeHMAC: hash(t), CodeChallenge: "challenge",
		Mailed: true, IP: "192.0.2.1", ExpiresAt: time.Now().Add(10 * time.Minute)}
}

func save(t *testing.T, db store.Store, otp store.EmailOTP) {
	t.Helper()
	if mailed, err := db.SaveEmailOTP(context.Background(), otp, roomyLimits); err != nil || mailed != otp.Mailed {
		t.Fatalf("save otp: mailed=%v %v", mailed, err)
	}
}

func accept(store.EmailOTP) bool { return true }

func perCode(n int) store.OTPAttempts { return store.OTPAttempts{PerCode: n} }
func refuse(store.EmailOTP) bool      { return false }

func runEmailOTPs(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store

	t.Run("a link is spent once and hands back what was sent", func(t *testing.T) {
		otp := linkOTP(t, uniqueEmail("otp-link"))
		save(t, db, otp)
		got, err := db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: otp.LinkHash}, perCode(5), accept)
		if err != nil || got.Email != otp.Email || got.Kind != store.OTPMagicLink || got.LinkHash != otp.LinkHash ||
			got.CodeChallenge != "challenge" || !got.CreateUser {
			t.Fatalf("redeemed = %+v %v", got, err)
		}
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: otp.LinkHash}, perCode(5), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("second redeem: %v", err)
		}
	})

	t.Run("a refused link is spent: it gets no second try", func(t *testing.T) {
		otp := linkOTP(t, uniqueEmail("otp-link-refused"))
		save(t, db, otp)
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: otp.LinkHash}, perCode(5), refuse); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("refused link: %v", err)
		}
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: otp.LinkHash}, perCode(5), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a refused link was redeemed after: %v", err)
		}
	})

	t.Run("a code is found by its address whatever its case and dies at its last attempt", func(t *testing.T) {
		email := uniqueEmail("Otp-Code")
		otp := codeOTP(t, email)
		save(t, db, otp)
		lookup := store.OTPLookup{Email: strings.ToUpper(email), CodeChallenge: "challenge"}
		for attempt := 1; attempt < 3; attempt++ {
			if _, err := db.RedeemEmailOTP(ctx, lookup, perCode(3), refuse); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("attempt %d: %v", attempt, err)
			}
		}
		var seen store.EmailOTP
		if _, err := db.RedeemEmailOTP(ctx, lookup, perCode(3), func(row store.EmailOTP) bool { seen = row; return false }); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("last attempt: %v", err)
		}
		if seen.Attempts != 2 || seen.CodeHMAC != otp.CodeHMAC || seen.Email != email {
			t.Fatalf("the check saw %+v", seen)
		}
		if _, err := db.RedeemEmailOTP(ctx, lookup, perCode(3), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a code past its attempts was redeemed: %v", err)
		}
	})

	t.Run("a right code after wrong ones is redeemed once", func(t *testing.T) {
		email := uniqueEmail("otp-code-ok")
		save(t, db, codeOTP(t, email))
		lookup := store.OTPLookup{Email: email, CodeChallenge: "challenge"}
		if _, err := db.RedeemEmailOTP(ctx, lookup, perCode(5), refuse); !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if got, err := db.RedeemEmailOTP(ctx, lookup, perCode(5), accept); err != nil || got.Attempts != 1 {
			t.Fatalf("redeem = %+v %v", got, err)
		}
		if _, err := db.RedeemEmailOTP(ctx, lookup, perCode(5), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("a code was redeemed twice: %v", err)
		}
	})

	t.Run("spent codes do not hold back the address's next one", func(t *testing.T) {
		email := uniqueEmail("otp-no-lockout")
		lookup := store.OTPLookup{Email: email, CodeChallenge: "challenge"}
		for range 3 {
			save(t, db, codeOTP(t, email))
			for range 5 {
				if _, err := db.RedeemEmailOTP(ctx, lookup, perCode(5), refuse); !errors.Is(err, store.ErrNotFound) {
					t.Fatal(err)
				}
			}
		}
		fresh := codeOTP(t, email)
		save(t, db, fresh)
		if got, err := db.RedeemEmailOTP(ctx, lookup, perCode(5), accept); err != nil || got.CodeHMAC != fresh.CodeHMAC {
			t.Fatalf("fifteen wrong guesses locked the address out: %+v %v", got, err)
		}
	})

	t.Run("a code is not reached by a link lookup, nor a link by an address", func(t *testing.T) {
		email := uniqueEmail("otp-kinds")
		link := linkOTP(t, email)
		save(t, db, link)
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: email, CodeChallenge: "challenge"}, perCode(5), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("an address reached a link: %v", err)
		}
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: link.LinkHash}, perCode(5), accept); err != nil {
			t.Fatalf("the link itself: %v", err)
		}
	})

	t.Run("an expired code or link is refused", func(t *testing.T) {
		email := uniqueEmail("otp-expired")
		code := codeOTP(t, email)
		code.ExpiresAt = time.Now().Add(-time.Second)
		save(t, db, code)
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: email, CodeChallenge: "challenge"}, perCode(5), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired code: %v", err)
		}
		link := linkOTP(t, uniqueEmail("otp-expired-link"))
		link.ExpiresAt = time.Now().Add(-time.Second)
		save(t, db, link)
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: link.LinkHash}, perCode(5), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("expired link: %v", err)
		}
	})

	t.Run("a code is reached only with the challenge it was sent with", func(t *testing.T) {
		email := uniqueEmail("otp-challenge")
		mine := codeOTP(t, email)
		save(t, db, mine)
		theirs := codeOTP(t, email)
		theirs.CodeChallenge = "another-challenge"
		save(t, db, theirs)
		for range 5 {
			if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: email, CodeChallenge: "another-challenge"}, perCode(5), refuse); !errors.Is(err, store.ErrNotFound) {
				t.Fatal(err)
			}
		}
		got, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: email, CodeChallenge: "challenge"}, perCode(5), accept)
		if err != nil || got.CodeHMAC != mine.CodeHMAC {
			t.Fatalf("guesses at another browser's code spent mine: %+v %v", got, err)
		}
	})

	t.Run("a new send ends the address's earlier code and link", func(t *testing.T) {
		email := uniqueEmail("otp-resend")
		first, link := codeOTP(t, email), linkOTP(t, email)
		save(t, db, first)
		save(t, db, link)
		second := codeOTP(t, email)
		save(t, db, second)
		if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{LinkHash: link.LinkHash}, perCode(5), accept); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the earlier link survived a new send: %v", err)
		}
		got, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: email, CodeChallenge: "challenge"}, perCode(5), accept)
		if err != nil || got.CodeHMAC != second.CodeHMAC {
			t.Fatalf("redeemed %+v %v, want the newest code", got, err)
		}
	})

	t.Run("an address waits between sends and has an hourly budget", func(t *testing.T) {
		email := uniqueEmail("otp-paced")
		paced := store.OTPLimits{MinInterval: time.Minute, PerAddressHour: 5, PerProjectDay: 1_000_000, PerIPDay: 1_000_000}
		if _, err := db.SaveEmailOTP(ctx, codeOTP(t, email), paced); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SaveEmailOTP(ctx, codeOTP(t, strings.ToUpper(email)), paced); !errors.Is(err, store.ErrRateLimited) {
			t.Fatalf("a send inside the interval: %v", err)
		}
		hourly := store.OTPLimits{PerAddressHour: 2, PerProjectDay: 1_000_000, PerIPDay: 1_000_000}
		if _, err := db.SaveEmailOTP(ctx, codeOTP(t, email), hourly); err != nil {
			t.Fatal(err)
		}
		if _, err := db.SaveEmailOTP(ctx, codeOTP(t, email), hourly); !errors.Is(err, store.ErrRateLimited) {
			t.Fatalf("a send past the hourly budget: %v", err)
		}
		if _, err := db.SaveEmailOTP(ctx, codeOTP(t, uniqueEmail("otp-other")), hourly); err != nil {
			t.Fatalf("another address shares the budget: %v", err)
		}
	})

	t.Run("the project's daily budget holds under concurrent sends", func(t *testing.T) {
		budget := fx.Count(t, "email_otps") + 3
		daily := store.OTPLimits{PerAddressHour: 1000, PerProjectDay: budget, PerIPDay: 1_000_000}
		var wg sync.WaitGroup
		var saved, limited atomic.Int64
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				switch mailed, err := db.SaveEmailOTP(ctx, codeOTP(t, uniqueEmail("otp-daily")), daily); {
				case err == nil && mailed:
					saved.Add(1)
				case err == nil:
					limited.Add(1)
				default:
					t.Errorf("send: %v", err)
				}
			}()
		}
		wg.Wait()
		if saved.Load() != 3 || limited.Load() != 5 {
			t.Fatalf("mailed %d and held back %d of 8, want 3 and 5", saved.Load(), limited.Load())
		}
	})

	t.Run("a send held back by the project's budget leaves the earlier code live", func(t *testing.T) {
		email := uniqueEmail("otp-held")
		first := codeOTP(t, email)
		save(t, db, first)
		held := codeOTP(t, email)
		held.Mailed = false
		save(t, db, held)
		got, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: email, CodeChallenge: "challenge"}, perCode(5), accept)
		if err != nil || got.CodeHMAC != first.CodeHMAC {
			t.Fatalf("redeemed %+v %v, want the mailed code", got, err)
		}
	})

	t.Run("only mailed sends spend the project's budget, and a client IP has its own", func(t *testing.T) {
		all := fx.Count(t, "email_otps")
		unmailed := codeOTP(t, uniqueEmail("otp-unmailed"))
		unmailed.Mailed = false
		exhausted := store.OTPLimits{PerAddressHour: 1000, PerProjectDay: all, PerIPDay: 1_000_000}
		if mailed, err := db.SaveEmailOTP(ctx, unmailed, exhausted); err != nil || mailed {
			t.Fatalf("unmailed send: %v %v", mailed, err)
		}
		if mailed, err := db.SaveEmailOTP(ctx, codeOTP(t, uniqueEmail("otp-over")), store.OTPLimits{PerAddressHour: 1000, PerProjectDay: all + 1, PerIPDay: 1_000_000}); err != nil || !mailed {
			t.Fatalf("an unmailed row spent the project's budget: %v %v", mailed, err)
		}
		perIP := store.OTPLimits{PerAddressHour: 1000, PerProjectDay: 1_000_000, PerIPDay: 2}
		for i := range 3 {
			otp := codeOTP(t, uniqueEmail("otp-ip"))
			otp.IP = "198.51.100.7"
			_, err := db.SaveEmailOTP(ctx, otp, perIP)
			if (i < 2) != (err == nil) || (i == 2 && !errors.Is(err, store.ErrRateLimited)) {
				t.Fatalf("send %d from one IP: %v", i+1, err)
			}
		}
		other := codeOTP(t, uniqueEmail("otp-ip-other"))
		other.IP = "198.51.100.8"
		if _, err := db.SaveEmailOTP(ctx, other, perIP); err != nil {
			t.Fatalf("another IP shares the budget: %v", err)
		}
	})

	t.Run("concurrent redeems of one code spend it once", func(t *testing.T) {
		email := uniqueEmail("otp-race")
		save(t, db, codeOTP(t, email))
		var wg sync.WaitGroup
		var won atomic.Int64
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := db.RedeemEmailOTP(ctx, store.OTPLookup{Email: email, CodeChallenge: "challenge"}, perCode(5), accept); err == nil {
					won.Add(1)
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 {
			t.Fatalf("%d redeems won, want 1", won.Load())
		}
	})
}

func runEmailSignIn(t *testing.T, fx Fixture) {
	ctx := context.Background()
	db := fx.Store

	signInEmail := func(t *testing.T, email string, allowCreate bool, want store.IdentityOutcome) store.Account {
		t.Helper()
		account, outcome, err := db.SignInWithEmail(ctx, email, "Mail Name", allowCreate)
		if err != nil || outcome != want {
			t.Fatalf("sign in %s: outcome=%d err=%v, want %d", email, outcome, err, want)
		}
		return account
	}

	t.Run("a new address makes a verified account without a password, once", func(t *testing.T) {
		email := uniqueEmail("mail-new")
		created := signInEmail(t, email, true, store.IdentityCreated)
		if created.ID <= 0 || created.Email != email || created.FullName != "Mail Name" || created.PasswordHash != "" ||
			!created.EmailVerified || created.Role != "user" || !created.Enabled {
			t.Fatalf("created = %+v", created)
		}
		if again := signInEmail(t, email, false, store.IdentityKnown); again.ID != created.ID {
			t.Fatalf("second sign-in reached %d, want %d", again.ID, created.ID)
		}
	})

	t.Run("a verified account keeps its password and sessions", func(t *testing.T) {
		id, email := newUser(t, db, "mail-verified")
		if _, err := db.MarkVerified(ctx, id, true, "!marker"); err != nil {
			t.Fatal(err)
		}
		live := hash(t)
		if err := db.InsertRefreshToken(ctx, live, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		account := signInEmail(t, strings.ToUpper(email), false, store.IdentityKnown)
		if account.ID != id || account.PasswordHash != "hash-mail-verified" {
			t.Fatalf("account = %+v", account)
		}
		if state, _ := db.RefreshTokenState(ctx, live); state.Revoked {
			t.Fatal("a sign-in by mail ended the account's sessions")
		}
	})

	t.Run("an unverified account is replaced, as a provider sign-in replaces it", func(t *testing.T) {
		id, email := newUser(t, db, "mail-squat")
		live := hash(t)
		if err := db.InsertRefreshToken(ctx, live, id, session(time.Hour)); err != nil {
			t.Fatal(err)
		}
		owner := signInEmail(t, email, false, store.IdentityTookOver)
		if owner.ID == id || owner.PasswordHash != "" || !owner.EmailVerified || owner.Email != email {
			t.Fatalf("taken over = %+v (squatted id %d)", owner, id)
		}
		if _, err := db.RefreshTokenState(ctx, live); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the squatter's session survived: %v", err)
		}
	})

	t.Run("a disabled account stays disabled, by mail or by provider", func(t *testing.T) {
		_, email := newUser(t, db, "mail-disabled")
		fx.Disable(t, email)
		if _, _, err := db.SignInWithEmail(ctx, email, "Name", true); !errors.Is(err, store.ErrAccountDisabled) {
			t.Fatalf("mail sign-in: %v, want ErrAccountDisabled", err)
		}
		if _, _, err := db.SignInWithIdentity(ctx, claimFor("github", email), true); !errors.Is(err, store.ErrAccountDisabled) {
			t.Fatalf("provider sign-in: %v, want ErrAccountDisabled", err)
		}
		if account, err := db.AccountByAddress(ctx, email); err != nil || account.Enabled {
			t.Fatalf("the disabled account was replaced: %+v %v", account, err)
		}
	})

	t.Run("closed sign-ups refuse a new address and write nothing", func(t *testing.T) {
		users := fx.Count(t, "users")
		if _, _, err := db.SignInWithEmail(ctx, uniqueEmail("mail-closed"), "Name", false); !errors.Is(err, store.ErrSignupsDisabled) {
			t.Fatalf("err = %v, want ErrSignupsDisabled", err)
		}
		if fx.Count(t, "users") != users {
			t.Fatal("a refused sign-up wrote a row")
		}
	})

	t.Run("the address an account answers to is found whatever its case", func(t *testing.T) {
		id, email := newUser(t, db, "Mail-Lookup")
		found, err := db.AccountByAddress(ctx, strings.ToLower(email))
		if err != nil || found.ID != id {
			t.Fatalf("found = %+v %v, want %d", found, err, id)
		}
		if _, err := db.AccountByAddress(ctx, uniqueEmail("mail-nobody")); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("unknown address: %v", err)
		}
	})

	t.Run("an audit row records who signed in, how and from where", func(t *testing.T) {
		before := fx.Count(t, "audit_log")
		if err := db.RecordAudit(ctx, store.AuditEvent{UserID: 42, Event: "sign_in", Method: "magiclink", IP: "203.0.113.9"}); err != nil {
			t.Fatal(err)
		}
		if err := db.RecordAudit(ctx, store.AuditEvent{Event: "sign_in", Method: "email"}); err != nil {
			t.Fatalf("an event without a user: %v", err)
		}
		if got := fx.Count(t, "audit_log"); got != before+2 {
			t.Fatalf("audit_log = %d rows, want %d", got, before+2)
		}
	})
}
