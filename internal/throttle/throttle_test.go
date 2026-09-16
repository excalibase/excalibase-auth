package throttle

import (
	"testing"
	"time"
)

func TestAllow_PermitsUpToLimitThenBlocks(t *testing.T) {
	th := New(3, time.Hour)

	for i := 1; i <= 3; i++ {
		if !th.Allow("alice") {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if th.Allow("alice") {
		t.Fatal("fourth attempt must be blocked")
	}
}

func TestAllow_KeysAreIndependent(t *testing.T) {
	th := New(1, time.Hour)

	if !th.Allow("alice") || !th.Allow("bob") {
		t.Fatal("distinct keys must not share a budget")
	}
	if th.Allow("alice") {
		t.Fatal("alice should be exhausted")
	}
}

func TestAllow_WindowExpiryResetsBudget(t *testing.T) {
	th := New(1, 20*time.Millisecond)

	if !th.Allow("alice") {
		t.Fatal("first attempt should be allowed")
	}
	if th.Allow("alice") {
		t.Fatal("second attempt inside the window must be blocked")
	}

	time.Sleep(30 * time.Millisecond)

	if !th.Allow("alice") {
		t.Fatal("budget must reset once the window elapses")
	}
}

func TestAllow_EmptyKeyIsNotThrottledGlobally(t *testing.T) {
	th := New(1, time.Hour)

	// An empty key would otherwise let one caller exhaust everyone's budget.
	if !th.Allow("") || !th.Allow("") {
		t.Fatal("an empty key must never consume a shared budget")
	}
}

func TestAllow_NonPositiveLimitDisablesThrottling(t *testing.T) {
	th := New(0, time.Hour)

	for i := 0; i < 5; i++ {
		if !th.Allow("alice") {
			t.Fatal("a non-positive limit must disable throttling")
		}
	}
}

func TestAllow_EvictsExpiredEntries(t *testing.T) {
	th := New(1, 10*time.Millisecond)

	for i := 0; i < 50; i++ {
		th.Allow(string(rune('a' + i%26)))
	}
	time.Sleep(20 * time.Millisecond)
	th.Allow("trigger-sweep")

	if got := th.size(); got > 1 {
		t.Fatalf("expired entries must be evicted, %d remain", got)
	}
}
