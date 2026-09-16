package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock so window/refill behaviour is tested
// deterministically instead of with sleeps.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestLimiter_AllowsUpToLimitThenBlocks(t *testing.T) {
	clock := newFakeClock()
	limiter := New(3, time.Minute, WithClock(clock.Now))

	for i := 0; i < 3; i++ {
		if d := limiter.Allow("k"); !d.Allowed {
			t.Fatalf("request %d: want allowed", i+1)
		}
	}
	d := limiter.Allow("k")
	if d.Allowed {
		t.Fatal("4th request: want blocked")
	}
	if d.RetryAfter <= 0 || d.RetryAfter > 20*time.Second {
		t.Errorf("retryAfter: got %v, want (0, 20s]", d.RetryAfter)
	}
}

func TestLimiter_RefillsAfterWindow(t *testing.T) {
	tests := []struct {
		name        string
		advance     time.Duration
		wantAllowed int
	}{
		{name: "no time passed", advance: 0, wantAllowed: 0},
		{name: "one third window refills one token", advance: 20 * time.Second, wantAllowed: 1},
		{name: "full window refills to capacity", advance: time.Minute, wantAllowed: 3},
		{name: "refill never exceeds capacity", advance: 10 * time.Minute, wantAllowed: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newFakeClock()
			limiter := New(3, time.Minute, WithClock(clock.Now))
			for i := 0; i < 3; i++ {
				limiter.Allow("k")
			}
			clock.Advance(tt.advance)

			allowed := 0
			for i := 0; i < 5; i++ {
				if limiter.Allow("k").Allowed {
					allowed++
				}
			}
			if allowed != tt.wantAllowed {
				t.Errorf("allowed after %v: got %d, want %d", tt.advance, allowed, tt.wantAllowed)
			}
		})
	}
}

func TestLimiter_KeysAreIsolated(t *testing.T) {
	clock := newFakeClock()
	limiter := New(1, time.Minute, WithClock(clock.Now))

	if !limiter.Allow("a").Allowed {
		t.Fatal("a: first request should pass")
	}
	if limiter.Allow("a").Allowed {
		t.Fatal("a: second request should be blocked")
	}
	if !limiter.Allow("b").Allowed {
		t.Fatal("b: must not be affected by a's exhaustion")
	}
}

func TestLimiter_ExhaustedDoesNotConsume(t *testing.T) {
	clock := newFakeClock()
	limiter := New(2, time.Minute, WithClock(clock.Now))

	for i := 0; i < 5; i++ {
		if d := limiter.Exhausted("k"); d.Blocked() {
			t.Fatalf("peek %d: must not consume tokens", i+1)
		}
	}
	limiter.Allow("k")
	limiter.Allow("k")
	d := limiter.Exhausted("k")
	if !d.Blocked() {
		t.Fatal("after consuming all tokens, Exhausted must report blocked")
	}
	if d.RetryAfter <= 0 {
		t.Errorf("retryAfter: got %v, want > 0", d.RetryAfter)
	}
}

func TestLimiter_ResetRestoresCapacity(t *testing.T) {
	clock := newFakeClock()
	limiter := New(1, time.Minute, WithClock(clock.Now))

	limiter.Allow("k")
	if limiter.Allow("k").Allowed {
		t.Fatal("should be blocked before reset")
	}
	limiter.Reset("k")
	if !limiter.Allow("k").Allowed {
		t.Fatal("should be allowed after reset")
	}
}

func TestLimiter_RetryAfterIsTimeToNextToken(t *testing.T) {
	clock := newFakeClock()
	limiter := New(4, time.Minute, WithClock(clock.Now))
	for i := 0; i < 4; i++ {
		limiter.Allow("k")
	}
	d := limiter.Allow("k")
	if d.RetryAfter != 15*time.Second {
		t.Errorf("retryAfter: got %v, want 15s (window/limit)", d.RetryAfter)
	}
}

func TestLimiter_SweepEvictsIdleKeys(t *testing.T) {
	clock := newFakeClock()
	limiter := New(1, time.Minute, WithClock(clock.Now))

	limiter.Allow("idle")
	clock.Advance(3 * time.Minute)
	limiter.Allow("fresh")

	if got := limiter.Len(); got != 1 {
		t.Errorf("tracked keys after sweep: got %d, want 1 (idle key evicted)", got)
	}
}

func TestLimiter_ZeroLimitBlocksEverything(t *testing.T) {
	limiter := New(0, time.Minute)
	if limiter.Allow("k").Allowed {
		t.Fatal("limit 0 must block every request")
	}
}

func TestLimiter_ConcurrentAccessIsSafe(t *testing.T) {
	limiter := New(100, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				limiter.Allow("shared")
			}
		}()
	}
	wg.Wait()
	if limiter.Allow("shared").Allowed {
		t.Fatal("500 concurrent requests must exhaust a limit of 100")
	}
}
