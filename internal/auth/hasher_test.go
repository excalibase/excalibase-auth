package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHashUsesTheOWASPProfile(t *testing.T) {
	hash, err := NewHasher(1, time.Second).Hash(context.Background(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash parameters: %s", hash)
	}
}

func TestCheckVerifiesItsOwnHash(t *testing.T) {
	h := NewHasher(1, time.Second)
	hash, _ := h.Hash(context.Background(), "correct-horse")
	ok, err := h.Check(context.Background(), "correct-horse", hash)
	if err != nil || !ok {
		t.Fatalf("own hash: ok=%v err=%v", ok, err)
	}
	if ok, _ := h.Check(context.Background(), "wrong", hash); ok {
		t.Fatal("wrong password verified")
	}
}

// Hashes live in the tenant's own database, which its developer can write, so
// a stored hash must not be able to name the cost of its own verification.
func TestCheckRefusesHashesCostlierThanOurs(t *testing.T) {
	salt := "c2FsdHNhbHRzYWx0c2FsdA"
	key := "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
	cases := map[string]string{
		"4 GiB of memory":     "m=4194304,t=2,p=1",
		"more memory":         "m=19457,t=2,p=1",
		"more passes":         "m=19456,t=200,p=1",
		"more lanes":          "m=19456,t=2,p=255",
		"zero lanes (panics)": "m=19456,t=2,p=0",
		"zero passes":         "m=19456,t=0,p=1",
	}
	h := NewHasher(1, time.Second)
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			encoded := fmt.Sprintf("$argon2id$v=19$%s$%s$%s", params, salt, key)
			ok, err := h.Check(context.Background(), "pw", encoded)
			if ok || err != nil {
				t.Fatalf("ok=%v err=%v, want a plain refusal", ok, err)
			}
		})
	}
}

func TestCheckRefusesAnOversizedKey(t *testing.T) {
	long := strings.Repeat("A", 1<<20)
	encoded := "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$" + long
	if ok, err := NewHasher(1, time.Second).Check(context.Background(), "pw", encoded); ok || err != nil {
		t.Fatalf("ok=%v err=%v, want a plain refusal", ok, err)
	}
}

func TestCheckRefusesMalformedHashes(t *testing.T) {
	h := NewHasher(1, time.Second)
	for _, encoded := range []string{"", "$2a$10$bcrypt", "$argon2id$v=19$garbage", "$argon2id$v=19$m=19456,t=2,p=1$!!$!!"} {
		if ok, err := h.Check(context.Background(), "pw", encoded); ok || err != nil {
			t.Errorf("%q: ok=%v err=%v", encoded, ok, err)
		}
	}
}

// blockingDerive stands in for argon2 and records how many run at once.
type blockingDerive struct {
	release  chan struct{}
	inFlight atomic.Int32
	peak     atomic.Int32
}

func (b *blockingDerive) derive(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
	n := b.inFlight.Add(1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	<-b.release
	b.inFlight.Add(-1)
	return make([]byte, keyLen)
}

func TestConcurrentHashesNeverExceedTheBoundAndTheRestAreRefused(t *testing.T) {
	fake := &blockingDerive{release: make(chan struct{})}
	h := NewHasher(2, 50*time.Millisecond)
	h.derive = fake.derive

	var busy atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := h.Hash(context.Background(), "pw"); errors.Is(err, ErrHashBusy) {
				busy.Add(1)
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for busy.Load() < 18 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(fake.release)
	wg.Wait()

	if got := fake.peak.Load(); got != 2 {
		t.Errorf("peak concurrent hashes: got %d, want 2", got)
	}
	if got := busy.Load(); got != 18 {
		t.Errorf("refused as busy: got %d, want 18", got)
	}
}

func TestAWaitingHashTakesASlotThatFreesInTime(t *testing.T) {
	fake := &blockingDerive{release: make(chan struct{})}
	h := NewHasher(1, 2*time.Second)
	h.derive = fake.derive

	first := make(chan error, 1)
	go func() { _, err := h.Hash(context.Background(), "pw"); first <- err }()
	for fake.inFlight.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	second := make(chan error, 1)
	go func() { _, err := h.Check(context.Background(), "pw", ownHash(t)); second <- err }()
	time.Sleep(20 * time.Millisecond)
	close(fake.release)
	if err := <-first; err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second waited for a slot and still failed: %v", err)
	}
}

func TestAHashWaitingForASlotStopsWithItsRequest(t *testing.T) {
	fake := &blockingDerive{release: make(chan struct{})}
	defer close(fake.release)
	h := NewHasher(1, time.Minute)
	h.derive = fake.derive
	go func() { _, _ = h.Hash(context.Background(), "pw") }()
	for fake.inFlight.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "pw"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait: got %v, want context.Canceled", err)
	}
}

func ownHash(t *testing.T) string {
	t.Helper()
	hash, err := NewHasher(1, time.Second).Hash(context.Background(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestNewHasherRefusesNoSlots(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewHasher accepted zero slots")
		}
	}()
	NewHasher(0, time.Second)
}

func TestHashBudgetFitsTheMemoryLimit(t *testing.T) {
	const mib = 1 << 20
	if err := CheckHashBudget(4, 256*mib); err != nil {
		t.Errorf("4 hashes in 256Mi: %v", err)
	}
	if err := CheckHashBudget(2, 128*mib); err != nil {
		t.Errorf("2 hashes in 128Mi: %v", err)
	}
	if err := CheckHashBudget(4, 128*mib); err == nil {
		t.Error("4 hashes (76Mi) in 128Mi leaves no room for the rest of the process")
	}
	if err := CheckHashBudget(64, 0); err != nil {
		t.Errorf("no limit known: %v", err)
	}
}
