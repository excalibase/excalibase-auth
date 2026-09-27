package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// OWASP's argon2id profile (m=19 MiB, t=2, p=1): each hash holds 19 MiB, so
// the number running at once is what bounds the pod's memory.
const (
	argon2Time    = 2
	argon2Memory  = 19 * 1024 // KiB
	argon2Threads = 1
	argon2KeyLen  = 32
	argon2SaltLen = 16

	// HashMemoryBytes is what one hash in flight holds.
	HashMemoryBytes = argon2Memory * 1024

	// DefaultHashSlots fits the smallest shipped memory limit (128Mi); the
	// charts set PASSWORD_HASH_CONCURRENCY to match their own limit.
	DefaultHashSlots = 2
	DefaultHashWait  = time.Second

	maxStoredKeyLen  = 64
	maxStoredSaltLen = 64

	// maxAcceptedMemory/Time/Threads is the highest argon2id cost this
	// service has ever run at (its pre-EXC-459 profile: m=64 MiB, t=3, p=4).
	// Check compares a stored hash against this fixed ceiling, not against
	// the currently configured profile, so lowering the default cost never
	// strands a hash written under a costlier one. A tenant-writable row
	// naming a cost above this ceiling is still refused unread: that is the
	// resource-exhaustion case this guard exists for.
	maxAcceptedMemory  = 64 * 1024 // KiB
	maxAcceptedTime    = 3
	maxAcceptedThreads = 4
)

// ErrHashBusy means every hashing slot stayed taken for the whole wait.
var ErrHashBusy = errors.New("password hashing is at capacity")

type deriveFunc func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

// Hasher runs argon2id with at most `slots` hashes in flight. A caller that
// cannot get a slot within `wait` gets ErrHashBusy instead of queueing
// without bound.
type Hasher struct {
	slots  chan struct{}
	wait   time.Duration
	derive deriveFunc
}

// NewHasher panics on fewer than one slot: that is a wiring mistake.
func NewHasher(slots int, wait time.Duration) *Hasher {
	if slots < 1 {
		panic(fmt.Sprintf("auth: password hash slots must be at least 1, got %d", slots))
	}
	return &Hasher{slots: make(chan struct{}, slots), wait: wait, derive: argon2.IDKey}
}

// CheckHashBudget refuses a slot count whose hashes alone would take more
// than half the memory limit; the other half is the rest of the process and
// the garbage collector's headroom. A limit of 0 means none is known.
func CheckHashBudget(slots int, limitBytes int64) error {
	if limitBytes <= 0 {
		return nil
	}
	need := int64(slots) * HashMemoryBytes
	if need > limitBytes/2 {
		return fmt.Errorf("%d concurrent password hashes need %d MiB, more than half the %d MiB memory limit",
			slots, need>>20, limitBytes>>20)
	}
	return nil
}

func (h *Hasher) acquire(ctx context.Context) (func(), error) {
	timer := time.NewTimer(h.wait)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrHashBusy
	}
}

// Hash returns an argon2id encoding of password.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	key := h.derive([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Check reports whether password matches encoded. A hash that is malformed or
// asks for more than our own parameters is refused without being computed:
// stored hashes sit in a database the tenant can write. The error is only
// ErrHashBusy or the context's.
func (h *Hasher) Check(ctx context.Context, password, encoded string) (bool, error) {
	stored, ok := parseArgon2id(encoded)
	if !ok {
		return false, nil
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	key := h.derive([]byte(password), stored.salt, stored.time, stored.memory, stored.threads, uint32(len(stored.key)))
	return subtle.ConstantTimeCompare(key, stored.key) == 1, nil
}

type storedHash struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func parseArgon2id(encoded string) (storedHash, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return storedHash{}, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return storedHash{}, false
	}
	var s storedHash
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &s.memory, &s.time, &s.threads); err != nil {
		return storedHash{}, false
	}
	if !withinOurCost(s) || len(parts[4]) > maxStoredSaltLen*2 || len(parts[5]) > maxStoredKeyLen*2 {
		return storedHash{}, false
	}
	var err error
	if s.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return storedHash{}, false
	}
	if s.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(s.key) == 0 || len(s.key) > maxStoredKeyLen {
		return storedHash{}, false
	}
	return s, true
}

func withinOurCost(s storedHash) bool {
	return s.memory >= 1 && s.memory <= maxAcceptedMemory &&
		s.time >= 1 && s.time <= maxAcceptedTime &&
		s.threads >= 1 && s.threads <= maxAcceptedThreads
}
