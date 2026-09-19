// Package token resolves the provisioning service token used on outbound calls.
//
// The token file is rotated in place by an external job without restarting this
// process, so callers must ask for the current value at request time instead of
// capturing it at startup.
package token

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// refreshInterval bounds how often the token file is stat'ed. Rotation is
// picked up within this window without adding a syscall to every request.
const refreshInterval = 5 * time.Second

// ErrNoToken is returned when a Source has no usable token — neither a
// literal value nor a readable, non-empty token file. Callers must treat this
// as fatal for the request rather than send an empty bearer token.
var ErrNoToken = errors.New("no provisioning token configured")

// Source supplies the current provisioning token.
type Source interface {
	// Get returns the current token, or an error when none is available. A
	// caller must never send a request with an empty token: on error, fail
	// the call instead.
	Get() (string, error)
}

type literalSource string

func (l literalSource) Get() (string, error) {
	if l == "" {
		return "", ErrNoToken
	}
	return string(l), nil
}

// Literal returns a Source that always yields the given token. An empty value
// yields ErrNoToken on every call.
func Literal(value string) Source { return literalSource(value) }

// Option customises a FileSource. Used by tests to inject a clock, a reader or
// a different throttle window.
type Option func(*FileSource)

// WithClock overrides the time source used for throttling.
func WithClock(now func() time.Time) Option {
	return func(s *FileSource) { s.now = now }
}

// WithReader overrides how the token file is read.
func WithReader(read func(string) ([]byte, error)) Option {
	return func(s *FileSource) { s.read = read }
}

// WithInterval overrides the throttle window between file checks.
func WithInterval(d time.Duration) Option {
	return func(s *FileSource) { s.interval = d }
}

// FileSource reads the token from a file that may be rotated in place. The file
// is checked at most once per interval; the cached value is returned otherwise.
// On any read failure it keeps the last known good value, so a momentarily
// missing or half-written file never blanks the token. When no good value has
// ever been read — and no literal fallback was given — Get reports ErrNoToken
// rather than returning an empty string.
type FileSource struct {
	path     string
	interval time.Duration
	now      func() time.Time
	stat     func(string) (os.FileInfo, error)
	read     func(string) ([]byte, error)

	mu        sync.Mutex
	current   string
	lastCheck time.Time
	checked   bool
	modTime   time.Time
	size      int64
	loaded    bool
}

// NewFileSource returns a Source backed by the file at path, falling back to
// literal when path is empty. literal also seeds the value until the first
// successful read.
func NewFileSource(path, literal string, opts ...Option) Source {
	if path == "" {
		return Literal(literal)
	}
	source := &FileSource{
		path:     path,
		interval: refreshInterval,
		now:      time.Now,
		stat:     os.Stat,
		read:     os.ReadFile,
		current:  literal,
	}
	for _, opt := range opts {
		opt(source)
	}
	return source
}

// Get returns the current token, refreshing from disk when the throttle window
// has elapsed and the file changed. It reports ErrNoToken when no value — from
// a prior successful read or the literal fallback — is available, so a caller
// never receives an empty string to send as a bearer token.
func (s *FileSource) Get() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if !s.checked || now.Sub(s.lastCheck) >= s.interval {
		s.lastCheck = now
		s.checked = true
		s.refresh()
	}
	if s.current == "" {
		return "", fmt.Errorf("%w: token file %q unreadable or empty, and no fallback set", ErrNoToken, s.path)
	}
	return s.current, nil
}

// refresh re-reads the token file when its mtime or size changed. Callers hold
// s.mu. Failures are deliberately silent: the token value must never reach logs
// and the last known good value stays in place.
func (s *FileSource) refresh() {
	info, err := s.stat(s.path)
	if err != nil {
		return
	}
	if s.loaded && info.ModTime().Equal(s.modTime) && info.Size() == s.size {
		return
	}
	data, err := s.read(s.path)
	if err != nil {
		return
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return
	}
	s.current = value
	s.modTime = info.ModTime()
	s.size = info.Size()
	s.loaded = true
}
