package token

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	fallbackPAT   = "fallback-pat"
	tokenFileName = "pat"
)

func writeToken(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
}

// mustGet asserts Get succeeds and returns the token.
func mustGet(t *testing.T, src Source) string {
	t.Helper()
	got, err := src.Get()
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	return got
}

func TestNewFileSource_NoPathUsesLiteral(t *testing.T) {
	src := NewFileSource("", "literal-pat")
	for i := 0; i < 3; i++ {
		if got := mustGet(t, src); got != "literal-pat" {
			t.Fatalf("call %d: got %q, want %q", i, got, "literal-pat")
		}
	}
}

func TestFileSource_ReadsAndTrims(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     string
	}{
		{name: "plain", contents: "excb_abc", want: "excb_abc"},
		{name: "trailing newline", contents: "excb_abc\n", want: "excb_abc"},
		{name: "surrounding whitespace", contents: "  excb_abc \n\t", want: "excb_abc"},
		{name: "empty file keeps fallback", contents: "   \n", want: fallbackPAT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tokenFileName)
			writeToken(t, path, tt.contents)

			src := NewFileSource(path, fallbackPAT)

			if got := mustGet(t, src); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFileSource_RotationPickedUpAfterThrottleWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), tokenFileName)
	writeToken(t, path, "old-pat")

	clock := time.Unix(1_700_000_000, 0)
	src := NewFileSource(path, fallbackPAT, WithClock(func() time.Time { return clock }))

	if got := mustGet(t, src); got != "old-pat" {
		t.Fatalf("initial: got %q, want old-pat", got)
	}

	writeToken(t, path, "rotated-pat-value")

	clock = clock.Add(refreshInterval - time.Millisecond)
	if got := mustGet(t, src); got != "old-pat" {
		t.Errorf("within throttle window: got %q, want cached old-pat", got)
	}

	clock = clock.Add(2 * time.Millisecond)
	if got := mustGet(t, src); got != "rotated-pat-value" {
		t.Errorf("after throttle window: got %q, want rotated-pat-value", got)
	}
}

func TestFileSource_UnchangedFileNotReread(t *testing.T) {
	path := filepath.Join(t.TempDir(), tokenFileName)
	writeToken(t, path, "stable-pat")

	reads := 0
	clock := time.Unix(1_700_000_000, 0)
	src := NewFileSource(path, fallbackPAT,
		WithClock(func() time.Time { return clock }),
		WithReader(func(name string) ([]byte, error) {
			reads++
			return os.ReadFile(name)
		}),
	)

	for i := 0; i < 3; i++ {
		if got := mustGet(t, src); got != "stable-pat" {
			t.Fatalf("call %d: got %q", i, got)
		}
		clock = clock.Add(refreshInterval)
	}

	if reads != 1 {
		t.Errorf("reads: got %d, want 1 (mtime+size unchanged)", reads)
	}
}

func TestFileSource_DeletedFileKeepsLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, tokenFileName)
	writeToken(t, path, "good-pat")

	clock := time.Unix(1_700_000_000, 0)
	src := NewFileSource(path, fallbackPAT, WithClock(func() time.Time { return clock }))

	if got := mustGet(t, src); got != "good-pat" {
		t.Fatalf("initial: got %q, want good-pat", got)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	clock = clock.Add(refreshInterval)

	if got := mustGet(t, src); got != "good-pat" {
		t.Errorf("after delete: got %q, want last known good-pat", got)
	}
}

func TestFileSource_MissingFileFromStartUsesFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")

	src := NewFileSource(path, fallbackPAT)

	if got := mustGet(t, src); got != fallbackPAT {
		t.Errorf("got %q, want fallback-pat", got)
	}
}

// TestFileSource_MissingFileAndNoFallbackErrors covers the "neither set" /
// "file unreadable at call time with nothing to fall back to" case: Get must
// report ErrNoToken instead of ever returning an empty string a caller could
// send as a bearer token.
func TestFileSource_MissingFileAndNoFallbackErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")

	src := NewFileSource(path, "")

	got, err := src.Get()
	if got != "" {
		t.Errorf("got %q, want empty string alongside the error", got)
	}
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("err: got %v, want ErrNoToken", err)
	}
}

// TestFileSource_EmptyFileAndNoFallbackErrors covers a token file present but
// blank, with no literal fallback configured.
func TestFileSource_EmptyFileAndNoFallbackErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), tokenFileName)
	writeToken(t, path, "   \n")

	src := NewFileSource(path, "")

	got, err := src.Get()
	if got != "" {
		t.Errorf("got %q, want empty string alongside the error", got)
	}
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("err: got %v, want ErrNoToken", err)
	}
}

func TestFileSource_ConcurrentGetIsSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), tokenFileName)
	writeToken(t, path, "concurrent-pat")

	src := NewFileSource(path, fallbackPAT, WithInterval(0))

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				if got := mustGet(t, src); got != "concurrent-pat" {
					t.Errorf("got %q, want concurrent-pat", got)
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

func TestLiteral(t *testing.T) {
	if got := mustGet(t, Literal("plain-pat")); got != "plain-pat" {
		t.Errorf("got %q, want plain-pat", got)
	}
}

// TestLiteral_EmptyErrors covers the "neither PROVISIONING_PAT nor
// PROVISIONING_PAT_FILE set" case: NewFileSource("", "") falls back to
// Literal(""), which must error rather than silently yield "".
func TestLiteral_EmptyErrors(t *testing.T) {
	got, err := Literal("").Get()
	if got != "" {
		t.Errorf("got %q, want empty string alongside the error", got)
	}
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("err: got %v, want ErrNoToken", err)
	}
}

// TestNewFileSource_NoPathNoLiteralErrors is the direct "neither set" case as
// main.go constructs it: token.NewFileSource(cfg.ProvisioningPATFile,
// cfg.ProvisioningPAT) with both empty.
func TestNewFileSource_NoPathNoLiteralErrors(t *testing.T) {
	got, err := NewFileSource("", "").Get()
	if got != "" {
		t.Errorf("got %q, want empty string alongside the error", got)
	}
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("err: got %v, want ErrNoToken", err)
	}
}
