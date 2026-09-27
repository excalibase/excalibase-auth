package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseHashConcurrency(t *testing.T) {
	tests := []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{raw: "", want: 2},
		{raw: "4", want: 4},
		{raw: " 3 ", want: 3},
		{raw: "0", wantErr: true},
		{raw: "-1", wantErr: true},
		{raw: "many", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseHashConcurrency(tt.raw)
		if (err != nil) != tt.wantErr {
			t.Errorf("%q: err %v, wantErr %v", tt.raw, err, tt.wantErr)
		}
		if err == nil && got != tt.want {
			t.Errorf("%q: got %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestLoadReadsHashConcurrency(t *testing.T) {
	t.Setenv("CORS_ORIGINS", "https://app.example.test")
	t.Setenv("PASSWORD_HASH_CONCURRENCY", "4")
	if got := Load().PasswordHashConcurrency; got != 4 {
		t.Errorf("PasswordHashConcurrency: got %d, want 4", got)
	}
}

func writeLimit(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "memory.max")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMemoryLimitBytes(t *testing.T) {
	if got, err := MemoryLimitBytes(writeLimit(t, "268435456\n")); err != nil || got != 268435456 {
		t.Errorf("numeric limit: got %d, %v", got, err)
	}
	if got, err := MemoryLimitBytes(writeLimit(t, "max\n")); err != nil || got != 0 {
		t.Errorf("unlimited: got %d, %v", got, err)
	}
	if got, err := MemoryLimitBytes(filepath.Join(t.TempDir(), "absent")); err != nil || got != 0 {
		t.Errorf("no cgroup file: got %d, %v", got, err)
	}
	if _, err := MemoryLimitBytes(writeLimit(t, "lots")); err == nil {
		t.Error("an unreadable limit must be an error, not a guess")
	}
}
