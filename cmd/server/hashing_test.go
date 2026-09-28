package main

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func memoryMaxFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "memory.max")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConfigureHashingRefusesSlotsTheMemoryLimitCannotHold(t *testing.T) {
	if _, err := configureHashing(4, memoryMaxFile(t, "134217728")); err == nil {
		t.Fatal("4 hashes accepted under a 128Mi limit")
	}
}

func TestConfigureHashingRefusesAnUnreadableLimit(t *testing.T) {
	if _, err := configureHashing(2, memoryMaxFile(t, "lots")); err == nil {
		t.Fatal("an unreadable limit was accepted")
	}
}

func TestConfigureHashingSetsTheGoMemoryLimitBelowTheContainers(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "")
	previous := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(previous)

	if _, err := configureHashing(2, memoryMaxFile(t, "134217728")); err != nil {
		t.Fatal(err)
	}
	if got := debug.SetMemoryLimit(-1); got != 134217728*9/10 {
		t.Fatalf("Go memory limit: got %d, want 90%% of the container's", got)
	}
}

func TestConfigureHashingWithoutALimitStillBoundsHashing(t *testing.T) {
	hasher, err := configureHashing(2, memoryMaxFile(t, "max"))
	if err != nil || hasher == nil {
		t.Fatalf("hasher=%v err=%v", hasher, err)
	}
}
