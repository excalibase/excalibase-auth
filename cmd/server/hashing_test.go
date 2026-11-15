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
	if _, err := configureHashing(4, memoryMaxFile(t, "134217728"), 4); err == nil {
		t.Fatal("4 hashes accepted under a 128Mi limit")
	}
}

func TestConfigureHashingRefusesAnUnreadableLimit(t *testing.T) {
	if _, err := configureHashing(2, memoryMaxFile(t, "lots"), 4); err == nil {
		t.Fatal("an unreadable limit was accepted")
	}
}

func TestConfigureHashingSetsTheGoMemoryLimitBelowTheContainers(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "")
	previous := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(previous)

	if _, err := configureHashing(2, memoryMaxFile(t, "134217728"), 4); err != nil {
		t.Fatal(err)
	}
	if got := debug.SetMemoryLimit(-1); got != 134217728*9/10 {
		t.Fatalf("Go memory limit: got %d, want 90%% of the container's", got)
	}
}

func TestConfigureHashingSizesAnUnsetGateFromTheContainer(t *testing.T) {
	cases := []struct {
		name   string
		limit  string
		cpus   int
		wanted int
	}{
		{"128Mi pod", "134217728", 8, 1},
		{"1 GiB, 8 cpus: cpu share", "1073741824", 8, 4},
		{"1 GiB, 32 cpus: memory share", "1073741824", 32, 13},
		{"no limit: cpu share", "max", 6, 3},
	}
	for _, tc := range cases {
		hasher, err := configureHashing(0, memoryMaxFile(t, tc.limit), tc.cpus)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := hasher.Slots(); got != tc.wanted {
			t.Errorf("%s: %d slots, want %d", tc.name, got, tc.wanted)
		}
	}
}

func TestConfigureHashingKeepsAnExplicitSlotCount(t *testing.T) {
	hasher, err := configureHashing(3, memoryMaxFile(t, "1073741824"), 64)
	if err != nil || hasher.Slots() != 3 {
		t.Fatalf("slots=%v err=%v, want 3", hasher, err)
	}
}

func TestConfigureHashingWithoutALimitStillBoundsHashing(t *testing.T) {
	hasher, err := configureHashing(2, memoryMaxFile(t, "max"), 4)
	if err != nil || hasher == nil {
		t.Fatalf("hasher=%v err=%v", hasher, err)
	}
}
