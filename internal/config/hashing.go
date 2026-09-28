package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/excalibase/auth/internal/auth"
)

// CgroupMemoryMax is where cgroup v2 publishes the container's memory limit.
const CgroupMemoryMax = "/sys/fs/cgroup/memory.max"

func parseHashConcurrency(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return auth.DefaultHashSlots, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("must be a whole number of at least 1, got %q", raw)
	}
	return n, nil
}

func hashConcurrency() int {
	n, err := parseHashConcurrency(os.Getenv("PASSWORD_HASH_CONCURRENCY"))
	if err != nil {
		log.Fatalf("PASSWORD_HASH_CONCURRENCY: %v", err)
	}
	return n
}

// MemoryLimitBytes reads a cgroup v2 memory.max file. No file (not in a
// cgroup v2 container) and "max" both mean no limit, reported as 0.
func MemoryLimitBytes(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(raw))
	if value == "max" {
		return 0, nil
	}
	limit, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("memory limit %q in %s: %w", value, path, err)
	}
	return limit, nil
}
