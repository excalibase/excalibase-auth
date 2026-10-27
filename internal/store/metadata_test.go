package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func patchOf(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	patch, err := ParseMetadataPatch([]byte(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return patch
}

func TestMergeMetadataReplacesTopLevelKeysAndNullRemovesOne(t *testing.T) {
	merged, err := MergeMetadata([]byte(`{"plan":"free","theme":{"dark":true},"drop":1}`),
		patchOf(t, `{"plan":"pro","drop":null,"new":[1,2]}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(merged) != `{"new":[1,2],"plan":"pro","theme":{"dark":true}}` {
		t.Fatalf("merged = %s", merged)
	}
}

func TestMergeMetadataReadsNothingStoredAsEmpty(t *testing.T) {
	for _, stored := range []string{"", "null"} {
		merged, err := MergeMetadata([]byte(stored), patchOf(t, `{"a":1}`))
		if err != nil || string(merged) != `{"a":1}` {
			t.Fatalf("from %q: %s %v", stored, merged, err)
		}
	}
}

func TestMergeMetadataRefusesAResultPastTheLimit(t *testing.T) {
	big := `{"blob":"` + strings.Repeat("x", MaxMetadataBytes) + `"}`
	if _, err := MergeMetadata(nil, patchOf(t, big)); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("err = %v, want ErrMetadataTooLarge", err)
	}
	half := `{"a":"` + strings.Repeat("x", MaxMetadataBytes/2) + `"}`
	stored, err := MergeMetadata(nil, patchOf(t, half))
	if err != nil {
		t.Fatal(err)
	}
	other := `{"b":"` + strings.Repeat("y", MaxMetadataBytes/2) + `"}`
	if _, err := MergeMetadata(stored, patchOf(t, other)); !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("two halves merged: %v", err)
	}
}

func TestParseMetadataPatchRefusesAnythingButAShallowEnoughObject(t *testing.T) {
	deep := strings.Repeat(`{"a":`, MaxMetadataDepth+1) + "1" + strings.Repeat("}", MaxMetadataDepth+1)
	for _, raw := range []string{`[1]`, `"x"`, `null`, `1`, `{"a":1`, `{"a":1} {}`, deep} {
		if _, err := ParseMetadataPatch([]byte(raw)); !errors.Is(err, ErrInvalidMetadata) {
			t.Errorf("%.40s: err = %v, want ErrInvalidMetadata", raw, err)
		}
	}
	ok := strings.Repeat(`{"a":`, MaxMetadataDepth) + "1" + strings.Repeat("}", MaxMetadataDepth)
	if _, err := ParseMetadataPatch([]byte(ok)); err != nil {
		t.Errorf("depth %d refused: %v", MaxMetadataDepth, err)
	}
}

func TestMetadataObjectReadsNullAsEmpty(t *testing.T) {
	if got := string(MetadataObject(nil)); got != "{}" {
		t.Fatalf("nil reads as %s", got)
	}
	if got := string(MetadataObject([]byte(`{"a": 1}`))); got != `{"a": 1}` {
		t.Fatalf("stored reads as %s", got)
	}
}
