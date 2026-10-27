package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	// MaxMetadataBytes bounds one metadata object as stored (compact JSON).
	MaxMetadataBytes = 16 << 10
	// MaxMetadataDepth bounds how deep objects and arrays nest, the outer object included.
	MaxMetadataDepth = 8
)

// ErrInvalidMetadata means a metadata patch is not a JSON object within the depth limit.
var ErrInvalidMetadata = errors.New("metadata must be a JSON object")

// ErrMetadataTooLarge means the merged metadata would pass MaxMetadataBytes.
var ErrMetadataTooLarge = errors.New("metadata is too large")

// ParseMetadataPatch reads a patch: a JSON object whose top-level keys replace
// the stored ones, a null value removing its key.
func ParseMetadataPatch(raw []byte) (map[string]json.RawMessage, error) {
	if !withinDepth(raw) {
		return nil, ErrInvalidMetadata
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var patch map[string]json.RawMessage
	if err := decoder.Decode(&patch); err != nil || patch == nil {
		return nil, ErrInvalidMetadata
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidMetadata
	}
	return patch, nil
}

// withinDepth walks the tokens, so a deep document is refused before it is decoded.
func withinDepth(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return true
		}
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			if depth++; depth > MaxMetadataDepth {
				return false
			}
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
}

// MergeMetadata applies a patch to stored metadata (nil or JSON null reads as
// empty) and returns the compact result.
func MergeMetadata(stored []byte, patch map[string]json.RawMessage) ([]byte, error) {
	current := map[string]json.RawMessage{}
	if len(stored) > 0 {
		if err := json.Unmarshal(stored, &current); err != nil {
			return nil, err
		}
		if current == nil {
			current = map[string]json.RawMessage{}
		}
	}
	for key, value := range patch {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			delete(current, key)
			continue
		}
		current[key] = value
	}
	merged, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, merged); err != nil {
		return nil, err
	}
	if compact.Len() > MaxMetadataBytes {
		return nil, ErrMetadataTooLarge
	}
	return compact.Bytes(), nil
}

// MetadataObject is stored metadata as the API answers it: never null.
func MetadataObject(stored []byte) json.RawMessage {
	if len(stored) == 0 || bytes.Equal(stored, []byte("null")) {
		return json.RawMessage("{}")
	}
	return json.RawMessage(stored)
}
