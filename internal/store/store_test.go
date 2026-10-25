package store

import (
	"errors"
	"testing"
)

func TestPickAddressMatch(t *testing.T) {
	none := errors.New("no rows")
	if _, _, err := PickAddressMatch(nil, none); !errors.Is(err, none) {
		t.Fatalf("no match: %v", err)
	}
	for name, tc := range map[string]struct {
		matches  []AddressMatch
		id       int64
		verified bool
	}{
		"exact first":          {[]AddressMatch{{ID: 2, Exact: true, Verified: true}, {ID: 1}}, 2, true},
		"one in another case":  {[]AddressMatch{{ID: 3, Verified: false}}, 3, false},
		"exact and unverified": {[]AddressMatch{{ID: 4, Exact: true}, {ID: 5, Verified: true}}, 4, false},
	} {
		id, verified, err := PickAddressMatch(tc.matches, none)
		if err != nil || id != tc.id || verified != tc.verified {
			t.Errorf("%s: id=%d verified=%v err=%v", name, id, verified, err)
		}
	}
	if _, _, err := PickAddressMatch([]AddressMatch{{ID: 6}, {ID: 7}}, none); !errors.Is(err, ErrAmbiguousEmail) {
		t.Fatalf("two in other cases: %v", err)
	}
}
