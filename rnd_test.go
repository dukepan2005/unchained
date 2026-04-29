package unchained

import (
	"strings"
	"testing"
)

func TestGetRandomStringLength(t *testing.T) {
	for _, n := range []int{0, 1, 12, 40, 64, 128} {
		s := GetRandomString(n)
		if len(s) != n {
			t.Errorf("GetRandomString(%d) returned length %d", n, len(s))
		}
	}
}

func TestGetRandomStringCharset(t *testing.T) {
	s := GetRandomString(1024)
	for i, r := range s {
		if !strings.ContainsRune(allowedChars, r) {
			t.Fatalf("GetRandomString produced disallowed character %q at index %d", r, i)
		}
	}
}

func TestGetRandomStringUniqueness(t *testing.T) {
	// Two consecutive 24-char strings should virtually never collide;
	// the previous implementation reseeded math/rand from crypto/rand
	// per call, so this also guards against a regression of that pattern.
	a := GetRandomString(24)
	b := GetRandomString(24)
	if a == b {
		t.Fatalf("GetRandomString returned identical consecutive values: %q", a)
	}
}
