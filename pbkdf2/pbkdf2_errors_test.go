package pbkdf2

import (
	"strings"
	"testing"
)

func TestPBKDF2EncodeRejectsDollarSaltSign(t *testing.T) {
	_, err := NewPBKDF2SHA256Hasher().Encode("admin", "bad$salt", 1000)
	if err != ErrSaltContainsDollarSign {
		t.Errorf("Expected ErrSaltContainsDollarSign, got: %v", err)
	}
}

func TestPBKDF2EncodeUsesDefaultIterationsWhenZero(t *testing.T) {
	h := NewPBKDF2SHA256Hasher()
	h.Iterations = 1234
	encoded, err := h.Encode("admin", "salt", 0)
	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}
	if !strings.HasPrefix(encoded, "pbkdf2_sha256$1234$salt$") {
		t.Errorf("Expected default iterations to be used, got: %s", encoded)
	}
}

func TestPBKDF2VerifyComponentMismatch(t *testing.T) {
	_, err := NewPBKDF2SHA256Hasher().Verify("admin", "pbkdf2_sha256$1000$saltonly")
	if err != ErrHashComponentMismatch {
		t.Errorf("Expected ErrHashComponentMismatch, got: %v", err)
	}
}

func TestPBKDF2VerifyAlgorithmMismatch(t *testing.T) {
	// SHA256 hasher fed a SHA1-encoded hash should refuse it.
	_, err := NewPBKDF2SHA256Hasher().Verify("admin", "pbkdf2_sha1$1000$salt$ZmFrZWhhc2g=")
	if err != ErrAlgorithmMismatch {
		t.Errorf("Expected ErrAlgorithmMismatch, got: %v", err)
	}
}

func TestPBKDF2VerifyUnreadableIterations(t *testing.T) {
	_, err := NewPBKDF2SHA256Hasher().Verify("admin", "pbkdf2_sha256$notanumber$salt$ZmFrZQ==")
	if err != ErrHashComponentUnreadable {
		t.Errorf("Expected ErrHashComponentUnreadable, got: %v", err)
	}
}

func TestPBKDF2DeprecatedAliasMatches(t *testing.T) {
	if ErrSaltContainsDollarSing != ErrSaltContainsDollarSign {
		t.Error("Deprecated alias must point at the canonical error")
	}
}

func TestPBKDF2WrongPasswordReturnsFalse(t *testing.T) {
	h := NewPBKDF2SHA256Hasher()
	encoded, err := h.Encode("right", "saltvalue", 1000)
	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}
	valid, err := h.Verify("wrong", encoded)
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if valid {
		t.Error("Wrong password should not validate")
	}
}
