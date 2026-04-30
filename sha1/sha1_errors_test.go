package sha1

import "testing"

func TestSHA1EncodeRejectsEmptySalt(t *testing.T) {
	_, err := NewSHA1PasswordHasher().Encode("admin", "")
	if err != ErrSaltIsEmpty {
		t.Errorf("Expected ErrSaltIsEmpty, got: %v", err)
	}
}

func TestSHA1EncodeRejectsDollarSaltSign(t *testing.T) {
	_, err := NewSHA1PasswordHasher().Encode("admin", "bad$salt")
	if err != ErrSaltContainsDollarSign {
		t.Errorf("Expected ErrSaltContainsDollarSign, got: %v", err)
	}
}

func TestSHA1VerifyComponentMismatch(t *testing.T) {
	_, err := NewSHA1PasswordHasher().Verify("admin", "sha1$saltonly")
	if err != ErrHashComponentMismatch {
		t.Errorf("Expected ErrHashComponentMismatch, got: %v", err)
	}
}

func TestSHA1VerifyAlgorithmMismatch(t *testing.T) {
	_, err := NewSHA1PasswordHasher().Verify("admin", "md5$salt$abc")
	if err != ErrAlgorithmMismatch {
		t.Errorf("Expected ErrAlgorithmMismatch, got: %v", err)
	}
}

func TestUnsaltedSHA1Encode(t *testing.T) {
	// Salted == false branch: salt parameter must be ignored.
	encoded, err := NewUnsaltedSHA1PasswordHasher().Encode("admin", "ignored")
	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}
	expected := "sha1$$d033e22ae348aeb5660fc2140aec35850c4da997"
	if encoded != expected {
		t.Errorf("Expected %q, got %q", expected, encoded)
	}
}

func TestSHA1DeprecatedAliasMatches(t *testing.T) {
	if ErrSaltContainsDollarSing != ErrSaltContainsDollarSign {
		t.Error("Deprecated alias must point at the canonical error")
	}
}
