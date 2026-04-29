package md5

import "testing"

func TestMD5EncodeRejectsEmptySalt(t *testing.T) {
	_, err := NewMD5PasswordHasher().Encode("admin", "")
	if err != ErrSaltIsEmpty {
		t.Errorf("Expected ErrSaltIsEmpty, got: %v", err)
	}
}

func TestMD5EncodeRejectsDollarSaltSign(t *testing.T) {
	_, err := NewMD5PasswordHasher().Encode("admin", "bad$salt")
	if err != ErrSaltContainsDollarSign {
		t.Errorf("Expected ErrSaltContainsDollarSign, got: %v", err)
	}
}

func TestMD5VerifyComponentMismatch(t *testing.T) {
	_, err := NewMD5PasswordHasher().Verify("admin", "md5$saltonly")
	if err != ErrHashComponentMismatch {
		t.Errorf("Expected ErrHashComponentMismatch, got: %v", err)
	}
}

func TestMD5VerifyAlgorithmMismatch(t *testing.T) {
	_, err := NewMD5PasswordHasher().Verify("admin", "sha1$salt$abc")
	if err != ErrAlgorithmMismatch {
		t.Errorf("Expected ErrAlgorithmMismatch, got: %v", err)
	}
}

func TestUnsaltedMD5VerifyMD5PrefixForm(t *testing.T) {
	// "md5$$<32-hex>" prefix form should validate as if it were the bare hash.
	valid, err := NewUnsaltedMD5PasswordHasher().Verify("admin", "md5$$21232f297a57a5a743894a0e4a801fc3")
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if !valid {
		t.Error("Password should be valid in md5$$<hex> prefix form")
	}
}

func TestMD5DeprecatedAliasMatches(t *testing.T) {
	if ErrSaltContainsDollarSing != ErrSaltContainsDollarSign {
		t.Error("Deprecated alias must point at the canonical error")
	}
}
