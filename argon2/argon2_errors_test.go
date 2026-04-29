package argon2

import "testing"

func TestArgon2VerifyComponentMismatch(t *testing.T) {
	_, err := NewArgon2idHasher().Verify("admin", "argon2$too$few$parts")
	if err != ErrHashComponentMismatch {
		t.Errorf("Expected ErrHashComponentMismatch, got: %v", err)
	}
}

func TestArgon2VerifyAlgorithmMismatch(t *testing.T) {
	// Six parts, but leading prefix isn't "argon2".
	_, err := NewArgon2idHasher().Verify("admin", "scrypt$argon2id$v=19$m=1,t=1,p=1$AAAA$AAAA")
	if err != ErrAlgorithmMismatch {
		t.Errorf("Expected ErrAlgorithmMismatch, got: %v", err)
	}
}

func TestArgon2VerifyUnreadableVersion(t *testing.T) {
	_, err := NewArgon2idHasher().Verify("admin", "argon2$argon2id$bogus$m=1,t=1,p=1$AAAA$AAAA")
	if err != ErrHashComponentUnreadable {
		t.Errorf("Expected ErrHashComponentUnreadable, got: %v", err)
	}
}

func TestArgon2VerifyIncompatibleVersion(t *testing.T) {
	_, err := NewArgon2idHasher().Verify("admin", "argon2$argon2id$v=99$m=1,t=1,p=1$AAAA$AAAA")
	if err != ErrIncompatibleVersion {
		t.Errorf("Expected ErrIncompatibleVersion, got: %v", err)
	}
}

func TestArgon2VerifyUnreadableParams(t *testing.T) {
	_, err := NewArgon2idHasher().Verify("admin", "argon2$argon2id$v=19$bogus$AAAA$AAAA")
	if err != ErrHashComponentUnreadable {
		t.Errorf("Expected ErrHashComponentUnreadable, got: %v", err)
	}
}

func TestArgon2VerifyUnreadableSalt(t *testing.T) {
	_, err := NewArgon2idHasher().Verify("admin", "argon2$argon2id$v=19$m=1,t=1,p=1$!!!notbase64!!!$AAAA")
	if err != ErrHashComponentUnreadable {
		t.Errorf("Expected ErrHashComponentUnreadable, got: %v", err)
	}
}

func TestArgon2VerifyUnreadableHash(t *testing.T) {
	_, err := NewArgon2idHasher().Verify("admin", "argon2$argon2id$v=19$m=1,t=1,p=1$AAAA$!!!notbase64!!!")
	if err != ErrHashComponentUnreadable {
		t.Errorf("Expected ErrHashComponentUnreadable, got: %v", err)
	}
}

func TestArgon2EncodeWithEmptyVariantDefaultsToArgon2id(t *testing.T) {
	h := &Argon2Hasher{
		Algorithm: "argon2",
		Variant:   "", // unset → should default to argon2id
		Time:      1,
		Memory:    8192,
		Threads:   1,
		Length:    16,
	}
	encoded, err := h.Encode("admin", "abcdefghijkl")
	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}
	const want = "argon2$argon2id$"
	if len(encoded) < len(want) || encoded[:len(want)] != want {
		t.Errorf("Expected default variant argon2id, got: %s", encoded)
	}
}

func TestArgon2EncodeRejectsUnsupportedVariant(t *testing.T) {
	h := &Argon2Hasher{
		Algorithm: "argon2",
		Variant:   "argon2d",
		Time:      1,
		Memory:    8192,
		Threads:   1,
		Length:    16,
	}
	_, err := h.Encode("admin", "salt")
	if err != ErrUnsupportedVariant {
		t.Errorf("Expected ErrUnsupportedVariant, got: %v", err)
	}
}

func TestNewArgon2HasherIsArgon2iAlias(t *testing.T) {
	h := NewArgon2Hasher()
	if h.Variant != VariantI {
		t.Errorf("NewArgon2Hasher (deprecated) should remain argon2i, got %q", h.Variant)
	}
}
