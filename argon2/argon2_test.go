package argon2

import (
	"strings"
	"testing"
)

func TestArgon2Encode1(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("admin", "6qY4lfA15naU")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Encode2(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("this-is-my-password", "h8lI73ohfXug")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$aDhsSTczb2hmWHVn$TPhJYMg9pKQauvPF4RPH8A"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Encode3(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("Th1S1sMYp4ssw0rd", "HUxfcH4lx2SP")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$SFV4ZmNINGx4MlNQ$fEh86SVdKL6mqx+pRDHOlg"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Encode4(t *testing.T) {
	encoded, err := NewArgon2Hasher().Encode("this$is#my@PASSWORD", "0iHb4EQbyJzL")

	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}

	expected := "argon2$argon2i$v=19$m=512,t=2,p=2$MGlIYjRFUWJ5SnpM$NMBj1EpUCdu+TGsTLdAyfw"

	if encoded != expected {
		t.Fatalf("Encoded hash %s does not match %s.", encoded, expected)
	}
}

func TestArgon2Verify1(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("admin", "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2Verify2(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("this-is-my-password", "argon2$argon2i$v=19$m=512,t=2,p=2$aDhsSTczb2hmWHVn$TPhJYMg9pKQauvPF4RPH8A")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2Verify3(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("Th1S1sMYp4ssw0rd", "argon2$argon2i$v=19$m=512,t=2,p=2$SFV4ZmNINGx4MlNQ$fEh86SVdKL6mqx+pRDHOlg")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2Verify4(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("this$is#my@PASSWORD", "argon2$argon2i$v=19$m=512,t=2,p=2$MGlIYjRFUWJ5SnpM$NMBj1EpUCdu+TGsTLdAyfw")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2VerifyInvalidPassword(t *testing.T) {
	valid, err := NewArgon2Hasher().Verify("wrongpassword", "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w")

	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}

	if valid {
		t.Fatal("Password should not be valid.")
	}
}

func TestArgon2idEncodeAndVerifyRoundTrip(t *testing.T) {
	h := NewArgon2idHasher()
	// Use weaker params for the test to keep CI fast.
	h.Memory = 8192
	h.Threads = 1
	h.Time = 1

	encoded, err := h.Encode("hello-world", "abcdefghijkl")
	if err != nil {
		t.Fatalf("Encode error: %s", err)
	}
	if !strings.HasPrefix(encoded, "argon2$argon2id$v=19$") {
		t.Fatalf("Expected argon2id prefix, got: %s", encoded)
	}

	valid, err := h.Verify("hello-world", encoded)
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if !valid {
		t.Fatal("Password should be valid.")
	}

	valid, err = h.Verify("wrong-password", encoded)
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if valid {
		t.Fatal("Password should not be valid.")
	}
}

func TestArgon2idHasherVerifiesArgon2iHash(t *testing.T) {
	// Verify is variant-agnostic: argon2id hasher should validate an argon2i
	// hash because the variant is auto-detected from the encoded string.
	valid, err := NewArgon2idHasher().Verify("admin", "argon2$argon2i$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w")
	if err != nil {
		t.Fatalf("Verify error: %s", err)
	}
	if !valid {
		t.Fatal("Password should be valid.")
	}
}

func TestArgon2VerifyUnsupportedVariant(t *testing.T) {
	_, err := NewArgon2Hasher().Verify("admin", "argon2$argon2d$v=19$m=512,t=2,p=2$NnFZNGxmQTE1bmFV$kPPGrqD6dnRllcQeksFN+w")
	if err != ErrUnsupportedVariant {
		t.Fatalf("Expected ErrUnsupportedVariant, got: %v", err)
	}
}
