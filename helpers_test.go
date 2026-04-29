package unchained

import (
	"strings"
	"testing"

	"github.com/alexandrevicenzi/unchained/argon2"
	"github.com/alexandrevicenzi/unchained/pbkdf2"
)

func TestIsValidHasher(t *testing.T) {
	valid := []string{
		Argon2Hasher, BCryptHasher, BCryptSHA256Hasher, CryptHasher,
		MD5Hasher, PBKDF2SHA1Hasher, PBKDF2SHA256Hasher, SHA1Hasher,
		UnsaltedMD5Hasher, UnsaltedSHA1Hasher,
	}
	for _, h := range valid {
		if !IsValidHasher(h) {
			t.Errorf("IsValidHasher(%q) = false, want true", h)
		}
	}

	invalid := []string{"", "scrypt", "unknown", "pbkdf2"}
	for _, h := range invalid {
		if IsValidHasher(h) {
			t.Errorf("IsValidHasher(%q) = true, want false", h)
		}
	}
}

func TestIsWeakHasher(t *testing.T) {
	weak := []string{CryptHasher, MD5Hasher, SHA1Hasher, UnsaltedMD5Hasher, UnsaltedSHA1Hasher}
	for _, h := range weak {
		if !IsWeakHasher(h) {
			t.Errorf("IsWeakHasher(%q) = false, want true", h)
		}
	}

	strong := []string{Argon2Hasher, BCryptHasher, BCryptSHA256Hasher, PBKDF2SHA1Hasher, PBKDF2SHA256Hasher}
	for _, h := range strong {
		if IsWeakHasher(h) {
			t.Errorf("IsWeakHasher(%q) = true, want false", h)
		}
	}
}

func TestIsHasherImplemented(t *testing.T) {
	implemented := []string{
		Argon2Hasher, BCryptHasher, BCryptSHA256Hasher, MD5Hasher,
		PBKDF2SHA1Hasher, PBKDF2SHA256Hasher, SHA1Hasher,
		UnsaltedMD5Hasher, UnsaltedSHA1Hasher,
	}
	for _, h := range implemented {
		if !IsHasherImplemented(h) {
			t.Errorf("IsHasherImplemented(%q) = false, want true", h)
		}
	}

	notImplemented := []string{CryptHasher, "scrypt", "unknown"}
	for _, h := range notImplemented {
		if IsHasherImplemented(h) {
			t.Errorf("IsHasherImplemented(%q) = true, want false", h)
		}
	}
}

func TestIdentifyHasherEdgeCases(t *testing.T) {
	cases := map[string]string{
		// 32-char hex with no $ → unsalted_md5
		"21232f297a57a5a743894a0e4a801fc3": UnsaltedMD5Hasher,
		// "md5$$<32-hex>" prefix-form unsalted_md5 (37 chars)
		"md5$$21232f297a57a5a743894a0e4a801fc3": UnsaltedMD5Hasher,
		// "sha1$$<40-hex>" prefix-form unsalted_sha1 (46 chars)
		"sha1$$d033e22ae348aeb5660fc2140aec35850c4da997": UnsaltedSHA1Hasher,
		// Generic prefix split
		"pbkdf2_sha256$1000$abc$def": PBKDF2SHA256Hasher,
		"argon2$argon2id$v=19$m=1$t=1$p=1$AAAA$AAAA": Argon2Hasher,
	}
	for encoded, want := range cases {
		if got := IdentifyHasher(encoded); got != want {
			t.Errorf("IdentifyHasher(%q) = %q, want %q", encoded, got, want)
		}
	}
}

func TestMakePasswordEmptyPasswordReturnsUnusable(t *testing.T) {
	encoded, err := MakePassword("", "salt", "default")
	if err != nil {
		t.Fatalf("MakePassword error: %s", err)
	}
	if !strings.HasPrefix(encoded, UnusablePasswordPrefix) {
		t.Errorf("Expected unusable prefix, got: %s", encoded)
	}
	if len(encoded) != len(UnusablePasswordPrefix)+UnusablePasswordSuffixLength {
		t.Errorf("Unusable password has wrong length: %d", len(encoded))
	}
	if IsPasswordUsable(encoded) {
		t.Errorf("Generated unusable password should not be usable")
	}
}

func TestMakePasswordInvalidHasher(t *testing.T) {
	_, err := MakePassword("admin", "salt", "totally-fake-hasher")
	if err != ErrInvalidHasher {
		t.Errorf("Expected ErrInvalidHasher, got: %v", err)
	}
}

func TestMakePasswordHasherNotImplemented(t *testing.T) {
	_, err := MakePassword("admin", "salt", CryptHasher)
	if err != ErrHasherNotImplemented {
		t.Errorf("Expected ErrHasherNotImplemented, got: %v", err)
	}
}

func TestCheckPasswordInvalidHasher(t *testing.T) {
	_, err := CheckPassword("admin", "totally-fake-hasher$abc$def")
	if err != ErrInvalidHasher {
		t.Errorf("Expected ErrInvalidHasher, got: %v", err)
	}
}

func TestCheckPasswordHasherNotImplemented(t *testing.T) {
	_, err := CheckPassword("admin", "crypt$abc$def")
	if err != ErrHasherNotImplemented {
		t.Errorf("Expected ErrHasherNotImplemented, got: %v", err)
	}
}

func TestCheckPasswordUnusable(t *testing.T) {
	valid, err := CheckPassword("admin", "!unusable")
	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}
	if valid {
		t.Errorf("Unusable password should never validate")
	}

	valid, err = CheckPassword("admin", "")
	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}
	if valid {
		t.Errorf("Empty password should never validate")
	}
}

func TestCheckPasswordPropagatesArgon2Error(t *testing.T) {
	// Truncated argon2 hash — the inner hasher's ErrHashComponentMismatch
	// must surface through CheckPassword instead of being swallowed.
	_, err := CheckPassword("admin", "argon2$argon2id$v=19$m=1,t=1,p=1")
	if err != argon2.ErrHashComponentMismatch {
		t.Errorf("Expected argon2.ErrHashComponentMismatch, got: %v", err)
	}
}

func TestCheckPasswordPropagatesPBKDF2Error(t *testing.T) {
	// Truncated pbkdf2 hash — pbkdf2.ErrHashComponentMismatch must surface.
	_, err := CheckPassword("admin", "pbkdf2_sha256$1000$saltonly")
	if err != pbkdf2.ErrHashComponentMismatch {
		t.Errorf("Expected pbkdf2.ErrHashComponentMismatch, got: %v", err)
	}
}

func TestCheckPasswordWrongPasswordReturnsFalse(t *testing.T) {
	encoded, err := MakePassword("right-password", "saltsaltsalt", "default")
	if err != nil {
		t.Fatalf("MakePassword error: %s", err)
	}
	valid, err := CheckPassword("wrong-password", encoded)
	if err != nil {
		t.Fatalf("CheckPassword error: %s", err)
	}
	if valid {
		t.Errorf("Wrong password should not validate")
	}
}
