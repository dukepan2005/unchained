package unchained

import (
	"crypto/rand"
	"encoding/binary"
)

const allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GetRandomString returns a cryptographically secure random string of the
// given length composed of characters from [a-zA-Z0-9].
//
// It panics if the system's secure random source is unavailable, mirroring
// Go's stdlib convention for cryptographic primitives whose failure is
// effectively unrecoverable.
func GetRandomString(length int) string {
	if length <= 0 {
		return ""
	}

	n := uint32(len(allowedChars))
	// Threshold for unbiased rejection sampling: discard any uint32 value
	// that would cause modulo bias.
	maxAcceptable := (uint32(1<<32-1)/n)*n + n
	if maxAcceptable < n {
		// Overflowed (n is a power of two divisor of 2^32); no bias possible.
		maxAcceptable = 0
	}

	out := make([]byte, length)
	// 4 bytes per character, with a generous overhead for rejection.
	bufSize := length * 8
	if bufSize < 32 {
		bufSize = 32
	}
	buf := make([]byte, bufSize)

	if _, err := rand.Read(buf); err != nil {
		panic("unchained: crypto/rand read failed: " + err.Error())
	}

	pos, bufIdx := 0, 0
	for pos < length {
		if bufIdx+4 > len(buf) {
			if _, err := rand.Read(buf); err != nil {
				panic("unchained: crypto/rand read failed: " + err.Error())
			}
			bufIdx = 0
		}
		v := binary.LittleEndian.Uint32(buf[bufIdx:])
		bufIdx += 4
		if maxAcceptable == 0 || v < maxAcceptable {
			out[pos] = allowedChars[v%n]
			pos++
		}
	}
	return string(out)
}
