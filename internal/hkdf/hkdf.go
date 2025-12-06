package hkdf

import (
	"crypto/hkdf"
	"hash"
)

// Extract wraps crypto/hkdf.Extract and returns any error.
//
// Errors from hkdf.Extract occur due to:
// - nil hash function
// - invalid hash state
// These conditions typically indicate programming bugs, but returning an error
// allows callers to handle them gracefully rather than crashing.
func Extract[H hash.Hash](h func() H, secret, salt []byte) ([]byte, error) {
	return hkdf.Extract(h, secret, salt)
}

// Expand wraps crypto/hkdf.Expand and returns any error.
//
// Errors from hkdf.Expand occur due to:
// - nil hash function
// - keyLength <= 0 or keyLength > 255*hash.Size()
// These conditions typically indicate programming bugs, but returning an error
// allows callers to handle them gracefully rather than crashing.
func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLength int) ([]byte, error) {
	return hkdf.Expand(h, pseudorandomKey, info, keyLength)
}
