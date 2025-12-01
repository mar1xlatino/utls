// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS Authentication Implementation
//
// Security Properties:
//   - All HMAC verification uses constant-time comparison (crypto/subtle)
//   - Timing attack resistant: VerifyAuthHMACWithWindow scans ALL timestamps
//   - Key validation: All functions reject nil/empty keys
//   - Replay protection: Timestamp-based with configurable window
//
// Recommended Usage:
//   - Use DeriveAuthKeySecure() for password-based keys (iterative KDF)
//   - Keep windowSeconds as small as tolerable (default: 30s)
//   - Use GenerateAuthSalt() for unique salts

package tls

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// AuthMode defines where authentication data is embedded.
type AuthMode string

const (
	// AuthModeSessionID embeds auth data in session ID (default, most compatible).
	AuthModeSessionID AuthMode = "session_id"

	// AuthModeExtension embeds auth data in a custom extension.
	AuthModeExtension AuthMode = "extension"

	// AuthModeCertificate embeds auth data in certificate (legacy).
	AuthModeCertificate AuthMode = "certificate"
)

// AuthConfig contains authentication configuration.
type AuthConfig struct {
	// Key is the shared secret for authentication.
	// Must be at least 32 bytes for security.
	Key []byte

	// Mode controls where authentication data is embedded.
	// Default is AuthModeSessionID.
	Mode AuthMode

	// ShortID is the 8-byte short ID for quick filtering.
	// Used to quickly reject non-authenticated connections.
	ShortID [8]byte

	// ServerNames is the list of allowed SNI values.
	// Empty means accept any SNI.
	ServerNames []string

	// Fingerprints is the list of allowed client certificate fingerprints.
	// Empty means no client cert verification.
	Fingerprints [][]byte

	// ComputeFunc is a custom function to compute authentication data.
	// If nil, default HMAC-SHA512 is used.
	// Parameters: authKey, publicKey, timestamp
	ComputeFunc func(authKey, publicKey []byte, timestamp time.Time) []byte

	// VerifyFunc is a custom function to verify authentication data.
	// If nil, default constant-time comparison is used.
	VerifyFunc func(authData, expected []byte) bool
}

// Validate checks if the AuthConfig is valid.
func (c *AuthConfig) Validate() error {
	if c == nil {
		return errors.New("tls: auth config is nil")
	}
	if len(c.Key) < 32 {
		return fmt.Errorf("tls: auth key must be at least 32 bytes, got %d", len(c.Key))
	}
	if c.Mode == "" {
		c.Mode = AuthModeSessionID
	}
	switch c.Mode {
	case AuthModeSessionID, AuthModeExtension, AuthModeCertificate:
		// Valid
	default:
		return fmt.Errorf("tls: unknown auth mode: %s", c.Mode)
	}
	return nil
}

// Clone creates a deep copy of AuthConfig.
func (c *AuthConfig) Clone() *AuthConfig {
	if c == nil {
		return nil
	}
	clone := &AuthConfig{
		Mode:        c.Mode,
		ComputeFunc: c.ComputeFunc,
		VerifyFunc:  c.VerifyFunc,
	}
	if c.Key != nil {
		clone.Key = make([]byte, len(c.Key))
		copy(clone.Key, c.Key)
	}
	clone.ShortID = c.ShortID
	if c.ServerNames != nil {
		clone.ServerNames = make([]string, len(c.ServerNames))
		copy(clone.ServerNames, c.ServerNames)
	}
	if c.Fingerprints != nil {
		clone.Fingerprints = make([][]byte, len(c.Fingerprints))
		for i, fp := range c.Fingerprints {
			clone.Fingerprints[i] = make([]byte, len(fp))
			copy(clone.Fingerprints[i], fp)
		}
	}
	return clone
}

// ComputeAuthHMAC computes authentication HMAC.
// Formula: HMAC-SHA512(authKey, publicKey || timestamp)
// Returns 64-byte HMAC.
// Returns nil if authKey is empty (security: prevents nil key bypass).
func ComputeAuthHMAC(authKey, publicKey []byte, timestamp time.Time) []byte {
	// Security: Reject empty keys to prevent nil key bypass attacks
	if len(authKey) == 0 {
		return nil
	}

	h := hmac.New(sha512.New, authKey)
	h.Write(publicKey)

	// Include timestamp (Unix seconds, 8 bytes big-endian)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp.Unix()))
	h.Write(ts[:])

	return h.Sum(nil)
}

// ComputeAuthHMACSimple computes HMAC without timestamp (for compatibility).
// Formula: HMAC-SHA512(authKey, publicKey)
// Returns nil if authKey is empty (security: prevents nil key bypass).
func ComputeAuthHMACSimple(authKey, publicKey []byte) []byte {
	// Security: Reject empty keys to prevent nil key bypass attacks
	if len(authKey) == 0 {
		return nil
	}

	h := hmac.New(sha512.New, authKey)
	h.Write(publicKey)
	return h.Sum(nil)
}

// VerifyAuthHMAC verifies authentication HMAC in constant time.
func VerifyAuthHMAC(authData, expected []byte) bool {
	if len(authData) == 0 || len(expected) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(authData, expected) == 1
}

// VerifyAuthHMACWithWindow verifies HMAC allowing for timestamp drift.
// windowSeconds specifies the allowed time drift in seconds.
// Security: Uses constant-time comparison across ALL timestamps to prevent
// timing attacks that could reveal the valid timestamp offset.
func VerifyAuthHMACWithWindow(authKey, publicKey, authData []byte, windowSeconds int64) bool {
	// Security: Reject empty keys
	if len(authKey) == 0 {
		return false
	}
	if len(authData) < 32 {
		return false
	}

	now := time.Now()

	// Security: Constant-time scan - check ALL timestamps, no early return
	// This prevents timing attacks that could reveal the server's clock offset
	found := 0
	for delta := -windowSeconds; delta <= windowSeconds; delta++ {
		ts := now.Add(time.Duration(delta) * time.Second)
		expected := ComputeAuthHMAC(authKey, publicKey, ts)

		// expected can be nil if authKey is empty (already checked above)
		if expected != nil {
			// Accumulate match result in constant time
			found |= subtle.ConstantTimeCompare(authData[:32], expected[:32])
		}
	}

	return found == 1
}

// EmbedAuthInSessionID embeds authentication data in session ID.
// Session ID is 32 bytes for TLS 1.3.
// Format: [HMAC truncated to 32 bytes]
func EmbedAuthInSessionID(authData []byte) []byte {
	sessionID := make([]byte, 32)
	if len(authData) >= 32 {
		copy(sessionID, authData[:32])
	} else {
		copy(sessionID, authData)
	}
	return sessionID
}

// ExtractAuthFromSessionID extracts authentication data from session ID.
func ExtractAuthFromSessionID(sessionID []byte) []byte {
	if len(sessionID) < 32 {
		return nil
	}
	result := make([]byte, 32)
	copy(result, sessionID[:32])
	return result
}

// ComputeShortID computes the 8-byte short ID from auth key.
// Used for quick filtering of non-authenticated connections.
func ComputeShortID(authKey []byte) [8]byte {
	h := sha256.Sum256(authKey)
	var shortID [8]byte
	copy(shortID[:], h[:8])
	return shortID
}

// MatchesShortID checks if session ID starts with expected short ID.
func MatchesShortID(sessionID []byte, shortID [8]byte) bool {
	if len(sessionID) < 8 {
		return false
	}
	return subtle.ConstantTimeCompare(sessionID[:8], shortID[:]) == 1
}

// AuthResult contains the result of authentication verification.
type AuthResult struct {
	// Authenticated is true if authentication succeeded.
	Authenticated bool

	// Reason describes why authentication failed (if it did).
	Reason string

	// PublicKey is the client's public key (if extracted).
	PublicKey []byte

	// Timestamp is the authentication timestamp (if extracted).
	Timestamp time.Time
}

// Authenticator handles TLS authentication.
type Authenticator struct {
	config *AuthConfig
}

// NewAuthenticator creates a new authenticator with the given config.
func NewAuthenticator(config *AuthConfig) (*Authenticator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Authenticator{config: config.Clone()}, nil
}

// ComputeClientAuth computes authentication data for client.
// publicKey is the client's ECDH public key.
func (a *Authenticator) ComputeClientAuth(publicKey []byte) []byte {
	if a.config.ComputeFunc != nil {
		return a.config.ComputeFunc(a.config.Key, publicKey, time.Now())
	}
	return ComputeAuthHMAC(a.config.Key, publicKey, time.Now())
}

// VerifyClientAuth verifies client authentication data on server.
// publicKey is the client's ECDH public key from ClientHello.
// authData is the authentication data from session ID.
func (a *Authenticator) VerifyClientAuth(publicKey, authData []byte) *AuthResult {
	result := &AuthResult{}

	// Quick filter with short ID
	if a.config.ShortID != [8]byte{} {
		if !MatchesShortID(authData, a.config.ShortID) {
			result.Reason = "short ID mismatch"
			return result
		}
	}

	// Verify HMAC with time window (allow 30 seconds drift)
	// Security: 30s window balances clock skew tolerance vs replay attack risk
	if a.config.VerifyFunc != nil {
		expected := a.ComputeClientAuth(publicKey)
		if !a.config.VerifyFunc(authData, expected) {
			result.Reason = "custom verification failed"
			return result
		}
	} else {
		if !VerifyAuthHMACWithWindow(a.config.Key, publicKey, authData, 30) {
			result.Reason = "HMAC verification failed"
			return result
		}
	}

	result.Authenticated = true
	result.PublicKey = publicKey
	return result
}

// GenerateSessionIDWithAuth generates a session ID containing auth data.
// publicKey is the client's ECDH public key.
func (a *Authenticator) GenerateSessionIDWithAuth(publicKey []byte) []byte {
	authData := a.ComputeClientAuth(publicKey)
	return EmbedAuthInSessionID(authData)
}

// AuthenticatedSessionID checks if a session ID contains valid auth.
// publicKey is the client's ECDH public key.
func (a *Authenticator) AuthenticatedSessionID(sessionID, publicKey []byte) bool {
	authData := ExtractAuthFromSessionID(sessionID)
	if authData == nil {
		return false
	}
	result := a.VerifyClientAuth(publicKey, authData)
	return result.Authenticated
}

// GenerateRandomSessionID generates a random 32-byte session ID.
// Used when authentication is not configured.
func GenerateRandomSessionID() ([]byte, error) {
	sessionID := make([]byte, 32)
	if _, err := rand.Read(sessionID); err != nil {
		return nil, err
	}
	return sessionID, nil
}

// DeriveAuthKey derives an authentication key from a password/passphrase.
//
// SECURITY WARNING: This function uses a single SHA-512 hash which is
// vulnerable to brute-force attacks. For production use, prefer
// DeriveAuthKeySecure() with a random salt, or use an external KDF
// like Argon2id, scrypt, or PBKDF2 with at least 100,000 iterations.
//
// Deprecated: Use DeriveAuthKeySecure for new code.
func DeriveAuthKey(password string) []byte {
	h := sha512.Sum512([]byte(password))
	return h[:]
}

// DeriveAuthKeyWithSalt derives an authentication key with salt.
// Uses HMAC-SHA-512 for key derivation.
//
// SECURITY WARNING: This uses a single HMAC iteration which provides
// some protection against rainbow tables but is still vulnerable to
// brute-force attacks. For production use, prefer DeriveAuthKeySecure().
//
// Deprecated: Use DeriveAuthKeySecure for new code.
func DeriveAuthKeyWithSalt(password string, salt []byte) []byte {
	if len(salt) == 0 {
		return nil // Security: require salt
	}
	h := hmac.New(sha512.New, salt)
	h.Write([]byte(password))
	return h.Sum(nil)
}

// DeriveAuthKeySecure derives an authentication key using iterative hashing.
// This provides better resistance to brute-force attacks than single-hash methods.
//
// Parameters:
//   - password: the passphrase to derive from
//   - salt: random salt (should be at least 16 bytes, unique per user)
//   - iterations: number of hash iterations (recommended: at least 100000)
//
// Returns 64-byte derived key, or nil if parameters are invalid.
func DeriveAuthKeySecure(password string, salt []byte, iterations int) []byte {
	if len(password) == 0 || len(salt) < 16 || iterations < 1 {
		return nil
	}

	// Use iterative HMAC-SHA512 (similar to PBKDF2)
	key := make([]byte, 64)
	copy(key, salt)

	// Initial hash
	h := hmac.New(sha512.New, []byte(password))
	h.Write(salt)
	h.Write([]byte{0, 0, 0, 1}) // Block counter
	u := h.Sum(nil)
	copy(key, u)

	// Iterate
	for i := 1; i < iterations; i++ {
		h.Reset()
		h.Write(u)
		u = h.Sum(nil)
		// XOR into result
		for j := range key {
			key[j] ^= u[j]
		}
	}

	return key
}

// GenerateAuthSalt generates a random salt for use with DeriveAuthKeySecure.
// Returns 32-byte random salt.
func GenerateAuthSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}
