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
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Deprecation warning guards - log once per process lifetime
var (
	deriveAuthKeyDeprecatedOnce         sync.Once
	deriveAuthKeyWithSaltDeprecatedOnce sync.Once
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
	//
	// Deprecated when UseEntropyShortID is true: entropy-enhanced short IDs
	// are computed per-connection and don't use this static value.
	ShortID [8]byte

	// UseEntropyShortID enables per-connection entropy in short ID computation.
	// When true, each connection generates a unique short ID using:
	//   HMAC-SHA256(authKey, timestamp || nonce)[:8]
	//
	// This prevents passive clustering detection where observers can identify
	// all REALITY connections sharing the same auth key by their identical
	// 8-byte session ID prefix.
	//
	// Tradeoffs:
	//   - Client: Slightly more CPU (one additional HMAC per connection)
	//   - Server: Significantly more CPU (601 HMACs per verification to scan window)
	//   - Security: Prevents clustering-based fingerprinting
	//
	// Recommended: Enable for deployments where fingerprint resistance is critical.
	// Default: false (for backwards compatibility)
	UseEntropyShortID bool

	// ShortIDWindowSeconds specifies the timestamp window for entropy short ID
	// verification. Only used when UseEntropyShortID is true.
	// Default: 30 seconds. Maximum: 300 seconds.
	ShortIDWindowSeconds int64

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
	// If nil, the default constant-time HMAC comparison is used.
	//
	// SECURITY CRITICAL: If you provide a custom VerifyFunc, it MUST use
	// constant-time comparison (e.g., subtle.ConstantTimeCompare) to prevent
	// timing attacks. Non-constant-time comparisons (like bytes.Equal or ==)
	// will leak information about the expected value through timing differences.
	//
	// Example of a SECURE implementation:
	//
	//	func(authData, expected []byte) bool {
	//	    return subtle.ConstantTimeCompare(authData, expected) == 1
	//	}
	//
	// Example of an INSECURE implementation (DO NOT USE):
	//
	//	func(authData, expected []byte) bool {
	//	    return bytes.Equal(authData, expected)  // VULNERABLE TO TIMING ATTACK
	//	}
	//
	// If in doubt, leave this nil to use the secure default implementation.
	VerifyFunc func(authData, expected []byte) bool
}

// Validate checks if the AuthConfig is valid.
// This method is read-only and does not modify the config.
// Use ApplyDefaults() to set default values before or after validation.
//
// Thread Safety: This method is safe to call concurrently as it performs
// no mutations. However, concurrent reads with writes to the same config
// from other goroutines are not safe.
func (c *AuthConfig) Validate() error {
	if c == nil {
		return errors.New("tls: auth config is nil")
	}
	if len(c.Key) < 32 {
		return fmt.Errorf("tls: auth key must be at least 32 bytes, got %d", len(c.Key))
	}
	switch c.Mode {
	case "", AuthModeSessionID, AuthModeExtension, AuthModeCertificate:
		// Valid: empty string is accepted (defaults to AuthModeSessionID when used)
	default:
		return fmt.Errorf("tls: unknown auth mode: %s", c.Mode)
	}
	return nil
}

// ApplyDefaults sets default values for unspecified fields.
// This method mutates the config and should be called before using the config.
// Returns the config for method chaining.
//
// Defaults applied:
//   - Mode: AuthModeSessionID (if empty)
//
// Thread Safety: This method mutates the config. Concurrent calls to ApplyDefaults
// or concurrent reads while ApplyDefaults is running are not safe. Callers should
// ensure proper synchronization or use Clone() to create independent copies.
func (c *AuthConfig) ApplyDefaults() *AuthConfig {
	if c == nil {
		return nil
	}
	if c.Mode == "" {
		c.Mode = AuthModeSessionID
	}
	// Default window for entropy short ID verification
	if c.UseEntropyShortID && c.ShortIDWindowSeconds == 0 {
		c.ShortIDWindowSeconds = 30 // 30 seconds default
	}
	return c
}

// Clone creates a deep copy of AuthConfig.
func (c *AuthConfig) Clone() *AuthConfig {
	if c == nil {
		return nil
	}
	clone := &AuthConfig{
		Mode:                 c.Mode,
		UseEntropyShortID:    c.UseEntropyShortID,
		ShortIDWindowSeconds: c.ShortIDWindowSeconds,
		ComputeFunc:          c.ComputeFunc,
		VerifyFunc:           c.VerifyFunc,
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

// maxAuthWindowSeconds defines the fixed maximum window size used for iteration.
// This ensures constant-time execution regardless of the actual windowSeconds
// parameter, preventing timing attacks that could reveal the configured window.
const maxAuthWindowSeconds int64 = 300 // 5 minutes max

// VerifyAuthHMACWithWindow verifies HMAC allowing for timestamp drift.
// windowSeconds specifies the allowed time drift in seconds (max 300s/5min).
//
// Security Properties:
//   - Uses constant-time comparison across ALL timestamps to prevent timing
//     attacks that could reveal the valid timestamp offset.
//   - Always iterates over maxAuthWindowSeconds*2+1 timestamps regardless of
//     actual windowSeconds to prevent timing attacks that reveal window size.
//   - The specific matching timestamp is not revealed through timing.
//
// Parameters:
//   - windowSeconds: actual window to accept (capped at maxAuthWindowSeconds)
//   - Iteration count is always fixed at (2*maxAuthWindowSeconds + 1)
func VerifyAuthHMACWithWindow(authKey, publicKey, authData []byte, windowSeconds int64) bool {
	// Security: Reject empty keys
	if len(authKey) == 0 {
		return false
	}
	if len(authData) < 32 {
		return false
	}

	// Cap windowSeconds to prevent excessive computation
	if windowSeconds > maxAuthWindowSeconds {
		windowSeconds = maxAuthWindowSeconds
	}
	if windowSeconds < 0 {
		windowSeconds = 0
	}

	now := time.Now()

	// SECURITY: Always iterate over the MAXIMUM window to ensure constant timing.
	// This prevents attackers from deducing the actual window size through timing.
	// We compute HMAC for all timestamps but only accumulate matches within
	// the actual window.
	found := 0
	for delta := -maxAuthWindowSeconds; delta <= maxAuthWindowSeconds; delta++ {
		ts := now.Add(time.Duration(delta) * time.Second)
		expected := ComputeAuthHMAC(authKey, publicKey, ts)

		// expected can be nil if authKey is empty (already checked above)
		if expected == nil {
			continue
		}

		// Compute match result for this timestamp
		match := subtle.ConstantTimeCompare(authData[:32], expected[:32])

		// Only count as valid if within actual window (constant-time check)
		// inWindow is 1 if |delta| <= windowSeconds, 0 otherwise
		absDeleta := delta
		if absDeleta < 0 {
			absDeleta = -absDeleta
		}
		// Use constant-time less-or-equal: 1 if absDeleta <= windowSeconds
		inWindow := subtle.ConstantTimeLessOrEq(int(absDeleta), int(windowSeconds))

		// Accumulate: found |= (match & inWindow)
		found |= match & inWindow
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
//
// SECURITY WARNING: This function produces STATIC output for a given auth key.
// All connections using the same auth key will have identical short IDs,
// enabling passive clustering detection by network observers.
//
// For fingerprint-resistant deployments, use ComputeShortIDWithEntropy instead.
//
// Deprecated: Use ComputeShortIDWithEntropy for new deployments to prevent
// clustering detection. This function is retained for backwards compatibility.
func ComputeShortID(authKey []byte) [8]byte {
	h := sha256.Sum256(authKey)
	var shortID [8]byte
	copy(shortID[:], h[:8])
	return shortID
}

// ShortIDNonceSize is the size of the random nonce used in entropy-enhanced short IDs.
// The nonce is embedded in session ID bytes 8-15 to allow server verification.
const ShortIDNonceSize = 8

// ComputeShortIDWithEntropy computes an 8-byte short ID with per-connection entropy.
// This prevents clustering detection by including timestamp and random nonce in
// the derivation, making each connection's short ID unique.
//
// Formula: HMAC-SHA256(authKey, timestamp || nonce)[:8]
//
// Parameters:
//   - authKey: the shared authentication key (must be at least 32 bytes)
//   - timestamp: connection timestamp (typically time.Now())
//   - nonce: random 8-byte nonce (use GenerateShortIDNonce())
//
// Returns the computed 8-byte short ID.
//
// Security Properties:
//   - Each connection produces unique short ID (no clustering)
//   - Server can verify by scanning timestamp window (VerifyShortIDWithWindow)
//   - Nonce must be transmitted to server (embedded in session ID bytes 8-15)
//   - Uses HMAC-SHA256 for cryptographic binding to auth key
func ComputeShortIDWithEntropy(authKey []byte, timestamp time.Time, nonce []byte) [8]byte {
	var shortID [8]byte
	if len(authKey) == 0 {
		return shortID
	}

	h := hmac.New(sha256.New, authKey)

	// Include timestamp (Unix seconds, 8 bytes big-endian)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp.Unix()))
	h.Write(ts[:])

	// Include nonce for per-connection uniqueness
	if len(nonce) >= ShortIDNonceSize {
		h.Write(nonce[:ShortIDNonceSize])
	}

	result := h.Sum(nil)
	copy(shortID[:], result[:8])
	return shortID
}

// GenerateShortIDNonce generates a cryptographically random nonce for use with
// ComputeShortIDWithEntropy. The nonce should be embedded in session ID bytes 8-15.
func GenerateShortIDNonce() ([ShortIDNonceSize]byte, error) {
	var nonce [ShortIDNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, err
	}
	return nonce, nil
}

// VerifyShortIDWithWindow verifies an entropy-enhanced short ID by scanning
// a timestamp window. This is the server-side counterpart to ComputeShortIDWithEntropy.
//
// Parameters:
//   - authKey: the shared authentication key
//   - shortIDFromSession: the 8-byte short ID extracted from session ID[:8]
//   - nonce: the 8-byte nonce extracted from session ID[8:16]
//   - windowSeconds: allowed timestamp drift (max 300 seconds)
//
// Security Properties:
//   - Uses constant-time comparison for each timestamp attempt
//   - Always scans full maxAuthWindowSeconds to prevent timing leaks about
//     actual window size or which timestamp matched
//   - Returns true if any timestamp within window produces matching short ID
//
// Performance Note:
// This function performs (2 * maxAuthWindowSeconds + 1) = 601 HMAC operations
// per verification call. For high-traffic servers, consider caching or using
// the static ComputeShortID for initial filtering, followed by full HMAC
// verification in VerifyAuthHMACWithWindow.
func VerifyShortIDWithWindow(authKey []byte, shortIDFromSession [8]byte, nonce []byte, windowSeconds int64) bool {
	// Security: Reject empty keys
	if len(authKey) == 0 {
		return false
	}
	if len(nonce) < ShortIDNonceSize {
		return false
	}

	// Cap windowSeconds to prevent excessive computation
	if windowSeconds > maxAuthWindowSeconds {
		windowSeconds = maxAuthWindowSeconds
	}
	if windowSeconds < 0 {
		windowSeconds = 0
	}

	now := time.Now()

	// SECURITY: Always iterate over the MAXIMUM window to ensure constant timing.
	// This prevents attackers from deducing the actual window size through timing.
	found := 0
	for delta := -maxAuthWindowSeconds; delta <= maxAuthWindowSeconds; delta++ {
		ts := now.Add(time.Duration(delta) * time.Second)
		expected := ComputeShortIDWithEntropy(authKey, ts, nonce)

		// Compute match result for this timestamp
		match := subtle.ConstantTimeCompare(shortIDFromSession[:], expected[:])

		// Only count as valid if within actual window (constant-time check)
		absDelta := delta
		if absDelta < 0 {
			absDelta = -absDelta
		}
		inWindow := subtle.ConstantTimeLessOrEq(int(absDelta), int(windowSeconds))

		// Accumulate: found |= (match & inWindow)
		found |= match & inWindow
	}

	return found == 1
}

// MatchesShortID checks if session ID starts with expected short ID.
//
// Deprecated: For entropy-enhanced short IDs, use MatchesShortIDWithEntropy instead.
func MatchesShortID(sessionID []byte, shortID [8]byte) bool {
	if len(sessionID) < 8 {
		return false
	}
	return subtle.ConstantTimeCompare(sessionID[:8], shortID[:]) == 1
}

// MatchesShortIDWithEntropy verifies an entropy-enhanced short ID embedded in session ID.
// This is the server-side verification for clients using ComputeShortIDWithEntropy.
//
// Session ID Format (entropy-enhanced):
//
//	Bytes 0-7:   Short ID (HMAC-SHA256(authKey, timestamp || nonce)[:8])
//	Bytes 8-15:  Nonce (random 8 bytes, generated by client)
//	Bytes 16-31: HMAC authentication data (truncated)
//
// Parameters:
//   - authKey: the shared authentication key
//   - sessionID: the 32-byte session ID from ClientHello
//   - windowSeconds: allowed timestamp drift (max 300 seconds)
//
// Returns true if the short ID matches for any timestamp within the window.
func MatchesShortIDWithEntropy(authKey, sessionID []byte, windowSeconds int64) bool {
	if len(sessionID) < 16 {
		return false
	}

	var shortIDFromSession [8]byte
	copy(shortIDFromSession[:], sessionID[:8])
	nonce := sessionID[8:16]

	return VerifyShortIDWithWindow(authKey, shortIDFromSession, nonce, windowSeconds)
}

// ExtractNonceFromSessionID extracts the 8-byte nonce from an entropy-enhanced session ID.
// Returns nil if session ID is too short.
func ExtractNonceFromSessionID(sessionID []byte) []byte {
	if len(sessionID) < 16 {
		return nil
	}
	nonce := make([]byte, ShortIDNonceSize)
	copy(nonce, sessionID[8:16])
	return nonce
}

// EntropySessionID represents a session ID with entropy-enhanced short ID format.
// This format prevents clustering detection while maintaining server verifiability.
//
// Format (32 bytes total):
//
//	Bytes 0-7:   Entropy-enhanced short ID
//	Bytes 8-15:  Random nonce
//	Bytes 16-31: HMAC authentication data (truncated)
type EntropySessionID struct {
	ShortID  [8]byte                // Bytes 0-7: HMAC-SHA256(authKey, timestamp || nonce)[:8]
	Nonce    [ShortIDNonceSize]byte // Bytes 8-15: Random nonce
	AuthData [16]byte               // Bytes 16-31: HMAC authentication data
}

// GenerateEntropySessionID creates a session ID with entropy-enhanced short ID.
// This should be used by REALITY clients to prevent clustering detection.
//
// Parameters:
//   - authKey: shared authentication key (at least 32 bytes)
//   - publicKey: client's ECDH public key
//
// Returns the 32-byte session ID and any error from nonce generation.
func GenerateEntropySessionID(authKey, publicKey []byte) ([]byte, error) {
	now := time.Now()

	// Generate random nonce for this connection
	nonce, err := GenerateShortIDNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Compute entropy-enhanced short ID
	shortID := ComputeShortIDWithEntropy(authKey, now, nonce[:])

	// Compute full HMAC for authentication
	authHMAC := ComputeAuthHMAC(authKey, publicKey, now)
	if authHMAC == nil {
		return nil, errors.New("failed to compute auth HMAC")
	}

	// Construct session ID
	sessionID := make([]byte, 32)
	copy(sessionID[0:8], shortID[:])
	copy(sessionID[8:16], nonce[:])
	copy(sessionID[16:32], authHMAC[:16])

	return sessionID, nil
}

// VerifyEntropySessionID verifies a session ID with entropy-enhanced short ID format.
// This combines short ID verification and HMAC authentication in one call.
//
// Parameters:
//   - authKey: shared authentication key
//   - sessionID: the 32-byte session ID from ClientHello
//   - publicKey: client's ECDH public key
//   - windowSeconds: allowed timestamp drift (max 300 seconds)
//
// Returns an AuthResult with verification status.
//
// Security Properties:
//   - Constant-time operations throughout
//   - Always performs full verification regardless of intermediate results
//   - Scans complete timestamp window to prevent timing attacks
func VerifyEntropySessionID(authKey, sessionID, publicKey []byte, windowSeconds int64) *AuthResult {
	result := &AuthResult{}

	if len(sessionID) < 32 || len(authKey) == 0 {
		result.Reason = "invalid session ID or auth key"
		return result
	}

	// Extract components
	var shortIDFromSession [8]byte
	copy(shortIDFromSession[:], sessionID[:8])
	nonce := sessionID[8:16]
	authDataFromSession := sessionID[16:32]

	// Verify short ID (constant-time, scans window)
	shortIDMatch := 0
	if VerifyShortIDWithWindow(authKey, shortIDFromSession, nonce, windowSeconds) {
		shortIDMatch = 1
	}

	// Verify HMAC authentication (constant-time, scans window)
	// We need to verify that the auth data matches for some timestamp
	hmacMatch := 0
	now := time.Now()

	// Cap windowSeconds
	if windowSeconds > maxAuthWindowSeconds {
		windowSeconds = maxAuthWindowSeconds
	}
	if windowSeconds < 0 {
		windowSeconds = 0
	}

	// SECURITY: Always scan full window for constant timing
	for delta := -maxAuthWindowSeconds; delta <= maxAuthWindowSeconds; delta++ {
		ts := now.Add(time.Duration(delta) * time.Second)
		expectedHMAC := ComputeAuthHMAC(authKey, publicKey, ts)
		if expectedHMAC == nil {
			continue
		}

		// Compare first 16 bytes of HMAC (what's stored in session ID)
		match := subtle.ConstantTimeCompare(authDataFromSession, expectedHMAC[:16])

		// Only count if within actual window
		absDelta := delta
		if absDelta < 0 {
			absDelta = -absDelta
		}
		inWindow := subtle.ConstantTimeLessOrEq(int(absDelta), int(windowSeconds))

		hmacMatch |= match & inWindow
	}

	// Both must match
	authenticated := shortIDMatch & hmacMatch
	if authenticated == 1 {
		result.Authenticated = true
		result.PublicKey = publicKey
	} else {
		if shortIDMatch == 0 {
			result.Reason = "entropy short ID mismatch"
		} else {
			result.Reason = "HMAC verification failed"
		}
	}

	return result
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
// The config is cloned and defaults are applied to the internal copy,
// leaving the original config unmodified.
func NewAuthenticator(config *AuthConfig) (*Authenticator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// Clone first, then apply defaults to the clone (original stays unmodified)
	cloned := config.Clone()
	cloned.ApplyDefaults()
	return &Authenticator{config: cloned}, nil
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
//
// Security Properties:
//   - ALWAYS performs HMAC verification regardless of short ID match
//   - Uses constant-time operations throughout to prevent timing attacks
//   - Short ID and HMAC results are combined using constant-time logic
//   - No early returns that could leak information through timing
func (a *Authenticator) VerifyClientAuth(publicKey, authData []byte) *AuthResult {
	result := &AuthResult{}

	// SECURITY: Always perform ALL verification steps to ensure constant timing.
	// Early returns would leak information about which check failed.

	// Check short ID if configured (always compute, no early exit)
	shortIDMatch := 1 // Default to match if not configured
	shortIDConfigured := a.config.ShortID != [8]byte{}
	if shortIDConfigured {
		if MatchesShortID(authData, a.config.ShortID) {
			shortIDMatch = 1
		} else {
			shortIDMatch = 0
		}
	}

	// ALWAYS verify HMAC regardless of short ID result (constant-time)
	// This prevents timing attacks that could enumerate valid short IDs
	var hmacMatch int
	if a.config.VerifyFunc != nil {
		expected := a.ComputeClientAuth(publicKey)
		if a.config.VerifyFunc(authData, expected) {
			hmacMatch = 1
		} else {
			hmacMatch = 0
		}
	} else {
		if VerifyAuthHMACWithWindow(a.config.Key, publicKey, authData, 30) {
			hmacMatch = 1
		} else {
			hmacMatch = 0
		}
	}

	// Combine results using constant-time AND: both must match
	// authenticated = shortIDMatch AND hmacMatch
	authenticated := shortIDMatch & hmacMatch

	// Set result based on combined check
	// Use constant-time selection for reason to avoid timing leaks
	if authenticated == 1 {
		result.Authenticated = true
		result.PublicKey = publicKey
	} else {
		// Determine reason without leaking which specific check failed through timing
		// We can reveal the reason since verification already completed
		if shortIDConfigured && shortIDMatch == 0 {
			result.Reason = "short ID mismatch"
		} else if hmacMatch == 0 {
			if a.config.VerifyFunc != nil {
				result.Reason = "custom verification failed"
			} else {
				result.Reason = "HMAC verification failed"
			}
		}
	}

	return result
}

// GenerateSessionIDWithAuth generates a session ID containing auth data.
// publicKey is the client's ECDH public key.
//
// Note: For entropy-enhanced session IDs that prevent clustering detection,
// use GenerateSessionIDWithEntropy instead when UseEntropyShortID is enabled.
func (a *Authenticator) GenerateSessionIDWithAuth(publicKey []byte) []byte {
	authData := a.ComputeClientAuth(publicKey)
	return EmbedAuthInSessionID(authData)
}

// GenerateSessionIDWithEntropy generates a session ID with entropy-enhanced short ID.
// This prevents passive clustering detection by using per-connection randomness.
//
// Session ID Format:
//
//	Bytes 0-7:   Entropy-enhanced short ID (HMAC-SHA256(authKey, timestamp || nonce)[:8])
//	Bytes 8-15:  Random nonce
//	Bytes 16-31: HMAC authentication data (truncated)
//
// Use this method when a.config.UseEntropyShortID is true.
func (a *Authenticator) GenerateSessionIDWithEntropy(publicKey []byte) ([]byte, error) {
	return GenerateEntropySessionID(a.config.Key, publicKey)
}

// VerifyClientAuthWithEntropy verifies client authentication using entropy-enhanced format.
// sessionID is the full 32-byte session ID from ClientHello.
// publicKey is the client's ECDH public key.
//
// This method should be used when UseEntropyShortID is enabled.
func (a *Authenticator) VerifyClientAuthWithEntropy(sessionID, publicKey []byte) *AuthResult {
	windowSeconds := a.config.ShortIDWindowSeconds
	if windowSeconds == 0 {
		windowSeconds = 30
	}
	return VerifyEntropySessionID(a.config.Key, sessionID, publicKey, windowSeconds)
}

// AuthenticatedSessionID checks if a session ID contains valid auth.
// publicKey is the client's ECDH public key.
//
// This method automatically uses the appropriate verification method based on
// UseEntropyShortID configuration.
func (a *Authenticator) AuthenticatedSessionID(sessionID, publicKey []byte) bool {
	if a.config.UseEntropyShortID {
		result := a.VerifyClientAuthWithEntropy(sessionID, publicKey)
		return result.Authenticated
	}
	authData := ExtractAuthFromSessionID(sessionID)
	if authData == nil {
		return false
	}
	result := a.VerifyClientAuth(publicKey, authData)
	return result.Authenticated
}

// UseEntropyShortID returns whether entropy-enhanced short IDs are enabled.
func (a *Authenticator) UseEntropyShortID() bool {
	return a.config.UseEntropyShortID
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
// # SECURITY CRITICAL WARNING - DO NOT USE IN NEW CODE
//
// This function uses a single SHA-512 hash which provides ZERO protection
// against brute-force attacks. Modern GPUs can compute billions of SHA-512
// hashes per second, meaning:
//   - 8-character password: cracked in seconds
//   - 12-character password: cracked in hours to days
//   - Any dictionary word: cracked instantly
//
// This function exists only for backwards compatibility with existing deployments.
// It will be removed in a future major version.
//
// For new code, use DeriveAuthKeySecure() with:
//   - A random 32-byte salt (use GenerateAuthSalt())
//   - At least 100,000 iterations (more for high-security applications)
//
// Or better, use a modern password hashing library:
//   - Argon2id (recommended)
//   - scrypt
//   - bcrypt
//
// Deprecated: DeriveAuthKey uses single SHA-512 which is insecure. Use DeriveAuthKeySecure instead.
func DeriveAuthKey(password string) []byte {
	deriveAuthKeyDeprecatedOnce.Do(func() {
		log.Printf("[Warning] DeriveAuthKey is deprecated and insecure: uses single SHA-512 hash " +
			"which can be brute-forced at billions of attempts/second on modern GPUs. " +
			"Migrate to DeriveAuthKeySecure(password, salt, iterations) with iterations >= 100000.")
	})
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
	deriveAuthKeyWithSaltDeprecatedOnce.Do(func() {
		log.Printf("[Warning] DeriveAuthKeyWithSalt is deprecated: uses single HMAC iteration " +
			"which is vulnerable to brute-force attacks. " +
			"Migrate to DeriveAuthKeySecure(password, salt, iterations) with iterations >= 100000.")
	})
	if len(salt) == 0 {
		return nil // Security: require salt
	}
	h := hmac.New(sha512.New, salt)
	h.Write([]byte(password))
	return h.Sum(nil)
}

// DeriveAuthKeySecure derives an authentication key using PBKDF2-HMAC-SHA256.
// This provides strong resistance to brute-force attacks through iterative hashing.
//
// PBKDF2 (Password-Based Key Derivation Function 2) is a standard algorithm
// defined in RFC 8018 that applies a pseudorandom function (HMAC-SHA256) many
// times to the password and salt, making brute-force attacks computationally
// expensive.
//
// Parameters:
//   - password: the passphrase to derive from (must not be empty)
//   - salt: random salt (must be at least 16 bytes, unique per user/key)
//   - iterations: number of PBKDF2 iterations (recommended: at least 100000)
//
// Returns 32-byte derived key, or nil if parameters are invalid.
//
// Example:
//
//	salt, err := GenerateAuthSalt()
//	if err != nil {
//	    // handle error
//	}
//	key := DeriveAuthKeySecure("my-secure-password", salt, 100000)
//	if key == nil {
//	    // handle invalid parameters
//	}
func DeriveAuthKeySecure(password string, salt []byte, iterations int) []byte {
	if len(password) == 0 || len(salt) < 16 || iterations < 1 {
		return nil
	}
	// Use standard PBKDF2 with HMAC-SHA256 and 32-byte output
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
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
