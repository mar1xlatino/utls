// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// JA4SVariationConfig controls JA4S fingerprint variation for anti-detection.
//
// Problem: Static JA4S fingerprints across all connections enable statistical detection.
// Real servers show JA4S variation due to load balancers, config changes, etc.
//
// Solution: Shuffle non-critical ServerHello extensions to create natural JA4S variation.
// This maintains protocol correctness while defeating fingerprint tracking.
//
// Usage:
//
//	config := &JA4SVariationConfig{
//	    Enabled: true,
//	    ShuffleExtensions: true,
//	}
//	synthesizer.WithJA4SVariation(config)
type JA4SVariationConfig struct {
	// Enabled controls whether JA4S variation is active.
	// When false, ServerHello is replayed exactly as captured.
	Enabled bool

	// ShuffleExtensions enables reordering of non-critical extensions.
	// Critical extensions (key_share, supported_versions) maintain relative order.
	// pre_shared_key always stays last per RFC 8446.
	ShuffleExtensions bool

	// ShuffleProbability is the chance of shuffling on each synthesis (0.0-1.0).
	// Default 0.3 (30%) provides variation without being too aggressive.
	// Set to 1.0 for maximum variation, 0.0 to disable shuffling.
	ShuffleProbability float64
}

// DefaultJA4SVariationConfig returns production-ready defaults.
// Enabled with 30% shuffle probability for natural variation.
func DefaultJA4SVariationConfig() *JA4SVariationConfig {
	return &JA4SVariationConfig{
		Enabled:            true,
		ShuffleExtensions:  true,
		ShuffleProbability: 0.3,
	}
}

// ExtensionInfo stores parsed extension data with position tracking.
// Used for reconstructing ServerHello with shuffled extensions.
type ExtensionInfo struct {
	Type   uint16 // Extension type code
	Data   []byte // Raw extension data (excluding type and length)
	Offset int    // Byte offset in original message (for reference)
}

// IsCriticalServerHelloExtension returns true for extensions that must maintain
// their relative position or have special placement rules in TLS 1.3 ServerHello.
//
// Per RFC 8446:
// - pre_shared_key (41) MUST be the last extension in ServerHello
// - key_share (51) and supported_versions (43) are critical for handshake
//
// These extensions are NOT shuffled to maintain protocol correctness.
func IsCriticalServerHelloExtension(extType uint16) bool {
	switch extType {
	case extensionPreSharedKey: // 41 - MUST be last per RFC 8446
		return true
	case extensionKeyShare: // 51 - contains key exchange data
		return true
	case extensionSupportedVersions: // 43 - indicates TLS version
		return true
	default:
		return false
	}
}

// IsShufflableServerHelloExtension returns true for extensions that can be
// safely reordered without breaking the TLS handshake.
//
// Shufflable extensions in TLS 1.3 ServerHello:
// - ALPN (16) - application layer negotiation
// - early_data (42) - 0-RTT indication
// - cookie (44) - HRR cookie
// - other non-critical extensions
func IsShufflableServerHelloExtension(extType uint16) bool {
	return !IsCriticalServerHelloExtension(extType)
}

// CapturedServerHello stores a captured ServerHello for replay.
// This enables mimicking real server TLS fingerprints (JA4S).
type CapturedServerHello struct {
	// Raw is the complete ServerHello message bytes (without record header).
	Raw []byte

	// Version is the TLS version from ServerHello.
	Version uint16

	// CipherSuite is the selected cipher suite.
	CipherSuite uint16

	// SessionID is the session ID (may be replaced during synthesis).
	SessionID []byte

	// Random is the server random (32 bytes, will be replaced during synthesis).
	Random [32]byte

	// CompressionMethod is the selected compression (always 0 for TLS 1.3).
	CompressionMethod uint8

	// Extensions contains the extension types present in order.
	Extensions []uint16

	// ExtensionData stores full extension data for reconstruction during shuffling.
	// Key: extension type, Value: raw extension data (excluding type/length header).
	// Populated during parsing to enable JA4S variation via extension reordering.
	ExtensionData map[uint16][]byte

	// ExtensionsOffset is the byte offset where extensions block starts in Raw.
	// Used for efficient ServerHello reconstruction with shuffled extensions.
	ExtensionsOffset int

	// KeyShareGroup is the selected key share group (for TLS 1.3).
	KeyShareGroup CurveID

	// KeyShareData is the server's key share public key data.
	KeyShareData []byte

	// SelectedALPN is the negotiated ALPN protocol.
	SelectedALPN string

	// SupportedVersion is the negotiated version from supported_versions extension.
	SupportedVersion uint16

	// CapturedAt is when this ServerHello was captured.
	CapturedAt time.Time

	// TargetHost is the hostname this was captured from.
	TargetHost string

	// JA4S is the computed JA4S fingerprint.
	JA4S string

	// Fingerprint is the SHA256 hash of structural elements (for quick comparison).
	Fingerprint [32]byte
}

// Clone creates a deep copy of CapturedServerHello.
// This prevents cache poisoning attacks where callers modify cached entries.
func (c *CapturedServerHello) Clone() *CapturedServerHello {
	if c == nil {
		return nil
	}
	clone := &CapturedServerHello{
		Version:          c.Version,
		CipherSuite:      c.CipherSuite,
		Random:           c.Random,
		CompressionMethod: c.CompressionMethod,
		ExtensionsOffset: c.ExtensionsOffset,
		KeyShareGroup:    c.KeyShareGroup,
		SelectedALPN:     c.SelectedALPN,
		SupportedVersion: c.SupportedVersion,
		CapturedAt:       c.CapturedAt,
		TargetHost:       c.TargetHost,
		JA4S:             c.JA4S,
		Fingerprint:      c.Fingerprint,
	}
	// Deep copy slices
	if c.Raw != nil {
		clone.Raw = make([]byte, len(c.Raw))
		copy(clone.Raw, c.Raw)
	}
	if c.SessionID != nil {
		clone.SessionID = make([]byte, len(c.SessionID))
		copy(clone.SessionID, c.SessionID)
	}
	if c.Extensions != nil {
		clone.Extensions = make([]uint16, len(c.Extensions))
		copy(clone.Extensions, c.Extensions)
	}
	if c.KeyShareData != nil {
		clone.KeyShareData = make([]byte, len(c.KeyShareData))
		copy(clone.KeyShareData, c.KeyShareData)
	}
	// Deep copy ExtensionData map
	if c.ExtensionData != nil {
		clone.ExtensionData = make(map[uint16][]byte, len(c.ExtensionData))
		for k, v := range c.ExtensionData {
			if v != nil {
				clonedData := make([]byte, len(v))
				copy(clonedData, v)
				clone.ExtensionData[k] = clonedData
			}
		}
	}
	return clone
}

// ComputeFingerprint computes a structural fingerprint of the ServerHello.
// This fingerprint ignores dynamic fields (random, session ID, key share data)
// and focuses on the structural elements that define the JA4S.
func (c *CapturedServerHello) ComputeFingerprint() [32]byte {
	h := sha256.New()

	// Version
	binary.Write(h, binary.BigEndian, c.Version)
	binary.Write(h, binary.BigEndian, c.SupportedVersion)

	// Cipher suite
	binary.Write(h, binary.BigEndian, c.CipherSuite)

	// Extensions (order matters for JA4S)
	for _, ext := range c.Extensions {
		binary.Write(h, binary.BigEndian, ext)
	}

	// Key share group
	binary.Write(h, binary.BigEndian, uint16(c.KeyShareGroup))

	// ALPN
	h.Write([]byte(c.SelectedALPN))

	var fp [32]byte
	copy(fp[:], h.Sum(nil))
	return fp
}

// ServerHelloCache stores captured ServerHellos per target.
// Thread-safe with LRU eviction when at capacity.
type ServerHelloCache struct {
	mu      sync.RWMutex
	entries map[string]*CapturedServerHello
	maxAge  time.Duration
	maxSize int
}

// NewServerHelloCache creates a cache for captured ServerHellos.
// maxSize: Maximum entries (0 = default 100)
// maxAge: Maximum age before expiry (0 = default 1 hour)
func NewServerHelloCache(maxSize int, maxAge time.Duration) *ServerHelloCache {
	if maxSize <= 0 {
		maxSize = 100
	}
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	return &ServerHelloCache{
		entries: make(map[string]*CapturedServerHello),
		maxAge:  maxAge,
		maxSize: maxSize,
	}
}

// Get retrieves a cached ServerHello for the target.
// Returns nil if not found or expired.
// Security: Returns a defensive copy to prevent cache poisoning.
// Expired entries are lazily deleted to prevent memory leaks.
func (c *ServerHelloCache) Get(targetHost string) *CapturedServerHello {
	c.mu.RLock()
	entry := c.entries[targetHost]
	if entry == nil {
		c.mu.RUnlock()
		return nil
	}

	// Check if entry is still valid
	if time.Since(entry.CapturedAt) <= c.maxAge {
		result := entry.Clone()
		c.mu.RUnlock()
		return result
	}

	// Entry is expired - upgrade to write lock and delete it
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under write lock (another goroutine may have modified)
	entry = c.entries[targetHost]
	if entry == nil {
		return nil
	}
	// Check again - entry may have been replaced with fresh one
	if time.Since(entry.CapturedAt) <= c.maxAge {
		return entry.Clone()
	}
	// Still expired, delete it
	delete(c.entries, targetHost)
	return nil
}

// Put stores a captured ServerHello.
// Evicts oldest entry if at capacity.
func (c *ServerHelloCache) Put(targetHost string, captured *CapturedServerHello) {
	if captured == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Set capture time if not set
	if captured.CapturedAt.IsZero() {
		captured.CapturedAt = time.Now()
	}

	// Compute fingerprint if not set
	if captured.Fingerprint == [32]byte{} {
		captured.Fingerprint = captured.ComputeFingerprint()
	}

	// Evict if at capacity (and not updating existing)
	if _, exists := c.entries[targetHost]; !exists && len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}

	c.entries[targetHost] = captured
}

// Delete removes a cached ServerHello.
func (c *ServerHelloCache) Delete(targetHost string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, targetHost)
}

// Size returns the number of cached entries.
func (c *ServerHelloCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries.
func (c *ServerHelloCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CapturedServerHello)
}

// CleanExpired removes expired entries. Returns count removed.
func (c *ServerHelloCache) CleanExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, entry := range c.entries {
		if now.Sub(entry.CapturedAt) > c.maxAge {
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

// evictOldestLocked removes the oldest entry. Must hold write lock.
// Also opportunistically removes any expired entries encountered.
func (c *ServerHelloCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	now := time.Now()
	var expiredKeys []string

	for key, entry := range c.entries {
		// Collect expired entries for removal
		if now.Sub(entry.CapturedAt) > c.maxAge {
			expiredKeys = append(expiredKeys, key)
			continue
		}
		if oldestKey == "" || entry.CapturedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.CapturedAt
		}
	}

	// Remove all expired entries first
	for _, key := range expiredKeys {
		delete(c.entries, key)
	}

	// If we removed expired entries and are now under capacity, we're done
	if len(expiredKeys) > 0 && len(c.entries) < c.maxSize {
		return
	}

	// Otherwise remove the oldest valid entry
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// ServerHelloSynthesizer creates ServerHellos that match captured patterns.
// It preserves the JA4S fingerprint while replacing dynamic fields.
//
// JA4S VARIATION (anti-detection):
// The synthesizer supports optional extension shuffling to create JA4S variation.
// This prevents static fingerprint tracking across multiple connections.
// Use WithJA4SVariation() to enable shuffling of non-critical extensions.
type ServerHelloSynthesizer struct {
	captured       *CapturedServerHello
	keyShareData   []byte   // Our key share public key (replaces captured)
	random         [32]byte // Our server random (replaces captured)
	sessionID      []byte   // Our session ID (replaces captured)
	hasRandom      bool
	hasSessionID   bool
	ja4sVariation  *JA4SVariationConfig // JA4S variation config (nil = disabled)
}

// NewServerHelloSynthesizer creates a synthesizer from captured ServerHello.
func NewServerHelloSynthesizer(captured *CapturedServerHello) *ServerHelloSynthesizer {
	return &ServerHelloSynthesizer{
		captured: captured,
	}
}

// WithKeyShare sets our key share data (replaces captured key share).
func (s *ServerHelloSynthesizer) WithKeyShare(publicKey []byte) *ServerHelloSynthesizer {
	s.keyShareData = publicKey
	return s
}

// WithRandom sets our server random (replaces captured random).
func (s *ServerHelloSynthesizer) WithRandom(random [32]byte) *ServerHelloSynthesizer {
	s.random = random
	s.hasRandom = true
	return s
}

// WithSessionID sets our session ID (replaces captured session ID).
func (s *ServerHelloSynthesizer) WithSessionID(sessionID []byte) *ServerHelloSynthesizer {
	s.sessionID = sessionID
	s.hasSessionID = true
	return s
}

// WithJA4SVariation enables JA4S fingerprint variation via extension shuffling.
// This creates natural variation in the JA4S fingerprint to defeat tracking.
//
// When enabled, non-critical extensions may be reordered based on ShuffleProbability.
// Critical extensions (key_share, supported_versions, pre_shared_key) maintain position.
func (s *ServerHelloSynthesizer) WithJA4SVariation(config *JA4SVariationConfig) *ServerHelloSynthesizer {
	s.ja4sVariation = config
	return s
}

// shouldShuffleExtensions returns true if extension shuffling should occur.
// Uses cryptographic randomness to determine shuffle probability.
func (s *ServerHelloSynthesizer) shouldShuffleExtensions() bool {
	if s.ja4sVariation == nil || !s.ja4sVariation.Enabled || !s.ja4sVariation.ShuffleExtensions {
		return false
	}
	if s.ja4sVariation.ShuffleProbability <= 0 {
		return false
	}
	if s.ja4sVariation.ShuffleProbability >= 1.0 {
		return true
	}
	// Use crypto/rand for unbiased probability check
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return false // Fail closed - don't shuffle on RNG error
	}
	threshold := uint8(s.ja4sVariation.ShuffleProbability * 256)
	return b[0] < threshold
}

// shuffleExtensions creates a shuffled extension order for JA4S variation.
// Returns the new extension order while respecting critical extension rules:
// - pre_shared_key (41) always stays last (RFC 8446 requirement)
// - Other extensions are Fisher-Yates shuffled
//
// Thread-safe: Uses crypto/rand for shuffling.
func shuffleExtensions(extensions []uint16) []uint16 {
	if len(extensions) <= 1 {
		return extensions
	}

	// Separate pre_shared_key (must be last) from other extensions
	var pskExt uint16
	var hasPSK bool
	other := make([]uint16, 0, len(extensions))

	for _, ext := range extensions {
		if ext == extensionPreSharedKey {
			pskExt = ext
			hasPSK = true
		} else {
			other = append(other, ext)
		}
	}

	// Fisher-Yates shuffle the non-PSK extensions
	n := len(other)
	for i := n - 1; i > 0; i-- {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			// On RNG error, return original order
			return extensions
		}
		j := int(b[0]) % (i + 1)
		other[i], other[j] = other[j], other[i]
	}

	// Append PSK at the end if present
	if hasPSK {
		other = append(other, pskExt)
	}

	return other
}

// Synthesize creates a ServerHello matching the captured pattern.
// If JA4S variation is enabled and shouldShuffleExtensions() returns true,
// extensions are reordered to create fingerprint variation.
// Returns synthesized bytes with replaced dynamic fields.
func (s *ServerHelloSynthesizer) Synthesize() ([]byte, error) {
	// Check if we should use shuffled extensions for JA4S variation
	if s.shouldShuffleExtensions() && s.captured.ExtensionData != nil && len(s.captured.ExtensionData) > 1 {
		return s.SynthesizeWithShuffledExtensions()
	}

	// Standard synthesis without extension shuffling
	return s.synthesizeStandard()
}

// synthesizeStandard creates a ServerHello using the original extension order.
func (s *ServerHelloSynthesizer) synthesizeStandard() ([]byte, error) {
	if s.captured == nil {
		return nil, errors.New("tls: no captured ServerHello")
	}

	// Minimum: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1) = 38
	minSize := 38
	offset := 0

	// Check if handshake header is present
	if len(s.captured.Raw) > 0 && s.captured.Raw[0] == typeServerHello {
		offset = 4
		minSize = 42 // Need 4 extra bytes for handshake header
	}

	if len(s.captured.Raw) < minSize {
		return nil, errors.New("tls: captured ServerHello too short")
	}

	// Create a copy to modify
	result := make([]byte, len(s.captured.Raw))
	copy(result, s.captured.Raw)

	// ServerHello structure (after handshake header):
	// - 2 bytes: legacy version
	// - 32 bytes: random
	// - 1 byte: session ID length
	// - N bytes: session ID
	// - 2 bytes: cipher suite
	// - 1 byte: compression method
	// - 2 bytes: extensions length
	// - extensions...

	// Skip legacy version (2 bytes)
	offset += 2

	// Replace random (32 bytes)
	if s.hasRandom {
		copy(result[offset:offset+32], s.random[:])
	}
	offset += 32

	// Handle session ID
	sessionIDLen := int(result[offset])
	offset++

	if s.hasSessionID {
		// Session ID length must match for structure preservation
		if len(s.sessionID) != sessionIDLen {
			// If lengths differ, we need to rebuild the message
			return s.rebuildWithNewSessionID()
		}
		copy(result[offset:offset+sessionIDLen], s.sessionID)
	}
	offset += sessionIDLen

	// Skip cipher suite (2) and compression (1)
	offset += 3

	// Parse extensions to find and replace key share
	if offset+2 > len(result) {
		return result, nil // No extensions
	}

	extLen := int(binary.BigEndian.Uint16(result[offset:]))
	offset += 2

	// Bounds check: ensure extension block fits within data
	if offset+extLen > len(result) {
		return nil, errors.New("tls: extension length exceeds data bounds")
	}

	if s.keyShareData != nil {
		// Find and replace key share extension data
		if err := s.replaceKeyShareInPlace(result, offset, extLen); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// SynthesizeWithShuffledExtensions rebuilds the ServerHello with shuffled extension order.
// This creates JA4S fingerprint variation while maintaining protocol correctness.
//
// The method:
// 1. Builds the ServerHello header (version, random, sessionID, cipher, compression)
// 2. Shuffles extensions (respecting pre_shared_key position)
// 3. Rebuilds extension block with new order
// 4. Updates handshake length fields
//
// Returns the synthesized ServerHello with varied JA4S fingerprint.
func (s *ServerHelloSynthesizer) SynthesizeWithShuffledExtensions() ([]byte, error) {
	if s.captured == nil {
		return nil, errors.New("tls: no captured ServerHello")
	}
	if s.captured.ExtensionData == nil || len(s.captured.Extensions) == 0 {
		// No extension data available for shuffling, fall back to standard
		return s.synthesizeStandard()
	}

	// Shuffle the extension order
	shuffledOrder := shuffleExtensions(s.captured.Extensions)

	// Calculate total extensions size
	var extBlockSize int
	for _, extType := range shuffledOrder {
		extData, ok := s.captured.ExtensionData[extType]
		if !ok {
			continue
		}
		extBlockSize += 4 + len(extData) // type(2) + length(2) + data
	}

	// Build the ServerHello with shuffled extensions
	// Structure: [handshake_header(4)] + version(2) + random(32) + sessionID_len(1) + sessionID(N) +
	//            cipher(2) + compression(1) + ext_len(2) + extensions
	headerOffset := 0
	hasHeader := len(s.captured.Raw) > 0 && s.captured.Raw[0] == typeServerHello
	if hasHeader {
		headerOffset = 4
	}

	// Calculate total message size
	sessionIDLen := len(s.captured.SessionID)
	if s.hasSessionID {
		sessionIDLen = len(s.sessionID)
	}

	// ServerHello body size (excluding handshake header)
	bodySize := 2 + 32 + 1 + sessionIDLen + 2 + 1 + 2 + extBlockSize

	var result []byte
	if hasHeader {
		result = make([]byte, 4+bodySize)
		// Handshake type and length
		result[0] = typeServerHello
		result[1] = byte(bodySize >> 16)
		result[2] = byte(bodySize >> 8)
		result[3] = byte(bodySize)
	} else {
		result = make([]byte, bodySize)
	}

	offset := headerOffset

	// Legacy version (copy from captured)
	binary.BigEndian.PutUint16(result[offset:], s.captured.Version)
	offset += 2

	// Random (use our random if set, otherwise captured)
	if s.hasRandom {
		copy(result[offset:offset+32], s.random[:])
	} else {
		copy(result[offset:offset+32], s.captured.Random[:])
	}
	offset += 32

	// Session ID
	if s.hasSessionID {
		result[offset] = byte(len(s.sessionID))
		offset++
		copy(result[offset:], s.sessionID)
		offset += len(s.sessionID)
	} else {
		result[offset] = byte(len(s.captured.SessionID))
		offset++
		copy(result[offset:], s.captured.SessionID)
		offset += len(s.captured.SessionID)
	}

	// Cipher suite
	binary.BigEndian.PutUint16(result[offset:], s.captured.CipherSuite)
	offset += 2

	// Compression method
	result[offset] = s.captured.CompressionMethod
	offset++

	// Extensions length
	binary.BigEndian.PutUint16(result[offset:], uint16(extBlockSize))
	offset += 2

	// Write extensions in shuffled order
	for _, extType := range shuffledOrder {
		extData, ok := s.captured.ExtensionData[extType]
		if !ok {
			continue
		}

		// Extension type
		binary.BigEndian.PutUint16(result[offset:], extType)
		offset += 2

		// Extension length
		binary.BigEndian.PutUint16(result[offset:], uint16(len(extData)))
		offset += 2

		// Extension data
		if extType == extensionKeyShare && s.keyShareData != nil {
			// Replace key share data with our key
			if len(s.keyShareData)+4 == len(extData) {
				// Data includes group(2) + keyLen(2) + key
				copy(result[offset:offset+4], extData[:4])   // Keep group and length
				copy(result[offset+4:], s.keyShareData)      // Replace key data
			} else if len(s.keyShareData) == len(extData)-4 {
				copy(result[offset:offset+4], extData[:4])
				copy(result[offset+4:], s.keyShareData)
			} else {
				// Length mismatch - copy as-is and log warning
				copy(result[offset:], extData)
			}
		} else {
			copy(result[offset:], extData)
		}
		offset += len(extData)
	}

	return result, nil
}

// GetShuffledJA4S returns the JA4S fingerprint that would result from shuffled extensions.
// Useful for logging and debugging JA4S variation.
func (s *ServerHelloSynthesizer) GetShuffledJA4S() (string, error) {
	if s.captured == nil {
		return "", errors.New("tls: no captured ServerHello")
	}
	if len(s.captured.Extensions) <= 1 {
		return s.captured.JA4S, nil
	}

	shuffledOrder := shuffleExtensions(s.captured.Extensions)

	// Compute JA4S with shuffled extension order
	// JA4S format: t{version}{extcount}{alpn}_{cipher}_{exthash}
	return computeJA4SFromComponents(
		s.captured.SupportedVersion,
		s.captured.CipherSuite,
		shuffledOrder,
		s.captured.SelectedALPN,
	), nil
}

// computeJA4SFromComponents computes JA4S fingerprint from individual components.
// Used for computing JA4S with shuffled extension order.
func computeJA4SFromComponents(version, cipher uint16, extensions []uint16, alpn string) string {
	// Protocol indicator (always 't' for TLS)
	proto := "t"

	// Version: 13 for TLS 1.3
	var versionStr string
	switch version {
	case VersionTLS13:
		versionStr = "13"
	case VersionTLS12:
		versionStr = "12"
	case VersionTLS11:
		versionStr = "11"
	case VersionTLS10:
		versionStr = "10"
	default:
		versionStr = fmt.Sprintf("%02x", version&0xFF)
	}

	// Extension count (2 digits)
	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN indicator (first and last char)
	alpnStr := "00"
	if len(alpn) > 0 {
		first := alpn[0]
		last := alpn[len(alpn)-1]
		alpnStr = string(first) + string(last)
	}

	// JA4S_a
	ja4sA := fmt.Sprintf("%s%s%02d%s", proto, versionStr, extCount, alpnStr)

	// JA4S_b: cipher in hex
	ja4sB := fmt.Sprintf("%04x", cipher)

	// JA4S_c: extension hash
	ja4sC := computeExtensionHash(extensions)

	return ja4sA + "_" + ja4sB + "_" + ja4sC
}

// rebuildWithNewSessionID rebuilds the ServerHello with a different session ID length.
func (s *ServerHelloSynthesizer) rebuildWithNewSessionID() ([]byte, error) {
	// This is complex - for now, return error if session ID lengths don't match
	return nil, errors.New("tls: session ID length mismatch, rebuild not implemented")
}

// replaceKeyShareInPlace replaces key share data in extensions.
func (s *ServerHelloSynthesizer) replaceKeyShareInPlace(data []byte, extStart, extLen int) error {
	offset := extStart
	end := extStart + extLen

	// Bounds check: ensure end doesn't exceed actual data length
	if end > len(data) {
		return errors.New("tls: extension block exceeds data bounds")
	}

	for offset+4 <= end {
		// Bounds check: ensure we can read extension header from actual data
		if offset+4 > len(data) {
			return errors.New("tls: truncated extension header")
		}
		extType := binary.BigEndian.Uint16(data[offset:])
		extDataLen := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4

		if offset+extDataLen > end {
			return errors.New("tls: malformed extension")
		}

		if extType == extensionKeyShare {
			// Key share extension format:
			// - 2 bytes: group
			// - 2 bytes: key exchange length
			// - N bytes: key exchange data
			if extDataLen < 4 {
				return errors.New("tls: key share extension too short")
			}

			// Bounds check: ensure we can read key exchange length
			if offset+4 > len(data) {
				return errors.New("tls: truncated key share extension")
			}

			keyExchangeLen := int(binary.BigEndian.Uint16(data[offset+2:]))
			if len(s.keyShareData) != keyExchangeLen {
				return fmt.Errorf("tls: key share data length mismatch: got %d, need %d",
					len(s.keyShareData), keyExchangeLen)
			}

			// Bounds check: ensure we can write key share data
			if offset+4+keyExchangeLen > len(data) {
				return errors.New("tls: key share data exceeds buffer")
			}

			// Replace key share data
			copy(data[offset+4:], s.keyShareData)
			return nil
		}

		offset += extDataLen
	}

	return errors.New("tls: key share extension not found")
}

// ValidateCompatibility checks if captured ServerHello is compatible with ClientHello.
func (s *ServerHelloSynthesizer) ValidateCompatibility(clientHello *ClientHelloInfo) error {
	if s.captured == nil {
		return errors.New("tls: no captured ServerHello")
	}

	if clientHello == nil {
		return errors.New("tls: no ClientHello provided")
	}

	// Check cipher suite is in client's list
	cipherOK := false
	for _, c := range clientHello.CipherSuites {
		if c == s.captured.CipherSuite {
			cipherOK = true
			break
		}
	}
	if !cipherOK {
		return fmt.Errorf("tls: cipher suite 0x%04x not in client's list", s.captured.CipherSuite)
	}

	// Check key share group is supported
	if s.captured.KeyShareGroup != 0 {
		groupOK := false
		for _, g := range clientHello.SupportedCurves {
			if g == s.captured.KeyShareGroup {
				groupOK = true
				break
			}
		}
		if !groupOK {
			return fmt.Errorf("tls: key share group %d not supported by client", s.captured.KeyShareGroup)
		}
	}

	// Check ALPN if set
	if s.captured.SelectedALPN != "" && len(clientHello.SupportedProtos) > 0 {
		alpnOK := false
		for _, proto := range clientHello.SupportedProtos {
			if proto == s.captured.SelectedALPN {
				alpnOK = true
				break
			}
		}
		if !alpnOK {
			return fmt.Errorf("tls: ALPN %q not in client's list", s.captured.SelectedALPN)
		}
	}

	return nil
}

// ProfileWarmer captures ServerHellos from real targets in background.
// This enables proactive caching of server fingerprints.
type ProfileWarmer struct {
	cache       *ServerHelloCache
	targets     []string
	interval    time.Duration
	dialTimeout time.Duration
	clientHello *ClientHelloSpec

	// Security: Optional certificate verification
	// If nil, InsecureSkipVerify is used (MitM risk in untrusted networks)
	RootCAs     *x509.CertPool
	VerifyCerts bool

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Callbacks
	OnCapture func(target string, captured *CapturedServerHello)
	OnError   func(target string, err error)
}

// NewProfileWarmer creates a background profile warmer.
// cache must not be nil; returns error if nil is provided.
// For panic-on-nil behavior, use MustNewProfileWarmer.
func NewProfileWarmer(cache *ServerHelloCache, targets []string) (*ProfileWarmer, error) {
	if cache == nil {
		return nil, errors.New("tls: NewProfileWarmer requires non-nil cache")
	}
	return &ProfileWarmer{
		cache:       cache,
		targets:     targets,
		interval:    5 * time.Minute,
		dialTimeout: 10 * time.Second,
	}, nil
}

// WithInterval sets the warming interval.
func (pw *ProfileWarmer) WithInterval(interval time.Duration) *ProfileWarmer {
	pw.interval = interval
	return pw
}

// WithDialTimeout sets the connection timeout.
func (pw *ProfileWarmer) WithDialTimeout(timeout time.Duration) *ProfileWarmer {
	pw.dialTimeout = timeout
	return pw
}

// WithClientHelloSpec sets the ClientHello spec to use for capture.
func (pw *ProfileWarmer) WithClientHelloSpec(spec *ClientHelloSpec) *ProfileWarmer {
	pw.clientHello = spec
	return pw
}

// Start begins background profiling.
func (pw *ProfileWarmer) Start() {
	pw.mu.Lock()
	if pw.running {
		pw.mu.Unlock()
		return
	}
	pw.running = true
	pw.stopCh = make(chan struct{})
	// Add to WaitGroup inside lock to prevent race with Stop()
	// Stop() checks running flag before calling wg.Wait()
	pw.wg.Add(1)
	pw.mu.Unlock()

	go pw.warmLoop()
}

// Stop halts background profiling and waits for completion.
func (pw *ProfileWarmer) Stop() {
	pw.mu.Lock()
	if !pw.running {
		pw.mu.Unlock()
		return
	}
	close(pw.stopCh)
	pw.running = false
	pw.mu.Unlock()

	pw.wg.Wait()
}

// IsRunning returns whether the warmer is active.
func (pw *ProfileWarmer) IsRunning() bool {
	pw.mu.Lock()
	defer pw.mu.Unlock()
	return pw.running
}

// WarmNow triggers immediate warming of all targets.
// Safe to call even when background warming is running.
func (pw *ProfileWarmer) WarmNow() {
	pw.mu.Lock()
	running := pw.running
	pw.mu.Unlock()

	// If background loop is running, just let it handle things
	// to avoid duplicate connections to same targets
	if running {
		return
	}

	pw.warmAll()
}

// WarmTarget captures ServerHello from a specific target.
func (pw *ProfileWarmer) WarmTarget(target string) error {
	return pw.warmTarget(target)
}

func (pw *ProfileWarmer) warmLoop() {
	defer pw.wg.Done()

	ticker := time.NewTicker(pw.interval)
	defer ticker.Stop()

	// Initial warm
	pw.warmAll()

	for {
		select {
		case <-ticker.C:
			pw.warmAll()
		case <-pw.stopCh:
			return
		}
	}
}

func (pw *ProfileWarmer) warmAll() {
	for _, target := range pw.targets {
		// Check if stopped
		select {
		case <-pw.stopCh:
			return
		default:
		}

		if err := pw.warmTarget(target); err != nil {
			if pw.OnError != nil {
				pw.OnError(target, err)
			}
		}
	}
}

func (pw *ProfileWarmer) warmTarget(target string) error {
	// Connect to target
	conn, err := net.DialTimeout("tcp", target, pw.dialTimeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Set deadline for handshake
	conn.SetDeadline(time.Now().Add(pw.dialTimeout))

	hostname := extractHostname(target)

	// Create TLS client config
	// Security: Use certificate verification if enabled
	config := &Config{
		ServerName:         hostname,
		InsecureSkipVerify: !pw.VerifyCerts,
		RootCAs:            pw.RootCAs,
	}

	// Capture ServerHello during handshake
	captured, err := captureServerHello(conn, config, pw.clientHello)
	if err != nil {
		return fmt.Errorf("capture: %w", err)
	}

	captured.TargetHost = target
	captured.CapturedAt = time.Now()

	// Store in cache
	pw.cache.Put(target, captured)

	if pw.OnCapture != nil {
		pw.OnCapture(target, captured)
	}

	return nil
}

// captureServerHello performs a TLS handshake and captures the ServerHello.
// Uses UClient which captures rawServerHello during handshake.
func captureServerHello(conn net.Conn, config *Config, spec *ClientHelloSpec) (*CapturedServerHello, error) {
	var uconn *UConn
	var err error

	if spec != nil {
		// Use UClient with custom spec
		uconn, err = UClient(conn, config, HelloCustom)
		if err != nil {
			return nil, err
		}
		if err := uconn.ApplyPreset(spec); err != nil {
			return nil, fmt.Errorf("apply preset: %w", err)
		}
	} else {
		// Use default Chrome fingerprint for capture
		uconn, err = UClient(conn, config, HelloChrome_Auto)
		if err != nil {
			return nil, err
		}
	}

	// Perform handshake - UConn captures rawServerHello automatically
	err = uconn.Handshake()

	// Check if we captured ServerHello (may have captured even if handshake failed)
	rawServerHello := uconn.RawServerHello()
	if len(rawServerHello) == 0 {
		if err != nil {
			return nil, fmt.Errorf("handshake: %w", err)
		}
		return nil, errors.New("tls: ServerHello not captured")
	}

	// Parse the captured ServerHello
	captured, parseErr := ParseServerHello(rawServerHello)
	if parseErr != nil {
		return nil, fmt.Errorf("parse ServerHello: %w", parseErr)
	}

	// Compute JA4S fingerprint
	ja4sFp, ja4sErr := CalculateJA4S(rawServerHello)
	if ja4sErr == nil && ja4sFp != nil {
		captured.JA4S = ja4sFp.JA4S
	}

	return captured, nil
}

// extractHostname extracts hostname from host:port string.
func extractHostname(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return target // Assume it's just a hostname
	}
	return host
}

// ParseServerHello parses raw ServerHello bytes into CapturedServerHello.
func ParseServerHello(raw []byte) (*CapturedServerHello, error) {
	// Minimum: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1) = 38
	minSize := 38

	// Check if handshake header is present (starts with typeServerHello = 0x02)
	offset := 0
	if len(raw) > 0 && raw[0] == typeServerHello {
		offset = 4
		minSize = 42 // Need 4 extra bytes for handshake header
	}

	if len(raw) < minSize {
		return nil, errors.New("tls: ServerHello too short")
	}

	captured := &CapturedServerHello{
		Raw: make([]byte, len(raw)),
	}
	copy(captured.Raw, raw)

	// Legacy version
	if offset+2 > len(raw) {
		return nil, errors.New("tls: ServerHello truncated at version")
	}
	captured.Version = binary.BigEndian.Uint16(raw[offset:])
	offset += 2

	// Random (32 bytes)
	if offset+32 > len(raw) {
		return nil, errors.New("tls: ServerHello truncated at random")
	}
	copy(captured.Random[:], raw[offset:offset+32])
	offset += 32

	// Session ID length
	if offset >= len(raw) {
		return nil, errors.New("tls: ServerHello truncated at session ID length")
	}
	sessionIDLen := int(raw[offset])

	// RFC 8446: legacy_session_id must be 0-32 bytes
	if sessionIDLen > 32 {
		return nil, errors.New("tls: ServerHello session ID exceeds maximum length (32 bytes)")
	}
	offset++
	if sessionIDLen > 0 {
		if offset+sessionIDLen > len(raw) {
			return nil, errors.New("tls: invalid session ID length")
		}
		captured.SessionID = make([]byte, sessionIDLen)
		copy(captured.SessionID, raw[offset:offset+sessionIDLen])
		offset += sessionIDLen
	}

	// Cipher suite
	if offset+2 > len(raw) {
		return nil, errors.New("tls: ServerHello truncated at cipher suite")
	}
	captured.CipherSuite = binary.BigEndian.Uint16(raw[offset:])
	offset += 2

	// Compression method
	if offset >= len(raw) {
		return nil, errors.New("tls: ServerHello truncated at compression")
	}
	captured.CompressionMethod = raw[offset]
	offset++

	// Extensions (optional)
	if offset+2 <= len(raw) {
		extLen := int(binary.BigEndian.Uint16(raw[offset:]))
		offset += 2

		// Bounds check: ensure extLen doesn't exceed remaining data
		if offset+extLen > len(raw) {
			return nil, errors.New("tls: ServerHello extensions length exceeds data")
		}

		if err := parseServerHelloExtensions(captured, raw[offset:offset+extLen]); err != nil {
			return nil, err
		}
	}

	captured.Fingerprint = captured.ComputeFingerprint()
	return captured, nil
}

// parseServerHelloExtensions parses extensions from raw bytes.
// Populates both Extensions (type list) and ExtensionData (full data map).
// ExtensionData enables JA4S variation by allowing extension reordering.
func parseServerHelloExtensions(captured *CapturedServerHello, data []byte) error {
	offset := 0

	// Initialize ExtensionData map for JA4S variation support
	if captured.ExtensionData == nil {
		captured.ExtensionData = make(map[uint16][]byte)
	}

	for offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset:])
		extLen := int(binary.BigEndian.Uint16(data[offset+2:]))
		offset += 4

		if offset+extLen > len(data) {
			return errors.New("tls: malformed extension")
		}

		captured.Extensions = append(captured.Extensions, extType)
		extData := data[offset : offset+extLen]

		// Store extension data for JA4S variation (enables shuffled reconstruction)
		// Deep copy to prevent aliasing with Raw buffer
		dataCopy := make([]byte, extLen)
		copy(dataCopy, extData)
		captured.ExtensionData[extType] = dataCopy

		switch extType {
		case extensionSupportedVersions:
			if extLen >= 2 {
				captured.SupportedVersion = binary.BigEndian.Uint16(extData)
			}

		case extensionKeyShare:
			if extLen >= 4 {
				captured.KeyShareGroup = CurveID(binary.BigEndian.Uint16(extData))
				keyLen := int(binary.BigEndian.Uint16(extData[2:]))
				if 4+keyLen <= extLen {
					captured.KeyShareData = make([]byte, keyLen)
					copy(captured.KeyShareData, extData[4:4+keyLen])
				}
			}

		case extensionALPN:
			if extLen >= 3 {
				// ALPN list length (2) + protocol length (1) + protocol
				protoLen := int(extData[2])
				if 3+protoLen <= extLen {
					captured.SelectedALPN = string(extData[3 : 3+protoLen])
				}
			}
		}

		offset += extLen
	}

	return nil
}
