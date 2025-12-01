// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"io"
	"sync"
	"time"
)

// JARMDefenseConfig configures JARM probe detection and defense.
type JARMDefenseConfig struct {
	// Enabled activates JARM probe detection.
	Enabled bool

	// OnProbeDetected is called when a JARM probe is detected.
	// score is the detection confidence (0-100).
	OnProbeDetected func(score int, clientHello *ClientHelloInfo)

	// RandomizeOnProbe randomizes ServerHello fields when probe detected.
	// This breaks JARM fingerprinting by making each response unique.
	RandomizeOnProbe bool

	// DisableSynthesisOnProbe disables ServerHello synthesis on probe.
	// Falls back to real server response behavior.
	DisableSynthesisOnProbe bool

	// MinScoreForAction is the minimum score to trigger defensive actions.
	// Default is 50.
	MinScoreForAction int

	// LogProbes enables logging of detected probes.
	LogProbes bool
}

// DefaultJARMDefenseConfig returns default JARM defense configuration.
func DefaultJARMDefenseConfig() *JARMDefenseConfig {
	return &JARMDefenseConfig{
		Enabled:           false,
		RandomizeOnProbe:  true,
		MinScoreForAction: 50,
	}
}

// JARMProbeDetector detects JARM fingerprinting probes.
type JARMProbeDetector struct {
	config *JARMDefenseConfig

	// Track recent connections for pattern analysis
	mu             sync.RWMutex
	recentProbes   []probeRecord
	maxProbeWindow time.Duration
	maxProbes      int // Maximum probe records to prevent memory exhaustion
}

// probeRecord stores information about a potential probe.
type probeRecord struct {
	timestamp time.Time
	score     int
}

// NewJARMProbeDetector creates a new JARM probe detector.
func NewJARMProbeDetector(config *JARMDefenseConfig) *JARMProbeDetector {
	if config == nil {
		config = DefaultJARMDefenseConfig()
	}
	return &JARMProbeDetector{
		config:         config,
		recentProbes:   make([]probeRecord, 0, 100),
		maxProbeWindow: 5 * time.Minute,
		maxProbes:      10000, // Limit to prevent memory exhaustion under DoS
	}
}

// Analyze analyzes a ClientHello for JARM probe characteristics.
// Returns score 0-100 where higher = more likely to be JARM probe.
func (d *JARMProbeDetector) Analyze(clientHello *ClientHelloInfo, timing time.Duration) int {
	if !d.config.Enabled {
		return 0
	}

	score := JARMProbeScore(clientHello, timing)

	// Record if above threshold
	if score >= d.config.MinScoreForAction {
		d.recordProbe(clientHello, score)

		if d.config.OnProbeDetected != nil {
			d.config.OnProbeDetected(score, clientHello)
		}
	}

	return score
}

// recordProbe records a detected probe.
func (d *JARMProbeDetector) recordProbe(clientHello *ClientHelloInfo, score int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Clean old entries
	d.cleanOldProbes()

	// Enforce max probes limit to prevent memory exhaustion
	if len(d.recentProbes) >= d.maxProbes {
		// Create new slice to avoid memory leak from reslicing
		// Reslicing keeps old backing array alive
		newProbes := make([]probeRecord, len(d.recentProbes)-1, d.maxProbes)
		copy(newProbes, d.recentProbes[1:])
		d.recentProbes = newProbes
	}

	// Add new entry
	d.recentProbes = append(d.recentProbes, probeRecord{
		timestamp: time.Now(),
		score:     score,
	})
}

// cleanOldProbes removes probes outside the window.
func (d *JARMProbeDetector) cleanOldProbes() {
	cutoff := time.Now().Add(-d.maxProbeWindow)

	// Count how many to keep
	keepCount := 0
	for _, p := range d.recentProbes {
		if p.timestamp.After(cutoff) {
			keepCount++
		}
	}

	// If no change needed, return early
	if keepCount == len(d.recentProbes) {
		return
	}

	// Create new slice with kept entries to free old memory
	kept := make([]probeRecord, 0, keepCount)
	for _, p := range d.recentProbes {
		if p.timestamp.After(cutoff) {
			kept = append(kept, p)
		}
	}
	d.recentProbes = kept
}

// RecentProbeCount returns count of recent probes above threshold.
// Note: Uses Lock (not RLock) because cleanOldProbes modifies state.
func (d *JARMProbeDetector) RecentProbeCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.cleanOldProbes()
	return len(d.recentProbes)
}

// IsUnderAttack returns true if many probes detected recently.
func (d *JARMProbeDetector) IsUnderAttack(threshold int) bool {
	return d.RecentProbeCount() >= threshold
}

// JARMProbeScore calculates likelihood of JARM probe (0-100).
// Higher score = more likely to be JARM scan.
//
// JARM sends 10 specific probes to fingerprint TLS servers:
// - Probes use unusual cipher suite combinations
// - Probes omit common extensions (SNI, ALPN)
// - Probes are sent rapidly in sequence
// - Probes use specific TLS versions and parameters
func JARMProbeScore(clientHello *ClientHelloInfo, timing time.Duration) int {
	if clientHello == nil {
		return 0
	}

	score := 0

	// === CIPHER SUITE ANALYSIS (30 points max) ===
	if hasJARMCipherPattern(clientHello.CipherSuites) {
		score += 30
	}

	// === EXTENSION ANALYSIS (30 points max) ===
	if hasJARMExtensionPattern(clientHello) {
		score += 30
	}

	// === TIMING ANALYSIS (20 points max) ===
	// JARM sends probes very quickly in sequence
	if timing > 0 && timing < 100*time.Millisecond {
		score += 20
	} else if timing > 0 && timing < 500*time.Millisecond {
		score += 10
	}

	// === MISSING COMMON EXTENSIONS (10 points max) ===
	// Real browsers always send SNI
	if clientHello.ServerName == "" {
		score += 5
	}
	// Real browsers almost always advertise ALPN
	if len(clientHello.SupportedProtos) == 0 {
		score += 5
	}

	// === VERSION ANALYSIS (10 points max) ===
	// JARM probes sometimes use unusual version combinations
	if hasJARMVersionPattern(clientHello) {
		score += 10
	}

	// === GREASE DETECTION (negative points) ===
	// Modern browsers use GREASE values, JARM probes don't
	// If GREASE is present, this is likely a real browser, not JARM
	if hasGREASEValues(clientHello) {
		score -= 20 // Reduce score significantly for GREASE presence
	}

	// Clamp to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// hasGREASEValues checks if ClientHello contains GREASE values.
// GREASE (Generate Random Extensions And Sustain Extensibility) values
// follow the pattern 0x?A?A (e.g., 0x0A0A, 0x1A1A, 0x2A2A, etc.)
// Modern browsers use GREASE, but JARM probes typically don't.
func hasGREASEValues(clientHello *ClientHelloInfo) bool {
	// Check cipher suites for GREASE
	for _, cs := range clientHello.CipherSuites {
		if isGREASE(uint16(cs)) {
			return true
		}
	}

	// Check supported curves for GREASE
	for _, curve := range clientHello.SupportedCurves {
		if isGREASE(uint16(curve)) {
			return true
		}
	}

	// Check supported versions for GREASE
	for _, ver := range clientHello.SupportedVersions {
		if isGREASE(ver) {
			return true
		}
	}

	return false
}

// isGREASE returns true if the value matches the GREASE pattern.
// GREASE values: 0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
//
//	0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
//	0xCACA, 0xDADA, 0xEAEA, 0xFAFA
func isGREASE(value uint16) bool {
	// GREASE pattern: both bytes are ?A where ? is the same nibble
	// Equivalent to: high byte & 0x0F == 0x0A && high byte == low byte
	return (value&0x0F0F) == 0x0A0A && (value>>8) == (value&0xFF)
}

// hasJARMCipherPattern checks for JARM-specific cipher suite patterns.
// JARM uses 10 different probe configurations with specific cipher sets.
func hasJARMCipherPattern(ciphers []uint16) bool {
	if len(ciphers) == 0 {
		return false
	}

	// JARM probe signatures use specific cipher suite combinations
	// Pattern 1: Very limited cipher set (less than 5)
	if len(ciphers) < 5 {
		return true
	}

	// Pattern 2: Only TLS 1.2 ciphers (no TLS 1.3)
	hasTLS13 := false
	for _, c := range ciphers {
		if jarmIsTLS13Cipher(c) {
			hasTLS13 = true
			break
		}
	}
	// Modern browsers always include TLS 1.3 ciphers
	if !hasTLS13 && len(ciphers) > 0 {
		return true
	}

	// Pattern 3: Unusual ordering or obsolete ciphers first
	// JARM sometimes puts weak/export ciphers first
	if len(ciphers) > 0 && isWeakCipher(ciphers[0]) {
		return true
	}

	// Pattern 4: Contains NULL cipher
	for _, c := range ciphers {
		if isNullCipher(c) {
			return true
		}
	}

	return false
}

// jarmIsTLS13Cipher checks if cipher is TLS 1.3.
// Includes all RFC 8446 cipher suites including CCM variants.
func jarmIsTLS13Cipher(cipher uint16) bool {
	switch cipher {
	case TLS_AES_128_GCM_SHA256,        // 0x1301
		TLS_AES_256_GCM_SHA384,         // 0x1302
		TLS_CHACHA20_POLY1305_SHA256,   // 0x1303
		0x1304,                         // TLS_AES_128_CCM_SHA256
		0x1305:                         // TLS_AES_128_CCM_8_SHA256
		return true
	}
	return false
}

// isWeakCipher checks if cipher is considered weak.
func isWeakCipher(cipher uint16) bool {
	// Export ciphers, DES, RC4, etc.
	switch cipher {
	case 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, // NULL, EXPORT
		0x0007, 0x0008, 0x0009, 0x000A, // DES
		0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, // EXPORT
		0x0060, 0x0061, 0x0062, 0x0063, 0x0064: // EXPORT1024
		return true
	}
	return false
}

// isNullCipher checks if cipher is NULL (no encryption).
func isNullCipher(cipher uint16) bool {
	// TLS_NULL_WITH_NULL_NULL and related
	return cipher == 0x0000 || cipher == 0x0001 || cipher == 0x002C || cipher == 0x002D || cipher == 0x002E
}

// hasJARMExtensionPattern checks for JARM-specific extension patterns.
func hasJARMExtensionPattern(clientHello *ClientHelloInfo) bool {
	if clientHello == nil {
		return false
	}

	// JARM probes typically have minimal extensions
	// Real browsers have 10+ extensions

	// Check supported curves (real browsers have many)
	if len(clientHello.SupportedCurves) < 3 {
		return true
	}

	// Check signature algorithms (real browsers advertise many)
	// Note: We can't easily check this from ClientHelloInfo
	// but we can infer from other patterns

	// Check for point formats - real browsers include multiple
	if len(clientHello.SupportedPoints) == 0 {
		return true
	}

	return false
}

// hasJARMVersionPattern checks for unusual TLS version patterns.
func hasJARMVersionPattern(clientHello *ClientHelloInfo) bool {
	if clientHello == nil {
		return false
	}

	// JARM probes sometimes use specific version combinations
	versions := clientHello.SupportedVersions

	// No supported_versions extension is suspicious for modern TLS
	if len(versions) == 0 {
		return true
	}

	// Only TLS 1.0 or 1.1 is suspicious
	onlyOldTLS := true
	for _, v := range versions {
		if v >= VersionTLS12 {
			onlyOldTLS = false
			break
		}
	}
	// len(versions) > 0 is guaranteed here (checked above)
	return onlyOldTLS
}

// RandomizeServerHelloForJARM randomizes ServerHello fields to break JARM fingerprint.
// This should be called when a JARM probe is detected.
// Returns true if randomization succeeded, false on error.
func RandomizeServerHelloForJARM(hello *serverHelloMsg) bool {
	if hello == nil {
		return false
	}

	// Randomize session ID (32 bytes)
	if len(hello.sessionId) > 0 {
		if _, err := io.ReadFull(rand.Reader, hello.sessionId); err != nil {
			// Security: On random failure, don't modify partially
			return false
		}
	}

	// Note: We keep other fields like cipher suite and version consistent
	// to maintain a valid handshake. Only session ID needs randomization
	// to break JARM's fingerprinting without breaking the handshake.
	return true
}

// RandomizeServerHelloBytes randomizes ServerHello at the byte level.
// Returns modified bytes with randomized session ID.
func RandomizeServerHelloBytes(raw []byte) []byte {
	if len(raw) < 39 {
		return raw // Too short to be valid ServerHello
	}

	// Make a copy to avoid modifying original
	result := make([]byte, len(raw))
	copy(result, raw)

	// ServerHello structure:
	// - Handshake type (1 byte)
	// - Length (3 bytes)
	// - Version (2 bytes)
	// - Random (32 bytes) - at offset 6
	// - Session ID length (1 byte) - at offset 38
	// - Session ID (variable)

	offset := 0
	if result[0] == typeServerHello {
		offset = 4 // Skip handshake header
	}

	// Skip version (2 bytes) and random (32 bytes)
	sessionIDLenOffset := offset + 2 + 32
	if sessionIDLenOffset >= len(result) {
		return result
	}

	sessionIDLen := int(result[sessionIDLenOffset])
	sessionIDOffset := sessionIDLenOffset + 1

	if sessionIDOffset+sessionIDLen > len(result) {
		return result
	}

	// Randomize session ID
	if sessionIDLen > 0 {
		if _, err := io.ReadFull(rand.Reader, result[sessionIDOffset:sessionIDOffset+sessionIDLen]); err != nil {
			// Security: On random failure, return original unmodified
			return raw
		}
	}

	return result
}

// JARMDefenseMiddleware wraps TLS config to apply JARM defense.
// Use this to automatically detect and respond to JARM probes.
type JARMDefenseMiddleware struct {
	config   *JARMDefenseConfig
	detector *JARMProbeDetector
}

// NewJARMDefenseMiddleware creates JARM defense middleware.
func NewJARMDefenseMiddleware(config *JARMDefenseConfig) *JARMDefenseMiddleware {
	if config == nil {
		config = DefaultJARMDefenseConfig()
	}
	return &JARMDefenseMiddleware{
		config:   config,
		detector: NewJARMProbeDetector(config),
	}
}

// ShouldRandomize returns true if ServerHello should be randomized.
func (m *JARMDefenseMiddleware) ShouldRandomize(clientHello *ClientHelloInfo, timing time.Duration) bool {
	if !m.config.Enabled || !m.config.RandomizeOnProbe {
		return false
	}

	score := m.detector.Analyze(clientHello, timing)
	return score >= m.config.MinScoreForAction
}

// ShouldDisableSynthesis returns true if ServerHello synthesis should be disabled.
func (m *JARMDefenseMiddleware) ShouldDisableSynthesis(clientHello *ClientHelloInfo, timing time.Duration) bool {
	if !m.config.Enabled || !m.config.DisableSynthesisOnProbe {
		return false
	}

	score := m.detector.Analyze(clientHello, timing)
	return score >= m.config.MinScoreForAction
}

// ProcessServerHello applies JARM defense to ServerHello if needed.
func (m *JARMDefenseMiddleware) ProcessServerHello(raw []byte, clientHello *ClientHelloInfo, timing time.Duration) []byte {
	if !m.config.Enabled {
		return raw
	}

	score := m.detector.Analyze(clientHello, timing)
	if score < m.config.MinScoreForAction {
		return raw
	}

	if m.config.RandomizeOnProbe {
		return RandomizeServerHelloBytes(raw)
	}

	return raw
}

// GetDetector returns the underlying probe detector for advanced usage.
func (m *JARMDefenseMiddleware) GetDetector() *JARMProbeDetector {
	return m.detector
}
