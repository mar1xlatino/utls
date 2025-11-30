// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// patternCache caches compiled regex patterns to avoid recompilation.
// Using sync.Map for concurrent access without explicit locking.
var patternCache sync.Map // map[string]*regexp.Regexp

// patternCacheSize tracks the approximate number of entries in patternCache.
// This is approximate because sync.Map doesn't provide a Size() method.
var patternCacheSize int64

// patternCacheMaxSize is the maximum number of patterns to cache.
// When exceeded, the cache is cleared to prevent unbounded memory growth.
const patternCacheMaxSize = 10000

// ValidationResult contains the outcome of fingerprint validation.
type ValidationResult struct {
	Valid      bool        // Overall validation passed
	Score      float64     // Match score 0.0-1.0
	Mismatches []Mismatch  // List of mismatches found
	Warnings   []Warning   // Non-fatal issues
	Timestamp  time.Time
}

// Mismatch represents a fingerprint mismatch.
type Mismatch struct {
	Field    string      // Field name: "JA4", "cipher_order", "extension_13"
	Expected interface{} // Expected value
	Actual   interface{} // Actual value
	Severity Severity    // critical, high, medium, low
	Message  string      // Human-readable description
}

// Severity levels for mismatches.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the severity as a string.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Warning represents a non-fatal validation issue.
type Warning struct {
	Field   string
	Message string
}

// FingerprintValidator validates TLS messages against a profile.
type FingerprintValidator struct {
	profile      *FingerprintProfile
	sessionState *SessionFingerprintState
	strictMode   bool
}

// NewValidator creates a validator for a profile.
func NewValidator(profile *FingerprintProfile) *FingerprintValidator {
	return &FingerprintValidator{
		profile:    profile,
		strictMode: false,
	}
}

// NewStrictValidator creates a strict validator (fails on any mismatch).
func NewStrictValidator(profile *FingerprintProfile) *FingerprintValidator {
	return &FingerprintValidator{
		profile:    profile,
		strictMode: true,
	}
}

// NewSessionValidator creates a validator using session state.
func NewSessionValidator(state *SessionFingerprintState) *FingerprintValidator {
	return &FingerprintValidator{
		sessionState: state,
		strictMode:   false,
	}
}

// ValidateJA4 validates JA4 fingerprint specifically.
func (v *FingerprintValidator) ValidateJA4(actual string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	expected := v.profile.Expected.JA4
	if expected == "" {
		result.Warnings = append(result.Warnings, Warning{
			Field:   "JA4",
			Message: "no expected JA4 fingerprint defined in profile",
		})
		return result
	}

	if actual != expected {
		result.Valid = false
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "JA4",
			Expected: expected,
			Actual:   actual,
			Severity: SeverityCritical,
			Message:  "JA4 fingerprint does not match expected value",
		})

		// Calculate partial match score
		result.Score = calculateJA4MatchScore(actual, expected)
	}

	return result
}

// ValidateJA3 validates JA3 fingerprint specifically.
func (v *FingerprintValidator) ValidateJA3(actual string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	expected := v.profile.Expected.JA3
	if expected == "" {
		result.Warnings = append(result.Warnings, Warning{
			Field:   "JA3",
			Message: "no expected JA3 fingerprint defined in profile",
		})
		return result
	}

	if actual != expected {
		result.Valid = false
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "JA3",
			Expected: expected,
			Actual:   actual,
			Severity: SeverityHigh,
			Message:  "JA3 fingerprint does not match expected value",
		})
		result.Score = 0.0
	}

	return result
}

// calculateJA4MatchScore calculates how closely two JA4 fingerprints match.
func calculateJA4MatchScore(actual, expected string) float64 {
	if actual == expected {
		return 1.0
	}

	// JA4 format: "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	actualParts := strings.Split(actual, "_")
	expectedParts := strings.Split(expected, "_")

	if len(actualParts) != 3 || len(expectedParts) != 3 {
		return 0.0
	}

	score := 0.0

	// Part A (protocol, version, SNI, counts, ALPN) - most important
	if actualParts[0] == expectedParts[0] {
		score += 0.5
	} else {
		// Partial match for part A
		comp := compareJA4PartA(actualParts[0], expectedParts[0])
		score += 0.5 * comp
	}

	// Part B (ciphers hash)
	if actualParts[1] == expectedParts[1] {
		score += 0.25
	}

	// Part C (extensions hash)
	if actualParts[2] == expectedParts[2] {
		score += 0.25
	}

	return score
}

// compareJA4PartA compares the A component of JA4 fingerprints.
func compareJA4PartA(actual, expected string) float64 {
	if len(actual) != len(expected) {
		return 0.0
	}

	matches := 0
	for i := 0; i < len(actual) && i < len(expected); i++ {
		if actual[i] == expected[i] {
			matches++
		}
	}

	if len(actual) == 0 {
		return 0.0
	}
	return float64(matches) / float64(len(actual))
}

// ValidateJA4S validates JA4S fingerprint.
func (v *FingerprintValidator) ValidateJA4S(actual string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	acceptablePatterns := v.profile.ServerExpectations.AcceptableJA4S
	if len(acceptablePatterns) == 0 {
		result.Warnings = append(result.Warnings, Warning{
			Field:   "JA4S",
			Message: "no acceptable JA4S patterns defined in profile",
		})
		return result
	}

	// Check if actual matches any acceptable pattern
	for _, pattern := range acceptablePatterns {
		if matchesPattern(actual, pattern) {
			return result // Match found
		}
	}

	result.Valid = false
	result.Score = 0.0
	result.Mismatches = append(result.Mismatches, Mismatch{
		Field:    "JA4S",
		Expected: acceptablePatterns,
		Actual:   actual,
		Severity: SeverityMedium,
		Message:  "JA4S does not match any acceptable pattern",
	})

	return result
}

// ValidateJA4X validates JA4X fingerprint.
func (v *FingerprintValidator) ValidateJA4X(actual string) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	acceptablePatterns := v.profile.ServerExpectations.Certificate.AcceptableJA4X
	if len(acceptablePatterns) == 0 {
		result.Warnings = append(result.Warnings, Warning{
			Field:   "JA4X",
			Message: "no acceptable JA4X patterns defined in profile",
		})
		return result
	}

	// Check if actual matches any acceptable pattern
	for _, pattern := range acceptablePatterns {
		if matchesPattern(actual, pattern) {
			return result // Match found
		}
	}

	result.Valid = false
	result.Score = 0.0
	result.Mismatches = append(result.Mismatches, Mismatch{
		Field:    "JA4X",
		Expected: acceptablePatterns,
		Actual:   actual,
		Severity: SeverityLow,
		Message:  "JA4X does not match any acceptable pattern",
	})

	return result
}

// matchesPattern checks if a value matches a pattern (exact or regex).
func matchesPattern(value, pattern string) bool {
	if value == pattern {
		return true
	}

	// Reject overly complex patterns to prevent ReDoS
	if len(pattern) > 500 {
		return false
	}

	// Try regex match with cached compiled pattern
	re := getCachedRegex(pattern)
	if re == nil {
		return false
	}

	return re.MatchString(value)
}

// getCachedRegex returns a cached compiled regex, compiling and caching if needed.
// Returns nil if the pattern is invalid.
// The cache is automatically cleared when it exceeds patternCacheMaxSize to prevent
// unbounded memory growth.
func getCachedRegex(pattern string) *regexp.Regexp {
	// Check cache first
	if cached, ok := patternCache.Load(pattern); ok {
		if re, ok := cached.(*regexp.Regexp); ok {
			return re
		}
		return nil // Cached as invalid
	}

	// Check if cache needs to be cleared (approximate size exceeded)
	currentSize := atomic.LoadInt64(&patternCacheSize)
	if currentSize >= patternCacheMaxSize {
		// Clear cache - this is a simple strategy that trades off some
		// cache misses for predictable memory usage.
		clearPatternCache()
	}

	// Compile and cache
	re, err := regexp.Compile(pattern)
	if err != nil {
		// Cache nil to avoid recompiling invalid patterns
		patternCache.Store(pattern, (*regexp.Regexp)(nil))
		atomic.AddInt64(&patternCacheSize, 1)
		return nil
	}

	patternCache.Store(pattern, re)
	atomic.AddInt64(&patternCacheSize, 1)
	return re
}

// clearPatternCache clears the pattern cache and resets the size counter.
// This is called when the cache exceeds patternCacheMaxSize.
func clearPatternCache() {
	// Create a new empty sync.Map by resetting the global variable.
	// Note: This is safe because sync.Map handles concurrent access internally.
	// Existing goroutines may still see some old entries during the transition,
	// which is acceptable for a cache.
	patternCache = sync.Map{}
	atomic.StoreInt64(&patternCacheSize, 0)
}

// ValidateCertificate validates a certificate's JA4X.
func (v *FingerprintValidator) ValidateCertificate(cert *x509.Certificate) *ValidationResult {
	if cert == nil {
		return &ValidationResult{
			Valid:     false,
			Score:     0.0,
			Timestamp: time.Now(),
			Mismatches: []Mismatch{{
				Field:    "certificate",
				Severity: SeverityCritical,
				Message:  "nil certificate",
			}},
		}
	}

	fp := CalculateJA4X(cert)
	return v.ValidateJA4X(fp.JA4X)
}

// ValidateCertificateChain validates entire certificate chain.
func (v *FingerprintValidator) ValidateCertificateChain(certs []*x509.Certificate) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	// Check for nil profile first to avoid nil pointer dereference
	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	if len(certs) == 0 {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "certificate_chain",
			Severity: SeverityCritical,
			Message:  "empty certificate chain",
		})
		return result
	}

	// Validate leaf certificate JA4X
	leafResult := v.ValidateCertificate(certs[0])
	if !leafResult.Valid {
		result.Valid = false
		result.Mismatches = append(result.Mismatches, leafResult.Mismatches...)
	}
	result.Score = leafResult.Score

	// Additional chain validation if required
	if v.profile.ServerExpectations.Certificate.ValidateChain {
		// Check chain length, validity, etc.
		for i, cert := range certs {
			if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
				result.Warnings = append(result.Warnings, Warning{
					Field:   fmt.Sprintf("certificate[%d]", i),
					Message: "certificate not within validity period",
				})
			}
		}
	}

	return result
}

// ValidateCipherSuites validates cipher suite selection.
func (v *FingerprintValidator) ValidateCipherSuites(ciphers []uint16) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	expected := v.profile.ClientHello.CipherSuites
	if len(expected) == 0 {
		result.Warnings = append(result.Warnings, Warning{
			Field:   "cipher_suites",
			Message: "no expected cipher suites defined",
		})
		return result
	}

	// Check count
	if len(ciphers) != len(expected) {
		result.Score -= 0.3
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "cipher_count",
			Expected: len(expected),
			Actual:   len(ciphers),
			Severity: SeverityHigh,
			Message:  "cipher suite count mismatch",
		})
	}

	// Check order
	orderMismatches := 0
	for i := 0; i < len(ciphers) && i < len(expected); i++ {
		if ciphers[i] != expected[i] {
			// Allow GREASE placeholder mismatch
			if !isGREASEUint16(expected[i]) {
				orderMismatches++
			}
		}
	}

	if orderMismatches > 0 {
		result.Score -= float64(orderMismatches) * 0.05
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "cipher_order",
			Expected: expected,
			Actual:   ciphers,
			Severity: SeverityMedium,
			Message:  fmt.Sprintf("%d cipher suites in wrong order", orderMismatches),
		})
	}

	if result.Score < 0 {
		result.Score = 0
	}
	result.Valid = len(result.Mismatches) == 0

	return result
}

// ValidateExtensions validates extension list.
func (v *FingerprintValidator) ValidateExtensions(extensions []uint16) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	expected := make([]uint16, len(v.profile.ClientHello.Extensions))
	for i, ext := range v.profile.ClientHello.Extensions {
		expected[i] = ext.Type
	}

	if len(expected) == 0 {
		result.Warnings = append(result.Warnings, Warning{
			Field:   "extensions",
			Message: "no expected extensions defined",
		})
		return result
	}

	// For browsers that shuffle (Chrome), we check presence not order
	if v.profile.ClientHello.ShuffleExtensions {
		return v.validateExtensionsUnordered(extensions, expected)
	}

	return v.validateExtensionsOrdered(extensions, expected)
}

// validateExtensionsOrdered validates extensions in strict order (Firefox).
func (v *FingerprintValidator) validateExtensionsOrdered(actual, expected []uint16) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	// Filter GREASE from both
	actualFiltered := filterGREASE(actual)
	expectedFiltered := filterGREASE(expected)

	if len(actualFiltered) != len(expectedFiltered) {
		result.Score -= 0.3
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "extension_count",
			Expected: len(expectedFiltered),
			Actual:   len(actualFiltered),
			Severity: SeverityHigh,
			Message:  "extension count mismatch",
		})
	}

	// Check order
	orderMismatches := 0
	for i := 0; i < len(actualFiltered) && i < len(expectedFiltered); i++ {
		if actualFiltered[i] != expectedFiltered[i] {
			orderMismatches++
		}
	}

	if orderMismatches > 0 {
		result.Score -= float64(orderMismatches) * 0.05
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "extension_order",
			Expected: expectedFiltered,
			Actual:   actualFiltered,
			Severity: SeverityHigh,
			Message:  fmt.Sprintf("%d extensions in wrong order", orderMismatches),
		})
	}

	if result.Score < 0 {
		result.Score = 0
	}
	result.Valid = len(result.Mismatches) == 0

	return result
}

// validateExtensionsUnordered validates extensions ignoring order (Chrome).
func (v *FingerprintValidator) validateExtensionsUnordered(actual, expected []uint16) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	// Filter GREASE from both
	actualFiltered := filterGREASE(actual)
	expectedFiltered := filterGREASE(expected)

	// Build sets
	actualSet := make(map[uint16]bool)
	expectedSet := make(map[uint16]bool)

	for _, ext := range actualFiltered {
		actualSet[ext] = true
	}
	for _, ext := range expectedFiltered {
		expectedSet[ext] = true
	}

	// Check for missing extensions
	var missing []uint16
	for ext := range expectedSet {
		if !actualSet[ext] {
			missing = append(missing, ext)
		}
	}

	// Check for extra extensions
	var extra []uint16
	for ext := range actualSet {
		if !expectedSet[ext] {
			extra = append(extra, ext)
		}
	}

	if len(missing) > 0 {
		result.Score -= float64(len(missing)) * 0.1
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "missing_extensions",
			Expected: missing,
			Severity: SeverityHigh,
			Message:  fmt.Sprintf("%d expected extensions missing", len(missing)),
		})
	}

	if len(extra) > 0 {
		result.Score -= float64(len(extra)) * 0.05
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "extra_extensions",
			Actual:   extra,
			Severity: SeverityMedium,
			Message:  fmt.Sprintf("%d unexpected extensions present", len(extra)),
		})
	}

	if result.Score < 0 {
		result.Score = 0
	}
	result.Valid = len(result.Mismatches) == 0

	return result
}

// filterGREASE removes GREASE values from a slice.
func filterGREASE(values []uint16) []uint16 {
	var result []uint16
	for _, v := range values {
		if !isGREASEUint16(v) {
			result = append(result, v)
		}
	}
	return result
}

// ValidateGREASE validates GREASE value usage.
func (v *FingerprintValidator) ValidateGREASE(ciphers, extensions []uint16) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.profile == nil {
		result.Valid = false
		result.Score = 0.0
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "profile",
			Severity: SeverityCritical,
			Message:  "validator has nil profile",
		})
		return result
	}

	greaseConfig := v.profile.ClientHello.GREASE

	// Check if GREASE is enabled when it shouldn't be
	hasGREASE := false
	for _, c := range ciphers {
		if isGREASEUint16(c) {
			hasGREASE = true
			break
		}
	}
	if !hasGREASE {
		for _, e := range extensions {
			if isGREASEUint16(e) {
				hasGREASE = true
				break
			}
		}
	}

	if greaseConfig.Enabled && !hasGREASE {
		result.Score -= 0.3
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "grease",
			Expected: "GREASE enabled",
			Actual:   "no GREASE values found",
			Severity: SeverityHigh,
			Message:  "GREASE should be enabled but no GREASE values found",
		})
	}

	if !greaseConfig.Enabled && hasGREASE {
		result.Score -= 0.3
		result.Mismatches = append(result.Mismatches, Mismatch{
			Field:    "grease",
			Expected: "GREASE disabled",
			Actual:   "GREASE values found",
			Severity: SeverityHigh,
			Message:  "GREASE should be disabled but GREASE values found",
		})
	}

	result.Valid = len(result.Mismatches) == 0

	return result
}

// ValidateSessionConsistency checks if values are consistent with session state.
func (v *FingerprintValidator) ValidateSessionConsistency(ciphers, extensions []uint16) *ValidationResult {
	result := &ValidationResult{
		Valid:     true,
		Score:     1.0,
		Timestamp: time.Now(),
	}

	if v.sessionState == nil {
		result.Warnings = append(result.Warnings, Warning{
			Field:   "session",
			Message: "no session state available for consistency check",
		})
		return result
	}

	// Check GREASE consistency - only if GREASE values were actually frozen
	// A zero value means GREASE was not enabled when session was created
	frozenGREASECipher := v.sessionState.FrozenGREASE.CipherSuite
	if frozenGREASECipher != 0 {
		for _, c := range ciphers {
			if isGREASEUint16(c) {
				if c != frozenGREASECipher {
					result.Score -= 0.2
					result.Mismatches = append(result.Mismatches, Mismatch{
						Field:    "grease_cipher",
						Expected: frozenGREASECipher,
						Actual:   c,
						Severity: SeverityCritical,
						Message:  "GREASE cipher value changed within session",
					})
				}
				break // Only check first GREASE
			}
		}

		// Also check extension GREASE values for consistency
		frozenGREASEExt1 := v.sessionState.FrozenGREASE.Extension1
		frozenGREASEExt2 := v.sessionState.FrozenGREASE.Extension2
		greaseExtCount := 0
		for _, e := range extensions {
			if isGREASEUint16(e) {
				greaseExtCount++
				var expected uint16
				if greaseExtCount == 1 {
					expected = frozenGREASEExt1
				} else if greaseExtCount == 2 {
					expected = frozenGREASEExt2
				} else {
					break // Only check first two GREASE extensions
				}
				if expected != 0 && e != expected {
					result.Score -= 0.1
					result.Mismatches = append(result.Mismatches, Mismatch{
						Field:    fmt.Sprintf("grease_extension_%d", greaseExtCount),
						Expected: expected,
						Actual:   e,
						Severity: SeverityHigh,
						Message:  fmt.Sprintf("GREASE extension %d value changed within session", greaseExtCount),
					})
				}
			}
		}
	}

	// Check extension order consistency if shuffled
	if v.sessionState.FrozenExtensionOrder != nil {
		actualOrder := filterGREASE(extensions)
		expectedOrder := filterGREASE(v.sessionState.FrozenExtensionOrder)

		if len(actualOrder) != len(expectedOrder) {
			result.Score -= 0.2
			result.Mismatches = append(result.Mismatches, Mismatch{
				Field:    "extension_count",
				Expected: len(expectedOrder),
				Actual:   len(actualOrder),
				Severity: SeverityHigh,
				Message:  "extension count changed within session",
			})
		} else {
			for i := range actualOrder {
				if actualOrder[i] != expectedOrder[i] {
					result.Score -= 0.1
					result.Mismatches = append(result.Mismatches, Mismatch{
						Field:    "extension_order",
						Expected: expectedOrder,
						Actual:   actualOrder,
						Severity: SeverityCritical,
						Message:  "extension order changed within session",
					})
					break
				}
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}
	result.Valid = len(result.Mismatches) == 0

	return result
}

// JA4Comparison shows which parts of JA4 match/differ.
type JA4Comparison struct {
	Match            bool
	VersionMatch     bool
	SNIMatch         bool
	CipherCountMatch bool
	ExtCountMatch    bool
	ALPNMatch        bool
	CipherHashMatch  bool
	ExtHashMatch     bool
	Diff             string
	AVersion         string
	BVersion         string
	ACipherCount     int
	BCipherCount     int
	AExtCount        int
	BExtCount        int
}

// CompareJA4 returns detailed comparison of two JA4 fingerprints.
// JA4 Part A format: {protocol}{version}{sni}{cipher_count}{ext_count}{alpn}
// Example: t13d1516h2 = TCP, TLS1.3, domain SNI, 15 ciphers, 16 extensions, h2 ALPN
func CompareJA4(a, b string) *JA4Comparison {
	comp := &JA4Comparison{}

	if a == b {
		comp.Match = true
		comp.VersionMatch = true
		comp.SNIMatch = true
		comp.CipherCountMatch = true
		comp.ExtCountMatch = true
		comp.ALPNMatch = true
		comp.CipherHashMatch = true
		comp.ExtHashMatch = true
		// Parse counts even for exact match for debugging info
		parseJA4PartA(a, &comp.AVersion, &comp.ACipherCount, &comp.AExtCount)
		comp.BVersion = comp.AVersion
		comp.BCipherCount = comp.ACipherCount
		comp.BExtCount = comp.AExtCount
		return comp
	}

	aParts := strings.Split(a, "_")
	bParts := strings.Split(b, "_")

	if len(aParts) != 3 || len(bParts) != 3 {
		comp.Diff = "invalid JA4 format"
		return comp
	}

	// Parse part A components
	// Format: {protocol:1}{version:2}{sni:1}{cipher_count:2}{ext_count:2}{alpn:2}
	// Minimum length: 10 chars (e.g., "t13d1516h2")
	parseJA4PartA(aParts[0], &comp.AVersion, &comp.ACipherCount, &comp.AExtCount)
	parseJA4PartA(bParts[0], &comp.BVersion, &comp.BCipherCount, &comp.BExtCount)

	// Compare version (positions 1-2)
	if len(aParts[0]) >= 3 && len(bParts[0]) >= 3 {
		comp.VersionMatch = comp.AVersion == comp.BVersion
	}

	// Compare SNI indicator (position 3)
	if len(aParts[0]) >= 4 && len(bParts[0]) >= 4 {
		comp.SNIMatch = aParts[0][3] == bParts[0][3]
	}

	// Compare cipher counts (positions 4-5)
	comp.CipherCountMatch = comp.ACipherCount == comp.BCipherCount

	// Compare extension counts (positions 6-7)
	comp.ExtCountMatch = comp.AExtCount == comp.BExtCount

	// Compare ALPN (positions 8-9)
	if len(aParts[0]) >= 10 && len(bParts[0]) >= 10 {
		comp.ALPNMatch = aParts[0][8:10] == bParts[0][8:10]
	} else if len(aParts[0]) >= 10 || len(bParts[0]) >= 10 {
		comp.ALPNMatch = false // One has ALPN, other doesn't
	} else {
		comp.ALPNMatch = true // Neither has ALPN field
	}

	// Compare cipher hash (part B)
	comp.CipherHashMatch = aParts[1] == bParts[1]

	// Compare extension hash (part C)
	comp.ExtHashMatch = aParts[2] == bParts[2]

	// Build diff string
	var diffs []string
	if !comp.VersionMatch {
		diffs = append(diffs, fmt.Sprintf("version: %s vs %s", comp.AVersion, comp.BVersion))
	}
	if !comp.SNIMatch && len(aParts[0]) >= 4 && len(bParts[0]) >= 4 {
		diffs = append(diffs, fmt.Sprintf("SNI: %c vs %c", aParts[0][3], bParts[0][3]))
	}
	if !comp.CipherCountMatch {
		diffs = append(diffs, fmt.Sprintf("cipher_count: %d vs %d", comp.ACipherCount, comp.BCipherCount))
	}
	if !comp.ExtCountMatch {
		diffs = append(diffs, fmt.Sprintf("ext_count: %d vs %d", comp.AExtCount, comp.BExtCount))
	}
	if !comp.ALPNMatch && len(aParts[0]) >= 10 && len(bParts[0]) >= 10 {
		diffs = append(diffs, fmt.Sprintf("ALPN: %s vs %s", aParts[0][8:10], bParts[0][8:10]))
	}
	if !comp.CipherHashMatch {
		diffs = append(diffs, fmt.Sprintf("ciphers: %s vs %s", aParts[1], bParts[1]))
	}
	if !comp.ExtHashMatch {
		diffs = append(diffs, fmt.Sprintf("extensions: %s vs %s", aParts[2], bParts[2]))
	}
	comp.Diff = strings.Join(diffs, "; ")

	return comp
}

// parseJA4PartA extracts version and counts from JA4 part A.
func parseJA4PartA(partA string, version *string, cipherCount, extCount *int) {
	if len(partA) >= 3 {
		*version = partA[1:3]
	}
	if len(partA) >= 6 {
		// Parse cipher count from positions 4-5 (0-indexed)
		if count, err := parseDigits(partA[4:6]); err == nil {
			*cipherCount = count
		}
	}
	if len(partA) >= 8 {
		// Parse extension count from positions 6-7 (0-indexed)
		if count, err := parseDigits(partA[6:8]); err == nil {
			*extCount = count
		}
	}
}

// parseDigits parses a 2-digit string into an integer.
func parseDigits(s string) (int, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("invalid length: %d", len(s))
	}
	d1 := int(s[0] - '0')
	d2 := int(s[1] - '0')
	if d1 < 0 || d1 > 9 || d2 < 0 || d2 > 9 {
		return 0, fmt.Errorf("invalid digits: %s", s)
	}
	return d1*10 + d2, nil
}

// ValidateJA4Match checks if two JA4 fingerprints match.
func ValidateJA4Match(actual, expected string) bool {
	return actual == expected
}

// JA3Comparison shows which parts of JA3 match/differ.
type JA3Comparison struct {
	Match           bool
	VersionMatch    bool
	CiphersMatch    bool
	ExtensionsMatch bool
	CurvesMatch     bool
	PointsMatch     bool
	Diff            string
}

// CompareJA3 returns detailed comparison of two JA3 fingerprints.
func CompareJA3(a, b string) *JA3Comparison {
	comp := &JA3Comparison{}

	if a == b {
		comp.Match = true
		comp.VersionMatch = true
		comp.CiphersMatch = true
		comp.ExtensionsMatch = true
		comp.CurvesMatch = true
		comp.PointsMatch = true
		return comp
	}

	// JA3 format: version,ciphers,extensions,curves,points
	aParts := strings.Split(a, ",")
	bParts := strings.Split(b, ",")

	if len(aParts) != 5 || len(bParts) != 5 {
		comp.Diff = "invalid JA3 format"
		return comp
	}

	comp.VersionMatch = aParts[0] == bParts[0]
	comp.CiphersMatch = aParts[1] == bParts[1]
	comp.ExtensionsMatch = aParts[2] == bParts[2]
	comp.CurvesMatch = aParts[3] == bParts[3]
	comp.PointsMatch = aParts[4] == bParts[4]

	var diffs []string
	if !comp.VersionMatch {
		diffs = append(diffs, fmt.Sprintf("version: %s vs %s", aParts[0], bParts[0]))
	}
	if !comp.CiphersMatch {
		diffs = append(diffs, "ciphers differ")
	}
	if !comp.ExtensionsMatch {
		diffs = append(diffs, "extensions differ")
	}
	if !comp.CurvesMatch {
		diffs = append(diffs, "curves differ")
	}
	if !comp.PointsMatch {
		diffs = append(diffs, "points differ")
	}
	comp.Diff = strings.Join(diffs, "; ")

	return comp
}
