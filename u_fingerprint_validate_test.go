// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/x509"
	"testing"
	"time"
)

// =============================================================================
// NewValidator Tests
// =============================================================================

// TestNewValidator_NilProfile verifies NewValidator handles nil profile gracefully.
func TestNewValidator_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	if v == nil {
		t.Fatal("NewValidator(nil) returned nil")
	}
	if v.profile != nil {
		t.Error("Validator with nil profile should have nil profile field")
	}
	if v.strictMode {
		t.Error("NewValidator should not enable strict mode")
	}
}

// TestNewValidator_WithValidProfile verifies NewValidator initializes correctly.
func TestNewValidator_WithValidProfile(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		Version: 133,
		Expected: ExpectedFingerprints{
			JA3: "abc123",
			JA4: "t13d1516h2_aabbccddee11_112233445566",
		},
	}

	v := NewValidator(profile)
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if v.profile == nil {
		t.Error("Validator profile is nil")
	}
	if v.profile.ID != "test_profile" {
		t.Errorf("Validator profile ID = %q, want %q", v.profile.ID, "test_profile")
	}
}

// TestNewStrictValidator_EnablesStrictMode verifies strict mode is enabled.
func TestNewStrictValidator_EnablesStrictMode(t *testing.T) {
	profile := &FingerprintProfile{ID: "test"}
	v := NewStrictValidator(profile)
	if v == nil {
		t.Fatal("NewStrictValidator returned nil")
	}
	if !v.strictMode {
		t.Error("NewStrictValidator should enable strict mode")
	}
}

// TestNewSessionValidator_WithSessionState verifies session state initialization.
func TestNewSessionValidator_WithSessionState(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
	}
	state := NewSessionFingerprintState(profile, "example.com:443")

	v := NewSessionValidator(state)
	if v == nil {
		t.Fatal("NewSessionValidator returned nil")
	}
	if v.sessionState == nil {
		t.Error("Validator sessionState is nil")
	}
	if v.sessionState != state {
		t.Error("Validator sessionState doesn't match input")
	}
}

// =============================================================================
// ValidateJA4 Tests
// =============================================================================

// TestValidateJA4_NilProfile verifies error handling with nil profile.
func TestValidateJA4_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	result := v.ValidateJA4("t13d1516h2_aabbccddee11_112233445566")

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
	if result.Score != 0.0 {
		t.Errorf("Score = %f, want 0.0", result.Score)
	}
	if len(result.Mismatches) == 0 {
		t.Error("Expected mismatch for nil profile")
	}

	// Check mismatch severity
	found := false
	for _, m := range result.Mismatches {
		if m.Field == "profile" && m.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected critical mismatch for nil profile")
	}
}

// TestValidateJA4_EmptyExpected verifies warning for empty expected JA4.
func TestValidateJA4_EmptyExpected(t *testing.T) {
	profile := &FingerprintProfile{
		ID:       "test",
		Expected: ExpectedFingerprints{JA4: ""},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4("t13d1516h2_aabbccddee11_112233445566")

	if !result.Valid {
		t.Error("Expected Valid=true when no expected JA4 defined")
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected warning for empty expected JA4")
	}

	found := false
	for _, w := range result.Warnings {
		if w.Field == "JA4" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected warning with Field='JA4'")
	}
}

// TestValidateJA4_ExactMatch verifies Valid=true for exact match.
func TestValidateJA4_ExactMatch(t *testing.T) {
	expected := "t13d1516h2_aabbccddee11_112233445566"
	profile := &FingerprintProfile{
		ID:       "test",
		Expected: ExpectedFingerprints{JA4: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4(expected)

	if !result.Valid {
		t.Error("Expected Valid=true for exact match")
	}
	if result.Score != 1.0 {
		t.Errorf("Score = %f, want 1.0", result.Score)
	}
	if len(result.Mismatches) > 0 {
		t.Error("Expected no mismatches for exact match")
	}
}

// TestValidateJA4_Mismatch verifies detection of mismatched JA4.
func TestValidateJA4_Mismatch(t *testing.T) {
	expected := "t13d1516h2_aabbccddee11_112233445566"
	actual := "t12d1012h1_ffeeddccbb22_665544332211"
	profile := &FingerprintProfile{
		ID:       "test",
		Expected: ExpectedFingerprints{JA4: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4(actual)

	if result.Valid {
		t.Error("Expected Valid=false for mismatch")
	}
	if len(result.Mismatches) == 0 {
		t.Error("Expected mismatches to be recorded")
	}

	// Verify mismatch details
	found := false
	for _, m := range result.Mismatches {
		if m.Field == "JA4" {
			found = true
			if m.Expected != expected {
				t.Errorf("Mismatch.Expected = %v, want %v", m.Expected, expected)
			}
			if m.Actual != actual {
				t.Errorf("Mismatch.Actual = %v, want %v", m.Actual, actual)
			}
			if m.Severity != SeverityCritical {
				t.Errorf("Mismatch.Severity = %v, want Critical", m.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("Expected JA4 mismatch to be recorded")
	}
}

// TestValidateJA4_PartialMatch_CiphersMatch verifies partial score calculation.
func TestValidateJA4_PartialMatch_CiphersMatch(t *testing.T) {
	// Same cipher hash (JA4_b), different extensions hash (JA4_c)
	expected := "t13d1516h2_aabbccddee11_112233445566"
	actual := "t13d1516h2_aabbccddee11_665544332211"
	profile := &FingerprintProfile{
		ID:       "test",
		Expected: ExpectedFingerprints{JA4: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4(actual)

	if result.Valid {
		t.Error("Expected Valid=false for partial mismatch")
	}
	// Score should be > 0 but < 1 (partial match: JA4_a and JA4_b match)
	if result.Score <= 0 || result.Score >= 1.0 {
		t.Errorf("Score = %f, expected partial score (0, 1)", result.Score)
	}
}

// =============================================================================
// ValidateJA3 Tests
// =============================================================================

// TestValidateJA3_NilProfile verifies error handling with nil profile.
func TestValidateJA3_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	result := v.ValidateJA3("abc123def456")

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
	if result.Score != 0.0 {
		t.Errorf("Score = %f, want 0.0", result.Score)
	}
}

// TestValidateJA3_ExactMatch verifies Valid=true for exact match.
func TestValidateJA3_ExactMatch(t *testing.T) {
	expected := "cd08e31494f9531f560d64c695473da9"
	profile := &FingerprintProfile{
		ID:       "test",
		Expected: ExpectedFingerprints{JA3: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateJA3(expected)

	if !result.Valid {
		t.Error("Expected Valid=true for exact match")
	}
	if result.Score != 1.0 {
		t.Errorf("Score = %f, want 1.0", result.Score)
	}
}

// TestValidateJA3_Mismatch verifies detection of mismatched JA3.
func TestValidateJA3_Mismatch(t *testing.T) {
	expected := "cd08e31494f9531f560d64c695473da9"
	actual := "ffffffffffffffffffffffffffffffff"
	profile := &FingerprintProfile{
		ID:       "test",
		Expected: ExpectedFingerprints{JA3: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateJA3(actual)

	if result.Valid {
		t.Error("Expected Valid=false for mismatch")
	}
	if result.Score != 0.0 {
		t.Errorf("Score = %f, want 0.0", result.Score)
	}
}

// =============================================================================
// ValidateJA4S Tests
// =============================================================================

// TestValidateJA4S_NilProfile verifies error handling with nil profile.
func TestValidateJA4S_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	result := v.ValidateJA4S("t1302h2_1301_a56c5b993250")

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
}

// TestValidateJA4S_NoAcceptablePatterns verifies warning for empty patterns.
func TestValidateJA4S_NoAcceptablePatterns(t *testing.T) {
	profile := &FingerprintProfile{
		ID:                 "test",
		ServerExpectations: ServerExpectations{AcceptableJA4S: nil},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4S("t1302h2_1301_a56c5b993250")

	if !result.Valid {
		t.Error("Expected Valid=true when no acceptable patterns defined")
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected warning for empty acceptable patterns")
	}
}

// TestValidateJA4S_ExactMatch verifies matching against acceptable patterns.
func TestValidateJA4S_ExactMatch(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ServerExpectations: ServerExpectations{
			AcceptableJA4S: []string{
				"t1302h2_1301_a56c5b993250",
				"t1302h2_1302_b67d6c094361",
			},
		},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4S("t1302h2_1301_a56c5b993250")

	if !result.Valid {
		t.Error("Expected Valid=true for exact match in acceptable list")
	}
}

// TestValidateJA4S_RegexMatch verifies regex pattern matching.
func TestValidateJA4S_RegexMatch(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ServerExpectations: ServerExpectations{
			AcceptableJA4S: []string{
				"t13.*_1301_.*",
			},
		},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4S("t1302h2_1301_a56c5b993250")

	if !result.Valid {
		t.Error("Expected Valid=true for regex match")
	}
}

// TestValidateJA4S_NoMatch verifies detection when no pattern matches.
func TestValidateJA4S_NoMatch(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ServerExpectations: ServerExpectations{
			AcceptableJA4S: []string{
				"t1302h2_1302_b67d6c094361",
				"t1202h1_1301_aaaaaabbbbbb",
			},
		},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4S("t1302h2_1301_xxxxxxyyyyyy")

	if result.Valid {
		t.Error("Expected Valid=false when no pattern matches")
	}
	if len(result.Mismatches) == 0 {
		t.Error("Expected mismatch to be recorded")
	}
}

// =============================================================================
// ValidateJA4X Tests
// =============================================================================

// TestValidateJA4X_NilProfile verifies error handling with nil profile.
func TestValidateJA4X_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	result := v.ValidateJA4X("2bab15409345_af684594efb4_3c12b456e789")

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
}

// TestValidateJA4X_ExactMatch verifies matching against acceptable patterns.
func TestValidateJA4X_ExactMatch(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ServerExpectations: ServerExpectations{
			Certificate: CertificateExpectations{
				AcceptableJA4X: []string{
					"2bab15409345_af684594efb4_3c12b456e789",
				},
			},
		},
	}
	v := NewValidator(profile)

	result := v.ValidateJA4X("2bab15409345_af684594efb4_3c12b456e789")

	if !result.Valid {
		t.Error("Expected Valid=true for exact match")
	}
}

// =============================================================================
// ValidateCertificate Tests
// =============================================================================

// TestValidateCertificate_NilCertificate verifies nil certificate handling.
func TestValidateCertificate_NilCertificate(t *testing.T) {
	profile := &FingerprintProfile{ID: "test"}
	v := NewValidator(profile)

	result := v.ValidateCertificate(nil)

	if result.Valid {
		t.Error("Expected Valid=false for nil certificate")
	}
	if len(result.Mismatches) == 0 {
		t.Error("Expected mismatch for nil certificate")
	}

	found := false
	for _, m := range result.Mismatches {
		if m.Field == "certificate" && m.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected critical mismatch for nil certificate")
	}
}

// =============================================================================
// ValidateCertificateChain Tests
// =============================================================================

// TestValidateCertificateChain_NilProfile verifies nil profile handling.
func TestValidateCertificateChain_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	certs := []*x509.Certificate{{}}

	result := v.ValidateCertificateChain(certs)

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
}

// TestValidateCertificateChain_EmptyChain verifies empty chain handling.
func TestValidateCertificateChain_EmptyChain(t *testing.T) {
	profile := &FingerprintProfile{ID: "test"}
	v := NewValidator(profile)

	result := v.ValidateCertificateChain([]*x509.Certificate{})

	if result.Valid {
		t.Error("Expected Valid=false for empty chain")
	}
	if len(result.Mismatches) == 0 {
		t.Error("Expected mismatch for empty chain")
	}
}

// =============================================================================
// ValidateCipherSuites Tests
// =============================================================================

// TestValidateCipherSuites_NilProfile verifies nil profile handling.
func TestValidateCipherSuites_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	ciphers := []uint16{TLS_AES_128_GCM_SHA256}

	result := v.ValidateCipherSuites(ciphers)

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
}

// TestValidateCipherSuites_NoExpected verifies warning for empty expected.
func TestValidateCipherSuites_NoExpected(t *testing.T) {
	profile := &FingerprintProfile{
		ID:          "test",
		ClientHello: ClientHelloConfig{CipherSuites: nil},
	}
	v := NewValidator(profile)

	result := v.ValidateCipherSuites([]uint16{TLS_AES_128_GCM_SHA256})

	if !result.Valid {
		t.Error("Expected Valid=true when no expected ciphers")
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected warning for empty expected")
	}
}

// TestValidateCipherSuites_ExactMatch verifies exact match validation.
func TestValidateCipherSuites_ExactMatch(t *testing.T) {
	expected := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}
	profile := &FingerprintProfile{
		ID:          "test",
		ClientHello: ClientHelloConfig{CipherSuites: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateCipherSuites(expected)

	if !result.Valid {
		t.Error("Expected Valid=true for exact match")
	}
	if result.Score != 1.0 {
		t.Errorf("Score = %f, want 1.0", result.Score)
	}
}

// TestValidateCipherSuites_CountMismatch detects cipher count mismatch.
func TestValidateCipherSuites_CountMismatch(t *testing.T) {
	expected := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}
	actual := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}
	profile := &FingerprintProfile{
		ID:          "test",
		ClientHello: ClientHelloConfig{CipherSuites: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateCipherSuites(actual)

	if result.Valid {
		t.Error("Expected Valid=false for count mismatch")
	}

	found := false
	for _, m := range result.Mismatches {
		if m.Field == "cipher_count" {
			found = true
			if m.Expected != len(expected) {
				t.Errorf("Expected count %v, got %v", len(expected), m.Expected)
			}
			if m.Actual != len(actual) {
				t.Errorf("Actual count %v, got %v", len(actual), m.Actual)
			}
			break
		}
	}
	if !found {
		t.Error("Expected cipher_count mismatch")
	}
}

// TestValidateCipherSuites_OrderMismatch detects cipher order mismatch.
func TestValidateCipherSuites_OrderMismatch(t *testing.T) {
	expected := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}
	actual := []uint16{
		TLS_AES_256_GCM_SHA384, // Swapped
		TLS_AES_128_GCM_SHA256, // Swapped
		TLS_CHACHA20_POLY1305_SHA256,
	}
	profile := &FingerprintProfile{
		ID:          "test",
		ClientHello: ClientHelloConfig{CipherSuites: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateCipherSuites(actual)

	if result.Valid {
		t.Error("Expected Valid=false for order mismatch")
	}

	found := false
	for _, m := range result.Mismatches {
		if m.Field == "cipher_order" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected cipher_order mismatch")
	}
}

// TestValidateCipherSuites_GREASEIgnored verifies GREASE values are ignored in comparison.
func TestValidateCipherSuites_GREASEIgnored(t *testing.T) {
	// Expected has GREASE placeholder
	expected := []uint16{
		0x0a0a, // GREASE
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}
	// Actual has different GREASE value but same ciphers
	actual := []uint16{
		0x1a1a, // Different GREASE
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}
	profile := &FingerprintProfile{
		ID:          "test",
		ClientHello: ClientHelloConfig{CipherSuites: expected},
	}
	v := NewValidator(profile)

	result := v.ValidateCipherSuites(actual)

	if !result.Valid {
		t.Error("Expected Valid=true when only GREASE differs")
	}
}

// =============================================================================
// ValidateExtensions Tests
// =============================================================================

// TestValidateExtensions_NilProfile verifies nil profile handling.
func TestValidateExtensions_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	extensions := []uint16{0, 10, 11, 13, 43}

	result := v.ValidateExtensions(extensions)

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
}

// TestValidateExtensions_OrderedValidation verifies ordered extension validation.
func TestValidateExtensions_OrderedValidation(t *testing.T) {
	expected := []ExtensionEntry{
		{Type: 0},  // SNI
		{Type: 10}, // supported_groups
		{Type: 11}, // ec_point_formats
		{Type: 13}, // signature_algorithms
		{Type: 43}, // supported_versions
	}
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			Extensions:        expected,
			ShuffleExtensions: false,
		},
	}
	v := NewValidator(profile)

	// Same order
	actual := []uint16{0, 10, 11, 13, 43}
	result := v.ValidateExtensions(actual)

	if !result.Valid {
		t.Error("Expected Valid=true for matching order")
	}

	// Different order
	actualWrong := []uint16{0, 11, 10, 13, 43}
	result = v.ValidateExtensions(actualWrong)

	if result.Valid {
		t.Error("Expected Valid=false for different order (non-shuffling profile)")
	}
}

// TestValidateExtensions_UnorderedValidation verifies unordered validation (Chrome-like).
func TestValidateExtensions_UnorderedValidation(t *testing.T) {
	expected := []ExtensionEntry{
		{Type: 0},
		{Type: 10},
		{Type: 11},
		{Type: 13},
		{Type: 43},
	}
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			Extensions:        expected,
			ShuffleExtensions: true, // Chrome shuffles
		},
	}
	v := NewValidator(profile)

	// Different order but same extensions
	actual := []uint16{43, 13, 0, 11, 10}
	result := v.ValidateExtensions(actual)

	if !result.Valid {
		t.Error("Expected Valid=true for shuffled extensions (same set)")
	}
}

// TestValidateExtensions_MissingExtension verifies missing extension detection.
func TestValidateExtensions_MissingExtension(t *testing.T) {
	expected := []ExtensionEntry{
		{Type: 0},
		{Type: 10},
		{Type: 11},
		{Type: 13},
		{Type: 43},
	}
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			Extensions:        expected,
			ShuffleExtensions: true,
		},
	}
	v := NewValidator(profile)

	// Missing extension 13
	actual := []uint16{0, 10, 11, 43}
	result := v.ValidateExtensions(actual)

	if result.Valid {
		t.Error("Expected Valid=false for missing extension")
	}

	found := false
	for _, m := range result.Mismatches {
		if m.Field == "missing_extensions" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected missing_extensions mismatch")
	}
}

// TestValidateExtensions_ExtraExtension verifies extra extension detection.
func TestValidateExtensions_ExtraExtension(t *testing.T) {
	expected := []ExtensionEntry{
		{Type: 0},
		{Type: 10},
		{Type: 11},
	}
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			Extensions:        expected,
			ShuffleExtensions: true,
		},
	}
	v := NewValidator(profile)

	// Extra extensions 13 and 43
	actual := []uint16{0, 10, 11, 13, 43}
	result := v.ValidateExtensions(actual)

	if result.Valid {
		t.Error("Expected Valid=false for extra extensions")
	}

	found := false
	for _, m := range result.Mismatches {
		if m.Field == "extra_extensions" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected extra_extensions mismatch")
	}
}

// TestValidateExtensions_GREASEFiltered verifies GREASE is filtered in validation.
func TestValidateExtensions_GREASEFiltered(t *testing.T) {
	expected := []ExtensionEntry{
		{Type: 0x0a0a}, // GREASE
		{Type: 0},
		{Type: 10},
	}
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			Extensions:        expected,
			ShuffleExtensions: false,
		},
	}
	v := NewValidator(profile)

	// Different GREASE but same actual extensions
	actual := []uint16{0x1a1a, 0, 10}
	result := v.ValidateExtensions(actual)

	if !result.Valid {
		t.Error("Expected Valid=true when only GREASE differs")
	}
}

// =============================================================================
// ValidateGREASE Tests
// =============================================================================

// TestValidateGREASE_NilProfile verifies nil profile handling.
func TestValidateGREASE_NilProfile(t *testing.T) {
	v := NewValidator(nil)
	result := v.ValidateGREASE([]uint16{0x0a0a}, []uint16{0x0a0a})

	if result.Valid {
		t.Error("Expected Valid=false with nil profile")
	}
}

// TestValidateGREASE_EnabledButMissing verifies detection of missing GREASE.
func TestValidateGREASE_EnabledButMissing(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}
	v := NewValidator(profile)

	// No GREASE values
	ciphers := []uint16{TLS_AES_128_GCM_SHA256}
	extensions := []uint16{0, 10, 11}

	result := v.ValidateGREASE(ciphers, extensions)

	if result.Valid {
		t.Error("Expected Valid=false when GREASE enabled but missing")
	}
}

// TestValidateGREASE_DisabledButPresent verifies detection of unexpected GREASE.
func TestValidateGREASE_DisabledButPresent(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: false},
		},
	}
	v := NewValidator(profile)

	// GREASE present
	ciphers := []uint16{0x0a0a, TLS_AES_128_GCM_SHA256}
	extensions := []uint16{0, 10, 11}

	result := v.ValidateGREASE(ciphers, extensions)

	if result.Valid {
		t.Error("Expected Valid=false when GREASE disabled but present")
	}
}

// TestValidateGREASE_EnabledAndPresent verifies valid GREASE usage.
func TestValidateGREASE_EnabledAndPresent(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}
	v := NewValidator(profile)

	// GREASE present in ciphers
	ciphers := []uint16{0x0a0a, TLS_AES_128_GCM_SHA256}
	extensions := []uint16{0, 10, 11}

	result := v.ValidateGREASE(ciphers, extensions)

	if !result.Valid {
		t.Error("Expected Valid=true when GREASE enabled and present")
	}
}

// TestValidateGREASE_InExtensions verifies GREASE detection in extensions.
func TestValidateGREASE_InExtensions(t *testing.T) {
	profile := &FingerprintProfile{
		ID: "test",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}
	v := NewValidator(profile)

	// GREASE only in extensions
	ciphers := []uint16{TLS_AES_128_GCM_SHA256}
	extensions := []uint16{0x2a2a, 0, 10, 11}

	result := v.ValidateGREASE(ciphers, extensions)

	if !result.Valid {
		t.Error("Expected Valid=true when GREASE present in extensions")
	}
}

// =============================================================================
// ValidateSessionConsistency Tests
// =============================================================================

// TestValidateSessionConsistency_NoSessionState verifies warning for no state.
func TestValidateSessionConsistency_NoSessionState(t *testing.T) {
	profile := &FingerprintProfile{ID: "test"}
	v := NewValidator(profile) // No session state

	result := v.ValidateSessionConsistency([]uint16{}, []uint16{})

	if !result.Valid {
		t.Error("Expected Valid=true with no session state")
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected warning for missing session state")
	}
}

// TestValidateSessionConsistency_GREASEConsistent verifies GREASE consistency check.
func TestValidateSessionConsistency_GREASEConsistent(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
	}
	state := NewSessionFingerprintState(profile, "example.com:443")
	state.FrozenGREASE.CipherSuite = 0x0a0a
	state.FrozenGREASE.Extension1 = 0x1a1a

	v := NewSessionValidator(state)

	// Consistent GREASE
	ciphers := []uint16{0x0a0a, TLS_AES_128_GCM_SHA256}
	extensions := []uint16{0x1a1a, 0, 10}

	result := v.ValidateSessionConsistency(ciphers, extensions)

	if !result.Valid {
		t.Error("Expected Valid=true for consistent GREASE")
	}
}

// TestValidateSessionConsistency_GREASEInconsistent verifies GREASE inconsistency detection.
func TestValidateSessionConsistency_GREASEInconsistent(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
	}
	state := NewSessionFingerprintState(profile, "example.com:443")
	state.FrozenGREASE.CipherSuite = 0x0a0a

	v := NewSessionValidator(state)

	// Inconsistent GREASE in ciphers
	ciphers := []uint16{0x1a1a, TLS_AES_128_GCM_SHA256} // Different GREASE
	extensions := []uint16{0, 10}

	result := v.ValidateSessionConsistency(ciphers, extensions)

	if result.Valid {
		t.Error("Expected Valid=false for inconsistent GREASE")
	}

	found := false
	for _, m := range result.Mismatches {
		if m.Field == "grease_cipher" && m.Severity == SeverityCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected critical mismatch for GREASE cipher inconsistency")
	}
}

// TestValidateSessionConsistency_ExtensionOrder verifies extension order consistency.
func TestValidateSessionConsistency_ExtensionOrder(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
	}
	state := NewSessionFingerprintState(profile, "example.com:443")
	state.FrozenExtensionOrder = []uint16{0, 10, 11, 13, 43}

	v := NewSessionValidator(state)

	// Consistent order
	result := v.ValidateSessionConsistency(
		[]uint16{TLS_AES_128_GCM_SHA256},
		[]uint16{0, 10, 11, 13, 43},
	)
	if !result.Valid {
		t.Error("Expected Valid=true for consistent extension order")
	}

	// Inconsistent order
	result = v.ValidateSessionConsistency(
		[]uint16{TLS_AES_128_GCM_SHA256},
		[]uint16{0, 11, 10, 13, 43}, // Order changed
	)
	if result.Valid {
		t.Error("Expected Valid=false for inconsistent extension order")
	}
}

// =============================================================================
// CompareJA4 Tests
// =============================================================================

// TestCompareJA4_ExactMatch verifies exact match comparison.
func TestCompareJA4_ExactMatch(t *testing.T) {
	ja4 := "t13d1516h2_aabbccddee11_112233445566"
	comp := CompareJA4(ja4, ja4)

	if !comp.Match {
		t.Error("Expected Match=true for identical JA4")
	}
	if !comp.VersionMatch {
		t.Error("Expected VersionMatch=true")
	}
	if !comp.SNIMatch {
		t.Error("Expected SNIMatch=true")
	}
	if !comp.CipherCountMatch {
		t.Error("Expected CipherCountMatch=true")
	}
	if !comp.ExtCountMatch {
		t.Error("Expected ExtCountMatch=true")
	}
	if !comp.ALPNMatch {
		t.Error("Expected ALPNMatch=true")
	}
	if !comp.CipherHashMatch {
		t.Error("Expected CipherHashMatch=true")
	}
	if !comp.ExtHashMatch {
		t.Error("Expected ExtHashMatch=true")
	}
	if comp.Diff != "" {
		t.Errorf("Expected empty Diff, got %q", comp.Diff)
	}
}

// TestCompareJA4_AllComponentsDiffer verifies all differences are detected.
func TestCompareJA4_AllComponentsDiffer(t *testing.T) {
	a := "t13d1516h2_aabbccddee11_112233445566"
	b := "t12i2025h1_ffeeddccbb22_665544332211"
	// Different: version (13 vs 12), SNI (d vs i), cipher count (15 vs 20),
	// ext count (16 vs 25), ALPN (h2 vs h1), cipher hash, ext hash

	comp := CompareJA4(a, b)

	if comp.Match {
		t.Error("Expected Match=false for different JA4")
	}
	if comp.VersionMatch {
		t.Error("Expected VersionMatch=false")
	}
	if comp.SNIMatch {
		t.Error("Expected SNIMatch=false")
	}
	if comp.CipherCountMatch {
		t.Error("Expected CipherCountMatch=false")
	}
	if comp.ExtCountMatch {
		t.Error("Expected ExtCountMatch=false")
	}
	if comp.ALPNMatch {
		t.Error("Expected ALPNMatch=false")
	}
	if comp.CipherHashMatch {
		t.Error("Expected CipherHashMatch=false")
	}
	if comp.ExtHashMatch {
		t.Error("Expected ExtHashMatch=false")
	}
	if comp.Diff == "" {
		t.Error("Expected non-empty Diff")
	}
}

// TestCompareJA4_PartialMatch verifies partial match detection.
func TestCompareJA4_PartialMatch(t *testing.T) {
	a := "t13d1516h2_aabbccddee11_112233445566"
	b := "t13d1516h2_aabbccddee11_665544332211" // Only ext hash differs

	comp := CompareJA4(a, b)

	if comp.Match {
		t.Error("Expected Match=false")
	}
	if !comp.VersionMatch {
		t.Error("Expected VersionMatch=true")
	}
	if !comp.CipherHashMatch {
		t.Error("Expected CipherHashMatch=true")
	}
	if comp.ExtHashMatch {
		t.Error("Expected ExtHashMatch=false")
	}
}

// TestCompareJA4_InvalidFormat verifies invalid format handling.
func TestCompareJA4_InvalidFormat(t *testing.T) {
	testCases := []struct {
		name string
		a    string
		b    string
	}{
		{"missing_underscore_a", "t13d1516h2aabbccddee11_112233445566", "t13d1516h2_aa_bb"},
		{"missing_underscore_b", "t13d1516h2_aa_bb", "t13d1516h2aabbccddee11"},
		{"too_few_parts_a", "t13d1516h2_aabbccddee11", "t13d1516h2_aa_bb"},
		{"too_few_parts_b", "t13d1516h2_aa_bb", "t13d1516h2"},
		{"empty_a", "", "t13d1516h2_aa_bb"},
		{"empty_b", "t13d1516h2_aa_bb", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			comp := CompareJA4(tc.a, tc.b)
			if comp.Match {
				t.Error("Expected Match=false for invalid format")
			}
			if comp.Diff == "" {
				t.Error("Expected non-empty Diff for invalid format")
			}
		})
	}
}

// TestCompareJA4_PopulatesVersionAndCounts verifies version/count fields are populated.
func TestCompareJA4_PopulatesVersionAndCounts(t *testing.T) {
	a := "t13d1516h2_aabbccddee11_112233445566"
	b := "t12d2025h1_ffeeddccbb22_665544332211"

	comp := CompareJA4(a, b)

	if comp.AVersion != "13" {
		t.Errorf("AVersion = %q, want %q", comp.AVersion, "13")
	}
	if comp.BVersion != "12" {
		t.Errorf("BVersion = %q, want %q", comp.BVersion, "12")
	}
	if comp.ACipherCount != 15 {
		t.Errorf("ACipherCount = %d, want %d", comp.ACipherCount, 15)
	}
	if comp.BCipherCount != 20 {
		t.Errorf("BCipherCount = %d, want %d", comp.BCipherCount, 20)
	}
	if comp.AExtCount != 16 {
		t.Errorf("AExtCount = %d, want %d", comp.AExtCount, 16)
	}
	if comp.BExtCount != 25 {
		t.Errorf("BExtCount = %d, want %d", comp.BExtCount, 25)
	}
}

// =============================================================================
// CompareJA3 Tests
// =============================================================================

// TestCompareJA3_ExactMatch verifies exact match comparison.
func TestCompareJA3_ExactMatch(t *testing.T) {
	ja3 := "771,4866-4867-4865,0-10-11-13-43,29-23,0"
	comp := CompareJA3(ja3, ja3)

	if !comp.Match {
		t.Error("Expected Match=true for identical JA3")
	}
	if !comp.VersionMatch {
		t.Error("Expected VersionMatch=true")
	}
	if !comp.CiphersMatch {
		t.Error("Expected CiphersMatch=true")
	}
	if !comp.ExtensionsMatch {
		t.Error("Expected ExtensionsMatch=true")
	}
	if !comp.CurvesMatch {
		t.Error("Expected CurvesMatch=true")
	}
	if !comp.PointsMatch {
		t.Error("Expected PointsMatch=true")
	}
}

// TestCompareJA3_AllComponentsDiffer verifies all differences detected.
func TestCompareJA3_AllComponentsDiffer(t *testing.T) {
	a := "771,4866-4867,0-10-11,29-23,0"
	b := "769,1301-1302,13-43-51,25-24,1"

	comp := CompareJA3(a, b)

	if comp.Match {
		t.Error("Expected Match=false")
	}
	if comp.VersionMatch {
		t.Error("Expected VersionMatch=false")
	}
	if comp.CiphersMatch {
		t.Error("Expected CiphersMatch=false")
	}
	if comp.ExtensionsMatch {
		t.Error("Expected ExtensionsMatch=false")
	}
	if comp.CurvesMatch {
		t.Error("Expected CurvesMatch=false")
	}
	if comp.PointsMatch {
		t.Error("Expected PointsMatch=false")
	}
	if comp.Diff == "" {
		t.Error("Expected non-empty Diff")
	}
}

// TestCompareJA3_InvalidFormat verifies invalid format handling.
func TestCompareJA3_InvalidFormat(t *testing.T) {
	testCases := []struct {
		name string
		a    string
		b    string
	}{
		{"too_few_parts_a", "771,4866", "771,4866,0,29,0"},
		{"too_few_parts_b", "771,4866,0,29,0", "771,4866"},
		{"empty_a", "", "771,4866,0,29,0"},
		{"empty_b", "771,4866,0,29,0", ""},
		{"too_many_parts", "771,4866,0,29,0,extra", "771,4866,0,29,0"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			comp := CompareJA3(tc.a, tc.b)
			if comp.Match {
				t.Error("Expected Match=false for invalid format")
			}
			if comp.Diff == "" {
				t.Error("Expected non-empty Diff for invalid format")
			}
		})
	}
}

// TestCompareJA3_PartialMatch verifies partial match detection.
func TestCompareJA3_PartialMatch(t *testing.T) {
	a := "771,4866-4867,0-10-11,29-23,0"
	b := "771,4866-4867,0-10-11,29-23,1" // Only points differ

	comp := CompareJA3(a, b)

	if comp.Match {
		t.Error("Expected Match=false")
	}
	if !comp.VersionMatch {
		t.Error("Expected VersionMatch=true")
	}
	if !comp.CiphersMatch {
		t.Error("Expected CiphersMatch=true")
	}
	if !comp.ExtensionsMatch {
		t.Error("Expected ExtensionsMatch=true")
	}
	if !comp.CurvesMatch {
		t.Error("Expected CurvesMatch=true")
	}
	if comp.PointsMatch {
		t.Error("Expected PointsMatch=false")
	}
}

// =============================================================================
// filterGREASE Tests
// =============================================================================

// TestFilterGREASE_RemovesAllValidGREASE verifies all 16 GREASE values are removed.
func TestFilterGREASE_RemovesAllValidGREASE(t *testing.T) {
	// All 16 valid GREASE values
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	for _, grease := range greaseValues {
		input := []uint16{grease, 0x1301, 0x1302}
		result := filterGREASE(input)

		// Should not contain GREASE
		for _, v := range result {
			if v == grease {
				t.Errorf("filterGREASE failed to remove GREASE value 0x%04x", grease)
			}
		}

		// Should still contain non-GREASE values
		if len(result) != 2 {
			t.Errorf("Expected 2 values after filtering GREASE 0x%04x, got %d", grease, len(result))
		}
	}
}

// TestFilterGREASE_KeepsNonGREASE verifies non-GREASE values are kept.
func TestFilterGREASE_KeepsNonGREASE(t *testing.T) {
	input := []uint16{
		TLS_AES_128_GCM_SHA256,        // 0x1301
		TLS_AES_256_GCM_SHA384,        // 0x1302
		TLS_CHACHA20_POLY1305_SHA256,  // 0x1303
		0, 10, 11, 13, 43, 51,         // Common extensions
	}

	result := filterGREASE(input)

	if len(result) != len(input) {
		t.Errorf("Expected %d values, got %d", len(input), len(result))
	}

	for i, v := range input {
		if result[i] != v {
			t.Errorf("Value at index %d: got 0x%04x, want 0x%04x", i, result[i], v)
		}
	}
}

// TestFilterGREASE_AllGREASE_ReturnsEmpty verifies empty result for all-GREASE input.
func TestFilterGREASE_AllGREASE_ReturnsEmpty(t *testing.T) {
	input := []uint16{0x0a0a, 0x1a1a, 0x2a2a}
	result := filterGREASE(input)

	if len(result) != 0 {
		t.Errorf("Expected empty slice for all-GREASE input, got %d values", len(result))
	}
}

// TestFilterGREASE_EmptyInput_ReturnsEmpty verifies empty input handling.
func TestFilterGREASE_EmptyInput_ReturnsEmpty(t *testing.T) {
	result := filterGREASE([]uint16{})
	if result == nil {
		// nil is acceptable for empty result
		return
	}
	if len(result) != 0 {
		t.Errorf("Expected empty slice for empty input, got %d values", len(result))
	}
}

// TestFilterGREASE_NilInput_ReturnsEmpty verifies nil input handling.
func TestFilterGREASE_NilInput_ReturnsEmpty(t *testing.T) {
	result := filterGREASE(nil)
	if result != nil && len(result) != 0 {
		t.Errorf("Expected nil or empty slice for nil input, got %d values", len(result))
	}
}

// TestFilterGREASE_MixedInput verifies mixed input handling.
func TestFilterGREASE_MixedInput(t *testing.T) {
	input := []uint16{
		0x0a0a,                        // GREASE
		TLS_AES_128_GCM_SHA256,
		0x1a1a,                        // GREASE
		TLS_AES_256_GCM_SHA384,
		0x2a2a,                        // GREASE
		TLS_CHACHA20_POLY1305_SHA256,
	}

	result := filterGREASE(input)

	expected := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}

	if len(result) != len(expected) {
		t.Fatalf("Expected %d values, got %d", len(expected), len(result))
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("Value at index %d: got 0x%04x, want 0x%04x", i, result[i], v)
		}
	}
}

// =============================================================================
// matchesPattern Tests
// =============================================================================

// TestMatchesPattern_ExactMatch verifies exact string match.
func TestMatchesPattern_ExactMatch(t *testing.T) {
	if !matchesPattern("hello", "hello") {
		t.Error("Expected true for exact match")
	}
}

// TestMatchesPattern_RegexMatch verifies regex pattern match.
func TestMatchesPattern_RegexMatch(t *testing.T) {
	testCases := []struct {
		value   string
		pattern string
		want    bool
	}{
		{"hello123", "hello[0-9]+", true},
		{"hello", "hello[0-9]+", false},
		{"t13d1516h2_aabbcc_112233", "t13.*_aabbcc_.*", true},
		{"t12d1516h2_aabbcc_112233", "t13.*_aabbcc_.*", false},
		{"test", ".*", true},
		{"", ".*", true},
	}

	for _, tc := range testCases {
		t.Run(tc.pattern, func(t *testing.T) {
			got := matchesPattern(tc.value, tc.pattern)
			if got != tc.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v",
					tc.value, tc.pattern, got, tc.want)
			}
		})
	}
}

// TestMatchesPattern_InvalidRegex verifies invalid regex handling.
func TestMatchesPattern_InvalidRegex(t *testing.T) {
	// Invalid regex should return false, not panic
	if matchesPattern("hello", "[invalid") {
		t.Error("Expected false for invalid regex")
	}
}

// TestMatchesPattern_LongPatternRejected verifies ReDoS prevention.
func TestMatchesPattern_LongPatternRejected(t *testing.T) {
	longPattern := make([]byte, 600)
	for i := range longPattern {
		longPattern[i] = 'a'
	}

	if matchesPattern("test", string(longPattern)) {
		t.Error("Expected false for overly long pattern")
	}
}

// =============================================================================
// Severity Tests
// =============================================================================

// TestSeverity_String verifies severity string conversion.
func TestSeverity_String(t *testing.T) {
	testCases := []struct {
		severity Severity
		want     string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(100), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.severity.String(); got != tc.want {
				t.Errorf("Severity(%d).String() = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

// =============================================================================
// ValidationResult Tests
// =============================================================================

// TestValidationResult_Timestamp verifies timestamp is set.
func TestValidationResult_Timestamp(t *testing.T) {
	before := time.Now()
	v := NewValidator(nil)
	result := v.ValidateJA4("test")
	after := time.Now()

	if result.Timestamp.Before(before) || result.Timestamp.After(after) {
		t.Error("Timestamp not within expected range")
	}
}

// =============================================================================
// ValidateJA4Match Tests
// =============================================================================

// TestValidateJA4Match verifies simple match function.
func TestValidateJA4Match(t *testing.T) {
	if !ValidateJA4Match("abc", "abc") {
		t.Error("Expected true for matching JA4")
	}
	if ValidateJA4Match("abc", "def") {
		t.Error("Expected false for non-matching JA4")
	}
}

// =============================================================================
// calculateJA4MatchScore Tests
// =============================================================================

// TestCalculateJA4MatchScore_ExactMatch verifies score 1.0 for exact match.
func TestCalculateJA4MatchScore_ExactMatch(t *testing.T) {
	ja4 := "t13d1516h2_aabbccddee11_112233445566"
	score := calculateJA4MatchScore(ja4, ja4)
	if score != 1.0 {
		t.Errorf("Score = %f, want 1.0", score)
	}
}

// TestCalculateJA4MatchScore_InvalidFormat verifies score 0.0 for invalid format.
func TestCalculateJA4MatchScore_InvalidFormat(t *testing.T) {
	testCases := []struct {
		a string
		b string
	}{
		{"invalid", "t13d1516h2_aa_bb"},
		{"t13d1516h2_aa_bb", "invalid"},
		{"a_b", "t13d1516h2_aa_bb"},
		{"", "t13d1516h2_aa_bb"},
	}

	for _, tc := range testCases {
		score := calculateJA4MatchScore(tc.a, tc.b)
		if score != 0.0 {
			t.Errorf("calculateJA4MatchScore(%q, %q) = %f, want 0.0", tc.a, tc.b, score)
		}
	}
}

// TestCalculateJA4MatchScore_PartialMatch verifies partial score calculation.
func TestCalculateJA4MatchScore_PartialMatch(t *testing.T) {
	a := "t13d1516h2_aabbccddee11_112233445566"
	b := "t13d1516h2_aabbccddee11_665544332211" // Only JA4_c differs

	score := calculateJA4MatchScore(a, b)

	// JA4_a matches (0.5) + JA4_b matches (0.25) = 0.75
	if score != 0.75 {
		t.Errorf("Score = %f, want 0.75", score)
	}
}
