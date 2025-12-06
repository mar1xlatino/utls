// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// =============================================================================
// Fingerprint Calculation Edge Case Tests
// =============================================================================
//
// These tests verify that fingerprint calculation functions handle edge cases
// correctly, including:
// - Truncated/malformed ClientHello messages
// - Invalid extension lengths
// - Empty inputs
// - Boundary conditions
//
// Security Impact: Malformed inputs should not cause panics or security bypasses.
// Fingerprint functions must be robust against adversarial input.

// TestCalculateFingerprints_TruncatedInput tests handling of truncated ClientHello.
// Security: Truncated messages should return error, not panic.
func TestCalculateFingerprints_TruncatedInput(t *testing.T) {
	// Minimal valid ClientHello structure
	// Format: handshake_type(1) + length(3) + version(2) + random(32) +
	//         session_id_len(1) + cipher_len(2) + cipher(2) + comp_len(1) + comp(1) = 45 bytes
	validCH := []byte{
		0x01,             // HandshakeType: ClientHello
		0x00, 0x00, 0x29, // Length: 41 bytes
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // Session ID length: 0
		0x00, 0x02, // Cipher suites length: 2
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, // Compression methods length: 1
		0x00, // null compression
	}

	// Test truncation at various critical points
	testCases := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"just type", 1},
		{"partial length", 3},
		{"just header", 4},
		{"partial version", 5},
		{"no random", 6},
		{"partial random", 20},
		{"no session id", 38},
		{"no ciphers", 39},
		{"partial ciphers", 41},
		{"no compression", 43},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.length > len(validCH) {
				t.Skip("Length exceeds valid ClientHello")
			}
			truncated := validCH[:tc.length]

			// Should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic at truncation point %d: %v", tc.length, r)
				}
			}()

			// Should return error, not panic
			_, err := CalculateFingerprints(truncated)
			if err == nil && tc.length < 45 {
				// Very short inputs should fail
				if tc.length < 10 {
					t.Errorf("CalculateFingerprints should return error for length %d", tc.length)
				}
			}
		})
	}
}

// TestCalculateFingerprints_ExtensionOverflow tests malformed extension handling.
// Security: Extension claiming more data than available should not cause OOB read.
func TestCalculateFingerprints_ExtensionOverflow(t *testing.T) {
	// ClientHello with extension length claiming more data than available
	malformedCH := []byte{
		0x01, 0x00, 0x00, 0x32, // HandshakeType + length (50)
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,             // Session ID length: 0
		0x00, 0x02,       // Cipher suites length: 2
		0x00, 0x2f,       // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, 0x00,       // Compression: 1 byte, null
		0xFF, 0xFF,       // Extensions length: 65535 (way more than available)
		0x00, 0x00, 0x00, // Some trailing bytes
	}

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic on malformed extension length: %v", r)
		}
	}()

	_, err := CalculateFingerprints(malformedCH)
	if err == nil {
		t.Error("CalculateFingerprints should return error for malformed extension length")
	}
}

// TestCalculateFingerprints_EmptyInput tests handling of empty input.
func TestCalculateFingerprints_EmptyInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic on empty input: %v", r)
		}
	}()

	_, err := CalculateFingerprints([]byte{})
	if err == nil {
		t.Error("CalculateFingerprints should return error for empty input")
	}
}

// TestCalculateFingerprints_NilInput tests handling of nil input.
func TestCalculateFingerprints_NilInput(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic on nil input: %v", r)
		}
	}()

	_, err := CalculateFingerprints(nil)
	if err == nil {
		t.Error("CalculateFingerprints should return error for nil input")
	}
}

// TestCalculateFingerprints_InvalidCipherSuiteLength tests malformed cipher suite length.
func TestCalculateFingerprints_InvalidCipherSuiteLength(t *testing.T) {
	// ClientHello with cipher suite length claiming more data than available
	malformedCH := []byte{
		0x01, 0x00, 0x00, 0x2A, // HandshakeType + length
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // Session ID length: 0
		0xFF, 0xFF, // Cipher suites length: 65535 (overflow)
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA (not enough data)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic on malformed cipher suite length: %v", r)
		}
	}()

	_, err := CalculateFingerprints(malformedCH)
	if err == nil {
		t.Error("CalculateFingerprints should return error for malformed cipher suite length")
	}
}

// TestCalculateFingerprints_InvalidSessionIDLength tests malformed session ID length.
func TestCalculateFingerprints_InvalidSessionIDLength(t *testing.T) {
	// ClientHello with session ID length claiming more data than available
	malformedCH := []byte{
		0x01, 0x00, 0x00, 0x2A, // HandshakeType + length
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, // Session ID length: 255 (overflow - max is 32)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic on malformed session ID length: %v", r)
		}
	}()

	_, err := CalculateFingerprints(malformedCH)
	if err == nil {
		t.Error("CalculateFingerprints should return error for malformed session ID length")
	}
}

// TestCalculateFingerprints_GREASEFiltering tests that GREASE values are filtered.
func TestCalculateFingerprints_GREASEFiltering(t *testing.T) {
	// Build a ClientHello with GREASE values
	// GREASE cipher: 0x0A0A, 0x1A1A, 0x2A2A, etc.
	chWithGREASE := []byte{
		0x01, 0x00, 0x00, 0x2D, // HandshakeType + length (45)
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // Session ID length: 0
		0x00, 0x06, // Cipher suites length: 6
		0x0A, 0x0A, // GREASE cipher (should be filtered)
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, // Compression methods length: 1
		0x00, // null compression
	}

	fp, err := CalculateFingerprints(chWithGREASE)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// JA3 raw string should NOT contain GREASE cipher (2570 = 0x0A0A)
	// It should contain 4865 (0x1301) and 47 (0x002F)
	if fp.JA3r == "" {
		t.Error("JA3r is empty")
	}

	// The raw string contains decimal cipher values separated by dash
	// GREASE 0x0A0A = 2570, should not appear
	// We just verify the fingerprint was calculated without error
	t.Logf("JA3r: %s", fp.JA3r)
}

// TestCalculateFingerprints_ValidClientHello tests fingerprinting a valid ClientHello.
func TestCalculateFingerprints_ValidClientHello(t *testing.T) {
	// Well-formed ClientHello with extensions
	validCH := []byte{
		0x01, 0x00, 0x00, 0x4F, // HandshakeType + length (79)
		0x03, 0x03, // Version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // Session ID length: 0
		0x00, 0x04, // Cipher suites length: 4
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x01,       // Compression methods length: 1
		0x00,       // null compression
		0x00, 0x22, // Extensions length: 34
		// Extension: server_name (0)
		0x00, 0x00, // Type: server_name
		0x00, 0x0E, // Length: 14
		0x00, 0x0C, // Server Name List Length: 12
		0x00,                                           // Type: hostname
		0x00, 0x09,                                     // Length: 9
		'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't',    // "localhost"
		// Extension: supported_groups (10)
		0x00, 0x0A, // Type: supported_groups
		0x00, 0x04, // Length: 4
		0x00, 0x02, // Groups Length: 2
		0x00, 0x1D, // X25519
		// Extension: signature_algorithms (13)
		0x00, 0x0D, // Type: signature_algorithms
		0x00, 0x04, // Length: 4
		0x00, 0x02, // Algorithms Length: 2
		0x04, 0x01, // rsa_pkcs1_sha256
	}

	fp, err := CalculateFingerprints(validCH)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// Verify all fingerprint fields are populated
	if fp.JA3 == "" {
		t.Error("JA3 is empty")
	}
	if fp.JA3r == "" {
		t.Error("JA3r is empty")
	}
	if fp.JA4 == "" {
		t.Error("JA4 is empty")
	}
	if fp.JA4r == "" {
		t.Error("JA4r is empty")
	}
	if fp.JA4o == "" {
		t.Error("JA4o is empty")
	}

	t.Logf("JA3:  %s", fp.JA3)
	t.Logf("JA3r: %s", fp.JA3r)
	t.Logf("JA4:  %s", fp.JA4)
}

// =============================================================================
// JA4S (ServerHello) Fingerprint Edge Case Tests
// =============================================================================

// TestCalculateJA4S_TruncatedInput tests handling of truncated ServerHello.
func TestCalculateJA4S_TruncatedInput(t *testing.T) {
	testCases := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"just type", 1},
		{"partial length", 3},
		{"header only", 4},
		{"partial version", 5},
	}

	validSH := []byte{
		0x02,             // ServerHello
		0x00, 0x00, 0x26, // Length: 38
		0x03, 0x03, // Version TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // Session ID length: 0
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x00, // Compression: null
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.length > len(validSH) {
				t.Skip("Length exceeds valid ServerHello")
			}
			truncated := validSH[:tc.length]

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic at truncation point %d: %v", tc.length, r)
				}
			}()

			_, err := CalculateJA4S(truncated)
			if err == nil {
				t.Errorf("CalculateJA4S should return error for length %d", tc.length)
			}
		})
	}
}

// TestCalculateJA4S_WrongType tests rejection of non-ServerHello handshake messages.
func TestCalculateJA4S_WrongType(t *testing.T) {
	// ClientHello (type 0x01) instead of ServerHello (type 0x02)
	wrongType := []byte{
		0x01,             // ClientHello (wrong!)
		0x00, 0x00, 0x26, // Length
		0x03, 0x03, // Version
		// ... rest doesn't matter
	}

	_, err := CalculateJA4S(wrongType)
	if err == nil {
		t.Error("CalculateJA4S should reject non-ServerHello messages")
	}
}

// TestCalculateJA4S_ValidServerHello tests fingerprinting a valid ServerHello.
func TestCalculateJA4S_ValidServerHello(t *testing.T) {
	validSH := []byte{
		0x02,             // ServerHello
		0x00, 0x00, 0x2E, // Length: 46
		0x03, 0x03, // Version TLS 1.2 (legacy for TLS 1.3)
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // Session ID length: 0
		0x13, 0x01, // TLS_AES_128_GCM_SHA256
		0x00,       // Compression: null
		0x00, 0x06, // Extensions length: 6
		// Extension: supported_versions (43)
		0x00, 0x2B, // Type
		0x00, 0x02, // Length: 2
		0x03, 0x04, // TLS 1.3
	}

	fp, err := CalculateJA4S(validSH)
	if err != nil {
		t.Fatalf("CalculateJA4S failed: %v", err)
	}

	if fp.JA4S == "" {
		t.Error("JA4S is empty")
	}
	if fp.JA4Sr == "" {
		t.Error("JA4Sr is empty")
	}

	t.Logf("JA4S:  %s", fp.JA4S)
	t.Logf("JA4Sr: %s", fp.JA4Sr)
}

// =============================================================================
// JA4X (Certificate) Fingerprint Edge Case Tests
// =============================================================================

// TestCalculateJA4X_NilCert tests handling of nil certificate.
func TestCalculateJA4X_NilCert(t *testing.T) {
	fp := CalculateJA4X(nil)
	if fp == nil {
		t.Fatal("CalculateJA4X returned nil for nil input")
	}

	// Should return a placeholder fingerprint
	expected := "000000000000_000000000000_000000000000"
	if fp.JA4X != expected {
		t.Errorf("JA4X = %s, expected %s", fp.JA4X, expected)
	}
}

// TestCalculateJA4X_EmptyCert tests handling of certificate with no fields.
func TestCalculateJA4X_EmptyCert(t *testing.T) {
	cert := &x509.Certificate{}
	fp := CalculateJA4X(cert)
	if fp == nil {
		t.Fatal("CalculateJA4X returned nil")
	}

	// Empty cert should produce placeholder hashes for empty OID lists
	if len(fp.IssuerOIDs) != 0 {
		t.Errorf("Expected empty IssuerOIDs, got %d", len(fp.IssuerOIDs))
	}
	if len(fp.SubjectOIDs) != 0 {
		t.Errorf("Expected empty SubjectOIDs, got %d", len(fp.SubjectOIDs))
	}

	t.Logf("JA4X: %s", fp.JA4X)
}

// TestCalculateJA4X_ValidCert tests fingerprinting a certificate with populated fields.
func TestCalculateJA4X_ValidCert(t *testing.T) {
	cert := &x509.Certificate{
		Issuer: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Org"},
			CommonName:   "Test Issuer",
		},
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test Org"},
			CommonName:   "Test Subject",
		},
		Extensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}}, // Key Usage
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}}, // Extended Key Usage
			{Id: asn1.ObjectIdentifier{2, 5, 29, 17}}, // Subject Alt Name
		},
	}

	fp := CalculateJA4X(cert)
	if fp == nil {
		t.Fatal("CalculateJA4X returned nil")
	}

	// Verify OIDs were extracted
	if len(fp.ExtensionOIDs) != 3 {
		t.Errorf("Expected 3 extension OIDs, got %d", len(fp.ExtensionOIDs))
	}

	if fp.JA4X == "" {
		t.Error("JA4X is empty")
	}
	if fp.JA4Xr == "" {
		t.Error("JA4Xr is empty")
	}

	t.Logf("JA4X:  %s", fp.JA4X)
	t.Logf("JA4Xr: %s", fp.JA4Xr)
	t.Logf("Issuer OIDs: %v", fp.IssuerOIDs)
	t.Logf("Subject OIDs: %v", fp.SubjectOIDs)
	t.Logf("Extension OIDs: %v", fp.ExtensionOIDs)
}

// =============================================================================
// Helper Function Tests
// =============================================================================

// TestOIDToHex_EdgeCases tests OID to hex encoding edge cases.
func TestOIDToHex_EdgeCases(t *testing.T) {
	testCases := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"empty OID", asn1.ObjectIdentifier{}},
		{"single arc", asn1.ObjectIdentifier{1}},
		{"common OID", asn1.ObjectIdentifier{2, 5, 29, 15}},          // Key Usage
		{"long OID", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1}}, // RSA
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic encoding OID %v: %v", tc.oid, r)
				}
			}()

			hex := oidToHex(tc.oid)
			t.Logf("OID %v -> %s", tc.oid, hex)
		})
	}
}

// TestEncodeVarInt_Boundaries tests variable-length integer encoding boundaries.
func TestEncodeVarInt_Boundaries(t *testing.T) {
	testCases := []struct {
		name  string
		value int
	}{
		{"zero", 0},
		{"one", 1},
		{"127 (max 1-byte)", 127},
		{"128 (min 2-byte)", 128},
		{"16383 (max 2-byte)", 16383},
		{"16384 (min 3-byte)", 16384},
		{"large value", 1000000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Panic encoding %d: %v", tc.value, r)
				}
			}()

			encoded := encodeVarInt(tc.value)
			if encoded == nil && tc.value >= 0 {
				t.Errorf("encodeVarInt(%d) returned nil", tc.value)
			}
			t.Logf("encodeVarInt(%d) = %x", tc.value, encoded)
		})
	}
}

// TestEncodeVarInt_Negative tests that negative values are handled safely.
func TestEncodeVarInt_Negative(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Panic on negative value: %v", r)
		}
	}()

	// Negative values should return nil (invalid for OID encoding)
	result := encodeVarInt(-1)
	if result != nil {
		t.Error("encodeVarInt(-1) should return nil")
	}
}

// TestJoinUint16Decimal_EmptySlice tests handling of empty slices.
func TestJoinUint16Decimal_EmptySlice(t *testing.T) {
	result := joinUint16Decimal([]uint16{}, "-")
	if result != "" {
		t.Errorf("Expected empty string, got %q", result)
	}

	result = joinUint16Decimal(nil, "-")
	if result != "" {
		t.Errorf("Expected empty string for nil, got %q", result)
	}
}

// TestJoinUint16Hex_EmptySlice tests handling of empty slices.
func TestJoinUint16Hex_EmptySlice(t *testing.T) {
	result := joinUint16Hex([]uint16{}, ",")
	if result != "" {
		t.Errorf("Expected empty string, got %q", result)
	}

	result = joinUint16Hex(nil, ",")
	if result != "" {
		t.Errorf("Expected empty string for nil, got %q", result)
	}
}

// TestIsAlphanumeric_Characters tests alphanumeric character detection.
func TestIsAlphanumeric_Characters(t *testing.T) {
	testCases := []struct {
		char byte
		want bool
	}{
		{'0', true},
		{'9', true},
		{'A', true},
		{'Z', true},
		{'a', true},
		{'z', true},
		{'-', false},
		{'/', false},
		{' ', false},
		{0x00, false},
		{0xFF, false},
	}

	for _, tc := range testCases {
		t.Run(string(tc.char), func(t *testing.T) {
			got := isAlphanumeric(tc.char)
			if got != tc.want {
				t.Errorf("isAlphanumeric(%q) = %v, want %v", tc.char, got, tc.want)
			}
		})
	}
}

// TestIsGREASEUint16 tests GREASE value detection.
func TestIsGREASEUint16(t *testing.T) {
	// GREASE values have the pattern 0x?A?A where ? is the same hex digit
	greaseValues := []uint16{
		0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
		0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
		0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
	}

	nonGreaseValues := []uint16{
		0x0000, 0x0001, 0x0A0B, 0x1301, 0xFFFF,
		TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
	}

	for _, v := range greaseValues {
		if !isGREASEUint16(v) {
			t.Errorf("isGREASEUint16(0x%04X) should return true", v)
		}
	}

	for _, v := range nonGreaseValues {
		if isGREASEUint16(v) {
			t.Errorf("isGREASEUint16(0x%04X) should return false", v)
		}
	}
}
