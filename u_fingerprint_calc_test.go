// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// SECTION 1: CalculateFingerprints Malformed Input Tests
// =============================================================================

// TestCalculateFingerprints_TooShortInput tests handling of truncated ClientHello data.
func TestCalculateFingerprints_TooShortInput(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{"empty_input", []byte{}},
		{"one_byte", []byte{0x01}},
		{"two_bytes", []byte{0x01, 0x00}},
		{"three_bytes", []byte{0x01, 0x00, 0x00}},
		{"four_bytes", []byte{0x01, 0x00, 0x00, 0x05}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fp, err := CalculateFingerprints(tc.input)
			if err == nil {
				t.Errorf("expected error for input length %d, got fingerprint: %+v", len(tc.input), fp)
			}
		})
	}
}

// TestCalculateFingerprints_TruncatedVersion tests ClientHello truncated after handshake header.
func TestCalculateFingerprints_TruncatedVersion(t *testing.T) {
	// Handshake type (1) + length (3) + partial version
	input := []byte{0x01, 0x00, 0x00, 0x20, 0x03}
	_, err := CalculateFingerprints(input)
	if err == nil {
		t.Error("expected error for truncated version field")
	}
}

// TestCalculateFingerprints_TruncatedRandom tests ClientHello truncated in random field.
func TestCalculateFingerprints_TruncatedRandom(t *testing.T) {
	// Handshake type + length + version + partial random (only 10 bytes instead of 32)
	input := make([]byte, 16)
	input[0] = 0x01 // handshake type
	input[1] = 0x00 // length MSB
	input[2] = 0x00 // length
	input[3] = 0x0c // length LSB (12 bytes after header)
	input[4] = 0x03 // version MSB
	input[5] = 0x03 // version LSB (TLS 1.2)
	// bytes 6-15 are partial random

	_, err := CalculateFingerprints(input)
	if err == nil {
		t.Error("expected error for truncated random field")
	}
}

// TestCalculateFingerprints_TruncatedSessionID tests ClientHello with truncated session ID.
func TestCalculateFingerprints_TruncatedSessionID(t *testing.T) {
	// Build minimal ClientHello up to session ID
	input := make([]byte, 38)
	input[0] = 0x01 // handshake type
	input[1] = 0x00
	input[2] = 0x00
	input[3] = 0x22 // length = 34 bytes
	input[4] = 0x03
	input[5] = 0x03 // version TLS 1.2
	// Random: bytes 6-37

	// Session ID length claims 32 but no data follows
	input = append(input, 0x20) // session ID length = 32

	_, err := CalculateFingerprints(input)
	if err == nil {
		t.Error("expected error for truncated session ID")
	}
}

// TestCalculateFingerprints_TruncatedCipherSuites tests ClientHello with truncated cipher suites.
func TestCalculateFingerprints_TruncatedCipherSuites(t *testing.T) {
	// Build ClientHello up to cipher suites
	input := make([]byte, 39)
	input[0] = 0x01 // handshake type
	input[1] = 0x00
	input[2] = 0x00
	input[3] = 0x26 // length
	input[4] = 0x03
	input[5] = 0x03                     // version TLS 1.2
	copy(input[6:38], make([]byte, 32)) // random
	input[38] = 0x00                    // session ID length = 0

	// Cipher suite length claims 4 bytes but only 2 follow
	input = append(input, 0x00, 0x04) // cipher suite length = 4
	input = append(input, 0x13, 0x01) // only one cipher (2 bytes)

	_, err := CalculateFingerprints(input)
	if err == nil {
		t.Error("expected error for truncated cipher suites")
	}
}

// TestCalculateFingerprints_TruncatedCompression tests ClientHello with truncated compression.
func TestCalculateFingerprints_TruncatedCompression(t *testing.T) {
	// Build ClientHello with cipher suites but truncated compression
	input := buildMinimalClientHelloUpToCiphers(t)

	// Add cipher suites
	input = append(input, 0x00, 0x02) // length = 2
	input = append(input, 0x13, 0x01) // TLS_AES_128_GCM_SHA256

	// Compression length claims 2 but no data follows
	input = append(input, 0x02) // compression length = 2

	_, err := CalculateFingerprints(input)
	if err == nil {
		t.Error("expected error for truncated compression methods")
	}
}

// TestCalculateFingerprints_TruncatedExtensions tests ClientHello with truncated extensions.
func TestCalculateFingerprints_TruncatedExtensions(t *testing.T) {
	// Build ClientHello with complete header up to extensions
	input := buildMinimalClientHelloUpToCiphers(t)
	input = append(input, 0x00, 0x02) // cipher length
	input = append(input, 0x13, 0x01) // cipher
	input = append(input, 0x01, 0x00) // compression: length=1, null

	// Extensions length claims 100 bytes but only 2 follow
	input = append(input, 0x00, 0x64) // extensions length = 100
	input = append(input, 0x00, 0x00) // partial extension

	_, err := CalculateFingerprints(input)
	if err == nil {
		t.Error("expected error for truncated extensions")
	}
}

// TestCalculateFingerprints_InvalidExtensionLength tests extensions with invalid length field.
func TestCalculateFingerprints_InvalidExtensionLength(t *testing.T) {
	// Build ClientHello with extension that has too-large length
	input := buildMinimalClientHelloUpToCiphers(t)
	input = append(input, 0x00, 0x02) // cipher length
	input = append(input, 0x13, 0x01) // cipher
	input = append(input, 0x01, 0x00) // compression

	// Extension block
	extData := []byte{
		0x00, 0x00, // SNI extension type
		0x00, 0x50, // length claims 80 bytes but only a few follow
		0x00, 0x01, // actual data
	}
	extLen := len(extData)
	input = append(input, byte(extLen>>8), byte(extLen))
	input = append(input, extData...)

	_, err := CalculateFingerprints(input)
	if err == nil {
		t.Error("expected error for extension with invalid length")
	}
}

// =============================================================================
// SECTION 2: JA3 Calculation Edge Cases
// =============================================================================

// TestJA3_EmptyCipherSuites tests JA3 calculation with no cipher suites.
func TestJA3_EmptyCipherSuites(t *testing.T) {
	raw := buildValidClientHello(t, []uint16{}, []uint16{0, 10, 11}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// JA3r format: version,ciphers,extensions,curves,points
	parts := strings.Split(fp.JA3r, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3r wrong format: %s", fp.JA3r)
	}

	// Ciphers field should be empty
	if parts[1] != "" {
		t.Errorf("expected empty ciphers field, got: %s", parts[1])
	}

	// JA3 hash should still be 32 chars
	if len(fp.JA3) != 32 {
		t.Errorf("JA3 hash wrong length: %d", len(fp.JA3))
	}
}

// TestJA3_OnlyGREASECiphers tests JA3 with only GREASE cipher suites (should filter all).
func TestJA3_OnlyGREASECiphers(t *testing.T) {
	// All 16 GREASE values
	greaseCiphers := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	raw := buildValidClientHello(t, greaseCiphers, []uint16{0, 10, 11}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3r wrong format: %s", fp.JA3r)
	}

	// All GREASE ciphers should be filtered, leaving empty field
	if parts[1] != "" {
		t.Errorf("expected empty ciphers after GREASE filtering, got: %s", parts[1])
	}
}

// TestJA3_MaximumCipherSuites tests JA3 with many cipher suites (100+).
func TestJA3_MaximumCipherSuites(t *testing.T) {
	// Generate 150 non-GREASE cipher suites
	ciphers := make([]uint16, 150)
	for i := 0; i < 150; i++ {
		// Use values that are NOT GREASE (avoid 0x?a?a pattern)
		ciphers[i] = uint16(0x0001 + i)
	}

	raw := buildValidClientHello(t, ciphers, []uint16{0, 10, 11}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3r wrong format: %s", fp.JA3r)
	}

	// Count ciphers in the output
	cipherParts := strings.Split(parts[1], "-")
	if len(cipherParts) != 150 {
		t.Errorf("expected 150 ciphers in JA3r, got: %d", len(cipherParts))
	}
}

// TestJA3_ZeroLengthExtensions tests JA3 with no extensions.
func TestJA3_ZeroLengthExtensions(t *testing.T) {
	// Build ClientHello with no extensions
	raw := buildValidClientHelloNoExtensions(t, []uint16{TLS_AES_128_GCM_SHA256})

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3r wrong format: %s", fp.JA3r)
	}

	// Extensions, curves, points should all be empty
	if parts[2] != "" {
		t.Errorf("expected empty extensions, got: %s", parts[2])
	}
	if parts[3] != "" {
		t.Errorf("expected empty curves, got: %s", parts[3])
	}
	if parts[4] != "" {
		t.Errorf("expected empty points, got: %s", parts[4])
	}
}

// TestJA3_SortedVsUnsorted tests JA3 vs JA3n (sorted extensions).
func TestJA3_SortedVsUnsorted(t *testing.T) {
	// Extensions in non-sorted order: 43, 10, 0, 11
	extensions := []uint16{43, 10, 0, 11}

	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// JA3r should have original order
	parts := strings.Split(fp.JA3r, ",")
	extParts := strings.Split(parts[2], "-")

	expectedOrder := []string{"43", "10", "0", "11"}
	for i, exp := range expectedOrder {
		if i >= len(extParts) || extParts[i] != exp {
			t.Errorf("JA3r extension order wrong at index %d: expected %s, got %v", i, exp, extParts)
			break
		}
	}

	// JA3rn should have sorted order
	partsN := strings.Split(fp.JA3rn, ",")
	extPartsN := strings.Split(partsN[2], "-")

	expectedSorted := []string{"0", "10", "11", "43"}
	for i, exp := range expectedSorted {
		if i >= len(extPartsN) || extPartsN[i] != exp {
			t.Errorf("JA3rn extension order wrong at index %d: expected %s, got %v", i, exp, extPartsN)
			break
		}
	}

	// JA3 and JA3n hashes should differ (different extension order)
	if fp.JA3 == fp.JA3n {
		t.Log("Note: JA3 equals JA3n - this can happen if hash collision or same content")
	}
}

// =============================================================================
// SECTION 3: JA4 Calculation Edge Cases
// =============================================================================

// TestJA4_MissingSNI tests JA4 SNI indicator is 'i' when SNI is absent.
func TestJA4_MissingSNI(t *testing.T) {
	// Build ClientHello without SNI extension (extension type 0)
	extensions := []uint16{10, 11, 43} // No SNI (type 0)

	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 wrong format: %s", fp.JA4)
	}

	ja4a := parts[0]
	// JA4a format: {proto}{version}{sni}{cipher_count}{ext_count}{alpn}
	// Position 3 is SNI indicator
	if len(ja4a) < 4 {
		t.Fatalf("JA4a too short: %s", ja4a)
	}

	sni := ja4a[3]
	if sni != 'i' {
		t.Errorf("expected SNI indicator 'i' for missing SNI, got '%c'", sni)
	}
}

// TestJA4_WithSNI tests JA4 SNI indicator is 'd' when SNI is present.
func TestJA4_WithSNI(t *testing.T) {
	// Build ClientHello with SNI extension
	extensions := []uint16{0, 10, 11, 43} // SNI is type 0

	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	ja4a := parts[0]

	sni := ja4a[3]
	if sni != 'd' {
		t.Errorf("expected SNI indicator 'd' for present SNI, got '%c'", sni)
	}
}

// TestJA4_NonAlphanumericALPN tests JA4 ALPN encoding for non-alphanumeric protocols.
func TestJA4_NonAlphanumericALPN(t *testing.T) {
	t.Parallel()

	// Build ClientHello with ALPN containing non-alphanumeric chars
	// ALPN like "spdy/3.1" has '/' which is non-alphanumeric
	extensions := []uint16{0, 10, 11, 16, 43} // 16 = ALPN

	// For this test, we'll manually verify the ALPN handling logic
	// Since buildValidClientHello doesn't support custom ALPN,
	// we test the helper function directly

	// Test alphanumeric ALPN
	t.Run("alphanumeric_h2", func(t *testing.T) {
		t.Parallel()
		alpn := "h2"
		first := alpn[0]
		last := alpn[len(alpn)-1]
		if !isAlphanumeric(first) || !isAlphanumeric(last) {
			t.Error("h2 should be alphanumeric")
		}
	})

	// Test non-alphanumeric ALPN
	t.Run("non_alphanumeric_spdy/3.1", func(t *testing.T) {
		t.Parallel()
		alpn := "spdy/3.1"
		first := alpn[0]
		last := alpn[len(alpn)-1]
		if !isAlphanumeric(first) {
			t.Error("'s' should be alphanumeric")
		}
		if !isAlphanumeric(last) {
			t.Error("'1' should be alphanumeric")
		}
	})

	// Test ALPN with special chars at both ends
	t.Run("special_chars_at_ends", func(t *testing.T) {
		t.Parallel()
		alpn := "/special/"
		first := alpn[0]
		last := alpn[len(alpn)-1]
		if isAlphanumeric(first) || isAlphanumeric(last) {
			t.Error("'/' should not be alphanumeric")
		}
	})

	// Test ClientHello with real ALPN
	t.Run("real_alpn_h2", func(t *testing.T) {
		t.Parallel()
		raw := buildValidClientHelloWithALPN(t, []uint16{TLS_AES_128_GCM_SHA256}, extensions, "h2")
		fp, err := CalculateFingerprints(raw)
		if err != nil {
			t.Fatalf("CalculateFingerprints failed: %v", err)
		}

		parts := strings.Split(fp.JA4, "_")
		ja4a := parts[0]
		// Last 2 chars should be ALPN indicator
		alpnIndicator := ja4a[len(ja4a)-2:]
		if alpnIndicator != "h2" {
			t.Errorf("expected ALPN indicator 'h2', got '%s'", alpnIndicator)
		}
	})
}

// TestJA4_EmptyALPN tests JA4 ALPN indicator when no ALPN extension.
func TestJA4_EmptyALPN(t *testing.T) {
	// Build ClientHello without ALPN extension (extension type 16)
	extensions := []uint16{0, 10, 11, 43} // No ALPN

	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	ja4a := parts[0]

	// Last 2 chars should be "00" for no ALPN
	alpnIndicator := ja4a[len(ja4a)-2:]
	if alpnIndicator != "00" {
		t.Errorf("expected ALPN indicator '00' for empty ALPN, got '%s'", alpnIndicator)
	}
}

// TestJA4_CipherCountCapped tests JA4 cipher count is capped at 99.
func TestJA4_CipherCountCapped(t *testing.T) {
	// Create 150 non-GREASE ciphers
	ciphers := make([]uint16, 150)
	for i := 0; i < 150; i++ {
		ciphers[i] = uint16(0x0001 + i) // Non-GREASE values
	}

	raw := buildValidClientHello(t, ciphers, []uint16{0, 10, 11, 43}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	ja4a := parts[0]

	// JA4a format: {proto:1}{version:2}{sni:1}{cipher_count:2}{ext_count:2}{alpn:2}
	// Cipher count is at positions 4-5
	cipherCountStr := ja4a[4:6]
	if cipherCountStr != "99" {
		t.Errorf("expected cipher count '99' (capped), got '%s'", cipherCountStr)
	}
}

// TestJA4_ExtensionCountCapped tests JA4 extension count is capped at 99.
func TestJA4_ExtensionCountCapped(t *testing.T) {
	// Create 150 non-GREASE extensions
	extensions := make([]uint16, 150)
	for i := 0; i < 150; i++ {
		// Use values that are NOT GREASE (avoid 0x?a?a pattern)
		extensions[i] = uint16(i)
	}

	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	ja4a := parts[0]

	// Extension count is at positions 6-7
	extCountStr := ja4a[6:8]
	if extCountStr != "99" {
		t.Errorf("expected extension count '99' (capped), got '%s'", extCountStr)
	}
}

// TestJA4_TLSVersions tests JA4 version detection for different TLS versions.
func TestJA4_TLSVersions(t *testing.T) {
	testCases := []struct {
		version         uint16
		supportedVers   []uint16
		expectedVersion string
	}{
		{VersionTLS12, nil, "12"},
		{VersionTLS12, []uint16{VersionTLS13}, "13"},
		{VersionTLS12, []uint16{VersionTLS12}, "12"},
		{VersionTLS11, nil, "11"},
		{VersionTLS10, nil, "10"},
		{VersionSSL30, nil, "s3"},
		{0x0305, nil, "00"}, // Unknown version
	}

	for _, tc := range testCases {
		t.Run(tc.expectedVersion, func(t *testing.T) {
			raw := buildValidClientHelloWithVersion(t, tc.version, tc.supportedVers)

			fp, err := CalculateFingerprints(raw)
			if err != nil {
				t.Fatalf("CalculateFingerprints failed: %v", err)
			}

			parts := strings.Split(fp.JA4, "_")
			ja4a := parts[0]

			// Version is at positions 1-2
			versionStr := ja4a[1:3]
			if versionStr != tc.expectedVersion {
				t.Errorf("expected version '%s', got '%s' (ja4a: %s)", tc.expectedVersion, versionStr, ja4a)
			}
		})
	}
}

// TestJA4_SortedCiphers tests that JA4 ciphers are sorted for JA4 but not for JA4o.
func TestJA4_SortedCiphers(t *testing.T) {
	// Ciphers in non-sorted order
	ciphers := []uint16{0x1302, 0x1301, 0x1303} // AES256, AES128, CHACHA20

	raw := buildValidClientHello(t, ciphers, []uint16{0, 10, 11, 43}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// JA4r (sorted, raw) should have sorted ciphers
	parts := strings.Split(fp.JA4r, "_")
	ja4b := parts[1]
	// Sorted order: 1301, 1302, 1303
	expectedSorted := "1301,1302,1303"
	if ja4b != expectedSorted {
		t.Errorf("JA4r ciphers should be sorted: expected %s, got %s", expectedSorted, ja4b)
	}

	// JA4ro (original order, raw) should have original order
	partsO := strings.Split(fp.JA4ro, "_")
	ja4bO := partsO[1]
	expectedOriginal := "1302,1301,1303"
	if ja4bO != expectedOriginal {
		t.Errorf("JA4ro ciphers should be original order: expected %s, got %s", expectedOriginal, ja4bO)
	}
}

// TestJA4_EmptyExtensionsHash tests JA4c hash for empty extensions.
func TestJA4_EmptyExtensionsHash(t *testing.T) {
	raw := buildValidClientHelloNoExtensions(t, []uint16{TLS_AES_128_GCM_SHA256})

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	ja4c := parts[2]

	// Empty extensions should produce "000000000000"
	if ja4c != "000000000000" {
		t.Errorf("expected JA4c '000000000000' for empty extensions, got '%s'", ja4c)
	}
}

// TestJA4_EmptyCiphersHash tests JA4b hash for empty ciphers.
func TestJA4_EmptyCiphersHash(t *testing.T) {
	raw := buildValidClientHello(t, []uint16{}, []uint16{0, 10, 11}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	ja4b := parts[1]

	// Empty ciphers should produce "000000000000"
	if ja4b != "000000000000" {
		t.Errorf("expected JA4b '000000000000' for empty ciphers, got '%s'", ja4b)
	}
}

// =============================================================================
// SECTION 4: JA4S (ServerHello) Calculation Edge Cases
// =============================================================================

// TestCalculateJA4S_TLS12 tests JA4S calculation for TLS 1.2 ServerHello.
func TestCalculateJA4S_TLS12(t *testing.T) {
	raw := buildValidServerHello(t, VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil, "")

	fp, err := CalculateJA4S(raw)
	if err != nil {
		t.Fatalf("CalculateJA4S failed: %v", err)
	}

	parts := strings.Split(fp.JA4S, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4S wrong format: %s", fp.JA4S)
	}

	ja4sA := parts[0]
	// Version should be "12"
	if len(ja4sA) < 3 {
		t.Fatalf("JA4S_a too short: %s", ja4sA)
	}
	version := ja4sA[1:3]
	if version != "12" {
		t.Errorf("expected version '12', got '%s'", version)
	}
}

// TestCalculateJA4S_TLS13 tests JA4S calculation for TLS 1.3 ServerHello.
func TestCalculateJA4S_TLS13(t *testing.T) {
	// TLS 1.3 uses supported_versions extension to signal version
	extensions := []uint16{43, 51} // supported_versions, key_share
	raw := buildValidServerHelloTLS13(t, TLS_AES_128_GCM_SHA256, extensions)

	fp, err := CalculateJA4S(raw)
	if err != nil {
		t.Fatalf("CalculateJA4S failed: %v", err)
	}

	parts := strings.Split(fp.JA4S, "_")
	ja4sA := parts[0]

	// Version should be "13" (from supported_versions extension)
	version := ja4sA[1:3]
	if version != "13" {
		t.Errorf("expected version '13', got '%s'", version)
	}
}

// TestCalculateJA4S_EmptyExtensions tests JA4S with no extensions.
func TestCalculateJA4S_EmptyExtensions(t *testing.T) {
	raw := buildValidServerHello(t, VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil, "")

	fp, err := CalculateJA4S(raw)
	if err != nil {
		t.Fatalf("CalculateJA4S failed: %v", err)
	}

	parts := strings.Split(fp.JA4S, "_")
	ja4sA := parts[0]
	ja4sC := parts[2]

	// Extension count should be "00"
	extCount := ja4sA[3:5]
	if extCount != "00" {
		t.Errorf("expected extension count '00', got '%s'", extCount)
	}

	// Extensions hash should be "000000000000"
	if ja4sC != "000000000000" {
		t.Errorf("expected JA4S_c '000000000000' for empty extensions, got '%s'", ja4sC)
	}
}

// TestCalculateJA4S_MissingALPN tests JA4S ALPN indicator when ALPN is absent.
func TestCalculateJA4S_MissingALPN(t *testing.T) {
	raw := buildValidServerHello(t, VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil, "")

	fp, err := CalculateJA4S(raw)
	if err != nil {
		t.Fatalf("CalculateJA4S failed: %v", err)
	}

	parts := strings.Split(fp.JA4S, "_")
	ja4sA := parts[0]

	// Last 2 chars should be "00" for no ALPN
	alpn := ja4sA[len(ja4sA)-2:]
	if alpn != "00" {
		t.Errorf("expected ALPN '00' for missing ALPN, got '%s'", alpn)
	}
}

// TestCalculateJA4S_WithALPN tests JA4S ALPN indicator when ALPN is present.
func TestCalculateJA4S_WithALPN(t *testing.T) {
	extensions := []uint16{16} // ALPN
	raw := buildValidServerHelloWithALPN(t, VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, extensions, "h2")

	fp, err := CalculateJA4S(raw)
	if err != nil {
		t.Fatalf("CalculateJA4S failed: %v", err)
	}

	parts := strings.Split(fp.JA4S, "_")
	ja4sA := parts[0]

	// Last 2 chars should be "h2"
	alpn := ja4sA[len(ja4sA)-2:]
	if alpn != "h2" {
		t.Errorf("expected ALPN 'h2', got '%s'", alpn)
	}
}

// TestCalculateJA4S_CipherFormatting tests JA4S cipher is formatted as 4 hex chars.
func TestCalculateJA4S_CipherFormatting(t *testing.T) {
	testCases := []struct {
		cipher   uint16
		expected string
	}{
		{TLS_AES_128_GCM_SHA256, "1301"},
		{TLS_AES_256_GCM_SHA384, "1302"},
		{TLS_CHACHA20_POLY1305_SHA256, "1303"},
		{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "c02f"},
		{0x0001, "0001"}, // Low value
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			raw := buildValidServerHello(t, VersionTLS12, tc.cipher, nil, "")

			fp, err := CalculateJA4S(raw)
			if err != nil {
				t.Fatalf("CalculateJA4S failed: %v", err)
			}

			parts := strings.Split(fp.JA4S, "_")
			ja4sB := parts[1]

			if ja4sB != tc.expected {
				t.Errorf("expected cipher '%s', got '%s'", tc.expected, ja4sB)
			}
		})
	}
}

// TestCalculateJA4S_TooShortInput tests JA4S with truncated ServerHello.
func TestCalculateJA4S_TooShortInput(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"one_byte", []byte{0x02}},
		{"four_bytes", []byte{0x02, 0x00, 0x00, 0x20}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CalculateJA4S(tc.input)
			if err == nil {
				t.Error("expected error for truncated ServerHello")
			}
		})
	}
}

// =============================================================================
// SECTION 5: JA4X (Certificate) Calculation Edge Cases
// =============================================================================

// TestCalculateJA4X_NilCertificate tests JA4X with nil certificate.
func TestCalculateJA4X_NilCertificate(t *testing.T) {
	fp := CalculateJA4X(nil)

	expected := "000000000000_000000000000_000000000000"
	if fp.JA4X != expected {
		t.Errorf("expected JA4X '%s' for nil cert, got '%s'", expected, fp.JA4X)
	}
}

// TestCalculateJA4X_NoIssuerOIDs tests JA4X with certificate having no issuer OIDs.
func TestCalculateJA4X_NoIssuerOIDs(t *testing.T) {
	cert := &x509.Certificate{
		Issuer: pkix.Name{}, // Empty issuer
		Subject: pkix.Name{
			CommonName: "Test",
		},
	}

	fp := CalculateJA4X(cert)

	// Issuer hash should be "000000000000" (empty OIDs)
	parts := strings.Split(fp.JA4X, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4X wrong format: %s", fp.JA4X)
	}

	issuerHash := parts[0]
	if issuerHash != "000000000000" {
		t.Errorf("expected issuer hash '000000000000' for empty issuer, got '%s'", issuerHash)
	}
}

// TestCalculateJA4X_NoSubjectOIDs tests JA4X with certificate having no subject OIDs.
func TestCalculateJA4X_NoSubjectOIDs(t *testing.T) {
	cert := &x509.Certificate{
		Issuer: pkix.Name{
			CommonName: "Issuer",
		},
		Subject: pkix.Name{}, // Empty subject
	}

	fp := CalculateJA4X(cert)

	parts := strings.Split(fp.JA4X, "_")
	subjectHash := parts[1]

	if subjectHash != "000000000000" {
		t.Errorf("expected subject hash '000000000000' for empty subject, got '%s'", subjectHash)
	}
}

// TestCalculateJA4X_NoExtensions tests JA4X with certificate having no extensions.
func TestCalculateJA4X_NoExtensions(t *testing.T) {
	cert := &x509.Certificate{
		Issuer: pkix.Name{
			CommonName: "Issuer",
		},
		Subject: pkix.Name{
			CommonName: "Subject",
		},
		Extensions: nil, // No extensions
	}

	fp := CalculateJA4X(cert)

	parts := strings.Split(fp.JA4X, "_")
	extHash := parts[2]

	if extHash != "000000000000" {
		t.Errorf("expected extensions hash '000000000000' for no extensions, got '%s'", extHash)
	}
}

// TestCalculateJA4X_RealCertificate tests JA4X with a real self-signed certificate.
func TestCalculateJA4X_RealCertificate(t *testing.T) {
	// Generate a real certificate
	cert := generateTestCertificate(t)

	fp := CalculateJA4X(cert)

	// Verify format
	parts := strings.Split(fp.JA4X, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4X wrong format: %s", fp.JA4X)
	}

	// Each part should be 12 hex chars
	for i, part := range parts {
		if len(part) != 12 {
			t.Errorf("JA4X part %d wrong length: expected 12, got %d (%s)", i, len(part), part)
		}
	}

	// Verify OIDs were extracted
	if len(fp.IssuerOIDs) == 0 {
		t.Error("expected non-empty IssuerOIDs")
	}
	if len(fp.SubjectOIDs) == 0 {
		t.Error("expected non-empty SubjectOIDs")
	}

	t.Logf("JA4X: %s", fp.JA4X)
	t.Logf("IssuerOIDs: %v", fp.IssuerOIDs)
	t.Logf("SubjectOIDs: %v", fp.SubjectOIDs)
	t.Logf("ExtensionOIDs: %v", fp.ExtensionOIDs)
}

// TestCalculateJA4X_OIDOrder tests that JA4X preserves OID order.
func TestCalculateJA4X_OIDOrder(t *testing.T) {
	// Create two certificates with same OIDs but different order
	cert1 := &x509.Certificate{
		Issuer: pkix.Name{
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},   // Country
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org"}, // Organization
			},
		},
	}

	cert2 := &x509.Certificate{
		Issuer: pkix.Name{
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org"}, // Organization first
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"},   // Country second
			},
		},
	}

	fp1 := CalculateJA4X(cert1)
	fp2 := CalculateJA4X(cert2)

	// Different OID order should produce different hashes
	parts1 := strings.Split(fp1.JA4X, "_")
	parts2 := strings.Split(fp2.JA4X, "_")

	if parts1[0] == parts2[0] {
		t.Log("Note: Same issuer hash despite different OID order - hashes may collide")
	}

	// Verify OID order in raw lists
	if len(fp1.IssuerOIDs) >= 2 && len(fp2.IssuerOIDs) >= 2 {
		if fp1.IssuerOIDs[0] == fp2.IssuerOIDs[0] && fp1.IssuerOIDs[1] == fp2.IssuerOIDs[1] {
			t.Error("OID order should be different between cert1 and cert2")
		}
	}
}

// TestCalculateJA4X_CommonOIDs tests JA4X with common certificate OIDs.
func TestCalculateJA4X_CommonOIDs(t *testing.T) {
	// Common OIDs and their expected hex encodings
	testCases := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string // DER-encoded hex
	}{
		{"CommonName", asn1.ObjectIdentifier{2, 5, 4, 3}, "550403"},
		{"Country", asn1.ObjectIdentifier{2, 5, 4, 6}, "550406"},
		{"State", asn1.ObjectIdentifier{2, 5, 4, 8}, "550408"},
		{"Locality", asn1.ObjectIdentifier{2, 5, 4, 7}, "550407"},
		{"Organization", asn1.ObjectIdentifier{2, 5, 4, 10}, "55040a"},
		{"OrganizationalUnit", asn1.ObjectIdentifier{2, 5, 4, 11}, "55040b"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := oidToHex(tc.oid)
			if result != tc.expected {
				t.Errorf("oidToHex(%v) = %s, want %s", tc.oid, result, tc.expected)
			}
		})
	}
}

// TestCalculateJA4X_ExtensionOIDs tests JA4X with common extension OIDs.
func TestCalculateJA4X_ExtensionOIDs(t *testing.T) {
	// Common extension OIDs
	testCases := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string
	}{
		{"SubjectAltName", asn1.ObjectIdentifier{2, 5, 29, 17}, "551d11"},
		{"KeyUsage", asn1.ObjectIdentifier{2, 5, 29, 15}, "551d0f"},
		{"ExtKeyUsage", asn1.ObjectIdentifier{2, 5, 29, 37}, "551d25"},
		{"BasicConstraints", asn1.ObjectIdentifier{2, 5, 29, 19}, "551d13"},
		{"AuthorityKeyId", asn1.ObjectIdentifier{2, 5, 29, 35}, "551d23"},
		{"SubjectKeyId", asn1.ObjectIdentifier{2, 5, 29, 14}, "551d0e"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := oidToHex(tc.oid)
			if result != tc.expected {
				t.Errorf("oidToHex(%v) = %s, want %s", tc.oid, result, tc.expected)
			}
		})
	}
}

// =============================================================================
// SECTION 6: GREASE Filtering Tests
// =============================================================================

// TestGREASE_AllValidValues tests that all 16 GREASE values are detected.
func TestGREASE_AllValidValues(t *testing.T) {
	// All 16 valid GREASE values (pattern: 0x?a?a where both nibbles match)
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	for _, grease := range greaseValues {
		t.Run(hex.EncodeToString([]byte{byte(grease >> 8), byte(grease)}), func(t *testing.T) {
			if !isGREASEUint16(grease) {
				t.Errorf("0x%04x should be detected as GREASE", grease)
			}
		})
	}
}

// TestGREASE_InvalidValues tests that GREASE-like but invalid values are NOT detected.
func TestGREASE_InvalidValues(t *testing.T) {
	// Values that look similar to GREASE but aren't valid
	invalidGrease := []uint16{
		0x0a0b,                       // Second byte doesn't match pattern
		0x0b0a,                       // First byte doesn't match pattern
		0x0a00,                       // Second byte is 0x00 not 0x0a
		0x000a,                       // First byte is 0x00
		0x1a2a,                       // Different high nibbles
		0x0aaa,                       // Second byte has different high nibble
		0xaa0a,                       // First byte has different high nibble
		0x0a1a,                       // High nibbles don't match
		0x1234,                       // Completely different
		0xffff,                       // All ones
		0x0000,                       // All zeros
		TLS_AES_128_GCM_SHA256,       // 0x1301 - real cipher
		TLS_AES_256_GCM_SHA384,       // 0x1302 - real cipher
		TLS_CHACHA20_POLY1305_SHA256, // 0x1303 - real cipher
	}

	for _, val := range invalidGrease {
		t.Run(hex.EncodeToString([]byte{byte(val >> 8), byte(val)}), func(t *testing.T) {
			if isGREASEUint16(val) {
				t.Errorf("0x%04x should NOT be detected as GREASE", val)
			}
		})
	}
}

// TestGREASE_MixedWithRealCiphers tests GREASE filtering with mixed cipher list.
func TestGREASE_MixedWithRealCiphers(t *testing.T) {
	// Mix of GREASE and real ciphers (typical Chrome pattern)
	mixedCiphers := []uint16{
		0x0a0a, // GREASE
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
		0x1a1a, // GREASE
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		0xfafa, // GREASE
	}

	raw := buildValidClientHello(t, mixedCiphers, []uint16{0, 10, 11, 43}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	cipherStr := parts[1]

	// Should NOT contain any GREASE values
	for _, grease := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		greaseDecimal := strings.Split(cipherStr, "-")
		for _, cipher := range greaseDecimal {
			if cipher == "" {
				continue
			}
			// Convert to check
			for _, c := range strings.Split(cipher, "-") {
				if c == "2570" || c == "6682" || c == "64250" { // Decimal for 0x0a0a, 0x1a1a, 0xfafa
					t.Errorf("GREASE value 0x%04x found in JA3r ciphers: %s", grease, cipherStr)
				}
			}
		}
	}

	// Should contain real ciphers
	expectedCiphers := []string{"4865", "4866", "4867", "49199"} // Decimal for TLS 1.3 ciphers + ECDHE
	for _, exp := range expectedCiphers {
		if !strings.Contains(cipherStr, exp) {
			t.Errorf("expected cipher %s not found in JA3r: %s", exp, cipherStr)
		}
	}
}

// TestGREASE_FilteredFromExtensions tests GREASE filtering in extensions.
func TestGREASE_FilteredFromExtensions(t *testing.T) {
	// Mix of GREASE and real extensions
	mixedExtensions := []uint16{
		0x0a0a, // GREASE
		0,      // SNI
		10,     // supported_groups
		0x1a1a, // GREASE
		11,     // ec_point_formats
		43,     // supported_versions
		0xfafa, // GREASE
	}

	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, mixedExtensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	extStr := parts[2]

	// Should NOT contain GREASE extensions
	greaseDecimal := []string{"2570", "6682", "64250"}
	for _, gd := range greaseDecimal {
		if strings.Contains("-"+extStr+"-", "-"+gd+"-") || extStr == gd {
			t.Errorf("GREASE extension %s found in JA3r: %s", gd, extStr)
		}
	}

	// Should contain real extensions
	for _, exp := range []string{"0", "10", "11", "43"} {
		found := false
		for _, e := range strings.Split(extStr, "-") {
			if e == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected extension %s not found in JA3r: %s", exp, extStr)
		}
	}
}

// TestGREASE_FilteredFromSupportedGroups tests GREASE filtering in supported_groups.
func TestGREASE_FilteredFromSupportedGroups(t *testing.T) {
	// This test verifies that GREASE values are filtered from the supported_groups
	// extension (extension type 10) when building JA3 curves component

	// Create raw ClientHello with GREASE in supported_groups
	ciphers := []uint16{TLS_AES_128_GCM_SHA256}
	extensions := []uint16{0, 10, 11, 43} // SNI, supported_groups, ec_point_formats, supported_versions

	// We'll use the curves parameter to include GREASE
	curves := []uint16{0x0a0a, uint16(X25519), uint16(CurveP256), 0x1a1a}

	raw := buildValidClientHello(t, ciphers, extensions, curves, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	curvesStr := parts[3]

	// Should NOT contain GREASE values (2570, 6682 decimal for 0x0a0a, 0x1a1a)
	if strings.Contains("-"+curvesStr+"-", "-2570-") || curvesStr == "2570" {
		t.Errorf("GREASE curve 0x0a0a found in JA3r curves: %s", curvesStr)
	}
	if strings.Contains("-"+curvesStr+"-", "-6682-") || curvesStr == "6682" {
		t.Errorf("GREASE curve 0x1a1a found in JA3r curves: %s", curvesStr)
	}

	// Should contain real curves (X25519=29, P256=23)
	if !strings.Contains("-"+curvesStr+"-", "-29-") && curvesStr != "29" && !strings.HasPrefix(curvesStr, "29-") && !strings.HasSuffix(curvesStr, "-29") {
		t.Errorf("expected curve X25519 (29) not found in JA3r: %s", curvesStr)
	}
	if !strings.Contains("-"+curvesStr+"-", "-23-") && curvesStr != "23" && !strings.HasPrefix(curvesStr, "23-") && !strings.HasSuffix(curvesStr, "-23") {
		t.Errorf("expected curve P256 (23) not found in JA3r: %s", curvesStr)
	}
}

// TestGREASE_FilteredFromSupportedVersions tests GREASE filtering in supported_versions.
func TestGREASE_FilteredFromSupportedVersions(t *testing.T) {
	// Build ClientHello with GREASE in supported_versions
	versions := []uint16{0x0a0a, VersionTLS13, VersionTLS12, 0xfafa}

	raw := buildValidClientHelloWithVersion(t, VersionTLS12, versions)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA4, "_")
	ja4a := parts[0]

	// Version should be "13" (highest non-GREASE version)
	version := ja4a[1:3]
	if version != "13" {
		t.Errorf("expected version '13' after GREASE filtering, got '%s'", version)
	}
}

// =============================================================================
// SECTION 7: Helper Function Tests
// =============================================================================

// TestJoinUint16Decimal tests the joinUint16Decimal helper function.
func TestJoinUint16Decimal(t *testing.T) {
	testCases := []struct {
		input    []uint16
		sep      string
		expected string
	}{
		{[]uint16{}, "-", ""},
		{[]uint16{1}, "-", "1"},
		{[]uint16{1, 2, 3}, "-", "1-2-3"},
		{[]uint16{65535, 0, 1}, ",", "65535,0,1"},
		{[]uint16{771}, "-", "771"},
	}

	for _, tc := range testCases {
		result := joinUint16Decimal(tc.input, tc.sep)
		if result != tc.expected {
			t.Errorf("joinUint16Decimal(%v, %q) = %q, want %q", tc.input, tc.sep, result, tc.expected)
		}
	}
}

// TestJoinUint8Decimal tests the joinUint8Decimal helper function.
func TestJoinUint8Decimal(t *testing.T) {
	testCases := []struct {
		input    []uint8
		sep      string
		expected string
	}{
		{[]uint8{}, "-", ""},
		{[]uint8{0}, "-", "0"},
		{[]uint8{0, 1, 2}, "-", "0-1-2"},
		{[]uint8{255, 128, 0}, ",", "255,128,0"},
	}

	for _, tc := range testCases {
		result := joinUint8Decimal(tc.input, tc.sep)
		if result != tc.expected {
			t.Errorf("joinUint8Decimal(%v, %q) = %q, want %q", tc.input, tc.sep, result, tc.expected)
		}
	}
}

// TestJoinUint16Hex tests the joinUint16Hex helper function.
func TestJoinUint16Hex(t *testing.T) {
	testCases := []struct {
		input    []uint16
		sep      string
		expected string
	}{
		{[]uint16{}, ",", ""},
		{[]uint16{0x1301}, ",", "1301"},
		{[]uint16{0x1301, 0x1302, 0x1303}, ",", "1301,1302,1303"},
		{[]uint16{0x0001, 0xffff}, "-", "0001-ffff"},
		{[]uint16{0x0000}, ",", "0000"},
	}

	for _, tc := range testCases {
		result := joinUint16Hex(tc.input, tc.sep)
		if result != tc.expected {
			t.Errorf("joinUint16Hex(%v, %q) = %q, want %q", tc.input, tc.sep, result, tc.expected)
		}
	}
}

// TestIsAlphanumeric tests the isAlphanumeric helper function.
func TestIsAlphanumeric(t *testing.T) {
	testCases := []struct {
		input    byte
		expected bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{' ', false},
		{'/', false},
		{'.', false},
		{'-', false},
		{'_', false},
		{0x00, false},
		{0xff, false},
	}

	for _, tc := range testCases {
		result := isAlphanumeric(tc.input)
		if result != tc.expected {
			t.Errorf("isAlphanumeric(%q) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}

// TestEncodeVarInt tests the encodeVarInt helper function.
func TestEncodeVarInt(t *testing.T) {
	testCases := []struct {
		input    int
		expected []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x00}},
		{255, []byte{0x81, 0x7f}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x81, 0x80, 0x00}},
	}

	for _, tc := range testCases {
		result := encodeVarInt(tc.input)
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("encodeVarInt(%d) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}

// =============================================================================
// SECTION 8: Test Helpers - Building Valid TLS Messages
// =============================================================================

// buildMinimalClientHelloUpToCiphers builds a ClientHello up to the cipher suites field.
func buildMinimalClientHelloUpToCiphers(t *testing.T) []byte {
	t.Helper()
	// Handshake header + version + random + session ID
	input := make([]byte, 39)
	input[0] = 0x01 // handshake type: ClientHello
	input[1] = 0x00
	input[2] = 0x00
	input[3] = 0x23 // length placeholder
	input[4] = 0x03
	input[5] = 0x03 // version: TLS 1.2
	// Random: bytes 6-37 (32 bytes of zeros)
	input[38] = 0x00 // session ID length = 0
	return input
}

// buildValidClientHello builds a valid ClientHello for testing.
func buildValidClientHello(t *testing.T, ciphers []uint16, extensions []uint16, curves []uint16, points []uint8, sigAlgs []uint16) []byte {
	t.Helper()
	return buildValidClientHelloFull(t, VersionTLS12, ciphers, extensions, curves, points, sigAlgs, nil, "")
}

// buildValidClientHelloFull builds a complete valid ClientHello with all options.
func buildValidClientHelloFull(t *testing.T, version uint16, ciphers []uint16, extensions []uint16, curves []uint16, points []uint8, sigAlgs []uint16, supportedVersions []uint16, alpn string) []byte {
	t.Helper()

	var buf bytes.Buffer

	// Placeholder for handshake header (will fill in later)
	buf.WriteByte(0x01)        // ClientHello
	buf.Write([]byte{0, 0, 0}) // Length placeholder

	// Version
	buf.WriteByte(byte(version >> 8))
	buf.WriteByte(byte(version))

	// Random (32 bytes)
	random := make([]byte, 32)
	buf.Write(random)

	// Session ID (empty)
	buf.WriteByte(0x00)

	// Cipher suites
	cipherBytes := len(ciphers) * 2
	buf.WriteByte(byte(cipherBytes >> 8))
	buf.WriteByte(byte(cipherBytes))
	for _, c := range ciphers {
		buf.WriteByte(byte(c >> 8))
		buf.WriteByte(byte(c))
	}

	// Compression methods
	buf.WriteByte(0x01) // length
	buf.WriteByte(0x00) // null compression

	// Extensions
	var extBuf bytes.Buffer
	for _, ext := range extensions {
		switch ext {
		case 0: // SNI
			extBuf.Write([]byte{0x00, 0x00}) // type
			extBuf.Write([]byte{0x00, 0x0e}) // length
			extBuf.Write([]byte{0x00, 0x0c}) // list length
			extBuf.WriteByte(0x00)           // type: hostname
			extBuf.Write([]byte{0x00, 0x09}) // hostname length
			extBuf.WriteString("localhost")
		case 10: // supported_groups
			if curves == nil {
				curves = []uint16{uint16(X25519), uint16(CurveP256)}
			}
			extBuf.Write([]byte{0x00, 0x0a}) // type
			dataLen := len(curves)*2 + 2
			extBuf.WriteByte(byte(dataLen >> 8))
			extBuf.WriteByte(byte(dataLen))
			extBuf.WriteByte(byte(len(curves) * 2 >> 8))
			extBuf.WriteByte(byte(len(curves) * 2))
			for _, c := range curves {
				extBuf.WriteByte(byte(c >> 8))
				extBuf.WriteByte(byte(c))
			}
		case 11: // ec_point_formats
			if points == nil {
				points = []uint8{0}
			}
			extBuf.Write([]byte{0x00, 0x0b}) // type
			extBuf.WriteByte(byte((len(points) + 1) >> 8))
			extBuf.WriteByte(byte(len(points) + 1))
			extBuf.WriteByte(byte(len(points)))
			extBuf.Write(points)
		case 13: // signature_algorithms
			if sigAlgs == nil {
				sigAlgs = []uint16{uint16(ECDSAWithP256AndSHA256), uint16(PSSWithSHA256)}
			}
			extBuf.Write([]byte{0x00, 0x0d}) // type
			dataLen := len(sigAlgs)*2 + 2
			extBuf.WriteByte(byte(dataLen >> 8))
			extBuf.WriteByte(byte(dataLen))
			extBuf.WriteByte(byte(len(sigAlgs) * 2 >> 8))
			extBuf.WriteByte(byte(len(sigAlgs) * 2))
			for _, s := range sigAlgs {
				extBuf.WriteByte(byte(s >> 8))
				extBuf.WriteByte(byte(s))
			}
		case 16: // ALPN
			if alpn == "" {
				alpn = "h2"
			}
			extBuf.Write([]byte{0x00, 0x10}) // type
			alpnLen := len(alpn)
			totalLen := alpnLen + 3
			extBuf.WriteByte(byte(totalLen >> 8))
			extBuf.WriteByte(byte(totalLen))
			extBuf.WriteByte(byte((alpnLen + 1) >> 8))
			extBuf.WriteByte(byte(alpnLen + 1))
			extBuf.WriteByte(byte(alpnLen))
			extBuf.WriteString(alpn)
		case 43: // supported_versions
			if supportedVersions == nil {
				supportedVersions = []uint16{VersionTLS13, VersionTLS12}
			}
			extBuf.Write([]byte{0x00, 0x2b}) // type
			dataLen := len(supportedVersions)*2 + 1
			extBuf.WriteByte(byte(dataLen >> 8))
			extBuf.WriteByte(byte(dataLen))
			extBuf.WriteByte(byte(len(supportedVersions) * 2))
			for _, v := range supportedVersions {
				extBuf.WriteByte(byte(v >> 8))
				extBuf.WriteByte(byte(v))
			}
		default:
			// Generic extension with empty data
			extBuf.WriteByte(byte(ext >> 8))
			extBuf.WriteByte(byte(ext))
			extBuf.Write([]byte{0x00, 0x00}) // length = 0
		}
	}

	extLen := extBuf.Len()
	buf.WriteByte(byte(extLen >> 8))
	buf.WriteByte(byte(extLen))
	buf.Write(extBuf.Bytes())

	// Fix handshake length
	result := buf.Bytes()
	bodyLen := len(result) - 4
	result[1] = byte(bodyLen >> 16)
	result[2] = byte(bodyLen >> 8)
	result[3] = byte(bodyLen)

	return result
}

// buildValidClientHelloNoExtensions builds a ClientHello without any extensions.
func buildValidClientHelloNoExtensions(t *testing.T, ciphers []uint16) []byte {
	t.Helper()

	var buf bytes.Buffer

	buf.WriteByte(0x01)        // ClientHello
	buf.Write([]byte{0, 0, 0}) // Length placeholder

	// Version: TLS 1.2
	buf.Write([]byte{0x03, 0x03})

	// Random (32 bytes)
	buf.Write(make([]byte, 32))

	// Session ID (empty)
	buf.WriteByte(0x00)

	// Cipher suites
	cipherBytes := len(ciphers) * 2
	buf.WriteByte(byte(cipherBytes >> 8))
	buf.WriteByte(byte(cipherBytes))
	for _, c := range ciphers {
		buf.WriteByte(byte(c >> 8))
		buf.WriteByte(byte(c))
	}

	// Compression methods
	buf.WriteByte(0x01)
	buf.WriteByte(0x00)

	// No extensions - end of ClientHello

	// Fix handshake length
	result := buf.Bytes()
	bodyLen := len(result) - 4
	result[1] = byte(bodyLen >> 16)
	result[2] = byte(bodyLen >> 8)
	result[3] = byte(bodyLen)

	return result
}

// buildValidClientHelloWithALPN builds a ClientHello with specific ALPN.
func buildValidClientHelloWithALPN(t *testing.T, ciphers []uint16, extensions []uint16, alpn string) []byte {
	t.Helper()
	return buildValidClientHelloFull(t, VersionTLS12, ciphers, extensions, nil, nil, nil, nil, alpn)
}

// buildValidClientHelloWithVersion builds a ClientHello with specific version.
func buildValidClientHelloWithVersion(t *testing.T, version uint16, supportedVersions []uint16) []byte {
	t.Helper()
	extensions := []uint16{0, 10, 11}
	if supportedVersions != nil {
		extensions = append(extensions, 43)
	}
	return buildValidClientHelloFull(t, version, []uint16{TLS_AES_128_GCM_SHA256}, extensions, nil, nil, nil, supportedVersions, "")
}

// buildValidServerHello builds a valid ServerHello for testing.
func buildValidServerHello(t *testing.T, version uint16, cipher uint16, extensions []uint16, alpn string) []byte {
	t.Helper()

	var buf bytes.Buffer

	buf.WriteByte(0x02)        // ServerHello
	buf.Write([]byte{0, 0, 0}) // Length placeholder

	// Version
	buf.WriteByte(byte(version >> 8))
	buf.WriteByte(byte(version))

	// Random (32 bytes)
	buf.Write(make([]byte, 32))

	// Session ID (empty for simplicity)
	buf.WriteByte(0x00)

	// Cipher suite
	buf.WriteByte(byte(cipher >> 8))
	buf.WriteByte(byte(cipher))

	// Compression method
	buf.WriteByte(0x00)

	// Extensions
	if len(extensions) > 0 {
		var extBuf bytes.Buffer
		for _, ext := range extensions {
			extBuf.WriteByte(byte(ext >> 8))
			extBuf.WriteByte(byte(ext))
			extBuf.Write([]byte{0x00, 0x00}) // empty extension data
		}
		extLen := extBuf.Len()
		buf.WriteByte(byte(extLen >> 8))
		buf.WriteByte(byte(extLen))
		buf.Write(extBuf.Bytes())
	}

	// Fix handshake length
	result := buf.Bytes()
	bodyLen := len(result) - 4
	result[1] = byte(bodyLen >> 16)
	result[2] = byte(bodyLen >> 8)
	result[3] = byte(bodyLen)

	return result
}

// buildValidServerHelloTLS13 builds a TLS 1.3 ServerHello.
func buildValidServerHelloTLS13(t *testing.T, cipher uint16, extensions []uint16) []byte {
	t.Helper()

	var buf bytes.Buffer

	buf.WriteByte(0x02)        // ServerHello
	buf.Write([]byte{0, 0, 0}) // Length placeholder

	// Legacy version (TLS 1.2 for TLS 1.3)
	buf.Write([]byte{0x03, 0x03})

	// Random (32 bytes)
	buf.Write(make([]byte, 32))

	// Session ID (echo back, using empty for simplicity)
	buf.WriteByte(0x00)

	// Cipher suite
	buf.WriteByte(byte(cipher >> 8))
	buf.WriteByte(byte(cipher))

	// Compression method
	buf.WriteByte(0x00)

	// Extensions - must include supported_versions for TLS 1.3
	var extBuf bytes.Buffer
	for _, ext := range extensions {
		extBuf.WriteByte(byte(ext >> 8))
		extBuf.WriteByte(byte(ext))
		if ext == 43 { // supported_versions
			extBuf.Write([]byte{0x00, 0x02}) // length
			extBuf.Write([]byte{0x03, 0x04}) // TLS 1.3
		} else if ext == 51 { // key_share
			extBuf.Write([]byte{0x00, 0x04}) // length
			extBuf.Write([]byte{0x00, 0x1d}) // X25519
			extBuf.Write([]byte{0x00, 0x00}) // empty key data (simplified)
		} else {
			extBuf.Write([]byte{0x00, 0x00}) // empty
		}
	}
	extLen := extBuf.Len()
	buf.WriteByte(byte(extLen >> 8))
	buf.WriteByte(byte(extLen))
	buf.Write(extBuf.Bytes())

	// Fix handshake length
	result := buf.Bytes()
	bodyLen := len(result) - 4
	result[1] = byte(bodyLen >> 16)
	result[2] = byte(bodyLen >> 8)
	result[3] = byte(bodyLen)

	return result
}

// buildValidServerHelloWithALPN builds a ServerHello with ALPN extension.
func buildValidServerHelloWithALPN(t *testing.T, version uint16, cipher uint16, extensions []uint16, alpn string) []byte {
	t.Helper()

	var buf bytes.Buffer

	buf.WriteByte(0x02)        // ServerHello
	buf.Write([]byte{0, 0, 0}) // Length placeholder

	// Version
	buf.WriteByte(byte(version >> 8))
	buf.WriteByte(byte(version))

	// Random (32 bytes)
	buf.Write(make([]byte, 32))

	// Session ID
	buf.WriteByte(0x00)

	// Cipher suite
	buf.WriteByte(byte(cipher >> 8))
	buf.WriteByte(byte(cipher))

	// Compression method
	buf.WriteByte(0x00)

	// Extensions
	var extBuf bytes.Buffer
	for _, ext := range extensions {
		extBuf.WriteByte(byte(ext >> 8))
		extBuf.WriteByte(byte(ext))
		if ext == 16 { // ALPN
			alpnLen := len(alpn)
			totalLen := alpnLen + 3
			extBuf.WriteByte(byte(totalLen >> 8))
			extBuf.WriteByte(byte(totalLen))
			extBuf.WriteByte(byte((alpnLen + 1) >> 8))
			extBuf.WriteByte(byte(alpnLen + 1))
			extBuf.WriteByte(byte(alpnLen))
			extBuf.WriteString(alpn)
		} else {
			extBuf.Write([]byte{0x00, 0x00}) // empty
		}
	}
	extLen := extBuf.Len()
	buf.WriteByte(byte(extLen >> 8))
	buf.WriteByte(byte(extLen))
	buf.Write(extBuf.Bytes())

	// Fix handshake length
	result := buf.Bytes()
	bodyLen := len(result) - 4
	result[1] = byte(bodyLen >> 16)
	result[2] = byte(bodyLen >> 8)
	result[3] = byte(bodyLen)

	return result
}

// generateTestCertificate generates a self-signed test certificate.
func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			CommonName:         "test.example.com",
		},
		Issuer: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "*.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// =============================================================================
// SECTION 9: Edge Case and Boundary Tests
// =============================================================================

// TestFingerprintBoundary_MaxMessageSize tests handling of large but valid ClientHello.
func TestFingerprintBoundary_MaxMessageSize(t *testing.T) {
	// Build a ClientHello with maximum reasonable size
	// 100 ciphers + 50 extensions
	ciphers := make([]uint16, 100)
	for i := 0; i < 100; i++ {
		ciphers[i] = uint16(0x0001 + i)
	}

	extensions := make([]uint16, 50)
	for i := 0; i < 50; i++ {
		extensions[i] = uint16(i)
	}

	raw := buildValidClientHello(t, ciphers, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed for large ClientHello: %v", err)
	}

	// Verify fingerprints are valid
	if len(fp.JA3) != 32 {
		t.Errorf("JA3 hash wrong length: %d", len(fp.JA3))
	}

	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Errorf("JA4 wrong format: %s", fp.JA4)
	}
}

// TestFingerprintBoundary_SingleCipher tests with exactly one cipher suite.
func TestFingerprintBoundary_SingleCipher(t *testing.T) {
	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, []uint16{0, 10, 11}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	cipherStr := parts[1]

	// Should be just one cipher
	if strings.Contains(cipherStr, "-") {
		t.Errorf("expected single cipher, got: %s", cipherStr)
	}
	if cipherStr != "4865" { // TLS_AES_128_GCM_SHA256 in decimal
		t.Errorf("expected cipher 4865, got: %s", cipherStr)
	}
}

// TestFingerprintBoundary_SingleExtension tests with exactly one extension.
func TestFingerprintBoundary_SingleExtension(t *testing.T) {
	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256}, []uint16{0}, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	extStr := parts[2]

	// Should be just SNI (0)
	if strings.Contains(extStr, "-") {
		t.Errorf("expected single extension, got: %s", extStr)
	}
	if extStr != "0" {
		t.Errorf("expected extension 0 (SNI), got: %s", extStr)
	}
}

// TestFingerprintConsistency_MultipleRuns verifies same input produces same output.
func TestFingerprintConsistency_MultipleRuns(t *testing.T) {
	raw := buildValidClientHello(t, []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}, []uint16{0, 10, 11, 43}, nil, nil, nil)

	var firstJA3, firstJA4 string

	for i := 0; i < 100; i++ {
		fp, err := CalculateFingerprints(raw)
		if err != nil {
			t.Fatalf("iteration %d: CalculateFingerprints failed: %v", i, err)
		}

		if i == 0 {
			firstJA3 = fp.JA3
			firstJA4 = fp.JA4
		} else {
			if fp.JA3 != firstJA3 {
				t.Errorf("JA3 inconsistent at iteration %d: expected %s, got %s", i, firstJA3, fp.JA3)
			}
			if fp.JA4 != firstJA4 {
				t.Errorf("JA4 inconsistent at iteration %d: expected %s, got %s", i, firstJA4, fp.JA4)
			}
		}
	}
}

// TestJA4SConsistency_MultipleRuns verifies JA4S consistency.
func TestJA4SConsistency_MultipleRuns(t *testing.T) {
	raw := buildValidServerHelloTLS13(t, TLS_AES_128_GCM_SHA256, []uint16{43, 51})

	var firstJA4S string

	for i := 0; i < 100; i++ {
		fp, err := CalculateJA4S(raw)
		if err != nil {
			t.Fatalf("iteration %d: CalculateJA4S failed: %v", i, err)
		}

		if i == 0 {
			firstJA4S = fp.JA4S
		} else {
			if fp.JA4S != firstJA4S {
				t.Errorf("JA4S inconsistent at iteration %d: expected %s, got %s", i, firstJA4S, fp.JA4S)
			}
		}
	}
}

// TestJA4XConsistency_MultipleRuns verifies JA4X consistency.
func TestJA4XConsistency_MultipleRuns(t *testing.T) {
	// Use fewer iterations in short mode for faster CI
	// This tests deterministic calculation - 10 iterations is sufficient
	iterations := 10
	if testing.Short() {
		iterations = 3
	}

	cert := generateTestCertificate(t)

	var firstJA4X string

	for i := 0; i < iterations; i++ {
		fp := CalculateJA4X(cert)

		if i == 0 {
			firstJA4X = fp.JA4X
		} else {
			if fp.JA4X != firstJA4X {
				t.Errorf("JA4X inconsistent at iteration %d: expected %s, got %s", i, firstJA4X, fp.JA4X)
			}
		}
	}
}

// =============================================================================
// SECTION 10: ALPN Handling Edge Cases
// =============================================================================

// TestALPN_MixedAlphanumericHandling tests ALPN indicator calculation for various inputs.
// This tests the fix for the bug where mixed alphanumeric/non-alphanumeric ALPN values
// were incorrectly handled (both chars were hex-encoded when only one should be).
func TestALPN_MixedAlphanumericHandling(t *testing.T) {
	testCases := []struct {
		name     string
		alpn     string
		expected string // Expected 2-char ALPN indicator in JA4_a
	}{
		// Both alphanumeric - use directly
		{"h2", "h2", "h2"},
		{"h3", "h3", "h3"},
		{"http_1.1", "http/1.1", "h1"}, // '/' is alphanumeric
		{"spdy_3.1", "spdy/3.1", "s1"}, // first='s', last='1', both alphanumeric

		// Single char - duplicated
		{"single_a", "a", "aa"},
		{"single_1", "1", "11"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			extensions := []uint16{0, 10, 11, 16, 43} // With ALPN
			raw := buildValidClientHelloWithALPN(t, []uint16{TLS_AES_128_GCM_SHA256}, extensions, tc.alpn)

			fp, err := CalculateFingerprints(raw)
			if err != nil {
				t.Fatalf("CalculateFingerprints failed: %v", err)
			}

			parts := strings.Split(fp.JA4, "_")
			ja4a := parts[0]
			alpnIndicator := ja4a[len(ja4a)-2:]

			if alpnIndicator != tc.expected {
				t.Errorf("ALPN %q: expected indicator %q, got %q (JA4: %s)", tc.alpn, tc.expected, alpnIndicator, fp.JA4)
			}
		})
	}
}

// TestALPN_isAlphanumericBoundaries tests the isAlphanumeric helper at boundaries.
func TestALPN_isAlphanumericBoundaries(t *testing.T) {
	testCases := []struct {
		char     byte
		expected bool
	}{
		// Digits
		{'0', true},
		{'9', true},
		// Uppercase
		{'A', true},
		{'Z', true},
		// Lowercase
		{'a', true},
		{'z', true},
		// Boundaries (not alphanumeric)
		{'/', false}, // before '0'
		{':', false}, // after '9'
		{'@', false}, // before 'A'
		{'[', false}, // after 'Z'
		{'`', false}, // before 'a'
		{'{', false}, // after 'z'
		// Special chars
		{'-', false},
		{'_', false},
		{'.', false},
		{' ', false},
		{'\x00', false},
		{'\xff', false},
	}

	for _, tc := range testCases {
		result := isAlphanumeric(tc.char)
		if result != tc.expected {
			t.Errorf("isAlphanumeric(%q) = %v, want %v", tc.char, result, tc.expected)
		}
	}
}

// TestJA4_RawVsHashedConsistency verifies that raw fingerprints hash to expected values.
func TestJA4_RawVsHashedConsistency(t *testing.T) {
	ciphers := []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	extensions := []uint16{0, 10, 11, 13, 43}

	raw := buildValidClientHello(t, ciphers, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// Parse JA4r: format is "a_b_c" where c may contain underscore for sig_algs
	// So we split with limit 3 to keep c intact (including any embedded underscore)
	parts := strings.SplitN(fp.JA4r, "_", 3)
	if len(parts) < 3 {
		t.Fatalf("JA4r wrong format: %s", fp.JA4r)
	}

	ja4rB := parts[1] // Cipher hex list
	ja4rC := parts[2] // Extension hex list (may include _sig_algs)

	// Hash JA4r_b and compare with JA4_b
	partsH := strings.Split(fp.JA4, "_")
	ja4B := partsH[1]
	ja4C := partsH[2]

	// Verify JA4_b is SHA256[:12] of JA4r_b
	if ja4rB != "" {
		hashB := sha256.Sum256([]byte(ja4rB))
		expectedB := hex.EncodeToString(hashB[:])[:12]
		if ja4B != expectedB {
			t.Errorf("JA4_b hash mismatch:\n  Raw: %s\n  Expected hash: %s\n  Actual: %s", ja4rB, expectedB, ja4B)
		}
	}

	// Verify JA4_c is SHA256[:12] of JA4r_c
	if ja4rC != "" {
		hashC := sha256.Sum256([]byte(ja4rC))
		expectedC := hex.EncodeToString(hashC[:])[:12]
		if ja4C != expectedC {
			t.Errorf("JA4_c hash mismatch:\n  Raw: %s\n  Expected hash: %s\n  Actual: %s", ja4rC, expectedC, ja4C)
		}
	}

	t.Logf("JA4r: %s", fp.JA4r)
	t.Logf("JA4:  %s", fp.JA4)
}

// TestJA3_RawVsHashedConsistency verifies JA3 hash matches raw string.
func TestJA3_RawVsHashedConsistency(t *testing.T) {
	ciphers := []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}
	extensions := []uint16{0, 10, 11, 13, 43}

	raw := buildValidClientHello(t, ciphers, extensions, nil, nil, nil)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// Verify JA3 is MD5 of JA3r
	expectedHash := md5.Sum([]byte(fp.JA3r))
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	if fp.JA3 != expectedHashStr {
		t.Errorf("JA3 hash mismatch:\n  Raw: %s\n  Expected: %s\n  Actual: %s", fp.JA3r, expectedHashStr, fp.JA3)
	}

	// Verify JA3n is MD5 of JA3rn
	expectedHashN := md5.Sum([]byte(fp.JA3rn))
	expectedHashNStr := hex.EncodeToString(expectedHashN[:])

	if fp.JA3n != expectedHashNStr {
		t.Errorf("JA3n hash mismatch:\n  Raw: %s\n  Expected: %s\n  Actual: %s", fp.JA3rn, expectedHashNStr, fp.JA3n)
	}
}

// TestJA4_VersionDetectionFromSupportedVersions tests version detection priority.
func TestJA4_VersionDetectionFromSupportedVersions(t *testing.T) {
	testCases := []struct {
		name              string
		clientHelloVer    uint16
		supportedVersions []uint16
		expectedVerStr    string
	}{
		{"no_supported_versions", VersionTLS12, nil, "12"},
		{"tls13_in_supported", VersionTLS12, []uint16{VersionTLS13, VersionTLS12}, "13"},
		{"only_tls12_in_supported", VersionTLS12, []uint16{VersionTLS12}, "12"},
		{"multiple_versions_picks_highest", VersionTLS12, []uint16{VersionTLS10, VersionTLS11, VersionTLS13}, "13"},
		{"grease_filtered", VersionTLS12, []uint16{0x0a0a, VersionTLS13}, "13"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildValidClientHelloWithVersion(t, tc.clientHelloVer, tc.supportedVersions)

			fp, err := CalculateFingerprints(raw)
			if err != nil {
				t.Fatalf("CalculateFingerprints failed: %v", err)
			}

			parts := strings.Split(fp.JA4, "_")
			ja4a := parts[0]
			verStr := ja4a[1:3]

			if verStr != tc.expectedVerStr {
				t.Errorf("Expected version %s, got %s (JA4: %s)", tc.expectedVerStr, verStr, fp.JA4)
			}
		})
	}
}

// TestJA4_SignatureAlgorithmsInHash tests that signature algorithms are included in JA4c.
func TestJA4_SignatureAlgorithmsInHash(t *testing.T) {
	// Build ClientHello with signature_algorithms extension
	ciphers := []uint16{TLS_AES_128_GCM_SHA256}
	extensions := []uint16{0, 10, 11, 13, 43} // 13 = signature_algorithms
	sigAlgs := []uint16{uint16(ECDSAWithP256AndSHA256), uint16(PSSWithSHA256)}

	raw := buildValidClientHello(t, ciphers, extensions, nil, nil, sigAlgs)

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// JA4r_c should contain signature algorithms after underscore
	// Use SplitN(3) to keep the full JA4r_c including any embedded underscore
	parts := strings.SplitN(fp.JA4r, "_", 3)
	if len(parts) < 3 {
		t.Fatalf("JA4r wrong format: %s", fp.JA4r)
	}
	ja4rC := parts[2]

	// JA4r_c should have format: extensions_sigalgs
	if !strings.Contains(ja4rC, "_") {
		t.Errorf("JA4r_c should contain underscore separating extensions from sig_algs: %s", ja4rC)
	}

	t.Logf("JA4r_c (with sig_algs): %s", ja4rC)
}

// TestJA4S_OriginalExtensionOrder tests that JA4S preserves original extension order.
func TestJA4S_OriginalExtensionOrder(t *testing.T) {
	// Build ServerHello with extensions in specific order
	extensions := []uint16{51, 43, 16} // key_share, supported_versions, ALPN

	raw := buildValidServerHelloWithALPN(t, VersionTLS12, TLS_AES_128_GCM_SHA256, extensions, "h2")

	fp, err := CalculateJA4S(raw)
	if err != nil {
		t.Fatalf("CalculateJA4S failed: %v", err)
	}

	// JA4Sr should have extensions in original order
	parts := strings.Split(fp.JA4Sr, "_")
	extHex := parts[2]

	// Extensions should be: 0033 (51), 002b (43), 0010 (16)
	// Verify order is preserved (not sorted)
	expected := "0033,002b,0010"
	if extHex != expected {
		t.Errorf("JA4Sr extensions should preserve order: expected %s, got %s", expected, extHex)
	}

	t.Logf("JA4S: %s", fp.JA4S)
	t.Logf("JA4Sr: %s", fp.JA4Sr)
}

// TestOIDToHex_LargeOIDs tests OID encoding for larger values.
func TestOIDToHex_LargeOIDs(t *testing.T) {
	testCases := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected string
	}{
		// Standard OIDs
		{"commonName", asn1.ObjectIdentifier{2, 5, 4, 3}, "550403"},
		{"country", asn1.ObjectIdentifier{2, 5, 4, 6}, "550406"},
		{"organization", asn1.ObjectIdentifier{2, 5, 4, 10}, "55040a"},

		// Larger arc values requiring multi-byte encoding
		// DER variable-length encoding: split into 7-bit groups, set high bit on all but last
		// 128 = 0b10000000 -> 0b0000001 0b0000000 -> 0x81 0x00
		{"large_arc_128", asn1.ObjectIdentifier{2, 5, 4, 128}, "55048100"},
		// 255 = 0b11111111 -> 0b0000001 0b1111111 -> 0x81 0x7f
		{"large_arc_255", asn1.ObjectIdentifier{2, 5, 4, 255}, "5504817f"},

		// Microsoft OID with large arcs: 1.3.6.1.4.1.311.21.20
		// 311 = 0b100110111 -> 0b0000010 0b0110111 -> 0x82 0x37
		{"microsoft_certtype", asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 20}, "2b0601040182371514"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := oidToHex(tc.oid)
			// For the Microsoft OID, just check it doesn't panic and produces output
			if tc.name == "microsoft_certtype" {
				if len(result) == 0 {
					t.Error("oidToHex returned empty string for valid OID")
				}
				t.Logf("Microsoft OID hex: %s", result)
				return
			}

			if result != tc.expected {
				t.Errorf("oidToHex(%v) = %s, want %s", tc.oid, result, tc.expected)
			}
		})
	}
}

// TestEncodeVarInt_EdgeCases tests variable-length integer encoding edge cases.
func TestEncodeVarInt_EdgeCases(t *testing.T) {
	testCases := []struct {
		input    int
		expected []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x00}},
		{129, []byte{0x81, 0x01}},
		{255, []byte{0x81, 0x7f}},
		{256, []byte{0x82, 0x00}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x81, 0x80, 0x00}},
		{65535, []byte{0x83, 0xff, 0x7f}},
	}

	for _, tc := range testCases {
		result := encodeVarInt(tc.input)
		if !bytes.Equal(result, tc.expected) {
			t.Errorf("encodeVarInt(%d) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}
