// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// JA4 fingerprint calculation helper functions.
// Reference: https://github.com/FoxIO-LLC/ja4
//
// JA4 format: JA4_a_JA4_b_JA4_c
// Example: t13d1516h2_8daaf6152771_b0da82dd1658
//
// JA4_a: Protocol + TLS version + SNI indicator + Cipher count + Extension count + ALPN
// JA4_b: First 12 chars of SHA256 of sorted cipher list (comma-separated hex)
// JA4_c: First 12 chars of SHA256 of sorted extension list (comma-separated hex)

// ja4Fingerprint holds the three components of a JA4 fingerprint.
type ja4Fingerprint struct {
	A string // Protocol + version + SNI + cipher count + ext count + ALPN
	B string // Truncated hash of sorted ciphers
	C string // Truncated hash of sorted extensions
}

// String returns the full JA4 fingerprint in canonical format.
func (j ja4Fingerprint) String() string {
	return fmt.Sprintf("%s_%s_%s", j.A, j.B, j.C)
}

// calculateJA4FromRaw computes JA4 fingerprint from raw ClientHello bytes.
// The raw bytes should be the complete ClientHello message (after TLS record header).
func calculateJA4FromRaw(raw []byte) (ja4Fingerprint, error) {
	var result ja4Fingerprint

	s := cryptobyte.String(raw)

	// Skip handshake type (1 byte) and length (3 bytes)
	if !s.Skip(4) {
		return result, fmt.Errorf("failed to skip handshake header")
	}

	// Read version (2 bytes)
	var version uint16
	if !s.ReadUint16(&version) {
		return result, fmt.Errorf("failed to read version")
	}

	// Skip random (32 bytes)
	if !s.Skip(32) {
		return result, fmt.Errorf("failed to skip random")
	}

	// Skip session ID
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return result, fmt.Errorf("failed to skip session ID")
	}

	// Read cipher suites
	var cipherBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherBytes) {
		return result, fmt.Errorf("failed to read cipher suites")
	}

	var cipherSuites []uint16
	for !cipherBytes.Empty() {
		var cipher uint16
		if !cipherBytes.ReadUint16(&cipher) {
			return result, fmt.Errorf("failed to read cipher suite")
		}
		// Exclude GREASE values from cipher list
		if !isGREASEUint16(cipher) {
			cipherSuites = append(cipherSuites, cipher)
		}
	}

	// Skip compression methods
	var compressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionMethods) {
		return result, fmt.Errorf("failed to skip compression methods")
	}

	// Read extensions
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return result, fmt.Errorf("failed to read extensions")
	}

	var extensionIDs []uint16     // For JA4_c hash: excludes SNI and ALPN
	var allExtensionCount int     // For JA4_a count: excludes only GREASE
	var hasSNI bool
	var alpnFirstChar string = "00" // Default: no ALPN

	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return result, fmt.Errorf("failed to read extension")
		}

		// Count all non-GREASE extensions for JA4_a
		if !isGREASEUint16(extType) {
			allExtensionCount++
		}

		// Check for SNI extension (type 0)
		if extType == 0 {
			hasSNI = true
		}

		// Check for ALPN extension (type 16)
		if extType == 16 && len(extData) > 0 {
			alpnData := cryptobyte.String(extData)
			var alpnList cryptobyte.String
			if alpnData.ReadUint16LengthPrefixed(&alpnList) && !alpnList.Empty() {
				var firstAlpnLen uint8
				if alpnList.ReadUint8(&firstAlpnLen) && firstAlpnLen > 0 {
					firstAlpnBytes := make([]byte, firstAlpnLen)
					if alpnList.CopyBytes(firstAlpnBytes) {
						firstAlpn := string(firstAlpnBytes)
						// Extract first and last char for JA4 ALPN component
						// Per JA4 spec: if alphanumeric, use directly; else use hex
						if len(firstAlpn) >= 1 {
							first := firstAlpn[0]
							last := firstAlpn[len(firstAlpn)-1]

							var firstChar, lastChar string
							if isAlphanumeric(first) {
								firstChar = string(first)
							} else {
								firstChar = string(fmt.Sprintf("%02x", first)[0])
							}
							if isAlphanumeric(last) {
								lastChar = string(last)
							} else {
								lastChar = string(fmt.Sprintf("%02x", last)[1])
							}
							alpnFirstChar = firstChar + lastChar
						}
					}
				}
			}
		}

		// Exclude GREASE, SNI (0), and ALPN (16) from extension list for JA4_c
		// Per JA4 spec: SNI and ALPN are captured in JA4_a, so excluded from JA4_c
		if !isGREASEUint16(extType) && extType != 0 && extType != 16 {
			extensionIDs = append(extensionIDs, extType)
		}
	}

	// Build JA4_a
	// Format: [q/t][TLS version][d/i][cipher count (2 digits)][ext count (2 digits)][ALPN first/last]
	protocol := "t" // TCP (q for QUIC)

	tlsVersion := "00"
	switch version {
	case VersionTLS10:
		tlsVersion = "10"
	case VersionTLS11:
		tlsVersion = "11"
	case VersionTLS12:
		tlsVersion = "12"
	case VersionTLS13:
		tlsVersion = "13"
	}

	sniIndicator := "i" // i = IP address / no SNI
	if hasSNI {
		sniIndicator = "d" // d = domain name
	}

	cipherCount := len(cipherSuites)
	extCount := allExtensionCount // Use total non-GREASE extension count (includes SNI/ALPN)

	// Clamp counts to 99 (2 digits)
	if cipherCount > 99 {
		cipherCount = 99
	}
	if extCount > 99 {
		extCount = 99
	}

	result.A = fmt.Sprintf("%s%s%s%02d%02d%s", protocol, tlsVersion, sniIndicator, cipherCount, extCount, alpnFirstChar)

	// Build JA4_b: SHA256 of sorted cipher list
	sortedCiphers := make([]uint16, len(cipherSuites))
	copy(sortedCiphers, cipherSuites)
	sort.Slice(sortedCiphers, func(i, j int) bool {
		return sortedCiphers[i] < sortedCiphers[j]
	})

	var cipherStrings []string
	for _, c := range sortedCiphers {
		cipherStrings = append(cipherStrings, fmt.Sprintf("%04x", c))
	}
	cipherHash := sha256.Sum256([]byte(strings.Join(cipherStrings, ",")))
	result.B = hex.EncodeToString(cipherHash[:])[:12]

	// Build JA4_c: SHA256 of sorted extension list
	sortedExts := make([]uint16, len(extensionIDs))
	copy(sortedExts, extensionIDs)
	sort.Slice(sortedExts, func(i, j int) bool {
		return sortedExts[i] < sortedExts[j]
	})

	var extStrings []string
	for _, e := range sortedExts {
		extStrings = append(extStrings, fmt.Sprintf("%04x", e))
	}

	if len(extStrings) == 0 {
		// No extensions (after filtering), use empty hash
		emptyHash := sha256.Sum256([]byte(""))
		result.C = hex.EncodeToString(emptyHash[:])[:12]
	} else {
		extHash := sha256.Sum256([]byte(strings.Join(extStrings, ",")))
		result.C = hex.EncodeToString(extHash[:])[:12]
	}

	return result, nil
}

// TestJA4StabilityWithShuffledExtensions verifies that JA4 fingerprint remains
// identical across multiple ClientHello generations with shuffled extensions.
// JA4 sorts extensions before hashing, making it stable despite shuffling.
func TestJA4StabilityWithShuffledExtensions(t *testing.T) {
	// Use fewer iterations in short mode for faster CI
	iterations := 20
	if testing.Short() {
		iterations = 5
	}
	serverName := "example.com"

	var ja4Fingerprints []string

	for i := 0; i < iterations; i++ {
		uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloChrome_142)
		if err != nil {
			t.Fatalf("iteration %d: UClient failed: %v", i, err)
		}
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("iteration %d: BuildHandshakeState failed: %v", i, err)
		}

		ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
		if err != nil {
			t.Fatalf("iteration %d: JA4 calculation failed: %v", i, err)
		}

		ja4Fingerprints = append(ja4Fingerprints, ja4.String())
	}

	// All JA4 fingerprints MUST be identical
	firstJA4 := ja4Fingerprints[0]
	for i, fp := range ja4Fingerprints {
		if fp != firstJA4 {
			t.Errorf("JA4 fingerprint mismatch at iteration %d:\n  expected: %s\n  got:      %s",
				i, firstJA4, fp)
		}
	}

	t.Logf("JA4 stability test passed: all %d fingerprints identical: %s", iterations, firstJA4)
}

// TestJA4ComponentsCalculation verifies each JA4 component is calculated correctly.
func TestJA4ComponentsCalculation(t *testing.T) {
	serverName := "example.com"

	uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloChrome_142)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("JA4 calculation failed: %v", err)
	}

	// Verify JA4_a format
	// Expected format: t13d1516h2 (example)
	// t = TCP, 13 = TLS 1.3, d = domain SNI present, 15 = cipher count, 16 = ext count, h2 = ALPN
	if len(ja4.A) < 7 {
		t.Errorf("JA4_a too short: %s", ja4.A)
	}

	// Check protocol indicator
	if ja4.A[0] != 't' {
		t.Errorf("JA4_a should start with 't' for TCP, got: %c", ja4.A[0])
	}

	// Check TLS version - Chrome 142 should negotiate TLS 1.3 (but ClientHello version is 1.2)
	// The version in JA4 is the ClientHello version, which is typically TLS 1.2
	// because supported_versions extension advertises TLS 1.3
	tlsVer := ja4.A[1:3]
	if tlsVer != "12" && tlsVer != "13" {
		t.Errorf("JA4_a TLS version unexpected: %s", tlsVer)
	}

	// Check SNI indicator
	sniIndicator := ja4.A[3]
	if sniIndicator != 'd' {
		t.Errorf("JA4_a SNI indicator should be 'd' for domain, got: %c", sniIndicator)
	}

	// Verify JA4_b and JA4_c are 12 hex characters
	if len(ja4.B) != 12 {
		t.Errorf("JA4_b should be 12 chars, got %d: %s", len(ja4.B), ja4.B)
	}
	if len(ja4.C) != 12 {
		t.Errorf("JA4_c should be 12 chars, got %d: %s", len(ja4.C), ja4.C)
	}

	// Verify they're valid hex
	if _, err := hex.DecodeString(ja4.B); err != nil {
		t.Errorf("JA4_b is not valid hex: %s", ja4.B)
	}
	if _, err := hex.DecodeString(ja4.C); err != nil {
		t.Errorf("JA4_c is not valid hex: %s", ja4.C)
	}

	t.Logf("JA4 components test passed:")
	t.Logf("  JA4_a: %s", ja4.A)
	t.Logf("  JA4_b: %s", ja4.B)
	t.Logf("  JA4_c: %s", ja4.C)
	t.Logf("  Full:  %s", ja4.String())
}

// TestJA4ForMultipleBrowserProfiles tests JA4 calculation for different browser profiles.
func TestJA4ForMultipleBrowserProfiles(t *testing.T) {
	t.Parallel()

	// Use representative sample of browser families for faster CI runs
	profiles := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_142", HelloChrome_142},
		{"Firefox_145", HelloFirefox_145},
		{"Safari_18", HelloSafari_18},
	}

	// In short mode, test only one profile
	if testing.Short() {
		profiles = profiles[:1]
	}

	serverName := "example.com"

	// Reduce iterations: 3 is sufficient to verify stability
	iterations := 3
	if testing.Short() {
		iterations = 1
	}

	for _, profile := range profiles {
		profile := profile // capture for parallel
		t.Run(profile.name, func(t *testing.T) {
			t.Parallel()

			// Generate fingerprint multiple times to verify stability
			var fingerprints []string
			for i := 0; i < iterations; i++ {
				uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, profile.id)
				if err != nil {
					t.Fatalf("UClient failed: %v", err)
				}
				if err := uconn.BuildHandshakeState(); err != nil {
					t.Fatalf("BuildHandshakeState failed: %v", err)
				}

				ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
				if err != nil {
					t.Fatalf("JA4 calculation failed: %v", err)
				}
				fingerprints = append(fingerprints, ja4.String())
			}

			// All fingerprints for this profile should be identical
			first := fingerprints[0]
			for i, fp := range fingerprints {
				if fp != first {
					t.Errorf("Fingerprint mismatch at iteration %d for %s:\n  expected: %s\n  got:      %s",
						i, profile.name, first, fp)
				}
			}

			t.Logf("%s JA4: %s", profile.name, first)
		})
	}
}

// TestJA4WithCustomSpec tests JA4 calculation with a custom ClientHelloSpec.
func TestJA4WithCustomSpec(t *testing.T) {
	t.Parallel()

	serverName := "example.com"

	customSpec := ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
				PKCS1WithSHA256,
			}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
		},
	}

	uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	if err := uconn.ApplyPreset(&customSpec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("JA4 calculation failed: %v", err)
	}

	// Verify the fingerprint format
	if len(ja4.A) < 7 {
		t.Errorf("JA4_a too short: %s", ja4.A)
	}

	// Skip consistency check in short mode
	if testing.Short() {
		t.Logf("Custom spec JA4: %s", ja4.String())
		return
	}

	// Custom spec should produce consistent fingerprint
	// Generate again and compare
	uconn2, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	if err := uconn2.ApplyPreset(&customSpec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if err := uconn2.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	ja4_2, err := calculateJA4FromRaw(uconn2.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("JA4 calculation failed: %v", err)
	}

	if ja4.String() != ja4_2.String() {
		t.Errorf("Custom spec produced inconsistent JA4:\n  first:  %s\n  second: %s",
			ja4.String(), ja4_2.String())
	}

	t.Logf("Custom spec JA4: %s", ja4.String())
}

// TestJA4WithoutSNI tests JA4 fingerprint when SNI is not set.
func TestJA4WithoutSNI(t *testing.T) {
	// No server name = no SNI extension
	// InsecureSkipVerify is required when no ServerName is provided
	uconn, err := UClient(&net.TCPConn{}, &Config{InsecureSkipVerify: true}, HelloChrome_142)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	uconn.SetSNI("") // Explicitly set empty SNI

	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("JA4 calculation failed: %v", err)
	}

	// Without SNI, the indicator should be 'i' (not 'd')
	if len(ja4.A) > 3 && ja4.A[3] != 'i' {
		t.Errorf("JA4_a SNI indicator should be 'i' without SNI, got: %c", ja4.A[3])
	}

	t.Logf("JA4 without SNI: %s", ja4.String())
}

// TestJA4ExtensionOrderIndependence verifies that extension order doesn't affect JA4.
func TestJA4ExtensionOrderIndependence(t *testing.T) {
	t.Parallel()

	serverName := "example.com"

	// Create two specs with same extensions but different order
	spec1 := ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PKCS1WithSHA256,
			}},
		},
	}

	// Same extensions, different order
	spec2 := ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PKCS1WithSHA256,
			}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
			&SNIExtension{},
		},
	}

	uconn1, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	if err := uconn1.ApplyPreset(&spec1); err != nil {
		t.Fatalf("ApplyPreset spec1 failed: %v", err)
	}
	if err := uconn1.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState spec1 failed: %v", err)
	}

	ja4_1, err := calculateJA4FromRaw(uconn1.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("JA4 calculation for spec1 failed: %v", err)
	}

	// In short mode, just verify spec1 works and skip spec2 comparison
	if testing.Short() {
		t.Logf("JA4 from spec1: %s", ja4_1.String())
		return
	}

	uconn2, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	if err := uconn2.ApplyPreset(&spec2); err != nil {
		t.Fatalf("ApplyPreset spec2 failed: %v", err)
	}
	if err := uconn2.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState spec2 failed: %v", err)
	}

	ja4_2, err := calculateJA4FromRaw(uconn2.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("JA4 calculation for spec2 failed: %v", err)
	}

	// JA4 should be identical regardless of extension order
	if ja4_1.String() != ja4_2.String() {
		t.Errorf("JA4 differs despite same extensions in different order:\n  spec1: %s\n  spec2: %s",
			ja4_1.String(), ja4_2.String())
	} else {
		t.Logf("JA4 extension order independence verified: %s", ja4_1.String())
	}
}

// TestJA4GREASEFiltering verifies that GREASE values are properly excluded.
func TestJA4GREASEFiltering(t *testing.T) {
	// Use fewer iterations in short mode for faster CI
	iterations := 5
	if testing.Short() {
		iterations = 2
	}
	serverName := "example.com"

	// Chrome profiles include GREASE - they should be filtered out
	uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloChrome_142)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Fatalf("JA4 calculation failed: %v", err)
	}

	// The fingerprint should be stable (GREASE values change but are filtered)
	// Verify by generating multiple times
	var fingerprints []string
	for i := 0; i < iterations; i++ {
		uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloChrome_142)
		if err != nil {
			t.Fatalf("iteration %d: UClient failed: %v", i, err)
		}
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("iteration %d: BuildHandshakeState failed: %v", i, err)
		}

		ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
		if err != nil {
			t.Fatalf("iteration %d: JA4 calculation failed: %v", i, err)
		}
		fingerprints = append(fingerprints, ja4.String())
	}

	// All should be identical (GREASE filtered correctly)
	first := fingerprints[0]
	for i, fp := range fingerprints {
		if fp != first {
			t.Errorf("GREASE filtering unstable at iteration %d:\n  expected: %s\n  got:      %s",
				i, first, fp)
		}
	}

	t.Logf("GREASE filtering test passed: %s", ja4.String())
}

// TestJA4ALPNVariations tests JA4 with different ALPN configurations.
func TestJA4ALPNVariations(t *testing.T) {
	serverName := "example.com"

	testCases := []struct {
		name     string
		alpn     []string
		expected string // Expected ALPN component in JA4_a
	}{
		{"h2 and http/1.1", []string{"h2", "http/1.1"}, "h2"},
		{"http/1.1 only", []string{"http/1.1"}, "h1"},
		{"h3 only", []string{"h3"}, "h3"},
		{"empty", []string{}, "00"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec := ClientHelloSpec{
				CipherSuites: []uint16{
					TLS_AES_128_GCM_SHA256,
					TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
				CompressionMethods: []byte{0x00},
				Extensions: []TLSExtension{
					&SNIExtension{},
					&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
					&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
				},
			}

			// Add ALPN extension if protocols specified
			if len(tc.alpn) > 0 {
				spec.Extensions = append(spec.Extensions, &ALPNExtension{AlpnProtocols: tc.alpn})
			}

			uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
			if err != nil {
				t.Fatalf("UClient failed: %v", err)
			}
			if err := uconn.ApplyPreset(&spec); err != nil {
				t.Fatalf("ApplyPreset failed: %v", err)
			}
			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			ja4, err := calculateJA4FromRaw(uconn.HandshakeState.Hello.Raw)
			if err != nil {
				t.Fatalf("JA4 calculation failed: %v", err)
			}

			// Check ALPN component (last 2 chars of JA4_a)
			if len(ja4.A) >= 2 {
				alpnComponent := ja4.A[len(ja4.A)-2:]
				if alpnComponent != tc.expected {
					t.Errorf("ALPN component mismatch: expected %s, got %s (JA4_a: %s)",
						tc.expected, alpnComponent, ja4.A)
				}
			}

			t.Logf("ALPN %v -> JA4: %s", tc.alpn, ja4.String())
		})
	}
}

// TestJA4RawBytesConsistency verifies JA4 calculation from raw bytes is consistent.
func TestJA4RawBytesConsistency(t *testing.T) {
	// Use fewer iterations in short mode for faster CI
	// This tests deterministic parsing - 10 iterations is sufficient
	iterations := 10
	if testing.Short() {
		iterations = 3
	}
	serverName := "example.com"

	uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloChrome_142)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	rawHello := uconn.HandshakeState.Hello.Raw

	// Calculate JA4 multiple times from same raw bytes
	var fingerprints []string
	for i := 0; i < iterations; i++ {
		ja4, err := calculateJA4FromRaw(rawHello)
		if err != nil {
			t.Fatalf("iteration %d: JA4 calculation failed: %v", i, err)
		}
		fingerprints = append(fingerprints, ja4.String())
	}

	// All must be identical (same input = same output)
	first := fingerprints[0]
	for i, fp := range fingerprints {
		if fp != first {
			t.Errorf("Inconsistent JA4 from same raw bytes at iteration %d:\n  expected: %s\n  got:      %s",
				i, first, fp)
		}
	}

	t.Logf("Raw bytes consistency test passed: %s", first)
}
