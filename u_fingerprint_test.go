// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"net"
	"strings"
	"testing"
)

// TestJA3Calculation verifies JA3 fingerprint format and stability.
func TestJA3Calculation(t *testing.T) {
	profiles := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_142", HelloChrome_142},
		{"Chrome_120", HelloChrome_120},
		{"Firefox_145", HelloFirefox_145},
		{"Firefox_120", HelloFirefox_120},
		{"Safari_18", HelloSafari_18},
		{"Edge_142", HelloEdge_142},
	}

	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, profile.id)
			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			fp, err := uconn.Fingerprint()
			if err != nil {
				t.Fatalf("Fingerprint failed: %v", err)
			}

			// JA3 hash must be 32 hex chars (MD5)
			if len(fp.JA3) != 32 {
				t.Errorf("JA3 hash wrong length: got %d, want 32", len(fp.JA3))
			}

			// JA3r must have 5 comma-separated fields
			parts := strings.Split(fp.JA3r, ",")
			if len(parts) != 5 {
				t.Errorf("JA3r wrong format: got %d parts, want 5", len(parts))
			}

			// Version must be numeric
			if parts[0] == "" {
				t.Error("JA3r version field is empty")
			}

			// JA3n hash must be 32 hex chars
			if len(fp.JA3n) != 32 {
				t.Errorf("JA3n hash wrong length: got %d, want 32", len(fp.JA3n))
			}

			// JA3rn must have 5 comma-separated fields
			partsN := strings.Split(fp.JA3rn, ",")
			if len(partsN) != 5 {
				t.Errorf("JA3rn wrong format: got %d parts, want 5", len(partsN))
			}

			t.Logf("%s JA3:   %s", profile.name, fp.JA3)
			t.Logf("%s JA3_r: %s", profile.name, fp.JA3r)
			t.Logf("%s JA3_n: %s", profile.name, fp.JA3n)
			t.Logf("%s JA3_rn:%s", profile.name, fp.JA3rn)
		})
	}
}

// TestJA4Calculation verifies JA4 fingerprint format and components.
func TestJA4Calculation(t *testing.T) {
	profiles := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_142", HelloChrome_142},
		{"Chrome_120", HelloChrome_120},
		{"Firefox_145", HelloFirefox_145},
		{"Firefox_120", HelloFirefox_120},
		{"Safari_18", HelloSafari_18},
		{"Edge_142", HelloEdge_142},
	}

	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, profile.id)
			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			fp, err := uconn.Fingerprint()
			if err != nil {
				t.Fatalf("Fingerprint failed: %v", err)
			}

			// JA4 format: JA4a_JA4b_JA4c
			parts := strings.Split(fp.JA4, "_")
			if len(parts) != 3 {
				t.Errorf("JA4 wrong format: got %d parts, want 3: %s", len(parts), fp.JA4)
			}

			ja4a := parts[0]
			ja4b := parts[1]
			ja4c := parts[2]

			// JA4a: protocol(1) + version(2) + sni(1) + ciphers(2) + exts(2) + alpn(2) = 10 chars
			if len(ja4a) != 10 {
				t.Errorf("JA4a wrong length: got %d, want 10: %s", len(ja4a), ja4a)
			}

			// Protocol must be 't' (TCP)
			if ja4a[0] != 't' {
				t.Errorf("JA4a protocol wrong: got %c, want 't'", ja4a[0])
			}

			// SNI indicator must be 'd' (domain present)
			if ja4a[3] != 'd' {
				t.Errorf("JA4a SNI indicator wrong: got %c, want 'd'", ja4a[3])
			}

			// JA4b and JA4c must be 12 hex chars
			if len(ja4b) != 12 {
				t.Errorf("JA4b wrong length: got %d, want 12", len(ja4b))
			}
			if len(ja4c) != 12 {
				t.Errorf("JA4c wrong length: got %d, want 12", len(ja4c))
			}

			t.Logf("%s JA4: %s", profile.name, fp.JA4)
		})
	}
}

// TestJA4Stability verifies fingerprint stability across multiple generations.
func TestJA4Stability(t *testing.T) {
	const iterations = 50

	profiles := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_142", HelloChrome_142},
		{"Firefox_145", HelloFirefox_145},
	}

	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			var firstJA3, firstJA4 string

			for i := 0; i < iterations; i++ {
				uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, profile.id)
				if err := uconn.BuildHandshakeState(); err != nil {
					t.Fatalf("iteration %d: BuildHandshakeState failed: %v", i, err)
				}

				fp, err := uconn.Fingerprint()
				if err != nil {
					t.Fatalf("iteration %d: Fingerprint failed: %v", i, err)
				}

				if i == 0 {
					firstJA3 = fp.JA3
					firstJA4 = fp.JA4
				} else {
					// JA4 should be stable (sorted extensions)
					if fp.JA4 != firstJA4 {
						t.Errorf("JA4 unstable at iteration %d:\n  first: %s\n  got:   %s", i, firstJA4, fp.JA4)
					}
					// Note: JA3 may vary if extension order changes (by design)
					// But for profiles without shuffling, it should be stable
				}
			}

			t.Logf("%s stability verified over %d iterations", profile.name, iterations)
			t.Logf("  JA3: %s", firstJA3)
			t.Logf("  JA4: %s", firstJA4)
		})
	}
}

// TestJA4Variants verifies all JA4 variant formats.
func TestJA4Variants(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloChrome_142)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// All variants should have same JA4a prefix
	variants := []struct {
		name  string
		value string
	}{
		{"JA4", fp.JA4},
		{"JA4r", fp.JA4r},
		{"JA4o", fp.JA4o},
		{"JA4ro", fp.JA4ro},
	}

	var ja4a string
	for _, v := range variants {
		parts := strings.Split(v.value, "_")
		if len(parts) < 3 {
			t.Errorf("%s wrong format: %s", v.name, v.value)
			continue
		}

		if ja4a == "" {
			ja4a = parts[0]
		} else if parts[0] != ja4a {
			t.Errorf("%s has different JA4a: got %s, want %s", v.name, parts[0], ja4a)
		}

		t.Logf("%s: %s", v.name, v.value)
	}

	// JA4 and JA4o should have 12-char hashed components
	for _, name := range []string{"JA4", "JA4o"} {
		var v string
		if name == "JA4" {
			v = fp.JA4
		} else {
			v = fp.JA4o
		}
		parts := strings.Split(v, "_")
		if len(parts[1]) != 12 || len(parts[2]) != 12 {
			t.Errorf("%s should have 12-char hashed components", name)
		}
	}

	// JA4r and JA4ro should have raw hex values (longer)
	for _, name := range []string{"JA4r", "JA4ro"} {
		var v string
		if name == "JA4r" {
			v = fp.JA4r
		} else {
			v = fp.JA4ro
		}
		parts := strings.Split(v, "_")
		// Raw cipher list should be longer than 12 chars
		if len(parts[1]) <= 12 {
			t.Errorf("%s should have raw (longer) cipher list: %s", name, parts[1])
		}
	}
}

// TestFingerprintWithoutSNI verifies SNI indicator when no domain is set.
func TestFingerprintWithoutSNI(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{InsecureSkipVerify: true}, HelloChrome_142)
	uconn.SetSNI("")

	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// Without SNI, indicator should be 'i'
	parts := strings.Split(fp.JA4, "_")
	ja4a := parts[0]
	if ja4a[3] != 'i' {
		t.Errorf("JA4a SNI indicator should be 'i' without SNI, got %c", ja4a[3])
	}

	t.Logf("JA4 without SNI: %s", fp.JA4)
}

// TestJA4CustomSpec verifies fingerprint calculation with custom ClientHelloSpec.
func TestJA4CustomSpec(t *testing.T) {
	spec := ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
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

	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// Verify format
	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Errorf("JA4 wrong format: %s", fp.JA4)
	}

	ja4a := parts[0]
	// Should have: t (TCP) + 13 (version from supported_versions) + d (domain) + 04 (4 ciphers) + 07 (7 extensions) + h2 (ALPN)
	// Per JA4 spec: extension count includes SNI and ALPN, only excludes GREASE
	expectedPrefix := "t13d0407"
	if !strings.HasPrefix(ja4a, expectedPrefix) {
		t.Errorf("JA4a prefix wrong: got %s, expected prefix %s", ja4a, expectedPrefix)
	}

	// ALPN should be "h2"
	if !strings.HasSuffix(ja4a, "h2") {
		t.Errorf("JA4a ALPN wrong: got %s, expected suffix h2", ja4a)
	}

	t.Logf("Custom spec JA4: %s", fp.JA4)
	t.Logf("Custom spec JA3: %s", fp.JA3)
}

// TestJA3Format verifies JA3 raw string format correctness.
func TestJA3Format(t *testing.T) {
	spec := ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // 0xc02f = 49199
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // 0xc030 = 49200
		},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SNIExtension{},                                                         // 0
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},         // 10
			&SupportedPointsExtension{SupportedPoints: []byte{0x00}},                // 11
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS12}},           // 43
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
			}}, // 13
		},
	}

	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	parts := strings.Split(fp.JA3r, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3r wrong format: %s", fp.JA3r)
	}

	// Version should be 771 (TLS 1.2 = 0x0303)
	if parts[0] != "771" {
		t.Errorf("JA3r version wrong: got %s, want 771", parts[0])
	}

	// Ciphers should contain 49199 and 49200
	if !strings.Contains(parts[1], "49199") || !strings.Contains(parts[1], "49200") {
		t.Errorf("JA3r ciphers missing expected values: %s", parts[1])
	}

	// Extensions should contain 0, 10, 11, 13, 43
	for _, ext := range []string{"0", "10", "11", "13", "43"} {
		if !strings.Contains(parts[2]+"-", ext+"-") && !strings.HasSuffix(parts[2], ext) && parts[2] != ext {
			// More careful check
			found := false
			for _, e := range strings.Split(parts[2], "-") {
				if e == ext {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("JA3r extensions missing %s: %s", ext, parts[2])
			}
		}
	}

	// Curves: X25519=29, P256=23
	if !strings.Contains(parts[3], "29") || !strings.Contains(parts[3], "23") {
		t.Errorf("JA3r curves wrong: %s", parts[3])
	}

	// Point formats: 0
	if parts[4] != "0" {
		t.Errorf("JA3r point formats wrong: got %s, want 0", parts[4])
	}

	t.Logf("JA3r: %s", fp.JA3r)
	t.Logf("JA3:  %s", fp.JA3)
}

// TestCalculateFingerprintsFromRaw verifies standalone function works.
func TestCalculateFingerprintsFromRaw(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloChrome_142)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	raw := uconn.HandshakeState.Hello.Raw

	// Calculate directly from raw bytes
	fp1, err := CalculateFingerprints(raw)
	if err != nil {
		t.Fatalf("CalculateFingerprints failed: %v", err)
	}

	// Calculate via UConn method
	fp2, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("uconn.Fingerprint failed: %v", err)
	}

	// Results must match
	if fp1.JA3 != fp2.JA3 {
		t.Errorf("JA3 mismatch:\n  raw:   %s\n  uconn: %s", fp1.JA3, fp2.JA3)
	}
	if fp1.JA4 != fp2.JA4 {
		t.Errorf("JA4 mismatch:\n  raw:   %s\n  uconn: %s", fp1.JA4, fp2.JA4)
	}

	t.Logf("Direct calculation matches UConn method")
}

// TestGREASEFiltering verifies GREASE values are excluded from fingerprints.
func TestGREASEFiltering(t *testing.T) {
	// Chrome profiles include GREASE - verify it doesn't affect fingerprint stability
	var fingerprints []string

	for i := 0; i < 20; i++ {
		uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloChrome_142)
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("iteration %d: BuildHandshakeState failed: %v", i, err)
		}

		fp, err := uconn.Fingerprint()
		if err != nil {
			t.Fatalf("iteration %d: Fingerprint failed: %v", i, err)
		}

		fingerprints = append(fingerprints, fp.JA4)
	}

	// All JA4 fingerprints must be identical (GREASE filtered)
	first := fingerprints[0]
	for i, fp := range fingerprints {
		if fp != first {
			t.Errorf("GREASE filtering failed at iteration %d:\n  first: %s\n  got:   %s", i, first, fp)
		}
	}

	t.Logf("GREASE filtering verified: all 20 JA4 fingerprints identical")
}

// TestFingerprintBeforeHandshake verifies error handling.
func TestFingerprintBeforeHandshake(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloChrome_142)
	// Don't call BuildHandshakeState

	_, err := uconn.Fingerprint()
	if err == nil {
		t.Error("Expected error when calling Fingerprint before BuildHandshakeState")
	}
}

// TestAllBrowserProfiles prints fingerprints for all supported profiles.
func TestAllBrowserProfiles(t *testing.T) {
	profiles := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_106", HelloChrome_106_Shuffle},
		{"Chrome_120", HelloChrome_120},
		{"Chrome_131", HelloChrome_131},
		{"Chrome_133", HelloChrome_133},
		{"Chrome_142", HelloChrome_142},
		{"Firefox_120", HelloFirefox_120},
		{"Firefox_145", HelloFirefox_145},
		{"Safari_18", HelloSafari_18},
		{"Safari_26", HelloSafari_26},
		{"Edge_106", HelloEdge_106},
		{"Edge_142", HelloEdge_142},
		{"iOS_18", HelloIOS_18},
		{"iOS_26", HelloIOS_26},
	}

	t.Log("Browser Profile Fingerprints:")
	t.Log("========================================")

	for _, p := range profiles {
		uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, p.id)
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Logf("%-15s FAILED: %v", p.name, err)
			continue
		}

		fp, err := uconn.Fingerprint()
		if err != nil {
			t.Logf("%-15s FAILED: %v", p.name, err)
			continue
		}

		t.Logf("%-15s JA4: %s", p.name, fp.JA4)
		t.Logf("%-15s JA3: %s", "", fp.JA3)
	}
}
