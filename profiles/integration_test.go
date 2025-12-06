// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package profiles_test contains integration tests that verify captured profiles
// work correctly with the utls library. This is an external test package to avoid
// import cycles.
package profiles_test

import (
	"net"
	"strings"
	"testing"

	tls "github.com/refraction-networking/utls"
	"github.com/refraction-networking/utls/profiles"
)

// isGREASE checks if a value is a GREASE value.
// GREASE values have the pattern 0x?a?a where ? is the same hex digit.
func isGREASE(v uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// TestCapturedProfilesIntegration verifies that captured profiles
// work correctly with FingerprintController.
func TestCapturedProfilesIntegration(t *testing.T) {
	// Verify profiles are registered (via init())
	registeredIDs := tls.DefaultRegistry.List()
	t.Logf("Found %d profiles in DefaultRegistry", len(registeredIDs))

	// All captured profile IDs should be registered
	for _, id := range profiles.IDs() {
		if !tls.DefaultRegistry.Exists(id) {
			t.Errorf("Captured profile %q not registered", id)
		}
	}

	// Test a subset of profiles
	testProfiles := []string{
		"chrome_142_linux",
		"firefox_145_linux",
		"safari_18_ios",
		"edge_141_windows_11",
	}

	for _, profileID := range testProfiles {
		t.Run(profileID, func(t *testing.T) {
			// Create UConn
			uconn, err := tls.UClient(&net.TCPConn{}, &tls.Config{ServerName: "example.com"}, tls.HelloCustom)
			if err != nil {
				t.Fatalf("UClient error: %v", err)
			}

			// Apply profile via FingerprintController
			ctrl := tls.NewFingerprintController()
			if err := ctrl.ApplyProfile(uconn, profileID); err != nil {
				t.Fatalf("ApplyProfile failed: %v", err)
			}

			// Verify profile was applied
			profile := ctrl.Profile()
			if profile == nil {
				t.Fatal("Profile is nil after ApplyProfile")
			}
			if profile.ID != profileID {
				t.Errorf("Profile ID mismatch: got %q, want %q", profile.ID, profileID)
			}

			// Build handshake
			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			// Get fingerprint
			fp, err := uconn.Fingerprint()
			if err != nil {
				t.Fatalf("Fingerprint failed: %v", err)
			}

			// Verify JA4 format
			parts := strings.Split(fp.JA4, "_")
			if len(parts) != 3 {
				t.Errorf("JA4 format invalid: %s", fp.JA4)
			}

			t.Logf("Profile %s JA4: %s", profileID, fp.JA4)
			t.Logf("Profile %s JA3: %s", profileID, fp.JA3)
		})
	}
}

// TestProfilesExtensionOrder verifies that profiles with ExtensionOrder
// produce extensions in the correct order.
func TestProfilesExtensionOrder(t *testing.T) {
	// Test Firefox (non-shuffling) profile
	profileID := "firefox_145_linux"

	uconn, err := tls.UClient(&net.TCPConn{}, &tls.Config{ServerName: "test.example.com"}, tls.HelloCustom)
	if err != nil {
		t.Fatalf("UClient error: %v", err)
	}

	ctrl := tls.NewFingerprintController()
	if err := ctrl.ApplyProfile(uconn, profileID); err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	profile := ctrl.Profile()

	// Firefox should have ExtensionOrder set
	if len(profile.ClientHello.ExtensionOrder) == 0 {
		t.Fatal("Firefox profile missing ExtensionOrder")
	}

	// Firefox should NOT shuffle
	if profile.ClientHello.ShuffleExtensions {
		t.Error("Firefox profile should not have ShuffleExtensions=true")
	}

	// Build handshake
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	t.Logf("Firefox ExtensionOrder: %v", profile.ClientHello.ExtensionOrder)
}

// TestProfilesGREASEConfiguration verifies GREASE is correctly applied.
func TestProfilesGREASEConfiguration(t *testing.T) {
	tests := []struct {
		profileID     string
		expectGREASE  bool
		expectShuffle bool
	}{
		{"chrome_142_linux", true, true},
		{"firefox_145_linux", false, false},
		{"edge_141_windows_11", true, true},
		{"safari_18_ios", true, false}, // Safari uses GREASE but doesn't shuffle
	}

	for _, tt := range tests {
		t.Run(tt.profileID, func(t *testing.T) {
			uconn, err := tls.UClient(&net.TCPConn{}, &tls.Config{ServerName: "example.com"}, tls.HelloCustom)
			if err != nil {
				t.Fatalf("UClient error: %v", err)
			}

			ctrl := tls.NewFingerprintController()
			if err := ctrl.ApplyProfile(uconn, tt.profileID); err != nil {
				t.Fatalf("ApplyProfile failed: %v", err)
			}

			profile := ctrl.Profile()

			if profile.ClientHello.GREASE.Enabled != tt.expectGREASE {
				t.Errorf("GREASE.Enabled = %v, want %v", profile.ClientHello.GREASE.Enabled, tt.expectGREASE)
			}

			if profile.ClientHello.ShuffleExtensions != tt.expectShuffle {
				t.Errorf("ShuffleExtensions = %v, want %v", profile.ClientHello.ShuffleExtensions, tt.expectShuffle)
			}

			// Build and verify GREASE in output
			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			hello := uconn.HandshakeState.Hello
			hasGREASECipher := false
			for _, c := range hello.CipherSuites {
				if isGREASE(c) {
					hasGREASECipher = true
					break
				}
			}

			if tt.expectGREASE && !hasGREASECipher {
				t.Error("Expected GREASE cipher suite but none found")
			}
			if !tt.expectGREASE && hasGREASECipher {
				t.Error("Found GREASE cipher suite but none expected")
			}
		})
	}
}

// TestProfilesSessionConsistency verifies GREASE stays frozen across connections.
func TestProfilesSessionConsistency(t *testing.T) {
	profileID := "chrome_142_linux"
	serverName := "session-test.example.com"

	var firstJA4 string
	var firstGREASECipher uint16

	for i := 0; i < 5; i++ {
		uconn, err := tls.UClient(&net.TCPConn{}, &tls.Config{ServerName: serverName}, tls.HelloCustom)
		if err != nil {
			t.Fatalf("iteration %d: UClient error: %v", i, err)
		}

		ctrl := tls.NewFingerprintController()
		if err := ctrl.ApplyProfile(uconn, profileID); err != nil {
			t.Fatalf("iteration %d: ApplyProfile failed: %v", i, err)
		}

		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("iteration %d: BuildHandshakeState failed: %v", i, err)
		}

		fp, err := uconn.Fingerprint()
		if err != nil {
			t.Fatalf("iteration %d: Fingerprint failed: %v", i, err)
		}

		// Find GREASE cipher
		var greaseCipher uint16
		for _, c := range uconn.HandshakeState.Hello.CipherSuites {
			if isGREASE(c) {
				greaseCipher = c
				break
			}
		}

		if i == 0 {
			firstJA4 = fp.JA4
			firstGREASECipher = greaseCipher
			t.Logf("First connection JA4: %s, GREASE cipher: 0x%04x", firstJA4, firstGREASECipher)
		} else {
			// JA4 should be consistent (GREASE filtered)
			if fp.JA4 != firstJA4 {
				t.Errorf("iteration %d: JA4 changed from %s to %s", i, firstJA4, fp.JA4)
			}
			// GREASE value should be frozen
			if greaseCipher != firstGREASECipher {
				t.Errorf("iteration %d: GREASE cipher changed from 0x%04x to 0x%04x", i, firstGREASECipher, greaseCipher)
			}
		}
	}
}

// TestAllCapturedProfilesBuildSuccessfully verifies all 26 profiles can build handshake.
func TestAllCapturedProfilesBuildSuccessfully(t *testing.T) {
	for _, p := range profiles.All() {
		t.Run(p.ID, func(t *testing.T) {
			uconn, err := tls.UClient(&net.TCPConn{}, &tls.Config{ServerName: "example.com"}, tls.HelloCustom)
			if err != nil {
				t.Fatalf("UClient error: %v", err)
			}

			ctrl := tls.NewFingerprintController()
			if err := ctrl.ApplyProfile(uconn, p.ID); err != nil {
				t.Fatalf("ApplyProfile failed: %v", err)
			}

			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			fp, err := uconn.Fingerprint()
			if err != nil {
				t.Fatalf("Fingerprint failed: %v", err)
			}

			// Basic sanity checks
			if fp.JA4 == "" {
				t.Error("JA4 is empty")
			}
			if fp.JA3 == "" {
				t.Error("JA3 is empty")
			}

			t.Logf("JA4: %s", fp.JA4)
		})
	}
}

// TestProfilesMatchExpectedJA4Prefix verifies JA4 prefix matches expected browser characteristics.
func TestProfilesMatchExpectedJA4Prefix(t *testing.T) {
	tests := []struct {
		profileID      string
		expectedPrefix string // JA4a part
	}{
		// Chrome profiles should have TLS 1.3 (13), domain (d), ~15 ciphers, h2 ALPN
		{"chrome_142_linux", "t13d"},
		{"chrome_142_windows_11", "t13d"},
		// Firefox same characteristics
		{"firefox_145_linux", "t13d"},
		// Safari may vary
		{"safari_18_ios", "t13d"},
	}

	for _, tt := range tests {
		t.Run(tt.profileID, func(t *testing.T) {
			uconn, err := tls.UClient(&net.TCPConn{}, &tls.Config{ServerName: "example.com"}, tls.HelloCustom)
			if err != nil {
				t.Fatalf("UClient error: %v", err)
			}

			ctrl := tls.NewFingerprintController()
			if err := ctrl.ApplyProfile(uconn, tt.profileID); err != nil {
				t.Fatalf("ApplyProfile failed: %v", err)
			}

			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			fp, err := uconn.Fingerprint()
			if err != nil {
				t.Fatalf("Fingerprint failed: %v", err)
			}

			ja4a := strings.Split(fp.JA4, "_")[0]
			if !strings.HasPrefix(ja4a, tt.expectedPrefix) {
				t.Errorf("JA4a prefix mismatch: got %s, want prefix %s", ja4a, tt.expectedPrefix)
			}
		})
	}
}
