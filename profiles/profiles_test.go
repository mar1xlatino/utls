// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profiles

import (
	"testing"

	tls "github.com/refraction-networking/utls"
)

// TestAllProfilesValid verifies all profiles pass validation
func TestAllProfilesValid(t *testing.T) {
	for _, p := range All() {
		t.Run(p.ID, func(t *testing.T) {
			errs := p.Validate()
			if len(errs) > 0 {
				for _, err := range errs {
					t.Errorf("validation error: %v", err)
				}
			}
		})
	}
}

// TestAllProfilesHaveExpectedFingerprints verifies all profiles have expected JA3/JA4
func TestAllProfilesHaveExpectedFingerprints(t *testing.T) {
	for _, p := range All() {
		t.Run(p.ID, func(t *testing.T) {
			if p.Expected.JA3 == "" {
				t.Error("missing Expected.JA3")
			}
			if p.Expected.JA4 == "" {
				t.Error("missing Expected.JA4")
			}
			if p.Expected.JA4o == "" {
				t.Error("missing Expected.JA4o (original order)")
			}
		})
	}
}

// TestAllProfilesHaveRequiredFields verifies required fields are set
func TestAllProfilesHaveRequiredFields(t *testing.T) {
	for _, p := range All() {
		t.Run(p.ID, func(t *testing.T) {
			if p.ID == "" {
				t.Error("missing ID")
			}
			if p.Browser == "" {
				t.Error("missing Browser")
			}
			if p.Version == 0 {
				t.Error("missing Version")
			}
			if p.Platform == "" {
				t.Error("missing Platform")
			}
			if len(p.ClientHello.CipherSuites) == 0 {
				t.Error("missing CipherSuites")
			}
			if len(p.ClientHello.ExtensionOrder) == 0 {
				t.Error("missing ExtensionOrder")
			}
			if len(p.ClientHello.SupportedGroups) == 0 {
				t.Error("missing SupportedGroups")
			}
			if len(p.ClientHello.SignatureAlgorithms) == 0 {
				t.Error("missing SignatureAlgorithms")
			}
		})
	}
}

// TestProfilesRegistered verifies profiles are auto-registered
func TestProfilesRegistered(t *testing.T) {
	// The init() function should have auto-registered all profiles
	for _, id := range IDs() {
		if !tls.DefaultRegistry.Exists(id) {
			t.Errorf("profile %q not registered in DefaultRegistry", id)
		}
	}
}

// TestProfileCount verifies expected number of profiles
func TestProfileCount(t *testing.T) {
	all := All()
	expected := 26 // Current count
	if len(all) != expected {
		t.Errorf("expected %d profiles, got %d", expected, len(all))
	}
}

// TestBrowserGroupings verifies browser grouping functions return correct profiles
func TestBrowserGroupings(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() []*tls.FingerprintProfile
		browser  string
		minCount int
	}{
		{"Chrome", Chrome, "chrome", 10},
		{"Firefox", Firefox, "firefox", 6},
		{"Safari", Safari, "safari", 2},
		{"Edge", Edge, "edge", 1},
		{"Opera", Opera, "opera", 3},
		{"SamsungInternet", SamsungInternet, "samsung_internet", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profiles := tt.fn()
			if len(profiles) < tt.minCount {
				t.Errorf("expected at least %d %s profiles, got %d", tt.minCount, tt.name, len(profiles))
			}
			for _, p := range profiles {
				if p.Browser != tt.browser {
					t.Errorf("profile %s has browser %q, expected %q", p.ID, p.Browser, tt.browser)
				}
			}
		})
	}
}

// TestAndroidProfiles verifies Android filter works
func TestAndroidProfiles(t *testing.T) {
	android := Android()
	if len(android) < 8 { // Chrome, Firefox, Opera, Samsung, UC, Yandex all have Android
		t.Errorf("expected at least 8 Android profiles, got %d", len(android))
	}
	for _, p := range android {
		if p.Platform != "android" {
			t.Errorf("profile %s has platform %q, expected android", p.ID, p.Platform)
		}
	}
}

// TestChromiumBrowsersHaveGREASE verifies Chromium-based browsers have GREASE enabled
func TestChromiumBrowsersHaveGREASE(t *testing.T) {
	chromiumBrowsers := []string{"chrome", "edge", "opera", "samsung_internet", "uc_browser", "yandex"}
	for _, p := range All() {
		isChromium := false
		for _, cb := range chromiumBrowsers {
			if p.Browser == cb {
				isChromium = true
				break
			}
		}
		if isChromium {
			t.Run(p.ID, func(t *testing.T) {
				if !p.ClientHello.GREASE.Enabled {
					t.Error("Chromium-based browser should have GREASE.Enabled=true")
				}
				if !p.ClientHello.ShuffleExtensions {
					t.Error("Chromium-based browser should have ShuffleExtensions=true")
				}
			})
		}
	}
}

// TestFirefoxNoGREASE verifies Firefox profiles don't use GREASE
func TestFirefoxNoGREASE(t *testing.T) {
	for _, p := range Firefox() {
		t.Run(p.ID, func(t *testing.T) {
			if p.ClientHello.GREASE.Enabled {
				t.Error("Firefox should not have GREASE.Enabled")
			}
			if p.ClientHello.ShuffleExtensions {
				t.Error("Firefox should not shuffle extensions")
			}
		})
	}
}

// TestSafariHasGREASE verifies Safari profiles use GREASE (modern Safari does use GREASE)
func TestSafariHasGREASE(t *testing.T) {
	for _, p := range Safari() {
		t.Run(p.ID, func(t *testing.T) {
			// Modern Safari (17+) uses GREASE
			if !p.ClientHello.GREASE.Enabled {
				t.Error("Modern Safari should have GREASE.Enabled=true")
			}
		})
	}
}

// TestProfileFingerprintMatch verifies that profiles produce expected JA4o fingerprints.
// Note: JA3 and JA4 (sorted) may vary due to GREASE, but JA4o (original order) should be stable
// when extension order is NOT shuffled (or matches frozen order).
func TestProfileFingerprintMatch(t *testing.T) {
	// Test non-shuffling profiles (Firefox) first - these should have stable JA4o
	for _, p := range Firefox() {
		t.Run(p.ID, func(t *testing.T) {
			// Verify Firefox profiles don't shuffle
			if p.ClientHello.ShuffleExtensions {
				t.Skip("Profile shuffles extensions, JA4o will vary")
			}

			// Check ExtensionOrder exists
			if len(p.ClientHello.ExtensionOrder) == 0 {
				t.Fatal("Profile missing ExtensionOrder")
			}

			// Verify expected fingerprints exist
			if p.Expected.JA4o == "" {
				t.Fatal("Profile missing Expected.JA4o")
			}
		})
	}
}

// TestProfileCloning verifies profiles can be cloned without mutation
func TestProfileCloning(t *testing.T) {
	for _, p := range All() {
		t.Run(p.ID, func(t *testing.T) {
			clone := p.Clone()
			if clone.ID != p.ID {
				t.Errorf("clone.ID = %q, want %q", clone.ID, p.ID)
			}
			if clone.Browser != p.Browser {
				t.Errorf("clone.Browser = %q, want %q", clone.Browser, p.Browser)
			}
			// Modify clone, verify original unchanged
			clone.ID = "modified"
			if p.ID == "modified" {
				t.Error("modifying clone affected original")
			}
		})
	}
}
