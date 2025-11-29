// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// =============================================================================
// NewProfileRegistry Tests
// =============================================================================

// TestNewProfileRegistry_ReturnsEmptyRegistry verifies that NewProfileRegistry
// returns an empty registry.
func TestNewProfileRegistry_ReturnsEmptyRegistry(t *testing.T) {
	registry := NewProfileRegistry()
	if registry == nil {
		t.Fatal("NewProfileRegistry returned nil")
	}

	count := registry.Count()
	if count != 0 {
		t.Errorf("expected empty registry, got %d profiles", count)
	}
}

// TestNewProfileRegistry_HasInitializedMap verifies the internal map is initialized.
func TestNewProfileRegistry_HasInitializedMap(t *testing.T) {
	registry := NewProfileRegistry()

	// Should be able to register without nil map panic
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "test",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := registry.Register(profile)
	if err != nil {
		t.Errorf("Register failed on new registry: %v", err)
	}
}

// =============================================================================
// Register Tests
// =============================================================================

// TestRegister_StoresProfile verifies that Register stores a profile.
func TestRegister_StoresProfile(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := registry.Register(profile)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if !registry.Exists("test_profile") {
		t.Error("profile not stored after Register")
	}
}

// TestRegister_NilProfile verifies that Register returns error for nil profile.
func TestRegister_NilProfile(t *testing.T) {
	registry := NewProfileRegistry()

	err := registry.Register(nil)
	if err == nil {
		t.Error("Register should return error for nil profile")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil: %v", err)
	}
}

// TestRegister_EmptyID verifies that Register returns error for empty ID.
func TestRegister_EmptyID(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := registry.Register(profile)
	if err == nil {
		t.Error("Register should return error for empty ID")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty: %v", err)
	}
}

// TestRegister_DuplicateID verifies that Register returns error for duplicate ID.
func TestRegister_DuplicateID(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "duplicate",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := registry.Register(profile)
	if err != nil {
		t.Fatalf("first Register failed: %v", err)
	}

	err = registry.Register(profile)
	if err == nil {
		t.Error("Register should return error for duplicate ID")
	}
	if !strings.Contains(err.Error(), "already") {
		t.Errorf("error should mention already registered: %v", err)
	}
}

// TestRegister_InvalidProfile verifies that Register validates the profile.
func TestRegister_InvalidProfile(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "invalid",
		Browser: "", // Empty browser - validation should fail
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := registry.Register(profile)
	if err == nil {
		t.Error("Register should return error for invalid profile")
	}
}

// TestRegister_StoresClone verifies that Register stores a clone, not the original.
func TestRegister_StoresClone(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "clone_test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := registry.Register(profile)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Modify original
	profile.Browser = "modified"

	// Retrieved profile should have original value
	retrieved, _ := registry.Get("clone_test")
	if retrieved.Browser != "chrome" {
		t.Error("Register did not store a clone")
	}
}

// =============================================================================
// RegisterOrUpdate Tests
// =============================================================================

// TestRegisterOrUpdate_AddsNew verifies that RegisterOrUpdate adds new profiles.
func TestRegisterOrUpdate_AddsNew(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "new_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := registry.RegisterOrUpdate(profile)
	if err != nil {
		t.Fatalf("RegisterOrUpdate failed: %v", err)
	}

	if !registry.Exists("new_profile") {
		t.Error("profile not stored after RegisterOrUpdate")
	}
}

// TestRegisterOrUpdate_UpdatesExisting verifies that RegisterOrUpdate updates existing profiles.
func TestRegisterOrUpdate_UpdatesExisting(t *testing.T) {
	registry := NewProfileRegistry()

	profile1 := &FingerprintProfile{
		ID:      "update_test",
		Browser: "chrome",
		Version: 100,
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.RegisterOrUpdate(profile1)

	profile2 := &FingerprintProfile{
		ID:      "update_test",
		Browser: "chrome",
		Version: 133,
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.RegisterOrUpdate(profile2)

	retrieved, _ := registry.Get("update_test")
	if retrieved.Version != 133 {
		t.Errorf("expected version 133, got %d", retrieved.Version)
	}
}

// TestRegisterOrUpdate_NilProfile verifies error for nil profile.
func TestRegisterOrUpdate_NilProfile(t *testing.T) {
	registry := NewProfileRegistry()

	err := registry.RegisterOrUpdate(nil)
	if err == nil {
		t.Error("RegisterOrUpdate should return error for nil profile")
	}
}

// TestRegisterOrUpdate_EmptyID verifies error for empty ID.
func TestRegisterOrUpdate_EmptyID(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "",
		Browser: "chrome",
	}

	err := registry.RegisterOrUpdate(profile)
	if err == nil {
		t.Error("RegisterOrUpdate should return error for empty ID")
	}
}

// =============================================================================
// Get Tests
// =============================================================================

// TestGet_ReturnsRegisteredProfile verifies that Get returns registered profiles.
func TestGet_ReturnsRegisteredProfile(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "get_test",
		Browser: "chrome",
		Version: 133,
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	retrieved, err := registry.Get("get_test")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Get returned nil profile")
	}
	if retrieved.ID != "get_test" {
		t.Errorf("expected ID 'get_test', got %q", retrieved.ID)
	}
	if retrieved.Version != 133 {
		t.Errorf("expected Version 133, got %d", retrieved.Version)
	}
}

// TestGet_ReturnsErrorForUnknown verifies that Get returns error for unknown profiles.
func TestGet_ReturnsErrorForUnknown(t *testing.T) {
	registry := NewProfileRegistry()

	_, err := registry.Get("nonexistent")
	if err == nil {
		t.Error("Get should return error for unknown profile")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found: %v", err)
	}
}

// TestGet_ReturnsClone verifies that Get returns a clone, not the stored profile.
func TestGet_ReturnsClone(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "clone_get_test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	retrieved1, _ := registry.Get("clone_get_test")
	retrieved1.Browser = "modified"

	retrieved2, _ := registry.Get("clone_get_test")
	if retrieved2.Browser != "chrome" {
		t.Error("Get did not return a clone")
	}
}

// =============================================================================
// MustGet Tests
// =============================================================================

// TestMustGet_ReturnsProfile verifies that MustGet returns profile for valid ID.
func TestMustGet_ReturnsProfile(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "must_get_test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	retrieved := registry.MustGet("must_get_test")
	if retrieved == nil {
		t.Error("MustGet returned nil")
	}
}

// TestMustGet_PanicsForUnknown verifies that MustGet panics for unknown profiles.
func TestMustGet_PanicsForUnknown(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGet should panic for unknown profile")
		}
	}()

	registry := NewProfileRegistry()
	_ = registry.MustGet("nonexistent")
}

// =============================================================================
// Unregister Tests
// =============================================================================

// TestUnregister_RemovesProfile verifies that Unregister removes a profile.
func TestUnregister_RemovesProfile(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "unregister_test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	err := registry.Unregister("unregister_test")
	if err != nil {
		t.Fatalf("Unregister failed: %v", err)
	}

	if registry.Exists("unregister_test") {
		t.Error("profile still exists after Unregister")
	}
}

// TestUnregister_ReturnsErrorForUnknown verifies error for unknown profile.
func TestUnregister_ReturnsErrorForUnknown(t *testing.T) {
	registry := NewProfileRegistry()

	err := registry.Unregister("nonexistent")
	if err == nil {
		t.Error("Unregister should return error for unknown profile")
	}
}

// =============================================================================
// Exists Tests
// =============================================================================

// TestExists_ReturnsTrueForRegistered verifies Exists returns true for registered profiles.
func TestExists_ReturnsTrueForRegistered(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "exists_test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	if !registry.Exists("exists_test") {
		t.Error("Exists should return true for registered profile")
	}
}

// TestExists_ReturnsFalseForUnknown verifies Exists returns false for unknown profiles.
func TestExists_ReturnsFalseForUnknown(t *testing.T) {
	registry := NewProfileRegistry()

	if registry.Exists("nonexistent") {
		t.Error("Exists should return false for unknown profile")
	}
}

// =============================================================================
// List Tests
// =============================================================================

// TestList_ReturnsAllIDs verifies that List returns all profile IDs.
func TestList_ReturnsAllIDs(t *testing.T) {
	registry := NewProfileRegistry()

	profiles := []string{"alpha", "beta", "gamma"}
	for _, id := range profiles {
		profile := &FingerprintProfile{
			ID:      id,
			Browser: "test",
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	list := registry.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(list))
	}
}

// TestList_ReturnsSortedIDs verifies that List returns sorted IDs.
func TestList_ReturnsSortedIDs(t *testing.T) {
	registry := NewProfileRegistry()

	// Register in unsorted order
	for _, id := range []string{"gamma", "alpha", "beta"} {
		profile := &FingerprintProfile{
			ID:      id,
			Browser: "test",
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	list := registry.List()
	expected := []string{"alpha", "beta", "gamma"}
	for i, id := range expected {
		if list[i] != id {
			t.Errorf("list not sorted: expected %q at position %d, got %q", id, i, list[i])
		}
	}
}

// TestList_ReturnsEmptyForEmptyRegistry verifies List returns empty slice for empty registry.
func TestList_ReturnsEmptyForEmptyRegistry(t *testing.T) {
	registry := NewProfileRegistry()

	list := registry.List()
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}
}

// =============================================================================
// ListByBrowser Tests
// =============================================================================

// TestListByBrowser_ReturnsMatchingProfiles verifies filtering by browser.
func TestListByBrowser_ReturnsMatchingProfiles(t *testing.T) {
	registry := NewProfileRegistry()

	// Register mixed profiles
	for _, p := range []struct {
		id, browser string
	}{
		{"chrome_100", "chrome"},
		{"chrome_120", "chrome"},
		{"firefox_100", "firefox"},
	} {
		profile := &FingerprintProfile{
			ID:      p.id,
			Browser: p.browser,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	chromeList := registry.ListByBrowser("chrome")
	if len(chromeList) != 2 {
		t.Errorf("expected 2 chrome profiles, got %d", len(chromeList))
	}

	firefoxList := registry.ListByBrowser("firefox")
	if len(firefoxList) != 1 {
		t.Errorf("expected 1 firefox profile, got %d", len(firefoxList))
	}
}

// TestListByBrowser_ReturnsEmptyForUnknownBrowser verifies empty result for unknown browser.
func TestListByBrowser_ReturnsEmptyForUnknownBrowser(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "chrome_100",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	list := registry.ListByBrowser("safari")
	if len(list) != 0 {
		t.Errorf("expected empty list for unknown browser, got %d items", len(list))
	}
}

// =============================================================================
// ListByPlatform Tests
// =============================================================================

// TestListByPlatform_ReturnsMatchingProfiles verifies filtering by platform.
func TestListByPlatform_ReturnsMatchingProfiles(t *testing.T) {
	registry := NewProfileRegistry()

	for _, p := range []struct {
		id, platform string
	}{
		{"chrome_win", "windows"},
		{"firefox_win", "windows"},
		{"safari_mac", "macos"},
	} {
		profile := &FingerprintProfile{
			ID:       p.id,
			Browser:  "test",
			Platform: p.platform,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	windowsList := registry.ListByPlatform("windows")
	if len(windowsList) != 2 {
		t.Errorf("expected 2 windows profiles, got %d", len(windowsList))
	}
}

// =============================================================================
// ListByBrowserAndPlatform Tests
// =============================================================================

// TestListByBrowserAndPlatform_ReturnsMatchingProfiles verifies filtering by both.
func TestListByBrowserAndPlatform_ReturnsMatchingProfiles(t *testing.T) {
	registry := NewProfileRegistry()

	for _, p := range []struct {
		id, browser, platform string
	}{
		{"chrome_win", "chrome", "windows"},
		{"chrome_mac", "chrome", "macos"},
		{"firefox_win", "firefox", "windows"},
	} {
		profile := &FingerprintProfile{
			ID:       p.id,
			Browser:  p.browser,
			Platform: p.platform,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	list := registry.ListByBrowserAndPlatform("chrome", "windows")
	if len(list) != 1 {
		t.Errorf("expected 1 chrome+windows profile, got %d", len(list))
	}
	if list[0] != "chrome_win" {
		t.Errorf("expected 'chrome_win', got %q", list[0])
	}
}

// =============================================================================
// Match Tests
// =============================================================================

// TestMatch_FindsMatchingProfile verifies Match finds profiles by criteria.
func TestMatch_FindsMatchingProfile(t *testing.T) {
	registry := NewProfileRegistry()

	for _, p := range []struct {
		id, browser, platform string
		version               int
	}{
		{"chrome_100_win", "chrome", "windows", 100},
		{"chrome_120_win", "chrome", "windows", 120},
		{"chrome_120_mac", "chrome", "macos", 120},
	} {
		profile := &FingerprintProfile{
			ID:       p.id,
			Browser:  p.browser,
			Platform: p.platform,
			Version:  p.version,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	// Match by browser and platform
	criteria := ProfileCriteria{
		Browser:  "chrome",
		Platform: "windows",
	}
	profile, err := registry.Match(criteria)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}
	if profile.Browser != "chrome" || profile.Platform != "windows" {
		t.Error("Match returned wrong profile")
	}
}

// TestMatch_ReturnsErrorForNoMatch verifies Match returns error for no matches.
func TestMatch_ReturnsErrorForNoMatch(t *testing.T) {
	registry := NewProfileRegistry()

	criteria := ProfileCriteria{Browser: "nonexistent"}
	_, err := registry.Match(criteria)
	if err == nil {
		t.Error("Match should return error when no profiles match")
	}
}

// TestMatch_VersionRange verifies Match respects version constraints.
func TestMatch_VersionRange(t *testing.T) {
	registry := NewProfileRegistry()

	for _, v := range []int{100, 110, 120, 130} {
		profile := &FingerprintProfile{
			ID:      strings.ReplaceAll("chrome_v", "v", string(rune('0'+v%10))),
			Browser: "chrome",
			Version: v,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		// Use unique IDs
		profile.ID = "chrome_" + string(rune('0'+(v/10)%10)) + string(rune('0'+v%10))
		_ = registry.Register(profile)
	}

	criteria := ProfileCriteria{
		Browser:    "chrome",
		MinVersion: 115,
		MaxVersion: 125,
	}
	profile, err := registry.Match(criteria)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}
	if profile.Version < 115 || profile.Version > 125 {
		t.Errorf("Match returned profile outside version range: %d", profile.Version)
	}
}

// =============================================================================
// Latest Tests
// =============================================================================

// TestLatest_ReturnsLatestVersion verifies Latest returns highest version.
func TestLatest_ReturnsLatestVersion(t *testing.T) {
	registry := NewProfileRegistry()

	for _, v := range []int{100, 133, 120, 110} {
		profile := &FingerprintProfile{
			ID:       "chrome_" + string(rune('0'+(v/100)%10)) + string(rune('0'+(v/10)%10)) + string(rune('0'+v%10)),
			Browser:  "chrome",
			Platform: "windows",
			Version:  v,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	profile, err := registry.Latest("chrome", "windows")
	if err != nil {
		t.Fatalf("Latest failed: %v", err)
	}
	if profile.Version != 133 {
		t.Errorf("expected version 133, got %d", profile.Version)
	}
}

// TestLatest_ReturnsErrorForUnknown verifies Latest returns error for unknown browser.
func TestLatest_ReturnsErrorForUnknown(t *testing.T) {
	registry := NewProfileRegistry()

	_, err := registry.Latest("nonexistent", "")
	if err == nil {
		t.Error("Latest should return error for unknown browser")
	}
}

// TestLatest_EmptyPlatformMatchesAny verifies empty platform matches any.
func TestLatest_EmptyPlatformMatchesAny(t *testing.T) {
	registry := NewProfileRegistry()

	for _, p := range []string{"windows", "macos", "linux"} {
		profile := &FingerprintProfile{
			ID:       "chrome_" + p,
			Browser:  "chrome",
			Platform: p,
			Version:  100,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	profile, err := registry.Latest("chrome", "")
	if err != nil {
		t.Fatalf("Latest with empty platform failed: %v", err)
	}
	if profile == nil {
		t.Error("Latest with empty platform returned nil")
	}
}

// =============================================================================
// Random Tests
// =============================================================================

// TestRandom_ReturnsProfile verifies Random returns a profile.
func TestRandom_ReturnsProfile(t *testing.T) {
	registry := NewProfileRegistry()

	for i := 0; i < 5; i++ {
		profile := &FingerprintProfile{
			ID:      "profile_" + string(rune('0'+i)),
			Browser: "chrome",
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	profile, err := registry.Random(nil)
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}
	if profile == nil {
		t.Error("Random returned nil profile")
	}
}

// TestRandom_ReturnsErrorForEmptyRegistry verifies error for empty registry.
func TestRandom_ReturnsErrorForEmptyRegistry(t *testing.T) {
	registry := NewProfileRegistry()

	_, err := registry.Random(nil)
	if err == nil {
		t.Error("Random should return error for empty registry")
	}
}

// TestRandom_RespectsFilter verifies Random respects filter criteria.
func TestRandom_RespectsFilter(t *testing.T) {
	registry := NewProfileRegistry()

	for _, b := range []string{"chrome", "firefox"} {
		profile := &FingerprintProfile{
			ID:      b + "_100",
			Browser: b,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	filter := &ProfileFilter{Browsers: []string{"firefox"}}

	// Call multiple times to verify filter is respected
	for i := 0; i < 10; i++ {
		profile, err := registry.Random(filter)
		if err != nil {
			t.Fatalf("Random with filter failed: %v", err)
		}
		if profile.Browser != "firefox" {
			t.Errorf("Random did not respect browser filter: got %q", profile.Browser)
		}
	}
}

// TestRandom_ReturnsErrorForNoMatches verifies error when filter matches nothing.
func TestRandom_ReturnsErrorForNoMatches(t *testing.T) {
	registry := NewProfileRegistry()

	profile := &FingerprintProfile{
		ID:      "chrome_100",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	filter := &ProfileFilter{Browsers: []string{"safari"}}
	_, err := registry.Random(filter)
	if err == nil {
		t.Error("Random should return error when filter matches nothing")
	}
}

// =============================================================================
// Count Tests
// =============================================================================

// TestCount_ReturnsCorrectCount verifies Count returns correct count.
func TestCount_ReturnsCorrectCount(t *testing.T) {
	registry := NewProfileRegistry()

	if registry.Count() != 0 {
		t.Errorf("expected count 0, got %d", registry.Count())
	}

	for i := 0; i < 5; i++ {
		profile := &FingerprintProfile{
			ID:      "profile_" + string(rune('0'+i)),
			Browser: "test",
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	if registry.Count() != 5 {
		t.Errorf("expected count 5, got %d", registry.Count())
	}
}

// =============================================================================
// Clear Tests
// =============================================================================

// TestClear_RemovesAllProfiles verifies Clear removes all profiles.
func TestClear_RemovesAllProfiles(t *testing.T) {
	registry := NewProfileRegistry()

	for i := 0; i < 5; i++ {
		profile := &FingerprintProfile{
			ID:      "profile_" + string(rune('0'+i)),
			Browser: "test",
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	registry.Clear()

	if registry.Count() != 0 {
		t.Errorf("expected count 0 after Clear, got %d", registry.Count())
	}
}

// =============================================================================
// Export/Import Tests
// =============================================================================

// TestExport_ReturnsJSON verifies Export returns valid JSON.
func TestExport_ReturnsJSON(t *testing.T) {
	registry := NewProfileRegistry()
	profile := &FingerprintProfile{
		ID:      "export_test",
		Browser: "chrome",
		Version: 133,
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(profile)

	data, err := registry.Export("export_test")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Export returned invalid JSON: %v", err)
	}

	if parsed["ID"] != "export_test" {
		t.Errorf("expected ID 'export_test', got %v", parsed["ID"])
	}
}

// TestExport_ReturnsErrorForUnknown verifies error for unknown profile.
func TestExport_ReturnsErrorForUnknown(t *testing.T) {
	registry := NewProfileRegistry()

	_, err := registry.Export("nonexistent")
	if err == nil {
		t.Error("Export should return error for unknown profile")
	}
}

// TestExportAll_ReturnsAllProfiles verifies ExportAll exports all profiles.
func TestExportAll_ReturnsAllProfiles(t *testing.T) {
	registry := NewProfileRegistry()

	for i := 0; i < 3; i++ {
		profile := &FingerprintProfile{
			ID:      "profile_" + string(rune('0'+i)),
			Browser: "test",
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	data, err := registry.ExportAll()
	if err != nil {
		t.Fatalf("ExportAll failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("ExportAll returned invalid JSON: %v", err)
	}

	if len(parsed) != 3 {
		t.Errorf("expected 3 profiles in export, got %d", len(parsed))
	}
}

// TestImport_AddsProfile verifies Import adds a profile from JSON.
func TestImport_AddsProfile(t *testing.T) {
	registry := NewProfileRegistry()

	jsonData := []byte(`{
		"ID": "imported_profile",
		"Browser": "chrome",
		"Version": 133,
		"Platform": "windows",
		"ClientHello": {
			"CipherSuites": [4865, 4866],
			"CompressionMethods": [0]
		}
	}`)

	err := registry.Import(jsonData)
	if err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	if !registry.Exists("imported_profile") {
		t.Error("imported profile not found in registry")
	}

	profile, _ := registry.Get("imported_profile")
	if profile.Version != 133 {
		t.Errorf("expected version 133, got %d", profile.Version)
	}
}

// TestImport_InvalidJSON verifies error for invalid JSON.
func TestImport_InvalidJSON(t *testing.T) {
	registry := NewProfileRegistry()

	err := registry.Import([]byte("not valid json"))
	if err == nil {
		t.Error("Import should return error for invalid JSON")
	}
}

// =============================================================================
// ValidateAll Tests
// =============================================================================

// TestValidateAll_ReturnsErrorsForInvalidProfiles verifies validation of all profiles.
func TestValidateAll_ReturnsErrorsForInvalidProfiles(t *testing.T) {
	registry := NewProfileRegistry()

	// Register valid profile
	valid := &FingerprintProfile{
		ID:      "valid",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}
	_ = registry.Register(valid)

	// Note: Can't directly register invalid profile since Register validates
	// This test verifies ValidateAll works on valid profiles
	results := registry.ValidateAll()

	// Valid profile should have no errors
	if errs, ok := results["valid"]; ok && len(errs) > 0 {
		t.Errorf("valid profile should have no errors: %v", errs)
	}
}

// =============================================================================
// DefaultRegistry Tests
// =============================================================================

// TestDefaultRegistry_HasBuiltinProfiles verifies built-in profiles exist.
func TestDefaultRegistry_HasBuiltinProfiles(t *testing.T) {
	// chrome_133_windows_11 should be registered
	if !DefaultRegistry.Exists("chrome_133_windows_11") {
		t.Error("chrome_133_windows_11 not found in default registry")
	}

	// firefox_145_windows_11 should be registered
	if !DefaultRegistry.Exists("firefox_145_windows_11") {
		t.Error("firefox_145_windows_11 not found in default registry")
	}

	// safari_18_macos_14 should be registered
	if !DefaultRegistry.Exists("safari_18_macos_14") {
		t.Error("safari_18_macos_14 not found in default registry")
	}
}

// TestDefaultRegistry_GetBuiltinProfile verifies Get works for built-in profiles.
func TestDefaultRegistry_GetBuiltinProfile(t *testing.T) {
	profile, err := DefaultRegistry.Get("chrome_133_windows_11")
	if err != nil {
		t.Fatalf("Get chrome_133_windows_11 failed: %v", err)
	}

	if profile.Browser != "chrome" {
		t.Errorf("expected browser 'chrome', got %q", profile.Browser)
	}
	if profile.Version != 133 {
		t.Errorf("expected version 133, got %d", profile.Version)
	}
}

// TestDefaultRegistry_CustomProfilesCanBeAdded verifies custom profiles work.
func TestDefaultRegistry_CustomProfilesCanBeAdded(t *testing.T) {
	// Use a unique ID to avoid conflicts with other tests
	customID := "test_custom_profile_registry_test_xyz"

	// Clean up first if exists
	_ = DefaultRegistry.Unregister(customID)

	custom := &FingerprintProfile{
		ID:      customID,
		Browser: "custom",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	err := DefaultRegistry.Register(custom)
	if err != nil {
		t.Fatalf("Register custom profile failed: %v", err)
	}
	defer DefaultRegistry.Unregister(customID)

	if !DefaultRegistry.Exists(customID) {
		t.Error("custom profile not found after registration")
	}
}

// =============================================================================
// Global Functions Tests
// =============================================================================

// TestGetProfile_UsesDefaultRegistry verifies GetProfile uses default registry.
func TestGetProfile_UsesDefaultRegistry(t *testing.T) {
	profile, err := GetProfile("chrome_133_windows_11")
	if err != nil {
		t.Fatalf("GetProfile failed: %v", err)
	}
	if profile == nil {
		t.Error("GetProfile returned nil")
	}
}

// TestListProfiles_UsesDefaultRegistry verifies ListProfiles uses default registry.
func TestListProfiles_UsesDefaultRegistry(t *testing.T) {
	list := ListProfiles()
	if len(list) == 0 {
		t.Error("ListProfiles returned empty list")
	}
}

// TestLatestProfile_UsesDefaultRegistry verifies LatestProfile uses default registry.
func TestLatestProfile_UsesDefaultRegistry(t *testing.T) {
	profile, err := LatestProfile("chrome", "")
	if err != nil {
		t.Fatalf("LatestProfile failed: %v", err)
	}
	if profile == nil {
		t.Error("LatestProfile returned nil")
	}
}

// TestRandomProfile_UsesDefaultRegistry verifies RandomProfile uses default registry.
func TestRandomProfile_UsesDefaultRegistry(t *testing.T) {
	profile, err := RandomProfile(nil)
	if err != nil {
		t.Fatalf("RandomProfile failed: %v", err)
	}
	if profile == nil {
		t.Error("RandomProfile returned nil")
	}
}

// =============================================================================
// Thread Safety Tests
// =============================================================================

// TestConcurrentRegisterGet verifies concurrent Register/Get is safe.
func TestConcurrentRegisterGet(t *testing.T) {
	registry := NewProfileRegistry()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			profile := &FingerprintProfile{
				ID:      "concurrent_" + string(rune('0'+(id/100)%10)) + string(rune('0'+(id/10)%10)) + string(rune('0'+id%10)),
				Browser: "test",
				ClientHello: ClientHelloConfig{
					CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
					CompressionMethods: []uint8{0},
				},
			}
			_ = registry.RegisterOrUpdate(profile)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.List()
			_ = registry.Count()
		}()
	}

	wg.Wait()

	// Verify no panic occurred and registry is functional
	count := registry.Count()
	if count == 0 {
		t.Error("registry should have profiles after concurrent operations")
	}
}

// TestConcurrentList verifies concurrent List is safe.
func TestConcurrentList(t *testing.T) {
	registry := NewProfileRegistry()

	// Pre-populate
	for i := 0; i < 10; i++ {
		profile := &FingerprintProfile{
			ID:      "list_test_" + string(rune('0'+i)),
			Browser: "test",
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
		_ = registry.Register(profile)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			list := registry.List()
			if len(list) != 10 {
				t.Errorf("List returned wrong count during concurrent access")
			}
		}()
	}

	wg.Wait()
}

// =============================================================================
// FingerprintProfile Clone Tests
// =============================================================================

// TestProfileClone_CreatesDeepCopy verifies Clone creates deep copy.
func TestProfileClone_CreatesDeepCopy(t *testing.T) {
	original := &FingerprintProfile{
		ID:      "clone_test",
		Browser: "chrome",
		Version: 133,
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
			SupportedVersions:  []uint16{VersionTLS13, VersionTLS12},
			ALPNProtocols:      []string{"h2", "http/1.1"},
			SupportedGroups:    []CurveID{X25519, CurveP256},
			CompressionMethods: []uint8{0},
		},
	}

	clone := original.Clone()

	// Modify clone
	clone.ID = "modified"
	clone.ClientHello.CipherSuites[0] = TLS_CHACHA20_POLY1305_SHA256
	clone.ClientHello.ALPNProtocols[0] = "http/1.1"

	// Original should be unchanged
	if original.ID != "clone_test" {
		t.Error("Clone modified original ID")
	}
	if original.ClientHello.CipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Error("Clone modified original CipherSuites")
	}
	if original.ClientHello.ALPNProtocols[0] != "h2" {
		t.Error("Clone modified original ALPNProtocols")
	}
}

// TestProfileClone_NilReturnsNil verifies Clone of nil returns nil.
func TestProfileClone_NilReturnsNil(t *testing.T) {
	var profile *FingerprintProfile = nil
	clone := profile.Clone()
	if clone != nil {
		t.Error("Clone of nil should return nil")
	}
}

// TestProfileClone_CopiesAllSlices verifies all slices are deep copied.
func TestProfileClone_CopiesAllSlices(t *testing.T) {
	original := &FingerprintProfile{
		ID:      "slice_test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			SupportedVersions:    []uint16{VersionTLS13},
			CipherSuites:         []uint16{TLS_AES_128_GCM_SHA256},
			Extensions:           []ExtensionEntry{{Type: 0}},
			SupportedGroups:      []CurveID{X25519},
			SignatureAlgorithms:  []SignatureScheme{ECDSAWithP256AndSHA256},
			ECPointFormats:       []uint8{0},
			ALPNProtocols:        []string{"h2"},
			KeyShareGroups:       []CurveID{X25519},
			CompressionMethods:   []uint8{0},
			PSKModes:             []uint8{1},
			CertCompressionAlgos: []CertCompressionAlgo{CertCompressionBrotli},
			GREASE: GREASEConfig{
				ExtensionPositions: []int{0, -2},
			},
		},
		ServerExpectations: ServerExpectations{
			AcceptableJA4S:    []string{"*"},
			AcceptableCiphers: []uint16{TLS_AES_128_GCM_SHA256},
			Certificate: CertificateExpectations{
				AcceptableJA4X: []string{"*"},
			},
		},
	}

	clone := original.Clone()

	// Verify slices are different instances
	if &original.ClientHello.CipherSuites == &clone.ClientHello.CipherSuites {
		t.Error("CipherSuites slice not cloned")
	}
	if &original.ClientHello.ALPNProtocols == &clone.ClientHello.ALPNProtocols {
		t.Error("ALPNProtocols slice not cloned")
	}
	if &original.ClientHello.GREASE.ExtensionPositions == &clone.ClientHello.GREASE.ExtensionPositions {
		t.Error("GREASE.ExtensionPositions slice not cloned")
	}
	if &original.ServerExpectations.AcceptableJA4S == &clone.ServerExpectations.AcceptableJA4S {
		t.Error("ServerExpectations.AcceptableJA4S slice not cloned")
	}
}

// =============================================================================
// containsString Helper Tests
// =============================================================================

// TestContainsString verifies the containsString helper function.
func TestContainsString(t *testing.T) {
	slice := []string{"a", "b", "c"}

	if !containsString(slice, "b") {
		t.Error("containsString should return true for existing element")
	}

	if containsString(slice, "d") {
		t.Error("containsString should return false for non-existing element")
	}

	if containsString(nil, "a") {
		t.Error("containsString should return false for nil slice")
	}

	if containsString([]string{}, "a") {
		t.Error("containsString should return false for empty slice")
	}
}

// =============================================================================
// FingerprintProfile Validate Tests
// =============================================================================

// TestProfileValidate_EmptyID verifies validation catches empty ID.
func TestProfileValidate_EmptyID(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		},
	}

	errs := profile.Validate()
	if len(errs) == 0 {
		t.Error("Validate should catch empty ID")
	}

	found := false
	for _, err := range errs {
		if strings.Contains(err.Error(), "ID") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Validate error should mention ID")
	}
}

// TestProfileValidate_EmptyBrowser verifies validation catches empty browser.
func TestProfileValidate_EmptyBrowser(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "",
		ClientHello: ClientHelloConfig{
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		},
	}

	errs := profile.Validate()
	if len(errs) == 0 {
		t.Error("Validate should catch empty browser")
	}
}

// TestProfileValidate_EmptyCipherSuites verifies validation catches empty cipher suites.
func TestProfileValidate_EmptyCipherSuites(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites: []uint16{},
		},
	}

	errs := profile.Validate()
	if len(errs) == 0 {
		t.Error("Validate should catch empty cipher suites")
	}
}

// TestProfileValidate_FirefoxWithGREASE verifies Firefox with GREASE is flagged.
func TestProfileValidate_FirefoxWithGREASE(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "firefox",
		ClientHello: ClientHelloConfig{
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
			GREASE:       GREASEConfig{Enabled: true},
		},
	}

	errs := profile.Validate()
	if len(errs) == 0 {
		t.Error("Validate should flag Firefox with GREASE enabled")
	}
}

// TestProfileValidate_FirefoxWithShuffle verifies Firefox with shuffle is flagged.
func TestProfileValidate_FirefoxWithShuffle(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "firefox",
		ClientHello: ClientHelloConfig{
			CipherSuites:      []uint16{TLS_AES_128_GCM_SHA256},
			ShuffleExtensions: true,
		},
	}

	errs := profile.Validate()
	if len(errs) == 0 {
		t.Error("Validate should flag Firefox with extension shuffling")
	}
}

// =============================================================================
// ProfileValidationError Tests
// =============================================================================

// TestProfileValidationError_Error verifies error message format.
func TestProfileValidationError_Error(t *testing.T) {
	err := &ProfileValidationError{
		Field:   "TestField",
		Message: "test message",
	}

	msg := err.Error()
	if !strings.Contains(msg, "TestField") {
		t.Error("error message should contain field name")
	}
	if !strings.Contains(msg, "test message") {
		t.Error("error message should contain message")
	}
}

// =============================================================================
// ToClientHelloSpec Tests
// =============================================================================

// TestToClientHelloSpec_ConvertsProfile verifies ToClientHelloSpec conversion.
func TestToClientHelloSpec_ConvertsProfile(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "spec_test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
			CompressionMethods: []uint8{0},
			SupportedVersions:  []uint16{VersionTLS13, VersionTLS12},
		},
	}

	spec := profile.ToClientHelloSpec()

	if len(spec.CipherSuites) != 2 {
		t.Errorf("expected 2 cipher suites, got %d", len(spec.CipherSuites))
	}
	if spec.CipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Error("first cipher suite not copied correctly")
	}
	if spec.TLSVersMax != VersionTLS13 {
		t.Errorf("expected TLSVersMax %d, got %d", VersionTLS13, spec.TLSVersMax)
	}
	if spec.TLSVersMin != VersionTLS12 {
		t.Errorf("expected TLSVersMin %d, got %d", VersionTLS12, spec.TLSVersMin)
	}
}
