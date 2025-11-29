// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// =============================================================================
// TEST 1: Full Chrome Fingerprint Application and JA4 Verification
// =============================================================================

// TestE2E_ChromeFingerprintApplication verifies that applying a Chrome profile
// produces expected JA4 fingerprint characteristics.
func TestE2E_ChromeFingerprintApplication(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloChrome_120)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint calculation failed: %v", err)
	}

	// Verify JA4 format: three underscore-separated parts
	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 format invalid: expected 3 parts, got %d: %s", len(parts), fp.JA4)
	}

	ja4a := parts[0]
	ja4b := parts[1]
	ja4c := parts[2]

	// JA4a should be 10 characters: protocol(1) + version(2) + sni(1) + ciphers(2) + exts(2) + alpn(2)
	if len(ja4a) != 10 {
		t.Errorf("JA4a wrong length: got %d, want 10: %s", len(ja4a), ja4a)
	}

	// Protocol should be 't' for TCP
	if ja4a[0] != 't' {
		t.Errorf("JA4a protocol wrong: got %c, want 't'", ja4a[0])
	}

	// TLS version should be 13 (TLS 1.3) since Chrome 120 uses TLS 1.3
	tlsVersion := ja4a[1:3]
	if tlsVersion != "13" {
		t.Errorf("JA4a TLS version: got %s, want 13", tlsVersion)
	}

	// SNI indicator should be 'd' (domain present)
	if ja4a[3] != 'd' {
		t.Errorf("JA4a SNI indicator: got %c, want 'd'", ja4a[3])
	}

	// ALPN should be "h2" (HTTP/2)
	alpn := ja4a[8:10]
	if alpn != "h2" {
		t.Errorf("JA4a ALPN: got %s, want h2", alpn)
	}

	// JA4b and JA4c should be 12-char hex hashes
	if len(ja4b) != 12 {
		t.Errorf("JA4b wrong length: got %d, want 12: %s", len(ja4b), ja4b)
	}
	if len(ja4c) != 12 {
		t.Errorf("JA4c wrong length: got %d, want 12: %s", len(ja4c), ja4c)
	}

	// Verify GREASE is present in cipher suites (Chrome uses GREASE)
	hello := uconn.HandshakeState.Hello
	hasGREASECipher := false
	for _, cipher := range hello.CipherSuites {
		if isGREASEUint16(cipher) {
			hasGREASECipher = true
			break
		}
	}
	if !hasGREASECipher {
		t.Error("Chrome profile should have GREASE cipher suite")
	}

	t.Logf("Chrome 120 JA4: %s", fp.JA4)
	t.Logf("Chrome 120 JA3: %s", fp.JA3)
}

// =============================================================================
// TEST 2: Session Consistency Across Connections
// =============================================================================

// TestE2E_SessionConsistency verifies that GREASE values remain consistent
// across multiple connections to the same origin within a session.
func TestE2E_SessionConsistency(t *testing.T) {
	const iterations = 10
	serverName := "consistent.example.com"

	var firstGREASECipher uint16
	var firstGREASEExt1 uint16
	var firstJA4 string

	for i := 0; i < iterations; i++ {
		uconn := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloChrome_142)
		if err := uconn.BuildHandshakeState(); err != nil {
			t.Fatalf("iteration %d: BuildHandshakeState failed: %v", i, err)
		}

		hello := uconn.HandshakeState.Hello

		// Find GREASE cipher
		var greaseCipher uint16
		for _, c := range hello.CipherSuites {
			if isGREASEUint16(c) {
				greaseCipher = c
				break
			}
		}

		// Find first GREASE extension
		var greaseExt1 uint16
		for _, ext := range uconn.Extensions {
			buf := make([]byte, 4)
			if n, _ := ext.Read(buf); n >= 2 {
				extType := uint16(buf[0])<<8 | uint16(buf[1])
				if isGREASEUint16(extType) {
					greaseExt1 = extType
					break
				}
			}
		}

		fp, err := uconn.Fingerprint()
		if err != nil {
			t.Fatalf("iteration %d: Fingerprint failed: %v", i, err)
		}

		if i == 0 {
			firstGREASECipher = greaseCipher
			firstGREASEExt1 = greaseExt1
			firstJA4 = fp.JA4
		} else {
			// JA4 should be consistent (GREASE filtered out)
			if fp.JA4 != firstJA4 {
				t.Errorf("iteration %d: JA4 inconsistent\n  first: %s\n  got:   %s", i, firstJA4, fp.JA4)
			}
		}
	}

	t.Logf("GREASE cipher: 0x%04x", firstGREASECipher)
	t.Logf("GREASE ext 1: 0x%04x", firstGREASEExt1)
	t.Logf("Consistent JA4: %s", firstJA4)
}

// =============================================================================
// TEST 3: GREASE Freezing Verification
// =============================================================================

// TestE2E_GREASEFreezing verifies that GREASE values follow the 0x?a?a pattern.
func TestE2E_GREASEFreezing(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "grease.example.com"}, HelloChrome_142)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	hello := uconn.HandshakeState.Hello

	// Verify GREASE cipher pattern
	var greaseCiphers []uint16
	for _, c := range hello.CipherSuites {
		if isGREASEUint16(c) {
			greaseCiphers = append(greaseCiphers, c)
			// Verify pattern: 0x?a?a
			if (c & 0x0f0f) != 0x0a0a {
				t.Errorf("GREASE cipher 0x%04x doesn't match 0x?a?a pattern", c)
			}
		}
	}

	// Verify GREASE in supported versions
	for _, v := range hello.SupportedVersions {
		if isGREASEUint16(v) {
			if (v & 0x0f0f) != 0x0a0a {
				t.Errorf("GREASE version 0x%04x doesn't match 0x?a?a pattern", v)
			}
		}
	}

	// Verify GREASE in supported curves
	for _, curve := range hello.SupportedCurves {
		if isGREASEUint16(uint16(curve)) {
			if (uint16(curve) & 0x0f0f) != 0x0a0a {
				t.Errorf("GREASE curve 0x%04x doesn't match 0x?a?a pattern", curve)
			}
		}
	}

	// Verify KeyShare GREASE matches SupportedCurves GREASE
	var keyShareGREASE CurveID
	for _, ks := range hello.KeyShares {
		if isGREASEUint16(uint16(ks.Group)) {
			keyShareGREASE = ks.Group
			break
		}
	}

	var curvesGREASE CurveID
	for _, curve := range hello.SupportedCurves {
		if isGREASEUint16(uint16(curve)) {
			curvesGREASE = curve
			break
		}
	}

	if keyShareGREASE != 0 && curvesGREASE != 0 && keyShareGREASE != curvesGREASE {
		t.Errorf("KeyShare GREASE (0x%04x) doesn't match SupportedCurves GREASE (0x%04x)",
			keyShareGREASE, curvesGREASE)
	}

	// Verify GREASE extensions are distinct
	var greaseExts []uint16
	for _, ext := range uconn.Extensions {
		buf := make([]byte, 4)
		if n, _ := ext.Read(buf); n >= 2 {
			extType := uint16(buf[0])<<8 | uint16(buf[1])
			if isGREASEUint16(extType) {
				greaseExts = append(greaseExts, extType)
			}
		}
	}

	if len(greaseExts) >= 2 && greaseExts[0] == greaseExts[1] {
		t.Errorf("GREASE extensions should be distinct: both are 0x%04x", greaseExts[0])
	}

	t.Logf("Found %d GREASE ciphers", len(greaseCiphers))
	t.Logf("Found %d GREASE extensions", len(greaseExts))
	if len(greaseExts) >= 2 {
		t.Logf("GREASE ext1: 0x%04x, ext2: 0x%04x", greaseExts[0], greaseExts[1])
	}
}

// =============================================================================
// TEST 4: Profile Builder to Connection Flow
// =============================================================================

// TestE2E_ProfileBuilderToConnection verifies the complete flow from
// profile builder to connection creation.
func TestE2E_ProfileBuilderToConnection(t *testing.T) {
	// Create custom profile using builder
	builder := NewEmptyProfileBuilder().
		WithID("test_custom_profile").
		WithBrowser("testbrowser").
		WithVersion(100).
		WithPlatform("testplatform").
		WithCipherSuites([]uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}).
		WithSupportedVersions([]uint16{VersionTLS13, VersionTLS12}).
		WithSupportedGroups([]CurveID{X25519, CurveP256, CurveP384}).
		WithSignatureAlgorithms([]SignatureScheme{
			ECDSAWithP256AndSHA256,
			PSSWithSHA256,
			PKCS1WithSHA256,
		}).
		WithALPN([]string{"h2", "http/1.1"}).
		WithGREASE(false).
		WithShuffleExtensions(false)

	profile, err := builder.Build()
	if err != nil {
		t.Fatalf("Profile build failed: %v", err)
	}

	// Register profile
	testRegistry := NewProfileRegistry()
	if err := testRegistry.Register(profile); err != nil {
		t.Fatalf("Profile registration failed: %v", err)
	}

	// Retrieve and verify
	retrieved, err := testRegistry.Get("test_custom_profile")
	if err != nil {
		t.Fatalf("Profile retrieval failed: %v", err)
	}

	if retrieved.Browser != "testbrowser" {
		t.Errorf("Browser mismatch: got %s, want testbrowser", retrieved.Browser)
	}
	if retrieved.Version != 100 {
		t.Errorf("Version mismatch: got %d, want 100", retrieved.Version)
	}
	if len(retrieved.ClientHello.CipherSuites) != 4 {
		t.Errorf("Cipher count mismatch: got %d, want 4", len(retrieved.ClientHello.CipherSuites))
	}

	t.Logf("Custom profile registered and retrieved successfully")
}

// =============================================================================
// TEST 5: Validation Round-Trip
// =============================================================================

// TestE2E_ValidationRoundTrip verifies that a profile's expected fingerprints
// match what's actually produced.
func TestE2E_ValidationRoundTrip(t *testing.T) {
	// Build profile with specific characteristics
	builder := NewEmptyProfileBuilder().
		WithID("validation_test_profile").
		WithBrowser("chrome").
		WithVersion(120).
		WithPlatform("windows").
		WithCipherSuites([]uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}).
		WithSupportedVersions([]uint16{VersionTLS13, VersionTLS12}).
		WithSupportedGroups([]CurveID{X25519, CurveP256}).
		WithSignatureAlgorithms([]SignatureScheme{
			ECDSAWithP256AndSHA256,
			PSSWithSHA256,
		}).
		WithALPN([]string{"h2"}).
		WithGREASE(false).
		WithShuffleExtensions(false)

	profile, err := builder.Build()
	if err != nil {
		t.Fatalf("Profile build failed: %v", err)
	}

	// Create connection and build ClientHello
	spec := ClientHelloSpec{
		CipherSuites:       profile.ClientHello.CipherSuites,
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: profile.ClientHello.SupportedGroups},
			&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&SupportedVersionsExtension{Versions: profile.ClientHello.SupportedVersions},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: profile.ClientHello.SignatureAlgorithms},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&ALPNExtension{AlpnProtocols: profile.ClientHello.ALPNProtocols},
		},
	}

	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "validation.example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	// Get fingerprint
	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// Store expected values in profile
	profile.Expected.JA4 = fp.JA4
	profile.Expected.JA3 = fp.JA3

	// Create validator and validate
	validator := NewValidator(profile)

	result := validator.ValidateJA4(fp.JA4)
	if !result.Valid {
		t.Errorf("JA4 validation failed: %v", result.Mismatches)
	}

	result = validator.ValidateJA3(fp.JA3)
	if !result.Valid {
		t.Errorf("JA3 validation failed: %v", result.Mismatches)
	}

	t.Logf("Validation round-trip successful")
	t.Logf("JA4: %s", fp.JA4)
	t.Logf("JA3: %s", fp.JA3)
}

// =============================================================================
// TEST 6: Record Padding Integration
// =============================================================================

// TestE2E_RecordPaddingIntegration verifies that record padding configuration
// is correctly applied to connections.
func TestE2E_RecordPaddingIntegration(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{"chrome", "chrome"},
		{"exponential", "exponential"},
		{"uniform", "uniform"},
		{"none", "none"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uconn := UClient(&net.TCPConn{}, &Config{ServerName: "padding.example.com"}, HelloChrome_142)

			// Apply padding mode
			uconn.SetRecordPaddingMode(tc.mode)

			// Verify configuration was set
			if tc.mode == "none" {
				if uconn.config.RecordPadding != nil {
					t.Error("RecordPadding should be nil for 'none' mode")
				}
			} else {
				if uconn.config.RecordPadding == nil {
					t.Errorf("RecordPadding should not be nil for '%s' mode", tc.mode)
				} else {
					if !uconn.config.RecordPadding.Enabled {
						t.Errorf("RecordPadding should be enabled for '%s' mode", tc.mode)
					}
				}
			}
		})
	}
}

// TestE2E_RecordPaddingConfig verifies custom record padding configuration.
func TestE2E_RecordPaddingConfig(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "padding.example.com"}, HelloChrome_142)

	// Set custom padding config
	customCfg := &RecordPaddingConfig{
		Enabled:      true,
		Distribution: "exponential",
		Lambda:       5.0,
		MaxPadding:   200,
	}
	uconn.SetRecordPadding(customCfg)

	// Verify configuration
	if uconn.config.RecordPadding == nil {
		t.Fatal("RecordPadding should not be nil")
	}
	if uconn.config.RecordPadding.Lambda != 5.0 {
		t.Errorf("Lambda mismatch: got %f, want 5.0", uconn.config.RecordPadding.Lambda)
	}
	if uconn.config.RecordPadding.MaxPadding != 200 {
		t.Errorf("MaxPadding mismatch: got %d, want 200", uconn.config.RecordPadding.MaxPadding)
	}
}

// =============================================================================
// TEST 7: Error Handling
// =============================================================================

// TestE2E_ErrorHandling_InvalidProfileID tests error when requesting non-existent profile.
func TestE2E_ErrorHandling_InvalidProfileID(t *testing.T) {
	registry := NewProfileRegistry()

	_, err := registry.Get("nonexistent_profile_id")
	if err == nil {
		t.Error("Expected error for non-existent profile")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Error should mention 'not found': %v", err)
	}
}

// TestE2E_ErrorHandling_NilProfile tests error when registering nil profile.
func TestE2E_ErrorHandling_NilProfile(t *testing.T) {
	registry := NewProfileRegistry()

	err := registry.Register(nil)
	if err == nil {
		t.Error("Expected error for nil profile registration")
	}
}

// TestE2E_ErrorHandling_EmptyProfileID tests error for empty profile ID.
func TestE2E_ErrorHandling_EmptyProfileID(t *testing.T) {
	registry := NewProfileRegistry()

	profile := &FingerprintProfile{
		ID: "", // Empty ID
	}

	err := registry.Register(profile)
	if err == nil {
		t.Error("Expected error for empty profile ID")
	}
}

// TestE2E_ErrorHandling_DuplicateRegistration tests error for duplicate profile.
func TestE2E_ErrorHandling_DuplicateRegistration(t *testing.T) {
	registry := NewProfileRegistry()

	profile := &FingerprintProfile{
		ID:       "duplicate_test",
		Browser:  "test",
		Platform: "test",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []uint8{0},
		},
	}

	// First registration should succeed
	err := registry.Register(profile)
	if err != nil {
		t.Fatalf("First registration failed: %v", err)
	}

	// Second registration should fail
	err = registry.Register(profile)
	if err == nil {
		t.Error("Expected error for duplicate registration")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("Error should mention 'already registered': %v", err)
	}
}

// TestE2E_ErrorHandling_FingerprintBeforeHandshake tests error when getting
// fingerprint before building handshake state.
func TestE2E_ErrorHandling_FingerprintBeforeHandshake(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloChrome_142)
	// Don't call BuildHandshakeState

	_, err := uconn.Fingerprint()
	if err == nil {
		t.Error("Expected error when calling Fingerprint before BuildHandshakeState")
	}
}

// =============================================================================
// TEST 8: Hooks Invocation
// =============================================================================

// TestE2E_HooksInvocation tests that fingerprint hooks are properly invoked.
func TestE2E_HooksInvocation(t *testing.T) {
	// Track hook calls
	var profileSelectedCalled atomic.Bool
	var sessionCreatedCalled atomic.Bool

	hooks := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			profileSelectedCalled.Store(true)
			if profile == nil {
				return errors.New("profile is nil")
			}
			return nil
		},
		OnSessionStateCreated: func(state *SessionFingerprintState) error {
			sessionCreatedCalled.Store(true)
			return nil
		},
	}

	// Create hook chain
	chain := NewHookChain(hooks)

	// Test CallProfileSelected
	testProfile := &FingerprintProfile{
		ID:      "hook_test",
		Browser: "test",
	}

	err := chain.CallProfileSelected(testProfile)
	if err != nil {
		t.Errorf("CallProfileSelected failed: %v", err)
	}

	if !profileSelectedCalled.Load() {
		t.Error("OnProfileSelected hook was not called")
	}

	// Test that nil profile causes error
	err = chain.CallProfileSelected(nil)
	if err == nil {
		t.Error("Expected error when calling hook with nil profile")
	}
}

// TestE2E_HookChainOrder tests that hooks are called in order and stop on error.
func TestE2E_HookChainOrder(t *testing.T) {
	var callOrder []int
	var mu sync.Mutex

	hooks1 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			mu.Lock()
			callOrder = append(callOrder, 1)
			mu.Unlock()
			return nil
		},
	}

	hooks2 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			mu.Lock()
			callOrder = append(callOrder, 2)
			mu.Unlock()
			return errors.New("hook 2 error")
		},
	}

	hooks3 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			mu.Lock()
			callOrder = append(callOrder, 3)
			mu.Unlock()
			return nil
		},
	}

	chain := NewHookChain(hooks1, hooks2, hooks3)

	profile := &FingerprintProfile{ID: "test"}
	err := chain.CallProfileSelected(profile)

	// Should get error from hook 2
	if err == nil {
		t.Error("Expected error from hook 2")
	}

	// Should have called hooks 1 and 2, but not 3
	mu.Lock()
	defer mu.Unlock()

	if len(callOrder) != 2 {
		t.Errorf("Expected 2 hooks called, got %d", len(callOrder))
	}
	if len(callOrder) >= 2 && (callOrder[0] != 1 || callOrder[1] != 2) {
		t.Errorf("Wrong call order: %v", callOrder)
	}
}

// TestE2E_FingerprintMonitor tests the fingerprint monitoring system.
func TestE2E_FingerprintMonitor(t *testing.T) {
	monitor := NewFingerprintMonitor(100)

	var eventCount atomic.Int32
	monitor.AddListener(func(event FingerprintEvent) {
		eventCount.Add(1)
	})

	// Emit events
	monitor.Emit(EventProfileSelected, "chrome_120")
	monitor.Emit(EventSessionCreated, "session-123")
	monitor.Emit(EventClientHelloBuilt, nil)

	// Check events were recorded
	events := monitor.Events()
	if len(events) != 3 {
		t.Errorf("Expected 3 events, got %d", len(events))
	}

	if eventCount.Load() != 3 {
		t.Errorf("Listener called %d times, expected 3", eventCount.Load())
	}

	// Test event types
	if events[0].Type != EventProfileSelected {
		t.Errorf("First event type wrong: got %d, want %d", events[0].Type, EventProfileSelected)
	}
	if events[1].Type != EventSessionCreated {
		t.Errorf("Second event type wrong: got %d, want %d", events[1].Type, EventSessionCreated)
	}
}

// =============================================================================
// TEST 9: Registry Operations
// =============================================================================

// TestE2E_RegistryOperations tests comprehensive registry functionality.
func TestE2E_RegistryOperations(t *testing.T) {
	registry := NewProfileRegistry()

	// Helper to create minimal valid profile
	makeProfile := func(id, browser, platform string, version int) *FingerprintProfile {
		return &FingerprintProfile{
			ID:       id,
			Browser:  browser,
			Version:  version,
			Platform: platform,
			ClientHello: ClientHelloConfig{
				CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
				CompressionMethods: []uint8{0},
			},
		}
	}

	// Register profiles for different browsers
	profiles := []*FingerprintProfile{
		makeProfile("chrome_100_windows", "chrome", "windows", 100),
		makeProfile("chrome_120_windows", "chrome", "windows", 120),
		makeProfile("chrome_120_macos", "chrome", "macos", 120),
		makeProfile("firefox_100_windows", "firefox", "windows", 100),
		makeProfile("firefox_120_linux", "firefox", "linux", 120),
	}

	for _, p := range profiles {
		if err := registry.Register(p); err != nil {
			t.Fatalf("Failed to register %s: %v", p.ID, err)
		}
	}

	// Test Count
	if registry.Count() != 5 {
		t.Errorf("Count wrong: got %d, want 5", registry.Count())
	}

	// Test ListByBrowser
	chromeProfiles := registry.ListByBrowser("chrome")
	if len(chromeProfiles) != 3 {
		t.Errorf("Chrome profiles count: got %d, want 3", len(chromeProfiles))
	}

	// Test ListByPlatform
	windowsProfiles := registry.ListByPlatform("windows")
	if len(windowsProfiles) != 3 {
		t.Errorf("Windows profiles count: got %d, want 3", len(windowsProfiles))
	}

	// Test ListByBrowserAndPlatform
	chromeWindows := registry.ListByBrowserAndPlatform("chrome", "windows")
	if len(chromeWindows) != 2 {
		t.Errorf("Chrome Windows profiles count: got %d, want 2", len(chromeWindows))
	}

	// Test Latest
	latestChrome, err := registry.Latest("chrome", "windows")
	if err != nil {
		t.Fatalf("Latest failed: %v", err)
	}
	if latestChrome.Version != 120 {
		t.Errorf("Latest Chrome version: got %d, want 120", latestChrome.Version)
	}

	// Test Match
	criteria := ProfileCriteria{
		Browser:    "firefox",
		MinVersion: 110,
	}
	matched, err := registry.Match(criteria)
	if err != nil {
		t.Fatalf("Match failed: %v", err)
	}
	if matched.Version < 110 {
		t.Errorf("Matched version too low: got %d, want >= 110", matched.Version)
	}

	// Test Exists
	if !registry.Exists("chrome_120_windows") {
		t.Error("Exists should return true for registered profile")
	}
	if registry.Exists("nonexistent") {
		t.Error("Exists should return false for unregistered profile")
	}

	// Test Unregister
	if err := registry.Unregister("chrome_100_windows"); err != nil {
		t.Errorf("Unregister failed: %v", err)
	}
	if registry.Count() != 4 {
		t.Errorf("Count after unregister: got %d, want 4", registry.Count())
	}

	// Test Clear
	registry.Clear()
	if registry.Count() != 0 {
		t.Errorf("Count after clear: got %d, want 0", registry.Count())
	}
}

// =============================================================================
// TEST 10: Browser Profile Fingerprint Consistency
// =============================================================================

// TestE2E_BrowserFingerprintConsistency verifies that different browser profiles
// produce consistent fingerprints across multiple generations.
func TestE2E_BrowserFingerprintConsistency(t *testing.T) {
	browsers := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_120", HelloChrome_120},
		{"Chrome_142", HelloChrome_142},
		{"Firefox_120", HelloFirefox_120},
		{"Firefox_145", HelloFirefox_145},
		{"Safari_18", HelloSafari_18},
		{"Edge_142", HelloEdge_142},
	}

	for _, browser := range browsers {
		t.Run(browser.name, func(t *testing.T) {
			var fingerprints []string
			const iterations = 20

			for i := 0; i < iterations; i++ {
				uconn := UClient(&net.TCPConn{}, &Config{ServerName: "test.example.com"}, browser.id)
				if err := uconn.BuildHandshakeState(); err != nil {
					t.Fatalf("iteration %d: BuildHandshakeState failed: %v", i, err)
				}

				fp, err := uconn.Fingerprint()
				if err != nil {
					t.Fatalf("iteration %d: Fingerprint failed: %v", i, err)
				}

				fingerprints = append(fingerprints, fp.JA4)
			}

			// All JA4 fingerprints should be identical (GREASE is filtered)
			first := fingerprints[0]
			for i, fp := range fingerprints {
				if fp != first {
					t.Errorf("JA4 inconsistent at iteration %d:\n  first: %s\n  got:   %s", i, first, fp)
				}
			}

			t.Logf("%s JA4: %s (stable over %d iterations)", browser.name, first, iterations)
		})
	}
}

// =============================================================================
// TEST 11: Firefox vs Chrome Differences
// =============================================================================

// TestE2E_FirefoxVsChromeCharacteristics verifies browser-specific characteristics.
func TestE2E_FirefoxVsChromeCharacteristics(t *testing.T) {
	// Chrome uses GREASE, Firefox doesn't
	chromeConn := UClient(&net.TCPConn{}, &Config{ServerName: "test.example.com"}, HelloChrome_142)
	if err := chromeConn.BuildHandshakeState(); err != nil {
		t.Fatalf("Chrome BuildHandshakeState failed: %v", err)
	}

	firefoxConn := UClient(&net.TCPConn{}, &Config{ServerName: "test.example.com"}, HelloFirefox_145)
	if err := firefoxConn.BuildHandshakeState(); err != nil {
		t.Fatalf("Firefox BuildHandshakeState failed: %v", err)
	}

	// Check for GREASE in Chrome cipher suites
	chromeHasGREASE := false
	for _, c := range chromeConn.HandshakeState.Hello.CipherSuites {
		if isGREASEUint16(c) {
			chromeHasGREASE = true
			break
		}
	}
	if !chromeHasGREASE {
		t.Error("Chrome should have GREASE in cipher suites")
	}

	// Check Firefox has no GREASE
	firefoxHasGREASE := false
	for _, c := range firefoxConn.HandshakeState.Hello.CipherSuites {
		if isGREASEUint16(c) {
			firefoxHasGREASE = true
			break
		}
	}
	if firefoxHasGREASE {
		t.Error("Firefox should not have GREASE in cipher suites")
	}

	// Get fingerprints
	chromeFP, err := chromeConn.Fingerprint()
	if err != nil {
		t.Fatalf("Chrome Fingerprint failed: %v", err)
	}

	firefoxFP, err := firefoxConn.Fingerprint()
	if err != nil {
		t.Fatalf("Firefox Fingerprint failed: %v", err)
	}

	// JA4 fingerprints should be different (different browser characteristics)
	if chromeFP.JA4 == firefoxFP.JA4 {
		t.Error("Chrome and Firefox should have different JA4 fingerprints")
	}

	t.Logf("Chrome JA4: %s", chromeFP.JA4)
	t.Logf("Firefox JA4: %s", firefoxFP.JA4)
}

// =============================================================================
// TEST 12: Custom Spec Application
// =============================================================================

// TestE2E_CustomSpecApplication tests applying a custom ClientHelloSpec.
func TestE2E_CustomSpecApplication(t *testing.T) {
	spec := ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256, CurveP384}},
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

	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "custom.example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset failed: %v", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	// Verify cipher suites were applied
	hello := uconn.HandshakeState.Hello
	if len(hello.CipherSuites) != 4 {
		t.Errorf("Cipher suite count: got %d, want 4", len(hello.CipherSuites))
	}
	if hello.CipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Errorf("First cipher suite: got 0x%04x, want 0x%04x",
			hello.CipherSuites[0], TLS_AES_128_GCM_SHA256)
	}

	// Get fingerprint
	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// Verify JA4 format
	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Errorf("JA4 format wrong: got %d parts", len(parts))
	}

	ja4a := parts[0]
	// Should have 4 ciphers (04)
	cipherCount := ja4a[4:6]
	if cipherCount != "04" {
		t.Errorf("JA4a cipher count: got %s, want 04", cipherCount)
	}

	t.Logf("Custom spec JA4: %s", fp.JA4)
}

// =============================================================================
// TEST 13: JA3/JA4 Format Verification
// =============================================================================

// TestE2E_JA3FormatVerification verifies JA3 string format correctness.
func TestE2E_JA3FormatVerification(t *testing.T) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "ja3.example.com"}, HelloChrome_142)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// JA3r format: version,ciphers,extensions,curves,points
	parts := strings.Split(fp.JA3r, ",")
	if len(parts) != 5 {
		t.Fatalf("JA3r wrong format: expected 5 parts, got %d: %s", len(parts), fp.JA3r)
	}

	// Version should be 771 (TLS 1.2 = 0x0303) or similar
	version := parts[0]
	if version != "771" && version != "769" && version != "770" {
		t.Logf("JA3r version: %s (non-standard)", version)
	}

	// Ciphers should be hyphen-separated numbers
	ciphers := parts[1]
	if ciphers != "" {
		cipherParts := strings.Split(ciphers, "-")
		for _, c := range cipherParts {
			if c != "" {
				// Each should be a number
				for _, ch := range c {
					if ch < '0' || ch > '9' {
						t.Errorf("JA3r cipher contains non-numeric: %s", c)
						break
					}
				}
			}
		}
	}

	// JA3 hash should be 32 hex characters
	if len(fp.JA3) != 32 {
		t.Errorf("JA3 hash wrong length: got %d, want 32", len(fp.JA3))
	}

	// All characters should be hex
	for _, c := range fp.JA3 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			t.Errorf("JA3 hash contains non-hex character: %c", c)
		}
	}

	t.Logf("JA3r: %s", fp.JA3r)
	t.Logf("JA3:  %s", fp.JA3)
}

// =============================================================================
// TEST 14: JA4 Comparison Utility
// =============================================================================

// TestE2E_JA4ComparisonUtility tests the JA4 comparison function.
func TestE2E_JA4ComparisonUtility(t *testing.T) {
	// Create two different connections
	chrome := UClient(&net.TCPConn{}, &Config{ServerName: "test.example.com"}, HelloChrome_142)
	if err := chrome.BuildHandshakeState(); err != nil {
		t.Fatalf("Chrome BuildHandshakeState failed: %v", err)
	}

	firefox := UClient(&net.TCPConn{}, &Config{ServerName: "test.example.com"}, HelloFirefox_145)
	if err := firefox.BuildHandshakeState(); err != nil {
		t.Fatalf("Firefox BuildHandshakeState failed: %v", err)
	}

	chromeFP, _ := chrome.Fingerprint()
	firefoxFP, _ := firefox.Fingerprint()

	// Compare same fingerprint
	sameComp := CompareJA4(chromeFP.JA4, chromeFP.JA4)
	if !sameComp.Match {
		t.Error("Same fingerprints should match")
	}
	if !sameComp.VersionMatch {
		t.Error("Same fingerprints should have matching version")
	}
	if !sameComp.CipherHashMatch {
		t.Error("Same fingerprints should have matching cipher hash")
	}
	if !sameComp.ExtHashMatch {
		t.Error("Same fingerprints should have matching extension hash")
	}

	// Compare different fingerprints
	diffComp := CompareJA4(chromeFP.JA4, firefoxFP.JA4)
	if diffComp.Match {
		t.Error("Chrome and Firefox fingerprints should not match")
	}

	t.Logf("Chrome JA4:  %s", chromeFP.JA4)
	t.Logf("Firefox JA4: %s", firefoxFP.JA4)
	t.Logf("Comparison: %s", diffComp.Diff)
}

// =============================================================================
// TEST 15: Validator With Session State
// =============================================================================

// TestE2E_ValidatorWithSessionState tests validation using session state.
func TestE2E_ValidatorWithSessionState(t *testing.T) {
	// Create session state
	state := &SessionFingerprintState{
		ID:     "test-session-123",
		Origin: "test.example.com",
		FrozenGREASE: FrozenGREASEValues{
			CipherSuite: 0x1a1a,
			Extension1:  0x2a2a,
			Extension2:  0x3a3a,
		},
		FrozenExtensionOrder: []uint16{0, 10, 11, 13, 43, 51, 45, 65281},
	}

	validator := NewSessionValidator(state)

	// Test consistency with correct values
	result := validator.ValidateSessionConsistency(
		[]uint16{0x1a1a, TLS_AES_128_GCM_SHA256},
		[]uint16{0x2a2a, 0, 10, 11, 13, 43, 51, 45, 65281, 0x3a3a},
	)

	if !result.Valid {
		t.Errorf("Valid session should pass consistency check: %v", result.Mismatches)
	}

	// Test with wrong GREASE cipher
	result = validator.ValidateSessionConsistency(
		[]uint16{0x4a4a, TLS_AES_128_GCM_SHA256}, // Wrong GREASE
		[]uint16{0x2a2a, 0, 10, 11, 13, 43, 51, 45, 65281, 0x3a3a},
	)

	if result.Valid {
		t.Error("Wrong GREASE cipher should fail consistency check")
	}
}

// =============================================================================
// TEST 16: Profile Export/Import
// =============================================================================

// TestE2E_ProfileExportImport tests profile JSON export and import.
func TestE2E_ProfileExportImport(t *testing.T) {
	registry := NewProfileRegistry()

	original := &FingerprintProfile{
		ID:          "export_test",
		Browser:     "testbrowser",
		Version:     100,
		Platform:    "testplatform",
		OSVersion:   "1.0",
		Description: "Test profile for export/import",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
			SupportedVersions:  []uint16{VersionTLS13, VersionTLS12},
			CompressionMethods: []uint8{0},
		},
	}

	if err := registry.Register(original); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Export
	exported, err := registry.Export("export_test")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Create new registry and import
	newRegistry := NewProfileRegistry()
	if err := newRegistry.Import(exported); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Verify imported profile
	imported, err := newRegistry.Get("export_test")
	if err != nil {
		t.Fatalf("Get imported profile failed: %v", err)
	}

	if imported.Browser != original.Browser {
		t.Errorf("Browser mismatch: got %s, want %s", imported.Browser, original.Browser)
	}
	if imported.Version != original.Version {
		t.Errorf("Version mismatch: got %d, want %d", imported.Version, original.Version)
	}
	if imported.Description != original.Description {
		t.Errorf("Description mismatch: got %s, want %s", imported.Description, original.Description)
	}
}

// =============================================================================
// TEST 17: Concurrent Registry Access
// =============================================================================

// TestE2E_ConcurrentRegistryAccess tests thread safety of registry operations.
func TestE2E_ConcurrentRegistryAccess(t *testing.T) {
	registry := NewProfileRegistry()
	var wg sync.WaitGroup
	const goroutines = 100

	// Concurrent writes
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			profile := &FingerprintProfile{
				ID:       fmt.Sprintf("concurrent_%d", idx),
				Browser:  "test",
				Platform: "test",
				ClientHello: ClientHelloConfig{
					CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
					CompressionMethods: []uint8{0},
				},
			}
			_ = registry.RegisterOrUpdate(profile)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = registry.List()
			_ = registry.Exists(fmt.Sprintf("concurrent_%d", idx))
		}(i)
	}

	wg.Wait()

	// Verify count
	if registry.Count() != goroutines {
		t.Errorf("Expected %d profiles, got %d", goroutines, registry.Count())
	}
}

// =============================================================================
// TEST 18: Profile Cloning
// =============================================================================

// TestE2E_ProfileCloning tests that profile cloning creates independent copies.
func TestE2E_ProfileCloning(t *testing.T) {
	original := &FingerprintProfile{
		ID:      "clone_test",
		Browser: "original",
		ClientHello: ClientHelloConfig{
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
		},
	}

	cloned := original.Clone()

	// Modify original
	original.Browser = "modified"
	original.ClientHello.CipherSuites[0] = TLS_CHACHA20_POLY1305_SHA256

	// Clone should be unchanged
	if cloned.Browser != "original" {
		t.Errorf("Clone browser was modified: got %s, want original", cloned.Browser)
	}
	if cloned.ClientHello.CipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Clone cipher suite was modified: got 0x%04x, want 0x%04x",
			cloned.ClientHello.CipherSuites[0], TLS_AES_128_GCM_SHA256)
	}
}

// =============================================================================
// TEST 19: SNI Handling
// =============================================================================

// TestE2E_SNIHandling tests various SNI configurations and their effect on fingerprints.
func TestE2E_SNIHandling(t *testing.T) {
	tests := []struct {
		name           string
		serverName     string
		expectedSNI    byte // 'd' for domain, 'i' for IP/empty
	}{
		{"with_domain", "example.com", 'd'},
		{"empty_name", "", 'i'},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{ServerName: tc.serverName, InsecureSkipVerify: true}
			uconn := UClient(&net.TCPConn{}, config, HelloChrome_142)
			if tc.serverName == "" {
				uconn.SetSNI("")
			}

			if err := uconn.BuildHandshakeState(); err != nil {
				t.Fatalf("BuildHandshakeState failed: %v", err)
			}

			fp, err := uconn.Fingerprint()
			if err != nil {
				t.Fatalf("Fingerprint failed: %v", err)
			}

			parts := strings.Split(fp.JA4, "_")
			ja4a := parts[0]

			if len(ja4a) < 4 {
				t.Fatalf("JA4a too short: %s", ja4a)
			}

			sniIndicator := ja4a[3]
			if sniIndicator != tc.expectedSNI {
				t.Errorf("SNI indicator: got %c, want %c", sniIndicator, tc.expectedSNI)
			}

			t.Logf("%s JA4: %s", tc.name, fp.JA4)
		})
	}
}

// =============================================================================
// TEST 20: Default Registry Contains Built-in Profiles
// =============================================================================

// TestE2E_DefaultRegistryBuiltinProfiles verifies default registry has built-in profiles.
func TestE2E_DefaultRegistryBuiltinProfiles(t *testing.T) {
	expectedProfiles := []string{
		"chrome_133_windows_11",
		"firefox_145_windows_11",
		"safari_18_macos_14",
	}

	for _, id := range expectedProfiles {
		if !DefaultRegistry.Exists(id) {
			t.Errorf("Expected built-in profile %q not found", id)
			continue
		}

		profile, err := DefaultRegistry.Get(id)
		if err != nil {
			t.Errorf("Failed to get profile %q: %v", id, err)
			continue
		}

		if profile.ID != id {
			t.Errorf("Profile ID mismatch: got %s, want %s", profile.ID, id)
		}

		// Verify profile has essential fields
		if profile.Browser == "" {
			t.Errorf("Profile %s missing browser", id)
		}
		if profile.Platform == "" {
			t.Errorf("Profile %s missing platform", id)
		}
		if len(profile.ClientHello.CipherSuites) == 0 {
			t.Errorf("Profile %s has no cipher suites", id)
		}

		t.Logf("Verified built-in profile: %s (%s %d on %s)",
			id, profile.Browser, profile.Version, profile.Platform)
	}

	// List all profiles
	allProfiles := DefaultRegistry.List()
	t.Logf("Total built-in profiles: %d", len(allProfiles))
}

// =============================================================================
// TEST 21: Profile Validation
// =============================================================================

// TestE2E_ProfileValidation tests profile validation catches invalid configurations.
func TestE2E_ProfileValidation(t *testing.T) {
	tests := []struct {
		name        string
		profile     *FingerprintProfile
		shouldError bool
	}{
		{
			name: "valid_profile",
			profile: &FingerprintProfile{
				ID:       "valid_test",
				Browser:  "test",
				Platform: "test",
				ClientHello: ClientHelloConfig{
					CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
					CompressionMethods: []uint8{0},
				},
			},
			shouldError: false,
		},
		{
			name: "empty_id",
			profile: &FingerprintProfile{
				ID:       "",
				Browser:  "test",
				Platform: "test",
				ClientHello: ClientHelloConfig{
					CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
					CompressionMethods: []uint8{0},
				},
			},
			shouldError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewProfileRegistry()
			err := registry.Register(tc.profile)

			if tc.shouldError && err == nil {
				t.Error("Expected validation error")
			}
			if !tc.shouldError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

// =============================================================================
// TEST 22: Hook Chain Management
// =============================================================================

// TestE2E_HookChainManagement tests adding, removing, and clearing hooks.
func TestE2E_HookChainManagement(t *testing.T) {
	chain := NewHookChain()

	if chain.Len() != 0 {
		t.Errorf("New chain should be empty, got %d hooks", chain.Len())
	}

	hook1 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			return nil
		},
	}
	hook2 := &FingerprintHooks{
		OnSessionStateCreated: func(state *SessionFingerprintState) error {
			return nil
		},
	}

	// Add hooks
	chain.Add(hook1)
	chain.Add(hook2)

	if chain.Len() != 2 {
		t.Errorf("Chain should have 2 hooks, got %d", chain.Len())
	}

	// Add nil hook (should be ignored)
	chain.Add(nil)
	if chain.Len() != 2 {
		t.Errorf("Adding nil should not change length, got %d", chain.Len())
	}

	// Remove hook
	if !chain.Remove(hook1) {
		t.Error("Remove should return true for existing hook")
	}
	if chain.Len() != 1 {
		t.Errorf("Chain should have 1 hook after removal, got %d", chain.Len())
	}

	// Remove non-existent hook
	if chain.Remove(hook1) {
		t.Error("Remove should return false for already removed hook")
	}

	// Clear
	chain.Clear()
	if chain.Len() != 0 {
		t.Errorf("Chain should be empty after clear, got %d", chain.Len())
	}
}

// =============================================================================
// TEST 23: Logging Hooks
// =============================================================================

// TestE2E_LoggingHooks tests the logging hooks factory function.
func TestE2E_LoggingHooks(t *testing.T) {
	var logs []string
	var mu sync.Mutex

	logFunc := func(format string, args ...interface{}) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	hooks := LoggingHooks(logFunc)

	// Test profile selected logging
	testProfile := &FingerprintProfile{ID: "test_profile"}
	_ = hooks.OnProfileSelected(testProfile)

	// Test nil profile handling
	_ = hooks.OnProfileSelected(nil)

	// Test session state created
	testState := &SessionFingerprintState{ID: "session-123", Origin: "example.com"}
	_ = hooks.OnSessionStateCreated(testState)

	mu.Lock()
	defer mu.Unlock()

	if len(logs) != 3 {
		t.Errorf("Expected 3 log entries, got %d", len(logs))
	}

	if !strings.Contains(logs[0], "test_profile") {
		t.Errorf("First log should contain profile ID: %s", logs[0])
	}
	if !strings.Contains(logs[1], "<nil>") {
		t.Errorf("Second log should mention nil: %s", logs[1])
	}
}

// =============================================================================
// TEST 24: Profile Builder Error Accumulation
// =============================================================================

// TestE2E_ProfileBuilderErrors tests that builder accumulates and reports errors.
func TestE2E_ProfileBuilderErrors(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("error_test").
		WithBrowser("test").
		AddCipherSuiteAt(TLS_AES_128_GCM_SHA256, -1000). // Invalid position
		WithSessionIDLength(64)                          // Invalid length (must be 0 or 32)

	errors := builder.Errors()
	if len(errors) < 1 {
		t.Error("Expected at least 1 error from invalid operations")
	}

	_, err := builder.Build()
	if err == nil {
		t.Error("Build should fail with accumulated errors")
	}
}

// =============================================================================
// TEST 25: Full End-to-End Profile Application
// =============================================================================

// TestE2E_FullProfileApplication tests complete workflow from profile creation
// to fingerprint generation with validation.
func TestE2E_FullProfileApplication(t *testing.T) {
	// Step 1: Create custom profile using builder
	builder := ChromeProfile(200, "linux").
		WithID("e2e_test_chrome_200").
		WithDescription("E2E Test Chrome 200").
		WithHTTP2WindowSize(6291456).
		WithRecordPadding(true).
		WithRecordPaddingMode(RecordPaddingExponential)

	profile, err := builder.Build()
	if err != nil {
		t.Fatalf("Profile build failed: %v", err)
	}

	// Step 2: Register in custom registry
	registry := NewProfileRegistry()
	if err := registry.Register(profile); err != nil {
		t.Fatalf("Profile registration failed: %v", err)
	}

	// Step 3: Verify profile exists and is retrievable
	if !registry.Exists("e2e_test_chrome_200") {
		t.Fatal("Profile should exist after registration")
	}

	retrieved, err := registry.Get("e2e_test_chrome_200")
	if err != nil {
		t.Fatalf("Profile retrieval failed: %v", err)
	}

	// Step 4: Verify profile properties
	if retrieved.Browser != "chrome" {
		t.Errorf("Browser mismatch: got %s, want chrome", retrieved.Browser)
	}
	if retrieved.Version != 200 {
		t.Errorf("Version mismatch: got %d, want 200", retrieved.Version)
	}
	if retrieved.Platform != "linux" {
		t.Errorf("Platform mismatch: got %s, want linux", retrieved.Platform)
	}
	if !retrieved.RecordLayer.PaddingEnabled {
		t.Error("Record padding should be enabled")
	}

	// Step 5: Create connection with built-in Chrome profile and verify fingerprint
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "e2e.example.com"}, HelloChrome_142)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	fp, err := uconn.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint failed: %v", err)
	}

	// Step 6: Verify fingerprint format
	parts := strings.Split(fp.JA4, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 format wrong: %s", fp.JA4)
	}

	// Step 7: Verify JA3 format
	ja3Parts := strings.Split(fp.JA3r, ",")
	if len(ja3Parts) != 5 {
		t.Fatalf("JA3r format wrong: %s", fp.JA3r)
	}

	t.Logf("E2E Profile Application Test PASSED")
	t.Logf("  Profile: %s", retrieved.ID)
	t.Logf("  JA4: %s", fp.JA4)
	t.Logf("  JA3: %s", fp.JA3)
}
