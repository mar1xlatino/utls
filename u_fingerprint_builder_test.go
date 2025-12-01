// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"testing"
	"time"
)

// =============================================================================
// NewEmptyProfileBuilder Tests
// =============================================================================

// TestNewEmptyProfileBuilder_ReturnsNonNil verifies that NewEmptyProfileBuilder
// returns a non-nil builder instance.
func TestNewEmptyProfileBuilder_ReturnsNonNil(t *testing.T) {
	builder := NewEmptyProfileBuilder()
	if builder == nil {
		t.Fatal("NewEmptyProfileBuilder returned nil")
	}
}

// TestNewEmptyProfileBuilder_HasDefaultCompressionMethods verifies that an empty
// profile has compressionNone set by default.
func TestNewEmptyProfileBuilder_HasDefaultCompressionMethods(t *testing.T) {
	builder := NewEmptyProfileBuilder()
	profile := builder.Profile()

	if len(profile.ClientHello.CompressionMethods) != 1 {
		t.Errorf("expected 1 compression method, got %d", len(profile.ClientHello.CompressionMethods))
	}
	if profile.ClientHello.CompressionMethods[0] != 0 {
		t.Errorf("expected compression method 0 (none), got %d", profile.ClientHello.CompressionMethods[0])
	}
}

// TestNewEmptyProfileBuilder_HasDefaultSessionIDLength verifies that an empty
// profile has session ID length of 32 by default.
func TestNewEmptyProfileBuilder_HasDefaultSessionIDLength(t *testing.T) {
	builder := NewEmptyProfileBuilder()
	profile := builder.Profile()

	if profile.ClientHello.SessionIDLength != 32 {
		t.Errorf("expected session ID length 32, got %d", profile.ClientHello.SessionIDLength)
	}
}

// TestNewEmptyProfileBuilder_BuildReturnsValidEmptyProfile verifies that Build()
// returns a valid profile even when mostly empty (but must have ID and Browser).
func TestNewEmptyProfileBuilder_BuildReturnsValidEmptyProfile(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("test_empty").
		WithBrowser("test").
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256})

	profile, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed for minimal profile: %v", err)
	}
	if profile == nil {
		t.Fatal("Build() returned nil profile")
	}
	if profile.ID != "test_empty" {
		t.Errorf("expected ID 'test_empty', got %q", profile.ID)
	}
}

// =============================================================================
// NewProfileBuilderFrom Tests
// =============================================================================

// TestNewProfileBuilderFrom_NilReturnsEmptyBuilder verifies that passing nil
// to NewProfileBuilderFrom returns an empty builder (not panic).
func TestNewProfileBuilderFrom_NilReturnsEmptyBuilder(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewProfileBuilderFrom(nil) panicked: %v", r)
		}
	}()

	builder := NewProfileBuilderFrom(nil)
	if builder == nil {
		t.Fatal("NewProfileBuilderFrom(nil) returned nil")
	}

	// Should have default values like NewEmptyProfileBuilder
	profile := builder.Profile()
	if len(profile.ClientHello.CompressionMethods) != 1 || profile.ClientHello.CompressionMethods[0] != 0 {
		t.Error("NewProfileBuilderFrom(nil) did not return empty builder with defaults")
	}
}

// TestNewProfileBuilderFrom_CopiesAllFields verifies that all fields from the
// base profile are copied to the builder's profile.
func TestNewProfileBuilderFrom_CopiesAllFields(t *testing.T) {
	base := &FingerprintProfile{
		ID:          "base_profile",
		Browser:     "chrome",
		Version:     133,
		Platform:    "windows",
		OSVersion:   "11",
		Description: "Test base profile",
		ClientHello: ClientHelloConfig{
			LegacyVersion:     VersionTLS12,
			SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
			},
			SupportedGroups: []CurveID{X25519, CurveP256},
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
			},
			ALPNProtocols:      []string{"h2", "http/1.1"},
			ShuffleExtensions:  true,
			SessionIDLength:    32,
			CompressionMethods: []uint8{0},
			GREASE: GREASEConfig{
				Enabled:      true,
				CipherSuites: true,
			},
		},
	}

	builder := NewProfileBuilderFrom(base)
	profile := builder.Profile()

	// Verify all fields copied
	if profile.ID != base.ID {
		t.Errorf("ID not copied: got %q, want %q", profile.ID, base.ID)
	}
	if profile.Browser != base.Browser {
		t.Errorf("Browser not copied: got %q, want %q", profile.Browser, base.Browser)
	}
	if profile.Version != base.Version {
		t.Errorf("Version not copied: got %d, want %d", profile.Version, base.Version)
	}
	if profile.Platform != base.Platform {
		t.Errorf("Platform not copied: got %q, want %q", profile.Platform, base.Platform)
	}
	if profile.OSVersion != base.OSVersion {
		t.Errorf("OSVersion not copied: got %q, want %q", profile.OSVersion, base.OSVersion)
	}
	if len(profile.ClientHello.CipherSuites) != len(base.ClientHello.CipherSuites) {
		t.Errorf("CipherSuites not copied: got %d, want %d",
			len(profile.ClientHello.CipherSuites), len(base.ClientHello.CipherSuites))
	}
	if len(profile.ClientHello.ALPNProtocols) != len(base.ClientHello.ALPNProtocols) {
		t.Errorf("ALPNProtocols not copied: got %d, want %d",
			len(profile.ClientHello.ALPNProtocols), len(base.ClientHello.ALPNProtocols))
	}
	if profile.ClientHello.GREASE.Enabled != base.ClientHello.GREASE.Enabled {
		t.Errorf("GREASE.Enabled not copied: got %v, want %v",
			profile.ClientHello.GREASE.Enabled, base.ClientHello.GREASE.Enabled)
	}
}

// TestNewProfileBuilderFrom_DeepCopy verifies that modifications to the builder
// do not affect the original profile (deep copy verification).
func TestNewProfileBuilderFrom_DeepCopy(t *testing.T) {
	base := &FingerprintProfile{
		ID:      "original",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
			SupportedVersions:  []uint16{VersionTLS13, VersionTLS12},
			ALPNProtocols:      []string{"h2"},
			CompressionMethods: []uint8{0},
		},
	}

	builder := NewProfileBuilderFrom(base)

	// Modify the builder
	builder.WithID("modified")
	builder.WithCipherSuites([]uint16{TLS_CHACHA20_POLY1305_SHA256})
	builder.WithALPN([]string{"http/1.1"})

	// Original should be unchanged
	if base.ID != "original" {
		t.Errorf("original ID was modified: got %q, want 'original'", base.ID)
	}
	if len(base.ClientHello.CipherSuites) != 2 {
		t.Errorf("original CipherSuites were modified: got %d, want 2", len(base.ClientHello.CipherSuites))
	}
	if base.ClientHello.CipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Errorf("original CipherSuites[0] was modified")
	}
	if len(base.ClientHello.ALPNProtocols) != 1 || base.ClientHello.ALPNProtocols[0] != "h2" {
		t.Errorf("original ALPNProtocols were modified")
	}
}

// =============================================================================
// NewProfileBuilder (from registry) Tests
// =============================================================================

// TestNewProfileBuilder_ValidBaseID verifies that NewProfileBuilder works with
// a valid base profile ID from the registry.
func TestNewProfileBuilder_ValidBaseID(t *testing.T) {
	// chrome_133_windows_11 should be registered by default
	builder, err := NewProfileBuilder("chrome_133_windows_11")
	if err != nil {
		t.Fatalf("NewProfileBuilder failed with valid ID: %v", err)
	}
	if builder == nil {
		t.Fatal("NewProfileBuilder returned nil builder")
	}

	profile := builder.Profile()
	if profile.Browser != "chrome" {
		t.Errorf("expected browser 'chrome', got %q", profile.Browser)
	}
}

// TestNewProfileBuilder_InvalidBaseID verifies that NewProfileBuilder returns
// an error for non-existent profile IDs.
func TestNewProfileBuilder_InvalidBaseID(t *testing.T) {
	_, err := NewProfileBuilder("nonexistent_profile_12345")
	if err == nil {
		t.Fatal("NewProfileBuilder should return error for non-existent profile")
	}
}

// =============================================================================
// Fluent API Methods Tests
// =============================================================================

// TestWithID_SetsID verifies that WithID sets the profile ID.
func TestWithID_SetsID(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithID("test_id")
	profile := builder.Profile()

	if profile.ID != "test_id" {
		t.Errorf("expected ID 'test_id', got %q", profile.ID)
	}
}

// TestWithID_ReturnsBuilder verifies that WithID returns the builder for chaining.
func TestWithID_ReturnsBuilder(t *testing.T) {
	builder := NewEmptyProfileBuilder()
	result := builder.WithID("test")

	if result != builder {
		t.Error("WithID did not return the same builder for chaining")
	}
}

// TestWithBrowser_SetsBrowser verifies that WithBrowser sets the browser name.
func TestWithBrowser_SetsBrowser(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithBrowser("firefox")
	profile := builder.Profile()

	if profile.Browser != "firefox" {
		t.Errorf("expected Browser 'firefox', got %q", profile.Browser)
	}
}

// TestWithVersion_SetsVersion verifies that WithVersion sets the browser version.
func TestWithVersion_SetsVersion(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithVersion(145)
	profile := builder.Profile()

	if profile.Version != 145 {
		t.Errorf("expected Version 145, got %d", profile.Version)
	}
}

// TestWithPlatform_SetsPlatform verifies that WithPlatform sets the platform.
func TestWithPlatform_SetsPlatform(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithPlatform("linux")
	profile := builder.Profile()

	if profile.Platform != "linux" {
		t.Errorf("expected Platform 'linux', got %q", profile.Platform)
	}
}

// TestWithOSVersion_SetsOSVersion verifies that WithOSVersion sets the OS version.
func TestWithOSVersion_SetsOSVersion(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithOSVersion("22.04")
	profile := builder.Profile()

	if profile.OSVersion != "22.04" {
		t.Errorf("expected OSVersion '22.04', got %q", profile.OSVersion)
	}
}

// TestWithDescription_SetsDescription verifies that WithDescription sets the description.
func TestWithDescription_SetsDescription(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithDescription("Test profile description")
	profile := builder.Profile()

	if profile.Description != "Test profile description" {
		t.Errorf("expected Description 'Test profile description', got %q", profile.Description)
	}
}

// TestFluentChaining verifies that all methods can be chained together.
func TestFluentChaining(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("chain_test").
		WithBrowser("chrome").
		WithVersion(133).
		WithPlatform("windows").
		WithOSVersion("11").
		WithDescription("Chaining test")

	profile := builder.Profile()

	if profile.ID != "chain_test" {
		t.Errorf("ID not set in chain: got %q", profile.ID)
	}
	if profile.Browser != "chrome" {
		t.Errorf("Browser not set in chain: got %q", profile.Browser)
	}
	if profile.Version != 133 {
		t.Errorf("Version not set in chain: got %d", profile.Version)
	}
	if profile.Platform != "windows" {
		t.Errorf("Platform not set in chain: got %q", profile.Platform)
	}
	if profile.OSVersion != "11" {
		t.Errorf("OSVersion not set in chain: got %q", profile.OSVersion)
	}
	if profile.Description != "Chaining test" {
		t.Errorf("Description not set in chain: got %q", profile.Description)
	}
}

// =============================================================================
// Cipher Suite Methods Tests
// =============================================================================

// TestWithCipherSuites_SetsCiphers verifies that WithCipherSuites replaces ciphers.
func TestWithCipherSuites_SetsCiphers(t *testing.T) {
	ciphers := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}

	builder := NewEmptyProfileBuilder().WithCipherSuites(ciphers)
	profile := builder.Profile()

	if len(profile.ClientHello.CipherSuites) != 3 {
		t.Fatalf("expected 3 cipher suites, got %d", len(profile.ClientHello.CipherSuites))
	}
	for i, c := range ciphers {
		if profile.ClientHello.CipherSuites[i] != c {
			t.Errorf("cipher suite %d mismatch: got %d, want %d", i, profile.ClientHello.CipherSuites[i], c)
		}
	}
}

// TestWithCipherSuites_MakesCopy verifies that WithCipherSuites makes a copy.
func TestWithCipherSuites_MakesCopy(t *testing.T) {
	ciphers := []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}

	builder := NewEmptyProfileBuilder().WithCipherSuites(ciphers)

	// Modify original slice
	ciphers[0] = TLS_CHACHA20_POLY1305_SHA256

	profile := builder.Profile()
	if profile.ClientHello.CipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Error("WithCipherSuites did not make a copy of the slice")
	}
}

// TestAddCipherSuite_AppendsCipher verifies that AddCipherSuite appends a cipher.
func TestAddCipherSuite_AppendsCipher(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256}).
		AddCipherSuite(TLS_AES_256_GCM_SHA384)

	profile := builder.Profile()
	if len(profile.ClientHello.CipherSuites) != 2 {
		t.Fatalf("expected 2 cipher suites, got %d", len(profile.ClientHello.CipherSuites))
	}
	if profile.ClientHello.CipherSuites[1] != TLS_AES_256_GCM_SHA384 {
		t.Errorf("AddCipherSuite did not append correctly")
	}
}

// TestAddCipherSuiteAt_InsertsAtPosition verifies insertion at specific position.
func TestAddCipherSuiteAt_InsertsAtPosition(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256}).
		AddCipherSuiteAt(TLS_AES_256_GCM_SHA384, 1)

	profile := builder.Profile()
	if len(profile.ClientHello.CipherSuites) != 3 {
		t.Fatalf("expected 3 cipher suites, got %d", len(profile.ClientHello.CipherSuites))
	}
	if profile.ClientHello.CipherSuites[1] != TLS_AES_256_GCM_SHA384 {
		t.Errorf("cipher not inserted at position 1")
	}
}

// TestAddCipherSuiteAt_NegativePosition verifies insertion with negative position.
func TestAddCipherSuiteAt_NegativePosition(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256}).
		AddCipherSuiteAt(TLS_AES_256_GCM_SHA384, -1)

	profile := builder.Profile()
	// -1 should insert at position len-1+1 = len (at the end)
	if len(profile.ClientHello.CipherSuites) != 3 {
		t.Fatalf("expected 3 cipher suites, got %d", len(profile.ClientHello.CipherSuites))
	}
}

// TestAddCipherSuiteAt_InvalidPosition verifies error handling for invalid position.
func TestAddCipherSuiteAt_InvalidPosition(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256}).
		AddCipherSuiteAt(TLS_AES_256_GCM_SHA384, 100)

	errors := builder.Errors()
	if len(errors) == 0 {
		t.Error("expected error for invalid position, got none")
	}
}

// TestRemoveCipherSuite_RemovesCipher verifies that RemoveCipherSuite removes a cipher.
func TestRemoveCipherSuite_RemovesCipher(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}).
		RemoveCipherSuite(TLS_AES_256_GCM_SHA384)

	profile := builder.Profile()
	if len(profile.ClientHello.CipherSuites) != 2 {
		t.Fatalf("expected 2 cipher suites after removal, got %d", len(profile.ClientHello.CipherSuites))
	}
	for _, c := range profile.ClientHello.CipherSuites {
		if c == TLS_AES_256_GCM_SHA384 {
			t.Error("RemoveCipherSuite did not remove the cipher")
		}
	}
}

// TestRemoveCipherSuite_NonExistent verifies that removing non-existent cipher is no-op.
func TestRemoveCipherSuite_NonExistent(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256}).
		RemoveCipherSuite(TLS_AES_256_GCM_SHA384)

	profile := builder.Profile()
	if len(profile.ClientHello.CipherSuites) != 1 {
		t.Errorf("expected 1 cipher suite, got %d", len(profile.ClientHello.CipherSuites))
	}
}

// TestReorderCipherSuites verifies cipher suite reordering.
func TestReorderCipherSuites(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}).
		ReorderCipherSuites([]uint16{TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256})

	profile := builder.Profile()
	// Only ciphers in both lists should remain, in new order
	if len(profile.ClientHello.CipherSuites) != 2 {
		t.Fatalf("expected 2 cipher suites after reorder, got %d", len(profile.ClientHello.CipherSuites))
	}
	if profile.ClientHello.CipherSuites[0] != TLS_CHACHA20_POLY1305_SHA256 {
		t.Error("first cipher not reordered correctly")
	}
	if profile.ClientHello.CipherSuites[1] != TLS_AES_128_GCM_SHA256 {
		t.Error("second cipher not reordered correctly")
	}
}

// =============================================================================
// Extension Methods Tests
// =============================================================================

// TestWithExtensions_SetsExtensions verifies that WithExtensions replaces extensions.
func TestWithExtensions_SetsExtensions(t *testing.T) {
	exts := []uint16{0, 10, 11, 13, 43, 51}

	builder := NewEmptyProfileBuilder().WithExtensions(exts)
	profile := builder.Profile()

	if len(profile.ClientHello.Extensions) != 6 {
		t.Fatalf("expected 6 extensions, got %d", len(profile.ClientHello.Extensions))
	}
	for i, e := range exts {
		if profile.ClientHello.Extensions[i].Type != e {
			t.Errorf("extension %d type mismatch: got %d, want %d", i, profile.ClientHello.Extensions[i].Type, e)
		}
	}
}

// TestAddExtension_AppendsExtension verifies that AddExtension appends an extension.
func TestAddExtension_AppendsExtension(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithExtensions([]uint16{0, 10}).
		AddExtension(11)

	profile := builder.Profile()
	if len(profile.ClientHello.Extensions) != 3 {
		t.Fatalf("expected 3 extensions, got %d", len(profile.ClientHello.Extensions))
	}
	if profile.ClientHello.Extensions[2].Type != 11 {
		t.Errorf("AddExtension did not append correctly")
	}
}

// TestAddExtensionAt_InsertsAtPosition verifies insertion at specific position.
func TestAddExtensionAt_InsertsAtPosition(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithExtensions([]uint16{0, 11}).
		AddExtensionAt(10, 1)

	profile := builder.Profile()
	if len(profile.ClientHello.Extensions) != 3 {
		t.Fatalf("expected 3 extensions, got %d", len(profile.ClientHello.Extensions))
	}
	if profile.ClientHello.Extensions[1].Type != 10 {
		t.Errorf("extension not inserted at position 1: got type %d", profile.ClientHello.Extensions[1].Type)
	}
}

// TestRemoveExtension_RemovesExtension verifies that RemoveExtension removes an extension.
func TestRemoveExtension_RemovesExtension(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithExtensions([]uint16{0, 10, 11}).
		RemoveExtension(10)

	profile := builder.Profile()
	if len(profile.ClientHello.Extensions) != 2 {
		t.Fatalf("expected 2 extensions after removal, got %d", len(profile.ClientHello.Extensions))
	}
	for _, e := range profile.ClientHello.Extensions {
		if e.Type == 10 {
			t.Error("RemoveExtension did not remove the extension")
		}
	}
}

// TestWithExtensionOrder verifies extension reordering.
func TestWithExtensionOrder(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithExtensions([]uint16{0, 10, 11, 13}).
		WithExtensionOrder([]uint16{13, 10, 0})

	profile := builder.Profile()
	if len(profile.ClientHello.Extensions) != 3 {
		t.Fatalf("expected 3 extensions after reorder, got %d", len(profile.ClientHello.Extensions))
	}
	if profile.ClientHello.Extensions[0].Type != 13 {
		t.Error("first extension not reordered correctly")
	}
	if profile.ClientHello.Extensions[1].Type != 10 {
		t.Error("second extension not reordered correctly")
	}
}

// TestWithShuffleExtensions verifies shuffle setting.
func TestWithShuffleExtensions(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithShuffleExtensions(true)
	profile := builder.Profile()

	if !profile.ClientHello.ShuffleExtensions {
		t.Error("ShuffleExtensions not set to true")
	}

	builder = builder.WithShuffleExtensions(false)
	profile = builder.Profile()

	if profile.ClientHello.ShuffleExtensions {
		t.Error("ShuffleExtensions not set to false")
	}
}

// =============================================================================
// GREASE Configuration Tests
// =============================================================================

// TestWithGREASE_EnablesGREASE verifies that WithGREASE enables GREASE.
func TestWithGREASE_EnablesGREASE(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithGREASE(true)
	profile := builder.Profile()

	if !profile.ClientHello.GREASE.Enabled {
		t.Error("GREASE not enabled")
	}
}

// TestWithGREASE_DisablesGREASE verifies that WithGREASE disables GREASE.
func TestWithGREASE_DisablesGREASE(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithGREASE(true).WithGREASE(false)
	profile := builder.Profile()

	if profile.ClientHello.GREASE.Enabled {
		t.Error("GREASE not disabled")
	}
}

// TestWithGREASECipherSuites verifies GREASE cipher suite configuration.
func TestWithGREASECipherSuites(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithGREASECipherSuites(true)
	profile := builder.Profile()

	if !profile.ClientHello.GREASE.CipherSuites {
		t.Error("GREASE.CipherSuites not enabled")
	}
}

// TestWithGREASEExtensions verifies GREASE extension configuration.
func TestWithGREASEExtensions(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithGREASEExtensions(true)
	profile := builder.Profile()

	if !profile.ClientHello.GREASE.Extensions {
		t.Error("GREASE.Extensions not enabled")
	}
}

// TestWithGREASEGroups verifies GREASE groups configuration.
func TestWithGREASEGroups(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithGREASEGroups(true)
	profile := builder.Profile()

	if !profile.ClientHello.GREASE.SupportedGroups {
		t.Error("GREASE.SupportedGroups not enabled")
	}
}

// TestWithGREASEVersions verifies GREASE versions configuration.
func TestWithGREASEVersions(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithGREASEVersions(true)
	profile := builder.Profile()

	if !profile.ClientHello.GREASE.SupportedVersions {
		t.Error("GREASE.SupportedVersions not enabled")
	}
}

// TestWithGREASEKeyShare verifies GREASE key share configuration.
func TestWithGREASEKeyShare(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithGREASEKeyShare(true)
	profile := builder.Profile()

	if !profile.ClientHello.GREASE.KeyShare {
		t.Error("GREASE.KeyShare not enabled")
	}
}

// TestWithGREASEPositions verifies GREASE position configuration.
func TestWithGREASEPositions(t *testing.T) {
	positions := []int{0, -2}
	builder := NewEmptyProfileBuilder().WithGREASEPositions(positions)
	profile := builder.Profile()

	if len(profile.ClientHello.GREASE.ExtensionPositions) != 2 {
		t.Fatalf("expected 2 GREASE positions, got %d", len(profile.ClientHello.GREASE.ExtensionPositions))
	}
	if profile.ClientHello.GREASE.ExtensionPositions[0] != 0 {
		t.Errorf("expected first position 0, got %d", profile.ClientHello.GREASE.ExtensionPositions[0])
	}
	if profile.ClientHello.GREASE.ExtensionPositions[1] != -2 {
		t.Errorf("expected second position -2, got %d", profile.ClientHello.GREASE.ExtensionPositions[1])
	}
}

// =============================================================================
// Other ClientHello Configuration Tests
// =============================================================================

// TestWithSupportedGroups verifies supported groups configuration.
func TestWithSupportedGroups(t *testing.T) {
	groups := []CurveID{X25519, CurveP256, CurveP384}
	builder := NewEmptyProfileBuilder().WithSupportedGroups(groups)
	profile := builder.Profile()

	if len(profile.ClientHello.SupportedGroups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(profile.ClientHello.SupportedGroups))
	}
	for i, g := range groups {
		if profile.ClientHello.SupportedGroups[i] != g {
			t.Errorf("group %d mismatch", i)
		}
	}
}

// TestWithSignatureAlgorithms verifies signature algorithms configuration.
func TestWithSignatureAlgorithms(t *testing.T) {
	algs := []SignatureScheme{ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256}
	builder := NewEmptyProfileBuilder().WithSignatureAlgorithms(algs)
	profile := builder.Profile()

	if len(profile.ClientHello.SignatureAlgorithms) != 3 {
		t.Fatalf("expected 3 signature algorithms, got %d", len(profile.ClientHello.SignatureAlgorithms))
	}
	for i, a := range algs {
		if profile.ClientHello.SignatureAlgorithms[i] != a {
			t.Errorf("algorithm %d mismatch", i)
		}
	}
}

// TestWithALPN verifies ALPN protocol configuration.
func TestWithALPN(t *testing.T) {
	protocols := []string{"h2", "http/1.1"}
	builder := NewEmptyProfileBuilder().WithALPN(protocols)
	profile := builder.Profile()

	if len(profile.ClientHello.ALPNProtocols) != 2 {
		t.Fatalf("expected 2 ALPN protocols, got %d", len(profile.ClientHello.ALPNProtocols))
	}
	if profile.ClientHello.ALPNProtocols[0] != "h2" {
		t.Errorf("expected first protocol 'h2', got %q", profile.ClientHello.ALPNProtocols[0])
	}
	if profile.ClientHello.ALPNProtocols[1] != "http/1.1" {
		t.Errorf("expected second protocol 'http/1.1', got %q", profile.ClientHello.ALPNProtocols[1])
	}
}

// TestWithKeyShareGroups verifies key share groups configuration.
func TestWithKeyShareGroups(t *testing.T) {
	groups := []CurveID{X25519, CurveP256}
	builder := NewEmptyProfileBuilder().WithKeyShareGroups(groups)
	profile := builder.Profile()

	if len(profile.ClientHello.KeyShareGroups) != 2 {
		t.Fatalf("expected 2 key share groups, got %d", len(profile.ClientHello.KeyShareGroups))
	}
}

// TestWithPadding verifies padding configuration.
func TestWithPadding(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithPadding(PaddingChrome, 517)
	profile := builder.Profile()

	if profile.ClientHello.PaddingStyle != PaddingChrome {
		t.Errorf("expected PaddingChrome, got %d", profile.ClientHello.PaddingStyle)
	}
	if profile.ClientHello.PaddingTarget != 517 {
		t.Errorf("expected padding target 517, got %d", profile.ClientHello.PaddingTarget)
	}
}

// TestWithSessionIDLength_Valid verifies valid session ID length.
func TestWithSessionIDLength_Valid(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithSessionIDLength(32)
	profile := builder.Profile()

	if profile.ClientHello.SessionIDLength != 32 {
		t.Errorf("expected session ID length 32, got %d", profile.ClientHello.SessionIDLength)
	}

	builder = NewEmptyProfileBuilder().WithSessionIDLength(0)
	profile = builder.Profile()

	if profile.ClientHello.SessionIDLength != 0 {
		t.Errorf("expected session ID length 0, got %d", profile.ClientHello.SessionIDLength)
	}
}

// TestWithSessionIDLength_Invalid verifies invalid session ID length.
func TestWithSessionIDLength_Invalid(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithSessionIDLength(16)

	errors := builder.Errors()
	if len(errors) == 0 {
		t.Error("expected error for invalid session ID length 16")
	}
}

// TestWithSNIBehavior verifies SNI behavior configuration.
func TestWithSNIBehavior(t *testing.T) {
	testCases := []struct {
		behavior SNIBehavior
		name     string
	}{
		{SNIAlways, "SNIAlways"},
		{SNIDomainOnly, "SNIDomainOnly"},
		{SNINever, "SNINever"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			builder := NewEmptyProfileBuilder().WithSNIBehavior(tc.behavior)
			profile := builder.Profile()

			if profile.ClientHello.SNIBehavior != tc.behavior {
				t.Errorf("expected %s, got %d", tc.name, profile.ClientHello.SNIBehavior)
			}
		})
	}
}

// TestWithPSKModes verifies PSK modes configuration.
func TestWithPSKModes(t *testing.T) {
	modes := []uint8{1} // psk_dhe_ke
	builder := NewEmptyProfileBuilder().WithPSKModes(modes)
	profile := builder.Profile()

	if len(profile.ClientHello.PSKModes) != 1 {
		t.Fatalf("expected 1 PSK mode, got %d", len(profile.ClientHello.PSKModes))
	}
	if profile.ClientHello.PSKModes[0] != 1 {
		t.Errorf("expected PSK mode 1, got %d", profile.ClientHello.PSKModes[0])
	}
}

// TestWithSupportedVersions verifies supported versions configuration.
func TestWithSupportedVersions(t *testing.T) {
	versions := []uint16{VersionTLS13, VersionTLS12}
	builder := NewEmptyProfileBuilder().WithSupportedVersions(versions)
	profile := builder.Profile()

	if len(profile.ClientHello.SupportedVersions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(profile.ClientHello.SupportedVersions))
	}
}

// TestWithLegacyVersion verifies legacy version configuration.
func TestWithLegacyVersion(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithLegacyVersion(VersionTLS12)
	profile := builder.Profile()

	if profile.ClientHello.LegacyVersion != VersionTLS12 {
		t.Errorf("expected legacy version TLS 1.2, got %d", profile.ClientHello.LegacyVersion)
	}
}

// TestWithCertCompression verifies certificate compression configuration.
func TestWithCertCompression(t *testing.T) {
	algos := []CertCompressionAlgo{CertCompressionBrotli}
	builder := NewEmptyProfileBuilder().WithCertCompression(algos)
	profile := builder.Profile()

	if len(profile.ClientHello.CertCompressionAlgos) != 1 {
		t.Fatalf("expected 1 cert compression algo, got %d", len(profile.ClientHello.CertCompressionAlgos))
	}
}

// TestWithApplicationSettings verifies application settings configuration.
func TestWithApplicationSettings(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithApplicationSettings(true)
	profile := builder.Profile()

	if !profile.ClientHello.ApplicationSettings {
		t.Error("ApplicationSettings not enabled")
	}
}

// TestWithDelegatedCredentials verifies delegated credentials configuration.
func TestWithDelegatedCredentials(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithDelegatedCredentials(true)
	profile := builder.Profile()

	if !profile.ClientHello.DelegatedCredentials {
		t.Error("DelegatedCredentials not enabled")
	}
}

// =============================================================================
// Expected Fingerprint Tests
// =============================================================================

// TestWithExpectedJA3 verifies expected JA3 configuration.
func TestWithExpectedJA3(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithExpectedJA3("abc123")
	profile := builder.Profile()

	if profile.Expected.JA3 != "abc123" {
		t.Errorf("expected JA3 'abc123', got %q", profile.Expected.JA3)
	}
}

// TestWithExpectedJA4 verifies expected JA4 configuration.
func TestWithExpectedJA4(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithExpectedJA4("t13d1517h2_abc_def")
	profile := builder.Profile()

	if profile.Expected.JA4 != "t13d1517h2_abc_def" {
		t.Errorf("expected JA4 'abc_def_ghi', got %q", profile.Expected.JA4)
	}
}

// TestExpectJA4S verifies server expectation configuration.
func TestExpectJA4S(t *testing.T) {
	builder := NewEmptyProfileBuilder().ExpectJA4S("t1302h2_*", "t1301h2_*")
	profile := builder.Profile()

	if len(profile.ServerExpectations.AcceptableJA4S) != 2 {
		t.Fatalf("expected 2 acceptable JA4S patterns, got %d", len(profile.ServerExpectations.AcceptableJA4S))
	}
}

// TestExpectCiphers verifies expected cipher configuration.
func TestExpectCiphers(t *testing.T) {
	builder := NewEmptyProfileBuilder().ExpectCiphers(TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384)
	profile := builder.Profile()

	if len(profile.ServerExpectations.AcceptableCiphers) != 2 {
		t.Fatalf("expected 2 acceptable ciphers, got %d", len(profile.ServerExpectations.AcceptableCiphers))
	}
}

// TestExpectJA4X verifies expected JA4X configuration.
func TestExpectJA4X(t *testing.T) {
	builder := NewEmptyProfileBuilder().ExpectJA4X("*_*_*")
	profile := builder.Profile()

	if len(profile.ServerExpectations.Certificate.AcceptableJA4X) != 1 {
		t.Fatalf("expected 1 acceptable JA4X pattern, got %d", len(profile.ServerExpectations.Certificate.AcceptableJA4X))
	}
}

// =============================================================================
// Record Layer Configuration Tests
// =============================================================================

// TestWithRecordPadding verifies record padding configuration.
func TestWithRecordPadding(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithRecordPadding(true)
	profile := builder.Profile()

	if !profile.RecordLayer.PaddingEnabled {
		t.Error("RecordLayer.PaddingEnabled not set to true")
	}
}

// TestWithRecordPaddingMode verifies record padding mode configuration.
func TestWithRecordPaddingMode(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithRecordPaddingMode(RecordPaddingExponential)
	profile := builder.Profile()

	if profile.RecordLayer.PaddingMode != RecordPaddingExponential {
		t.Errorf("expected RecordPaddingExponential, got %d", profile.RecordLayer.PaddingMode)
	}
}

// TestWithPaddingLambda verifies padding lambda configuration.
func TestWithPaddingLambda(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithPaddingLambda(3.0)
	profile := builder.Profile()

	if profile.RecordLayer.PaddingLambda != 3.0 {
		t.Errorf("expected lambda 3.0, got %f", profile.RecordLayer.PaddingLambda)
	}
}

// TestWithMaxRecordSize verifies max record size configuration.
func TestWithMaxRecordSize(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithMaxRecordSize(16384)
	profile := builder.Profile()

	if profile.RecordLayer.MaxRecordSize != 16384 {
		t.Errorf("expected max record size 16384, got %d", profile.RecordLayer.MaxRecordSize)
	}
}

// =============================================================================
// Session Configuration Tests
// =============================================================================

// TestWithResumption verifies session resumption configuration.
func TestWithResumption(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithResumption(true)
	profile := builder.Profile()

	if !profile.Session.ResumptionEnabled {
		t.Error("Session.ResumptionEnabled not set to true")
	}
}

// TestWithEarlyData verifies early data configuration.
func TestWithEarlyData(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithEarlyData(true)
	profile := builder.Profile()

	if !profile.Session.EarlyDataEnabled {
		t.Error("Session.EarlyDataEnabled not set to true")
	}
}

// TestWithTicketLifetime verifies ticket lifetime configuration.
func TestWithTicketLifetime(t *testing.T) {
	lifetime := 24 * time.Hour
	builder := NewEmptyProfileBuilder().WithTicketLifetime(lifetime)
	profile := builder.Profile()

	if profile.Session.TicketLifetime != lifetime {
		t.Errorf("expected ticket lifetime %v, got %v", lifetime, profile.Session.TicketLifetime)
	}
}

// =============================================================================
// HTTP/2 Configuration Tests
// =============================================================================

// TestWithHTTP2Settings verifies HTTP/2 settings configuration.
func TestWithHTTP2Settings(t *testing.T) {
	settings := HTTP2FingerprintConfig{
		HeaderTableSize:      65536,
		EnablePush:           false,
		MaxConcurrentStreams: 1000,
		InitialWindowSize:    6291456,
	}

	builder := NewEmptyProfileBuilder().WithHTTP2Settings(settings)
	profile := builder.Profile()

	if profile.HTTP2.HeaderTableSize != 65536 {
		t.Errorf("expected HeaderTableSize 65536, got %d", profile.HTTP2.HeaderTableSize)
	}
	if profile.HTTP2.MaxConcurrentStreams != 1000 {
		t.Errorf("expected MaxConcurrentStreams 1000, got %d", profile.HTTP2.MaxConcurrentStreams)
	}
}

// TestWithHTTP2WindowSize verifies HTTP/2 window size configuration.
func TestWithHTTP2WindowSize(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithHTTP2WindowSize(6291456)
	profile := builder.Profile()

	if profile.HTTP2.InitialWindowSize != 6291456 {
		t.Errorf("expected InitialWindowSize 6291456, got %d", profile.HTTP2.InitialWindowSize)
	}
}

// TestWithHTTP2MaxStreams verifies HTTP/2 max streams configuration.
func TestWithHTTP2MaxStreams(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithHTTP2MaxStreams(100)
	profile := builder.Profile()

	if profile.HTTP2.MaxConcurrentStreams != 100 {
		t.Errorf("expected MaxConcurrentStreams 100, got %d", profile.HTTP2.MaxConcurrentStreams)
	}
}

// =============================================================================
// Build Tests
// =============================================================================

// TestBuild_ReturnsCompleteProfile verifies Build() returns complete profile.
func TestBuild_ReturnsCompleteProfile(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("build_test").
		WithBrowser("chrome").
		WithVersion(133).
		WithPlatform("linux").
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256})

	profile, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	if profile.ID != "build_test" {
		t.Errorf("profile ID mismatch")
	}
	if profile.Browser != "chrome" {
		t.Errorf("profile Browser mismatch")
	}
	if profile.Version != 133 {
		t.Errorf("profile Version mismatch")
	}
}

// TestBuild_ReturnsClone verifies Build() returns a clone, not the internal profile.
func TestBuild_ReturnsClone(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("clone_test").
		WithBrowser("chrome").
		WithVersion(133).
		WithPlatform("linux").
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256})

	profile1, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
	profile2, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}

	// Modify profile1
	profile1.ID = "modified"

	// profile2 should be unchanged
	if profile2.ID != "clone_test" {
		t.Error("Build() did not return independent clones")
	}
}

// TestBuild_FailsWithErrors verifies Build() fails when builder has errors.
func TestBuild_FailsWithErrors(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("error_test").
		WithBrowser("chrome").
		WithSessionIDLength(16) // Invalid - causes error

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail when builder has errors")
	}
}

// TestBuild_FailsValidation verifies Build() fails validation.
func TestBuild_FailsValidation(t *testing.T) {
	builder := NewEmptyProfileBuilder() // Missing ID and Browser

	_, err := builder.Build()
	if err == nil {
		t.Error("Build() should fail validation for empty ID/Browser")
	}
}

// =============================================================================
// Validate and Errors Tests
// =============================================================================

// TestValidate_ReturnsBuilderErrors verifies Validate() returns builder errors.
func TestValidate_ReturnsBuilderErrors(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithSessionIDLength(16) // Invalid

	errors := builder.Validate()
	if len(errors) == 0 {
		t.Error("Validate() should return builder errors")
	}
}

// TestValidate_ReturnsProfileErrors verifies Validate() returns profile validation errors.
func TestValidate_ReturnsProfileErrors(t *testing.T) {
	builder := NewEmptyProfileBuilder() // Missing ID and Browser

	errors := builder.Validate()
	if len(errors) == 0 {
		t.Error("Validate() should return profile validation errors")
	}
}

// TestErrors_ReturnsAccumulatedErrors verifies Errors() returns accumulated errors.
func TestErrors_ReturnsAccumulatedErrors(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithSessionIDLength(16). // Invalid
		AddCipherSuiteAt(0, 100) // Invalid position

	errors := builder.Errors()
	if len(errors) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(errors))
	}
}

// =============================================================================
// Clone Tests
// =============================================================================

// TestClone_CreatesIndependentCopy verifies Clone() creates independent copy.
func TestClone_CreatesIndependentCopy(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("original").
		WithBrowser("chrome").
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256})

	clone := builder.Clone()

	// Modify clone
	clone.WithID("cloned")

	// Original should be unchanged
	original := builder.Profile()
	if original.ID != "original" {
		t.Error("Clone() did not create independent copy")
	}
}

// TestClone_CopiesErrors verifies Clone() copies accumulated errors.
func TestClone_CopiesErrors(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithSessionIDLength(16) // Invalid

	clone := builder.Clone()

	if len(clone.Errors()) != len(builder.Errors()) {
		t.Error("Clone() did not copy errors")
	}
}

// =============================================================================
// Profile Method Tests
// =============================================================================

// TestProfile_ReturnsCurrentProfile verifies Profile() returns current profile.
func TestProfile_ReturnsCurrentProfile(t *testing.T) {
	builder := NewEmptyProfileBuilder().WithID("profile_test")
	profile := builder.Profile()

	if profile.ID != "profile_test" {
		t.Errorf("expected ID 'profile_test', got %q", profile.ID)
	}
}

// =============================================================================
// QuickProfile Tests
// =============================================================================

// TestQuickProfile_CreatesMinimalProfile verifies QuickProfile creates minimal profile.
func TestQuickProfile_CreatesMinimalProfile(t *testing.T) {
	builder := QuickProfile("quick_test", "chrome", "windows", 133)
	profile := builder.Profile()

	if profile.ID != "quick_test" {
		t.Errorf("expected ID 'quick_test', got %q", profile.ID)
	}
	if profile.Browser != "chrome" {
		t.Errorf("expected Browser 'chrome', got %q", profile.Browser)
	}
	if profile.Platform != "windows" {
		t.Errorf("expected Platform 'windows', got %q", profile.Platform)
	}
	if profile.Version != 133 {
		t.Errorf("expected Version 133, got %d", profile.Version)
	}
}

// =============================================================================
// Browser Template Tests
// =============================================================================

// TestChromeProfile_SetsCorrectDefaults verifies ChromeProfile sets Chrome defaults.
func TestChromeProfile_SetsCorrectDefaults(t *testing.T) {
	builder := ChromeProfile(142, "windows_11")
	profile := builder.Profile()

	if profile.Browser != "chrome" {
		t.Errorf("expected Browser 'chrome', got %q", profile.Browser)
	}
	if profile.Version != 142 {
		t.Errorf("expected Version 142, got %d", profile.Version)
	}
	if !profile.ClientHello.GREASE.Enabled {
		t.Error("Chrome profile should have GREASE enabled")
	}
	if !profile.ClientHello.ShuffleExtensions {
		t.Error("Chrome profile should have extension shuffling enabled")
	}
	if profile.ClientHello.PaddingStyle != PaddingChrome {
		t.Error("Chrome profile should have Chrome padding style")
	}
	if profile.ClientHello.PaddingTarget != 517 {
		t.Errorf("Chrome profile should have padding target 517, got %d", profile.ClientHello.PaddingTarget)
	}
}

// TestFirefoxProfile_SetsCorrectDefaults verifies FirefoxProfile sets Firefox defaults.
func TestFirefoxProfile_SetsCorrectDefaults(t *testing.T) {
	builder := FirefoxProfile(145, "windows_11")
	profile := builder.Profile()

	if profile.Browser != "firefox" {
		t.Errorf("expected Browser 'firefox', got %q", profile.Browser)
	}
	if profile.Version != 145 {
		t.Errorf("expected Version 145, got %d", profile.Version)
	}
	if profile.ClientHello.GREASE.Enabled {
		t.Error("Firefox profile should have GREASE disabled")
	}
	if profile.ClientHello.ShuffleExtensions {
		t.Error("Firefox profile should have extension shuffling disabled")
	}
}

// TestSafariProfile_SetsCorrectDefaults verifies SafariProfile sets Safari defaults.
func TestSafariProfile_SetsCorrectDefaults(t *testing.T) {
	builder := SafariProfile(18, "macos_14")
	profile := builder.Profile()

	if profile.Browser != "safari" {
		t.Errorf("expected Browser 'safari', got %q", profile.Browser)
	}
	if profile.Version != 18 {
		t.Errorf("expected Version 18, got %d", profile.Version)
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

// TestEmptySliceInputs verifies handling of empty slice inputs.
func TestEmptySliceInputs(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites([]uint16{}).
		WithExtensions([]uint16{}).
		WithSupportedGroups([]CurveID{}).
		WithSignatureAlgorithms([]SignatureScheme{}).
		WithALPN([]string{})

	profile := builder.Profile()

	if len(profile.ClientHello.CipherSuites) != 0 {
		t.Error("expected empty CipherSuites")
	}
	if len(profile.ClientHello.Extensions) != 0 {
		t.Error("expected empty Extensions")
	}
}

// TestNilSliceInputs verifies handling of nil slice inputs.
func TestNilSliceInputs(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithCipherSuites(nil).
		WithExtensions(nil).
		WithALPN(nil)

	profile := builder.Profile()

	// Should create empty slices, not nil
	if profile.ClientHello.CipherSuites == nil {
		t.Error("CipherSuites should be empty slice, not nil")
	}
}

// TestChainedModifications verifies multiple chained modifications work correctly.
func TestChainedModifications(t *testing.T) {
	builder := NewEmptyProfileBuilder().
		WithID("chain").
		WithBrowser("test").
		WithCipherSuites([]uint16{TLS_AES_128_GCM_SHA256}).
		AddCipherSuite(TLS_AES_256_GCM_SHA384).
		AddCipherSuite(TLS_CHACHA20_POLY1305_SHA256).
		RemoveCipherSuite(TLS_AES_256_GCM_SHA384)

	profile := builder.Profile()

	if len(profile.ClientHello.CipherSuites) != 2 {
		t.Fatalf("expected 2 cipher suites after chain, got %d", len(profile.ClientHello.CipherSuites))
	}
	if profile.ClientHello.CipherSuites[0] != TLS_AES_128_GCM_SHA256 {
		t.Error("first cipher mismatch after chain")
	}
	if profile.ClientHello.CipherSuites[1] != TLS_CHACHA20_POLY1305_SHA256 {
		t.Error("second cipher mismatch after chain")
	}
}
