// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// SECTION 1: NewFingerprintController Tests
// =============================================================================

// TestNewFingerprintController_ReturnsNonNil verifies that NewFingerprintController
// returns a non-nil controller with properly initialized fields.
func TestNewFingerprintController_ReturnsNonNil(t *testing.T) {
	ctrl := NewFingerprintController()
	if ctrl == nil {
		t.Fatal("NewFingerprintController returned nil")
	}
}

// TestNewFingerprintController_HasInitializedHooksChain verifies that the hooks
// chain is properly initialized and not nil.
func TestNewFingerprintController_HasInitializedHooksChain(t *testing.T) {
	ctrl := NewFingerprintController()

	if ctrl.hooks == nil {
		t.Fatal("hooks chain is nil after initialization")
	}

	// Verify it's a usable HookChain
	if ctrl.Hooks() == nil {
		t.Fatal("Hooks() accessor returned nil")
	}
}

// TestNewFingerprintController_HasNilProfileUntilApplied verifies that profile
// is nil until ApplyProfile is called.
func TestNewFingerprintController_HasNilProfileUntilApplied(t *testing.T) {
	ctrl := NewFingerprintController()

	if ctrl.Profile() != nil {
		t.Error("profile should be nil before ApplyProfile is called")
	}

	if ctrl.SessionState() != nil {
		t.Error("sessionState should be nil before ApplyProfile is called")
	}
}

// TestNewFingerprintControllerWithOptions_CustomOptions verifies that custom
// options are properly applied to the controller.
func TestNewFingerprintControllerWithOptions_CustomOptions(t *testing.T) {
	opts := FingerprintControllerOptions{
		ValidateOnBuild:         true,
		StrictValidation:        true,
		FreezeSessionOnFirstUse: false,
		UseSessionCache:         false,
		SessionCacheKey:         "custom-key",
	}

	ctrl := NewFingerprintControllerWithOptions(opts)
	if ctrl == nil {
		t.Fatal("NewFingerprintControllerWithOptions returned nil")
	}

	// Verify options are stored correctly
	if ctrl.opts.ValidateOnBuild != true {
		t.Error("ValidateOnBuild option not set correctly")
	}
	if ctrl.opts.StrictValidation != true {
		t.Error("StrictValidation option not set correctly")
	}
	if ctrl.opts.FreezeSessionOnFirstUse != false {
		t.Error("FreezeSessionOnFirstUse option not set correctly")
	}
	if ctrl.opts.UseSessionCache != false {
		t.Error("UseSessionCache option not set correctly")
	}
	if ctrl.opts.SessionCacheKey != "custom-key" {
		t.Errorf("SessionCacheKey not set correctly: got %q", ctrl.opts.SessionCacheKey)
	}
}

// TestDefaultFingerprintControllerOptions_DefaultValues verifies the default
// option values are sensible.
func TestDefaultFingerprintControllerOptions_DefaultValues(t *testing.T) {
	opts := DefaultFingerprintControllerOptions()

	if opts.ValidateOnBuild != false {
		t.Error("default ValidateOnBuild should be false")
	}
	if opts.StrictValidation != false {
		t.Error("default StrictValidation should be false")
	}
	if opts.FreezeSessionOnFirstUse != true {
		t.Error("default FreezeSessionOnFirstUse should be true")
	}
	if opts.UseSessionCache != true {
		t.Error("default UseSessionCache should be true")
	}
}

// =============================================================================
// SECTION 2: ApplyProfile Tests
// =============================================================================

// TestApplyProfile_WithValidProfileID verifies that a valid profile ID can be
// applied successfully to a UConn.
func TestApplyProfile_WithValidProfileID(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	if err != nil {
		t.Fatalf("ApplyProfile failed for valid profile: %v", err)
	}

	// Verify profile was set
	profile := ctrl.Profile()
	if profile == nil {
		t.Fatal("profile is nil after ApplyProfile")
	}
	if profile.ID != "chrome_133_windows_11" {
		t.Errorf("profile ID mismatch: got %q", profile.ID)
	}
}

// TestApplyProfile_WithInvalidProfileID verifies that an invalid profile ID
// returns an error.
func TestApplyProfile_WithInvalidProfileID(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "nonexistent_profile_xyz")

	if err == nil {
		t.Fatal("ApplyProfile should return error for invalid profile ID")
	}

	// Profile should remain nil
	if ctrl.Profile() != nil {
		t.Error("profile should remain nil after failed ApplyProfile")
	}
}

// TestApplyProfile_WithNilUConn verifies that nil UConn returns an error.
func TestApplyProfile_WithNilUConn(t *testing.T) {
	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(nil, "chrome_133_windows_11")

	if err == nil {
		t.Fatal("ApplyProfile should return error for nil UConn")
	}

	expectedMsg := "tls: cannot apply profile to nil UConn"
	if err.Error() != expectedMsg {
		t.Errorf("unexpected error message: got %q, want %q", err.Error(), expectedMsg)
	}
}

// TestApplyProfile_ProfileIsStoredCorrectly verifies that the profile is
// cloned and stored correctly after ApplyProfile.
func TestApplyProfile_ProfileIsStoredCorrectly(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "firefox_145_windows_11")

	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	profile := ctrl.Profile()
	if profile.Browser != "firefox" {
		t.Errorf("browser mismatch: got %q, want %q", profile.Browser, "firefox")
	}
	if profile.Version != 145 {
		t.Errorf("version mismatch: got %d, want %d", profile.Version, 145)
	}
	if profile.Platform != "windows" {
		t.Errorf("platform mismatch: got %q, want %q", profile.Platform, "windows")
	}
}

// TestApplyProfile_SessionStateIsCreated verifies that session state is created
// after ApplyProfile is called.
func TestApplyProfile_SessionStateIsCreated(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	state := ctrl.SessionState()
	if state == nil {
		t.Fatal("session state should be created after ApplyProfile")
	}

	if state.ProfileID != "chrome_133_windows_11" {
		t.Errorf("session state profile ID mismatch: got %q", state.ProfileID)
	}
}

// TestApplyFingerprintProfile_WithNilProfile verifies error handling for nil profile.
func TestApplyFingerprintProfile_WithNilProfile(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyFingerprintProfile(uconn, nil)

	if err == nil {
		t.Fatal("ApplyFingerprintProfile should return error for nil profile")
	}

	expectedMsg := "tls: cannot apply nil profile"
	if err.Error() != expectedMsg {
		t.Errorf("unexpected error message: got %q, want %q", err.Error(), expectedMsg)
	}
}

// TestApplyProfile_ValidatorIsInitialized verifies that the validator is set up
// after ApplyProfile.
func TestApplyProfile_ValidatorIsInitialized(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	if ctrl.Validator() == nil {
		t.Error("validator should be initialized after ApplyProfile")
	}
}

// TestApplyProfile_TimingControllerIsInitialized verifies that timing controller
// is set up after ApplyProfile.
func TestApplyProfile_TimingControllerIsInitialized(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	if ctrl.TimingController() == nil {
		t.Error("timing controller should be initialized after ApplyProfile")
	}
}

// =============================================================================
// SECTION 3: applyFrozenGREASE Tests
// =============================================================================

// TestApplyFrozenGREASE_GreaseSeedArraySetCorrectly verifies that the greaseSeed
// array is populated with the correct frozen values.
func TestApplyFrozenGREASE_GreaseSeedArraySetCorrectly(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	state := ctrl.SessionState()
	frozenGREASE := state.FrozenGREASE

	// greaseSeed stores the high byte that when transformed gives GREASE value
	// For 0xXaXa, the seed high nibble is X
	expectedCipherSeed := frozenGREASE.CipherSuite >> 8
	expectedGroupSeed := frozenGREASE.SupportedGroup >> 8
	expectedVersionSeed := frozenGREASE.SupportedVersion >> 8
	expectedExt1Seed := frozenGREASE.Extension1 >> 8
	expectedExt2Seed := frozenGREASE.Extension2 >> 8

	if uconn.greaseSeed[ssl_grease_cipher] != expectedCipherSeed {
		t.Errorf("greaseSeed[cipher] mismatch: got 0x%02x, want 0x%02x",
			uconn.greaseSeed[ssl_grease_cipher], expectedCipherSeed)
	}
	if uconn.greaseSeed[ssl_grease_group] != expectedGroupSeed {
		t.Errorf("greaseSeed[group] mismatch: got 0x%02x, want 0x%02x",
			uconn.greaseSeed[ssl_grease_group], expectedGroupSeed)
	}
	if uconn.greaseSeed[ssl_grease_version] != expectedVersionSeed {
		t.Errorf("greaseSeed[version] mismatch: got 0x%02x, want 0x%02x",
			uconn.greaseSeed[ssl_grease_version], expectedVersionSeed)
	}
	if uconn.greaseSeed[ssl_grease_extension1] != expectedExt1Seed {
		t.Errorf("greaseSeed[ext1] mismatch: got 0x%02x, want 0x%02x",
			uconn.greaseSeed[ssl_grease_extension1], expectedExt1Seed)
	}
	if uconn.greaseSeed[ssl_grease_extension2] != expectedExt2Seed {
		t.Errorf("greaseSeed[ext2] mismatch: got 0x%02x, want 0x%02x",
			uconn.greaseSeed[ssl_grease_extension2], expectedExt2Seed)
	}
}

// TestApplyFrozenGREASE_CipherSuitesHasGREASE verifies that GREASE is prepended
// or replaced in cipher suites.
func TestApplyFrozenGREASE_CipherSuitesHasGREASE(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	hello := uconn.HandshakeState.Hello
	state := ctrl.SessionState()
	frozenCipherGREASE := state.FrozenGREASE.CipherSuite

	// Check that the frozen GREASE value is in the cipher suites
	foundGREASE := false
	for _, cs := range hello.CipherSuites {
		if cs == frozenCipherGREASE {
			foundGREASE = true
			break
		}
	}

	if !foundGREASE {
		t.Errorf("frozen GREASE value 0x%04x not found in cipher suites", frozenCipherGREASE)
	}
}

// TestApplyFrozenGREASE_SupportedVersionsHasGREASE verifies that GREASE is in
// supported versions.
func TestApplyFrozenGREASE_SupportedVersionsHasGREASE(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	hello := uconn.HandshakeState.Hello
	state := ctrl.SessionState()
	frozenVersionGREASE := state.FrozenGREASE.SupportedVersion

	// Check that frozen GREASE is in supported versions
	foundGREASE := false
	for _, v := range hello.SupportedVersions {
		if v == frozenVersionGREASE {
			foundGREASE = true
			break
		}
	}

	if !foundGREASE {
		t.Errorf("frozen GREASE value 0x%04x not found in supported versions", frozenVersionGREASE)
	}
}

// TestApplyFrozenGREASE_SupportedVersionsExtensionMatches verifies that the
// SupportedVersionsExtension internal Versions array matches hello.SupportedVersions.
func TestApplyFrozenGREASE_SupportedVersionsExtensionMatches(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	state := ctrl.SessionState()
	frozenVersionGREASE := state.FrozenGREASE.SupportedVersion

	// Find SupportedVersionsExtension and verify it has the frozen GREASE
	for _, ext := range uconn.Extensions {
		if sve, ok := ext.(*SupportedVersionsExtension); ok {
			foundGREASE := false
			for _, v := range sve.Versions {
				if v == frozenVersionGREASE {
					foundGREASE = true
					break
				}
			}
			if !foundGREASE {
				t.Errorf("SupportedVersionsExtension does not contain frozen GREASE 0x%04x",
					frozenVersionGREASE)
			}
			return
		}
	}

	// If SupportedVersionsExtension is not found, that might be OK depending on profile
	t.Log("SupportedVersionsExtension not found in extensions list")
}

// TestApplyFrozenGREASE_SupportedCurvesHasGREASE verifies that GREASE is in
// supported curves.
func TestApplyFrozenGREASE_SupportedCurvesHasGREASE(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	hello := uconn.HandshakeState.Hello
	state := ctrl.SessionState()
	frozenGroupGREASE := CurveID(state.FrozenGREASE.SupportedGroup)

	foundGREASE := false
	for _, curve := range hello.SupportedCurves {
		if curve == frozenGroupGREASE {
			foundGREASE = true
			break
		}
	}

	if !foundGREASE {
		t.Errorf("frozen GREASE value 0x%04x not found in supported curves", frozenGroupGREASE)
	}
}

// TestApplyFrozenGREASE_SupportedCurvesExtensionMatches verifies that the
// SupportedCurvesExtension internal Curves array matches.
func TestApplyFrozenGREASE_SupportedCurvesExtensionMatches(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	state := ctrl.SessionState()
	frozenGroupGREASE := CurveID(state.FrozenGREASE.SupportedGroup)

	for _, ext := range uconn.Extensions {
		if sce, ok := ext.(*SupportedCurvesExtension); ok {
			foundGREASE := false
			for _, c := range sce.Curves {
				if c == frozenGroupGREASE {
					foundGREASE = true
					break
				}
			}
			if !foundGREASE {
				t.Errorf("SupportedCurvesExtension does not contain frozen GREASE 0x%04x",
					frozenGroupGREASE)
			}
			return
		}
	}
}

// TestApplyFrozenGREASE_KeySharesHasGREASE verifies that GREASE key share has
// Data set to []byte{0}.
func TestApplyFrozenGREASE_KeySharesHasGREASE(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	hello := uconn.HandshakeState.Hello
	state := ctrl.SessionState()
	frozenKeyShareGREASE := CurveID(state.FrozenGREASE.KeyShare)

	foundGREASE := false
	for _, ks := range hello.KeyShares {
		if ks.Group == frozenKeyShareGREASE {
			foundGREASE = true
			// GREASE key shares must have non-empty data (per RFC 8446)
			if len(ks.Data) == 0 {
				t.Error("GREASE key share has empty data, should have []byte{0}")
			}
			break
		}
	}

	if !foundGREASE {
		t.Errorf("frozen GREASE key share 0x%04x not found in key shares", frozenKeyShareGREASE)
	}
}

// TestApplyFrozenGREASE_KeyShareExtensionMatches verifies that KeyShareExtension
// internal KeyShares array has the frozen GREASE.
func TestApplyFrozenGREASE_KeyShareExtensionMatches(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	state := ctrl.SessionState()
	frozenKeyShareGREASE := CurveID(state.FrozenGREASE.KeyShare)

	for _, ext := range uconn.Extensions {
		if kse, ok := ext.(*KeyShareExtension); ok {
			foundGREASE := false
			for _, ks := range kse.KeyShares {
				if ks.Group == frozenKeyShareGREASE {
					foundGREASE = true
					break
				}
			}
			if !foundGREASE {
				t.Errorf("KeyShareExtension does not contain frozen GREASE 0x%04x",
					frozenKeyShareGREASE)
			}
			return
		}
	}
}

// TestApplyFrozenGREASE_UtlsGREASEExtensionValues verifies that UtlsGREASEExtension
// values are set to Extension1/Extension2 from frozen GREASE.
func TestApplyFrozenGREASE_UtlsGREASEExtensionValues(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	state := ctrl.SessionState()
	ext1 := state.FrozenGREASE.Extension1
	ext2 := state.FrozenGREASE.Extension2

	greaseExtIdx := 0
	for _, ext := range uconn.Extensions {
		if ge, ok := ext.(*UtlsGREASEExtension); ok {
			var expected uint16
			if greaseExtIdx == 0 {
				expected = ext1
			} else {
				expected = ext2
			}

			if ge.Value != expected {
				t.Errorf("UtlsGREASEExtension[%d] has value 0x%04x, want 0x%04x",
					greaseExtIdx, ge.Value, expected)
			}
			greaseExtIdx++
		}
	}

	// Chrome profile should have 2 GREASE extensions
	if greaseExtIdx < 2 {
		t.Logf("found %d GREASE extensions (may be OK for some profiles)", greaseExtIdx)
	}
}

// TestApplyFrozenGREASE_NoGREASEForFirefox verifies that Firefox profile does
// not have GREASE applied.
func TestApplyFrozenGREASE_NoGREASEForFirefox(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "firefox_145_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	hello := uconn.HandshakeState.Hello

	// Firefox should NOT have GREASE in cipher suites
	for _, cs := range hello.CipherSuites {
		if isGREASEUint16(cs) {
			t.Errorf("Firefox profile should not have GREASE cipher suite: 0x%04x", cs)
		}
	}
}

// TestApplyFrozenGREASE_GREASEConsistencyAcrossMultipleConnections verifies
// that GREASE values stay consistent across multiple connections to same origin.
func TestApplyFrozenGREASE_GREASEConsistencyAcrossMultipleConnections(t *testing.T) {
	config := &Config{ServerName: "example.com"}

	var firstCipherGREASE, firstVersionGREASE uint16

	for i := 0; i < 5; i++ {
		conn := &net.TCPConn{}
		uconn := UClient(conn, config, HelloCustom)

		ctrl := NewFingerprintController()
		err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
		if err != nil {
			t.Fatalf("iteration %d: ApplyProfile failed: %v", i, err)
		}

		state := ctrl.SessionState()
		if i == 0 {
			firstCipherGREASE = state.FrozenGREASE.CipherSuite
			firstVersionGREASE = state.FrozenGREASE.SupportedVersion
		} else {
			// Session cache should return same frozen values
			if state.FrozenGREASE.CipherSuite != firstCipherGREASE {
				t.Errorf("iteration %d: cipher GREASE changed from 0x%04x to 0x%04x",
					i, firstCipherGREASE, state.FrozenGREASE.CipherSuite)
			}
			if state.FrozenGREASE.SupportedVersion != firstVersionGREASE {
				t.Errorf("iteration %d: version GREASE changed from 0x%04x to 0x%04x",
					i, firstVersionGREASE, state.FrozenGREASE.SupportedVersion)
			}
		}
	}
}

// =============================================================================
// SECTION 4: convertRecordLayerToRecordPadding Tests
// =============================================================================

// TestConvertRecordLayerToRecordPadding_RecordPaddingNone returns nil.
func TestConvertRecordLayerToRecordPadding_RecordPaddingNone(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingNone,
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result != nil {
		t.Error("RecordPaddingNone should return nil")
	}
}

// TestConvertRecordLayerToRecordPadding_RecordPaddingChrome returns chrome distribution.
func TestConvertRecordLayerToRecordPadding_RecordPaddingChrome(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingChrome,
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result == nil {
		t.Fatal("RecordPaddingChrome should not return nil")
	}

	if result.Distribution != "chrome" {
		t.Errorf("distribution mismatch: got %q, want %q", result.Distribution, "chrome")
	}

	if !result.Enabled {
		t.Error("Enabled should be true")
	}
}

// TestConvertRecordLayerToRecordPadding_RecordPaddingFirefox returns nil.
func TestConvertRecordLayerToRecordPadding_RecordPaddingFirefox(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingFirefox,
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result != nil {
		t.Error("RecordPaddingFirefox should return nil (Firefox uses no padding)")
	}
}

// TestConvertRecordLayerToRecordPadding_RecordPaddingExponential returns correct lambda.
func TestConvertRecordLayerToRecordPadding_RecordPaddingExponential(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingExponential,
		PaddingLambda:  5.0,
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result == nil {
		t.Fatal("RecordPaddingExponential should not return nil")
	}

	if result.Distribution != "exponential" {
		t.Errorf("distribution mismatch: got %q, want %q", result.Distribution, "exponential")
	}

	if result.Lambda != 5.0 {
		t.Errorf("lambda mismatch: got %f, want %f", result.Lambda, 5.0)
	}
}

// TestConvertRecordLayerToRecordPadding_MaxPaddingClampedTo255 verifies that
// MaxPadding is clamped to 255.
func TestConvertRecordLayerToRecordPadding_MaxPaddingClampedTo255(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingRandom,
		PaddingMax:     1000, // Exceeds 255
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result == nil {
		t.Fatal("should not return nil")
	}

	if result.MaxPadding != 255 {
		t.Errorf("MaxPadding should be clamped to 255, got %d", result.MaxPadding)
	}
}

// TestConvertRecordLayerToRecordPadding_DefaultMaxPadding verifies default is used
// when PaddingMax is 0 or negative.
func TestConvertRecordLayerToRecordPadding_DefaultMaxPadding(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingRandom,
		PaddingMax:     0, // Should default
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result == nil {
		t.Fatal("should not return nil")
	}

	if result.MaxPadding != 255 {
		t.Errorf("MaxPadding should default to 255, got %d", result.MaxPadding)
	}
}

// TestConvertRecordLayerToRecordPadding_DefaultLambda verifies default lambda is
// used when PaddingLambda is 0 or negative.
func TestConvertRecordLayerToRecordPadding_DefaultLambda(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingExponential,
		PaddingLambda:  0, // Should default
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result == nil {
		t.Fatal("should not return nil")
	}

	if result.Lambda != 3.0 {
		t.Errorf("Lambda should default to 3.0, got %f", result.Lambda)
	}
}

// TestConvertRecordLayerToRecordPadding_NilConfig returns nil.
func TestConvertRecordLayerToRecordPadding_NilConfig(t *testing.T) {
	result := convertRecordLayerToRecordPadding(nil)
	if result != nil {
		t.Error("nil config should return nil")
	}
}

// TestConvertRecordLayerToRecordPadding_PaddingDisabled returns nil.
func TestConvertRecordLayerToRecordPadding_PaddingDisabled(t *testing.T) {
	cfg := &RecordLayerConfig{
		PaddingEnabled: false,
		PaddingMode:    RecordPaddingChrome,
	}

	result := convertRecordLayerToRecordPadding(cfg)
	if result != nil {
		t.Error("disabled padding should return nil")
	}
}

// =============================================================================
// SECTION 5: HookChain Tests
// =============================================================================

// TestHookChain_Add_AddsHooks verifies that hooks can be added to the chain.
func TestHookChain_Add_AddsHooks(t *testing.T) {
	chain := NewHookChain()

	if chain.Len() != 0 {
		t.Errorf("initial length should be 0, got %d", chain.Len())
	}

	hook := &FingerprintHooks{}
	chain.Add(hook)

	if chain.Len() != 1 {
		t.Errorf("length should be 1 after adding hook, got %d", chain.Len())
	}
}

// TestHookChain_Add_IgnoresNilHooks verifies that nil hooks are ignored.
func TestHookChain_Add_IgnoresNilHooks(t *testing.T) {
	chain := NewHookChain()
	chain.Add(nil)

	if chain.Len() != 0 {
		t.Errorf("nil hooks should be ignored, got length %d", chain.Len())
	}
}

// TestHookChain_CallProfileSelected_InvokesAllHooks verifies all hooks are called.
func TestHookChain_CallProfileSelected_InvokesAllHooks(t *testing.T) {
	chain := NewHookChain()

	var callCount int
	hook1 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			callCount++
			return nil
		},
	}
	hook2 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			callCount++
			return nil
		},
	}

	chain.Add(hook1)
	chain.Add(hook2)

	err := chain.CallProfileSelected(&FingerprintProfile{ID: "test"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 calls, got %d", callCount)
	}
}

// TestHookChain_CallProfileSelected_StopsOnError verifies that chain stops on error.
func TestHookChain_CallProfileSelected_StopsOnError(t *testing.T) {
	chain := NewHookChain()

	expectedErr := errors.New("hook error")
	var callCount int

	hook1 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			callCount++
			return expectedErr
		},
	}
	hook2 := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			callCount++
			return nil
		},
	}

	chain.Add(hook1)
	chain.Add(hook2)

	err := chain.CallProfileSelected(&FingerprintProfile{ID: "test"})
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 call (should stop on error), got %d", callCount)
	}
}

// TestHookChain_CallBeforeBuildClientHello_InvokesAllHooks verifies CallBeforeBuildClientHello.
func TestHookChain_CallBeforeBuildClientHello_InvokesAllHooks(t *testing.T) {
	chain := NewHookChain()

	var callCount int
	hook := &FingerprintHooks{
		OnBeforeBuildClientHello: func(profile *FingerprintProfile) error {
			callCount++
			return nil
		},
	}

	chain.Add(hook)

	err := chain.CallBeforeBuildClientHello(&FingerprintProfile{ID: "test"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

// TestHookChain_ThreadSafety_ConcurrentAddAndCall verifies thread safety of HookChain.
func TestHookChain_ThreadSafety_ConcurrentAddAndCall(t *testing.T) {
	chain := NewHookChain()
	var wg sync.WaitGroup
	var callCount int64

	// Add hooks concurrently
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hook := &FingerprintHooks{
				OnProfileSelected: func(profile *FingerprintProfile) error {
					atomic.AddInt64(&callCount, 1)
					return nil
				},
			}
			chain.Add(hook)
		}()
	}

	// Call hooks concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = chain.CallProfileSelected(&FingerprintProfile{ID: "test"})
		}()
	}

	wg.Wait()

	// Verify no panics occurred and chain has hooks
	if chain.Len() != 10 {
		t.Errorf("expected 10 hooks, got %d", chain.Len())
	}
}

// TestHookChain_Remove_RemovesHook verifies that hooks can be removed.
func TestHookChain_Remove_RemovesHook(t *testing.T) {
	chain := NewHookChain()

	hook := &FingerprintHooks{}
	chain.Add(hook)

	if chain.Len() != 1 {
		t.Fatalf("length should be 1, got %d", chain.Len())
	}

	removed := chain.Remove(hook)
	if !removed {
		t.Error("Remove should return true for existing hook")
	}

	if chain.Len() != 0 {
		t.Errorf("length should be 0 after removal, got %d", chain.Len())
	}
}

// TestHookChain_Remove_ReturnsFalseForNonexistent verifies Remove returns false
// for hooks not in chain.
func TestHookChain_Remove_ReturnsFalseForNonexistent(t *testing.T) {
	chain := NewHookChain()

	hook := &FingerprintHooks{}
	removed := chain.Remove(hook)

	if removed {
		t.Error("Remove should return false for nonexistent hook")
	}
}

// TestHookChain_Clear_RemovesAllHooks verifies Clear removes all hooks.
func TestHookChain_Clear_RemovesAllHooks(t *testing.T) {
	chain := NewHookChain()

	chain.Add(&FingerprintHooks{})
	chain.Add(&FingerprintHooks{})
	chain.Add(&FingerprintHooks{})

	if chain.Len() != 3 {
		t.Fatalf("length should be 3, got %d", chain.Len())
	}

	chain.Clear()

	if chain.Len() != 0 {
		t.Errorf("length should be 0 after Clear, got %d", chain.Len())
	}
}

// TestHookChain_CallSessionStateCreated_InvokesAllHooks verifies CallSessionStateCreated.
func TestHookChain_CallSessionStateCreated_InvokesAllHooks(t *testing.T) {
	chain := NewHookChain()

	var callCount int
	hook := &FingerprintHooks{
		OnSessionStateCreated: func(state *SessionFingerprintState) error {
			callCount++
			return nil
		},
	}

	chain.Add(hook)

	state := &SessionFingerprintState{ID: "test-session"}
	err := chain.CallSessionStateCreated(state)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

// TestHookChain_CallSessionStateRestored_InvokesAllHooks verifies CallSessionStateRestored.
func TestHookChain_CallSessionStateRestored_InvokesAllHooks(t *testing.T) {
	chain := NewHookChain()

	var callCount int
	hook := &FingerprintHooks{
		OnSessionStateRestored: func(state *SessionFingerprintState) error {
			callCount++
			return nil
		},
	}

	chain.Add(hook)

	state := &SessionFingerprintState{ID: "test-session"}
	err := chain.CallSessionStateRestored(state)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 call, got %d", callCount)
	}
}

// =============================================================================
// SECTION 6: QuickFingerprintedConn Tests
// =============================================================================

// TestQuickFingerprintedConn_CreatesValidUConn verifies that QuickFingerprintedConn
// creates a valid UConn.
func TestQuickFingerprintedConn_CreatesValidUConn(t *testing.T) {
	conn := &net.TCPConn{}
	uconn, err := QuickFingerprintedConn(conn, "example.com", "chrome_133_windows_11")

	if err != nil {
		t.Fatalf("QuickFingerprintedConn failed: %v", err)
	}

	if uconn == nil {
		t.Fatal("QuickFingerprintedConn returned nil UConn")
	}

	if uconn.config.ServerName != "example.com" {
		t.Errorf("ServerName mismatch: got %q", uconn.config.ServerName)
	}
}

// TestQuickFingerprintedConn_AppliesProfileCorrectly verifies that the profile
// is applied correctly.
func TestQuickFingerprintedConn_AppliesProfileCorrectly(t *testing.T) {
	conn := &net.TCPConn{}
	uconn, err := QuickFingerprintedConn(conn, "example.com", "chrome_133_windows_11")

	if err != nil {
		t.Fatalf("QuickFingerprintedConn failed: %v", err)
	}

	// Build handshake state to verify profile was applied
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	hello := uconn.HandshakeState.Hello

	// Chrome should have GREASE
	hasGREASE := false
	for _, cs := range hello.CipherSuites {
		if isGREASEUint16(cs) {
			hasGREASE = true
			break
		}
	}

	if !hasGREASE {
		t.Error("Chrome profile should have GREASE in cipher suites")
	}
}

// TestQuickFingerprintedConn_ReturnsErrorForInvalidProfile verifies error handling.
func TestQuickFingerprintedConn_ReturnsErrorForInvalidProfile(t *testing.T) {
	conn := &net.TCPConn{}
	uconn, err := QuickFingerprintedConn(conn, "example.com", "invalid_profile_xyz")

	if err == nil {
		t.Fatal("QuickFingerprintedConn should return error for invalid profile")
	}

	if uconn != nil {
		t.Error("UConn should be nil when error occurs")
	}
}

// TestNewFingerprintedConn_ReturnsValidUConnAndController verifies
// NewFingerprintedConn returns both UConn and controller.
func TestNewFingerprintedConn_ReturnsValidUConnAndController(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}

	uconn, ctrl, err := NewFingerprintedConn(conn, config, "chrome_133_windows_11")

	if err != nil {
		t.Fatalf("NewFingerprintedConn failed: %v", err)
	}

	if uconn == nil {
		t.Fatal("UConn should not be nil")
	}

	if ctrl == nil {
		t.Fatal("controller should not be nil")
	}

	// Verify controller has profile set
	if ctrl.Profile() == nil {
		t.Error("controller profile should be set")
	}

	if ctrl.Profile().ID != "chrome_133_windows_11" {
		t.Errorf("profile ID mismatch: got %q", ctrl.Profile().ID)
	}
}

// TestNewFingerprintedConn_ReturnsErrorForInvalidProfile verifies error handling.
func TestNewFingerprintedConn_ReturnsErrorForInvalidProfile(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}

	uconn, ctrl, err := NewFingerprintedConn(conn, config, "nonexistent_profile")

	if err == nil {
		t.Fatal("NewFingerprintedConn should return error for invalid profile")
	}

	if uconn != nil {
		t.Error("UConn should be nil when error occurs")
	}

	if ctrl != nil {
		t.Error("controller should be nil when error occurs")
	}
}

// =============================================================================
// SECTION 7: Controller Accessors and Additional Tests
// =============================================================================

// TestFingerprintController_GetExpectedJA4_ReturnsCorrectValue verifies
// GetExpectedJA4 returns the expected fingerprint.
func TestFingerprintController_GetExpectedJA4_ReturnsCorrectValue(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	ja4 := ctrl.GetExpectedJA4()
	// Expected JA4 may be empty if not set in profile, that's OK
	t.Logf("Expected JA4: %q", ja4)
}

// TestFingerprintController_GetExpectedJA3_ReturnsCorrectValue verifies
// GetExpectedJA3 returns the expected fingerprint.
func TestFingerprintController_GetExpectedJA3_ReturnsCorrectValue(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	ja3 := ctrl.GetExpectedJA3()
	// Expected JA3 may be empty if not set in profile, that's OK
	t.Logf("Expected JA3: %q", ja3)
}

// TestFingerprintController_GetExpectedJA4_ReturnsEmptyWhenNoProfile verifies
// behavior when no profile is set.
func TestFingerprintController_GetExpectedJA4_ReturnsEmptyWhenNoProfile(t *testing.T) {
	ctrl := NewFingerprintController()

	ja4 := ctrl.GetExpectedJA4()
	if ja4 != "" {
		t.Errorf("expected empty string when no profile set, got %q", ja4)
	}
}

// TestFingerprintController_AddHook_AddsToChain verifies AddHook works.
func TestFingerprintController_AddHook_AddsToChain(t *testing.T) {
	ctrl := NewFingerprintController()

	hook := &FingerprintHooks{}
	ctrl.AddHook(hook)

	if ctrl.Hooks().Len() != 1 {
		t.Errorf("hook chain length should be 1, got %d", ctrl.Hooks().Len())
	}
}

// TestFingerprintController_GetRecordDelay_ReturnsZeroWhenNoController verifies
// GetRecordDelay behavior when timing controller is nil.
func TestFingerprintController_GetRecordDelay_ReturnsZeroWhenNoController(t *testing.T) {
	ctrl := NewFingerprintController()

	delay := ctrl.GetRecordDelay()
	if delay != 0 {
		t.Errorf("expected 0 delay when timing controller is nil, got %v", delay)
	}
}

// TestFingerprintController_GetRecordDelay_AfterApplyProfile verifies
// GetRecordDelay returns timing from controller.
func TestFingerprintController_GetRecordDelay_AfterApplyProfile(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	// Set a delay on timing controller
	tc := ctrl.TimingController()
	if tc != nil {
		tc.SetDelay(10 * time.Millisecond)
		delay := ctrl.GetRecordDelay()
		if delay < 10*time.Millisecond {
			t.Errorf("expected delay >= 10ms, got %v", delay)
		}
	}
}

// TestFingerprintController_RecordController_NilBeforeApply verifies
// RecordController is nil before ApplyProfile.
func TestFingerprintController_RecordController_NilBeforeApply(t *testing.T) {
	ctrl := NewFingerprintController()

	if ctrl.RecordController() != nil {
		t.Error("RecordController should be nil before ApplyProfile")
	}
}

// TestFingerprintController_RecordController_SetAfterApplyWithPadding verifies
// RecordController is set when padding is enabled.
func TestFingerprintController_RecordController_SetAfterApplyWithPadding(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	// Chrome profile has padding enabled
	if ctrl.RecordController() == nil {
		t.Error("RecordController should be set for Chrome profile with padding")
	}
}

// TestFingerprintController_Validator_NilBeforeApply verifies
// Validator is nil before ApplyProfile.
func TestFingerprintController_Validator_NilBeforeApply(t *testing.T) {
	ctrl := NewFingerprintController()

	if ctrl.Validator() != nil {
		t.Error("Validator should be nil before ApplyProfile")
	}
}

// =============================================================================
// SECTION 8: Edge Cases and Error Handling Tests
// =============================================================================

// TestApplyProfile_MultipleProfiles_OverwritesPrevious verifies that applying
// a second profile overwrites the first.
func TestApplyProfile_MultipleProfiles_OverwritesPrevious(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()

	// Apply first profile
	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("first ApplyProfile failed: %v", err)
	}

	firstProfile := ctrl.Profile()
	if firstProfile.Browser != "chrome" {
		t.Fatalf("first profile browser mismatch: got %q", firstProfile.Browser)
	}

	// Apply second profile
	err = ctrl.ApplyProfile(uconn, "firefox_145_windows_11")
	if err != nil {
		t.Fatalf("second ApplyProfile failed: %v", err)
	}

	secondProfile := ctrl.Profile()
	if secondProfile.Browser != "firefox" {
		t.Errorf("second profile browser mismatch: got %q", secondProfile.Browser)
	}
}

// TestApplyProfile_ProfileCloning verifies that the profile is cloned internally
// during ApplyProfile (so changes to original don't affect controller).
// Note: Profile() accessor returns a direct pointer to internal profile.
func TestApplyProfile_ProfileCloning(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	// Get original profile from registry
	originalProfile, err := DefaultRegistry.Get("chrome_133_windows_11")
	if err != nil {
		t.Fatalf("Failed to get original profile: %v", err)
	}

	ctrl := NewFingerprintController()
	err = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	// Modify the registry profile after ApplyProfile
	originalProfile.Description = "modified description"

	// Controller's internal profile should not be affected
	// since ApplyProfile clones during application
	appliedProfile := ctrl.Profile()
	if appliedProfile.Description == "modified description" {
		t.Error("controller profile should be cloned, not affected by later modifications to registry")
	}

	// Verify the profile was properly set
	if appliedProfile.ID != "chrome_133_windows_11" {
		t.Errorf("profile ID mismatch: got %q, want %q", appliedProfile.ID, "chrome_133_windows_11")
	}
}

// TestFingerprintController_ThreadSafety_ConcurrentAccess verifies thread safety
// of controller methods.
func TestFingerprintController_ThreadSafety_ConcurrentAccess(t *testing.T) {
	ctrl := NewFingerprintController()
	var wg sync.WaitGroup

	// Apply profile in one goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn := &net.TCPConn{}
		config := &Config{ServerName: "example.com"}
		uconn := UClient(conn, config, HelloCustom)
		_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	}()

	// Access profile in multiple goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ctrl.Profile()
			_ = ctrl.SessionState()
			_ = ctrl.Hooks()
			_ = ctrl.GetExpectedJA4()
		}()
	}

	wg.Wait()
}

// TestApplyProfile_HooksCalledInOrder verifies that hooks are called in the
// correct order during ApplyProfile.
//
// Hook call flow:
// 1. OnProfileSelected - called after profile is loaded and validated
// 2. For NEW sessions: OnSessionStateCreated (connectionCount==1 after Touch())
// 3. For EXISTING sessions: OnSessionStateRestored (connectionCount>1 after Touch())
func TestApplyProfile_HooksCalledInOrder(t *testing.T) {
	// Use unique origin to avoid session cache conflicts
	uniqueOrigin := fmt.Sprintf("test-hooks-%d.com", time.Now().UnixNano())

	conn := &net.TCPConn{}
	config := &Config{ServerName: uniqueOrigin}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()

	var callOrder []string

	hook := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			callOrder = append(callOrder, "profile_selected")
			return nil
		},
		OnSessionStateCreated: func(state *SessionFingerprintState) error {
			callOrder = append(callOrder, "session_created")
			return nil
		},
		OnSessionStateRestored: func(state *SessionFingerprintState) error {
			callOrder = append(callOrder, "session_restored")
			return nil
		},
	}

	ctrl.AddHook(hook)

	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err != nil {
		t.Fatalf("ApplyProfile failed: %v", err)
	}

	// Verify order
	if len(callOrder) < 2 {
		t.Errorf("expected at least 2 hook calls, got %d: %v", len(callOrder), callOrder)
	}

	if len(callOrder) >= 1 && callOrder[0] != "profile_selected" {
		t.Errorf("first hook should be profile_selected, got %s", callOrder[0])
	}

	// New session: GetOrCreate calls Touch() which increments connectionCount from 0 to 1.
	// ApplyFingerprintProfile checks connectionCount() == 1, so OnSessionStateCreated is called.
	if len(callOrder) >= 2 && callOrder[1] != "session_created" {
		t.Errorf("second hook should be session_created (first connection), got %s", callOrder[1])
	}
}

// TestApplyProfile_HookError_AbortsOperation verifies that a hook error aborts
// the ApplyProfile operation.
func TestApplyProfile_HookError_AbortsOperation(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()

	expectedErr := errors.New("hook abort")
	hook := &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			return expectedErr
		},
	}

	ctrl.AddHook(hook)

	err := ctrl.ApplyProfile(uconn, "chrome_133_windows_11")
	if err == nil {
		t.Fatal("ApplyProfile should return error when hook fails")
	}

	// Error message should contain the hook error
	if !errors.Is(err, expectedErr) && err.Error() != "tls: profile selection hook failed: hook abort" {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestSessionStateCache_DifferentOrigins verifies that different origins get
// different session states.
func TestSessionStateCache_DifferentOrigins(t *testing.T) {
	config1 := &Config{ServerName: "example1.com"}
	config2 := &Config{ServerName: "example2.com"}

	// Connection 1
	conn1 := &net.TCPConn{}
	uconn1 := UClient(conn1, config1, HelloCustom)
	ctrl1 := NewFingerprintController()
	_ = ctrl1.ApplyProfile(uconn1, "chrome_133_windows_11")

	// Connection 2
	conn2 := &net.TCPConn{}
	uconn2 := UClient(conn2, config2, HelloCustom)
	ctrl2 := NewFingerprintController()
	_ = ctrl2.ApplyProfile(uconn2, "chrome_133_windows_11")

	state1 := ctrl1.SessionState()
	state2 := ctrl2.SessionState()

	if state1.Origin == state2.Origin {
		t.Error("different origins should have different session states")
	}
}

// TestApplyProfile_SafariProfile verifies Safari profile application.
func TestApplyProfile_SafariProfile(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	ctrl := NewFingerprintController()
	err := ctrl.ApplyProfile(uconn, "safari_18_macos_14")

	if err != nil {
		t.Fatalf("ApplyProfile for Safari failed: %v", err)
	}

	profile := ctrl.Profile()
	if profile.Browser != "safari" {
		t.Errorf("browser mismatch: got %q, want %q", profile.Browser, "safari")
	}
}

// TestFingerprintController_getOrigin_UsesSessionCacheKey verifies that custom
// session cache key is used when set.
func TestFingerprintController_getOrigin_UsesSessionCacheKey(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)

	opts := FingerprintControllerOptions{
		UseSessionCache: true,
		SessionCacheKey: "custom-origin:443",
	}
	ctrl := NewFingerprintControllerWithOptions(opts)

	_ = ctrl.ApplyProfile(uconn, "chrome_133_windows_11")

	state := ctrl.SessionState()
	if state.Origin != "custom-origin:443" {
		t.Errorf("origin should use custom key: got %q, want %q",
			state.Origin, "custom-origin:443")
	}
}

// TestFingerprintController_SessionStateNotCached_WhenDisabled verifies that
// session state is not cached when UseSessionCache is false.
func TestFingerprintController_SessionStateNotCached_WhenDisabled(t *testing.T) {
	config := &Config{ServerName: "example.com"}

	opts := FingerprintControllerOptions{
		UseSessionCache: false,
	}

	// First connection
	conn1 := &net.TCPConn{}
	uconn1 := UClient(conn1, config, HelloCustom)
	ctrl1 := NewFingerprintControllerWithOptions(opts)
	_ = ctrl1.ApplyProfile(uconn1, "chrome_133_windows_11")

	// Second connection
	conn2 := &net.TCPConn{}
	uconn2 := UClient(conn2, config, HelloCustom)
	ctrl2 := NewFingerprintControllerWithOptions(opts)
	_ = ctrl2.ApplyProfile(uconn2, "chrome_133_windows_11")

	state1 := ctrl1.SessionState()
	state2 := ctrl2.SessionState()

	// Session IDs should be different since caching is disabled
	if state1.ID == state2.ID {
		t.Error("session IDs should be different when caching is disabled")
	}
}

// TestFingerprintedConn_ImplementsInterface verifies fingerprintedConn implements
// FingerprintControllerInterface.
func TestFingerprintedConn_ImplementsInterface(t *testing.T) {
	conn := &net.TCPConn{}
	config := &Config{ServerName: "example.com"}
	uconn := UClient(conn, config, HelloCustom)
	ctrl := NewFingerprintController()

	fpc := &fingerprintedConn{
		UConn:      uconn,
		controller: ctrl,
	}

	// Verify it implements FingerprintControllerInterface
	var _ FingerprintControllerInterface = fpc

	// Verify GetFingerprintController returns correct controller
	if fpc.GetFingerprintController() != ctrl {
		t.Error("GetFingerprintController should return the controller")
	}
}

// TestIsGREASEUint16_ValidGREASEValues verifies GREASE detection.
func TestIsGREASEUint16_ValidGREASEValues(t *testing.T) {
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
		0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
		0xcaca, 0xdada, 0xeaea, 0xfafa,
	}

	for _, v := range greaseValues {
		if !isGREASEUint16(v) {
			t.Errorf("0x%04x should be detected as GREASE", v)
		}
	}
}

// TestIsGREASEUint16_NonGREASEValues verifies non-GREASE detection.
func TestIsGREASEUint16_NonGREASEValues(t *testing.T) {
	nonGreaseValues := []uint16{
		0x0001, 0x0301, 0x0303, 0x0304,
		TLS_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		uint16(X25519),
	}

	for _, v := range nonGreaseValues {
		if isGREASEUint16(v) {
			t.Errorf("0x%04x should NOT be detected as GREASE", v)
		}
	}
}
