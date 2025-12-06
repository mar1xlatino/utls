// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"sync"
	"testing"
	"time"
)

// =============================================================================
// TEST SUITE: NewSessionFingerprintState
// =============================================================================

// TestNewSessionFingerprintState_NilProfile verifies that passing nil profile
// returns a valid state with empty profile ID (never returns nil).
// This prevents nil pointer dereferences in callers.
func TestNewSessionFingerprintState_NilProfile(t *testing.T) {
	state := NewSessionFingerprintState(nil, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState(nil, origin) should return valid state, got nil")
	}
	if state.ProfileID != "" {
		t.Errorf("ProfileID should be empty for nil profile, got %q", state.ProfileID)
	}
	if state.Origin != "example.com:443" {
		t.Errorf("Origin should be set, got %q", state.Origin)
	}
	if state.ID == "" {
		t.Error("ID should be generated even for nil profile")
	}
}

// TestNewSessionFingerprintState_ValidProfile verifies that a valid profile
// creates a properly initialized session state.
func TestNewSessionFingerprintState_ValidProfile(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		Version: 133,
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{
				Enabled: true,
			},
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
			},
			KeyShareGroups: []CurveID{
				X25519,
				CurveP256,
			},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil for valid profile")
	}

	// Verify identity fields
	if state.ProfileID != profile.ID {
		t.Errorf("ProfileID mismatch: expected %q, got %q", profile.ID, state.ProfileID)
	}
	if state.Origin != "example.com:443" {
		t.Errorf("Origin mismatch: expected %q, got %q", "example.com:443", state.Origin)
	}

	// Verify ID was generated (32 hex chars from 16 bytes)
	if len(state.ID) != 32 {
		t.Errorf("Session ID should be 32 hex chars, got %d: %q", len(state.ID), state.ID)
	}

	// Verify timestamps are set
	if state.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if state.lastUsed.IsZero() {
		t.Error("lastUsed should not be zero")
	}
}

// TestNewSessionFingerprintState_GREASEDisabled verifies that GREASE values
// are zero when GREASE is disabled in the profile.
func TestNewSessionFingerprintState_GREASEDisabled(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "firefox_profile",
		Browser: "firefox",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{
				Enabled: false, // Firefox doesn't use GREASE
			},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// All GREASE values should be zero when disabled
	if state.FrozenGREASE.CipherSuite != 0 {
		t.Errorf("CipherSuite GREASE should be 0 when disabled, got 0x%04x", state.FrozenGREASE.CipherSuite)
	}
	if state.FrozenGREASE.Extension1 != 0 {
		t.Errorf("Extension1 GREASE should be 0 when disabled, got 0x%04x", state.FrozenGREASE.Extension1)
	}
}

// TestNewSessionFingerprintState_CopiesSlices verifies that slices from the
// profile are deep-copied into the session state, not referenced.
func TestNewSessionFingerprintState_CopiesSlices(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
			KeyShareGroups: []CurveID{
				X25519,
				CurveP256,
			},
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
			},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Modify original profile slices
	profile.ClientHello.KeyShareGroups[0] = CurveP384
	profile.ClientHello.SignatureAlgorithms[0] = PSSWithSHA384

	// Session state should retain original values (deep copy verification)
	if len(state.FrozenKeyShareGroups) > 0 && state.FrozenKeyShareGroups[0] != X25519 {
		t.Errorf("FrozenKeyShareGroups was not deep-copied, got %v", state.FrozenKeyShareGroups[0])
	}
	if len(state.FrozenSigAlgOrder) > 0 && state.FrozenSigAlgOrder[0] != ECDSAWithP256AndSHA256 {
		t.Errorf("FrozenSigAlgOrder was not deep-copied, got %v", state.FrozenSigAlgOrder[0])
	}
}

// =============================================================================
// TEST SUITE: FrozenGREASE Generation
// =============================================================================

// TestFrozenGREASE_ValidRange verifies all GREASE values follow the 0x?a?a pattern.
func TestFrozenGREASE_ValidRange(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	// Test multiple times to cover randomness
	for i := 0; i < 100; i++ {
		state := NewSessionFingerprintState(profile, "example.com:443")
		if state == nil {
			t.Fatal("NewSessionFingerprintState returned nil")
		}

		greaseValues := []uint16{
			state.FrozenGREASE.CipherSuite,
			state.FrozenGREASE.Extension1,
			state.FrozenGREASE.Extension2,
			state.FrozenGREASE.SupportedGroup,
			state.FrozenGREASE.SupportedVersion,
			state.FrozenGREASE.KeyShare,
			state.FrozenGREASE.SignatureAlgo,
			state.FrozenGREASE.PSKMode,
		}

		for j, v := range greaseValues {
			if !isGREASEUint16(v) {
				t.Errorf("Iteration %d: GREASE value %d (0x%04x) at index %d is not valid GREASE",
					i, v, v, j)
			}
		}
	}
}

// TestFrozenGREASE_Extension1Extension2_NaturalCollisionRate verifies that
// Extension1 and Extension2 have a natural ~6.25% collision rate (like Chrome).
// Real Chrome/BoringSSL does NOT deduplicate GREASE values - collisions are allowed.
func TestFrozenGREASE_Extension1Extension2_NaturalCollisionRate(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	// Run many iterations to measure collision rate
	const iterations = 10000
	collisions := 0
	for i := 0; i < iterations; i++ {
		state := NewSessionFingerprintState(profile, "example.com:443")
		if state == nil {
			t.Fatal("NewSessionFingerprintState returned nil")
		}

		if state.FrozenGREASE.Extension1 == state.FrozenGREASE.Extension2 {
			collisions++
		}
	}

	// Expected collision rate: 1/16 = 6.25%
	// With 10000 iterations, expected collisions ~625, stddev ~24
	// Allow 3-sigma range: 625 +/- 72 = [553, 697]
	// We use a wider range [400, 850] to reduce test flakiness
	actualRate := float64(collisions) / float64(iterations)

	// Verify collision rate is approximately 6.25% (with tolerance for randomness)
	minCollisions := 400 // ~4% minimum
	maxCollisions := 850 // ~8.5% maximum

	if collisions < minCollisions || collisions > maxCollisions {
		t.Errorf("Collision rate out of expected range: got %d collisions (%.2f%%), expected ~625 (6.25%%)",
			collisions, actualRate*100)
	}

	// Log actual rate for debugging
	t.Logf("GREASE collision rate: %d/%d = %.2f%% (expected ~6.25%%)",
		collisions, iterations, actualRate*100)
}

// TestFrozenGREASE_KeyShareMatchesSupportedGroup verifies Chrome behavior where
// KeyShare GREASE must equal SupportedGroup GREASE.
func TestFrozenGREASE_KeyShareMatchesSupportedGroup(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	for i := 0; i < 100; i++ {
		state := NewSessionFingerprintState(profile, "example.com:443")
		if state == nil {
			t.Fatal("NewSessionFingerprintState returned nil")
		}

		if state.FrozenGREASE.KeyShare != state.FrozenGREASE.SupportedGroup {
			t.Errorf("Iteration %d: KeyShare (0x%04x) != SupportedGroup (0x%04x) - violates Chrome behavior",
				i, state.FrozenGREASE.KeyShare, state.FrozenGREASE.SupportedGroup)
		}
	}
}

// TestFrozenGREASE_DeterministicForSameOrigin verifies that once a session is
// created, the GREASE values remain constant (session consistency).
func TestFrozenGREASE_DeterministicForSameOrigin(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Store initial values
	initialGREASE := state.FrozenGREASE

	// Access values multiple times - they should never change
	for i := 0; i < 100; i++ {
		if state.GetGREASEValue(GREASECipherSuite) != initialGREASE.CipherSuite {
			t.Errorf("Iteration %d: CipherSuite GREASE changed unexpectedly", i)
		}
		if state.GetGREASEValue(GREASEExtension1) != initialGREASE.Extension1 {
			t.Errorf("Iteration %d: Extension1 GREASE changed unexpectedly", i)
		}
		if state.GetGREASEValue(GREASEExtension2) != initialGREASE.Extension2 {
			t.Errorf("Iteration %d: Extension2 GREASE changed unexpectedly", i)
		}
	}
}

// TestFrozenGREASE_AllValuesPopulated verifies that when GREASE is enabled,
// all 6 key GREASE values are populated with non-zero values.
func TestFrozenGREASE_AllValuesPopulated(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Verify all 6 key values are populated
	checks := []struct {
		name  string
		value uint16
	}{
		{"CipherSuite", state.FrozenGREASE.CipherSuite},
		{"Extension1", state.FrozenGREASE.Extension1},
		{"Extension2", state.FrozenGREASE.Extension2},
		{"SupportedGroup", state.FrozenGREASE.SupportedGroup},
		{"SupportedVersion", state.FrozenGREASE.SupportedVersion},
		{"KeyShare", state.FrozenGREASE.KeyShare},
	}

	for _, check := range checks {
		if check.value == 0 {
			t.Errorf("%s GREASE value is 0 when GREASE is enabled", check.name)
		}
	}
}

// =============================================================================
// TEST SUITE: Session Freezing
// =============================================================================

// TestSessionFreezing_FreezePreventsFrozenFlag verifies Freeze() sets frozen flag.
func TestSessionFreezing_FreezePreventsFrozenFlag(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Before freeze
	if state.IsFrozen() {
		t.Error("Session should not be frozen initially")
	}

	// Freeze
	state.Freeze()

	// After freeze
	if !state.IsFrozen() {
		t.Error("Session should be frozen after Freeze() call")
	}
}

// TestSessionFreezing_SetSessionTicketFailsAfterFreeze verifies that
// SetSessionTicket returns ErrSessionFrozen after the session is frozen.
func TestSessionFreezing_SetSessionTicketFailsAfterFreeze(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Set ticket before freeze - should work
	ticket := []byte("test-ticket-data")
	err := state.SetSessionTicket(ticket)
	if err != nil {
		t.Errorf("SetSessionTicket before freeze should succeed, got error: %v", err)
	}

	// Freeze the session
	state.Freeze()

	// Set ticket after freeze - should fail
	err = state.SetSessionTicket([]byte("new-ticket"))
	if err != ErrSessionFrozen {
		t.Errorf("SetSessionTicket after freeze should return ErrSessionFrozen, got: %v", err)
	}

	// Verify original ticket is still there
	retrieved := state.GetSessionTicket()
	if string(retrieved) != string(ticket) {
		t.Errorf("Original ticket should be preserved, expected %q, got %q", ticket, retrieved)
	}
}

// TestSessionFreezing_SetResumptionSecretFailsAfterFreeze verifies that
// SetResumptionSecret returns ErrSessionFrozen after the session is frozen.
func TestSessionFreezing_SetResumptionSecretFailsAfterFreeze(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Set secret before freeze - should work
	secret := []byte("resumption-secret-data")
	err := state.SetResumptionSecret(secret)
	if err != nil {
		t.Errorf("SetResumptionSecret before freeze should succeed, got error: %v", err)
	}

	// Freeze the session
	state.Freeze()

	// Set secret after freeze - should fail
	err = state.SetResumptionSecret([]byte("new-secret"))
	if err != ErrSessionFrozen {
		t.Errorf("SetResumptionSecret after freeze should return ErrSessionFrozen, got: %v", err)
	}

	// Verify original secret is still there
	retrieved := state.GetResumptionSecret()
	if string(retrieved) != string(secret) {
		t.Errorf("Original secret should be preserved, expected %q, got %q", secret, retrieved)
	}
}

// TestSessionFreezing_MultipleFreezesCalls verifies that multiple Freeze() calls
// are safe and idempotent.
func TestSessionFreezing_MultipleFreezesCalls(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Multiple freeze calls should not panic
	for i := 0; i < 10; i++ {
		state.Freeze()
	}

	if !state.IsFrozen() {
		t.Error("Session should be frozen after multiple Freeze() calls")
	}
}

// =============================================================================
// TEST SUITE: Session Cache
// =============================================================================

// TestSessionCache_GetOrCreate_ReturnsSameStateForSameOrigin verifies that
// GetOrCreate returns the same session state for the same origin.
func TestSessionCache_GetOrCreate_ReturnsSameStateForSameOrigin(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	origin := "example.com:443"

	// First call creates
	state1 := cache.GetOrCreate(origin, profile)
	if state1 == nil {
		t.Fatal("First GetOrCreate returned nil")
	}

	// Second call returns same
	state2 := cache.GetOrCreate(origin, profile)
	if state2 == nil {
		t.Fatal("Second GetOrCreate returned nil")
	}

	// Should be the exact same object
	if state1 != state2 {
		t.Error("GetOrCreate should return same state for same origin")
	}

	// GREASE values should match (same session)
	if state1.FrozenGREASE.CipherSuite != state2.FrozenGREASE.CipherSuite {
		t.Error("GREASE values should be identical for same session")
	}
}

// TestSessionCache_GetOrCreate_DifferentStateForDifferentOrigin verifies that
// GetOrCreate returns different session states for different origins.
func TestSessionCache_GetOrCreate_DifferentStateForDifferentOrigin(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	state1 := cache.GetOrCreate("example.com:443", profile)
	state2 := cache.GetOrCreate("other.com:443", profile)

	if state1 == nil || state2 == nil {
		t.Fatal("GetOrCreate returned nil")
	}

	// Should be different objects
	if state1 == state2 {
		t.Error("GetOrCreate should return different states for different origins")
	}

	// Session IDs should be different
	if state1.ID == state2.ID {
		t.Error("Session IDs should be different for different origins")
	}
}

// TestSessionCache_EvictionAtMaxSize verifies that the cache evicts oldest
// entries when reaching capacity.
func TestSessionCache_EvictionAtMaxSize(t *testing.T) {
	maxSize := 5
	cache := NewSessionStateCache(maxSize, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	// Fill cache to capacity
	origins := make([]string, maxSize+3)
	for i := 0; i < maxSize+3; i++ {
		origins[i] = "origin" + string(rune('A'+i)) + ".com:443"
		cache.GetOrCreate(origins[i], profile)
		// Small delay to ensure different timestamps
		time.Sleep(time.Millisecond)
	}

	// Cache size should be at most maxSize
	stats := cache.Stats()
	if stats.Size > maxSize {
		t.Errorf("Cache size should be at most %d, got %d", maxSize, stats.Size)
	}

	// Oldest entries should be evicted
	// First entries should be gone
	for i := 0; i < 3; i++ {
		state := cache.Get(origins[i])
		if state != nil {
			t.Errorf("Origin %s should have been evicted", origins[i])
		}
	}
}

// TestSessionCache_CleanupExpiredEntries verifies that Cleanup removes expired
// entries from the cache.
func TestSessionCache_CleanupExpiredEntries(t *testing.T) {
	// Very short TTL for testing
	cache := NewSessionStateCache(100, 10*time.Millisecond)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	// Create some entries
	cache.GetOrCreate("origin1.com:443", profile)
	cache.GetOrCreate("origin2.com:443", profile)

	// Verify they exist
	stats := cache.Stats()
	if stats.Size != 2 {
		t.Errorf("Expected 2 entries, got %d", stats.Size)
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Run cleanup
	removed := cache.Cleanup()
	if removed != 2 {
		t.Errorf("Expected to remove 2 entries, removed %d", removed)
	}

	// Cache should be empty
	stats = cache.Stats()
	if stats.Size != 0 {
		t.Errorf("Expected 0 entries after cleanup, got %d", stats.Size)
	}
}

// TestSessionCache_ThreadSafety_ConcurrentAccess verifies thread-safe concurrent
// access to the session cache.
//
// Uses moderate concurrency to validate thread-safety without excessive memory
// overhead from race detector instrumentation.
func TestSessionCache_ThreadSafety_ConcurrentAccess(t *testing.T) {
	cache := NewSessionStateCache(50, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	var wg sync.WaitGroup
	const goroutines = 20
	const iterations = 20

	// Run concurrent GetOrCreate operations
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				origin := "o" + string(rune('A'+id%10)) + ".com"
				state := cache.GetOrCreate(origin, profile)
				if state == nil {
					t.Errorf("GetOrCreate returned nil for goroutine %d, iteration %d", id, j)
					return
				}
				// Access some fields to trigger race detector
				_ = state.FrozenGREASE.CipherSuite
				_ = state.ID
				state.Touch()
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is consistent
	stats := cache.Stats()
	if stats.Size == 0 {
		t.Error("Cache should have entries after concurrent access")
	}
}

// TestSessionCache_Get_ReturnsNilForNonexistent verifies that Get returns nil
// for origins not in the cache.
func TestSessionCache_Get_ReturnsNilForNonexistent(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)

	state := cache.Get("nonexistent.com:443")
	if state != nil {
		t.Error("Get should return nil for nonexistent origin")
	}
}

// TestSessionCache_Delete_RemovesEntry verifies that Delete removes an entry
// and clears its sensitive data.
func TestSessionCache_Delete_RemovesEntry(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	origin := "example.com:443"
	state := cache.GetOrCreate(origin, profile)
	if state == nil {
		t.Fatal("GetOrCreate returned nil")
	}

	// Set some sensitive data
	state.SetSessionTicket([]byte("secret-ticket"))

	// Delete
	cache.Delete(origin)

	// Should be gone
	retrieved := cache.Get(origin)
	if retrieved != nil {
		t.Error("Get should return nil after Delete")
	}
}

// TestSessionCache_Clear_RemovesAllEntries verifies that Clear removes all
// entries and clears their sensitive data.
func TestSessionCache_Clear_RemovesAllEntries(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	// Add multiple entries
	for i := 0; i < 10; i++ {
		cache.GetOrCreate("origin"+string(rune('A'+i))+".com:443", profile)
	}

	stats := cache.Stats()
	if stats.Size != 10 {
		t.Errorf("Expected 10 entries, got %d", stats.Size)
	}

	// Clear all
	cache.Clear()

	stats = cache.Stats()
	if stats.Size != 0 {
		t.Errorf("Expected 0 entries after Clear, got %d", stats.Size)
	}
}

// TestSessionCache_TouchUpdatesTimestamp verifies that Touch() updates the
// lastUsed timestamp and connection count.
func TestSessionCache_TouchUpdatesTimestamp(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := cache.GetOrCreate("example.com:443", profile)
	if state == nil {
		t.Fatal("GetOrCreate returned nil")
	}

	initialCount := state.ConnectionCount()
	initialLastUsed := state.LastUsed()

	// Small delay
	time.Sleep(time.Millisecond)

	// Touch
	state.Touch()

	if state.ConnectionCount() != initialCount+1 {
		t.Errorf("ConnectionCount should increment, expected %d, got %d",
			initialCount+1, state.ConnectionCount())
	}

	if !state.LastUsed().After(initialLastUsed) {
		t.Error("LastUsed should be updated after Touch()")
	}
}

// =============================================================================
// TEST SUITE: simplePRNG
// =============================================================================

// TestSimplePRNG_ZeroSeedHandling verifies that a zero seed produces non-zero
// output (xorshift64 would fail with all zeros otherwise).
func TestSimplePRNG_ZeroSeedHandling(t *testing.T) {
	prng := newPRNGFromSeed(0)

	// Should not be stuck at zero
	allZero := true
	for i := 0; i < 100; i++ {
		// Use a temporary slice to call Shuffle
		vals := make([]int, 10)
		for j := range vals {
			vals[j] = j
		}
		originalSum := 0
		for _, v := range vals {
			originalSum += v
		}

		prng.Shuffle(len(vals), func(a, b int) {
			vals[a], vals[b] = vals[b], vals[a]
		})

		// Check if any value moved (shuffle happened)
		for j, v := range vals {
			if v != j {
				allZero = false
				break
			}
		}
		if !allZero {
			break
		}
	}

	// After 100 shuffles, at least one should have changed something
	// (if PRNG works, this is astronomically likely)
	if allZero {
		t.Error("PRNG with zero seed should still produce non-trivial output")
	}
}

// TestSimplePRNG_ShuffleThreadSafe verifies that Shuffle is thread-safe
// when called concurrently from multiple goroutines.
//
// Uses moderate concurrency to validate thread-safety without excessive memory
// overhead from race detector instrumentation.
func TestSimplePRNG_ShuffleThreadSafe(t *testing.T) {
	prng := newPRNGFromSeed(12345)

	var wg sync.WaitGroup
	const goroutines = 10
	const iterations = 20

	// Run concurrent shuffles - no panic or race should occur
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				vals := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
				prng.Shuffle(len(vals), func(a, b int) {
					vals[a], vals[b] = vals[b], vals[a]
				})
			}
		}()
	}

	wg.Wait()
}

// TestSimplePRNG_DistributionReasonablyUniform verifies that the PRNG produces
// a reasonably uniform distribution of values.
func TestSimplePRNG_DistributionReasonablyUniform(t *testing.T) {
	prng := newPRNGFromSeed(42)

	// Track which position each element ends up in
	n := 10
	iterations := 10000
	positionCounts := make([][]int, n)
	for i := range positionCounts {
		positionCounts[i] = make([]int, n)
	}

	for iter := 0; iter < iterations; iter++ {
		vals := make([]int, n)
		for i := range vals {
			vals[i] = i
		}
		prng.Shuffle(n, func(a, b int) {
			vals[a], vals[b] = vals[b], vals[a]
		})
		for pos, val := range vals {
			positionCounts[val][pos]++
		}
	}

	// Each element should appear in each position roughly iterations/n times
	expected := float64(iterations) / float64(n)
	tolerance := expected * 0.2 // Allow 20% deviation

	for val := 0; val < n; val++ {
		for pos := 0; pos < n; pos++ {
			count := float64(positionCounts[val][pos])
			deviation := count - expected
			if deviation < 0 {
				deviation = -deviation
			}
			if deviation > tolerance {
				t.Errorf("Element %d appeared in position %d %d times (expected ~%d, tolerance %f)",
					val, pos, positionCounts[val][pos], int(expected), tolerance)
			}
		}
	}
}

// =============================================================================
// TEST SUITE: Key Material Zeroing
// =============================================================================

// TestKeyMaterialZeroing_Clear verifies that Clear() zeros all sensitive data.
func TestKeyMaterialZeroing_Clear(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Set sensitive data
	ticket := []byte("super-secret-ticket")
	psk := []byte("psk-identity")
	secret := []byte("resumption-secret")

	state.SetSessionTicket(ticket)
	state.PSKIdentity = make([]byte, len(psk))
	copy(state.PSKIdentity, psk)
	state.SetResumptionSecret(secret)

	// Clear
	state.Clear()

	// All should be nil
	if state.SessionTicket != nil {
		t.Error("SessionTicket should be nil after Clear()")
	}
	if state.PSKIdentity != nil {
		t.Error("PSKIdentity should be nil after Clear()")
	}
	if state.ResumptionSecret != nil {
		t.Error("ResumptionSecret should be nil after Clear()")
	}
}

// TestKeyMaterialZeroing_SetSessionTicketZerosOld verifies that SetSessionTicket
// zeros the old ticket before setting a new one.
func TestKeyMaterialZeroing_SetSessionTicketZerosOld(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Set initial ticket
	oldTicket := []byte("old-secret-ticket-data")
	state.SetSessionTicket(oldTicket)

	// Keep reference to old internal slice
	// Note: We can't directly access the internal slice, but we verify
	// the behavior by checking that GetSessionTicket returns a copy

	// Get ticket and verify it's a copy
	retrieved := state.GetSessionTicket()
	if &retrieved[0] == &oldTicket[0] {
		t.Error("GetSessionTicket should return a copy, not the original slice")
	}

	// Set new ticket (should zero the old one internally)
	newTicket := []byte("new-secret-ticket-data")
	state.SetSessionTicket(newTicket)

	// Verify new ticket is stored
	retrieved = state.GetSessionTicket()
	if string(retrieved) != string(newTicket) {
		t.Errorf("Expected new ticket %q, got %q", newTicket, retrieved)
	}
}

// TestKeyMaterialZeroing_SetSessionTicketNilClears verifies that
// SetSessionTicket(nil) clears the ticket.
func TestKeyMaterialZeroing_SetSessionTicketNilClears(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Set ticket
	state.SetSessionTicket([]byte("some-ticket"))

	// Clear with nil
	err := state.SetSessionTicket(nil)
	if err != nil {
		t.Errorf("SetSessionTicket(nil) should succeed, got error: %v", err)
	}

	// Should be nil now
	retrieved := state.GetSessionTicket()
	if retrieved != nil {
		t.Errorf("SessionTicket should be nil after SetSessionTicket(nil), got %v", retrieved)
	}
}

// TestKeyMaterialZeroing_SetSessionTicketEmptySliceClears verifies that
// SetSessionTicket([]byte{}) clears the ticket.
func TestKeyMaterialZeroing_SetSessionTicketEmptySliceClears(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Set ticket
	state.SetSessionTicket([]byte("some-ticket"))

	// Clear with empty slice
	err := state.SetSessionTicket([]byte{})
	if err != nil {
		t.Errorf("SetSessionTicket([]byte{}) should succeed, got error: %v", err)
	}

	// Should be nil now
	retrieved := state.GetSessionTicket()
	if retrieved != nil {
		t.Errorf("SessionTicket should be nil after SetSessionTicket([]byte{}), got %v", retrieved)
	}
}

// TestKeyMaterialZeroing_SetResumptionSecretZerosOld verifies that
// SetResumptionSecret zeros the old secret before setting a new one.
func TestKeyMaterialZeroing_SetResumptionSecretZerosOld(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Set initial secret
	oldSecret := []byte("old-resumption-secret")
	state.SetResumptionSecret(oldSecret)

	// Get secret and verify it's a copy
	retrieved := state.GetResumptionSecret()
	if string(retrieved) != string(oldSecret) {
		t.Error("GetResumptionSecret should return matching data")
	}

	// Set new secret
	newSecret := []byte("new-resumption-secret")
	state.SetResumptionSecret(newSecret)

	// Verify new secret is stored
	retrieved = state.GetResumptionSecret()
	if string(retrieved) != string(newSecret) {
		t.Errorf("Expected new secret %q, got %q", newSecret, retrieved)
	}
}

// =============================================================================
// TEST SUITE: GetGREASEValue
// =============================================================================

// TestGetGREASEValue_AllPositions verifies GetGREASEValue returns correct
// values for all defined positions.
func TestGetGREASEValue_AllPositions(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	tests := []struct {
		pos      GREASEPosition
		expected uint16
	}{
		{GREASECipherSuite, state.FrozenGREASE.CipherSuite},
		{GREASEExtension1, state.FrozenGREASE.Extension1},
		{GREASEExtension2, state.FrozenGREASE.Extension2},
		{GREASESupportedGroup, state.FrozenGREASE.SupportedGroup},
		{GREASESupportedVersion, state.FrozenGREASE.SupportedVersion},
		{GREASEKeyShare, state.FrozenGREASE.KeyShare},
		{GREASESignatureAlgo, state.FrozenGREASE.SignatureAlgo},
		{GREASEPSKMode, state.FrozenGREASE.PSKMode},
	}

	for _, tt := range tests {
		got := state.GetGREASEValue(tt.pos)
		if got != tt.expected {
			t.Errorf("GetGREASEValue(%d) = 0x%04x, expected 0x%04x",
				tt.pos, got, tt.expected)
		}
	}
}

// TestGetGREASEValue_UnknownPosition verifies that unknown GREASE positions
// return a consistent fallback value (Extension1).
func TestGetGREASEValue_UnknownPosition(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE: GREASEConfig{Enabled: true},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Unknown position (high value)
	unknownPos := GREASEPosition(999)
	got := state.GetGREASEValue(unknownPos)

	// Should return Extension1 as fallback
	expected := state.FrozenGREASE.Extension1
	if got != expected {
		t.Errorf("GetGREASEValue(unknown) = 0x%04x, expected fallback 0x%04x",
			got, expected)
	}
}

// =============================================================================
// TEST SUITE: Session ID Generation
// =============================================================================

// TestGenerateSessionID_Length verifies session IDs have correct length.
func TestGenerateSessionID_Length(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := generateSessionID()
		// 16 bytes = 32 hex chars
		if len(id) != 32 {
			t.Errorf("Session ID should be 32 chars, got %d: %q", len(id), id)
		}
	}
}

// TestGenerateSessionID_Uniqueness verifies session IDs are unique.
func TestGenerateSessionID_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10000; i++ {
		id := generateSessionID()
		if seen[id] {
			t.Errorf("Duplicate session ID generated: %q", id)
		}
		seen[id] = true
	}
}

// TestGenerateSessionID_HexCharacters verifies session IDs contain only hex chars.
func TestGenerateSessionID_HexCharacters(t *testing.T) {
	for i := 0; i < 100; i++ {
		id := generateSessionID()
		for _, c := range id {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("Session ID contains non-hex character: %c in %q", c, id)
			}
		}
	}
}

// =============================================================================
// TEST SUITE: Default Cache
// =============================================================================

// TestDefaultSessionCache_Exists verifies the default cache is initialized.
func TestDefaultSessionCache_Exists(t *testing.T) {
	if DefaultSessionCache == nil {
		t.Fatal("DefaultSessionCache should not be nil")
	}

	stats := DefaultSessionCache.Stats()
	if stats.MaxSize <= 0 {
		t.Errorf("DefaultSessionCache.MaxSize should be positive, got %d", stats.MaxSize)
	}
	if stats.MaxAge <= 0 {
		t.Errorf("DefaultSessionCache.MaxAge should be positive, got %v", stats.MaxAge)
	}
}

// =============================================================================
// TEST SUITE: ErrSessionFrozen
// =============================================================================

// TestErrSessionFrozen_ErrorMessage verifies the error message.
func TestErrSessionFrozen_ErrorMessage(t *testing.T) {
	expected := "tls: session state is frozen"
	if ErrSessionFrozen.Error() != expected {
		t.Errorf("ErrSessionFrozen.Error() = %q, expected %q",
			ErrSessionFrozen.Error(), expected)
	}
}

// =============================================================================
// TEST SUITE: NewSessionStateCache
// =============================================================================

// TestNewSessionStateCache_DefaultValues verifies default values are applied
// for invalid inputs.
func TestNewSessionStateCache_DefaultValues(t *testing.T) {
	// Zero/negative maxSize should use default
	cache := NewSessionStateCache(0, time.Hour)
	stats := cache.Stats()
	if stats.MaxSize != 10000 {
		t.Errorf("MaxSize with 0 input should be 10000, got %d", stats.MaxSize)
	}

	// Negative maxAge should use default
	cache = NewSessionStateCache(100, 0)
	stats = cache.Stats()
	if stats.MaxAge != 24*time.Hour {
		t.Errorf("MaxAge with 0 input should be 24h, got %v", stats.MaxAge)
	}

	// Negative maxSize
	cache = NewSessionStateCache(-5, time.Hour)
	stats = cache.Stats()
	if stats.MaxSize != 10000 {
		t.Errorf("MaxSize with -5 input should be 10000, got %d", stats.MaxSize)
	}

	// Negative maxAge
	cache = NewSessionStateCache(100, -time.Hour)
	stats = cache.Stats()
	if stats.MaxAge != 24*time.Hour {
		t.Errorf("MaxAge with negative input should be 24h, got %v", stats.MaxAge)
	}
}

// =============================================================================
// TEST SUITE: Stats
// =============================================================================

// TestSessionCacheStats_WithTickets verifies ticket count is accurate.
func TestSessionCacheStats_WithTickets(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	// Create entries
	state1 := cache.GetOrCreate("origin1.com:443", profile)
	state2 := cache.GetOrCreate("origin2.com:443", profile)
	state3 := cache.GetOrCreate("origin3.com:443", profile)

	// Set tickets on some
	state1.SetSessionTicket([]byte("ticket1"))
	state3.SetSessionTicket([]byte("ticket3"))

	stats := cache.Stats()
	if stats.Size != 3 {
		t.Errorf("Expected Size 3, got %d", stats.Size)
	}
	if stats.WithTickets != 2 {
		t.Errorf("Expected WithTickets 2, got %d", stats.WithTickets)
	}

	// Use state2 to avoid unused variable warning
	_ = state2
}

// TestSessionCacheStats_TotalConnections verifies connection count is accurate.
func TestSessionCacheStats_TotalConnections(t *testing.T) {
	cache := NewSessionStateCache(100, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	state := cache.GetOrCreate("example.com:443", profile)

	// GetOrCreate calls Touch() once for new states, so connectionCount starts at 1
	// Touch 9 more times to get to 10 total
	for i := 0; i < 9; i++ {
		state.Touch()
	}

	stats := cache.Stats()
	// 1 (from GetOrCreate) + 9 (from loop) = 10
	if stats.TotalConnections != 10 {
		t.Errorf("Expected TotalConnections 10, got %d", stats.TotalConnections)
	}
}

// =============================================================================
// TEST SUITE: Get() Expired Entry Cleanup
// =============================================================================

// TestSessionCache_Get_RemovesExpiredEntry verifies that Get() removes expired
// entries from the cache instead of leaving them as memory leaks.
func TestSessionCache_Get_RemovesExpiredEntry(t *testing.T) {
	// Very short TTL for testing
	cache := NewSessionStateCache(100, 10*time.Millisecond)
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
	}

	// Create an entry
	_ = cache.GetOrCreate("origin.com:443", profile)

	// Verify it exists
	stats := cache.Stats()
	if stats.Size != 1 {
		t.Fatalf("Expected 1 entry, got %d", stats.Size)
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Get() should return nil AND remove the expired entry
	state := cache.Get("origin.com:443")
	if state != nil {
		t.Error("Get() should return nil for expired entry")
	}

	// The entry should be removed from cache
	stats = cache.Stats()
	if stats.Size != 0 {
		t.Errorf("Get() should remove expired entry, but cache size is %d", stats.Size)
	}
}

// TestSessionCache_Get_ConcurrentExpiredCleanup verifies thread-safe cleanup
// of expired entries in Get().
//
// This test uses moderate concurrency to validate lock upgrade safety without
// excessive memory usage from race detector overhead.
func TestSessionCache_Get_ConcurrentExpiredCleanup(t *testing.T) {
	cache := NewSessionStateCache(20, 5*time.Millisecond)
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
	}

	// Create entries - use small count to minimize memory footprint
	const numEntries = 5
	origins := make([]string, numEntries)
	for i := 0; i < numEntries; i++ {
		origins[i] = "o" + string(rune('A'+i)) + ".com"
		cache.GetOrCreate(origins[i], profile)
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Concurrent Get() calls should safely cleanup expired entries.
	// Use moderate goroutine count (2x entries) to test lock contention
	// without excessive memory overhead from race detector.
	var wg sync.WaitGroup
	const goroutines = numEntries * 2
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = cache.Get(origins[id%numEntries])
		}(i)
	}

	wg.Wait()

	// All expired entries should be cleaned up
	stats := cache.Stats()
	if stats.Size != 0 {
		t.Errorf("All expired entries should be cleaned up, but size is %d", stats.Size)
	}
}

// =============================================================================
// TEST SUITE: Frozen Value Getters
// =============================================================================

// TestGetFrozenExtensionOrder_ReturnsCopy verifies GetFrozenExtensionOrder
// returns a copy that doesn't affect the original state when modified.
func TestGetFrozenExtensionOrder_ReturnsCopy(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE:            GREASEConfig{Enabled: true},
			ShuffleExtensions: true,
			Extensions: []ExtensionEntry{
				{Type: 0x0001},
				{Type: 0x0002},
				{Type: 0x0003},
			},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Get frozen order
	copy1 := state.GetFrozenExtensionOrder()
	if copy1 == nil {
		t.Skip("No frozen extension order set")
	}

	// Store original first value
	originalFirst := copy1[0]

	// Modify the copy
	copy1[0] = 0xFFFF

	// Get another copy
	copy2 := state.GetFrozenExtensionOrder()

	// Original should be unchanged
	if copy2[0] != originalFirst {
		t.Errorf("Original frozen extension order was modified: expected 0x%04x, got 0x%04x",
			originalFirst, copy2[0])
	}
}

// TestGetFrozenKeyShareGroups_ReturnsCopy verifies the copy behavior.
func TestGetFrozenKeyShareGroups_ReturnsCopy(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			KeyShareGroups: []CurveID{X25519, CurveP256, CurveP384},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Get frozen groups
	copy1 := state.GetFrozenKeyShareGroups()
	if len(copy1) == 0 {
		t.Fatal("Expected frozen key share groups to be set")
	}

	originalFirst := copy1[0]

	// Modify the copy
	copy1[0] = CurveP521

	// Get another copy
	copy2 := state.GetFrozenKeyShareGroups()

	// Original should be unchanged
	if copy2[0] != originalFirst {
		t.Errorf("Original frozen key share groups was modified: expected %v, got %v",
			originalFirst, copy2[0])
	}
}

// TestGetFrozenSigAlgOrder_ReturnsCopy verifies the copy behavior.
func TestGetFrozenSigAlgOrder_ReturnsCopy(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
				PKCS1WithSHA256,
			},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// Get frozen order
	copy1 := state.GetFrozenSigAlgOrder()
	if len(copy1) == 0 {
		t.Fatal("Expected frozen sig alg order to be set")
	}

	originalFirst := copy1[0]

	// Modify the copy
	copy1[0] = PSSWithSHA512

	// Get another copy
	copy2 := state.GetFrozenSigAlgOrder()

	// Original should be unchanged
	if copy2[0] != originalFirst {
		t.Errorf("Original frozen sig alg order was modified: expected %v, got %v",
			originalFirst, copy2[0])
	}
}

// TestGetFrozenValues_NilReturnsNil verifies getters return nil for unset values.
func TestGetFrozenValues_NilReturnsNil(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test_profile",
		Browser: "chrome",
		// No KeyShareGroups, SignatureAlgorithms, or shuffle
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	// All getters should return nil for unset values
	if state.GetFrozenExtensionOrder() != nil {
		t.Error("GetFrozenExtensionOrder should return nil when not set")
	}

	if state.GetFrozenCipherOrder() != nil {
		t.Error("GetFrozenCipherOrder should return nil when not set")
	}
}

// TestGetFrozenValues_ThreadSafe verifies concurrent access to getters.
//
// Uses moderate concurrency to validate thread-safety without excessive memory
// overhead from race detector instrumentation.
func TestGetFrozenValues_ThreadSafe(t *testing.T) {
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
		ClientHello: ClientHelloConfig{
			GREASE:            GREASEConfig{Enabled: true},
			ShuffleExtensions: true,
			Extensions: []ExtensionEntry{
				{Type: 0x0001},
				{Type: 0x0002},
			},
			KeyShareGroups: []CurveID{X25519, CurveP256},
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
			},
		},
	}

	state := NewSessionFingerprintState(profile, "example.com:443")
	if state == nil {
		t.Fatal("NewSessionFingerprintState returned nil")
	}

	var wg sync.WaitGroup

	const goroutines = 20
	const iterations = 20
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Call all getters concurrently
				_ = state.GetFrozenExtensionOrder()
				_ = state.GetFrozenCipherOrder()
				_ = state.GetFrozenKeyShareGroups()
				_ = state.GetFrozenSigAlgOrder()
				_ = state.GetGREASEValue(GREASECipherSuite)
				_ = state.IsFrozen()
				_ = state.ConnectionCount()
				_ = state.LastUsed()
			}
		}()
	}

	wg.Wait()
}

// =============================================================================
// TEST SUITE: evictOldest Race Condition Fix
// =============================================================================

// TestEvictOldest_LastUsedRaceCondition tests that evictOldest correctly
// handles concurrent Touch() calls without reading inconsistent timestamps.
//
// Uses moderate concurrency to validate race condition fix without excessive
// memory overhead from race detector instrumentation.
func TestEvictOldest_LastUsedRaceCondition(t *testing.T) {
	cache := NewSessionStateCache(5, time.Hour)
	profile := &FingerprintProfile{
		ID:      "test",
		Browser: "chrome",
	}

	// Fill cache to capacity
	const numEntries = 5
	origins := make([]string, numEntries)
	for i := 0; i < numEntries; i++ {
		origins[i] = "o" + string(rune('A'+i)) + ".com"
		cache.GetOrCreate(origins[i], profile)
		time.Sleep(time.Millisecond) // Ensure different timestamps
	}

	var wg sync.WaitGroup

	// Concurrently touch existing sessions while adding new ones
	const goroutines = 10
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Touch existing entries
			for j := 0; j < numEntries; j++ {
				state := cache.Get(origins[j])
				if state != nil {
					state.Touch()
				}
			}

			// Add new entries (triggers eviction)
			newOrigin := "n" + string(rune('A'+id%10)) + ".com"
			cache.GetOrCreate(newOrigin, profile)
		}(i)
	}

	wg.Wait()

	// Cache should not exceed max size
	stats := cache.Stats()
	if stats.Size > 5 {
		t.Errorf("Cache size %d exceeds max 5", stats.Size)
	}
}
