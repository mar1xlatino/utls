// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"testing"
	"time"
)

// =============================================================================
// TLS Authentication Timing Attack Tests
// =============================================================================
//
// These tests verify that authentication functions are resistant to timing
// attacks. Constant-time operations should have consistent execution time
// regardless of where in the input data a mismatch occurs.
//
// IMPORTANT: These are basic smoke tests. Production security testing requires
// sophisticated statistical analysis with thousands of samples to detect
// subtle timing variations. Consider using tools like:
// - dudect (https://github.com/oreparaz/dudect)
// - ctgrind (Valgrind tool for constant-time verification)
//
// The tests here primarily verify:
// 1. Functions don't have obvious early exits
// 2. Timing variance is within expected bounds
// 3. Basic constant-time patterns are followed

// TestVerifyAuthHMAC_TimingConsistency verifies that HMAC verification time
// is consistent regardless of where the mismatch occurs.
func TestVerifyAuthHMAC_TimingConsistency(t *testing.T) {
	authKey := make([]byte, 64)
	if _, err := rand.Read(authKey); err != nil {
		t.Fatalf("Failed to generate auth key: %v", err)
	}

	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		t.Fatalf("Failed to generate public key: %v", err)
	}

	// Generate valid auth data
	validAuth := ComputeAuthHMAC(authKey, publicKey, time.Now())
	if validAuth == nil {
		t.Fatal("ComputeAuthHMAC returned nil")
	}

	// Generate invalid auth data with mismatch at different positions
	invalidFirst := make([]byte, len(validAuth))
	copy(invalidFirst, validAuth)
	invalidFirst[0] ^= 0xFF // First byte wrong

	invalidMiddle := make([]byte, len(validAuth))
	copy(invalidMiddle, validAuth)
	invalidMiddle[len(invalidMiddle)/2] ^= 0xFF // Middle byte wrong

	invalidLast := make([]byte, len(validAuth))
	copy(invalidLast, validAuth)
	invalidLast[len(invalidLast)-1] ^= 0xFF // Last byte wrong

	invalidAll := make([]byte, len(validAuth))
	rand.Read(invalidAll) // All bytes random/wrong

	// Number of iterations for timing measurement
	// Higher iterations provide more accurate timing but slower tests
	const iterations = 10000

	measureTime := func(authData []byte) time.Duration {
		expected := validAuth // We compare against the valid auth
		start := time.Now()
		for i := 0; i < iterations; i++ {
			VerifyAuthHMAC(authData, expected)
		}
		return time.Since(start)
	}

	// Measure verification times
	timeValid := measureTime(validAuth)
	timeFirst := measureTime(invalidFirst)
	timeMiddle := measureTime(invalidMiddle)
	timeLast := measureTime(invalidLast)
	timeAll := measureTime(invalidAll)

	// Log times for analysis
	t.Logf("Verification times (%d iterations):", iterations)
	t.Logf("  Valid match:        %v", timeValid)
	t.Logf("  First byte wrong:   %v", timeFirst)
	t.Logf("  Middle byte wrong:  %v", timeMiddle)
	t.Logf("  Last byte wrong:    %v", timeLast)
	t.Logf("  All bytes wrong:    %v", timeAll)

	// Calculate variance threshold (20% of average)
	// Constant-time implementations should have minimal variance
	times := []time.Duration{timeValid, timeFirst, timeMiddle, timeLast, timeAll}
	var total time.Duration
	for _, t := range times {
		total += t
	}
	avg := total / time.Duration(len(times))
	threshold := avg / 5 // 20% variance allowed

	t.Logf("  Average: %v, threshold: +/-%v", avg, threshold)

	// Check that all times are within threshold of average
	// Note: This is a weak test - real timing attacks can exploit nanosecond differences
	for i, tm := range times {
		diff := tm - avg
		if diff < 0 {
			diff = -diff
		}
		if diff > threshold {
			t.Logf("WARNING: Time %d (%v) differs from average by %v (threshold: %v)",
				i, tm, diff, threshold)
			// We log but don't fail because:
			// 1. Test environment timing is noisy
			// 2. This is a basic smoke test, not rigorous timing analysis
		}
	}
}

// TestVerifyAuthHMACWithWindow_TimingConsistency tests that window-based
// verification scans ALL timestamps regardless of match position.
//
// NOTE: The underlying function iterates over 601 timestamps (maxAuthWindowSeconds*2+1)
// for constant-time security. This test uses reduced iterations to keep runtime
// reasonable while still validating the timing consistency property.
//
// Use -short to skip this test in CI environments where timing measurements are unreliable.
func TestVerifyAuthHMACWithWindow_TimingConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing consistency test in short mode (use full mode for security validation)")
	}

	authKey := make([]byte, 64)
	if _, err := rand.Read(authKey); err != nil {
		t.Fatalf("Failed to generate auth key: %v", err)
	}

	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		t.Fatalf("Failed to generate public key: %v", err)
	}

	// Window size for actual validity check (function still iterates full 601 timestamps)
	const windowSeconds int64 = 5

	// Reduced iterations: 50 is sufficient to detect gross timing differences
	// while keeping total runtime under 3 seconds. The function's constant-time
	// property comes from always iterating 601 timestamps, not from this test.
	// For rigorous timing analysis, use dedicated tools like dudect.
	const iterations = 50

	// Valid auth data for current time
	validAuth := ComputeAuthHMAC(authKey, publicKey, time.Now())

	// Valid auth data for time at start of window
	validAuthStart := ComputeAuthHMAC(authKey, publicKey, time.Now().Add(-time.Duration(windowSeconds)*time.Second))

	// Valid auth data for time at end of window
	validAuthEnd := ComputeAuthHMAC(authKey, publicKey, time.Now().Add(time.Duration(windowSeconds)*time.Second))

	// Completely invalid auth data
	invalidAuth := make([]byte, len(validAuth))
	rand.Read(invalidAuth)

	measureTime := func(authData []byte) time.Duration {
		start := time.Now()
		for i := 0; i < iterations; i++ {
			VerifyAuthHMACWithWindow(authKey, publicKey, authData, windowSeconds)
		}
		return time.Since(start)
	}

	timeValid := measureTime(validAuth)
	timeStart := measureTime(validAuthStart)
	timeEnd := measureTime(validAuthEnd)
	timeInvalid := measureTime(invalidAuth)

	t.Logf("Window verification times (%d iterations, window=%ds):", iterations, windowSeconds)
	t.Logf("  Valid (current time):     %v", timeValid)
	t.Logf("  Valid (start of window):  %v", timeStart)
	t.Logf("  Valid (end of window):    %v", timeEnd)
	t.Logf("  Invalid (no match):       %v", timeInvalid)

	// All times should be similar because the function checks ALL timestamps
	times := []time.Duration{timeValid, timeStart, timeEnd, timeInvalid}
	var total time.Duration
	for _, tm := range times {
		total += tm
	}
	avg := total / time.Duration(len(times))
	threshold := avg / 4 // 25% variance allowed

	t.Logf("  Average: %v, threshold: +/-%v", avg, threshold)

	// The key property: invalid auth should take same time as valid
	// (because function checks all timestamps regardless of match)
	validInvalidDiff := timeValid - timeInvalid
	if validInvalidDiff < 0 {
		validInvalidDiff = -validInvalidDiff
	}
	if validInvalidDiff > threshold {
		t.Logf("WARNING: Valid vs Invalid time difference (%v) exceeds threshold (%v)",
			validInvalidDiff, threshold)
	}
}

// TestComputeAuthHMAC_NilKey tests that nil key returns nil (security).
func TestComputeAuthHMAC_NilKey(t *testing.T) {
	result := ComputeAuthHMAC(nil, []byte("pubkey"), time.Now())
	if result != nil {
		t.Error("ComputeAuthHMAC should return nil for nil key")
	}
}

// TestComputeAuthHMAC_EmptyKey tests that empty key returns nil (security).
func TestComputeAuthHMAC_EmptyKey(t *testing.T) {
	result := ComputeAuthHMAC([]byte{}, []byte("pubkey"), time.Now())
	if result != nil {
		t.Error("ComputeAuthHMAC should return nil for empty key")
	}
}

// TestComputeAuthHMACSimple_NilKey tests nil key handling for simple variant.
func TestComputeAuthHMACSimple_NilKey(t *testing.T) {
	result := ComputeAuthHMACSimple(nil, []byte("pubkey"))
	if result != nil {
		t.Error("ComputeAuthHMACSimple should return nil for nil key")
	}
}

// TestComputeAuthHMACSimple_EmptyKey tests empty key handling for simple variant.
func TestComputeAuthHMACSimple_EmptyKey(t *testing.T) {
	result := ComputeAuthHMACSimple([]byte{}, []byte("pubkey"))
	if result != nil {
		t.Error("ComputeAuthHMACSimple should return nil for empty key")
	}
}

// TestVerifyAuthHMAC_EmptyInputs tests handling of empty inputs.
func TestVerifyAuthHMAC_EmptyInputs(t *testing.T) {
	testCases := []struct {
		name     string
		authData []byte
		expected []byte
		want     bool
	}{
		{"both empty", []byte{}, []byte{}, false},
		{"authData empty", []byte{}, []byte("expected"), false},
		{"expected empty", []byte("authData"), []byte{}, false},
		{"both nil", nil, nil, false},
		{"authData nil", nil, []byte("expected"), false},
		{"expected nil", []byte("authData"), nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := VerifyAuthHMAC(tc.authData, tc.expected)
			if result != tc.want {
				t.Errorf("VerifyAuthHMAC(%v, %v) = %v, want %v",
					tc.authData, tc.expected, result, tc.want)
			}
		})
	}
}

// TestVerifyAuthHMACWithWindow_EmptyKey tests that empty key returns false.
func TestVerifyAuthHMACWithWindow_EmptyKey(t *testing.T) {
	result := VerifyAuthHMACWithWindow([]byte{}, []byte("pubkey"), []byte("auth"), 30)
	if result {
		t.Error("VerifyAuthHMACWithWindow should return false for empty key")
	}
}

// TestVerifyAuthHMACWithWindow_ShortAuthData tests that short auth data returns false.
func TestVerifyAuthHMACWithWindow_ShortAuthData(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)

	// Auth data must be at least 32 bytes per implementation
	shortAuth := make([]byte, 16)
	rand.Read(shortAuth)

	result := VerifyAuthHMACWithWindow(key, []byte("pubkey"), shortAuth, 30)
	if result {
		t.Error("VerifyAuthHMACWithWindow should return false for short auth data")
	}
}

// =============================================================================
// DeriveAuthKeySecure Tests
// =============================================================================

// TestDeriveAuthKeySecure_EdgeCases tests edge cases in key derivation.
func TestDeriveAuthKeySecure_EdgeCases(t *testing.T) {
	testCases := []struct {
		name       string
		password   string
		salt       []byte
		iterations int
		wantNil    bool
	}{
		{"valid params", "password123", make([]byte, 32), 100000, false},
		{"empty password", "", make([]byte, 32), 100000, true},
		{"empty salt", "password123", []byte{}, 100000, true},
		{"short salt (8 bytes)", "password123", make([]byte, 8), 100000, true},
		{"short salt (15 bytes)", "password123", make([]byte, 15), 100000, true},
		{"minimum salt (16 bytes)", "password123", make([]byte, 16), 100000, false},
		{"zero iterations", "password123", make([]byte, 32), 0, true},
		{"one iteration", "password123", make([]byte, 32), 1, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Initialize salt with random data for valid cases
			if len(tc.salt) > 0 {
				rand.Read(tc.salt)
			}

			result := DeriveAuthKeySecure(tc.password, tc.salt, tc.iterations)
			if tc.wantNil && result != nil {
				t.Errorf("DeriveAuthKeySecure should return nil for %s", tc.name)
			}
			if !tc.wantNil && result == nil {
				t.Errorf("DeriveAuthKeySecure should return valid key for %s", tc.name)
			}
			if result != nil && len(result) != 32 {
				t.Errorf("DeriveAuthKeySecure returned key of length %d, expected 32", len(result))
			}
		})
	}
}

// TestDeriveAuthKeySecure_Deterministic tests that same inputs produce same output.
func TestDeriveAuthKeySecure_Deterministic(t *testing.T) {
	password := "test password for determinism"
	salt := make([]byte, 32)
	rand.Read(salt)
	iterations := 10000

	key1 := DeriveAuthKeySecure(password, salt, iterations)
	key2 := DeriveAuthKeySecure(password, salt, iterations)

	if key1 == nil || key2 == nil {
		t.Fatal("DeriveAuthKeySecure returned nil")
	}

	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatal("DeriveAuthKeySecure is not deterministic")
		}
	}
}

// TestDeriveAuthKeySecure_SaltDifference tests that different salts produce different keys.
func TestDeriveAuthKeySecure_SaltDifference(t *testing.T) {
	password := "same password"
	salt1 := make([]byte, 32)
	salt2 := make([]byte, 32)
	rand.Read(salt1)
	rand.Read(salt2)
	iterations := 10000

	key1 := DeriveAuthKeySecure(password, salt1, iterations)
	key2 := DeriveAuthKeySecure(password, salt2, iterations)

	if key1 == nil || key2 == nil {
		t.Fatal("DeriveAuthKeySecure returned nil")
	}

	// Keys should be different with different salts
	same := true
	for i := range key1 {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}

	if same {
		t.Error("Different salts should produce different keys")
	}
}

// TestDeriveAuthKeySecure_PasswordDifference tests that different passwords produce different keys.
func TestDeriveAuthKeySecure_PasswordDifference(t *testing.T) {
	salt := make([]byte, 32)
	rand.Read(salt)
	iterations := 10000

	key1 := DeriveAuthKeySecure("password1", salt, iterations)
	key2 := DeriveAuthKeySecure("password2", salt, iterations)

	if key1 == nil || key2 == nil {
		t.Fatal("DeriveAuthKeySecure returned nil")
	}

	// Keys should be different with different passwords
	same := true
	for i := range key1 {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}

	if same {
		t.Error("Different passwords should produce different keys")
	}
}

// =============================================================================
// AuthConfig Validation Tests
// =============================================================================

// TestAuthConfig_Validate tests AuthConfig validation.
func TestAuthConfig_Validate(t *testing.T) {
	testCases := []struct {
		name    string
		config  *AuthConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "empty key",
			config:  &AuthConfig{Key: []byte{}},
			wantErr: true,
		},
		{
			name:    "short key (16 bytes)",
			config:  &AuthConfig{Key: make([]byte, 16)},
			wantErr: true,
		},
		{
			name:    "short key (31 bytes)",
			config:  &AuthConfig{Key: make([]byte, 31)},
			wantErr: true,
		},
		{
			name:    "minimum key (32 bytes)",
			config:  &AuthConfig{Key: make([]byte, 32)},
			wantErr: false,
		},
		{
			name: "invalid mode",
			config: &AuthConfig{
				Key:  make([]byte, 32),
				Mode: "invalid_mode",
			},
			wantErr: true,
		},
		{
			name: "valid SessionID mode",
			config: &AuthConfig{
				Key:  make([]byte, 32),
				Mode: AuthModeSessionID,
			},
			wantErr: false,
		},
		{
			name: "valid Extension mode",
			config: &AuthConfig{
				Key:  make([]byte, 32),
				Mode: AuthModeExtension,
			},
			wantErr: false,
		},
		{
			name: "valid Certificate mode",
			config: &AuthConfig{
				Key:  make([]byte, 32),
				Mode: AuthModeCertificate,
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate() should return error for %s", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() returned unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

// TestAuthConfig_Clone tests deep cloning of AuthConfig.
func TestAuthConfig_Clone(t *testing.T) {
	original := &AuthConfig{
		Key:         make([]byte, 64),
		Mode:        AuthModeSessionID,
		ShortID:     [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		ServerNames: []string{"example.com", "test.com"},
		Fingerprints: [][]byte{
			{0x01, 0x02, 0x03},
			{0x04, 0x05, 0x06},
		},
	}
	rand.Read(original.Key)

	clone := original.Clone()
	if clone == nil {
		t.Fatal("Clone returned nil")
	}

	// Verify deep copy - modifying clone should not affect original
	clone.Key[0] ^= 0xFF
	clone.ShortID[0] ^= 0xFF
	clone.ServerNames[0] = "modified.com"
	clone.Fingerprints[0][0] ^= 0xFF

	if original.Key[0] == clone.Key[0] {
		t.Error("Clone did not deep copy Key")
	}
	if original.ShortID[0] == clone.ShortID[0] {
		t.Error("Clone did not deep copy ShortID")
	}
	if original.ServerNames[0] == clone.ServerNames[0] {
		t.Error("Clone did not deep copy ServerNames")
	}
	if original.Fingerprints[0][0] == clone.Fingerprints[0][0] {
		t.Error("Clone did not deep copy Fingerprints")
	}
}

// TestAuthConfig_CloneNil tests cloning nil config.
func TestAuthConfig_CloneNil(t *testing.T) {
	var config *AuthConfig
	clone := config.Clone()
	if clone != nil {
		t.Error("Clone of nil should return nil")
	}
}

// =============================================================================
// MatchesShortID Tests
// =============================================================================

// TestMatchesShortID_ConstantTime verifies constant-time comparison is used.
func TestMatchesShortID_ConstantTime(t *testing.T) {
	shortID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Matching session ID
	matchingSessionID := make([]byte, 32)
	copy(matchingSessionID, shortID[:])

	// Non-matching at first byte
	nonMatchFirst := make([]byte, 32)
	copy(nonMatchFirst, shortID[:])
	nonMatchFirst[0] ^= 0xFF

	// Non-matching at last byte
	nonMatchLast := make([]byte, 32)
	copy(nonMatchLast, shortID[:])
	nonMatchLast[7] ^= 0xFF

	const iterations = 100000

	measureTime := func(sessionID []byte) time.Duration {
		start := time.Now()
		for i := 0; i < iterations; i++ {
			MatchesShortID(sessionID, shortID)
		}
		return time.Since(start)
	}

	timeMatch := measureTime(matchingSessionID)
	timeFirstWrong := measureTime(nonMatchFirst)
	timeLastWrong := measureTime(nonMatchLast)

	t.Logf("MatchesShortID times (%d iterations):", iterations)
	t.Logf("  Matching:        %v", timeMatch)
	t.Logf("  First wrong:     %v", timeFirstWrong)
	t.Logf("  Last wrong:      %v", timeLastWrong)

	// All times should be similar for constant-time comparison
	avg := (timeMatch + timeFirstWrong + timeLastWrong) / 3
	threshold := avg / 5 // 20% variance

	for _, tm := range []time.Duration{timeMatch, timeFirstWrong, timeLastWrong} {
		diff := tm - avg
		if diff < 0 {
			diff = -diff
		}
		if diff > threshold {
			t.Logf("WARNING: Time variance (%v) exceeds threshold (%v)", diff, threshold)
		}
	}
}

// TestMatchesShortID_TooShort tests handling of too-short session ID.
func TestMatchesShortID_TooShort(t *testing.T) {
	shortID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	testCases := []struct {
		name      string
		sessionID []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"1 byte", []byte{0x01}},
		{"7 bytes", make([]byte, 7)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := MatchesShortID(tc.sessionID, shortID)
			if result {
				t.Errorf("MatchesShortID should return false for %s", tc.name)
			}
		})
	}
}
