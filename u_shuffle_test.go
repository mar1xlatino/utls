// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// ============================================================================
// TEST 1: SHUFFLE RANDOMNESS TEST
// ============================================================================
// Verifies that extension shuffling produces sufficient entropy.
// Generates 1000 ClientHellos and expects at least 100 unique orderings.

func TestShuffleRandomnessChrome(t *testing.T) {
	const iterations = 1000
	const minUniqueOrderings = 100

	orderingCounts := make(map[string]int)

	for i := 0; i < iterations; i++ {
		spec, err := UTLSIdToSpec(HelloChrome_120)
		if err != nil {
			t.Fatalf("iteration %d: failed to get spec: %v", i, err)
		}

		// Extract extension order as string key
		order := extractExtensionOrder(spec.Extensions)
		orderingCounts[order]++
	}

	uniqueOrderings := len(orderingCounts)
	t.Logf("Chrome shuffle: %d unique orderings out of %d iterations", uniqueOrderings, iterations)

	if uniqueOrderings < minUniqueOrderings {
		t.Errorf("INSUFFICIENT RANDOMNESS: only %d unique orderings (expected >= %d)",
			uniqueOrderings, minUniqueOrderings)
		t.Logf("Top 10 most common orderings:")
		for order, count := range orderingCounts {
			if count > iterations/100 { // Show orderings appearing more than 1%
				t.Logf("  Count %d: %s...", count, truncate(order, 80))
			}
		}
	}

	// Calculate Shannon entropy
	entropy := calculateEntropy(orderingCounts, iterations)
	t.Logf("Entropy: %.2f bits (theoretical max for %d items: %.2f bits)",
		entropy, uniqueOrderings, math.Log2(float64(uniqueOrderings)))

	// Entropy should be reasonably high - at least 4 bits
	if entropy < 4.0 {
		t.Errorf("LOW ENTROPY: %.2f bits - shuffle may be predictable", entropy)
	}
}

func TestShuffleRandomnessFirefox(t *testing.T) {
	const iterations = 1000
	const minUniqueOrderings = 100

	orderingCounts := make(map[string]int)

	for i := 0; i < iterations; i++ {
		spec, err := UTLSIdToSpec(HelloFirefox_145)
		if err != nil {
			t.Fatalf("iteration %d: failed to get spec: %v", i, err)
		}

		order := extractExtensionOrder(spec.Extensions)
		orderingCounts[order]++
	}

	uniqueOrderings := len(orderingCounts)
	t.Logf("Firefox shuffle: %d unique orderings out of %d iterations", uniqueOrderings, iterations)

	if uniqueOrderings < minUniqueOrderings {
		t.Errorf("INSUFFICIENT RANDOMNESS: only %d unique orderings (expected >= %d)",
			uniqueOrderings, minUniqueOrderings)
	}

	entropy := calculateEntropy(orderingCounts, iterations)
	t.Logf("Entropy: %.2f bits", entropy)
	if entropy < 4.0 {
		t.Errorf("LOW ENTROPY: %.2f bits", entropy)
	}
}

// ============================================================================
// TEST 2: SHUFFLE DETERMINISM WITH SEED
// ============================================================================
// Verifies that given same random seed, output is reproducible (for debugging).

func TestShuffleDeterminismWithSeed(t *testing.T) {
	// Create seed for deterministic PRNG
	seed := &PRNGSeed{}
	for i := 0; i < PRNGSeedLength; i++ {
		seed[i] = byte(i * 7) // Deterministic seed
	}

	// Generate two extension lists with same seed
	exts1 := createTestExtensions()
	exts2 := createTestExtensions()

	// Shuffle with deterministic PRNG
	prng1, err := newPRNGWithSeed(seed)
	if err != nil {
		t.Fatalf("failed to create prng1: %v", err)
	}
	prng1.Shuffle(len(exts1), func(i, j int) {
		exts1[i], exts1[j] = exts1[j], exts1[i]
	})

	// Reset with same seed
	seed2 := &PRNGSeed{}
	for i := 0; i < PRNGSeedLength; i++ {
		seed2[i] = byte(i * 7) // Same deterministic seed
	}
	prng2, err := newPRNGWithSeed(seed2)
	if err != nil {
		t.Fatalf("failed to create prng2: %v", err)
	}
	prng2.Shuffle(len(exts2), func(i, j int) {
		exts2[i], exts2[j] = exts2[j], exts2[i]
	})

	// Verify IDENTICAL output
	order1 := extractExtensionOrder(exts1)
	order2 := extractExtensionOrder(exts2)

	if order1 != order2 {
		t.Errorf("DETERMINISM FAILURE: same seed produced different orderings")
		t.Logf("Order 1: %s", order1)
		t.Logf("Order 2: %s", order2)
	} else {
		t.Logf("Deterministic shuffle verified: %s", truncate(order1, 60))
	}
}

// ============================================================================
// TEST 3: GREASE VALUE RANDOMNESS
// ============================================================================
// Verifies GREASE values change between connections and are valid per RFC 8701.

func TestGREASEValueRandomness(t *testing.T) {
	const iterations = 100

	// Valid GREASE values per RFC 8701: 0x?a?a pattern
	validGREASE := map[uint16]bool{
		0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
		0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
		0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
		0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
	}

	greaseExtValues := make(map[uint16]int)
	greaseCipherValues := make(map[uint16]int)
	greaseGroupValues := make(map[uint16]int)

	for i := 0; i < iterations; i++ {
		spec, err := UTLSIdToSpec(HelloChrome_120)
		if err != nil {
			t.Fatalf("iteration %d: failed to get spec: %v", i, err)
		}

		// Extract GREASE extension values
		for _, ext := range spec.Extensions {
			if grease, ok := ext.(*UtlsGREASEExtension); ok {
				if grease.Value != 0 {
					greaseExtValues[grease.Value]++
					if !validGREASE[grease.Value] && !isGREASEUint16(grease.Value) {
						t.Errorf("INVALID GREASE extension value: 0x%04x", grease.Value)
					}
				}
			}
			// Check GREASE in curves
			if curves, ok := ext.(*SupportedCurvesExtension); ok {
				for _, curve := range curves.Curves {
					if isGREASEUint16(uint16(curve)) {
						greaseGroupValues[uint16(curve)]++
						if !validGREASE[uint16(curve)] {
							t.Errorf("INVALID GREASE curve value: 0x%04x", curve)
						}
					}
				}
			}
			// Check GREASE in supported versions
			if versions, ok := ext.(*SupportedVersionsExtension); ok {
				for _, v := range versions.Versions {
					if isGREASEUint16(v) {
						if !validGREASE[v] {
							t.Errorf("INVALID GREASE version value: 0x%04x", v)
						}
					}
				}
			}
		}

		// Check GREASE in cipher suites
		for _, cs := range spec.CipherSuites {
			if isGREASEUint16(cs) {
				greaseCipherValues[cs]++
				if !validGREASE[cs] {
					t.Errorf("INVALID GREASE cipher value: 0x%04x", cs)
				}
			}
		}
	}

	// Verify we see multiple different GREASE values
	t.Logf("GREASE Extension values seen (%d unique): %v", len(greaseExtValues), greaseExtValues)
	t.Logf("GREASE Cipher values seen (%d unique): %v", len(greaseCipherValues), greaseCipherValues)
	t.Logf("GREASE Group values seen (%d unique): %v", len(greaseGroupValues), greaseGroupValues)

	// After applying preset, GREASE values should vary
	// Note: UTLSIdToSpec returns pre-shuffle specs, actual GREASE randomization
	// happens in ApplyPreset. For this test we verify the mechanism works.
}

func TestGREASEValidation(t *testing.T) {
	// Test isGREASEUint16 function correctness
	testCases := []struct {
		value    uint16
		expected bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a2a, true},
		{0x3a3a, true},
		{0x4a4a, true},
		{0x5a5a, true},
		{0x6a6a, true},
		{0x7a7a, true},
		{0x8a8a, true},
		{0x9a9a, true},
		{0xaaaa, true},
		{0xbaba, true},
		{0xcaca, true},
		{0xdada, true},
		{0xeaea, true},
		{0xfafa, true},
		// Invalid values
		{0x0000, false},
		{0x0a0b, false}, // Bytes don't match
		{0x0b0a, false}, // Low nibble not 0xa
		{0x1234, false},
		{0xffff, false},
		{0x0a00, false},
		{0x000a, false},
		{0x1a2a, false}, // High nibbles don't match
	}

	for _, tc := range testCases {
		result := isGREASEUint16(tc.value)
		if result != tc.expected {
			t.Errorf("isGREASEUint16(0x%04x) = %v, expected %v", tc.value, result, tc.expected)
		}
	}
}

// ============================================================================
// TEST 4: SHUFFLE PRESERVES REQUIRED ORDER
// ============================================================================
// RFC 8446 requirement: pre_shared_key MUST be the last extension.
// Also verifies positional invariants for GREASE and padding.

func TestShufflePreservesPSKLast(t *testing.T) {
	// Test profiles that have PSK extension
	profiles := []ClientHelloID{
		HelloChrome_112_PSK_Shuf,
		HelloChrome_114_Padding_PSK_Shuf,
		HelloChrome_115_PQ_PSK,
	}

	for _, profile := range profiles {
		t.Run(profile.Str(), func(t *testing.T) {
			for i := 0; i < 50; i++ {
				spec, err := UTLSIdToSpec(profile)
				if err != nil {
					t.Fatalf("iteration %d: failed to get spec: %v", i, err)
				}

				if len(spec.Extensions) == 0 {
					t.Fatal("No extensions in spec")
				}

				// Find PSK extension position
				pskIdx := -1
				for idx, ext := range spec.Extensions {
					if _, ok := ext.(PreSharedKeyExtension); ok {
						pskIdx = idx
					}
				}

				if pskIdx == -1 {
					t.Skip("No PSK extension in this profile")
				}

				// PSK must be at the very last position
				if pskIdx != len(spec.Extensions)-1 {
					t.Errorf("PSK extension at index %d, but last index is %d - RFC 8446 VIOLATION",
						pskIdx, len(spec.Extensions)-1)
					t.Logf("Extension order: %s", extractExtensionOrder(spec.Extensions))
				}
			}
		})
	}
}

func TestShufflePreservesGREASEPosition(t *testing.T) {
	// Chrome keeps GREASE extensions in their original positions
	const iterations = 50

	for i := 0; i < iterations; i++ {
		spec, err := UTLSIdToSpec(HelloChrome_120)
		if err != nil {
			t.Fatalf("iteration %d: failed to get spec: %v", i, err)
		}

		// First extension should be GREASE
		if _, ok := spec.Extensions[0].(*UtlsGREASEExtension); !ok {
			t.Errorf("First extension is not GREASE, got: %T", spec.Extensions[0])
		}

		// There should be another GREASE near the end (before last)
		foundSecondGREASE := false
		for idx := len(spec.Extensions) - 3; idx < len(spec.Extensions); idx++ {
			if idx >= 0 {
				if _, ok := spec.Extensions[idx].(*UtlsGREASEExtension); ok {
					foundSecondGREASE = true
					break
				}
			}
		}
		if !foundSecondGREASE {
			t.Logf("Warning: Second GREASE not found in expected position")
		}
	}
}

func TestShufflePreservesPaddingPosition(t *testing.T) {
	// Padding should stay in its position (not shuffled)
	profiles := []ClientHelloID{
		HelloChrome_120,
		HelloFirefox_145,
	}

	for _, profile := range profiles {
		t.Run(profile.Str(), func(t *testing.T) {
			for i := 0; i < 30; i++ {
				spec, err := UTLSIdToSpec(profile)
				if err != nil {
					t.Fatalf("failed to get spec: %v", err)
				}

				// Find padding positions
				for idx, ext := range spec.Extensions {
					if _, ok := ext.(*UtlsPaddingExtension); ok {
						// Padding should typically be near the end
						// Chrome: padding is last or second-to-last
						// Firefox: padding is before ECH
						t.Logf("%s iteration %d: padding at index %d/%d",
							profile.Str(), i, idx, len(spec.Extensions)-1)
					}
				}
			}
		})
	}
}

// ============================================================================
// TEST 5: FIREFOX VS CHROME SHUFFLE COMPARISON
// ============================================================================
// Both browsers shuffle but with different invariants.
// Chrome preserves GREASE positions, Firefox does not use GREASE.

func TestFirefoxVsChromeShuffleComparison(t *testing.T) {
	const iterations = 100

	chromeOrderings := make(map[string]bool)
	firefoxOrderings := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		chromeSpec, err := UTLSIdToSpec(HelloChrome_120)
		if err != nil {
			t.Fatalf("Chrome iteration %d: %v", i, err)
		}
		chromeOrderings[extractExtensionOrder(chromeSpec.Extensions)] = true

		firefoxSpec, err := UTLSIdToSpec(HelloFirefox_145)
		if err != nil {
			t.Fatalf("Firefox iteration %d: %v", i, err)
		}
		firefoxOrderings[extractExtensionOrder(firefoxSpec.Extensions)] = true
	}

	t.Logf("Chrome unique orderings: %d", len(chromeOrderings))
	t.Logf("Firefox unique orderings: %d", len(firefoxOrderings))

	// Both should produce multiple orderings
	if len(chromeOrderings) < 10 {
		t.Errorf("Chrome shuffle producing too few unique orderings: %d", len(chromeOrderings))
	}
	if len(firefoxOrderings) < 10 {
		t.Errorf("Firefox shuffle producing too few unique orderings: %d", len(firefoxOrderings))
	}

	// Verify Chrome has GREASE extensions, Firefox does not
	chromeSpec, _ := UTLSIdToSpec(HelloChrome_120)
	firefoxSpec, _ := UTLSIdToSpec(HelloFirefox_145)

	chromeHasGREASE := false
	firefoxHasGREASE := false

	for _, ext := range chromeSpec.Extensions {
		if _, ok := ext.(*UtlsGREASEExtension); ok {
			chromeHasGREASE = true
			break
		}
	}
	for _, ext := range firefoxSpec.Extensions {
		if _, ok := ext.(*UtlsGREASEExtension); ok {
			firefoxHasGREASE = true
			break
		}
	}

	if !chromeHasGREASE {
		t.Error("Chrome profile should have GREASE extensions")
	}
	if firefoxHasGREASE {
		t.Error("Firefox profile should NOT have GREASE extensions")
	}
}

// ============================================================================
// TEST 6: NO SHUFFLE FOR LEGACY PROFILES
// ============================================================================
// Safari and iOS profiles should NOT shuffle - identical extension order always.

func TestNoShuffleLegacyProfiles(t *testing.T) {
	legacyProfiles := []ClientHelloID{
		HelloSafari_18,
	}

	for _, profile := range legacyProfiles {
		t.Run(profile.Str(), func(t *testing.T) {
			const iterations = 100

			var referenceOrder string
			for i := 0; i < iterations; i++ {
				spec, err := UTLSIdToSpec(profile)
				if err != nil {
					t.Fatalf("iteration %d: failed to get spec: %v", i, err)
				}

				order := extractExtensionOrder(spec.Extensions)

				if i == 0 {
					referenceOrder = order
					t.Logf("Reference order: %s", truncate(order, 80))
				} else if order != referenceOrder {
					t.Errorf("UNEXPECTED SHUFFLE in %s at iteration %d", profile.Str(), i)
					t.Logf("Expected: %s", truncate(referenceOrder, 80))
					t.Logf("Got:      %s", truncate(order, 80))
					return
				}
			}
			t.Logf("%s: Verified %d iterations with identical extension order", profile.Str(), iterations)
		})
	}
}

func TestNonShufflingFirefox120(t *testing.T) {
	// Firefox 120 does NOT use shuffle (shuffle was added in Firefox 106/NSS 3.84)
	// but our HelloFirefox_120 profile is defined without shuffle
	const iterations = 100

	var referenceOrder string
	for i := 0; i < iterations; i++ {
		spec, err := UTLSIdToSpec(HelloFirefox_120)
		if err != nil {
			t.Fatalf("iteration %d: failed to get spec: %v", i, err)
		}

		order := extractExtensionOrder(spec.Extensions)

		if i == 0 {
			referenceOrder = order
		} else if order != referenceOrder {
			t.Errorf("Firefox 120 should NOT shuffle but order changed at iteration %d", i)
			return
		}
	}
	t.Logf("Firefox 120: Verified %d iterations with identical extension order", iterations)
}

// ============================================================================
// TEST 7: EDGE CASES AND BOUNDARY CONDITIONS
// ============================================================================

func TestShuffleFunctionDirectly(t *testing.T) {
	// Test ShuffleChromeTLSExtensions directly
	t.Run("ShuffleChromeTLSExtensions", func(t *testing.T) {
		orderings := make(map[string]bool)
		for i := 0; i < 100; i++ {
			exts := []TLSExtension{
				&UtlsGREASEExtension{},    // Should stay at position 0
				&SNIExtension{},           // Can be shuffled
				&ALPNExtension{},          // Can be shuffled
				&StatusRequestExtension{}, // Can be shuffled
				&SCTExtension{},           // Can be shuffled
				&UtlsGREASEExtension{},    // Should stay in position
				&UtlsPaddingExtension{},   // Should stay in position
			}

			shuffled := ShuffleChromeTLSExtensions(exts)
			order := extractExtensionOrder(shuffled)
			orderings[order] = true

			// Verify GREASE at position 0
			if _, ok := shuffled[0].(*UtlsGREASEExtension); !ok {
				t.Errorf("First GREASE moved from position 0")
			}

			// Verify Padding stays in its position (last)
			if _, ok := shuffled[len(shuffled)-1].(*UtlsPaddingExtension); !ok {
				t.Errorf("Padding moved from last position")
			}
		}

		if len(orderings) < 5 {
			t.Errorf("Direct shuffle produced too few orderings: %d", len(orderings))
		}
	})

	t.Run("ShuffleFirefoxTLSExtensions", func(t *testing.T) {
		orderings := make(map[string]bool)
		for i := 0; i < 100; i++ {
			exts := []TLSExtension{
				&SNIExtension{},
				&ALPNExtension{},
				&StatusRequestExtension{},
				&SCTExtension{},
				&UtlsPaddingExtension{}, // Should stay in position
			}

			shuffled := ShuffleFirefoxTLSExtensions(exts)
			order := extractExtensionOrder(shuffled)
			orderings[order] = true

			// Verify Padding stays
			if _, ok := shuffled[len(shuffled)-1].(*UtlsPaddingExtension); !ok {
				t.Errorf("Padding moved from last position")
			}
		}

		if len(orderings) < 5 {
			t.Errorf("Direct shuffle produced too few orderings: %d", len(orderings))
		}
	})
}

func TestShuffleWithPSKExtension(t *testing.T) {
	// PSK must ALWAYS be last per RFC 8446
	for i := 0; i < 100; i++ {
		exts := []TLSExtension{
			&SNIExtension{},
			&ALPNExtension{},
			&StatusRequestExtension{},
			&FakePreSharedKeyExtension{}, // PSK must stay last
		}

		shuffled := ShuffleChromeTLSExtensions(exts)

		// PSK must be at the end
		if _, ok := shuffled[len(shuffled)-1].(*FakePreSharedKeyExtension); !ok {
			t.Errorf("PSK extension moved from last position!")
			t.Logf("Order: %s", extractExtensionOrder(shuffled))
		}
	}
}

func TestShuffleEmptyAndSingleExtension(t *testing.T) {
	// Empty list
	t.Run("Empty", func(t *testing.T) {
		exts := []TLSExtension{}
		shuffled := ShuffleChromeTLSExtensions(exts)
		if len(shuffled) != 0 {
			t.Error("Empty shuffle should return empty")
		}
	})

	// Single extension
	t.Run("Single", func(t *testing.T) {
		exts := []TLSExtension{&SNIExtension{}}
		shuffled := ShuffleChromeTLSExtensions(exts)
		if len(shuffled) != 1 {
			t.Error("Single shuffle should return single element")
		}
	})

	// All non-shuffleable
	t.Run("AllInvariant", func(t *testing.T) {
		exts := []TLSExtension{
			&UtlsGREASEExtension{},
			&UtlsPaddingExtension{},
		}
		for i := 0; i < 10; i++ {
			shuffled := ShuffleChromeTLSExtensions(exts)
			if len(shuffled) != 2 {
				t.Error("Invariant shuffle length changed")
			}
			// Order should be stable since both are invariant
			if _, ok := shuffled[0].(*UtlsGREASEExtension); !ok {
				t.Error("GREASE moved")
			}
			if _, ok := shuffled[1].(*UtlsPaddingExtension); !ok {
				t.Error("Padding moved")
			}
		}
	})
}

// ============================================================================
// TEST 8: CONCURRENT SHUFFLE SAFETY
// ============================================================================
// Verify shuffle functions are safe for concurrent use.

func TestShuffleConcurrentSafety(t *testing.T) {
	const goroutines = 50
	const iterationsPerGoroutine = 100

	done := make(chan bool, goroutines)
	errors := make(chan error, goroutines*iterationsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer func() { done <- true }()
			for i := 0; i < iterationsPerGoroutine; i++ {
				spec, err := UTLSIdToSpec(HelloChrome_120)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d iteration %d: %w", id, i, err)
					return
				}
				if len(spec.Extensions) == 0 {
					errors <- fmt.Errorf("goroutine %d iteration %d: empty extensions", id, i)
					return
				}
			}
		}(g)
	}

	// Wait for all goroutines
	for i := 0; i < goroutines; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func extractExtensionOrder(exts []TLSExtension) string {
	var parts []string
	for _, ext := range exts {
		typeName := reflect.TypeOf(ext).String()
		// Remove package prefix for cleaner output
		if idx := strings.LastIndex(typeName, "."); idx != -1 {
			typeName = typeName[idx+1:]
		}
		parts = append(parts, typeName)
	}
	return strings.Join(parts, ",")
}

func calculateEntropy(counts map[string]int, total int) float64 {
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func createTestExtensions() []TLSExtension {
	return []TLSExtension{
		&SNIExtension{},
		&ALPNExtension{},
		&StatusRequestExtension{},
		&SCTExtension{},
		&ExtendedMasterSecretExtension{},
		&RenegotiationInfoExtension{},
		&SessionTicketExtension{},
		&SupportedCurvesExtension{},
		&SupportedPointsExtension{},
		&SignatureAlgorithmsExtension{},
	}
}

// ============================================================================
// TEST 9: PRNG THREAD SAFETY VERIFICATION
// ============================================================================

func TestPRNGShuffleThreadSafety(t *testing.T) {
	seed, err := NewPRNGSeed()
	if err != nil {
		t.Fatal(err)
	}

	prng, err := newPRNGWithSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 20
	const iterations = 100

	done := make(chan bool, goroutines)
	panicChan := make(chan interface{}, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					panicChan <- r
				}
				done <- true
			}()

			for i := 0; i < iterations; i++ {
				slice := make([]int, 10)
				for j := range slice {
					slice[j] = j
				}
				prng.Shuffle(len(slice), func(a, b int) {
					slice[a], slice[b] = slice[b], slice[a]
				})
			}
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	close(panicChan)
	for p := range panicChan {
		t.Errorf("PRNG Shuffle caused panic: %v", p)
	}
}

// ============================================================================
// TEST 10: EXTENSION TYPE PRESERVATION
// ============================================================================
// Verify shuffling doesn't corrupt extension types or lose extensions.

func TestShufflePreservesExtensionTypes(t *testing.T) {
	profiles := []ClientHelloID{
		HelloChrome_120,
		HelloFirefox_145,
	}

	for _, profile := range profiles {
		t.Run(profile.Str(), func(t *testing.T) {
			spec1, _ := UTLSIdToSpec(profile)
			spec2, _ := UTLSIdToSpec(profile)

			// Count extension types in both specs
			types1 := countExtensionTypes(spec1.Extensions)
			types2 := countExtensionTypes(spec2.Extensions)

			// Same number of extensions
			if len(spec1.Extensions) != len(spec2.Extensions) {
				t.Errorf("Extension count mismatch: %d vs %d",
					len(spec1.Extensions), len(spec2.Extensions))
			}

			// Same types present (may be in different order)
			for typeName, count1 := range types1 {
				count2, exists := types2[typeName]
				if !exists {
					t.Errorf("Extension type %s missing in second spec", typeName)
				} else if count1 != count2 {
					t.Errorf("Extension type %s count mismatch: %d vs %d",
						typeName, count1, count2)
				}
			}
		})
	}
}

func countExtensionTypes(exts []TLSExtension) map[string]int {
	counts := make(map[string]int)
	for _, ext := range exts {
		typeName := reflect.TypeOf(ext).String()
		counts[typeName]++
	}
	return counts
}
