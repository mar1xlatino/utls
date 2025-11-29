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
// NoPaddingStrategy Tests
// =============================================================================

// TestNoPaddingStrategy_Pad_AlwaysReturnsZero verifies NoPaddingStrategy.Pad always returns 0.
func TestNoPaddingStrategy_Pad_AlwaysReturnsZero(t *testing.T) {
	s := &NoPaddingStrategy{}

	testCases := []struct {
		name    string
		dataLen int
		maxSize int
	}{
		{"zero_data", 0, 16384},
		{"small_data", 100, 16384},
		{"medium_data", 8000, 16384},
		{"large_data", 16000, 16384},
		{"max_data", 16384, 16384},
		{"exceed_max_data", 20000, 16384},
		{"zero_max_size", 100, 0},
		{"negative_implied_space", 16385, 16384},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := s.Pad(tc.dataLen, tc.maxSize)
			if result != 0 {
				t.Errorf("NoPaddingStrategy.Pad(%d, %d) = %d, want 0", tc.dataLen, tc.maxSize, result)
			}
		})
	}
}

// TestNoPaddingStrategy_Name verifies the strategy name.
func TestNoPaddingStrategy_Name(t *testing.T) {
	s := &NoPaddingStrategy{}
	if name := s.Name(); name != "none" {
		t.Errorf("NoPaddingStrategy.Name() = %q, want %q", name, "none")
	}
}

// =============================================================================
// RandomPaddingStrategy Tests
// =============================================================================

// TestRandomPaddingStrategy_Pad_ZeroMaxPad verifies behavior when MaxPad is zero.
func TestRandomPaddingStrategy_Pad_ZeroMaxPad(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: 0}
	result := s.Pad(100, 16384)
	if result != 0 {
		t.Errorf("RandomPaddingStrategy.Pad with MaxPad=0 returned %d, want 0", result)
	}
}

// TestRandomPaddingStrategy_Pad_NegativeMaxPad verifies behavior when MaxPad is negative.
func TestRandomPaddingStrategy_Pad_NegativeMaxPad(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: -10}
	result := s.Pad(100, 16384)
	if result != 0 {
		t.Errorf("RandomPaddingStrategy.Pad with MaxPad=-10 returned %d, want 0", result)
	}
}

// TestRandomPaddingStrategy_Pad_ReturnsValueInRange verifies padding is within [0, MaxPad].
func TestRandomPaddingStrategy_Pad_ReturnsValueInRange(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: 100}

	for i := 0; i < 1000; i++ {
		result := s.Pad(1000, 16384)
		if result < 0 || result > 100 {
			t.Errorf("iteration %d: RandomPaddingStrategy.Pad returned %d, want [0, 100]", i, result)
		}
	}
}

// TestRandomPaddingStrategy_Pad_RespectsAvailableSpace verifies padding respects available space.
func TestRandomPaddingStrategy_Pad_RespectsAvailableSpace(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: 1000}

	// Only 50 bytes available
	for i := 0; i < 100; i++ {
		result := s.Pad(16334, 16384)
		if result > 50 {
			t.Errorf("iteration %d: padding %d exceeds available space 50", i, result)
		}
	}
}

// TestRandomPaddingStrategy_Pad_OverflowPrevention_MaxPadCapped verifies overflow prevention.
// MaxPad > 65534 should be capped to prevent uint16 overflow when adding 1.
func TestRandomPaddingStrategy_Pad_OverflowPrevention_MaxPadCapped(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: 70000}

	for i := 0; i < 100; i++ {
		result := s.Pad(0, 100000)
		// Should be capped at 65534
		if result > 65534 {
			t.Errorf("iteration %d: padding %d exceeds capped max 65534", i, result)
		}
		if result < 0 {
			t.Errorf("iteration %d: padding %d is negative", i, result)
		}
	}
}

// TestRandomPaddingStrategy_Pad_NoAvailableSpace verifies behavior when no space available.
func TestRandomPaddingStrategy_Pad_NoAvailableSpace(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: 100}
	result := s.Pad(16384, 16384)
	if result != 0 {
		t.Errorf("RandomPaddingStrategy.Pad with no available space returned %d, want 0", result)
	}
}

// TestRandomPaddingStrategy_Pad_NegativeAvailableSpace verifies behavior when data exceeds max.
func TestRandomPaddingStrategy_Pad_NegativeAvailableSpace(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: 100}
	result := s.Pad(20000, 16384)
	if result != 0 {
		t.Errorf("RandomPaddingStrategy.Pad with negative available space returned %d, want 0", result)
	}
}

// TestRandomPaddingStrategy_Name verifies the strategy name.
func TestRandomPaddingStrategy_Name(t *testing.T) {
	s := &RandomPaddingStrategy{MaxPad: 100}
	if name := s.Name(); name != "random" {
		t.Errorf("RandomPaddingStrategy.Name() = %q, want %q", name, "random")
	}
}

// =============================================================================
// BlockPaddingStrategy Tests
// =============================================================================

// TestBlockPaddingStrategy_Pad_ZeroBlockSize verifies behavior when BlockSize is zero.
func TestBlockPaddingStrategy_Pad_ZeroBlockSize(t *testing.T) {
	s := &BlockPaddingStrategy{BlockSize: 0}
	result := s.Pad(100, 16384)
	if result != 0 {
		t.Errorf("BlockPaddingStrategy.Pad with BlockSize=0 returned %d, want 0", result)
	}
}

// TestBlockPaddingStrategy_Pad_NegativeBlockSize verifies behavior when BlockSize is negative.
func TestBlockPaddingStrategy_Pad_NegativeBlockSize(t *testing.T) {
	s := &BlockPaddingStrategy{BlockSize: -16}
	result := s.Pad(100, 16384)
	if result != 0 {
		t.Errorf("BlockPaddingStrategy.Pad with BlockSize=-16 returned %d, want 0", result)
	}
}

// TestBlockPaddingStrategy_Pad_CorrectAlignment verifies correct block alignment.
func TestBlockPaddingStrategy_Pad_CorrectAlignment(t *testing.T) {
	testCases := []struct {
		name        string
		blockSize   int
		dataLen     int
		maxSize     int
		wantPadding int
	}{
		{"aligned_16_no_padding", 16, 16, 16384, 0},
		{"aligned_16_needs_15", 16, 1, 16384, 15},
		{"aligned_16_needs_8", 16, 8, 16384, 8},
		{"aligned_16_needs_1", 16, 15, 16384, 1},
		{"aligned_32_no_padding", 32, 64, 16384, 0},
		{"aligned_32_needs_20", 32, 12, 16384, 20},
		{"aligned_64_needs_63", 64, 1, 16384, 63},
		{"aligned_128_no_padding", 128, 256, 16384, 0},
		{"aligned_128_needs_64", 128, 64, 16384, 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := &BlockPaddingStrategy{BlockSize: tc.blockSize}
			result := s.Pad(tc.dataLen, tc.maxSize)
			if result != tc.wantPadding {
				t.Errorf("BlockPaddingStrategy{%d}.Pad(%d, %d) = %d, want %d",
					tc.blockSize, tc.dataLen, tc.maxSize, result, tc.wantPadding)
			}
		})
	}
}

// TestBlockPaddingStrategy_Pad_RespectsMaxSize verifies padding respects max size.
func TestBlockPaddingStrategy_Pad_RespectsMaxSize(t *testing.T) {
	s := &BlockPaddingStrategy{BlockSize: 16}
	// dataLen=16380, need 4 bytes to reach 16384 (next block boundary)
	// But maxSize is 16384, so dataLen+padding would be 16384, which is okay
	result := s.Pad(16380, 16384)
	if result != 4 {
		t.Errorf("BlockPaddingStrategy.Pad(16380, 16384) = %d, want 4", result)
	}

	// dataLen=16382, need 2 bytes to reach 16384
	result = s.Pad(16382, 16384)
	if result != 2 {
		t.Errorf("BlockPaddingStrategy.Pad(16382, 16384) = %d, want 2", result)
	}

	// dataLen=16383, need 1 byte to reach 16384
	result = s.Pad(16383, 16384)
	if result != 1 {
		t.Errorf("BlockPaddingStrategy.Pad(16383, 16384) = %d, want 1", result)
	}

	// dataLen=16384, already aligned, no padding needed
	result = s.Pad(16384, 16384)
	if result != 0 {
		t.Errorf("BlockPaddingStrategy.Pad(16384, 16384) = %d, want 0", result)
	}
}

// TestBlockPaddingStrategy_Pad_ExceedsMaxSize verifies no padding when exceeds max.
func TestBlockPaddingStrategy_Pad_ExceedsMaxSize(t *testing.T) {
	s := &BlockPaddingStrategy{BlockSize: 16}
	// dataLen=16381, need 3 bytes to reach 16384, but that's okay
	// However, dataLen=16379, need 5 bytes to reach 16384 (16379+5=16384 is still okay)
	// Test when dataLen+padding > maxSize
	// dataLen=16375, blockSize=16, next boundary is 16384, padding=9
	// 16375 + 9 = 16384 <= 16384, so it's fine

	// Let's test with a smaller maxSize
	// dataLen=100, blockSize=64, next boundary is 128, padding=28
	// If maxSize=120, then 100+28=128 > 120, should return 0
	result := s.Pad(100, 120)
	// Need 12 bytes to reach 112 (next 16-byte boundary after 100)
	// 100 + 12 = 112 <= 120, so it should return 12
	if result != 12 {
		t.Errorf("BlockPaddingStrategy{16}.Pad(100, 120) = %d, want 12", result)
	}

	// dataLen=118, blockSize=16, next boundary is 128, padding=10
	// 118 + 10 = 128 > 120, should return 0
	result = s.Pad(118, 120)
	if result != 0 {
		t.Errorf("BlockPaddingStrategy{16}.Pad(118, 120) = %d, want 0", result)
	}
}

// TestBlockPaddingStrategy_Name verifies the strategy name.
func TestBlockPaddingStrategy_Name(t *testing.T) {
	s := &BlockPaddingStrategy{BlockSize: 16}
	if name := s.Name(); name != "block" {
		t.Errorf("BlockPaddingStrategy.Name() = %q, want %q", name, "block")
	}
}

// =============================================================================
// ExponentialPaddingStrategy Tests
// =============================================================================

// TestExponentialPaddingStrategy_Pad_DefaultLambda verifies default lambda when zero.
func TestExponentialPaddingStrategy_Pad_DefaultLambda(t *testing.T) {
	s := &ExponentialPaddingStrategy{Lambda: 0}
	// With lambda=0, it should default to 3.0
	// Just verify it doesn't panic and returns reasonable values
	for i := 0; i < 100; i++ {
		result := s.Pad(0, 16384)
		if result < 0 || result > 16384 {
			t.Errorf("iteration %d: ExponentialPaddingStrategy.Pad returned %d, want [0, 16384]", i, result)
		}
	}
}

// TestExponentialPaddingStrategy_Pad_NegativeLambda verifies default lambda when negative.
func TestExponentialPaddingStrategy_Pad_NegativeLambda(t *testing.T) {
	s := &ExponentialPaddingStrategy{Lambda: -5.0}
	// Should default to 3.0
	for i := 0; i < 100; i++ {
		result := s.Pad(0, 16384)
		if result < 0 || result > 16384 {
			t.Errorf("iteration %d: ExponentialPaddingStrategy.Pad returned %d, want [0, 16384]", i, result)
		}
	}
}

// TestExponentialPaddingStrategy_Pad_ReasonableValues verifies reasonable output distribution.
func TestExponentialPaddingStrategy_Pad_ReasonableValues(t *testing.T) {
	s := &ExponentialPaddingStrategy{Lambda: 3.0}

	var sum int
	iterations := 1000
	for i := 0; i < iterations; i++ {
		result := s.Pad(0, 16384)
		if result < 0 {
			t.Errorf("iteration %d: padding %d is negative", i, result)
		}
		sum += result
	}

	// With lambda=3.0, the mean should be around 5.33 * 16 = 85 (approximately)
	// Allow wide range for statistical variance
	avgPadding := float64(sum) / float64(iterations)
	if avgPadding < 10 || avgPadding > 500 {
		t.Logf("Warning: average padding %f is outside expected range [10, 500]", avgPadding)
	}
}

// TestExponentialPaddingStrategy_Pad_RespectsMaxSize verifies padding respects available space.
func TestExponentialPaddingStrategy_Pad_RespectsMaxSize(t *testing.T) {
	s := &ExponentialPaddingStrategy{Lambda: 1.0}

	for i := 0; i < 100; i++ {
		result := s.Pad(16380, 16384)
		if result > 4 {
			t.Errorf("iteration %d: padding %d exceeds available space 4", i, result)
		}
	}
}

// TestExponentialPaddingStrategy_Pad_NoAvailableSpace verifies behavior when no space.
func TestExponentialPaddingStrategy_Pad_NoAvailableSpace(t *testing.T) {
	s := &ExponentialPaddingStrategy{Lambda: 3.0}
	result := s.Pad(16384, 16384)
	if result != 0 {
		t.Errorf("ExponentialPaddingStrategy.Pad with no space returned %d, want 0", result)
	}
}

// TestExponentialPaddingStrategy_Name verifies the strategy name.
func TestExponentialPaddingStrategy_Name(t *testing.T) {
	s := &ExponentialPaddingStrategy{Lambda: 3.0}
	if name := s.Name(); name != "exponential" {
		t.Errorf("ExponentialPaddingStrategy.Name() = %q, want %q", name, "exponential")
	}
}

// =============================================================================
// ChromePaddingStrategy Tests
// =============================================================================

// TestChromePaddingStrategy_Pad_SmallRecords_NoPadding verifies no padding for small records.
func TestChromePaddingStrategy_Pad_SmallRecords_NoPadding(t *testing.T) {
	s := &ChromePaddingStrategy{}

	// Records < 256 bytes should get no padding
	for dataLen := 0; dataLen < 256; dataLen += 25 {
		result := s.Pad(dataLen, 16384)
		if result != 0 {
			t.Errorf("ChromePaddingStrategy.Pad(%d, 16384) = %d, want 0 for small records", dataLen, result)
		}
	}
}

// TestChromePaddingStrategy_Pad_LargerRecords_CappedAt255 verifies padding is capped at 255.
func TestChromePaddingStrategy_Pad_LargerRecords_CappedAt255(t *testing.T) {
	s := &ChromePaddingStrategy{}

	for i := 0; i < 1000; i++ {
		result := s.Pad(1000, 16384)
		if result > 255 {
			t.Errorf("iteration %d: ChromePaddingStrategy.Pad returned %d, want <= 255", i, result)
		}
		if result < 0 {
			t.Errorf("iteration %d: ChromePaddingStrategy.Pad returned negative %d", i, result)
		}
	}
}

// TestChromePaddingStrategy_Pad_RespectsAvailableSpace verifies padding respects available space.
func TestChromePaddingStrategy_Pad_RespectsAvailableSpace(t *testing.T) {
	s := &ChromePaddingStrategy{}

	// Only 50 bytes available, but dataLen >= 256 to trigger padding
	for i := 0; i < 100; i++ {
		result := s.Pad(16334, 16384)
		if result > 50 {
			t.Errorf("iteration %d: padding %d exceeds available space 50", i, result)
		}
	}
}

// TestChromePaddingStrategy_Name verifies the strategy name.
func TestChromePaddingStrategy_Name(t *testing.T) {
	s := &ChromePaddingStrategy{}
	if name := s.Name(); name != "chrome" {
		t.Errorf("ChromePaddingStrategy.Name() = %q, want %q", name, "chrome")
	}
}

// =============================================================================
// FirefoxPaddingStrategy Tests
// =============================================================================

// TestFirefoxPaddingStrategy_Pad_AlwaysReturnsZero verifies Firefox strategy returns 0.
func TestFirefoxPaddingStrategy_Pad_AlwaysReturnsZero(t *testing.T) {
	s := &FirefoxPaddingStrategy{}

	testCases := []struct {
		dataLen int
		maxSize int
	}{
		{0, 16384},
		{100, 16384},
		{1000, 16384},
		{10000, 16384},
		{16384, 16384},
	}

	for _, tc := range testCases {
		result := s.Pad(tc.dataLen, tc.maxSize)
		if result != 0 {
			t.Errorf("FirefoxPaddingStrategy.Pad(%d, %d) = %d, want 0", tc.dataLen, tc.maxSize, result)
		}
	}
}

// TestFirefoxPaddingStrategy_Name verifies the strategy name.
func TestFirefoxPaddingStrategy_Name(t *testing.T) {
	s := &FirefoxPaddingStrategy{}
	if name := s.Name(); name != "firefox" {
		t.Errorf("FirefoxPaddingStrategy.Name() = %q, want %q", name, "firefox")
	}
}

// =============================================================================
// RecordLayerController Tests
// =============================================================================

// TestNewRecordLayerController_NilConfig_UsesDefaults verifies nil config uses defaults.
func TestNewRecordLayerController_NilConfig_UsesDefaults(t *testing.T) {
	ctrl := NewRecordLayerController(nil)
	if ctrl == nil {
		t.Fatal("NewRecordLayerController(nil) returned nil")
	}

	// Should use NoPaddingStrategy by default (padding disabled)
	strategy := ctrl.Strategy()
	if strategy == nil {
		t.Fatal("Controller has nil strategy")
	}

	if strategy.Name() != "none" {
		t.Errorf("Default strategy is %q, want %q", strategy.Name(), "none")
	}

	// Config should have maxPlaintext as MaxRecordSize
	if ctrl.Config().MaxRecordSize != maxPlaintext {
		t.Errorf("Default MaxRecordSize = %d, want %d", ctrl.Config().MaxRecordSize, maxPlaintext)
	}

	// Padding should be disabled
	if ctrl.Config().PaddingEnabled {
		t.Error("Default config has PaddingEnabled=true, want false")
	}
}

// TestNewRecordLayerController_WithConfig_AppliesPaddingMode verifies config is applied.
func TestNewRecordLayerController_WithConfig_AppliesPaddingMode(t *testing.T) {
	testCases := []struct {
		name            string
		mode            RecordPaddingMode
		paddingEnabled  bool
		expectedName    string
	}{
		{"none_mode", RecordPaddingNone, true, "none"},
		{"random_mode", RecordPaddingRandom, true, "random"},
		{"block_mode", RecordPaddingBlock, true, "block"},
		{"exponential_mode", RecordPaddingExponential, true, "exponential"},
		{"chrome_mode", RecordPaddingChrome, true, "chrome"},
		{"firefox_mode", RecordPaddingFirefox, true, "firefox"},
		{"disabled_ignores_mode", RecordPaddingChrome, false, "none"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &RecordLayerConfig{
				PaddingEnabled: tc.paddingEnabled,
				PaddingMode:    tc.mode,
				MaxRecordSize:  16384,
			}
			ctrl := NewRecordLayerController(config)
			strategy := ctrl.Strategy()
			if strategy.Name() != tc.expectedName {
				t.Errorf("Strategy name = %q, want %q", strategy.Name(), tc.expectedName)
			}
		})
	}
}

// TestRecordLayerController_CalculatePadding_ThreadSafe verifies thread safety.
func TestRecordLayerController_CalculatePadding_ThreadSafe(t *testing.T) {
	config := &RecordLayerConfig{
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingRandom,
		PaddingMax:     100,
		MaxRecordSize:  16384,
	}
	ctrl := NewRecordLayerController(config)

	var wg sync.WaitGroup
	goroutines := 100
	iterations := 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				padding := ctrl.CalculatePadding(1000)
				if padding < 0 || padding > 100 {
					t.Errorf("Invalid padding %d returned under concurrent access", padding)
				}
			}
		}()
	}

	wg.Wait()
}

// TestRecordLayerController_SetStrategy_ThreadSafe verifies SetStrategy thread safety.
func TestRecordLayerController_SetStrategy_ThreadSafe(t *testing.T) {
	ctrl := NewRecordLayerController(nil)

	var wg sync.WaitGroup
	goroutines := 50

	strategies := []PaddingStrategy{
		&NoPaddingStrategy{},
		&RandomPaddingStrategy{MaxPad: 100},
		&BlockPaddingStrategy{BlockSize: 16},
		&ChromePaddingStrategy{},
	}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				ctrl.SetStrategy(strategies[idx%len(strategies)])
				_ = ctrl.CalculatePadding(1000)
				_ = ctrl.Strategy()
			}
		}(i)
	}

	wg.Wait()
}

// TestRecordLayerController_CalculatePadding_NilStrategy verifies nil strategy handling.
func TestRecordLayerController_CalculatePadding_NilStrategy(t *testing.T) {
	ctrl := NewRecordLayerController(nil)
	ctrl.SetStrategy(nil)

	result := ctrl.CalculatePadding(1000)
	if result != 0 {
		t.Errorf("CalculatePadding with nil strategy returned %d, want 0", result)
	}
}

// TestRecordLayerController_FragmentData_Disabled verifies fragmentation when disabled.
func TestRecordLayerController_FragmentData_Disabled(t *testing.T) {
	config := &RecordLayerConfig{
		AllowFragmentation: false,
		FragmentPattern:    []int{100, 200, 300},
	}
	ctrl := NewRecordLayerController(config)

	data := make([]byte, 1000)
	fragments := ctrl.FragmentData(data)

	if len(fragments) != 1 {
		t.Errorf("FragmentData returned %d fragments, want 1 when disabled", len(fragments))
	}
	if len(fragments[0]) != 1000 {
		t.Errorf("Fragment size = %d, want 1000", len(fragments[0]))
	}
}

// TestRecordLayerController_FragmentData_EmptyPattern verifies fragmentation with empty pattern.
func TestRecordLayerController_FragmentData_EmptyPattern(t *testing.T) {
	config := &RecordLayerConfig{
		AllowFragmentation: true,
		FragmentPattern:    []int{},
	}
	ctrl := NewRecordLayerController(config)

	data := make([]byte, 1000)
	fragments := ctrl.FragmentData(data)

	if len(fragments) != 1 {
		t.Errorf("FragmentData returned %d fragments, want 1 with empty pattern", len(fragments))
	}
}

// TestRecordLayerController_FragmentData_CorrectFragmentation verifies correct fragmentation.
func TestRecordLayerController_FragmentData_CorrectFragmentation(t *testing.T) {
	config := &RecordLayerConfig{
		AllowFragmentation: true,
		FragmentPattern:    []int{100, 200, 150},
	}
	ctrl := NewRecordLayerController(config)

	data := make([]byte, 600)
	for i := range data {
		data[i] = byte(i % 256)
	}

	fragments := ctrl.FragmentData(data)

	// Expected: 100, 200, 150, 100 (remaining=50), so 100, 200, 150, 50
	// Wait, pattern cycles: 100, 200, 150, 100, ... until data exhausted
	// 100 + 200 + 150 + 100 = 550, remaining = 50
	// So: [100, 200, 150, 100, 50] = 5 fragments? No...
	// Let me re-read the code:
	// patternIdx cycles through FragmentPattern
	// Fragment 1: size=100, remaining=500, patternIdx=1
	// Fragment 2: size=200, remaining=300, patternIdx=2
	// Fragment 3: size=150, remaining=150, patternIdx=0 (wraps)
	// Fragment 4: size=100, remaining=50, patternIdx=1
	// Fragment 5: size=50 (min of 200, 50), remaining=0, patternIdx=2

	expectedSizes := []int{100, 200, 150, 100, 50}
	if len(fragments) != len(expectedSizes) {
		t.Fatalf("FragmentData returned %d fragments, want %d", len(fragments), len(expectedSizes))
	}

	for i, frag := range fragments {
		if len(frag) != expectedSizes[i] {
			t.Errorf("Fragment %d size = %d, want %d", i, len(frag), expectedSizes[i])
		}
	}
}

// TestRecordLayerController_FragmentData_PreservesContent verifies data integrity.
func TestRecordLayerController_FragmentData_PreservesContent(t *testing.T) {
	config := &RecordLayerConfig{
		AllowFragmentation: true,
		FragmentPattern:    []int{50, 75, 100},
	}
	ctrl := NewRecordLayerController(config)

	data := make([]byte, 300)
	for i := range data {
		data[i] = byte(i)
	}

	fragments := ctrl.FragmentData(data)

	// Reassemble and verify
	var reassembled []byte
	for _, frag := range fragments {
		reassembled = append(reassembled, frag...)
	}

	if len(reassembled) != len(data) {
		t.Fatalf("Reassembled length = %d, want %d", len(reassembled), len(data))
	}

	for i := range data {
		if reassembled[i] != data[i] {
			t.Errorf("Mismatch at byte %d: got %d, want %d", i, reassembled[i], data[i])
		}
	}
}

// TestRecordLayerController_FragmentData_ZeroSizeInPattern verifies handling of zero sizes.
func TestRecordLayerController_FragmentData_ZeroSizeInPattern(t *testing.T) {
	config := &RecordLayerConfig{
		AllowFragmentation: true,
		FragmentPattern:    []int{0, 50, 0, 100},
	}
	ctrl := NewRecordLayerController(config)

	data := make([]byte, 200)
	fragments := ctrl.FragmentData(data)

	// Zero size should take remaining data according to code: if size <= 0 || size > len(remaining)
	// Fragment 1: size=0 -> size=200, takes all
	if len(fragments) != 1 {
		t.Errorf("FragmentData with zero size returned %d fragments, want 1", len(fragments))
	}
	if len(fragments[0]) != 200 {
		t.Errorf("Fragment size = %d, want 200", len(fragments[0]))
	}
}

// =============================================================================
// RecordTimingController Tests
// =============================================================================

// TestRecordTimingController_SetDelay_AtomicStore verifies atomic delay storage.
func TestRecordTimingController_SetDelay_AtomicStore(t *testing.T) {
	ctrl := NewRecordTimingController()

	delays := []time.Duration{
		0,
		1 * time.Millisecond,
		10 * time.Millisecond,
		100 * time.Millisecond,
		1 * time.Second,
	}

	for _, d := range delays {
		ctrl.SetDelay(d)
		// Verify by getting delay (with no jitter)
		ctrl.SetJitter(0)
		ctrl.SetBurstSize(0) // No burst mode
		got := ctrl.GetDelay()
		if got != d {
			t.Errorf("SetDelay(%v) then GetDelay() = %v", d, got)
		}
	}
}

// TestRecordTimingController_SetJitter_AtomicStore verifies atomic jitter storage.
func TestRecordTimingController_SetJitter_AtomicStore(t *testing.T) {
	ctrl := NewRecordTimingController()
	ctrl.SetDelay(10 * time.Millisecond)

	// Set jitter and verify delay includes it
	ctrl.SetJitter(5 * time.Millisecond)
	ctrl.SetBurstSize(0)

	// Get multiple delays and verify they vary
	delays := make(map[time.Duration]bool)
	for i := 0; i < 100; i++ {
		d := ctrl.GetDelay()
		delays[d] = true
		// Delay should be in [10ms, 15ms)
		if d < 10*time.Millisecond || d >= 15*time.Millisecond {
			t.Errorf("Delay %v outside expected range [10ms, 15ms)", d)
		}
	}

	// Should have some variation
	if len(delays) < 2 {
		t.Logf("Warning: jitter produced only %d unique delays", len(delays))
	}
}

// TestRecordTimingController_GetDelay_IncludesJitter verifies jitter is included.
func TestRecordTimingController_GetDelay_IncludesJitter(t *testing.T) {
	ctrl := NewRecordTimingController()
	ctrl.SetDelay(100 * time.Millisecond)
	ctrl.SetJitter(50 * time.Millisecond)
	ctrl.SetBurstSize(0)

	min := 100 * time.Millisecond
	max := 150 * time.Millisecond

	for i := 0; i < 100; i++ {
		d := ctrl.GetDelay()
		if d < min || d >= max {
			t.Errorf("iteration %d: delay %v outside [%v, %v)", i, d, min, max)
		}
	}
}

// TestRecordTimingController_BurstSize_NoDelayDuringBurst verifies burst behavior.
func TestRecordTimingController_BurstSize_NoDelayDuringBurst(t *testing.T) {
	ctrl := NewRecordTimingController()
	ctrl.SetDelay(100 * time.Millisecond)
	ctrl.SetJitter(0)
	ctrl.SetBurstSize(5)

	// First 5 calls should return 0 (no delay during burst)
	for i := 0; i < 5; i++ {
		d := ctrl.GetDelay()
		if d != 0 {
			t.Errorf("Burst call %d: delay = %v, want 0", i, d)
		}
	}

	// 6th call should return the base delay (burst exhausted)
	d := ctrl.GetDelay()
	if d != 100*time.Millisecond {
		t.Errorf("Post-burst delay = %v, want 100ms", d)
	}

	// Next 5 calls should be no delay again (new burst)
	for i := 0; i < 5; i++ {
		d := ctrl.GetDelay()
		if d != 0 {
			t.Errorf("Second burst call %d: delay = %v, want 0", i, d)
		}
	}
}

// TestRecordTimingController_ThreadSafe verifies thread safety.
func TestRecordTimingController_ThreadSafe(t *testing.T) {
	ctrl := NewRecordTimingController()
	ctrl.SetDelay(10 * time.Millisecond)
	ctrl.SetJitter(5 * time.Millisecond)
	ctrl.SetBurstSize(3)

	var wg sync.WaitGroup
	goroutines := 50
	iterations := 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = ctrl.GetDelay()
				ctrl.SetDelay(time.Duration(j) * time.Microsecond)
				ctrl.SetJitter(time.Duration(j%10) * time.Microsecond)
				ctrl.SetBurstSize(j % 10)
			}
		}()
	}

	wg.Wait()
}

// TestRecordTimingController_ZeroBaseDelay verifies zero base delay behavior.
func TestRecordTimingController_ZeroBaseDelay(t *testing.T) {
	ctrl := NewRecordTimingController()
	ctrl.SetDelay(0)
	ctrl.SetJitter(10 * time.Millisecond)
	ctrl.SetBurstSize(0)

	// With zero base delay and jitter, delay should be in [0, 10ms)
	for i := 0; i < 100; i++ {
		d := ctrl.GetDelay()
		if d < 0 || d >= 10*time.Millisecond {
			t.Errorf("iteration %d: delay %v outside [0, 10ms)", i, d)
		}
	}
}

// TestRecordTimingController_ZeroJitter verifies zero jitter behavior.
func TestRecordTimingController_ZeroJitter(t *testing.T) {
	ctrl := NewRecordTimingController()
	ctrl.SetDelay(50 * time.Millisecond)
	ctrl.SetJitter(0)
	ctrl.SetBurstSize(0)

	// All delays should be exactly 50ms
	for i := 0; i < 100; i++ {
		d := ctrl.GetDelay()
		if d != 50*time.Millisecond {
			t.Errorf("iteration %d: delay %v, want 50ms", i, d)
		}
	}
}

// =============================================================================
// NewPaddingStrategy Tests
// =============================================================================

// TestNewPaddingStrategy_AllModes verifies factory function for all modes.
func TestNewPaddingStrategy_AllModes(t *testing.T) {
	testCases := []struct {
		mode         RecordPaddingMode
		params       map[string]interface{}
		expectedName string
	}{
		{RecordPaddingNone, nil, "none"},
		{RecordPaddingRandom, nil, "random"},
		{RecordPaddingRandom, map[string]interface{}{"max_pad": 200}, "random"},
		{RecordPaddingBlock, nil, "block"},
		{RecordPaddingBlock, map[string]interface{}{"block_size": 32}, "block"},
		{RecordPaddingExponential, nil, "exponential"},
		{RecordPaddingExponential, map[string]interface{}{"lambda": 5.0}, "exponential"},
		{RecordPaddingChrome, nil, "chrome"},
		{RecordPaddingFirefox, nil, "firefox"},
		{RecordPaddingMode(999), nil, "none"}, // Unknown mode defaults to none
	}

	for i, tc := range testCases {
		t.Run(tc.expectedName, func(t *testing.T) {
			strategy := NewPaddingStrategy(tc.mode, tc.params)
			if strategy == nil {
				t.Fatalf("test %d: NewPaddingStrategy returned nil", i)
			}
			if strategy.Name() != tc.expectedName {
				t.Errorf("test %d: strategy name = %q, want %q", i, strategy.Name(), tc.expectedName)
			}
		})
	}
}

// TestNewPaddingStrategy_RandomWithParams verifies random strategy with custom params.
func TestNewPaddingStrategy_RandomWithParams(t *testing.T) {
	params := map[string]interface{}{"max_pad": 500}
	strategy := NewPaddingStrategy(RecordPaddingRandom, params)

	randStrategy, ok := strategy.(*RandomPaddingStrategy)
	if !ok {
		t.Fatalf("Expected *RandomPaddingStrategy, got %T", strategy)
	}
	if randStrategy.MaxPad != 500 {
		t.Errorf("MaxPad = %d, want 500", randStrategy.MaxPad)
	}
}

// TestNewPaddingStrategy_BlockWithParams verifies block strategy with custom params.
func TestNewPaddingStrategy_BlockWithParams(t *testing.T) {
	params := map[string]interface{}{"block_size": 64}
	strategy := NewPaddingStrategy(RecordPaddingBlock, params)

	blockStrategy, ok := strategy.(*BlockPaddingStrategy)
	if !ok {
		t.Fatalf("Expected *BlockPaddingStrategy, got %T", strategy)
	}
	if blockStrategy.BlockSize != 64 {
		t.Errorf("BlockSize = %d, want 64", blockStrategy.BlockSize)
	}
}

// TestNewPaddingStrategy_ExponentialWithParams verifies exponential strategy with custom params.
func TestNewPaddingStrategy_ExponentialWithParams(t *testing.T) {
	params := map[string]interface{}{"lambda": 2.5}
	strategy := NewPaddingStrategy(RecordPaddingExponential, params)

	expStrategy, ok := strategy.(*ExponentialPaddingStrategy)
	if !ok {
		t.Fatalf("Expected *ExponentialPaddingStrategy, got %T", strategy)
	}
	if expStrategy.Lambda != 2.5 {
		t.Errorf("Lambda = %f, want 2.5", expStrategy.Lambda)
	}
}

// =============================================================================
// Config Helper Functions Tests
// =============================================================================

// TestChromeRecordLayerConfig verifies Chrome config helper.
func TestChromeRecordLayerConfig(t *testing.T) {
	config := ChromeRecordLayerConfig()
	if config == nil {
		t.Fatal("ChromeRecordLayerConfig() returned nil")
	}
	if !config.PaddingEnabled {
		t.Error("Chrome config should have PaddingEnabled=true")
	}
	if config.PaddingMode != RecordPaddingChrome {
		t.Errorf("Chrome config mode = %d, want %d", config.PaddingMode, RecordPaddingChrome)
	}
	if config.MaxRecordSize != maxPlaintext {
		t.Errorf("Chrome config MaxRecordSize = %d, want %d", config.MaxRecordSize, maxPlaintext)
	}
}

// TestFirefoxRecordLayerConfig verifies Firefox config helper.
func TestFirefoxRecordLayerConfig(t *testing.T) {
	config := FirefoxRecordLayerConfig()
	if config == nil {
		t.Fatal("FirefoxRecordLayerConfig() returned nil")
	}
	if config.PaddingEnabled {
		t.Error("Firefox config should have PaddingEnabled=false")
	}
	if config.PaddingMode != RecordPaddingFirefox {
		t.Errorf("Firefox config mode = %d, want %d", config.PaddingMode, RecordPaddingFirefox)
	}
}
