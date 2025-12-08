// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"testing"
)

func TestRecordPaddingConfig_GenerateUniform(t *testing.T) {
	config := &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   10,
		MaxPadding:   50,
		Distribution: "uniform",
	}

	iterations := shortModeIterations(1000, 100)
	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 10 || padding > 50 {
			t.Errorf("Uniform padding out of range: got %d, want [10, 50]", padding)
		}
	}
}

func TestRecordPaddingConfig_GenerateChrome(t *testing.T) {
	config := &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   0,
		MaxPadding:   255,
		Distribution: "chrome",
		Lambda:       3.0,
	}

	// Collect distribution statistics
	var total int64
	iterations := shortModeIterations(10000, 1000)
	belowMean := 0
	aboveHigh := 0

	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 0 || padding > 255 {
			t.Errorf("Chrome padding out of range: got %d, want [0, 255]", padding)
		}
		total += int64(padding)
		if padding < 85 {
			belowMean++
		}
		if padding > 200 {
			aboveHigh++
		}
	}

	// Chrome-like distribution should have mean around 72 for lambda=3.0
	// Allow wider tolerance for statistical variation
	mean := float64(total) / float64(int64(iterations))
	if mean < 40 || mean > 120 {
		t.Errorf("Chrome padding mean unexpected: got %.2f, expected around 72", mean)
	}

	// Majority should be below mean (exponential distribution skews low)
	belowMeanPct := float64(belowMean) / float64(int64(iterations)) * 100
	if belowMeanPct < 50 {
		t.Errorf("Chrome distribution not skewed low enough: %.1f%% below 85", belowMeanPct)
	}
}

func TestRecordPaddingConfig_GenerateExponential(t *testing.T) {
	config := &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   0,
		MaxPadding:   255,
		Distribution: "exponential",
		Lambda:       1.0,
	}

	iterations := shortModeIterations(1000, 100)
	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 0 || padding > 255 {
			t.Errorf("Exponential padding out of range: got %d, want [0, 255]", padding)
		}
	}
}

func TestRecordPaddingConfig_Disabled(t *testing.T) {
	config := &RecordPaddingConfig{
		Enabled:      false,
		MinPadding:   10,
		MaxPadding:   50,
		Distribution: "uniform",
	}

	iterations := shortModeIterations(100, 20)
	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding != 0 {
			t.Errorf("Disabled padding should return 0, got %d", padding)
		}
	}
}

func TestRecordPaddingConfig_NilConfig(t *testing.T) {
	var config *RecordPaddingConfig
	padding := config.GeneratePadding()
	if padding != 0 {
		t.Errorf("Nil config should return 0 padding, got %d", padding)
	}
}

func TestRecordPaddingConfig_EqualMinMax(t *testing.T) {
	config := &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   42,
		MaxPadding:   42,
		Distribution: "uniform",
	}

	iterations := shortModeIterations(100, 20)
	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding != 42 {
			t.Errorf("Equal min/max should always return that value, got %d", padding)
		}
	}
}

func TestDefaultRecordPaddingConfig(t *testing.T) {
	config := DefaultRecordPaddingConfig()

	if !config.Enabled {
		t.Error("Default config should be enabled")
	}
	if config.MinPadding != 0 {
		t.Errorf("Default MinPadding should be 0, got %d", config.MinPadding)
	}
	if config.MaxPadding != 255 {
		t.Errorf("Default MaxPadding should be 255, got %d", config.MaxPadding)
	}
	if config.Distribution != "chrome" {
		t.Errorf("Default Distribution should be 'chrome', got %s", config.Distribution)
	}
	if config.Lambda != 3.0 {
		t.Errorf("Default Lambda should be 3.0, got %f", config.Lambda)
	}

	// Verify it generates valid padding
	iterations := shortModeIterations(100, 20)
	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 0 || padding > 255 {
			t.Errorf("Default config padding out of range: got %d", padding)
		}
	}
}

func TestClampPaddingToRecordLimit(t *testing.T) {
	tests := []struct {
		name             string
		contentLen       int
		requestedPadding int
		expected         int
	}{
		{
			name:             "normal padding",
			contentLen:       100,
			requestedPadding: 50,
			expected:         50,
		},
		{
			name:             "padding clamped by record limit",
			contentLen:       maxPlaintext - 10,
			requestedPadding: 100,
			expected:         9, // maxPlaintext - contentLen - 1
		},
		{
			name:             "padding clamped to 255",
			contentLen:       100,
			requestedPadding: 300,
			expected:         255,
		},
		{
			name:             "full record no padding",
			contentLen:       maxPlaintext,
			requestedPadding: 10,
			expected:         0,
		},
		{
			name:             "over full record",
			contentLen:       maxPlaintext + 10,
			requestedPadding: 10,
			expected:         0,
		},
		{
			name:             "zero padding request",
			contentLen:       100,
			requestedPadding: 0,
			expected:         0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClampPaddingToRecordLimit(tc.contentLen, tc.requestedPadding)
			if result != tc.expected {
				t.Errorf("ClampPaddingToRecordLimit(%d, %d) = %d, want %d",
					tc.contentLen, tc.requestedPadding, result, tc.expected)
			}
		})
	}
}

func TestRecordPaddingConfig_InvalidValues(t *testing.T) {
	iterations := shortModeIterations(100, 20)

	// Test with negative values
	config := &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   -10,
		MaxPadding:   50,
		Distribution: "uniform",
	}

	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 0 || padding > 50 {
			t.Errorf("Negative min should be clamped to 0: got %d", padding)
		}
	}

	// Test with max exceeding RFC limit
	config = &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   0,
		MaxPadding:   500,
		Distribution: "uniform",
	}

	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 0 || padding > 255 {
			t.Errorf("Max should be clamped to 255: got %d", padding)
		}
	}

	// Test with inverted min/max
	config = &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   100,
		MaxPadding:   50,
		Distribution: "uniform",
	}

	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding != 100 {
			t.Errorf("Inverted min/max should clamp max to min: got %d", padding)
		}
	}
}

func TestRecordPaddingConfig_ZeroLambda(t *testing.T) {
	iterations := shortModeIterations(100, 20)

	// Test that zero lambda defaults properly
	config := &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   0,
		MaxPadding:   255,
		Distribution: "chrome",
		Lambda:       0, // Should default to 3.0
	}

	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 0 || padding > 255 {
			t.Errorf("Zero lambda should use default, got padding: %d", padding)
		}
	}

	// Same for exponential
	config.Distribution = "exponential"
	for i := 0; i < iterations; i++ {
		padding := config.GeneratePadding()
		if padding < 0 || padding > 255 {
			t.Errorf("Zero lambda exponential should use default, got padding: %d", padding)
		}
	}
}

// BenchmarkRecordPaddingGeneration benchmarks padding generation performance
func BenchmarkRecordPaddingGeneration(b *testing.B) {
	configs := map[string]*RecordPaddingConfig{
		"uniform": {
			Enabled:      true,
			MinPadding:   0,
			MaxPadding:   255,
			Distribution: "uniform",
		},
		"chrome": {
			Enabled:      true,
			MinPadding:   0,
			MaxPadding:   255,
			Distribution: "chrome",
			Lambda:       3.0,
		},
		"exponential": {
			Enabled:      true,
			MinPadding:   0,
			MaxPadding:   255,
			Distribution: "exponential",
			Lambda:       1.0,
		},
	}

	for name, config := range configs {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = config.GeneratePadding()
			}
		})
	}
}
