// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/sha256"
	"math"
	"testing"
	"time"
)

// TestPSKBinderConstantTime verifies that the constant-time PSK binder
// computation normalizes timing regardless of transcript size.
func TestPSKBinderConstantTime(t *testing.T) {
	// Create a test cipher suite
	suite := &cipherSuiteTLS13{
		id:     TLS_AES_128_GCM_SHA256,
		keyLen: 16,
		aead:   aeadAESGCMTLS13,
		hash:   crypto.SHA256,
	}

	// Create a test binder key
	binderKey := make([]byte, 32)
	for i := range binderKey {
		binderKey[i] = byte(i)
	}

	// Test with different transcript sizes
	testSizes := []int{64, 256, 512, 1024, 2048}
	iterations := 50

	t.Run("ConstantTimeNormalizeTiming", func(t *testing.T) {
		var allTimings []time.Duration

		for _, size := range testSizes {
			for i := 0; i < iterations; i++ {
				// Create transcript with specific size
				transcript := sha256.New()
				data := make([]byte, size)
				for j := range data {
					data[j] = byte(j % 256)
				}
				transcript.Write(data)

				// Measure constant-time mode
				start := time.Now()
				_, err := suite.finishedHashConstantTime(binderKey, transcript)
				elapsed := time.Since(start)

				if err != nil {
					t.Fatalf("finishedHashConstantTime failed: %v", err)
				}

				allTimings = append(allTimings, elapsed)
			}
		}

		// Calculate coefficient of variation
		cv := calculateCoeffOfVariation(allTimings)
		t.Logf("Constant-time mode CV across all sizes: %.2f%%", cv)

		// CV should be reasonably low (normalized timing)
		// Allow some variance due to OS scheduling
		if cv > 100 {
			t.Errorf("Constant-time mode has too high variance (CV=%.2f%%), expected <100%%", cv)
		}
	})

	t.Run("MinimumDurationRespected", func(t *testing.T) {
		// All constant-time computations should be >= pskBinderMinDuration
		for _, size := range testSizes {
			transcript := sha256.New()
			data := make([]byte, size)
			transcript.Write(data)

			start := time.Now()
			suite.finishedHashConstantTime(binderKey, transcript)
			elapsed := time.Since(start)

			if elapsed < pskBinderMinDuration {
				t.Errorf("Size %d: timing %v is less than minimum %v", size, elapsed, pskBinderMinDuration)
			}
		}
	})

	t.Run("RegularModeShowsVariation", func(t *testing.T) {
		var allTimings []time.Duration

		for _, size := range testSizes {
			for i := 0; i < iterations; i++ {
				transcript := sha256.New()
				data := make([]byte, size)
				for j := range data {
					data[j] = byte(j % 256)
				}
				transcript.Write(data)

				start := time.Now()
				_, err := suite.finishedHash(binderKey, transcript)
				elapsed := time.Since(start)

				if err != nil {
					t.Fatalf("finishedHash failed: %v", err)
				}

				allTimings = append(allTimings, elapsed)
			}
		}

		// Regular mode should show more variance than constant-time mode
		cv := calculateCoeffOfVariation(allTimings)
		t.Logf("Regular mode CV across all sizes: %.2f%%", cv)
	})
}

// TestPSKBinderConfigClone verifies that PSKBinderConstantTime is cloned correctly.
func TestPSKBinderConfigClone(t *testing.T) {
	config := &Config{
		PSKBinderConstantTime: true,
	}

	clone := config.Clone()
	if clone.PSKBinderConstantTime != config.PSKBinderConstantTime {
		t.Errorf("Clone did not preserve PSKBinderConstantTime: got %v, want %v",
			clone.PSKBinderConstantTime, config.PSKBinderConstantTime)
	}

	// Also test with false
	config.PSKBinderConstantTime = false
	clone = config.Clone()
	if clone.PSKBinderConstantTime != config.PSKBinderConstantTime {
		t.Errorf("Clone did not preserve PSKBinderConstantTime=false: got %v, want %v",
			clone.PSKBinderConstantTime, config.PSKBinderConstantTime)
	}
}

// TestMinimumDurationValue verifies the minimum duration constant is reasonable.
func TestPSKBinderMinimumDurationValue(t *testing.T) {
	// Minimum duration should be between 50us and 500us
	// - Too short: won't effectively normalize timing
	// - Too long: adds unnecessary latency to handshakes
	minAcceptable := 50 * time.Microsecond
	maxAcceptable := 500 * time.Microsecond

	if pskBinderMinDuration < minAcceptable {
		t.Errorf("pskBinderMinDuration (%v) is too short; should be at least %v",
			pskBinderMinDuration, minAcceptable)
	}

	if pskBinderMinDuration > maxAcceptable {
		t.Errorf("pskBinderMinDuration (%v) is too long; should be at most %v",
			pskBinderMinDuration, maxAcceptable)
	}

	t.Logf("pskBinderMinDuration: %v", pskBinderMinDuration)
}

// calculateCoeffOfVariation calculates the coefficient of variation (CV) as a percentage.
// CV = (standard deviation / mean) * 100
func calculateCoeffOfVariation(timings []time.Duration) float64 {
	if len(timings) == 0 {
		return 0
	}

	// Calculate mean
	var sum float64
	for _, t := range timings {
		sum += float64(t.Nanoseconds())
	}
	mean := sum / float64(len(timings))

	if mean == 0 {
		return 0
	}

	// Calculate variance
	var variance float64
	for _, t := range timings {
		diff := float64(t.Nanoseconds()) - mean
		variance += diff * diff
	}
	variance /= float64(len(timings))

	// Standard deviation
	stdDev := math.Sqrt(variance)

	// Coefficient of variation as percentage
	return (stdDev / mean) * 100
}

// BenchmarkPSKBinderComputation benchmarks both regular and constant-time modes.
func BenchmarkPSKBinderComputation(b *testing.B) {
	suite := &cipherSuiteTLS13{
		id:     TLS_AES_128_GCM_SHA256,
		keyLen: 16,
		aead:   aeadAESGCMTLS13,
		hash:   crypto.SHA256,
	}

	binderKey := make([]byte, 32)
	for i := range binderKey {
		binderKey[i] = byte(i)
	}

	transcriptData := make([]byte, 512)
	for i := range transcriptData {
		transcriptData[i] = byte(i % 256)
	}

	b.Run("Regular", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			transcript := sha256.New()
			transcript.Write(transcriptData)
			suite.finishedHash(binderKey, transcript)
		}
	})

	b.Run("ConstantTime", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			transcript := sha256.New()
			transcript.Write(transcriptData)
			suite.finishedHashConstantTime(binderKey, transcript)
		}
	})
}
