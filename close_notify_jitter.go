// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// CloseNotifyConfig controls timing jitter for close_notify alerts to resist
// TLS fingerprinting based on connection shutdown timing patterns.
//
// Real Browser Behavior:
//   - Chrome: Sometimes closes TCP without close_notify on navigation/abort
//   - Firefox: Typically sends close_notify with variable delay (0-50ms)
//   - Safari: Mixed behavior depending on connection state
//
// Without jitter, all connections close with identical timing, which is a
// detectable fingerprint. This configuration allows mimicking real browser
// variability in connection shutdown behavior.
type CloseNotifyConfig struct {
	// Enabled controls whether timing jitter is applied to close_notify.
	// When false, close_notify is sent immediately (default TLS behavior).
	Enabled bool

	// MinDelayMs is the minimum delay in milliseconds before sending close_notify.
	// Default: 0 (no minimum delay)
	MinDelayMs int

	// MaxDelayMs is the maximum delay in milliseconds before sending close_notify.
	// The actual delay is uniformly distributed between MinDelayMs and MaxDelayMs.
	// Default: 50 (maximum 50ms delay, similar to Firefox behavior)
	MaxDelayMs int

	// SkipProbability is the probability (0.0 to 1.0) of skipping close_notify entirely.
	// When skipped, the TCP connection is closed without sending close_notify.
	// This mimics browser behavior during abrupt navigation or connection abort.
	//
	// Real browser observations:
	//   - Chrome: ~10-15% skip rate on navigation/abort
	//   - Firefox: ~5% skip rate
	//   - Safari: ~8% skip rate
	//
	// Default: 0.1 (10% chance to skip, mimics Chrome behavior)
	// Set to 0.0 to always send close_notify.
	//
	// WARNING: Skipping close_notify may cause the peer to treat the connection
	// as abnormally terminated. This is acceptable for fingerprint resistance
	// but may affect error handling on the server side.
	SkipProbability float64
}

// DefaultCloseNotifyConfig returns a configuration that mimics typical browser
// close_notify behavior for fingerprint resistance.
//
// Settings:
//   - Enabled: true
//   - MinDelayMs: 0
//   - MaxDelayMs: 50 (similar to Firefox)
//   - SkipProbability: 0.1 (10% skip rate, similar to Chrome)
func DefaultCloseNotifyConfig() *CloseNotifyConfig {
	return &CloseNotifyConfig{
		Enabled:         true,
		MinDelayMs:      0,
		MaxDelayMs:      50,
		SkipProbability: 0.1,
	}
}

// ChromeCloseNotifyConfig returns a configuration that mimics Chrome's
// close_notify behavior.
//
// Chrome tends to skip close_notify more often during abrupt navigation,
// and has shorter delays when it does send one.
func ChromeCloseNotifyConfig() *CloseNotifyConfig {
	return &CloseNotifyConfig{
		Enabled:         true,
		MinDelayMs:      0,
		MaxDelayMs:      30,
		SkipProbability: 0.12,
	}
}

// FirefoxCloseNotifyConfig returns a configuration that mimics Firefox's
// close_notify behavior.
//
// Firefox is more consistent about sending close_notify with moderate delays.
func FirefoxCloseNotifyConfig() *CloseNotifyConfig {
	return &CloseNotifyConfig{
		Enabled:         true,
		MinDelayMs:      0,
		MaxDelayMs:      50,
		SkipProbability: 0.05,
	}
}

// SafariCloseNotifyConfig returns a configuration that mimics Safari's
// close_notify behavior.
//
// Safari has intermediate behavior between Chrome and Firefox.
func SafariCloseNotifyConfig() *CloseNotifyConfig {
	return &CloseNotifyConfig{
		Enabled:         true,
		MinDelayMs:      0,
		MaxDelayMs:      40,
		SkipProbability: 0.08,
	}
}

// DisabledCloseNotifyConfig returns a configuration that disables all
// close_notify jitter. Close_notify is sent immediately without delay or skip.
//
// Use this when:
//   - You need deterministic connection shutdown behavior
//   - You're debugging TLS issues
//   - The server requires reliable close_notify
func DisabledCloseNotifyConfig() *CloseNotifyConfig {
	return &CloseNotifyConfig{
		Enabled: false,
	}
}

// ShouldSkip returns true if close_notify should be skipped based on SkipProbability.
// Uses cryptographically secure randomness for the decision.
// Thread-safe.
func (c *CloseNotifyConfig) ShouldSkip() bool {
	if c == nil || !c.Enabled || c.SkipProbability <= 0 {
		return false
	}
	if c.SkipProbability >= 1.0 {
		return true
	}

	// Read cryptographically secure random bytes
	var randBytes [8]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		// On error, don't skip (safer default)
		return false
	}

	// Convert to float64 in range [0, 1)
	randVal := float64(binary.LittleEndian.Uint64(randBytes[:])) / float64(^uint64(0))

	return randVal < c.SkipProbability
}

// GetDelay returns the delay duration to apply before sending close_notify.
// Returns 0 if jitter is disabled or delay range is invalid.
// Uses cryptographically secure randomness for delay calculation.
// Thread-safe.
func (c *CloseNotifyConfig) GetDelay() time.Duration {
	if c == nil || !c.Enabled {
		return 0
	}

	// Validate and normalize configuration
	minMs := c.MinDelayMs
	maxMs := c.MaxDelayMs
	if minMs < 0 {
		minMs = 0
	}
	if maxMs < 0 {
		maxMs = 0
	}
	if maxMs < minMs {
		maxMs = minMs
	}

	// If no range, return minimum delay
	if minMs == maxMs {
		return time.Duration(minMs) * time.Millisecond
	}

	// Generate uniform random delay in [minMs, maxMs]
	rangeSize := uint64(maxMs - minMs + 1)

	// Calculate rejection threshold to eliminate modulo bias
	max := ^uint64(0) - (^uint64(0) % rangeSize)

	var randVal uint64
	for {
		var randBytes [8]byte
		if _, err := rand.Read(randBytes[:]); err != nil {
			// On error, return minimum delay (safe fallback)
			return time.Duration(minMs) * time.Millisecond
		}
		randVal = binary.LittleEndian.Uint64(randBytes[:])

		// Accept only if below rejection threshold
		if randVal < max {
			delayMs := minMs + int(randVal%rangeSize)
			return time.Duration(delayMs) * time.Millisecond
		}
		// Otherwise loop and try again (rejection sampling)
	}
}
