// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"time"
)

// HandshakeTimingConfig controls timing jitter during TLS handshakes to resist
// timing-based fingerprinting. Real browsers have variable delays during handshakes
// due to certificate validation, key computation, and UI rendering. Without timing
// jitter, sub-millisecond timing between handshake messages reveals automation.
//
// Timing is applied at four points:
//   - After ServerHello: simulates parsing delay (default: 1-5ms)
//   - Around CCS: simulates dummy ChangeCipherSpec timing (default: 0-2ms pre, 0-1ms post)
//   - After certificate verification: simulates chain validation (default: 5-20ms)
//   - Before Finished: simulates computation delay (default: 1-3ms)
type HandshakeTimingConfig struct {
	// Enabled controls whether handshake timing jitter is applied.
	// When false, all timing delays are skipped.
	Enabled bool

	// ServerHelloDelay is applied after receiving and processing ServerHello.
	// Simulates parsing and extension processing time.
	// Default: 1-5ms with exponential distribution
	ServerHelloDelay TimingRange

	// CCSDelay controls timing around the dummy ChangeCipherSpec message in TLS 1.3.
	// The CCS timing pattern is a fingerprinting vector - Chrome sends it immediately
	// after ClientHello in some cases, Firefox has variable timing.
	// Default: PreDelay 0-2ms, PostDelay 0-1ms
	CCSDelay CCSTimingConfig

	// CertificateDelay is applied after certificate chain verification.
	// Simulates OCSP check, chain building, and signature verification.
	// This is typically the longest delay as cert verification is expensive.
	// Default: 5-20ms with exponential distribution
	CertificateDelay TimingRange

	// FinishedDelay is applied before sending the Finished message.
	// Simulates key derivation and MAC computation.
	// Default: 1-3ms with exponential distribution
	FinishedDelay TimingRange

	// Distribution controls how random delays are generated within the range.
	// Valid values: "exponential" (default), "uniform", "normal"
	// Exponential distribution better matches real browser behavior.
	Distribution string
}

// CCSTimingConfig controls timing jitter around the dummy ChangeCipherSpec message
// in TLS 1.3. Per RFC 8446 Appendix D.4, a dummy CCS is sent for middlebox compatibility.
// The exact timing of this message relative to other handshake messages can reveal
// automation vs real browser behavior.
//
// Real browser behavior varies:
//   - Chrome: typically sends CCS immediately after ClientHello
//   - Firefox: has variable timing depending on state machine
//   - Safari: similar to Chrome with slight variations
type CCSTimingConfig struct {
	// Enabled controls whether CCS timing jitter is applied.
	// When false, CCS is sent immediately without delay.
	Enabled bool

	// PreDelay is applied before sending the CCS message.
	// Simulates the delay before the client decides to send CCS.
	// Default: 0-2ms
	PreDelay TimingRange

	// PostDelay is applied after sending the CCS message.
	// Simulates processing delay after CCS is sent.
	// Default: 0-1ms
	PostDelay TimingRange
}

// TimingRange specifies a range for timing delays with min and max bounds.
type TimingRange struct {
	// Min is the minimum delay in milliseconds. Must be >= 0.
	Min float64

	// Max is the maximum delay in milliseconds. Must be >= Min.
	Max float64
}

// Duration returns a random duration within the timing range using the specified
// distribution. If the range is invalid or zero, returns 0.
func (tr TimingRange) Duration(distribution string) time.Duration {
	if tr.Max <= 0 || tr.Max < tr.Min || tr.Min < 0 {
		return 0
	}

	var delayMs float64
	switch distribution {
	case "uniform":
		delayMs = tr.uniformRandom()
	case "normal":
		delayMs = tr.normalRandom()
	default: // "exponential" or anything else
		delayMs = tr.exponentialRandom()
	}

	return time.Duration(delayMs * float64(time.Millisecond))
}

// exponentialRandom returns a random value in [Min, Max] using truncated
// exponential distribution. This better matches real browser timing patterns
// where most delays are short but occasionally longer.
func (tr TimingRange) exponentialRandom() float64 {
	// Use lambda = 3.0 to match Chrome-like behavior
	lambda := 3.0
	rangeSize := tr.Max - tr.Min

	// Generate exponential random value
	u := cryptoRandomFloat64()
	if u <= 0 {
		u = 1e-10 // Avoid log(0)
	}

	// Exponential: -ln(U) / lambda, scaled to range
	expVal := -math.Log(u) / lambda
	// Normalize to [0, 1] range (truncate at ~3 standard deviations)
	normalized := expVal / 3.0
	if normalized > 1.0 {
		normalized = 1.0
	}

	return tr.Min + (rangeSize * normalized)
}

// uniformRandom returns a uniformly distributed random value in [Min, Max].
func (tr TimingRange) uniformRandom() float64 {
	u := cryptoRandomFloat64()
	return tr.Min + (tr.Max-tr.Min)*u
}

// normalRandom returns a normally distributed random value clamped to [Min, Max].
// Uses Box-Muller transform with mean at center of range.
func (tr TimingRange) normalRandom() float64 {
	u1 := cryptoRandomFloat64()
	u2 := cryptoRandomFloat64()

	// Avoid log(0)
	if u1 <= 0 {
		u1 = 1e-10
	}

	// Box-Muller transform
	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)

	// Scale to range: mean at center, stddev = range/6 (99.7% within range)
	mean := (tr.Min + tr.Max) / 2
	stddev := (tr.Max - tr.Min) / 6
	value := mean + z*stddev

	// Clamp to range
	if value < tr.Min {
		value = tr.Min
	}
	if value > tr.Max {
		value = tr.Max
	}

	return value
}

// cryptoRandomFloat64 returns a cryptographically random float64 in [0, 1).
func cryptoRandomFloat64() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0.5 // Fallback to middle value on error
	}
	return float64(binary.BigEndian.Uint64(b[:])) / float64(^uint64(0))
}

// DefaultHandshakeTimingConfig returns the recommended configuration for
// handshake timing that mimics real browser behavior.
// Uses exponential distribution for realistic timing patterns.
func DefaultHandshakeTimingConfig() *HandshakeTimingConfig {
	return &HandshakeTimingConfig{
		Enabled: true,
		ServerHelloDelay: TimingRange{
			Min: 1.0,
			Max: 5.0,
		},
		CCSDelay: CCSTimingConfig{
			Enabled: true,
			PreDelay: TimingRange{
				Min: 0.0,
				Max: 2.0,
			},
			PostDelay: TimingRange{
				Min: 0.0,
				Max: 1.0,
			},
		},
		CertificateDelay: TimingRange{
			Min: 5.0,
			Max: 20.0,
		},
		FinishedDelay: TimingRange{
			Min: 1.0,
			Max: 3.0,
		},
		Distribution: "exponential",
	}
}

// ChromeHandshakeTimingConfig returns timing configuration that approximates
// Chrome's handshake timing behavior.
// Chrome typically sends CCS immediately after ClientHello with minimal delay.
func ChromeHandshakeTimingConfig() *HandshakeTimingConfig {
	return &HandshakeTimingConfig{
		Enabled: true,
		ServerHelloDelay: TimingRange{
			Min: 0.5,
			Max: 3.0,
		},
		CCSDelay: CCSTimingConfig{
			Enabled: true,
			PreDelay: TimingRange{
				Min: 0.0,
				Max: 0.5, // Chrome sends CCS quickly
			},
			PostDelay: TimingRange{
				Min: 0.0,
				Max: 0.5,
			},
		},
		CertificateDelay: TimingRange{
			Min: 3.0,
			Max: 15.0,
		},
		FinishedDelay: TimingRange{
			Min: 0.5,
			Max: 2.0,
		},
		Distribution: "exponential",
	}
}

// FirefoxHandshakeTimingConfig returns timing configuration that approximates
// Firefox's handshake timing behavior.
// Firefox has more variable CCS timing compared to Chrome.
func FirefoxHandshakeTimingConfig() *HandshakeTimingConfig {
	return &HandshakeTimingConfig{
		Enabled: true,
		ServerHelloDelay: TimingRange{
			Min: 1.0,
			Max: 4.0,
		},
		CCSDelay: CCSTimingConfig{
			Enabled: true,
			PreDelay: TimingRange{
				Min: 0.0,
				Max: 2.0, // Firefox has more variable timing
			},
			PostDelay: TimingRange{
				Min: 0.0,
				Max: 1.5,
			},
		},
		CertificateDelay: TimingRange{
			Min: 5.0,
			Max: 25.0,
		},
		FinishedDelay: TimingRange{
			Min: 1.0,
			Max: 4.0,
		},
		Distribution: "exponential",
	}
}

// TimingConfigForClientHelloID returns the appropriate HandshakeTimingConfig
// for a given ClientHelloID. Returns nil for custom/golang/randomized profiles
// where timing should be manually configured, and browser-specific configs for
// browser-mimicking profiles.
//
// This is used internally to enable timing jitter by default for browser profiles.
func TimingConfigForClientHelloID(id ClientHelloID) *HandshakeTimingConfig {
	switch id.Client {
	case helloChrome:
		return ChromeHandshakeTimingConfig()
	case helloFirefox:
		return FirefoxHandshakeTimingConfig()
	case helloSafari, helloIOS:
		// Safari/iOS: use default config (no browser-specific data yet)
		return DefaultHandshakeTimingConfig()
	case helloEdge:
		// Edge is Chromium-based, use Chrome timing
		return ChromeHandshakeTimingConfig()
	default:
		// For custom, golang, randomized profiles: no default timing
		// Users can enable it manually if desired
		return nil
	}
}

// handshakeTimingController manages timing delays during a single handshake.
// It is NOT thread-safe and should only be used within a single handshake goroutine.
type handshakeTimingController struct {
	config *HandshakeTimingConfig
	mu     sync.Mutex

	// Track which delays have been applied to prevent double-application
	serverHelloApplied bool
	ccsApplied         bool
	certificateApplied bool
	finishedApplied    bool
}

// newHandshakeTimingController creates a new timing controller for a handshake.
func newHandshakeTimingController(config *HandshakeTimingConfig) *handshakeTimingController {
	return &handshakeTimingController{
		config: config,
	}
}

// ApplyServerHelloDelay applies the post-ServerHello timing delay.
// Returns immediately if timing is disabled or already applied.
func (htc *handshakeTimingController) ApplyServerHelloDelay() {
	htc.mu.Lock()
	defer htc.mu.Unlock()

	if htc.config == nil || !htc.config.Enabled || htc.serverHelloApplied {
		return
	}
	htc.serverHelloApplied = true

	delay := htc.config.ServerHelloDelay.Duration(htc.config.Distribution)
	if delay > 0 {
		time.Sleep(delay)
	}
}

// ApplyCCSPreDelay applies timing delay before sending the dummy CCS message.
// Returns immediately if CCS timing is disabled or already applied.
// This is called once per handshake, before the first CCS send.
func (htc *handshakeTimingController) ApplyCCSPreDelay() {
	htc.mu.Lock()
	defer htc.mu.Unlock()

	if htc.config == nil || !htc.config.Enabled || !htc.config.CCSDelay.Enabled || htc.ccsApplied {
		return
	}

	delay := htc.config.CCSDelay.PreDelay.Duration(htc.config.Distribution)
	if delay > 0 {
		time.Sleep(delay)
	}
}

// ApplyCCSPostDelay applies timing delay after sending the dummy CCS message.
// Returns immediately if CCS timing is disabled or already applied.
// Marks CCS as applied to prevent double-application.
func (htc *handshakeTimingController) ApplyCCSPostDelay() {
	htc.mu.Lock()
	defer htc.mu.Unlock()

	if htc.config == nil || !htc.config.Enabled || !htc.config.CCSDelay.Enabled || htc.ccsApplied {
		return
	}
	htc.ccsApplied = true

	delay := htc.config.CCSDelay.PostDelay.Duration(htc.config.Distribution)
	if delay > 0 {
		time.Sleep(delay)
	}
}

// ApplyCertificateDelay applies the post-certificate-verification timing delay.
// Returns immediately if timing is disabled or already applied.
func (htc *handshakeTimingController) ApplyCertificateDelay() {
	htc.mu.Lock()
	defer htc.mu.Unlock()

	if htc.config == nil || !htc.config.Enabled || htc.certificateApplied {
		return
	}
	htc.certificateApplied = true

	delay := htc.config.CertificateDelay.Duration(htc.config.Distribution)
	if delay > 0 {
		time.Sleep(delay)
	}
}

// ApplyFinishedDelay applies the pre-Finished timing delay.
// Returns immediately if timing is disabled or already applied.
func (htc *handshakeTimingController) ApplyFinishedDelay() {
	htc.mu.Lock()
	defer htc.mu.Unlock()

	if htc.config == nil || !htc.config.Enabled || htc.finishedApplied {
		return
	}
	htc.finishedApplied = true

	delay := htc.config.FinishedDelay.Duration(htc.config.Distribution)
	if delay > 0 {
		time.Sleep(delay)
	}
}

// Reset clears the applied flags, allowing delays to be re-applied.
// This is useful for handling HelloRetryRequest scenarios.
func (htc *handshakeTimingController) Reset() {
	htc.mu.Lock()
	defer htc.mu.Unlock()

	htc.serverHelloApplied = false
	htc.ccsApplied = false
	htc.certificateApplied = false
	htc.finishedApplied = false
}
