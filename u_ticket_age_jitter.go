// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"io"
	"math"
	"time"
)

// TicketAgeJitterConfig controls the jitter applied to obfuscated_ticket_age
// in TLS 1.3 session resumption. This prevents DPI from correlating sessions
// by observing deterministic ticket age patterns.
//
// Background: TLS 1.3 computes obfuscated_ticket_age as:
//
//	obfuscated_ticket_age = (ticket_age_ms + ticket_age_add) mod 2^32
//
// Without jitter, the ticket_age_ms is deterministic based on wall clock time,
// allowing sophisticated DPI to correlate multiple resumption attempts by
// observing consistent ticket age progressions.
//
// With jitter enabled, small random variations (simulating clock drift) are
// added to ticket_age_ms before obfuscation, making correlation more difficult.
type TicketAgeJitterConfig struct {
	// Enabled controls whether jitter is applied to ticket age.
	// When false (default), ticket age is computed deterministically.
	Enabled bool

	// MaxJitterMs is the maximum jitter in milliseconds to add/subtract.
	// The actual jitter will be uniformly distributed in [-MaxJitterMs, +MaxJitterMs].
	// Default: 500 (when Enabled is true but MaxJitterMs is 0 or negative)
	//
	// Recommended range: 100-1000ms
	//   - Too small (<50ms): May not provide meaningful protection
	//   - Too large (>2000ms): May cause server-side ticket age validation issues
	//
	// Real browsers have natural clock drift of 50-500ms relative to servers,
	// so values in this range appear natural.
	MaxJitterMs int
}

// DefaultTicketAgeJitterConfig returns a TicketAgeJitterConfig with sensible defaults.
// The returned config has jitter ENABLED with MaxJitterMs of 500.
//
// This mimics natural clock drift between client and server, which typically
// ranges from 50-500ms in real-world conditions.
func DefaultTicketAgeJitterConfig() *TicketAgeJitterConfig {
	return &TicketAgeJitterConfig{
		Enabled:     true,
		MaxJitterMs: 500,
	}
}

// DisabledTicketAgeJitterConfig returns a TicketAgeJitterConfig with jitter disabled.
// Use this for deterministic behavior (NOT RECOMMENDED for fingerprint resistance).
func DisabledTicketAgeJitterConfig() *TicketAgeJitterConfig {
	return &TicketAgeJitterConfig{
		Enabled:     false,
		MaxJitterMs: 0,
	}
}

// computeObfuscatedTicketAge computes the obfuscated_ticket_age for a TLS 1.3
// PSK identity, optionally applying jitter to resist traffic analysis.
//
// Parameters:
//   - ticketAgeMs: The actual ticket age in milliseconds (time since ticket was received)
//   - ageAdd: The ticket_age_add value from the NewSessionTicket message
//   - jitterConfig: Configuration for jitter (may be nil for no jitter)
//   - rand: Random source for jitter generation
//
// Returns the obfuscated ticket age as uint32.
//
// Per RFC 8446 Section 4.2.11.1:
//
//	obfuscated_ticket_age = (ticket_age + ticket_age_add) mod 2^32
//
// where ticket_age is in milliseconds. The mod 2^32 is implicit in uint32 arithmetic.
func computeObfuscatedTicketAge(ticketAgeMs int64, ageAdd uint32, jitterConfig *TicketAgeJitterConfig, rand io.Reader) uint32 {
	// Start with the base ticket age
	adjustedAge := ticketAgeMs

	// Apply jitter if enabled
	if jitterConfig != nil && jitterConfig.Enabled {
		maxJitter := jitterConfig.MaxJitterMs
		if maxJitter <= 0 {
			maxJitter = 500 // Default to 500ms
		}

		// Generate random jitter in range [-maxJitter, +maxJitter]
		jitter := generateJitter(maxJitter, rand)
		adjustedAge += int64(jitter)

		// Ensure non-negative (ticket age cannot be negative)
		if adjustedAge < 0 {
			adjustedAge = 0
		}
	}

	// Handle potential overflow: if adjustedAge exceeds uint32 max, wrap around
	// This is the "mod 2^32" part of the RFC specification
	if adjustedAge > math.MaxUint32 {
		adjustedAge = adjustedAge % (math.MaxUint32 + 1)
	}

	// Compute obfuscated age: (ticket_age + age_add) mod 2^32
	// The mod 2^32 is implicit in uint32 arithmetic
	return uint32(adjustedAge) + ageAdd
}

// generateJitter generates a random jitter value in the range [-maxJitter, +maxJitter].
// Uses uniform distribution for simplicity and unpredictability.
func generateJitter(maxJitter int, rand io.Reader) int {
	if rand == nil || maxJitter <= 0 {
		return 0
	}

	// Generate 4 random bytes
	var buf [4]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		// On error, return 0 jitter (fail safe)
		return 0
	}

	// Convert to uint32 and then to a value in [0, 2*maxJitter]
	randVal := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	jitterRange := uint32(maxJitter * 2)

	// Use modulo to get a value in [0, 2*maxJitter], then subtract maxJitter
	// to get [-maxJitter, +maxJitter]
	jitter := int(randVal%jitterRange) - maxJitter

	return jitter
}

// computeTicketAgeWithJitter is a convenience function that computes the jittered
// ticket age from a time.Duration and session data.
//
// This function is used internally during TLS 1.3 session resumption to compute
// the obfuscated_ticket_age field of the pre_shared_key extension.
func computeTicketAgeWithJitter(ticketAge time.Duration, ageAdd uint32, config *Config) uint32 {
	ticketAgeMs := int64(ticketAge / time.Millisecond)

	// Clamp to valid range: ticket age cannot be negative or exceed uint32 max
	if ticketAgeMs < 0 {
		ticketAgeMs = 0
	}
	if ticketAgeMs > math.MaxUint32 {
		// Ticket is too old for valid resumption anyway
		ticketAgeMs = math.MaxUint32
	}

	return computeObfuscatedTicketAge(ticketAgeMs, ageAdd, config.TicketAgeJitter, config.rand())
}
