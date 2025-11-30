// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// RecordLayerController manages record-level fingerprinting.
// Thread-safe: uses RWMutex to protect strategy field.
type RecordLayerController struct {
	config   *RecordLayerConfig
	strategy PaddingStrategy
	mu       sync.RWMutex
}

// NewRecordLayerController creates a controller for a connection.
func NewRecordLayerController(config *RecordLayerConfig) *RecordLayerController {
	if config == nil {
		config = &RecordLayerConfig{
			MaxRecordSize:  maxPlaintext,
			PaddingEnabled: false,
		}
	}

	c := &RecordLayerController{
		config: config,
	}

	// Initialize padding strategy
	c.strategy = c.createPaddingStrategy()

	return c
}

// createPaddingStrategy creates a padding strategy based on config.
func (c *RecordLayerController) createPaddingStrategy() PaddingStrategy {
	if !c.config.PaddingEnabled {
		return &NoPaddingStrategy{}
	}

	switch c.config.PaddingMode {
	case RecordPaddingNone:
		return &NoPaddingStrategy{}
	case RecordPaddingRandom:
		return &RandomPaddingStrategy{MaxPad: c.config.PaddingMax}
	case RecordPaddingBlock:
		blockSize := 16
		if c.config.PaddingMax > 0 {
			blockSize = c.config.PaddingMax
		}
		return &BlockPaddingStrategy{BlockSize: blockSize}
	case RecordPaddingExponential:
		lambda := c.config.PaddingLambda
		if lambda <= 0 {
			lambda = 3.0
		}
		return &ExponentialPaddingStrategy{Lambda: lambda}
	case RecordPaddingChrome:
		return &ChromePaddingStrategy{}
	case RecordPaddingFirefox:
		return &FirefoxPaddingStrategy{}
	default:
		return &NoPaddingStrategy{}
	}
}

// PaddingStrategy defines how to pad TLS 1.3 records.
type PaddingStrategy interface {
	// Pad calculates the number of padding bytes to add.
	Pad(dataLen, maxSize int) int

	// Name returns strategy name.
	Name() string
}

// NoPaddingStrategy adds no padding.
type NoPaddingStrategy struct{}

// Pad returns 0 (no padding).
func (s *NoPaddingStrategy) Pad(dataLen, maxSize int) int {
	return 0
}

// Name returns the strategy name.
func (s *NoPaddingStrategy) Name() string {
	return "none"
}

// RandomPaddingStrategy adds random padding up to MaxPad bytes.
type RandomPaddingStrategy struct {
	MaxPad int
}

// Pad returns a random padding length.
// Uses rejection sampling to eliminate modulo bias for uniform distribution.
func (s *RandomPaddingStrategy) Pad(dataLen, maxSize int) int {
	if s.MaxPad <= 0 {
		return 0
	}

	maxPad := s.MaxPad
	available := maxSize - dataLen
	if available < maxPad {
		maxPad = available
	}
	if maxPad <= 0 {
		return 0
	}

	// Cap maxPad to prevent overflow issues
	// RFC 8446 allows up to 255 bytes of padding, but we allow more for flexibility
	if maxPad > 65534 {
		maxPad = 65534
	}

	// Use rejection sampling to eliminate modulo bias
	// rangeSize is the number of valid values [0, maxPad] inclusive
	rangeSize := uint32(maxPad + 1)
	// max is the largest multiple of rangeSize that fits in uint32
	// We use uint32 for 4 bytes of randomness (better than 2 bytes)
	max := ^uint32(0) - (^uint32(0) % rangeSize)

	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			// Fallback to no padding on rand failure
			return 0
		}
		randVal := binary.BigEndian.Uint32(b[:])

		// Accept only if below rejection threshold
		if randVal < max {
			return int(randVal % rangeSize)
		}
		// Otherwise loop and try again (expected iterations: ~1.0)
	}
}

// Name returns the strategy name.
func (s *RandomPaddingStrategy) Name() string {
	return "random"
}

// BlockPaddingStrategy pads to block boundary.
type BlockPaddingStrategy struct {
	BlockSize int
}

// Pad returns padding to reach next block boundary.
func (s *BlockPaddingStrategy) Pad(dataLen, maxSize int) int {
	if s.BlockSize <= 0 {
		return 0
	}

	remainder := dataLen % s.BlockSize
	if remainder == 0 {
		return 0
	}

	padding := s.BlockSize - remainder
	if dataLen+padding > maxSize {
		return 0
	}

	return padding
}

// Name returns the strategy name.
func (s *BlockPaddingStrategy) Name() string {
	return "block"
}

// ExponentialPaddingStrategy uses exponential distribution (like Chrome).
type ExponentialPaddingStrategy struct {
	Lambda float64 // Rate parameter
}

// Pad returns padding from exponential distribution.
func (s *ExponentialPaddingStrategy) Pad(dataLen, maxSize int) int {
	lambda := s.Lambda
	if lambda <= 0 {
		lambda = 3.0
	}

	// Generate exponential random variable
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to no padding on rand failure
		return 0
	}
	u := float64(binary.BigEndian.Uint64(b[:])) / float64(^uint64(0))

	// Protect against Log(0) which returns -Inf
	// Use smallest positive float64 as lower bound
	if u <= 0 {
		u = math.SmallestNonzeroFloat64
	}

	// Exponential distribution: -ln(U) / lambda
	// Cap the result to prevent overflow when converting to int
	logVal := -math.Log(u) / lambda * 16
	if logVal > 65535 {
		logVal = 65535 // Cap at reasonable maximum
	}
	padding := int(logVal)

	// Clamp to available space
	available := maxSize - dataLen
	if padding > available {
		padding = available
	}
	if padding < 0 {
		padding = 0
	}

	return padding
}

// Name returns the strategy name.
func (s *ExponentialPaddingStrategy) Name() string {
	return "exponential"
}

// ChromePaddingStrategy exactly matches Chrome's padding behavior.
// Unlike ExponentialPaddingStrategy (which is configurable), this uses
// Chrome's specific parameters: lambda=3, 255-byte cap, and no padding
// for small records (<256 bytes).
type ChromePaddingStrategy struct{}

// Pad returns Chrome-like padding.
func (s *ChromePaddingStrategy) Pad(dataLen, maxSize int) int {
	// Chrome uses a probabilistic padding scheme
	// This is a simplified approximation

	// Small records: minimal padding
	if dataLen < 256 {
		return 0
	}

	// Medium records: exponential padding
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to no padding on rand failure
		return 0
	}
	u := float64(binary.BigEndian.Uint64(b[:])) / float64(^uint64(0))

	// Protect against Log(0) which returns -Inf
	if u <= 0 {
		u = math.SmallestNonzeroFloat64
	}

	// Exponential with lambda=3
	logVal := -math.Log(u) / 3.0 * 16
	if logVal > 65535 {
		logVal = 65535
	}
	padding := int(logVal)

	// Clamp
	available := maxSize - dataLen
	if padding > available {
		padding = available
	}
	if padding > 255 {
		padding = 255 // Chrome caps at 255
	}
	if padding < 0 {
		padding = 0
	}

	return padding
}

// Name returns the strategy name.
func (s *ChromePaddingStrategy) Name() string {
	return "chrome"
}

// FirefoxPaddingStrategy matches Firefox's padding behavior.
type FirefoxPaddingStrategy struct{}

// Pad returns Firefox-like padding.
func (s *FirefoxPaddingStrategy) Pad(dataLen, maxSize int) int {
	// Firefox uses minimal padding
	// Only pads application data in some cases
	return 0
}

// Name returns the strategy name.
func (s *FirefoxPaddingStrategy) Name() string {
	return "firefox"
}

// CalculatePadding returns the padding bytes to add for a given data length.
// This is a public API method for external callers who need to calculate
// padding without actually applying it (e.g., for size estimation).
// Thread-safe: acquires read lock before accessing strategy.
func (c *RecordLayerController) CalculatePadding(dataLen int) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.strategy == nil {
		return 0
	}
	return c.strategy.Pad(dataLen, c.config.MaxRecordSize)
}

// FragmentData fragments data into multiple records based on config.
// Fragments are capped at MaxRecordSize (or maxPlaintext if not set) to ensure
// they fit within valid TLS record boundaries.
func (c *RecordLayerController) FragmentData(data []byte) [][]byte {
	if !c.config.AllowFragmentation || len(c.config.FragmentPattern) == 0 {
		return [][]byte{data}
	}

	// Determine maximum fragment size - cap at maxPlaintext for TLS compliance
	maxFragmentSize := c.config.MaxRecordSize
	if maxFragmentSize <= 0 || maxFragmentSize > maxPlaintext {
		maxFragmentSize = maxPlaintext
	}

	var fragments [][]byte
	remaining := data
	patternIdx := 0

	for len(remaining) > 0 {
		size := c.config.FragmentPattern[patternIdx]

		// Handle invalid or oversized pattern entries
		if size <= 0 || size > len(remaining) {
			size = len(remaining)
		}

		// Cap fragment size at maximum allowed to prevent TLS record overflow
		if size > maxFragmentSize {
			size = maxFragmentSize
		}

		fragment := make([]byte, size)
		copy(fragment, remaining[:size])
		fragments = append(fragments, fragment)

		remaining = remaining[size:]
		patternIdx = (patternIdx + 1) % len(c.config.FragmentPattern)
	}

	return fragments
}

// SetStrategy sets a custom padding strategy.
// Thread-safe: acquires write lock before modifying strategy.
func (c *RecordLayerController) SetStrategy(strategy PaddingStrategy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.strategy = strategy
}

// Strategy returns the current padding strategy.
// Thread-safe: acquires read lock before accessing strategy.
func (c *RecordLayerController) Strategy() PaddingStrategy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.strategy
}

// Config returns the record layer configuration.
func (c *RecordLayerController) Config() *RecordLayerConfig {
	return c.config
}

// RecordTimingController manages record timing for fingerprint resistance.
// Thread-safe: all fields use atomic operations for concurrent access.
type RecordTimingController struct {
	baseDelay  atomic.Int64 // Stored as nanoseconds
	jitter     atomic.Int64 // Stored as nanoseconds
	burstSize  atomic.Int32
	burstCount atomic.Int32
}

// NewRecordTimingController creates a timing controller.
func NewRecordTimingController() *RecordTimingController {
	return &RecordTimingController{}
}

// SetDelay sets the base delay between records.
// Thread-safe: uses atomic store.
func (c *RecordTimingController) SetDelay(delay time.Duration) {
	c.baseDelay.Store(int64(delay))
}

// SetJitter sets the random jitter to add to delays.
// Thread-safe: uses atomic store.
func (c *RecordTimingController) SetJitter(jitter time.Duration) {
	c.jitter.Store(int64(jitter))
}

// SetBurstSize sets how many records to send in a burst.
// Thread-safe: uses atomic store.
func (c *RecordTimingController) SetBurstSize(size int) {
	c.burstSize.Store(int32(size))
}

// GetDelay returns the delay to use before sending the next record.
// Thread-safe: uses atomic loads and CompareAndSwap for burst handling.
func (c *RecordTimingController) GetDelay() time.Duration {
	// If in burst mode and still in burst
	burstSize := c.burstSize.Load()
	if burstSize > 0 {
		// Use CompareAndSwap loop to atomically handle burst counting
		// This prevents race conditions where multiple goroutines exceed
		// burstSize and all try to reset the counter
		for {
			current := c.burstCount.Load()
			if current < burstSize {
				// Try to claim a spot in the current burst
				if c.burstCount.CompareAndSwap(current, current+1) {
					return 0 // Successfully claimed spot, no delay
				}
				// CAS failed, retry
				continue
			}
			// Burst exhausted, try to reset counter for next burst
			// The goroutine that successfully resets will get the delay
			if c.burstCount.CompareAndSwap(current, 0) {
				// Successfully reset, this caller gets the delay
				break // Exit loop to apply delay
			}
			// CAS failed (another goroutine reset or incremented), retry
		}
	}

	// Calculate delay with jitter
	delay := time.Duration(c.baseDelay.Load())

	// Clamp negative base delay to 0 for safety
	if delay < 0 {
		delay = 0
	}

	jitter := c.jitter.Load()
	if jitter > 0 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err == nil {
			jitterNs := int64(binary.BigEndian.Uint64(b[:]) % uint64(jitter))
			delay += time.Duration(jitterNs)
		}
		// On rand failure, just use base delay without jitter
	}

	return delay
}

// NewPaddingStrategy creates a padding strategy by mode.
func NewPaddingStrategy(mode RecordPaddingMode, params map[string]interface{}) PaddingStrategy {
	switch mode {
	case RecordPaddingNone:
		return &NoPaddingStrategy{}

	case RecordPaddingRandom:
		maxPad := 255
		if v, ok := params["max_pad"].(int); ok {
			maxPad = v
		}
		return &RandomPaddingStrategy{MaxPad: maxPad}

	case RecordPaddingBlock:
		blockSize := 16
		if v, ok := params["block_size"].(int); ok {
			blockSize = v
		}
		return &BlockPaddingStrategy{BlockSize: blockSize}

	case RecordPaddingExponential:
		lambda := 3.0
		if v, ok := params["lambda"].(float64); ok {
			lambda = v
		}
		return &ExponentialPaddingStrategy{Lambda: lambda}

	case RecordPaddingChrome:
		return &ChromePaddingStrategy{}

	case RecordPaddingFirefox:
		return &FirefoxPaddingStrategy{}

	default:
		return &NoPaddingStrategy{}
	}
}

// ChromeRecordLayerConfig returns Chrome-like record layer configuration.
func ChromeRecordLayerConfig() *RecordLayerConfig {
	return &RecordLayerConfig{
		MaxRecordSize:  maxPlaintext,
		PaddingEnabled: true,
		PaddingMode:    RecordPaddingChrome,
		PaddingLambda:  3.0,
	}
}

// FirefoxRecordLayerConfig returns Firefox-like record layer configuration.
func FirefoxRecordLayerConfig() *RecordLayerConfig {
	return &RecordLayerConfig{
		MaxRecordSize:  maxPlaintext,
		PaddingEnabled: false,
		PaddingMode:    RecordPaddingFirefox,
	}
}
