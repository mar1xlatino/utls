// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// SessionFingerprintState holds all values that must remain consistent across
// multiple connections to the same origin within a session.
//
// CRITICAL: Chrome randomizes GREASE values and shuffles extensions, but these
// must stay CONSISTENT within a session. This struct freezes those values.
type SessionFingerprintState struct {
	// Identity
	ID        string // Unique session identifier
	ProfileID string // Base profile this session uses
	Origin    string // "example.com:443"
	CreatedAt time.Time

	// Frozen GREASE values
	// Each GREASE position gets a random value that stays fixed for the session
	FrozenGREASE FrozenGREASEValues

	// Frozen ordering
	// For browsers that shuffle (Chrome), the order is frozen for the session
	FrozenExtensionOrder []uint16          // Extension types in frozen order
	FrozenCipherOrder    []uint16          // Cipher suites in frozen order (if shuffled)
	FrozenKeyShareGroups []CurveID         // Key share groups in frozen order
	FrozenSigAlgOrder    []SignatureScheme // Signature algorithms in frozen order

	// Derived fingerprints (computed once from frozen values)
	ExpectedJA3  string
	ExpectedJA4  string
	ExpectedJA4o string

	// Session state
	frozen          bool // Once frozen, no modifications allowed
	connectionCount int  // Number of connections using this state
	lastUsed        time.Time

	// TLS session data (for resumption)
	SessionTicket    []byte // TLS session ticket for resumption
	PSKIdentity      []byte // PSK identity
	ResumptionSecret []byte // TLS 1.3 resumption master secret

	mu sync.RWMutex
}

// FrozenGREASEValues holds all GREASE values for a session.
// These are selected randomly once and then used consistently.
type FrozenGREASEValues struct {
	CipherSuite      uint16 // GREASE value in cipher suite list
	Extension1       uint16 // First GREASE extension
	Extension2       uint16 // Second GREASE extension
	SupportedGroup   uint16 // GREASE in supported_groups
	SupportedVersion uint16 // GREASE in supported_versions
	KeyShare         uint16 // GREASE key share group
	SignatureAlgo    uint16 // GREASE in signature_algorithms
	PSKMode          uint8  // GREASE in PSK modes (RFC 8701 uses different values: 0x0B, 0x2A, etc.)
}

// GreaseExtMarker1 and GreaseExtMarker2 are special marker values used in
// FrozenExtensionOrder to distinguish the first and second GREASE extensions
// after shuffle. This solves the bug where applyFrozenGREASE would assign
// Extension1 to whichever GREASE extension appeared first in the shuffled
// order, rather than the one that was originally first.
//
// These values must not conflict with any valid TLS extension type.
// 0xFFFF and 0xFFFE are safe because:
// 1. They are not valid GREASE values (GREASE uses 0x?a?a pattern)
// 2. They are not assigned extension types (max assigned is ~65280)
const (
	GreaseExtMarker1 uint16 = 0xFFFF // Marker for first GREASE extension
	GreaseExtMarker2 uint16 = 0xFFFE // Marker for second GREASE extension
)

// IsGreaseExtMarker returns true if the value is a GREASE extension marker.
func IsGreaseExtMarker(v uint16) bool {
	return v == GreaseExtMarker1 || v == GreaseExtMarker2
}

// greaseValues is the set of valid GREASE values per RFC 8701.
var greaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
	0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
	0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// greasePSKModeValues is the set of valid GREASE values for PskKeyExchangeModes per RFC 8701.
// These are single-byte values (different from the 2-byte GREASE pattern used elsewhere).
var greasePSKModeValues = []uint8{
	0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4,
}

// randomGREASE returns a random GREASE value.
func randomGREASE() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to first GREASE value if rand fails
		return greaseValues[0]
	}
	idx := binary.BigEndian.Uint16(b[:]) % uint16(len(greaseValues))
	return greaseValues[idx]
}

// randomPSKModeGREASE returns a random GREASE value for PskKeyExchangeModes per RFC 8701.
func randomPSKModeGREASE() uint8 {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return greasePSKModeValues[0]
	}
	return greasePSKModeValues[b[0]%uint8(len(greasePSKModeValues))]
}

// IsValidPSKModeGREASE returns true if v is a valid GREASE value for PskKeyExchangeModes per RFC 8701.
func IsValidPSKModeGREASE(v uint8) bool {
	for _, valid := range greasePSKModeValues {
		if v == valid {
			return true
		}
	}
	return false
}

// NewSessionFingerprintState creates a new session state from a profile.
// Always returns a valid state. If profile is nil, returns a state with empty profile ID.
func NewSessionFingerprintState(profile *FingerprintProfile, origin string) *SessionFingerprintState {
	now := time.Now()

	profileID := ""
	if profile != nil {
		profileID = profile.ID
	}

	state := &SessionFingerprintState{
		ID:        generateSessionID(),
		ProfileID: profileID,
		Origin:    origin,
		CreatedAt: now,
		lastUsed:  now,
	}

	// Only populate profile-dependent fields if profile is provided
	if profile != nil {
		// Generate frozen GREASE values
		if profile.ClientHello.GREASE.Enabled {
			// Generate Extension1 and Extension2 independently (NO deduplication)
			// Real Chrome/BoringSSL generates GREASE values independently without
			// deduplication. With 16 possible GREASE values (0x0A0A through 0xFAFA),
			// there's a natural 1/16 = 6.25% collision rate. This is CORRECT behavior.
			// Previous code always deduplicated, giving 0% collision rate, which was
			// detectable as non-Chrome behavior.
			ext1 := randomGREASE()
			ext2 := randomGREASE()
			// Allow natural collision - do NOT deduplicate

			// Generate SupportedGroup GREASE
			// CRITICAL: Chrome/BoringSSL uses ssl_grease_group for BOTH supported_groups
			// and key_share extensions. They MUST be the same value!
			supportedGroup := randomGREASE()

			state.FrozenGREASE = FrozenGREASEValues{
				CipherSuite:      randomGREASE(),
				Extension1:       ext1,
				Extension2:       ext2,
				SupportedGroup:   supportedGroup,
				SupportedVersion: randomGREASE(),
				KeyShare:         supportedGroup, // MUST match SupportedGroup per Chrome behavior
				SignatureAlgo:    randomGREASE(),
				PSKMode:          randomPSKModeGREASE(), // RFC 8701: PSK modes use different GREASE values
			}
		}

		// Freeze extension order if shuffling is enabled
		if profile.ClientHello.ShuffleExtensions {
			if len(profile.ClientHello.Extensions) > 0 {
				// Use Extensions if available (has both type and data)
				state.FrozenExtensionOrder = shuffleExtensionOrder(profile.ClientHello.Extensions, profile.ClientHello.ShuffleSeed)
			} else if len(profile.ClientHello.ExtensionOrder) > 0 {
				// Fall back to ExtensionOrder for built-in profiles
				state.FrozenExtensionOrder = shuffleExtensionOrderFromTypes(profile.ClientHello.ExtensionOrder, profile.ClientHello.ShuffleSeed)
			}
		}

		// Copy key share groups order
		if len(profile.ClientHello.KeyShareGroups) > 0 {
			state.FrozenKeyShareGroups = make([]CurveID, len(profile.ClientHello.KeyShareGroups))
			copy(state.FrozenKeyShareGroups, profile.ClientHello.KeyShareGroups)
		}

		// Copy signature algorithm order
		if len(profile.ClientHello.SignatureAlgorithms) > 0 {
			state.FrozenSigAlgOrder = make([]SignatureScheme, len(profile.ClientHello.SignatureAlgorithms))
			copy(state.FrozenSigAlgOrder, profile.ClientHello.SignatureAlgorithms)
		}
	}

	return state
}

// sessionIDCounter is an atomic counter used as fallback entropy when rand.Read fails.
// This ensures unique session IDs even in concurrent fallback scenarios.
var sessionIDCounter uint64

// generateSessionID creates a unique session identifier.
// Returns a hex-encoded string to avoid issues with null bytes and non-printable characters.
func generateSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to timestamp + atomic counter if rand fails.
		// Using atomic counter ensures uniqueness even in concurrent calls
		// within the same nanosecond.
		counter := atomic.AddUint64(&sessionIDCounter, 1)
		binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(b[8:], counter)
	}
	return hex.EncodeToString(b[:])
}

// shuffleExtensionOrder shuffles extension order like Chrome does.
// Returns the extension types in shuffled order.
func shuffleExtensionOrder(extensions []ExtensionEntry, seed int64) []uint16 {
	types := make([]uint16, len(extensions))
	for i, ext := range extensions {
		types[i] = ext.Type
	}

	return shuffleExtensionOrderFromTypes(types, seed)
}

// shuffleExtensionOrderFromTypes shuffles a list of extension types.
// This variant takes []uint16 directly for built-in profiles that use ExtensionOrder.
//
// IMPORTANT: GREASE extension types are replaced with GreaseExtMarker1 and
// GreaseExtMarker2 to preserve which GREASE extension was first/second in the
// original order. After shuffling, applyFrozenGREASE uses these markers to
// assign the correct frozen GREASE values.
func shuffleExtensionOrderFromTypes(types []uint16, seed int64) []uint16 {
	// Make a copy to avoid mutating the input
	result := make([]uint16, len(types))

	// Replace GREASE types with markers to track original positions
	// This ensures correct GREASE value assignment after shuffle
	greaseCount := 0
	for i, extType := range types {
		if isGREASEUint16(extType) {
			// First GREASE becomes Marker1, second becomes Marker2
			if greaseCount == 0 {
				result[i] = GreaseExtMarker1
			} else {
				result[i] = GreaseExtMarker2
			}
			greaseCount++
		} else {
			result[i] = extType
		}
	}

	// Chrome's shuffle excludes certain extensions that must be at fixed positions
	// PSK extension must be last, GREASE extensions at specific positions
	// This is a simplified shuffle - real Chrome behavior is more complex

	// For now, use Fisher-Yates shuffle with seed
	// In production, this should match Chrome's exact algorithm
	if seed == 0 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			// Fallback to time-based seed if rand fails
			seed = time.Now().UnixNano()
		} else {
			seed = int64(binary.BigEndian.Uint64(b[:]))
		}
	}

	// Create local PRNG for deterministic shuffle
	prng := newPRNGFromSeed(seed)
	prng.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})

	return result
}

// newPRNGFromSeed creates a simple PRNG from a seed.
// IMPORTANT: xorshift64 produces all zeros if state is 0, so we ensure non-zero.
func newPRNGFromSeed(seed int64) *simplePRNG {
	state := uint64(seed)
	if state == 0 {
		state = 1 // Ensure non-zero state for xorshift64
	}
	return &simplePRNG{state: state}
}

// simplePRNG is a minimal PRNG for shuffling.
// Thread-safe: uses mutex to protect state field.
type simplePRNG struct {
	state uint64
	mu    sync.Mutex
}

// Shuffle shuffles n elements using the provided swap function.
// Thread-safe: acquires mutex before accessing state.
func (p *simplePRNG) Shuffle(n int, swap func(i, j int)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := n - 1; i > 0; i-- {
		j := int(p.nextUnsafe() % uint64(i+1))
		swap(i, j)
	}
}

// nextUnsafe advances the PRNG state and returns the next value.
// MUST be called with mu held.
func (p *simplePRNG) nextUnsafe() uint64 {
	// Simple xorshift64
	p.state ^= p.state << 13
	p.state ^= p.state >> 7
	p.state ^= p.state << 17
	return p.state
}

// Freeze locks the session state, preventing further modifications.
func (s *SessionFingerprintState) Freeze() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frozen = true
}

// IsFrozen returns whether the session state is frozen.
func (s *SessionFingerprintState) IsFrozen() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.frozen
}

// Touch updates the last used timestamp.
func (s *SessionFingerprintState) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUsed = time.Now()
	s.connectionCount++
}

// ConnectionCount returns the number of connections using this state.
func (s *SessionFingerprintState) ConnectionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connectionCount
}

// LastUsed returns when this state was last used.
func (s *SessionFingerprintState) LastUsed() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastUsed
}

// GetGREASEValue returns the frozen GREASE value for a given position.
func (s *SessionFingerprintState) GetGREASEValue(position GREASEPosition) uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch position {
	case GREASECipherSuite:
		return s.FrozenGREASE.CipherSuite
	case GREASEExtension1:
		return s.FrozenGREASE.Extension1
	case GREASEExtension2:
		return s.FrozenGREASE.Extension2
	case GREASESupportedGroup:
		return s.FrozenGREASE.SupportedGroup
	case GREASESupportedVersion:
		return s.FrozenGREASE.SupportedVersion
	case GREASEKeyShare:
		return s.FrozenGREASE.KeyShare
	case GREASESignatureAlgo:
		return s.FrozenGREASE.SignatureAlgo
	case GREASEPSKMode:
		return uint16(s.FrozenGREASE.PSKMode)
	default:
		// Return a consistent value for unknown positions instead of random
		// to maintain session consistency
		return s.FrozenGREASE.Extension1
	}
}

// GetFrozenExtensionOrder returns a copy of the frozen extension order.
// Returns nil if no frozen order is set.
// The returned slice is safe to modify without affecting session state.
func (s *SessionFingerprintState) GetFrozenExtensionOrder() []uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.FrozenExtensionOrder == nil {
		return nil
	}

	result := make([]uint16, len(s.FrozenExtensionOrder))
	copy(result, s.FrozenExtensionOrder)
	return result
}

// GetFrozenCipherOrder returns a copy of the frozen cipher order.
// Returns nil if no frozen order is set.
// The returned slice is safe to modify without affecting session state.
func (s *SessionFingerprintState) GetFrozenCipherOrder() []uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.FrozenCipherOrder == nil {
		return nil
	}

	result := make([]uint16, len(s.FrozenCipherOrder))
	copy(result, s.FrozenCipherOrder)
	return result
}

// GetFrozenKeyShareGroups returns a copy of the frozen key share groups.
// Returns nil if no frozen groups are set.
// The returned slice is safe to modify without affecting session state.
func (s *SessionFingerprintState) GetFrozenKeyShareGroups() []CurveID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.FrozenKeyShareGroups == nil {
		return nil
	}

	result := make([]CurveID, len(s.FrozenKeyShareGroups))
	copy(result, s.FrozenKeyShareGroups)
	return result
}

// GetFrozenSigAlgOrder returns a copy of the frozen signature algorithm order.
// Returns nil if no frozen order is set.
// The returned slice is safe to modify without affecting session state.
func (s *SessionFingerprintState) GetFrozenSigAlgOrder() []SignatureScheme {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.FrozenSigAlgOrder == nil {
		return nil
	}

	result := make([]SignatureScheme, len(s.FrozenSigAlgOrder))
	copy(result, s.FrozenSigAlgOrder)
	return result
}

// GREASEPosition identifies where a GREASE value is used.
type GREASEPosition int

const (
	GREASECipherSuite GREASEPosition = iota
	GREASEExtension1
	GREASEExtension2
	GREASESupportedGroup
	GREASESupportedVersion
	GREASEKeyShare
	GREASESignatureAlgo
	GREASEPSKMode
)

// SetSessionTicket stores the session ticket for resumption.
// Pass nil or empty slice to clear the ticket.
// Returns ErrSessionFrozen if the session state has been frozen.
func (s *SessionFingerprintState) SetSessionTicket(ticket []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.frozen {
		return ErrSessionFrozen
	}

	// Zero previous ticket before overwriting for security
	zeroSlice(s.SessionTicket)

	// Treat nil/empty as clearing the ticket
	if len(ticket) == 0 {
		s.SessionTicket = nil
		return nil
	}

	s.SessionTicket = make([]byte, len(ticket))
	copy(s.SessionTicket, ticket)
	return nil
}

// GetSessionTicket returns the stored session ticket.
func (s *SessionFingerprintState) GetSessionTicket() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.SessionTicket == nil {
		return nil
	}

	ticket := make([]byte, len(s.SessionTicket))
	copy(ticket, s.SessionTicket)
	return ticket
}

// SetResumptionSecret stores the TLS 1.3 resumption secret.
// Pass nil or empty slice to clear the secret.
// Returns ErrSessionFrozen if the session state has been frozen.
func (s *SessionFingerprintState) SetResumptionSecret(secret []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.frozen {
		return ErrSessionFrozen
	}

	// Zero previous secret before overwriting for security
	zeroSlice(s.ResumptionSecret)

	// Treat nil/empty as clearing the secret
	if len(secret) == 0 {
		s.ResumptionSecret = nil
		return nil
	}

	s.ResumptionSecret = make([]byte, len(secret))
	copy(s.ResumptionSecret, secret)
	return nil
}

// GetResumptionSecret returns the stored resumption secret.
func (s *SessionFingerprintState) GetResumptionSecret() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ResumptionSecret == nil {
		return nil
	}

	secret := make([]byte, len(s.ResumptionSecret))
	copy(secret, s.ResumptionSecret)
	return secret
}

// Clear zeros and clears all sensitive session data.
func (s *SessionFingerprintState) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	zeroSlice(s.SessionTicket)
	zeroSlice(s.PSKIdentity)
	zeroSlice(s.ResumptionSecret)

	s.SessionTicket = nil
	s.PSKIdentity = nil
	s.ResumptionSecret = nil
}

// SessionStateCache manages session states per origin.
//
// Lock ordering: When both SessionStateCache.mu and SessionFingerprintState.mu
// need to be held, always acquire SessionStateCache.mu first. This is enforced
// by the current implementation where SessionFingerprintState doesn't hold a
// reference to its parent cache, making reverse-order acquisition impossible.
type SessionStateCache struct {
	cache   map[string]*SessionFingerprintState
	mu      sync.RWMutex
	maxSize int
	maxAge  time.Duration
}

// NewSessionStateCache creates a new session state cache.
func NewSessionStateCache(maxSize int, maxAge time.Duration) *SessionStateCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}

	return &SessionStateCache{
		cache:   make(map[string]*SessionFingerprintState),
		maxSize: maxSize,
		maxAge:  maxAge,
	}
}

// makeCacheKey creates a cache key from origin and profile ID.
// The key format is "origin|profileID" to ensure different profiles
// don't share incompatible session state.
func makeCacheKey(origin, profileID string) string {
	return origin + "|" + profileID
}

// GetOrCreate returns existing session state or creates a new one.
// Touch() is called on the returned state to track connection count:
// - connectionCount == 1: First connection (new session)
// - connectionCount > 1: Subsequent connections (reused session)
//
// IMPORTANT: Session state is keyed by both origin AND profile ID. This prevents
// different profiles from sharing incompatible session state (e.g., a profile
// with GREASE disabled creating state with zeroed GREASE values that would
// corrupt a GREASE-enabled profile that later connects to the same origin).
func (c *SessionStateCache) GetOrCreate(origin string, profile *FingerprintProfile) *SessionFingerprintState {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build cache key that includes both origin and profile ID.
	// This ensures different profiles don't share incompatible session state.
	// For example, Firefox (no GREASE) and Chrome (with GREASE) connecting to
	// the same origin must have separate session states.
	profileID := ""
	if profile != nil {
		profileID = profile.ID
	}
	cacheKey := makeCacheKey(origin, profileID)

	// Check for existing state
	if state, ok := c.cache[cacheKey]; ok {
		if time.Since(state.CreatedAt) < c.maxAge {
			state.Touch()
			return state
		}
		// Expired, remove it
		state.Clear()
		delete(c.cache, cacheKey)
	}

	// Create new state (always returns valid state, even if profile is nil)
	state := NewSessionFingerprintState(profile, origin)

	// Touch the new state so connectionCount becomes 1
	// This allows ApplyFingerprintProfile to distinguish:
	// - connectionCount == 1: new session -> OnSessionStateCreated
	// - connectionCount > 1: reused session -> OnSessionStateRestored
	state.Touch()

	// Evict oldest if at capacity
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[cacheKey] = state
	return state
}

// Get returns session state for origin and profile if it exists.
// Returns nil if the entry doesn't exist or is expired.
// Expired entries are lazily removed on the next write operation.
//
// The profileID parameter is required because session state is keyed by
// both origin and profile ID to prevent incompatible state sharing.
func (c *SessionStateCache) Get(origin, profileID string) *SessionFingerprintState {
	cacheKey := makeCacheKey(origin, profileID)

	c.mu.RLock()
	state, ok := c.cache[cacheKey]
	if !ok {
		c.mu.RUnlock()
		return nil
	}

	// Check if entry is still valid
	if time.Since(state.CreatedAt) < c.maxAge {
		c.mu.RUnlock()
		return state
	}

	// Entry is expired - upgrade to write lock and remove it
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check under write lock (another goroutine may have modified)
	state, ok = c.cache[cacheKey]
	if !ok {
		return nil
	}
	// Check again - entry may have been replaced with fresh one
	if time.Since(state.CreatedAt) < c.maxAge {
		return state
	}
	// Still expired, remove it
	state.Clear()
	delete(c.cache, cacheKey)
	return nil
}

// Set stores session state for origin and profile.
//
// The profileID parameter is required because session state is keyed by
// both origin and profile ID to prevent incompatible state sharing.
func (c *SessionStateCache) Set(origin, profileID string, state *SessionFingerprintState) {
	cacheKey := makeCacheKey(origin, profileID)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Clear any existing state
	if existing, ok := c.cache[cacheKey]; ok {
		existing.Clear()
	}

	// Evict oldest if at capacity
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	c.cache[cacheKey] = state
}

// Delete removes session state for origin and profile.
//
// The profileID parameter is required because session state is keyed by
// both origin and profile ID to prevent incompatible state sharing.
func (c *SessionStateCache) Delete(origin, profileID string) {
	cacheKey := makeCacheKey(origin, profileID)

	c.mu.Lock()
	defer c.mu.Unlock()

	if state, ok := c.cache[cacheKey]; ok {
		state.Clear()
		delete(c.cache, cacheKey)
	}
}

// Clear removes all session states.
func (c *SessionStateCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, state := range c.cache {
		state.Clear()
	}
	c.cache = make(map[string]*SessionFingerprintState)
}

// evictOldest removes the oldest session state.
// Also opportunistically removes expired entries to reduce memory pressure.
// Must be called with lock held.
func (c *SessionStateCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	now := time.Now()
	var expiredKeys []string

	for key, state := range c.cache {
		// Collect expired entries for removal
		if now.Sub(state.CreatedAt) > c.maxAge {
			expiredKeys = append(expiredKeys, key)
			continue
		}

		// Read LastUsed() once to avoid race condition where Touch() is called
		// between the comparison and assignment. Although we hold c.mu, state.mu
		// is released between calls to LastUsed(), allowing concurrent Touch().
		stateLastUsed := state.LastUsed()
		if oldestKey == "" || stateLastUsed.Before(oldestTime) {
			oldestKey = key
			oldestTime = stateLastUsed
		}
	}

	// Remove all expired entries first
	for _, key := range expiredKeys {
		if state, ok := c.cache[key]; ok {
			state.Clear()
		}
		delete(c.cache, key)
	}

	// If we removed expired entries and are now under capacity, we're done
	if len(expiredKeys) > 0 && len(c.cache) < c.maxSize {
		return
	}

	// Otherwise remove the oldest valid entry
	if oldestKey != "" {
		if state, ok := c.cache[oldestKey]; ok {
			state.Clear()
		}
		delete(c.cache, oldestKey)
	}
}

// Stats returns cache statistics.
func (c *SessionStateCache) Stats() SessionCacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := SessionCacheStats{
		Size:    len(c.cache),
		MaxSize: c.maxSize,
		MaxAge:  c.maxAge,
	}

	for _, state := range c.cache {
		stats.TotalConnections += state.ConnectionCount()
		// Use GetSessionTicket() to avoid data race - it acquires proper lock
		if state.GetSessionTicket() != nil {
			stats.WithTickets++
		}
	}

	return stats
}

// SessionCacheStats contains cache statistics.
type SessionCacheStats struct {
	Size             int
	MaxSize          int
	MaxAge           time.Duration
	TotalConnections int
	WithTickets      int
}

// Cleanup removes expired entries from the cache.
func (c *SessionStateCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	var removed int
	now := time.Now()

	for key, state := range c.cache {
		if now.Sub(state.CreatedAt) >= c.maxAge {
			state.Clear()
			delete(c.cache, key)
			removed++
		}
	}

	return removed
}

// DefaultSessionCache is the global session state cache.
var DefaultSessionCache = NewSessionStateCache(10000, 24*time.Hour)

// ErrSessionFrozen is returned when attempting to modify a frozen session.
var ErrSessionFrozen = errors.New("tls: session state is frozen")
