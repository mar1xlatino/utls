// Package memcontrol provides memory-aware resource management for REALITY.
//
// This is adapted from Xray-core's common/buf memory budget system,
// simplified for REALITY's needs as a TLS fingerprinting library.
//
// Architecture:
//   - Budget tracks total memory usage with soft/hard limits
//   - Soft limit triggers eviction mode (stop caching, shed connections)
//   - Hard limit blocks allocations until space available
//   - Connection registry allows shedding idle/slow connections
package memcontrol

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// MemoryBudget tracks and limits buffer memory usage.
// This is the PRIMARY control point for memory management.
//
// Three states:
//   - NORMAL (usage < soft): Cache all buffers
//   - EVICT (soft <= usage < hard): Don't cache returned buffers, trigger shedding
//   - BLOCK (usage >= hard): Block allocations until space available
type MemoryBudget struct {
	// Current usage (bytes)
	totalBytes atomic.Int64 // Total tracked (inUse + cached)
	inUseBytes atomic.Int64 // Currently loaned out

	// Pool cache tracking for drift detection
	// When Release() returns true (cache), we increment cachedBytes
	// When RecordHit() is called (buffer from pool), we decrement cachedBytes
	// If sync.Pool GCs buffers, cachedBytes becomes stale (overestimates)
	// Periodic reconciliation detects and corrects this drift
	cachedBytes    atomic.Int64 // Expected bytes cached in pools
	lastActivity   atomic.Int64 // UnixNano of last Get/Put (for idle detection)
	reconcileCount atomic.Uint64 // Number of reconciliations performed

	// Limits (bytes)
	softLimit atomic.Int64 // Eviction threshold
	hardLimit atomic.Int64 // Blocking threshold

	// Blocking state
	waiters atomic.Int32 // Number of goroutines blocked waiting

	// Stats - all atomic for lock-free performance
	gets      atomic.Uint64 // Total Get() calls
	hits      atomic.Uint64 // Reused from pool (cache hit)
	misses    atomic.Uint64 // Allocated new (cache miss)
	evictions atomic.Uint64 // Buffers not cached due to pressure
	blocks    atomic.Uint64 // Times allocation had to wait

	// Callback for connection shedding
	onEviction atomic.Pointer[func()]

	// State
	inEviction          atomic.Bool
	lastEvictionTime    atomic.Int64 // UnixNano timestamp of last eviction callback
	evictionRateLimitNs atomic.Int64 // Rate limit in nanoseconds (default 1 second)
	disabled            atomic.Bool

	// Reconciliation control
	reconcileStop chan struct{}
	reconcileOnce sync.Once
}

var globalMemoryBudget *MemoryBudget

func init() {
	globalMemoryBudget = newMemoryBudget()
}

// getEnvCompat checks REALITY_*, XRAY_*, and UTLS_* environment variables for compatibility.
// Priority: REALITY_* > XRAY_* > UTLS_* (first non-empty wins).
func getEnvCompat(key string) string {
	// Check REALITY_ prefix first (this project's naming)
	if val := os.Getenv("REALITY_" + key); val != "" {
		return val
	}
	// Fall back to XRAY_ prefix (for xray-core compatibility)
	if val := os.Getenv("XRAY_" + key); val != "" {
		return val
	}
	// Fall back to UTLS_ prefix (for uTLS compatibility)
	return os.Getenv("UTLS_" + key)
}

// Default eviction rate limit: 1 second in nanoseconds
const defaultEvictionRateLimitNs = 1_000_000_000

func newMemoryBudget() *MemoryBudget {
	mb := &MemoryBudget{}
	mb.evictionRateLimitNs.Store(defaultEvictionRateLimitNs)

	// Check kill switch (supports both REALITY_DISABLE_BUDGET and XRAY_DISABLE_BUDGET)
	if getEnvCompat("DISABLE_BUDGET") == "1" {
		mb.disabled.Store(true)
		mb.softLimit.Store(1 << 62)
		mb.hardLimit.Store(1 << 62)
		return mb
	}

	// Check for manual override via environment (supports both REALITY_* and XRAY_* prefixes)
	softEnv := getEnvCompat("SOFT_LIMIT")
	hardEnv := getEnvCompat("HARD_LIMIT")

	if softEnv != "" && hardEnv != "" {
		softVal, softErr := strconv.ParseInt(softEnv, 10, 64)
		hardVal, hardErr := strconv.ParseInt(hardEnv, 10, 64)

		if softErr == nil && hardErr == nil && softVal > 0 && hardVal > softVal {
			mb.softLimit.Store(softVal)
			mb.hardLimit.Store(hardVal)
			return mb
		}
	}

	// Auto-detect device profile (defaults to client mode for safety)
	// Xray-core should call ConfigureMemory() with explicit client/server config
	profile := getDeviceProfile()
	mb.softLimit.Store(profile.BufferSoftCap)
	mb.hardLimit.Store(profile.BufferHardCap)

	// Log auto-detected profile
	logWarn("auto-detected profile: %s (soft=%dMB, hard=%dMB) - call ConfigureMemory() for explicit config",
		profile.Name, profile.BufferSoftCap/(1024*1024), profile.BufferHardCap/(1024*1024))

	return mb
}

// SetEvictionCallback sets function called when entering eviction state.
// Used to trigger connection shedding.
func (mb *MemoryBudget) SetEvictionCallback(fn func()) {
	// Guard against nil receiver (should never happen with init(), but defensive)
	if mb == nil {
		return
	}
	if fn == nil {
		mb.onEviction.Store(nil)
		return
	}
	// Heap-allocate to ensure pointer survives function return
	fnPtr := new(func())
	*fnPtr = fn
	mb.onEviction.Store(fnPtr)
}

// TryAllocate attempts to allocate size bytes without blocking.
// Call ONLY on cache miss (new memory entering system).
// Returns true if successful, false if would exceed hard limit.
func (mb *MemoryBudget) TryAllocate(size int64) bool {
	if mb == nil {
		return true
	}
	if mb.disabled.Load() || size <= 0 {
		return true
	}

	hard := mb.hardLimit.Load()

	for {
		current := mb.totalBytes.Load()
		if current+size > hard {
			return false
		}
		if mb.totalBytes.CompareAndSwap(current, current+size) {
			mb.inUseBytes.Add(size)
			mb.checkEvictionState(current + size)
			return true
		}
	}
}

// MarkInUse records that a cached buffer is now in use.
// Call on cache hit (no new memory, just moving from cached to in-use).
func (mb *MemoryBudget) MarkInUse(size int64) {
	if mb == nil {
		return
	}
	if mb.disabled.Load() || size <= 0 {
		return
	}
	mb.inUseBytes.Add(size)
	// Buffer came from cache, so decrement cached tracking
	mb.cachedBytes.Add(-size)
}

// RecordGet increments the total Get() counter.
func (mb *MemoryBudget) RecordGet() {
	if mb == nil {
		return
	}
	mb.gets.Add(1)
}

// RecordHit increments the cache hit counter.
func (mb *MemoryBudget) RecordHit() {
	if mb == nil {
		return
	}
	mb.hits.Add(1)
	mb.lastActivity.Store(time.Now().UnixNano())
	// Note: cachedBytes is decremented in MarkInUse when buffer size is known
}

// RecordMiss increments the cache miss counter.
func (mb *MemoryBudget) RecordMiss() {
	if mb == nil {
		return
	}
	mb.misses.Add(1)
	mb.lastActivity.Store(time.Now().UnixNano())
}

// AllocateBlocking blocks until size bytes can be allocated or timeout expires.
// Returns true if allocation succeeded, false on timeout.
func (mb *MemoryBudget) AllocateBlocking(size int64, timeout time.Duration) bool {
	// Fast path
	if mb.TryAllocate(size) {
		return true
	}

	if mb.disabled.Load() {
		return true
	}

	// Slow path - poll until space available or timeout
	mb.blocks.Add(1)
	mb.waiters.Add(1)
	defer mb.waiters.Add(-1)

	deadline := time.Now().Add(timeout)
	const pollInterval = 5 * time.Millisecond

	for {
		time.Sleep(pollInterval)

		if mb.TryAllocate(size) {
			return true
		}

		if time.Now().After(deadline) {
			return false
		}
	}
}

// Release returns size bytes to the budget.
// Returns true if caller should cache the buffer, false if should evict.
func (mb *MemoryBudget) Release(size int64) bool {
	if mb == nil {
		return true
	}
	if mb.disabled.Load() || size <= 0 {
		return true
	}

	mb.inUseBytes.Add(-size)
	mb.lastActivity.Store(time.Now().UnixNano())

	// Use CAS loop to atomically check and decrement
	// This prevents TOCTOU race where stale value causes wrong decision
	soft := mb.softLimit.Load()

	for {
		current := mb.totalBytes.Load()

		if current > soft {
			// Over soft limit - evict (decrement totalBytes)
			newTotal := current - size
			if mb.totalBytes.CompareAndSwap(current, newTotal) {
				// Success - we atomically checked and decremented
				mb.evictions.Add(1)
				mb.checkEvictionState(newTotal)
				return false
			}
			// CAS failed - another thread modified totalBytes
			// Retry with new value (usually succeeds on first try)
		} else {
			// Under soft limit - cache (keep in totalBytes)
			// Track that this buffer is now in cache
			mb.cachedBytes.Add(size)
			return true
		}
	}
}

// ForceEvict forcibly removes size bytes from totalBytes.
// This is used when a buffer is rejected (e.g., grown buffer in PutBuffer default case)
// AFTER Release() was called. Release() decrements inUseBytes but may not decrement
// totalBytes if under soft limit. ForceEvict ensures totalBytes is decremented when
// a buffer is actually leaving the system despite Release() returning true (cache).
func (mb *MemoryBudget) ForceEvict(size int64) {
	if mb == nil {
		return
	}
	if mb.disabled.Load() || size <= 0 {
		return
	}

	// Decrement totalBytes (inUseBytes was already decremented in Release)
	newTotal := mb.totalBytes.Add(-size)
	mb.evictions.Add(1)
	mb.checkEvictionState(newTotal)
}

// checkEvictionState triggers callback when crossing into eviction zone.
//
// IMPORTANT: The inEviction flag represents "are we in eviction mode" and MUST
// stay true while totalBytes > softLimit. This is separate from callback rate limiting.
// The callback fires at most once per rate limit interval, but inEviction reflects the actual state.
func (mb *MemoryBudget) checkEvictionState(current int64) {
	soft := mb.softLimit.Load()
	nowEvicting := current > soft

	if nowEvicting {
		// Use CompareAndSwap to ensure ONLY ONE thread triggers callback
		// Multiple threads crossing soft limit simultaneously will race,
		// but only the CAS winner will launch the callback.
		wasEvicting := mb.inEviction.Load()
		if !wasEvicting && mb.inEviction.CompareAndSwap(false, true) {
			// Entered eviction mode
			logWarn("memory pressure: entered EVICT mode (current=%dKB, soft=%dKB)",
				current/1024, soft/1024)

			// Rate limit callbacks to avoid flooding
			now := time.Now().UnixNano()
			last := mb.lastEvictionTime.Load()
			rateLimit := mb.evictionRateLimitNs.Load()
			if rateLimit == 0 {
				rateLimit = defaultEvictionRateLimitNs
			}
			if now-last > rateLimit {
				mb.lastEvictionTime.Store(now)
				if fn := mb.onEviction.Load(); fn != nil {
					logInfo("triggering eviction callback")
					go (*fn)() // Async to not block allocation
				}
			}
			// Note: inEviction stays true because we ARE in eviction mode.
			// Callback rate limiting is separate from eviction state.
		}
		// If CAS failed, another thread already set inEviction=true
	} else {
		// Dropped below soft limit - exit eviction mode
		wasEvicting := mb.inEviction.Swap(false)
		if wasEvicting {
			logInfo("memory pressure relieved: exited EVICT mode (current=%dKB, soft=%dKB)",
				current/1024, soft/1024)
		}
	}
}

// BudgetState is a snapshot of budget statistics.
type BudgetState struct {
	TotalBytes  int64
	InUseBytes  int64
	CachedBytes int64 // Computed: TotalBytes - InUseBytes
	SoftLimit   int64
	HardLimit   int64
	Waiters     int32
	InEviction  bool
	Disabled    bool

	// Counters
	Gets      uint64
	Hits      uint64
	Misses    uint64
	Evictions uint64
	Blocks    uint64

	// Derived
	HitRate float64 // Hits / Gets * 100

	// Reconciliation stats
	TrackedCachedBytes int64  // Explicitly tracked cached bytes (may drift from CachedBytes)
	ReconcileCount     uint64 // Number of reconciliations performed
	CacheDrift         int64  // TrackedCachedBytes - CachedBytes (positive = overestimate)
}

// State returns current budget state.
func (mb *MemoryBudget) State() BudgetState {
	// Guard against nil receiver - return zero state
	if mb == nil {
		return BudgetState{}
	}

	total := mb.totalBytes.Load()
	inUse := mb.inUseBytes.Load()
	gets := mb.gets.Load()
	hits := mb.hits.Load()
	trackedCached := mb.cachedBytes.Load()

	var hitRate float64
	if gets > 0 {
		hitRate = float64(hits) / float64(gets) * 100
	}

	// Clamp cached bytes to non-negative (negative indicates accounting bug)
	cached := total - inUse
	if cached < 0 {
		cached = 0
	}

	return BudgetState{
		TotalBytes:         total,
		InUseBytes:         inUse,
		CachedBytes:        cached,
		SoftLimit:          mb.softLimit.Load(),
		HardLimit:          mb.hardLimit.Load(),
		Waiters:            mb.waiters.Load(),
		InEviction:         mb.inEviction.Load(),
		Disabled:           mb.disabled.Load(),
		Gets:               gets,
		Hits:               hits,
		Misses:             mb.misses.Load(),
		Evictions:          mb.evictions.Load(),
		Blocks:             mb.blocks.Load(),
		HitRate:            hitRate,
		TrackedCachedBytes: trackedCached,
		ReconcileCount:     mb.reconcileCount.Load(),
		CacheDrift:         trackedCached - cached,
	}
}

// StateName returns "NORMAL", "EVICT", "BLOCK", or "DISABLED".
func (s BudgetState) StateName() string {
	if s.Disabled {
		return "DISABLED"
	}
	if s.Waiters > 0 {
		return "BLOCK"
	}
	if s.InEviction {
		return "EVICT"
	}
	return "NORMAL"
}

// UsagePercent returns usage as percentage of hard limit.
func (s BudgetState) UsagePercent() float64 {
	if s.HardLimit <= 0 {
		return 0
	}
	return float64(s.TotalBytes) / float64(s.HardLimit) * 100
}

// SetLimits allows manual override of limits.
func (mb *MemoryBudget) SetLimits(soft, hard int64) {
	if mb == nil {
		return
	}
	if soft > 0 {
		mb.softLimit.Store(soft)
	}
	if hard > 0 {
		mb.hardLimit.Store(hard)
	}
}

// SetEvictionRateLimit sets the minimum interval between eviction callbacks.
// Default is 1 second. Use shorter values in tests for faster execution.
func (mb *MemoryBudget) SetEvictionRateLimit(d time.Duration) {
	if mb == nil {
		return
	}
	mb.evictionRateLimitNs.Store(d.Nanoseconds())
}

// IsEvicting returns true if in eviction mode.
func (mb *MemoryBudget) IsEvicting() bool {
	if mb == nil {
		return false
	}
	return mb.inEviction.Load()
}

// Available returns bytes available before hard limit.
func (mb *MemoryBudget) Available() int64 {
	if mb == nil {
		return 0
	}
	return mb.hardLimit.Load() - mb.totalBytes.Load()
}

// GetBudget returns the global budget instance.
func GetBudget() *MemoryBudget {
	return globalMemoryBudget
}

// ResetForTest clears all budget counters and returns to normal state.
// This should only be used in tests to ensure test isolation.
// NOT thread-safe - only call from test setup with no concurrent allocations.
func ResetForTest() {
	mb := globalMemoryBudget
	if mb == nil {
		return
	}

	// Clear usage counters
	mb.totalBytes.Store(0)
	mb.inUseBytes.Store(0)
	mb.cachedBytes.Store(0)

	// Clear blocking state
	mb.waiters.Store(0)

	// Clear stats
	mb.gets.Store(0)
	mb.hits.Store(0)
	mb.misses.Store(0)
	mb.evictions.Store(0)
	mb.blocks.Store(0)

	// Clear eviction state
	mb.inEviction.Store(false)
	mb.lastEvictionTime.Store(0)

	// Clear reconciliation state
	mb.lastActivity.Store(0)
	mb.reconcileCount.Store(0)
}

// Reconciliation constants
const (
	// ReconcileInterval is how often we check for drift (30 seconds)
	ReconcileInterval = 30 * time.Second

	// IdleThreshold: if no activity for this long, assume pool may have been GC'd
	IdleThreshold = 60 * time.Second

	// DecayFactor: when idle, decay cachedBytes by this fraction (50%)
	DecayFactor = 0.5

	// DriftThreshold: if cachedBytes differs from expected by more than this, reconcile
	// Expected = totalBytes - inUseBytes
	DriftThreshold = 0.2 // 20% drift tolerance
)

// StartReconciliation starts the background reconciliation goroutine.
// Call once at startup (idempotent - multiple calls are safe).
func StartReconciliation() {
	mb := globalMemoryBudget
	if mb == nil {
		return
	}

	mb.reconcileOnce.Do(func() {
		mb.reconcileStop = make(chan struct{})
		go mb.reconcileLoop()
		logInfo("started periodic reconciliation (interval=%v)", ReconcileInterval)
	})
}

// StopReconciliation stops the background reconciliation goroutine.
// Safe to call even if not started.
func StopReconciliation() {
	mb := globalMemoryBudget
	if mb == nil || mb.reconcileStop == nil {
		return
	}

	select {
	case <-mb.reconcileStop:
		// Already stopped
	default:
		close(mb.reconcileStop)
	}
}

// reconcileLoop runs periodically to detect and correct budget drift.
func (mb *MemoryBudget) reconcileLoop() {
	ticker := time.NewTicker(ReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mb.reconcileStop:
			logInfo("reconciliation stopped")
			return
		case <-ticker.C:
			mb.reconcile()
		}
	}
}

// reconcile checks for and corrects budget drift.
// Two strategies:
// 1. Idle decay: If no activity for IdleThreshold, decay cachedBytes (pool may have been GC'd)
// 2. Drift detection: If cachedBytes drifts significantly from expected, correct it
func (mb *MemoryBudget) reconcile() {
	if mb.disabled.Load() {
		return
	}

	now := time.Now().UnixNano()
	lastAct := mb.lastActivity.Load()
	idleNs := now - lastAct

	// Strategy 1: Idle decay
	// If no activity for > IdleThreshold, pool may have been GC'd
	if idleNs > int64(IdleThreshold) && lastAct > 0 {
		cached := mb.cachedBytes.Load()
		if cached > 0 {
			// Decay cachedBytes and totalBytes by DecayFactor
			decay := int64(float64(cached) * DecayFactor)
			if decay > 0 {
				mb.cachedBytes.Add(-decay)
				mb.totalBytes.Add(-decay)
				mb.reconcileCount.Add(1)
				logDebug("idle decay: reduced cachedBytes by %d bytes (idle for %v)",
					decay, time.Duration(idleNs))
			}
		}
		return
	}

	// Strategy 2: Drift detection
	// If we're getting cache misses when cachedBytes claims we have cached buffers,
	// the pool was GC'd without our knowledge
	total := mb.totalBytes.Load()
	inUse := mb.inUseBytes.Load()
	cached := mb.cachedBytes.Load()

	// Expected cached = total - inUse (what we think should be in pool)
	expectedCached := total - inUse

	// If cachedBytes > expectedCached, we have drift (released more than we thought we had)
	// This shouldn't happen in normal operation, but can occur due to races
	if cached > expectedCached && expectedCached >= 0 {
		drift := cached - expectedCached
		if float64(drift) > float64(expectedCached)*DriftThreshold && expectedCached > 0 {
			// Significant drift - correct it
			mb.cachedBytes.Store(expectedCached)
			mb.reconcileCount.Add(1)
			logDebug("corrected cachedBytes drift: %d -> %d", cached, expectedCached)
		}
	}

	// If cachedBytes < 0 (shouldn't happen), reset to 0
	if cached < 0 {
		mb.cachedBytes.Store(0)
		mb.reconcileCount.Add(1)
		logWarn("cachedBytes was negative (%d), reset to 0", cached)
	}
}

// DeviceProfile contains resource limits for a device class.
type DeviceProfile struct {
	Name          string
	BufferSoftCap int64
	BufferHardCap int64
}

// getDeviceProfile auto-detects device class based on RAM.
// CONSERVATIVE: Assumes client mode (tighter limits) for safety.
// Xray-core should use ConfigureMemory() with explicit client/server config.
func getDeviceProfile() DeviceProfile {
	totalMem := getTotalSystemMemory()
	const MB = 1024 * 1024

	// If can't detect RAM, assume constrained client device
	if totalMem == 0 {
		return DeviceProfile{"unknown_client", 5 * MB, 8 * MB}
	}

	// Conservative profiles (assume client mode)
	switch {
	case totalMem <= 32*MB:
		return DeviceProfile{"tiny_router", 2 * MB, 3 * MB}
	case totalMem <= 64*MB:
		return DeviceProfile{"small_router", 5 * MB, 8 * MB}
	case totalMem <= 128*MB:
		return DeviceProfile{"medium_router", 8 * MB, 12 * MB}
	case totalMem <= 512*MB:
		return DeviceProfile{"mobile_client", 10 * MB, 16 * MB}
	case totalMem <= 1024*MB:
		return DeviceProfile{"desktop_client", 16 * MB, 24 * MB}
	case totalMem <= 2048*MB:
		return DeviceProfile{"desktop_client_large", 24 * MB, 32 * MB}
	default:
		// Even on big machines, default to client mode (conservative)
		// Server should explicitly call ConfigureMemory(ServerConfig())
		return DeviceProfile{"client_default", 32 * MB, 48 * MB}
	}
}

// ============================================================================
// GLOBAL BUDGET ACCESS FUNCTIONS
// ============================================================================
// These functions provide unified access to the effective budget.
// When an external budget is set (via UseExternalBudget), all operations
// delegate to it. Otherwise, they use the internal globalMemoryBudget.
//
// This allows Xray-core to provide ONE global budget that tracks memory
// across ALL subsystems (Xray buffers, TLS buffers, REALITY buffers).

// BudgetTryAllocate attempts to allocate size bytes.
// Uses external budget if set, otherwise internal.
func BudgetTryAllocate(size int64) bool {
	if ext := getExternalBudget(); ext != nil {
		return ext.TryAllocate(size)
	}
	if globalMemoryBudget == nil {
		return true // No budget configured, allow allocation
	}
	return globalMemoryBudget.TryAllocate(size)
}

// BudgetRelease returns size bytes to the budget.
// Uses external budget if set, otherwise internal.
func BudgetRelease(size int64) bool {
	if ext := getExternalBudget(); ext != nil {
		return ext.Release(size)
	}
	if globalMemoryBudget == nil {
		return true // No budget configured, allow caching
	}
	return globalMemoryBudget.Release(size)
}

// BudgetMarkInUse records a cached buffer as in-use.
// Uses external budget if set, otherwise internal.
func BudgetMarkInUse(size int64) {
	if ext := getExternalBudget(); ext != nil {
		ext.MarkInUse(size)
		return
	}
	if globalMemoryBudget == nil {
		return
	}
	globalMemoryBudget.MarkInUse(size)
}

// BudgetForceEvict forcibly removes bytes from tracking.
// Uses external budget if set, otherwise internal.
func BudgetForceEvict(size int64) {
	if ext := getExternalBudget(); ext != nil {
		ext.ForceEvict(size)
		return
	}
	if globalMemoryBudget == nil {
		return
	}
	globalMemoryBudget.ForceEvict(size)
}

// BudgetIsEvicting returns true if in eviction mode.
// Uses external budget if set, otherwise internal.
func BudgetIsEvicting() bool {
	if ext := getExternalBudget(); ext != nil {
		return ext.IsEvicting()
	}
	if globalMemoryBudget == nil {
		return false
	}
	return globalMemoryBudget.IsEvicting()
}

// BudgetRecordGet increments allocation counter.
// Uses external budget if set, otherwise internal.
func BudgetRecordGet() {
	if ext := getExternalBudget(); ext != nil {
		ext.RecordGet()
		return
	}
	if globalMemoryBudget == nil {
		return
	}
	globalMemoryBudget.RecordGet()
}

// BudgetRecordHit increments cache hit counter.
// Uses external budget if set, otherwise internal.
func BudgetRecordHit() {
	if ext := getExternalBudget(); ext != nil {
		ext.RecordHit()
		return
	}
	if globalMemoryBudget == nil {
		return
	}
	globalMemoryBudget.RecordHit()
}

// BudgetRecordMiss increments cache miss counter.
// Uses external budget if set, otherwise internal.
func BudgetRecordMiss() {
	if ext := getExternalBudget(); ext != nil {
		ext.RecordMiss()
		return
	}
	if globalMemoryBudget == nil {
		return
	}
	globalMemoryBudget.RecordMiss()
}

// SetGlobalEvictionCallback sets the eviction callback.
// Uses external budget if set, otherwise internal.
func SetGlobalEvictionCallback(fn func()) {
	if ext := getExternalBudget(); ext != nil {
		ext.SetEvictionCallback(fn)
		return
	}
	if globalMemoryBudget == nil {
		return
	}
	globalMemoryBudget.SetEvictionCallback(fn)
}
