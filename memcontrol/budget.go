// Package memcontrol provides memory-aware resource management for uTLS.
//
// This is adapted from Xray-core's common/buf memory budget system,
// simplified for uTLS's needs as a TLS fingerprinting library.
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
	inEviction       atomic.Bool
	lastEvictionTime atomic.Int64 // UnixNano timestamp of last eviction callback
	disabled         atomic.Bool
}

var globalMemoryBudget *MemoryBudget

func init() {
	globalMemoryBudget = newMemoryBudget()
}

// getEnv returns the value of UTLS_<key> environment variable.
func getEnv(key string) string {
	return os.Getenv("UTLS_" + key)
}

func newMemoryBudget() *MemoryBudget {
	mb := &MemoryBudget{}

	// Check kill switch via UTLS_DISABLE_BUDGET=1
	if getEnv("DISABLE_BUDGET") == "1" {
		mb.disabled.Store(true)
		mb.softLimit.Store(1 << 62)
		mb.hardLimit.Store(1 << 62)
		return mb
	}

	// Check for manual override via environment (UTLS_SOFT_LIMIT, UTLS_HARD_LIMIT)
	softEnv := getEnv("SOFT_LIMIT")
	hardEnv := getEnv("HARD_LIMIT")

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
	// Applications should call ConfigureMemory() with explicit client/server config
	profile := getDeviceProfile()
	mb.softLimit.Store(profile.BufferSoftCap)
	mb.hardLimit.Store(profile.BufferHardCap)

	// Log auto-detected profile
	logInfo("auto-detected profile: %s (soft=%dMB, hard=%dMB)",
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
}

// RecordMiss increments the cache miss counter.
func (mb *MemoryBudget) RecordMiss() {
	if mb == nil {
		return
	}
	mb.misses.Add(1)
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
			// No CAS needed here - just returning decision
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
// The callback fires at most once per second, but inEviction reflects the actual state.
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

			// Rate limit callbacks to 1 per second
			now := time.Now().UnixNano()
			last := mb.lastEvictionTime.Load()
			if now-last > 1_000_000_000 { // 1 second in nanoseconds
				mb.lastEvictionTime.Store(now)
				if fn := mb.onEviction.Load(); fn != nil {
					logInfo("triggering eviction callback")
					go (*fn)() // Async to not block allocation
				}
			}
			// Note: inEviction stays true because we ARE in eviction mode.
			// Callback rate limiting is separate from eviction state.
		}
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
	CachedBytes int64
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
		TotalBytes:  total,
		InUseBytes:  inUse,
		CachedBytes: cached,
		SoftLimit:   mb.softLimit.Load(),
		HardLimit:   mb.hardLimit.Load(),
		Waiters:     mb.waiters.Load(),
		InEviction:  mb.inEviction.Load(),
		Disabled:    mb.disabled.Load(),
		Gets:        gets,
		Hits:        hits,
		Misses:      mb.misses.Load(),
		Evictions:   mb.evictions.Load(),
		Blocks:      mb.blocks.Load(),
		HitRate:     hitRate,
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

// DeviceProfile contains resource limits for a device class.
type DeviceProfile struct {
	Name          string
	BufferSoftCap int64
	BufferHardCap int64
}

// getDeviceProfile auto-detects device class based on RAM.
// CONSERVATIVE: Assumes client mode (tighter limits) for safety.
// Applications should use ConfigureMemory() with explicit client/server config.
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
	return globalMemoryBudget.TryAllocate(size)
}

// BudgetRelease returns size bytes to the budget.
// Uses external budget if set, otherwise internal.
func BudgetRelease(size int64) bool {
	if ext := getExternalBudget(); ext != nil {
		return ext.Release(size)
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
	globalMemoryBudget.MarkInUse(size)
}

// BudgetForceEvict forcibly removes bytes from tracking.
// Uses external budget if set, otherwise internal.
func BudgetForceEvict(size int64) {
	if ext := getExternalBudget(); ext != nil {
		ext.ForceEvict(size)
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
	return globalMemoryBudget.IsEvicting()
}

// BudgetRecordGet increments allocation counter.
// Uses external budget if set, otherwise internal.
func BudgetRecordGet() {
	if ext := getExternalBudget(); ext != nil {
		ext.RecordGet()
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
	globalMemoryBudget.RecordHit()
}

// BudgetRecordMiss increments cache miss counter.
// Uses external budget if set, otherwise internal.
func BudgetRecordMiss() {
	if ext := getExternalBudget(); ext != nil {
		ext.RecordMiss()
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
	globalMemoryBudget.SetEvictionCallback(fn)
}
