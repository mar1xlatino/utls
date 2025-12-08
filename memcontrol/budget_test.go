package memcontrol

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	SetLogLevel(LogLevelOff)
}

// newTestBudget creates a fresh MemoryBudget for testing (not the global singleton).
func newTestBudget(soft, hard int64) *MemoryBudget {
	mb := &MemoryBudget{}
	mb.softLimit.Store(soft)
	mb.hardLimit.Store(hard)
	mb.evictionRateLimitNs.Store(defaultEvictionRateLimitNs) // Default 1 second
	return mb
}

// TestBudgetBasicAllocation verifies TryAllocate succeeds within limits and fails at hard limit.
func TestBudgetBasicAllocation(t *testing.T) {
	const (
		softLimit = 1000
		hardLimit = 2000
	)
	mb := newTestBudget(softLimit, hardLimit)

	// Allocation within limits should succeed
	if !mb.TryAllocate(500) {
		t.Error("TryAllocate(500) should succeed when under soft limit")
	}

	state := mb.State()
	if state.TotalBytes != 500 {
		t.Errorf("TotalBytes = %d, want 500", state.TotalBytes)
	}
	if state.InUseBytes != 500 {
		t.Errorf("InUseBytes = %d, want 500", state.InUseBytes)
	}

	// Allocate up to just under hard limit
	if !mb.TryAllocate(1400) {
		t.Error("TryAllocate(1400) should succeed when under hard limit")
	}

	state = mb.State()
	if state.TotalBytes != 1900 {
		t.Errorf("TotalBytes = %d, want 1900", state.TotalBytes)
	}

	// Allocation that would exceed hard limit should fail
	if mb.TryAllocate(200) {
		t.Error("TryAllocate(200) should fail when it would exceed hard limit (1900 + 200 > 2000)")
	}

	// TotalBytes should not have changed after failed allocation
	state = mb.State()
	if state.TotalBytes != 1900 {
		t.Errorf("TotalBytes = %d after failed alloc, want 1900 (unchanged)", state.TotalBytes)
	}

	// Allocation at exact remaining space should succeed
	if !mb.TryAllocate(100) {
		t.Error("TryAllocate(100) should succeed at exactly hard limit")
	}

	state = mb.State()
	if state.TotalBytes != 2000 {
		t.Errorf("TotalBytes = %d, want 2000 (at hard limit)", state.TotalBytes)
	}

	// Any further allocation should fail
	if mb.TryAllocate(1) {
		t.Error("TryAllocate(1) should fail when at hard limit")
	}
}

// TestBudgetZeroAndNegativeAllocation verifies edge cases with zero and negative sizes.
func TestBudgetZeroAndNegativeAllocation(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Zero allocation should succeed without changing counters
	if !mb.TryAllocate(0) {
		t.Error("TryAllocate(0) should always succeed")
	}

	state := mb.State()
	if state.TotalBytes != 0 {
		t.Errorf("TotalBytes = %d after zero alloc, want 0", state.TotalBytes)
	}

	// Negative allocation should succeed without changing counters
	if !mb.TryAllocate(-100) {
		t.Error("TryAllocate(-100) should succeed (ignored)")
	}

	state = mb.State()
	if state.TotalBytes != 0 {
		t.Errorf("TotalBytes = %d after negative alloc, want 0", state.TotalBytes)
	}
}

// TestBudgetRelease verifies Release returns true (cache) under soft limit, false (evict) over soft limit.
func TestBudgetRelease(t *testing.T) {
	const (
		softLimit = 1000
		hardLimit = 2000
	)
	mb := newTestBudget(softLimit, hardLimit)

	// Allocate memory under soft limit
	mb.TryAllocate(800)

	// Release under soft limit should return true (cache the buffer)
	shouldCache := mb.Release(400)
	if !shouldCache {
		t.Error("Release(400) should return true (cache) when under soft limit")
	}

	state := mb.State()
	// TotalBytes should NOT decrease when caching (still 800)
	if state.TotalBytes != 800 {
		t.Errorf("TotalBytes = %d after cache release, want 800", state.TotalBytes)
	}
	// InUseBytes should decrease
	if state.InUseBytes != 400 {
		t.Errorf("InUseBytes = %d after release, want 400", state.InUseBytes)
	}

	// Now allocate to go over soft limit
	mb.TryAllocate(600) // Total now 1400, InUse now 1000

	// Release over soft limit should return false (evict the buffer)
	shouldCache = mb.Release(200)
	if shouldCache {
		t.Error("Release(200) should return false (evict) when over soft limit")
	}

	state = mb.State()
	// TotalBytes should decrease when evicting
	if state.TotalBytes != 1200 {
		t.Errorf("TotalBytes = %d after evict release, want 1200 (1400 - 200)", state.TotalBytes)
	}
	// InUseBytes should also decrease
	if state.InUseBytes != 800 {
		t.Errorf("InUseBytes = %d after release, want 800 (1000 - 200)", state.InUseBytes)
	}

	// Evictions counter should increment
	if state.Evictions != 1 {
		t.Errorf("Evictions = %d, want 1", state.Evictions)
	}
}

// TestBudgetReleaseZeroAndNegative verifies edge cases for Release.
func TestBudgetReleaseZeroAndNegative(t *testing.T) {
	mb := newTestBudget(1000, 2000)
	mb.TryAllocate(500)

	// Zero release should succeed and return true (cache)
	if !mb.Release(0) {
		t.Error("Release(0) should return true")
	}

	// Negative release should succeed and return true (cache)
	if !mb.Release(-100) {
		t.Error("Release(-100) should return true")
	}

	// State should be unchanged
	state := mb.State()
	if state.TotalBytes != 500 || state.InUseBytes != 500 {
		t.Errorf("State changed after zero/negative release: Total=%d, InUse=%d", state.TotalBytes, state.InUseBytes)
	}
}

// TestBudgetEvictionMode verifies entering and exiting eviction mode at soft limit boundary.
func TestBudgetEvictionMode(t *testing.T) {
	const (
		softLimit = 1000
		hardLimit = 2000
	)
	mb := newTestBudget(softLimit, hardLimit)

	// Initially not in eviction mode
	if mb.IsEvicting() {
		t.Error("Should not be in eviction mode initially")
	}

	// Allocate under soft limit - should still not be evicting
	mb.TryAllocate(800)
	if mb.IsEvicting() {
		t.Error("Should not be in eviction mode when under soft limit")
	}

	// Allocate to cross soft limit
	mb.TryAllocate(400) // Total now 1200 > soft limit of 1000
	if !mb.IsEvicting() {
		t.Error("Should be in eviction mode after crossing soft limit")
	}

	state := mb.State()
	if !state.InEviction {
		t.Error("State.InEviction should be true")
	}

	// Release enough to drop below soft limit
	mb.Release(300) // Evicts, Total becomes 900 < soft limit

	// Should exit eviction mode
	if mb.IsEvicting() {
		t.Error("Should exit eviction mode after dropping below soft limit")
	}
}

// TestBudgetEvictionCallback verifies callback fires when entering eviction and is rate-limited.
func TestBudgetEvictionCallback(t *testing.T) {
	const (
		softLimit = 1000
		hardLimit = 2000
		// Use shorter rate limit for tests (50ms instead of 1s)
		testRateLimit = 50 * time.Millisecond
	)
	mb := newTestBudget(softLimit, hardLimit)
	mb.SetEvictionRateLimit(testRateLimit) // Override for fast test

	var callCount atomic.Int32

	mb.SetEvictionCallback(func() {
		callCount.Add(1)
	})

	// Cross soft limit to trigger callback
	mb.TryAllocate(1100)

	// Give async callback time to execute
	time.Sleep(10 * time.Millisecond)

	if callCount.Load() != 1 {
		t.Errorf("Eviction callback should fire once, got %d", callCount.Load())
	}

	// Exit and re-enter eviction immediately (within rate limit)
	mb.Release(200) // Exit eviction (Total = 900)
	if mb.IsEvicting() {
		t.Fatal("Should have exited eviction mode")
	}

	mb.TryAllocate(200) // Re-enter eviction (Total = 1100)
	if !mb.IsEvicting() {
		t.Fatal("Should have re-entered eviction mode")
	}

	time.Sleep(10 * time.Millisecond)

	// Callback should NOT fire again due to rate limiting
	if callCount.Load() != 1 {
		t.Errorf("Eviction callback should still be 1 (rate limited), got %d", callCount.Load())
	}

	// Wait for rate limit to expire and trigger again
	time.Sleep(60 * time.Millisecond) // 50ms rate limit + 10ms buffer

	// Exit and re-enter to trigger again
	mb.Release(200) // Exit eviction
	mb.TryAllocate(200) // Re-enter eviction

	time.Sleep(10 * time.Millisecond)

	if callCount.Load() != 2 {
		t.Errorf("Eviction callback should fire again after rate limit expires, got %d", callCount.Load())
	}
}

// TestBudgetEvictionCallbackNil verifies nil callback is handled gracefully.
func TestBudgetEvictionCallbackNil(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Set nil callback should not panic
	mb.SetEvictionCallback(nil)

	// Trigger eviction mode - should not panic
	mb.TryAllocate(1100)

	if !mb.IsEvicting() {
		t.Error("Should be in eviction mode")
	}
}

// TestBudgetMarkInUse verifies InUse tracking for cache hits.
func TestBudgetMarkInUse(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Allocate and release to simulate cached buffer
	mb.TryAllocate(500)
	mb.Release(500) // Caches buffer (TotalBytes=500, InUseBytes=0)

	state := mb.State()
	if state.TotalBytes != 500 {
		t.Errorf("TotalBytes = %d, want 500", state.TotalBytes)
	}
	if state.InUseBytes != 0 {
		t.Errorf("InUseBytes = %d, want 0", state.InUseBytes)
	}
	if state.CachedBytes != 500 {
		t.Errorf("CachedBytes = %d, want 500", state.CachedBytes)
	}

	// Mark as in use (cache hit)
	mb.MarkInUse(500)

	state = mb.State()
	if state.TotalBytes != 500 {
		t.Errorf("TotalBytes = %d, want 500 (unchanged)", state.TotalBytes)
	}
	if state.InUseBytes != 500 {
		t.Errorf("InUseBytes = %d, want 500", state.InUseBytes)
	}
	if state.CachedBytes != 0 {
		t.Errorf("CachedBytes = %d, want 0", state.CachedBytes)
	}
}

// TestBudgetMarkInUseZeroAndNegative verifies edge cases for MarkInUse.
func TestBudgetMarkInUseZeroAndNegative(t *testing.T) {
	mb := newTestBudget(1000, 2000)
	mb.TryAllocate(500)
	mb.Release(500)

	initialState := mb.State()

	// Zero should be ignored
	mb.MarkInUse(0)
	state := mb.State()
	if state.InUseBytes != initialState.InUseBytes {
		t.Error("MarkInUse(0) should not change InUseBytes")
	}

	// Negative should be ignored
	mb.MarkInUse(-100)
	state = mb.State()
	if state.InUseBytes != initialState.InUseBytes {
		t.Error("MarkInUse(-100) should not change InUseBytes")
	}
}

// TestBudgetForceEvict verifies ForceEvict decrements totalBytes.
func TestBudgetForceEvict(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Allocate and release (caches under soft limit)
	mb.TryAllocate(500)
	mb.Release(500) // TotalBytes=500, InUseBytes=0

	state := mb.State()
	if state.TotalBytes != 500 {
		t.Errorf("TotalBytes = %d before ForceEvict, want 500", state.TotalBytes)
	}

	// Force evict the cached buffer
	mb.ForceEvict(500)

	state = mb.State()
	if state.TotalBytes != 0 {
		t.Errorf("TotalBytes = %d after ForceEvict, want 0", state.TotalBytes)
	}
	if state.Evictions != 1 {
		t.Errorf("Evictions = %d, want 1", state.Evictions)
	}
}

// TestBudgetForceEvictZeroAndNegative verifies edge cases for ForceEvict.
func TestBudgetForceEvictZeroAndNegative(t *testing.T) {
	mb := newTestBudget(1000, 2000)
	mb.TryAllocate(500)

	// Zero should be ignored
	mb.ForceEvict(0)
	state := mb.State()
	if state.TotalBytes != 500 {
		t.Error("ForceEvict(0) should not change TotalBytes")
	}

	// Negative should be ignored
	mb.ForceEvict(-100)
	state = mb.State()
	if state.TotalBytes != 500 {
		t.Error("ForceEvict(-100) should not change TotalBytes")
	}
}

// TestBudgetState verifies State() returns correct snapshot.
func TestBudgetState(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Set up state
	mb.TryAllocate(600)
	mb.Release(200) // Cache 200 (TotalBytes=600, InUseBytes=400)
	mb.RecordGet()
	mb.RecordGet()
	mb.RecordGet()
	mb.RecordHit()
	mb.RecordMiss()
	mb.RecordMiss()

	state := mb.State()

	if state.TotalBytes != 600 {
		t.Errorf("TotalBytes = %d, want 600", state.TotalBytes)
	}
	if state.InUseBytes != 400 {
		t.Errorf("InUseBytes = %d, want 400", state.InUseBytes)
	}
	if state.CachedBytes != 200 {
		t.Errorf("CachedBytes = %d, want 200", state.CachedBytes)
	}
	if state.SoftLimit != 1000 {
		t.Errorf("SoftLimit = %d, want 1000", state.SoftLimit)
	}
	if state.HardLimit != 2000 {
		t.Errorf("HardLimit = %d, want 2000", state.HardLimit)
	}
	if state.Gets != 3 {
		t.Errorf("Gets = %d, want 3", state.Gets)
	}
	if state.Hits != 1 {
		t.Errorf("Hits = %d, want 1", state.Hits)
	}
	if state.Misses != 2 {
		t.Errorf("Misses = %d, want 2", state.Misses)
	}
	if state.InEviction {
		t.Error("InEviction should be false (we're under soft limit)")
	}
	if state.Disabled {
		t.Error("Disabled should be false")
	}

	// Hit rate: 1/3 * 100 = 33.33...
	expectedHitRate := float64(1) / float64(3) * 100
	if state.HitRate != expectedHitRate {
		t.Errorf("HitRate = %f, want %f", state.HitRate, expectedHitRate)
	}
}

// TestBudgetStateName verifies StateName() returns correct state names.
func TestBudgetStateName(t *testing.T) {
	tests := []struct {
		name     string
		state    BudgetState
		expected string
	}{
		{
			name:     "DISABLED",
			state:    BudgetState{Disabled: true},
			expected: "DISABLED",
		},
		{
			name:     "BLOCK",
			state:    BudgetState{Waiters: 1},
			expected: "BLOCK",
		},
		{
			name:     "EVICT",
			state:    BudgetState{InEviction: true},
			expected: "EVICT",
		},
		{
			name:     "NORMAL",
			state:    BudgetState{},
			expected: "NORMAL",
		},
		{
			name:     "DISABLED takes priority over BLOCK",
			state:    BudgetState{Disabled: true, Waiters: 1},
			expected: "DISABLED",
		},
		{
			name:     "BLOCK takes priority over EVICT",
			state:    BudgetState{Waiters: 1, InEviction: true},
			expected: "BLOCK",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.state.StateName()
			if got != tc.expected {
				t.Errorf("StateName() = %q, want %q", got, tc.expected)
			}
		})
	}
}

// TestBudgetUsagePercent verifies UsagePercent calculation.
func TestBudgetUsagePercent(t *testing.T) {
	tests := []struct {
		name       string
		state      BudgetState
		expected   float64
	}{
		{
			name:     "50% usage",
			state:    BudgetState{TotalBytes: 500, HardLimit: 1000},
			expected: 50.0,
		},
		{
			name:     "100% usage",
			state:    BudgetState{TotalBytes: 1000, HardLimit: 1000},
			expected: 100.0,
		},
		{
			name:     "0% usage",
			state:    BudgetState{TotalBytes: 0, HardLimit: 1000},
			expected: 0.0,
		},
		{
			name:     "Zero hard limit",
			state:    BudgetState{TotalBytes: 500, HardLimit: 0},
			expected: 0.0,
		},
		{
			name:     "Negative hard limit",
			state:    BudgetState{TotalBytes: 500, HardLimit: -1000},
			expected: 0.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.state.UsagePercent()
			if got != tc.expected {
				t.Errorf("UsagePercent() = %f, want %f", got, tc.expected)
			}
		})
	}
}

// TestBudgetConcurrent verifies concurrent allocations don't corrupt counters.
func TestBudgetConcurrent(t *testing.T) {
	const (
		softLimit     = 100000
		hardLimit     = 200000
		numGoroutines = 100
		opsPerRoutine = 1000
		allocSize     = 10
	)

	mb := newTestBudget(softLimit, hardLimit)

	var wg sync.WaitGroup
	var successfulAllocs atomic.Int64
	var successfulReleases atomic.Int64

	// Run concurrent allocations and releases
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerRoutine; j++ {
				if mb.TryAllocate(allocSize) {
					successfulAllocs.Add(1)
					// Immediately release to keep within limits
					if mb.Release(allocSize) {
						successfulReleases.Add(1)
					}
				}
				// Yield to create more interleaving
				runtime.Gosched()
			}
		}()
	}

	wg.Wait()

	state := mb.State()

	// Verify counters are non-negative
	if state.TotalBytes < 0 {
		t.Errorf("TotalBytes = %d, should be non-negative", state.TotalBytes)
	}
	if state.InUseBytes < 0 {
		t.Errorf("InUseBytes = %d, should be non-negative", state.InUseBytes)
	}

	// We released everything, so TotalBytes should equal cached amount
	// InUseBytes should be 0 since we released everything we allocated
	if state.InUseBytes != 0 {
		t.Errorf("InUseBytes = %d, want 0 (all released)", state.InUseBytes)
	}

	t.Logf("Concurrent test: %d successful allocs, %d successful releases, final TotalBytes=%d",
		successfulAllocs.Load(), successfulReleases.Load(), state.TotalBytes)
}

// TestBudgetConcurrentContention verifies behavior under high contention at hard limit.
func TestBudgetConcurrentContention(t *testing.T) {
	const (
		softLimit     = 500
		hardLimit     = 1000
		numGoroutines = 50
		allocSize     = 100
	)

	mb := newTestBudget(softLimit, hardLimit)

	// Pre-fill to near hard limit
	mb.TryAllocate(900)

	var wg sync.WaitGroup
	var successes atomic.Int64
	var failures atomic.Int64

	// Many goroutines try to allocate the last 100 bytes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if mb.TryAllocate(allocSize) {
				successes.Add(1)
				// Hold briefly then release
				time.Sleep(time.Microsecond)
				mb.Release(allocSize)
			} else {
				failures.Add(1)
			}
		}()
	}

	wg.Wait()

	// At most one should succeed initially (only 100 bytes available)
	// But since we release, multiple can succeed over time
	t.Logf("Contention test: %d successes, %d failures", successes.Load(), failures.Load())

	// Verify no corruption
	state := mb.State()
	if state.TotalBytes < 0 || state.InUseBytes < 0 {
		t.Errorf("Negative counters: TotalBytes=%d, InUseBytes=%d", state.TotalBytes, state.InUseBytes)
	}
}

// TestBudgetNilSafe verifies all methods handle nil receiver gracefully.
func TestBudgetNilSafe(t *testing.T) {
	var mb *MemoryBudget = nil

	// These should all not panic
	if !mb.TryAllocate(100) {
		t.Error("nil.TryAllocate should return true")
	}

	if !mb.Release(100) {
		t.Error("nil.Release should return true")
	}

	mb.MarkInUse(100)
	mb.ForceEvict(100)
	mb.RecordGet()
	mb.RecordHit()
	mb.RecordMiss()
	mb.SetEvictionCallback(func() {})
	mb.SetLimits(1000, 2000)

	if mb.IsEvicting() {
		t.Error("nil.IsEvicting should return false")
	}

	if mb.Available() != 0 {
		t.Errorf("nil.Available = %d, want 0", mb.Available())
	}

	state := mb.State()
	if state.TotalBytes != 0 || state.SoftLimit != 0 || state.HardLimit != 0 {
		t.Errorf("nil.State() should return zero state, got: %+v", state)
	}
}

// TestBudgetDisabled verifies disabled budget allows unlimited allocation.
func TestBudgetDisabled(t *testing.T) {
	mb := &MemoryBudget{}
	mb.disabled.Store(true)
	mb.softLimit.Store(100)
	mb.hardLimit.Store(200)

	// Should succeed despite exceeding limits
	if !mb.TryAllocate(10000) {
		t.Error("Disabled budget should allow unlimited TryAllocate")
	}

	// Counters should not change when disabled
	state := mb.State()
	if state.TotalBytes != 0 {
		t.Errorf("Disabled budget TotalBytes = %d, want 0", state.TotalBytes)
	}

	// Release should return true when disabled
	if !mb.Release(10000) {
		t.Error("Disabled budget Release should return true")
	}

	// MarkInUse should be no-op when disabled
	mb.MarkInUse(10000)
	state = mb.State()
	if state.InUseBytes != 0 {
		t.Errorf("Disabled budget InUseBytes = %d, want 0", state.InUseBytes)
	}

	// ForceEvict should be no-op when disabled
	mb.ForceEvict(10000)
	state = mb.State()
	if state.TotalBytes != 0 {
		t.Errorf("Disabled budget TotalBytes after ForceEvict = %d, want 0", state.TotalBytes)
	}

	// State should show disabled
	if !state.Disabled {
		t.Error("State.Disabled should be true")
	}
	if state.StateName() != "DISABLED" {
		t.Errorf("StateName = %q, want DISABLED", state.StateName())
	}
}

// TestBudgetHitMissCounters verifies RecordGet/Hit/Miss update stats correctly.
func TestBudgetHitMissCounters(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Record operations
	for i := 0; i < 10; i++ {
		mb.RecordGet()
	}
	for i := 0; i < 7; i++ {
		mb.RecordHit()
	}
	for i := 0; i < 3; i++ {
		mb.RecordMiss()
	}

	state := mb.State()

	if state.Gets != 10 {
		t.Errorf("Gets = %d, want 10", state.Gets)
	}
	if state.Hits != 7 {
		t.Errorf("Hits = %d, want 7", state.Hits)
	}
	if state.Misses != 3 {
		t.Errorf("Misses = %d, want 3", state.Misses)
	}

	// Verify hit rate calculation: 7/10 * 100 = 70%
	if state.HitRate != 70.0 {
		t.Errorf("HitRate = %f, want 70.0", state.HitRate)
	}
}

// TestBudgetHitRateZeroGets verifies hit rate is 0 when no gets.
func TestBudgetHitRateZeroGets(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Record hits without gets (edge case)
	mb.RecordHit()
	mb.RecordHit()

	state := mb.State()

	// With 0 gets, hit rate should be 0 (not NaN or panic)
	if state.HitRate != 0 {
		t.Errorf("HitRate with 0 gets = %f, want 0", state.HitRate)
	}
}

// TestBudgetSetLimits verifies SetLimits updates limits correctly.
func TestBudgetSetLimits(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Update both limits
	mb.SetLimits(500, 1000)

	state := mb.State()
	if state.SoftLimit != 500 {
		t.Errorf("SoftLimit = %d, want 500", state.SoftLimit)
	}
	if state.HardLimit != 1000 {
		t.Errorf("HardLimit = %d, want 1000", state.HardLimit)
	}

	// Update only soft limit (pass 0 for hard)
	mb.SetLimits(250, 0)
	state = mb.State()
	if state.SoftLimit != 250 {
		t.Errorf("SoftLimit = %d, want 250", state.SoftLimit)
	}
	if state.HardLimit != 1000 {
		t.Errorf("HardLimit = %d, want 1000 (unchanged)", state.HardLimit)
	}

	// Update only hard limit (pass 0 for soft)
	mb.SetLimits(0, 500)
	state = mb.State()
	if state.SoftLimit != 250 {
		t.Errorf("SoftLimit = %d, want 250 (unchanged)", state.SoftLimit)
	}
	if state.HardLimit != 500 {
		t.Errorf("HardLimit = %d, want 500", state.HardLimit)
	}

	// Negative values should be ignored
	mb.SetLimits(-100, -200)
	state = mb.State()
	if state.SoftLimit != 250 {
		t.Errorf("SoftLimit = %d after negative, want 250 (unchanged)", state.SoftLimit)
	}
	if state.HardLimit != 500 {
		t.Errorf("HardLimit = %d after negative, want 500 (unchanged)", state.HardLimit)
	}
}

// TestBudgetCachedBytesNonNegative verifies CachedBytes is clamped to 0 if negative.
func TestBudgetCachedBytesNonNegative(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Artificially create a situation where InUseBytes > TotalBytes
	// This shouldn't happen in normal operation but tests the clamping
	mb.TryAllocate(100)          // TotalBytes=100, InUseBytes=100
	mb.inUseBytes.Store(200)     // Force InUseBytes > TotalBytes

	state := mb.State()

	// CachedBytes should be clamped to 0, not negative
	if state.CachedBytes < 0 {
		t.Errorf("CachedBytes = %d, should be clamped to 0", state.CachedBytes)
	}
	if state.CachedBytes != 0 {
		t.Errorf("CachedBytes = %d, want 0 (clamped)", state.CachedBytes)
	}
}

// TestBudgetAvailable verifies Available() calculation.
func TestBudgetAvailable(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Initially all available
	if avail := mb.Available(); avail != 2000 {
		t.Errorf("Available = %d, want 2000", avail)
	}

	// Allocate some
	mb.TryAllocate(500)
	if avail := mb.Available(); avail != 1500 {
		t.Errorf("Available = %d, want 1500", avail)
	}

	// At hard limit
	mb.TryAllocate(1500)
	if avail := mb.Available(); avail != 0 {
		t.Errorf("Available = %d, want 0", avail)
	}
}

// TestBudgetAllocateBlocking verifies blocking allocation with timeout.
func TestBudgetAllocateBlocking(t *testing.T) {
	mb := newTestBudget(100, 200)

	// Fill to hard limit
	mb.TryAllocate(200)

	// Blocking allocation should timeout
	start := time.Now()
	success := mb.AllocateBlocking(50, 50*time.Millisecond)
	elapsed := time.Since(start)

	if success {
		t.Error("AllocateBlocking should fail on timeout")
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("AllocateBlocking returned too quickly: %v", elapsed)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("AllocateBlocking took too long: %v", elapsed)
	}

	// Verify blocks counter incremented
	state := mb.State()
	if state.Blocks != 1 {
		t.Errorf("Blocks = %d, want 1", state.Blocks)
	}

	// Release some space and try blocking allocation again
	go func() {
		time.Sleep(20 * time.Millisecond)
		mb.Release(100) // Make space available
	}()

	success = mb.AllocateBlocking(50, 100*time.Millisecond)
	if !success {
		t.Error("AllocateBlocking should succeed when space becomes available")
	}
}

// TestBudgetAllocateBlockingFastPath verifies blocking allocation fast path.
func TestBudgetAllocateBlockingFastPath(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Fast path - space already available
	start := time.Now()
	success := mb.AllocateBlocking(100, time.Second)
	elapsed := time.Since(start)

	if !success {
		t.Error("AllocateBlocking should succeed on fast path")
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("AllocateBlocking fast path too slow: %v", elapsed)
	}

	// Blocks counter should NOT increment on fast path
	state := mb.State()
	if state.Blocks != 0 {
		t.Errorf("Blocks = %d, want 0 (fast path)", state.Blocks)
	}
}

// TestBudgetAllocateBlockingDisabled verifies blocking allocation when disabled.
func TestBudgetAllocateBlockingDisabled(t *testing.T) {
	mb := &MemoryBudget{}
	mb.disabled.Store(true)
	mb.hardLimit.Store(100) // Very small limit

	// Should succeed immediately even for large allocation
	start := time.Now()
	success := mb.AllocateBlocking(10000, time.Second)
	elapsed := time.Since(start)

	if !success {
		t.Error("Disabled budget AllocateBlocking should always succeed")
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("Disabled budget AllocateBlocking too slow: %v", elapsed)
	}
}

// TestBudgetWaitersCounter verifies waiters counter during blocking.
func TestBudgetWaitersCounter(t *testing.T) {
	mb := newTestBudget(100, 200)
	mb.TryAllocate(200) // Fill to hard limit

	state := mb.State()
	if state.Waiters != 0 {
		t.Errorf("Initial Waiters = %d, want 0", state.Waiters)
	}

	// Start blocking allocation in goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		mb.AllocateBlocking(50, 100*time.Millisecond)
	}()

	// Give goroutine time to enter waiting state
	time.Sleep(20 * time.Millisecond)

	state = mb.State()
	if state.Waiters != 1 {
		t.Errorf("Waiters = %d during blocking, want 1", state.Waiters)
	}
	if state.StateName() != "BLOCK" {
		t.Errorf("StateName = %q during blocking, want BLOCK", state.StateName())
	}

	// Wait for timeout
	wg.Wait()

	state = mb.State()
	if state.Waiters != 0 {
		t.Errorf("Waiters = %d after timeout, want 0", state.Waiters)
	}
}

// TestBudgetGlobalSingleton verifies GetBudget returns the global singleton.
func TestBudgetGlobalSingleton(t *testing.T) {
	budget := GetBudget()

	if budget == nil {
		t.Fatal("GetBudget() returned nil")
	}

	// Should return the same instance
	budget2 := GetBudget()
	if budget != budget2 {
		t.Error("GetBudget() should return the same singleton instance")
	}

	// Verify it's properly initialized
	state := budget.State()
	if state.SoftLimit <= 0 {
		t.Errorf("Global budget SoftLimit = %d, should be > 0", state.SoftLimit)
	}
	if state.HardLimit <= 0 {
		t.Errorf("Global budget HardLimit = %d, should be > 0", state.HardLimit)
	}
	if state.HardLimit <= state.SoftLimit {
		t.Errorf("HardLimit (%d) should be > SoftLimit (%d)", state.HardLimit, state.SoftLimit)
	}
}

// TestBudgetDeviceProfile verifies getDeviceProfile returns valid profiles.
func TestBudgetDeviceProfile(t *testing.T) {
	profile := getDeviceProfile()

	if profile.Name == "" {
		t.Error("Profile name should not be empty")
	}
	if profile.BufferSoftCap <= 0 {
		t.Errorf("BufferSoftCap = %d, should be > 0", profile.BufferSoftCap)
	}
	if profile.BufferHardCap <= 0 {
		t.Errorf("BufferHardCap = %d, should be > 0", profile.BufferHardCap)
	}
	if profile.BufferHardCap <= profile.BufferSoftCap {
		t.Errorf("BufferHardCap (%d) should be > BufferSoftCap (%d)",
			profile.BufferHardCap, profile.BufferSoftCap)
	}

	t.Logf("Device profile: %s (soft=%dKB, hard=%dKB)",
		profile.Name, profile.BufferSoftCap/1024, profile.BufferHardCap/1024)
}

// TestBudgetEvictionModeTransitions verifies all eviction mode transitions.
func TestBudgetEvictionModeTransitions(t *testing.T) {
	mb := newTestBudget(1000, 2000)

	// Transition: NORMAL -> EVICT (via allocation crossing soft)
	mb.TryAllocate(1100)
	if !mb.IsEvicting() {
		t.Error("Should enter EVICT after crossing soft limit via allocation")
	}

	// Transition: EVICT -> EVICT (stay in eviction, allocate more)
	mb.TryAllocate(100)
	if !mb.IsEvicting() {
		t.Error("Should stay in EVICT after more allocation")
	}

	// Transition: EVICT -> NORMAL (via release dropping below soft)
	mb.Release(300) // Evicts, Total becomes 900
	if mb.IsEvicting() {
		t.Error("Should exit EVICT after dropping below soft limit")
	}

	// Transition: NORMAL -> EVICT (via ForceEvict NOT - ForceEvict only decrements)
	// Actually ForceEvict should keep us in normal if we're already below soft
	mb.TryAllocate(200) // Back to 1100, in eviction
	if !mb.IsEvicting() {
		t.Error("Should be in EVICT")
	}

	// ForceEvict to drop below soft
	mb.ForceEvict(200) // 900
	if mb.IsEvicting() {
		t.Error("Should exit EVICT after ForceEvict drops below soft")
	}
}

// TestBudgetReleaseCASRetry verifies Release CAS loop handles contention.
func TestBudgetReleaseCASRetry(t *testing.T) {
	const (
		softLimit     = 100       // Low soft limit
		hardLimit     = 10000    // High hard limit
		numGoroutines = 50
		allocSize     = int64(100)
	)

	mb := newTestBudget(softLimit, hardLimit)

	// Fill well past soft limit - all releases should evict
	mb.TryAllocate(int64(numGoroutines) * allocSize * 2) // 10000 bytes

	var wg sync.WaitGroup
	var evictionCount atomic.Int64

	// Many goroutines releasing simultaneously - triggers CAS contention
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each releases allocSize bytes
			if !mb.Release(allocSize) {
				evictionCount.Add(1)
			}
		}()
	}

	wg.Wait()

	state := mb.State()

	// We started at 10000, soft=100
	// Since we're always way over soft, all releases should evict
	// Expected: TotalBytes = 10000 - 50*100 = 5000
	expectedTotal := int64(numGoroutines)*allocSize*2 - int64(numGoroutines)*allocSize
	if state.TotalBytes != expectedTotal {
		t.Errorf("TotalBytes = %d, want %d", state.TotalBytes, expectedTotal)
	}

	// All releases should have evicted (we stayed above soft the whole time)
	if evictionCount.Load() != int64(numGoroutines) {
		t.Errorf("Eviction count = %d, want %d", evictionCount.Load(), numGoroutines)
	}

	// Evictions counter should match
	if state.Evictions != uint64(numGoroutines) {
		t.Errorf("Evictions = %d, want %d", state.Evictions, numGoroutines)
	}

	t.Logf("CAS contention test completed: evictions=%d, TotalBytes=%d",
		evictionCount.Load(), state.TotalBytes)
}

// TestReconcileIdleDecay verifies idle decay reduces stale cachedBytes.
func TestReconcileIdleDecay(t *testing.T) {
	mb := newTestBudget(100000, 200000)

	// Simulate cache activity: allocate and cache some buffers
	mb.TryAllocate(10000)
	mb.inUseBytes.Store(0)         // Simulate all returned
	mb.cachedBytes.Store(10000)    // Manually set cached (normally done by Release)
	mb.lastActivity.Store(time.Now().Add(-2 * IdleThreshold).UnixNano()) // Set old activity

	// Before reconcile
	stateBefore := mb.State()
	if stateBefore.TrackedCachedBytes != 10000 {
		t.Fatalf("Before: TrackedCachedBytes = %d, want 10000", stateBefore.TrackedCachedBytes)
	}

	// Trigger reconcile
	mb.reconcile()

	// After reconcile - should have decayed by 50%
	stateAfter := mb.State()
	expectedDecay := int64(10000 * DecayFactor) // 5000
	expectedRemaining := int64(10000) - expectedDecay

	if stateAfter.TrackedCachedBytes != expectedRemaining {
		t.Errorf("After: TrackedCachedBytes = %d, want %d", stateAfter.TrackedCachedBytes, expectedRemaining)
	}

	// totalBytes should also have been decremented
	expectedTotal := int64(10000) - expectedDecay
	if stateAfter.TotalBytes != expectedTotal {
		t.Errorf("After: TotalBytes = %d, want %d", stateAfter.TotalBytes, expectedTotal)
	}

	// ReconcileCount should be 1
	if stateAfter.ReconcileCount != 1 {
		t.Errorf("ReconcileCount = %d, want 1", stateAfter.ReconcileCount)
	}

	t.Logf("Idle decay test: before=%d, after=%d, decay=%d",
		stateBefore.TrackedCachedBytes, stateAfter.TrackedCachedBytes, expectedDecay)
}

// TestReconcileNegativeCachedBytes verifies negative cachedBytes is corrected.
func TestReconcileNegativeCachedBytes(t *testing.T) {
	mb := newTestBudget(100000, 200000)

	// Simulate bug: negative cachedBytes (shouldn't happen but test recovery)
	mb.cachedBytes.Store(-1000)
	mb.lastActivity.Store(time.Now().UnixNano()) // Recent activity (skip idle decay)

	// Trigger reconcile
	mb.reconcile()

	// cachedBytes should be reset to 0
	state := mb.State()
	if state.TrackedCachedBytes != 0 {
		t.Errorf("TrackedCachedBytes = %d, want 0", state.TrackedCachedBytes)
	}

	if state.ReconcileCount != 1 {
		t.Errorf("ReconcileCount = %d, want 1", state.ReconcileCount)
	}
}

// TestReconcileNoopWhenActive verifies reconcile is no-op during active usage.
func TestReconcileNoopWhenActive(t *testing.T) {
	mb := newTestBudget(100000, 200000)

	// Simulate active usage
	mb.TryAllocate(10000)
	mb.cachedBytes.Store(5000)
	mb.lastActivity.Store(time.Now().UnixNano()) // Very recent

	stateBefore := mb.State()

	// Trigger reconcile
	mb.reconcile()

	stateAfter := mb.State()

	// Nothing should have changed (not idle, no drift)
	if stateAfter.TrackedCachedBytes != stateBefore.TrackedCachedBytes {
		t.Errorf("TrackedCachedBytes changed: %d -> %d",
			stateBefore.TrackedCachedBytes, stateAfter.TrackedCachedBytes)
	}

	if stateAfter.ReconcileCount != 0 {
		t.Errorf("ReconcileCount = %d, want 0 (no reconciliation needed)", stateAfter.ReconcileCount)
	}
}

// TestCachedBytesTracking verifies cachedBytes is tracked correctly through normal operations.
func TestCachedBytesTracking(t *testing.T) {
	mb := newTestBudget(100000, 200000)

	// Allocate
	mb.TryAllocate(8192)
	state := mb.State()
	if state.TotalBytes != 8192 {
		t.Errorf("After allocate: TotalBytes = %d, want 8192", state.TotalBytes)
	}
	if state.TrackedCachedBytes != 0 {
		t.Errorf("After allocate: TrackedCachedBytes = %d, want 0", state.TrackedCachedBytes)
	}

	// Simulate use (MarkInUse called by GetBuffer on hit, but we allocated fresh)
	mb.inUseBytes.Store(8192)

	// Release (under soft limit, should cache)
	shouldCache := mb.Release(8192)
	if !shouldCache {
		t.Error("Release should return true (cache) when under soft limit")
	}

	state = mb.State()
	// After release: inUse = 0, cachedBytes should be 8192
	if state.TrackedCachedBytes != 8192 {
		t.Errorf("After release: TrackedCachedBytes = %d, want 8192", state.TrackedCachedBytes)
	}

	// Now simulate MarkInUse (cache hit)
	mb.MarkInUse(8192)

	state = mb.State()
	// After MarkInUse: cachedBytes should be 0 (taken from cache)
	if state.TrackedCachedBytes != 0 {
		t.Errorf("After MarkInUse: TrackedCachedBytes = %d, want 0", state.TrackedCachedBytes)
	}

	t.Logf("Cached bytes tracking verified correctly")
}
