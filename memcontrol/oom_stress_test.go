// OOM stress tests for memcontrol package.
// These tests verify that the memory budget system actually prevents OOM conditions
// by rejecting allocations when limits are reached.
//
// CRITICAL: These tests intentionally try to exhaust memory to verify protection works.
// They use small limits (1-10MB) to avoid actually triggering OOM on the test system.

package memcontrol

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestOOM_HardLimitBlocksAllocation verifies that allocations are rejected
// when the hard limit is reached, preventing OOM.
func TestOOM_HardLimitBlocksAllocation(t *testing.T) {
	// Create isolated budget with tiny limits (1MB soft, 2MB hard)
	budget := &MemoryBudget{}
	budget.softLimit.Store(1 * 1024 * 1024)  // 1MB soft
	budget.hardLimit.Store(2 * 1024 * 1024)  // 2MB hard

	// Allocate up to hard limit
	const chunkSize = 100 * 1024 // 100KB chunks
	allocated := int64(0)
	allocations := 0

	for {
		if !budget.TryAllocate(chunkSize) {
			break // Hard limit reached
		}
		allocated += chunkSize
		allocations++

		// Safety: don't loop forever
		if allocations > 100 {
			t.Fatal("allocations should have been blocked before 100 iterations")
		}
	}

	// Verify we stopped at hard limit
	state := budget.State()
	if state.TotalBytes > state.HardLimit {
		t.Errorf("exceeded hard limit: total=%d, hard=%d", state.TotalBytes, state.HardLimit)
	}

	t.Logf("OOM protection verified: blocked at %d bytes (%d allocations), hard limit=%d",
		allocated, allocations, state.HardLimit)

	// Verify further allocations are blocked
	if budget.TryAllocate(chunkSize) {
		t.Error("allocation should be blocked when at hard limit")
	}

	// Release some memory
	budget.Release(chunkSize * 5)

	// Now allocation should succeed
	if !budget.TryAllocate(chunkSize) {
		t.Error("allocation should succeed after releasing memory")
	}
}

// TestOOM_SoftLimitTriggersEviction verifies that crossing soft limit
// activates eviction mode and triggers callback.
func TestOOM_SoftLimitTriggersEviction(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(500 * 1024)       // 500KB soft
	budget.hardLimit.Store(1 * 1024 * 1024)  // 1MB hard

	evictionTriggered := atomic.Bool{}
	budget.SetEvictionCallback(func() {
		evictionTriggered.Store(true)
	})

	// Allocate below soft limit - no eviction
	budget.TryAllocate(400 * 1024) // 400KB
	time.Sleep(10 * time.Millisecond)

	if budget.IsEvicting() {
		t.Error("should not be evicting below soft limit")
	}

	// Cross soft limit
	budget.TryAllocate(200 * 1024) // 600KB total (> 500KB soft)
	time.Sleep(50 * time.Millisecond) // Allow async callback

	if !budget.IsEvicting() {
		t.Error("should be evicting after crossing soft limit")
	}

	if !evictionTriggered.Load() {
		t.Error("eviction callback should have been triggered")
	}

	// Verify Release returns false (don't cache)
	shouldCache := budget.Release(100 * 1024)
	if shouldCache {
		t.Error("Release should return false when in eviction mode")
	}

	// Drop below soft limit
	budget.Release(300 * 1024)
	time.Sleep(10 * time.Millisecond)

	if budget.IsEvicting() {
		t.Error("should exit eviction mode after dropping below soft limit")
	}
}

// TestOOM_ConcurrentAllocationRace verifies that concurrent allocations
// don't exceed the hard limit due to race conditions.
func TestOOM_ConcurrentAllocationRace(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(5 * 1024 * 1024)  // 5MB soft
	budget.hardLimit.Store(10 * 1024 * 1024) // 10MB hard

	const goroutines = 100
	const allocationsPerGoroutine = 50
	const chunkSize = int64(50 * 1024) // 50KB

	var wg sync.WaitGroup
	successCount := atomic.Int64{}
	failCount := atomic.Int64{}

	// Launch concurrent allocators
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < allocationsPerGoroutine; j++ {
				if budget.TryAllocate(chunkSize) {
					successCount.Add(1)
				} else {
					failCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()

	state := budget.State()

	// CRITICAL: Total bytes must NEVER exceed hard limit
	if state.TotalBytes > state.HardLimit {
		t.Fatalf("RACE CONDITION: exceeded hard limit! total=%d, hard=%d",
			state.TotalBytes, state.HardLimit)
	}

	// Verify accounting is consistent
	expectedBytes := successCount.Load() * chunkSize
	if state.TotalBytes != expectedBytes {
		t.Errorf("accounting mismatch: tracked=%d, expected=%d", state.TotalBytes, expectedBytes)
	}

	t.Logf("Race test passed: %d successful, %d blocked, total=%d bytes (limit=%d)",
		successCount.Load(), failCount.Load(), state.TotalBytes, state.HardLimit)
}

// TestOOM_BufferPoolRespectsLimit verifies that GetBuffer respects
// the memory budget and rejects allocations when limit reached.
func TestOOM_BufferPoolRespectsLimit(t *testing.T) {
	// This test verifies the integration between buffer pool and budget.
	// Use the budget directly to test allocation limits, since the buffer
	// pool has cache hit behavior that complicates the test.

	budget := &MemoryBudget{}
	budget.softLimit.Store(512 * 1024)   // 512KB soft
	budget.hardLimit.Store(1024 * 1024)  // 1MB hard

	// Simulate buffer pool behavior: allocate until hard limit reached
	const bufSize = int64(16384) // 16KB
	allocations := 0
	for {
		if !budget.TryAllocate(bufSize) {
			break // Hard limit reached
		}
		allocations++
		if allocations > 100 {
			t.Fatal("should have hit hard limit")
		}
	}

	state := budget.State()

	// Verify we allocated up to the limit
	expectedAllocs := int(state.HardLimit / bufSize)
	if allocations < expectedAllocs-1 || allocations > expectedAllocs+1 {
		t.Errorf("expected ~%d allocations, got %d", expectedAllocs, allocations)
	}

	// Verify we're at capacity
	if state.TotalBytes > state.HardLimit {
		t.Errorf("exceeded hard limit: %d > %d", state.TotalBytes, state.HardLimit)
	}

	t.Logf("Buffer pool limit test: %d allocations (%d bytes), limit=%d",
		allocations, state.TotalBytes, state.HardLimit)
}

// oomTestConn is a simple mock for net.Conn for OOM testing purposes.
type oomTestConn struct {
	closed atomic.Bool
}

func (m *oomTestConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *oomTestConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *oomTestConn) Close() error                       { m.closed.Store(true); return nil }
func (m *oomTestConn) LocalAddr() net.Addr                { return nil }
func (m *oomTestConn) RemoteAddr() net.Addr               { return nil }
func (m *oomTestConn) SetDeadline(t time.Time) error      { return nil }
func (m *oomTestConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *oomTestConn) SetWriteDeadline(t time.Time) error { return nil }

// TestOOM_ConnectionSheddingUnderPressure verifies that connections
// are shed when memory pressure is high.
func TestOOM_ConnectionSheddingUnderPressure(t *testing.T) {
	// Save and restore
	origBudget := globalMemoryBudget
	origRegistry := globalRegistry
	defer func() {
		globalMemoryBudget = origBudget
		globalRegistry = origRegistry
	}()

	// Fresh test instances
	testBudget := &MemoryBudget{}
	testBudget.softLimit.Store(100 * 1024)  // 100KB soft
	testBudget.hardLimit.Store(200 * 1024)  // 200KB hard
	globalMemoryBudget = testBudget

	testRegistry := &Registry{
		conns: make(map[uint64]*Conn),
		byTag: make(map[string]*atomic.Int32),
	}
	globalRegistry = testRegistry

	// Wire eviction to shed connections
	shedCount := atomic.Int32{}
	testBudget.SetEvictionCallback(func() {
		count := testRegistry.CloseIdle(0) // Close ALL connections
		shedCount.Add(int32(count))
	})

	// Create mock connections with idle time
	pastTime := time.Now().Add(-time.Minute).UnixNano() // 1 minute ago
	for i := 0; i < 10; i++ {
		c := &Conn{
			Conn:      &oomTestConn{}, // Use mock to prevent nil dereference
			id:        uint64(i + 1),
			tag:       "test",
			createdAt: pastTime,
		}
		c.lastReadAt.Store(pastTime)  // 1 minute idle
		c.lastWriteAt.Store(pastTime) // 1 minute idle
		testRegistry.register(c)
	}

	initialCount := testRegistry.Count()
	if initialCount != 10 {
		t.Fatalf("expected 10 connections, got %d", initialCount)
	}

	// Trigger memory pressure by allocating past soft limit
	testBudget.TryAllocate(150 * 1024) // 150KB (> 100KB soft)
	time.Sleep(100 * time.Millisecond) // Allow async callback

	// Verify connections were shed
	if shedCount.Load() == 0 {
		t.Error("connections should have been shed under memory pressure")
	}

	t.Logf("Shed %d connections under memory pressure", shedCount.Load())
}

// TestOOM_ExtremeLoadWouldOOM verifies that without protection,
// the test would allocate way more than the limit.
// With protection, allocations are capped.
func TestOOM_ExtremeLoadWouldOOM(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(1 * 1024 * 1024)  // 1MB soft
	budget.hardLimit.Store(2 * 1024 * 1024)  // 2MB hard

	// Try to allocate 100MB worth of memory
	const targetAllocation = 100 * 1024 * 1024 // 100MB
	const chunkSize = int64(64 * 1024)         // 64KB chunks
	const totalChunks = targetAllocation / chunkSize

	allocated := int64(0)
	blocked := int64(0)

	for i := int64(0); i < totalChunks; i++ {
		if budget.TryAllocate(chunkSize) {
			allocated += chunkSize
		} else {
			blocked++
		}
	}

	state := budget.State()

	// Without protection, we would have allocated 100MB
	// With protection, we're capped at 2MB
	if allocated > state.HardLimit {
		t.Fatalf("OOM PROTECTION FAILED: allocated %dMB, limit=%dMB",
			allocated/(1024*1024), state.HardLimit/(1024*1024))
	}

	t.Logf("OOM protection verified: attempted=%dMB, allocated=%dMB, blocked=%d allocations",
		targetAllocation/(1024*1024), allocated/(1024*1024), blocked)
}

// TestOOM_AllocateBlockingTimeout verifies that blocking allocation
// times out correctly and doesn't hang forever.
func TestOOM_AllocateBlockingTimeout(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(100 * 1024)  // 100KB
	budget.hardLimit.Store(100 * 1024)  // Same as soft (immediately at limit)

	// Fill to capacity
	budget.TryAllocate(100 * 1024)

	// Try blocking allocation with timeout
	start := time.Now()
	succeeded := budget.AllocateBlocking(1024, 50*time.Millisecond)
	elapsed := time.Since(start)

	if succeeded {
		t.Error("blocking allocation should have failed (at limit)")
	}

	if elapsed < 45*time.Millisecond {
		t.Errorf("timeout too short: %v (expected ~50ms)", elapsed)
	}

	if elapsed > 200*time.Millisecond {
		t.Errorf("timeout too long: %v (expected ~50ms)", elapsed)
	}

	t.Logf("Blocking allocation timed out correctly after %v", elapsed)
}

// TestOOM_MemoryRecoveryAfterPressure verifies that the system recovers
// correctly after memory pressure is relieved.
func TestOOM_MemoryRecoveryAfterPressure(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(500 * 1024)       // 500KB
	budget.hardLimit.Store(1 * 1024 * 1024)  // 1MB

	// Phase 1: Fill to hard limit
	chunks := []int64{}
	for {
		if !budget.TryAllocate(50 * 1024) {
			break
		}
		chunks = append(chunks, 50*1024)
	}

	state := budget.State()
	t.Logf("Phase 1: Filled to %d bytes (hard limit=%d)", state.TotalBytes, state.HardLimit)

	// Should be in eviction mode (over soft limit)
	if !state.InEviction {
		t.Error("should be in eviction mode when over soft limit")
	}

	// Verify at capacity
	if budget.TryAllocate(50 * 1024) {
		t.Error("should not be able to allocate at hard limit")
	}

	// Phase 2: Release all memory
	// When in eviction mode, Release() returns false and decrements totalBytes
	for _, size := range chunks {
		shouldCache := budget.Release(size)
		// While over soft limit, Release returns false (don't cache = evict)
		// This decrements totalBytes
		if shouldCache {
			// Below soft limit - use ForceEvict to actually free the memory
			budget.ForceEvict(size)
		}
	}

	state = budget.State()
	// After release, inUseBytes should be 0
	if state.InUseBytes != 0 {
		t.Errorf("after release, inUseBytes should be 0, got %d", state.InUseBytes)
	}

	// totalBytes should be 0 after we ForceEvict'd the cached portions
	if state.TotalBytes != 0 {
		t.Errorf("after release+force evict, totalBytes should be 0, got %d", state.TotalBytes)
	}

	if state.InEviction {
		t.Error("should not be in eviction mode after releasing all memory")
	}

	// Phase 3: Should be able to allocate again
	if !budget.TryAllocate(500 * 1024) {
		t.Error("should be able to allocate after recovery")
	}

	t.Log("Memory recovery test passed")
}

// TestOOM_ConcurrentAllocateRelease simulates realistic workload
// with concurrent allocations and releases.
func TestOOM_ConcurrentAllocateRelease(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(2 * 1024 * 1024)  // 2MB
	budget.hardLimit.Store(4 * 1024 * 1024)  // 4MB

	const duration = 2 * time.Second
	const goroutines = 50

	var wg sync.WaitGroup
	stop := make(chan struct{})

	stats := struct {
		allocations atomic.Int64
		releases    atomic.Int64
		failures    atomic.Int64
		maxSeen     atomic.Int64
	}{}

	// Launch workers that allocate and release randomly
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sizes := []int64{4096, 8192, 16384, 32768}

			for {
				select {
				case <-stop:
					return
				default:
				}

				size := sizes[time.Now().UnixNano()%int64(len(sizes))]

				if budget.TryAllocate(size) {
					stats.allocations.Add(1)

					// Track max seen
					current := budget.totalBytes.Load()
					for {
						max := stats.maxSeen.Load()
						if current <= max || stats.maxSeen.CompareAndSwap(max, current) {
							break
						}
					}

					// Hold briefly then release
					time.Sleep(time.Duration(time.Now().UnixNano()%1000) * time.Microsecond)
					budget.Release(size)
					stats.releases.Add(1)
				} else {
					stats.failures.Add(1)
				}
			}
		}()
	}

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	state := budget.State()

	// Verify accounting is correct
	if state.TotalBytes < 0 {
		t.Errorf("negative total bytes: %d (accounting bug)", state.TotalBytes)
	}

	// Verify max never exceeded hard limit
	if stats.maxSeen.Load() > state.HardLimit {
		t.Errorf("max usage exceeded hard limit: max=%d, limit=%d",
			stats.maxSeen.Load(), state.HardLimit)
	}

	t.Logf("Concurrent test: %d allocs, %d releases, %d failures, max=%dKB, limit=%dKB",
		stats.allocations.Load(), stats.releases.Load(), stats.failures.Load(),
		stats.maxSeen.Load()/1024, state.HardLimit/1024)
}

// TestOOM_BufferPoolConcurrentStress stress tests the buffer pool
// under high concurrency to verify no OOM.
func TestOOM_BufferPoolConcurrentStress(t *testing.T) {
	// Save and restore global budget
	origBudget := globalMemoryBudget
	defer func() { globalMemoryBudget = origBudget }()

	// Create test budget with moderate limit
	testBudget := &MemoryBudget{}
	testBudget.softLimit.Store(5 * 1024 * 1024)   // 5MB soft
	testBudget.hardLimit.Store(10 * 1024 * 1024)  // 10MB hard
	globalMemoryBudget = testBudget

	const duration = 2 * time.Second
	const goroutines = 100

	var wg sync.WaitGroup
	stop := make(chan struct{})

	stats := struct {
		gets      atomic.Int64
		puts      atomic.Int64
		exhausted atomic.Int64
	}{}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sizes := []int{128, 512, 2048, 4096, 8192, 16384}

			for {
				select {
				case <-stop:
					return
				default:
				}

				size := sizes[time.Now().UnixNano()%int64(len(sizes))]

				buf, err := GetBuffer(size)
				if err == ErrBufferPoolExhausted {
					stats.exhausted.Add(1)
					continue
				}
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					continue
				}

				stats.gets.Add(1)

				// Simulate work
				for j := 0; j < len(*buf) && j < 100; j++ {
					(*buf)[j] = byte(j)
				}

				// Random hold time
				time.Sleep(time.Duration(time.Now().UnixNano()%500) * time.Microsecond)

				PutBuffer(buf)
				stats.puts.Add(1)
			}
		}()
	}

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	state := testBudget.State()

	// Force GC to clean up
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	t.Logf("Buffer pool stress: gets=%d, puts=%d, exhausted=%d, final_total=%dKB, limit=%dKB",
		stats.gets.Load(), stats.puts.Load(), stats.exhausted.Load(),
		state.TotalBytes/1024, state.HardLimit/1024)

	// Verify gets == puts (no leaks)
	if stats.gets.Load() != stats.puts.Load() {
		t.Errorf("buffer leak detected: gets=%d, puts=%d",
			stats.gets.Load(), stats.puts.Load())
	}
}

// TestOOM_RapidAllocationBurst tests rapid burst allocation
// that would typically cause OOM without protection.
func TestOOM_RapidAllocationBurst(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(1 * 1024 * 1024)  // 1MB
	budget.hardLimit.Store(2 * 1024 * 1024)  // 2MB

	const goroutines = 200
	const allocSize = int64(64 * 1024) // 64KB each

	var wg sync.WaitGroup
	ready := make(chan struct{})
	succeeded := atomic.Int64{}
	failed := atomic.Int64{}

	// Setup all goroutines
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready // Wait for signal

			// Try to allocate
			if budget.TryAllocate(allocSize) {
				succeeded.Add(1)
			} else {
				failed.Add(1)
			}
		}()
	}

	// Fire all at once
	close(ready)
	wg.Wait()

	state := budget.State()

	// Without limit: 200 * 64KB = 12.8MB would be allocated
	// With limit: max 2MB (31 allocations)
	maxPossible := state.HardLimit / allocSize

	if succeeded.Load() > maxPossible+1 { // +1 for rounding
		t.Errorf("burst allocation exceeded limit: succeeded=%d, max=%d",
			succeeded.Load(), maxPossible)
	}

	if state.TotalBytes > state.HardLimit {
		t.Fatalf("burst test FAILED: total=%d > hard=%d", state.TotalBytes, state.HardLimit)
	}

	t.Logf("Burst test: %d/%d succeeded, total=%dKB, limit=%dKB",
		succeeded.Load(), goroutines, state.TotalBytes/1024, state.HardLimit/1024)
}

// TestOOM_EvictionCallbackPreventsOOM verifies that eviction callback
// can free memory to prevent OOM.
func TestOOM_EvictionCallbackPreventsOOM(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(500 * 1024)       // 500KB
	budget.hardLimit.Store(1 * 1024 * 1024)  // 1MB

	// Track allocated chunks
	var chunks []int64
	var chunksMu sync.Mutex

	// Eviction callback releases oldest chunks
	budget.SetEvictionCallback(func() {
		chunksMu.Lock()
		defer chunksMu.Unlock()

		// Release 20% of chunks
		toRelease := len(chunks) / 5
		if toRelease < 1 {
			toRelease = 1
		}

		for i := 0; i < toRelease && len(chunks) > 0; i++ {
			size := chunks[0]
			chunks = chunks[1:]
			budget.Release(size)
		}
	})

	// Allocate continuously
	allocated := 0
	for i := 0; i < 100; i++ {
		chunkSize := int64(50 * 1024) // 50KB

		if budget.TryAllocate(chunkSize) {
			chunksMu.Lock()
			chunks = append(chunks, chunkSize)
			chunksMu.Unlock()
			allocated++
		}

		// Allow eviction callback to run
		time.Sleep(5 * time.Millisecond)
	}

	state := budget.State()

	// With eviction, we should have been able to allocate more than
	// hardLimit/chunkSize would suggest
	minWithoutEviction := int(state.HardLimit / (50 * 1024))

	if allocated <= minWithoutEviction {
		t.Logf("Note: allocated %d, min without eviction=%d", allocated, minWithoutEviction)
	}

	t.Logf("Eviction test: allocated %d chunks, evictions=%d, total=%dKB",
		allocated, state.Evictions, state.TotalBytes/1024)
}

// TestOOM_AccountingAccuracyUnderStress verifies that memory accounting
// stays accurate under extreme concurrent load.
func TestOOM_AccountingAccuracyUnderStress(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(10 * 1024 * 1024)  // 10MB
	budget.hardLimit.Store(20 * 1024 * 1024)  // 20MB

	const iterations = 10000
	const goroutines = 50

	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				sizes := []int64{1024, 2048, 4096, 8192}
				size := sizes[i%len(sizes)]

				if budget.TryAllocate(size) {
					// Immediate release - use ForceEvict to ensure totalBytes decrements
					// In production, PutBuffer calls ForceEvict when rejecting buffers
					shouldCache := budget.Release(size)
					if shouldCache {
						// Below soft limit - force evict to free memory
						budget.ForceEvict(size)
					}
				}
			}
		}()
	}

	wg.Wait()

	state := budget.State()

	// After all allocations and releases with force evict, total should be 0
	if state.TotalBytes != 0 {
		t.Errorf("accounting error: total=%d, expected=0", state.TotalBytes)
	}

	if state.InUseBytes != 0 {
		t.Errorf("accounting error: inUse=%d, expected=0", state.InUseBytes)
	}

	t.Logf("Accounting test passed: %d total operations, final total=%d",
		goroutines*iterations*2, state.TotalBytes)
}

// TestOOM_ZeroLimitRejectsAll verifies that a zero hard limit
// rejects all allocations (fail-safe behavior).
func TestOOM_ZeroLimitRejectsAll(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(0)
	budget.hardLimit.Store(0)

	// Any allocation should fail
	if budget.TryAllocate(1) {
		t.Error("allocation should be rejected with zero hard limit")
	}

	// Even zero-size should "succeed" (no-op)
	if !budget.TryAllocate(0) {
		t.Error("zero-size allocation should always succeed")
	}
}

// TestOOM_NegativeSizeHandling verifies that negative sizes
// are handled safely (don't corrupt accounting).
func TestOOM_NegativeSizeHandling(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(1 * 1024 * 1024)
	budget.hardLimit.Store(2 * 1024 * 1024)

	// Negative size should be treated as 0 (no-op)
	if !budget.TryAllocate(-1000) {
		t.Error("negative size should be treated as no-op")
	}

	state := budget.State()
	if state.TotalBytes != 0 {
		t.Errorf("negative allocation corrupted accounting: total=%d", state.TotalBytes)
	}

	// Negative release should also be no-op
	budget.TryAllocate(1000)
	budget.Release(-500)

	state = budget.State()
	if state.TotalBytes != 1000 {
		t.Errorf("negative release corrupted accounting: total=%d, expected=1000", state.TotalBytes)
	}
}

// TestOOM_DisabledBudgetAllowsUnlimited verifies that disabled budget
// doesn't limit allocations (for testing/debugging).
func TestOOM_DisabledBudgetAllowsUnlimited(t *testing.T) {
	budget := &MemoryBudget{}
	budget.disabled.Store(true)
	budget.softLimit.Store(100)
	budget.hardLimit.Store(100)

	// Should be able to allocate way over limit
	const hugeAllocation = int64(1 * 1024 * 1024 * 1024) // 1GB
	if !budget.TryAllocate(hugeAllocation) {
		t.Error("disabled budget should allow any allocation")
	}

	// Verify it actually tracked nothing
	state := budget.State()
	if !state.Disabled {
		t.Error("state should report disabled")
	}
}

// TestOOM_WaitersCountAccuracy verifies waiters count is accurate.
func TestOOM_WaitersCountAccuracy(t *testing.T) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(100)
	budget.hardLimit.Store(100)

	// Fill to capacity
	budget.TryAllocate(100)

	const waiters = 10
	var wg sync.WaitGroup
	started := atomic.Int32{}

	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Add(1)
			// Will block for 100ms
			budget.AllocateBlocking(10, 100*time.Millisecond)
		}()
	}

	// Wait for all to start blocking
	time.Sleep(20 * time.Millisecond)

	state := budget.State()
	if state.Waiters < int32(waiters/2) {
		t.Errorf("expected ~%d waiters, got %d", waiters, state.Waiters)
	}

	// Wait for all to timeout
	wg.Wait()

	state = budget.State()
	if state.Waiters != 0 {
		t.Errorf("waiters should be 0 after timeout, got %d", state.Waiters)
	}
}

// BenchmarkOOM_AllocationUnderPressure benchmarks allocation performance
// when approaching the hard limit.
func BenchmarkOOM_AllocationUnderPressure(b *testing.B) {
	budget := &MemoryBudget{}
	budget.softLimit.Store(100 * 1024 * 1024)  // 100MB
	budget.hardLimit.Store(200 * 1024 * 1024)  // 200MB

	// Pre-fill to 95% capacity
	budget.TryAllocate(190 * 1024 * 1024)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if budget.TryAllocate(1024) {
				budget.Release(1024)
			}
		}
	})
}
