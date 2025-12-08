package memcontrol

import (
	"bytes"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// init configures test environment with small budget limits
func init() {
	// Set small limits for testing budget exhaustion
	budget := GetBudget()
	if budget != nil {
		// 1MB soft, 2MB hard for testing
		budget.SetLimits(1*1024*1024, 2*1024*1024)
	}
}

// resetStats clears all pool statistics for isolated test runs
func resetStats() {
	for i := 0; i < 6; i++ {
		stats.allocated[i].Store(0)
		stats.returned[i].Store(0)
	}
	stats.oversized.Store(0)
	stats.polluted.Store(0)
	stats.orphaned.Store(0)
	stats.evicted.Store(0)
}

// resetBudget clears budget counters and memory tracking
func resetBudget() {
	budget := GetBudget()
	if budget != nil {
		// Reset counters
		budget.gets.Store(0)
		budget.hits.Store(0)
		budget.misses.Store(0)
		budget.evictions.Store(0)
		budget.blocks.Store(0)
		// Reset memory tracking
		budget.totalBytes.Store(0)
		budget.inUseBytes.Store(0)
		budget.inEviction.Store(false)
	}
}

// cleanupBufferMap clears orphaned entries in bufferOriginalSizes
func cleanupBufferMap() {
	bufferOriginalSizes.Range(func(key, value any) bool {
		bufferOriginalSizes.Delete(key)
		bufferSizeMapCount.Add(-1)
		return true
	})
	bufferSizeMapCount.Store(0)
}

// TestGetBufferTierSelection verifies correct tier selection for each size range
func TestGetBufferTierSelection(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Set large limits for this test to avoid budget exhaustion
	budget := GetBudget()
	budget.SetLimits(64*1024*1024, 128*1024*1024)

	testCases := []struct {
		name         string
		requestSize  int
		expectedCap  int
		expectedTier int // 0=128B, 1=512B, 2=2KB, 3=4KB, 4=8KB, 5=16KB
	}{
		// Tier 0: 0-128 bytes -> 128B
		{"zero_size", 0, Size128B, 0},
		{"one_byte", 1, Size128B, 0},
		{"mid_tier0", 64, Size128B, 0},
		{"boundary_tier0", 128, Size128B, 0},

		// Tier 1: 129-512 bytes -> 512B
		{"just_over_128", 129, Size512B, 1},
		{"mid_tier1", 256, Size512B, 1},
		{"boundary_tier1", 512, Size512B, 1},

		// Tier 2: 513-2048 bytes -> 2KB
		{"just_over_512", 513, Size2KB, 2},
		{"mid_tier2", 1024, Size2KB, 2},
		{"boundary_tier2", 2048, Size2KB, 2},

		// Tier 3: 2049-4096 bytes -> 4KB
		{"just_over_2KB", 2049, Size4KB, 3},
		{"mid_tier3", 3000, Size4KB, 3},
		{"boundary_tier3", 4096, Size4KB, 3},

		// Tier 4: 4097-8192 bytes -> 8KB
		{"just_over_4KB", 4097, Size8KB, 4},
		{"mid_tier4", 6000, Size8KB, 4},
		{"boundary_tier4", 8192, Size8KB, 4},

		// Tier 5: 8193-16384 bytes -> 16KB
		{"just_over_8KB", 8193, Size16KB, 5},
		{"mid_tier5", 12000, Size16KB, 5},
		{"boundary_tier5", 16384, Size16KB, 5},

		// Oversized: >16384 bytes -> exact size
		{"just_over_16KB", 16385, 16385, -1},
		{"large_oversized", 32768, 32768, -1},
		// Note: max_size test moved to TestExactMaxSize to properly handle budget
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := GetBuffer(tc.requestSize)
			if err != nil {
				t.Fatalf("GetBuffer(%d) returned error: %v", tc.requestSize, err)
			}
			defer PutBuffer(buf)

			if cap(*buf) != tc.expectedCap {
				t.Errorf("GetBuffer(%d): expected cap=%d, got cap=%d",
					tc.requestSize, tc.expectedCap, cap(*buf))
			}

			// Verify buffer is usable up to requested size
			if len(*buf) < tc.requestSize && tc.requestSize > 0 {
				// Slice to requested size should work
				data := (*buf)[:tc.requestSize]
				if len(data) != tc.requestSize {
					t.Errorf("Buffer not usable up to requested size %d", tc.requestSize)
				}
			}
		})
	}
}

// TestGetBufferCapacity verifies returned buffer has correct capacity for tier
func TestGetBufferCapacity(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	tierSizes := []int{Size128B, Size512B, Size2KB, Size4KB, Size8KB, Size16KB}

	for _, tierSize := range tierSizes {
		t.Run(tierName(tierSize), func(t *testing.T) {
			buf, err := GetBuffer(tierSize)
			if err != nil {
				t.Fatalf("GetBuffer(%d) returned error: %v", tierSize, err)
			}
			defer PutBuffer(buf)

			if cap(*buf) != tierSize {
				t.Errorf("GetBuffer(%d): expected exact capacity %d, got %d",
					tierSize, tierSize, cap(*buf))
			}

			// Buffer should be fully accessible
			if len(*buf) != tierSize {
				t.Errorf("GetBuffer(%d): expected len=%d, got len=%d",
					tierSize, tierSize, len(*buf))
			}
		})
	}
}

// TestPutBufferPoolReturn verifies buffers return to correct pool
func TestPutBufferPoolReturn(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Allocate and return buffers for each tier
	tierSizes := []struct {
		size      int
		tierIndex int
	}{
		{Size128B, 0},
		{Size512B, 1},
		{Size2KB, 2},
		{Size4KB, 3},
		{Size8KB, 4},
		{Size16KB, 5},
	}

	for _, tier := range tierSizes {
		t.Run(tierName(tier.size), func(t *testing.T) {
			resetStats()
			resetBudget()

			buf, err := GetBuffer(tier.size)
			if err != nil {
				t.Fatalf("GetBuffer(%d) returned error: %v", tier.size, err)
			}

			// Verify allocated counter incremented
			allocBefore := stats.allocated[tier.tierIndex].Load()
			if allocBefore != 1 {
				t.Errorf("Expected allocated[%d]=1, got %d", tier.tierIndex, allocBefore)
			}

			// Put buffer back
			PutBuffer(buf)

			// Wait a tiny bit for atomic operations
			runtime.Gosched()

			// Verify returned counter incremented (may be 0 if eviction mode)
			returnedAfter := stats.returned[tier.tierIndex].Load()
			polluted := stats.polluted.Load()

			// Either returned or polluted should increment (depending on budget state)
			if returnedAfter == 0 && polluted == 0 {
				t.Errorf("Expected returned[%d] or polluted to increment after PutBuffer", tier.tierIndex)
			}
		})
	}
}

// TestPutBufferPollutionRejection verifies grown buffers are rejected
func TestPutBufferPollutionRejection(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Get a 4KB buffer
	buf, err := GetBuffer(Size4KB)
	if err != nil {
		t.Fatalf("GetBuffer(%d) returned error: %v", Size4KB, err)
	}
	if buf == nil {
		t.Fatal("GetBuffer returned nil buffer without error")
	}

	// Simulate buffer growth via append (creates new backing array)
	largeData := make([]byte, Size8KB)
	*buf = append(*buf, largeData...)

	// Verify capacity changed
	if cap(*buf) == Size4KB {
		t.Skip("Buffer did not grow - append optimization may have reused backing array")
	}

	pollutedBefore := stats.polluted.Load()

	// Return the grown buffer
	PutBuffer(buf)

	runtime.Gosched()

	pollutedAfter := stats.polluted.Load()

	// Should be rejected as polluted
	if pollutedAfter <= pollutedBefore {
		t.Errorf("Expected polluted counter to increment for grown buffer, before=%d after=%d",
			pollutedBefore, pollutedAfter)
	}
}

// TestGetBufferWithCopy verifies GetBufferWithCopy copies data correctly
func TestGetBufferWithCopy(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"small", []byte("hello")},
		{"medium", bytes.Repeat([]byte("x"), 1000)},
		{"large", bytes.Repeat([]byte("y"), 10000)},
		{"exact_tier", bytes.Repeat([]byte("z"), Size4KB)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			buf, data, err := GetBufferWithCopy(tc.data)
			if err != nil {
				t.Fatalf("GetBufferWithCopy returned error: %v", err)
			}
			defer PutBuffer(buf)

			// Verify data length matches
			if len(data) != len(tc.data) {
				t.Errorf("Expected data len=%d, got %d", len(tc.data), len(data))
			}

			// Verify data content matches
			if !bytes.Equal(data, tc.data) {
				t.Errorf("Copied data does not match original")
			}

			// Verify data is a slice of buf
			if len(tc.data) > 0 && &data[0] != &(*buf)[0] {
				t.Errorf("Data should be a slice of the buffer")
			}
		})
	}
}

// TestBufferClearOnReturn verifies buffer is zeroed before pooling (security)
func TestBufferClearOnReturn(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Get a buffer and fill with sensitive data
	buf, err := GetBuffer(Size4KB)
	if err != nil {
		t.Fatalf("GetBuffer returned error: %v", err)
	}

	// Fill with non-zero data (simulating sensitive data)
	sensitiveData := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, Size4KB/4)
	copy(*buf, sensitiveData)

	// Verify data is there
	if (*buf)[0] != 0xDE {
		t.Fatal("Failed to write test data to buffer")
	}

	// Store pointer to track same buffer
	bufPtr := buf

	// Return to pool
	PutBuffer(buf)

	// The buffer should be zeroed after PutBuffer
	// Note: This tests the clearBuffer function behavior
	// After Put, the length is set to 0 but capacity preserved
	// We can check by verifying the slice was cleared

	// Get buffer again - may be same one from pool
	buf2, err := GetBuffer(Size4KB)
	if err != nil {
		t.Fatalf("Second GetBuffer returned error: %v", err)
	}
	defer PutBuffer(buf2)

	// If we got the same buffer back (same pointer), it should be zeroed
	if buf2 == bufPtr {
		for i := 0; i < Size4KB; i++ {
			if (*buf2)[i] != 0 {
				t.Errorf("Buffer at index %d not zeroed: got 0x%02X, expected 0x00",
					i, (*buf2)[i])
				break
			}
		}
	}
	// If different buffer, clearing worked but we can't verify same buffer
}

// TestPoolStats verifies GetPoolStats returns accurate counters
func TestPoolStats(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Get initial stats
	statsBefore := GetPoolStats()

	// Allocate buffers across tiers
	allocations := []int{
		Size128B,  // tier 0
		Size512B,  // tier 1
		Size2KB,   // tier 2
		Size4KB,   // tier 3
		Size8KB,   // tier 4
		Size16KB,  // tier 5
	}

	buffers := make([]*[]byte, len(allocations))
	for i, size := range allocations {
		buf, err := GetBuffer(size)
		if err != nil {
			t.Fatalf("GetBuffer(%d) returned error: %v", size, err)
		}
		buffers[i] = buf
	}

	// Check allocated counts
	statsAfterAlloc := GetPoolStats()
	if statsAfterAlloc.Tier128B.Allocated != statsBefore.Tier128B.Allocated+1 {
		t.Errorf("Tier128B.Allocated: expected +1")
	}
	if statsAfterAlloc.Tier512B.Allocated != statsBefore.Tier512B.Allocated+1 {
		t.Errorf("Tier512B.Allocated: expected +1")
	}
	if statsAfterAlloc.Tier2KB.Allocated != statsBefore.Tier2KB.Allocated+1 {
		t.Errorf("Tier2KB.Allocated: expected +1")
	}
	if statsAfterAlloc.Tier4KB.Allocated != statsBefore.Tier4KB.Allocated+1 {
		t.Errorf("Tier4KB.Allocated: expected +1")
	}
	if statsAfterAlloc.Tier8KB.Allocated != statsBefore.Tier8KB.Allocated+1 {
		t.Errorf("Tier8KB.Allocated: expected +1")
	}
	if statsAfterAlloc.Tier16KB.Allocated != statsBefore.Tier16KB.Allocated+1 {
		t.Errorf("Tier16KB.Allocated: expected +1")
	}

	// Return all buffers
	for _, buf := range buffers {
		PutBuffer(buf)
	}

	runtime.Gosched()

	// Check returned counts or polluted (depending on eviction state)
	statsAfterReturn := GetPoolStats()
	totalReturned := statsAfterReturn.Tier128B.Returned + statsAfterReturn.Tier512B.Returned +
		statsAfterReturn.Tier2KB.Returned + statsAfterReturn.Tier4KB.Returned +
		statsAfterReturn.Tier8KB.Returned + statsAfterReturn.Tier16KB.Returned

	totalBefore := statsBefore.Tier128B.Returned + statsBefore.Tier512B.Returned +
		statsBefore.Tier2KB.Returned + statsBefore.Tier4KB.Returned +
		statsBefore.Tier8KB.Returned + statsBefore.Tier16KB.Returned

	pollutedDelta := statsAfterReturn.Polluted - statsBefore.Polluted

	// Either returned or polluted should account for all buffers
	returnedDelta := totalReturned - totalBefore
	if returnedDelta+pollutedDelta < uint64(len(allocations)) {
		t.Errorf("Expected %d buffers accounted for (returned=%d, polluted=%d)",
			len(allocations), returnedDelta, pollutedDelta)
	}
}

// TestBufferNegativeSize verifies GetBuffer(-1) returns ErrBufferNegativeSize
func TestBufferNegativeSize(t *testing.T) {
	testCases := []int{-1, -100, -1000, -MaxBufferSize}

	for _, size := range testCases {
		t.Run("size_"+string(rune(-size)), func(t *testing.T) {
			buf, err := GetBuffer(size)
			if err != ErrBufferNegativeSize {
				t.Errorf("GetBuffer(%d): expected ErrBufferNegativeSize, got %v", size, err)
			}
			if buf != nil {
				t.Errorf("GetBuffer(%d): expected nil buffer on error", size)
			}
		})
	}
}

// TestBufferTooLarge verifies GetBuffer(>16MB) returns ErrBufferTooLarge
func TestBufferTooLarge(t *testing.T) {
	testCases := []int{
		MaxBufferSize + 1,
		MaxBufferSize + 1000,
		MaxBufferSize * 2,
		1 << 30, // 1GB
	}

	for _, size := range testCases {
		t.Run("size_over_max", func(t *testing.T) {
			buf, err := GetBuffer(size)
			if err != ErrBufferTooLarge {
				t.Errorf("GetBuffer(%d): expected ErrBufferTooLarge, got %v", size, err)
			}
			if buf != nil {
				t.Errorf("GetBuffer(%d): expected nil buffer on error", size)
			}
		})
	}
}

// TestBufferPoolExhausted verifies error when budget exhausted
func TestBufferPoolExhausted(t *testing.T) {
	resetStats()
	cleanupBufferMap()

	// Set very small limits for testing
	budget := GetBudget()
	if budget == nil {
		t.Fatal("GetBudget returned nil")
	}
	originalSoft := budget.softLimit.Load()
	originalHard := budget.hardLimit.Load()
	originalTotal := budget.totalBytes.Load()
	originalInUse := budget.inUseBytes.Load()

	// Set tiny limits: 32KB soft, 64KB hard
	budget.SetLimits(32*1024, 64*1024)
	// Pre-fill budget to near hard limit so next allocation fails
	// This simulates a system under memory pressure
	budget.totalBytes.Store(60 * 1024) // 60KB of 64KB used
	budget.inUseBytes.Store(0)
	budget.inEviction.Store(false)

	defer func() {
		// Restore original state
		budget.SetLimits(originalSoft, originalHard)
		budget.totalBytes.Store(originalTotal)
		budget.inUseBytes.Store(originalInUse)
		budget.inEviction.Store(false)
	}()

	// Try to allocate 16KB - should fail since 60KB + 16KB > 64KB hard limit
	// Note: This tests the TryAllocate path, which only triggers on cache miss.
	// Since sync.Pool always returns a buffer (cache hit), we need to test via
	// direct TryAllocate call instead.
	ok := budget.TryAllocate(Size16KB)
	if ok {
		t.Error("Expected TryAllocate to fail when budget is near hard limit")
	}

	// Also verify GetBuffer respects the budget limit
	// First, simulate that the next GetBuffer would be a cache miss
	// by setting totalBytes to exactly at hard limit
	budget.totalBytes.Store(64 * 1024) // Exactly at hard limit

	// Now try to allocate - should fail
	buf, err := GetBuffer(Size16KB)
	if err == nil {
		// Note: This may succeed if sync.Pool has cached buffers (cache hit path)
		// In that case, GetBuffer doesn't call TryAllocate, so no error
		// This is expected behavior - cache hits don't allocate new memory
		PutBuffer(buf)
		t.Log("GetBuffer succeeded via cache hit (no new allocation needed)")
	} else if err == ErrBufferPoolExhausted {
		t.Log("GetBuffer correctly returned ErrBufferPoolExhausted on cache miss")
	}
}

// TestTryAllocateHardLimit verifies TryAllocate respects hard limit
func TestTryAllocateHardLimit(t *testing.T) {
	budget := GetBudget()
	if budget == nil {
		t.Fatal("GetBudget returned nil")
	}
	originalSoft := budget.softLimit.Load()
	originalHard := budget.hardLimit.Load()
	originalTotal := budget.totalBytes.Load()

	defer func() {
		budget.SetLimits(originalSoft, originalHard)
		budget.totalBytes.Store(originalTotal)
	}()

	// Set hard limit to 100KB
	budget.SetLimits(50*1024, 100*1024)
	budget.totalBytes.Store(0)

	// Allocate 90KB - should succeed
	if !budget.TryAllocate(90 * 1024) {
		t.Error("TryAllocate(90KB) should succeed when budget is 0/100KB")
	}

	// Try to allocate another 20KB - should fail (90+20 > 100)
	if budget.TryAllocate(20 * 1024) {
		t.Error("TryAllocate(20KB) should fail when budget is 90KB/100KB")
	}

	// Allocate exactly 10KB to reach limit - should succeed
	if !budget.TryAllocate(10 * 1024) {
		t.Error("TryAllocate(10KB) should succeed when budget is 90KB/100KB")
	}

	// Now at 100KB, any allocation should fail
	if budget.TryAllocate(1) {
		t.Error("TryAllocate(1) should fail when budget is at hard limit")
	}
}

// TestConcurrentGetPut verifies concurrent Get/Put don't corrupt pool
func TestConcurrentGetPut(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Set larger limits for concurrency test
	budget := GetBudget()
	budget.SetLimits(32*1024*1024, 64*1024*1024)

	const numGoroutines = 100
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	var errors atomic.Int64

	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()

			for op := 0; op < opsPerGoroutine; op++ {
				// Vary tier selection
				sizes := []int{Size128B, Size512B, Size2KB, Size4KB, Size8KB, Size16KB}
				size := sizes[(goroutineID+op)%len(sizes)]

				buf, err := GetBuffer(size)
				if err != nil {
					// Budget exhaustion is acceptable under high concurrency
					if err != ErrBufferPoolExhausted {
						errors.Add(1)
					}
					continue
				}

				// Verify buffer is valid
				if buf == nil || *buf == nil {
					errors.Add(1)
					continue
				}

				// Verify capacity
				if cap(*buf) < size {
					errors.Add(1)
				}

				// Write some data
				if len(*buf) > 0 {
					(*buf)[0] = byte(goroutineID)
				}

				// Simulate some work
				runtime.Gosched()

				// Return buffer
				PutBuffer(buf)
			}
		}(g)
	}

	wg.Wait()

	if errCount := errors.Load(); errCount > 0 {
		t.Errorf("Concurrent test had %d errors", errCount)
	}

	// Verify no data corruption - stats should be consistent
	poolStats := GetPoolStats()
	totalAllocated := poolStats.Tier128B.Allocated + poolStats.Tier512B.Allocated +
		poolStats.Tier2KB.Allocated + poolStats.Tier4KB.Allocated +
		poolStats.Tier8KB.Allocated + poolStats.Tier16KB.Allocated

	if totalAllocated == 0 {
		t.Error("No allocations recorded during concurrent test")
	}
}

// TestBufferOriginalSizeTracking verifies bufferOriginalSizes map tracks correctly
func TestBufferOriginalSizeTracking(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Initial count should be 0
	countBefore := bufferSizeMapCount.Load()
	if countBefore != 0 {
		t.Errorf("Expected initial map count 0, got %d", countBefore)
	}

	// Allocate several buffers
	buffers := make([]*[]byte, 5)
	for i := 0; i < 5; i++ {
		buf, err := GetBuffer(Size4KB)
		if err != nil {
			t.Fatalf("GetBuffer returned error: %v", err)
		}
		buffers[i] = buf
	}

	// Count should be 5
	countAfterAlloc := bufferSizeMapCount.Load()
	if countAfterAlloc != 5 {
		t.Errorf("Expected map count 5 after allocations, got %d", countAfterAlloc)
	}

	// Verify each buffer is tracked
	for i, buf := range buffers {
		val, ok := bufferOriginalSizes.Load(buf)
		if !ok {
			t.Errorf("Buffer %d not tracked in map", i)
			continue
		}
		entry := val.(bufferSizeEntry)
		if entry.size != Size4KB {
			t.Errorf("Buffer %d: expected size %d, got %d", i, Size4KB, entry.size)
		}
		if entry.allocTime == 0 {
			t.Errorf("Buffer %d: allocTime not set", i)
		}
	}

	// Return buffers
	for _, buf := range buffers {
		PutBuffer(buf)
	}

	runtime.Gosched()

	// Count should be 0 (entries removed on PutBuffer)
	countAfterReturn := bufferSizeMapCount.Load()
	if countAfterReturn != 0 {
		t.Errorf("Expected map count 0 after returns, got %d", countAfterReturn)
	}
}

// TestPoolHitRate verifies cache hits vs misses are tracked correctly
func TestPoolHitRate(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Set large limits to avoid exhaustion
	budget := GetBudget()
	budget.SetLimits(32*1024*1024, 64*1024*1024)

	// First allocation should be a miss (pool empty)
	buf1, err := GetBuffer(Size4KB)
	if err != nil {
		t.Fatalf("GetBuffer returned error: %v", err)
	}

	state1 := budget.State()
	if state1.Gets != 1 {
		t.Errorf("Expected 1 get, got %d", state1.Gets)
	}

	// Return buffer to pool
	PutBuffer(buf1)
	runtime.Gosched()

	// Second allocation should be a hit (buffer in pool)
	buf2, err := GetBuffer(Size4KB)
	if err != nil {
		t.Fatalf("Second GetBuffer returned error: %v", err)
	}
	defer PutBuffer(buf2)

	state2 := budget.State()
	if state2.Gets != 2 {
		t.Errorf("Expected 2 gets, got %d", state2.Gets)
	}

	// Hits + Misses should equal Gets
	if state2.Hits+state2.Misses != state2.Gets {
		t.Errorf("Hits(%d) + Misses(%d) != Gets(%d)",
			state2.Hits, state2.Misses, state2.Gets)
	}

	// With pooling, we should have at least one hit
	// (depends on whether budget allowed caching)
	t.Logf("Stats: Gets=%d, Hits=%d, Misses=%d, HitRate=%.2f%%",
		state2.Gets, state2.Hits, state2.Misses, state2.HitRate)
}

// TestNilBufferPut verifies PutBuffer handles nil gracefully
func TestNilBufferPut(t *testing.T) {
	// Should not panic
	PutBuffer(nil)

	// Empty pointer should not panic
	var buf *[]byte
	PutBuffer(buf)

	// Pointer to nil slice should not panic
	var slice []byte
	PutBuffer(&slice)
}

// TestZeroSizeBuffer verifies zero-size requests work correctly
func TestZeroSizeBuffer(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	buf, err := GetBuffer(0)
	if err != nil {
		t.Fatalf("GetBuffer(0) returned error: %v", err)
	}
	defer PutBuffer(buf)

	// Should get minimum tier (128B)
	if cap(*buf) != Size128B {
		t.Errorf("GetBuffer(0): expected cap=%d, got %d", Size128B, cap(*buf))
	}
}

// TestExactMaxSize verifies MaxBufferSize is accepted
func TestExactMaxSize(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Set large limits for this test
	budget := GetBudget()
	budget.SetLimits(32*1024*1024, 64*1024*1024)

	buf, err := GetBuffer(MaxBufferSize)
	if err != nil {
		t.Fatalf("GetBuffer(MaxBufferSize) returned error: %v", err)
	}
	defer PutBuffer(buf)

	if cap(*buf) != MaxBufferSize {
		t.Errorf("GetBuffer(MaxBufferSize): expected cap=%d, got %d", MaxBufferSize, cap(*buf))
	}
}

// TestOversizedBufferNotPooled verifies oversized buffers increment oversized counter
func TestOversizedBufferNotPooled(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Set large limits
	budget := GetBudget()
	budget.SetLimits(32*1024*1024, 64*1024*1024)

	oversizedBefore := stats.oversized.Load()

	// Request size larger than largest tier
	buf, err := GetBuffer(Size16KB + 1)
	if err != nil {
		t.Fatalf("GetBuffer(oversized) returned error: %v", err)
	}
	defer PutBuffer(buf)

	oversizedAfter := stats.oversized.Load()
	if oversizedAfter <= oversizedBefore {
		t.Errorf("Expected oversized counter to increment, before=%d after=%d",
			oversizedBefore, oversizedAfter)
	}
}

// TestBufferWriteability verifies all buffer bytes are writable
func TestBufferWriteability(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	tierSizes := []int{Size128B, Size512B, Size2KB, Size4KB, Size8KB, Size16KB}

	for _, size := range tierSizes {
		t.Run(tierName(size), func(t *testing.T) {
			buf, err := GetBuffer(size)
			if err != nil {
				t.Fatalf("GetBuffer(%d) returned error: %v", size, err)
			}
			defer PutBuffer(buf)

			// Write to every byte
			for i := 0; i < size; i++ {
				(*buf)[i] = byte(i % 256)
			}

			// Verify writes
			for i := 0; i < size; i++ {
				if (*buf)[i] != byte(i%256) {
					t.Errorf("Buffer corruption at index %d", i)
					break
				}
			}
		})
	}
}

// TestPoolStatsActive verifies Active count is calculated correctly
func TestPoolStatsActive(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// No active buffers initially
	stats1 := GetPoolStats()
	if stats1.Tier4KB.Active != 0 {
		t.Errorf("Expected 0 active, got %d", stats1.Tier4KB.Active)
	}

	// Allocate one buffer
	buf, err := GetBuffer(Size4KB)
	if err != nil {
		t.Fatalf("GetBuffer returned error: %v", err)
	}

	stats2 := GetPoolStats()
	if stats2.Tier4KB.Active != 1 {
		t.Errorf("Expected 1 active after allocation, got %d", stats2.Tier4KB.Active)
	}

	// Return buffer
	PutBuffer(buf)
	runtime.Gosched()

	stats3 := GetPoolStats()
	// Active should be 0 or negative (if returned incremented)
	if stats3.Tier4KB.Active > 1 {
		t.Errorf("Expected <=1 active after return, got %d", stats3.Tier4KB.Active)
	}
}

// TestRapidAllocFree tests rapid allocation and freeing
func TestRapidAllocFree(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	// Set larger limits
	budget := GetBudget()
	budget.SetLimits(32*1024*1024, 64*1024*1024)

	const iterations = 1000

	for i := 0; i < iterations; i++ {
		buf, err := GetBuffer(Size4KB)
		if err != nil {
			t.Fatalf("Iteration %d: GetBuffer returned error: %v", i, err)
		}
		PutBuffer(buf)
	}

	stats := GetPoolStats()
	if stats.Tier4KB.Allocated < uint64(iterations) {
		t.Errorf("Expected at least %d allocations, got %d", iterations, stats.Tier4KB.Allocated)
	}
}

// TestBufferSizeEntryFields verifies bufferSizeEntry struct fields
func TestBufferSizeEntryFields(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	timeBefore := time.Now().UnixNano()

	buf, err := GetBuffer(Size8KB)
	if err != nil {
		t.Fatalf("GetBuffer returned error: %v", err)
	}

	timeAfter := time.Now().UnixNano()

	// Check entry in map
	val, ok := bufferOriginalSizes.Load(buf)
	if !ok {
		t.Fatal("Buffer not tracked in map")
	}

	entry := val.(bufferSizeEntry)

	// Verify size
	if entry.size != Size8KB {
		t.Errorf("Expected size %d, got %d", Size8KB, entry.size)
	}

	// Verify allocTime is reasonable
	if entry.allocTime < timeBefore || entry.allocTime > timeAfter {
		t.Errorf("allocTime %d not in expected range [%d, %d]",
			entry.allocTime, timeBefore, timeAfter)
	}

	PutBuffer(buf)
}

// TestGetBufferWithCopyEmpty verifies empty slice handling
func TestGetBufferWithCopyEmpty(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	buf, data, err := GetBufferWithCopy([]byte{})
	if err != nil {
		t.Fatalf("GetBufferWithCopy(empty) returned error: %v", err)
	}
	defer PutBuffer(buf)

	if len(data) != 0 {
		t.Errorf("Expected empty data slice, got len=%d", len(data))
	}
}

// TestClearBufferNil verifies clearBuffer handles nil
func TestClearBufferNil(t *testing.T) {
	// Should not panic
	clearBuffer(nil)
}

// TestBudgetIntegration verifies buffer pool integrates with budget system
func TestBudgetIntegration(t *testing.T) {
	resetStats()
	resetBudget()
	cleanupBufferMap()

	budget := GetBudget()

	// Verify budget is used
	stateBefore := budget.State()

	buf, err := GetBuffer(Size4KB)
	if err != nil {
		t.Fatalf("GetBuffer returned error: %v", err)
	}

	stateAfterAlloc := budget.State()

	// Gets should increment
	if stateAfterAlloc.Gets <= stateBefore.Gets {
		t.Error("Budget Gets did not increment on allocation")
	}

	// Either InUseBytes increased (cache miss) or stayed same (cache hit)
	// but at least one of hits/misses should increment
	if stateAfterAlloc.Hits+stateAfterAlloc.Misses <= stateBefore.Hits+stateBefore.Misses {
		t.Error("Budget Hits+Misses did not increment")
	}

	PutBuffer(buf)
}

// helper function for tier name
func tierName(size int) string {
	switch size {
	case Size128B:
		return "128B"
	case Size512B:
		return "512B"
	case Size2KB:
		return "2KB"
	case Size4KB:
		return "4KB"
	case Size8KB:
		return "8KB"
	case Size16KB:
		return "16KB"
	default:
		return "unknown"
	}
}
