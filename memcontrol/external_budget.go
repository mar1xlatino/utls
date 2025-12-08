package memcontrol

import "sync/atomic"

// ExternalBudget is the interface for integrating with an upstream memory budget.
// When set, all memory tracking operations are delegated to the external budget
// instead of using the internal globalMemoryBudget.
//
// This allows an upstream application to provide a single global budget that
// tracks memory across ALL subsystems in ONE place.
//
// Example usage:
//
//	// In application initialization
//	appBudget := buf.GetBudget()
//	memcontrol.UseExternalBudget(&budgetAdapter{appBudget})
//
// The adapter pattern allows the upstream budget to be used without circular imports.
type ExternalBudget interface {
	// TryAllocate attempts to allocate size bytes without blocking.
	// Returns true if allocation succeeded, false if would exceed hard limit.
	TryAllocate(size int64) bool

	// AllocateBlocking blocks until size bytes can be allocated or timeout.
	// Returns true if allocation succeeded, false on timeout.
	AllocateBlocking(size int64, timeoutMs int64) bool

	// MarkInUse records that a cached buffer is now in use.
	// Called on cache hit (no new memory, just moving from cached to in-use).
	MarkInUse(size int64)

	// Release returns size bytes to the budget.
	// Returns true if caller should cache the buffer, false if should evict.
	Release(size int64) bool

	// ForceEvict forcibly removes size bytes from tracking.
	// Used when a buffer is rejected despite Release() returning "cache".
	ForceEvict(size int64)

	// IsEvicting returns true if budget is in eviction mode (above soft limit).
	IsEvicting() bool

	// RecordGet increments the allocation attempt counter.
	RecordGet()

	// RecordHit increments the cache hit counter.
	RecordHit()

	// RecordMiss increments the cache miss counter.
	RecordMiss()

	// SetEvictionCallback sets the function called when entering eviction mode.
	SetEvictionCallback(fn func())
}

// externalBudget holds the external budget if set.
// Uses atomic.Pointer for thread-safe access without locks.
var externalBudget atomic.Pointer[ExternalBudget]

// UseExternalBudget configures this package to use an external budget
// for all memory tracking operations.
//
// When set:
//   - All TryAllocate/Release/etc calls go to external budget
//   - The internal globalMemoryBudget is bypassed
//   - Memory is tracked globally with all other subsystems
//
// Pass nil to revert to internal budget.
//
// This should be called early in initialization, before any buffers
// are allocated.
func UseExternalBudget(budget ExternalBudget) {
	if budget == nil {
		externalBudget.Store(nil)
	} else {
		externalBudget.Store(&budget)
	}
}

// getEffectiveBudget returns the external budget if set, otherwise nil.
// Callers should fall back to globalMemoryBudget if this returns nil.
func getExternalBudget() ExternalBudget {
	ptr := externalBudget.Load()
	if ptr == nil {
		return nil
	}
	return *ptr
}
