package memcontrol

import (
	"math"
	"sync/atomic"
)

// Config contains memory limits for TLS connections.
// Lightweight - typically needs 5-20MB for TLS handshakes.
type Config struct {
	// SoftLimit triggers cache eviction (stop caching returned buffers)
	SoftLimit int64

	// HardLimit blocks allocations until space available
	HardLimit int64

	// SessionCacheLimit is max session cache entries (default: 10000)
	SessionCacheLimit int

	// ReplayCacheLimit is max replay cache entries (default: 100000)
	ReplayCacheLimit int

	// Disabled completely disables memory tracking (for testing)
	Disabled bool
}

// DefaultConfig returns conservative defaults.
// Uses 5MB soft / 8MB hard - suitable for constrained systems.
// DEPRECATED: Use ClientConfig() or ServerConfig() instead.
func DefaultConfig() Config {
	return ClientConfig() // Default to client (tighter limits)
}

// ClientConfig returns tight limits for client mode.
// Optimized for routers, mobile devices, embedded systems.
//
// Memory breakdown:
//   - TLS buffers: 2-4MB (handshake buffers)
//   - Session cache: 1-2MB (2000 sessions)
//   - Replay cache: 1-2MB (20000 nonces)
//   - Total: ~5-8MB typical usage
func ClientConfig() Config {
	return Config{
		SoftLimit:         5 * 1024 * 1024,  // 5MB - start shedding
		HardLimit:         8 * 1024 * 1024,  // 8MB - block allocations
		SessionCacheLimit: 2000,             // Small cache for client
		ReplayCacheLimit:  20000,            // Limited anti-replay window
		Disabled:          false,
	}
}

// ServerConfig returns generous limits for server mode.
// Optimized for VPS/dedicated servers handling many connections.
//
// Memory breakdown:
//   - TLS buffers: 20-40MB (many concurrent handshakes)
//   - Session cache: 10-20MB (20000 sessions)
//   - Replay cache: 5-10MB (100000 nonces)
//   - Total: ~35-70MB typical usage
func ServerConfig() Config {
	return Config{
		SoftLimit:         64 * 1024 * 1024,  // 64MB - start shedding
		HardLimit:         96 * 1024 * 1024,  // 96MB - block allocations
		SessionCacheLimit: 20000,             // Large cache for server
		ReplayCacheLimit:  100000,            // Full anti-replay protection
		Disabled:          false,
	}
}

// TinyRouterConfig returns minimal limits for extremely constrained devices.
// For devices with <64MB RAM (OpenWrt routers, IoT devices).
func TinyRouterConfig() Config {
	return Config{
		SoftLimit:         2 * 1024 * 1024,  // 2MB
		HardLimit:         3 * 1024 * 1024,  // 3MB
		SessionCacheLimit: 500,              // Minimal cache
		ReplayCacheLimit:  5000,             // Short replay window
		Disabled:          false,
	}
}

// LargeServerConfig returns very generous limits for powerful servers.
// For dedicated servers with 8GB+ RAM handling 10K+ connections.
func LargeServerConfig() Config {
	return Config{
		SoftLimit:         128 * 1024 * 1024, // 128MB
		HardLimit:         256 * 1024 * 1024, // 256MB
		SessionCacheLimit: 50000,             // Huge cache
		ReplayCacheLimit:  200000,            // Maximum protection
		Disabled:          false,
	}
}

// ConfigureMemory configures memory limits.
// This is the primary integration point for applications.
//
// Example usage:
//
//	memcontrol.ConfigureMemory(memcontrol.Config{
//	    SoftLimit: 10 * 1024 * 1024,  // 10MB
//	    HardLimit: 12 * 1024 * 1024,  // 12MB
//	})
//
// Typical allocations:
//   - Small system (64MB RAM):  5-10MB
//   - Medium system (512MB RAM): 20-32MB
//   - Server (4GB+ RAM):         48-96MB
func ConfigureMemory(cfg Config) {
	// Defensive: Ensure globalMemoryBudget is initialized (should be done by init())
	if globalMemoryBudget == nil {
		panic("memcontrol: globalMemoryBudget not initialized - init() failed")
	}

	if cfg.Disabled {
		globalMemoryBudget.disabled.Store(true)
		globalMemoryBudget.softLimit.Store(1 << 62)
		globalMemoryBudget.hardLimit.Store(1 << 62)
		return
	}

	if cfg.SoftLimit > 0 {
		globalMemoryBudget.softLimit.Store(cfg.SoftLimit)
	}

	if cfg.HardLimit > 0 {
		globalMemoryBudget.hardLimit.Store(cfg.HardLimit)
	}

	// Store cache limits for session/replay caches to use
	// Cap at MaxInt32 to prevent integer truncation on 64-bit systems
	if cfg.SessionCacheLimit > 0 {
		limit := cfg.SessionCacheLimit
		if limit > math.MaxInt32 {
			limit = math.MaxInt32
		}
		sessionCacheLimit.Store(int32(limit))
	}

	if cfg.ReplayCacheLimit > 0 {
		limit := cfg.ReplayCacheLimit
		if limit > math.MaxInt32 {
			limit = math.MaxInt32
		}
		replayCacheLimit.Store(int32(limit))
	}
}

// Global limits for session and replay caches
var (
	sessionCacheLimit atomic.Int32 // Default: 10000
	replayCacheLimit  atomic.Int32 // Default: 100000
)

func init() {
	defaults := DefaultConfig()
	sessionCacheLimit.Store(int32(defaults.SessionCacheLimit))
	replayCacheLimit.Store(int32(defaults.ReplayCacheLimit))
}

// GetSessionCacheLimit returns current session cache entry limit.
func GetSessionCacheLimit() int {
	return int(sessionCacheLimit.Load())
}

// GetReplayCacheLimit returns current replay cache entry limit.
func GetReplayCacheLimit() int {
	return int(replayCacheLimit.Load())
}

// SetEvictionCallback sets function called when memory pressure occurs.
// Applications can use this to trigger connection shedding.
//
// Example:
//
//	memcontrol.SetEvictionCallback(func() {
//	    // Shed idle connections
//	    memcontrol.GetRegistry().Shed()
//	})
func SetEvictionCallback(fn func()) {
	SetGlobalEvictionCallback(fn)
}

// GetBudgetState returns current memory usage statistics.
// Applications can use this for monitoring/diagnostics.
func GetBudgetState() BudgetState {
	return globalMemoryBudget.State()
}

// GetMemoryUsage returns current usage in bytes (for stats APIs).
func GetMemoryUsage() (total, inUse, cached int64) {
	state := globalMemoryBudget.State()
	return state.TotalBytes, state.InUseBytes, state.CachedBytes
}

// IsMemoryPressure returns true if in eviction mode (over soft limit).
func IsMemoryPressure() bool {
	return BudgetIsEvicting()
}

// ============================================================================
// DOWNSTREAM CONFIGURATION API
// ============================================================================
// These functions allow upstream libraries to configure this package's
// memory budget as part of a chain: upstream → this library → downstream
//
// When an upstream library sets memory configuration, this library receives it
// and can also pass a portion downstream for coordinated memory management.
// ============================================================================

// ConfigureFromUpstream configures memory budget from an upstream library.
// This allows upstream to pass its memory configuration downstream.
//
// Example:
//
//	func ConfigureMemory(cfg MemoryConfig) {
//	    // Configure upstream's own memcontrol
//	    memcontrol.ConfigureMemory(cfg)
//
//	    // Pass downstream
//	    downstream_memcontrol.ConfigureFromUpstream(downstream_memcontrol.Config{
//	        SoftLimit: cfg.SoftLimit,
//	        HardLimit: cfg.HardLimit,
//	    })
//	}
func ConfigureFromUpstream(cfg Config) {
	ConfigureMemory(cfg)
	logInfo("configured from upstream: soft=%dMB, hard=%dMB",
		cfg.SoftLimit/(1024*1024), cfg.HardLimit/(1024*1024))
}

// ConfigureFromUpstreamWithPortion configures with a portion of upstream's budget.
// This is useful when this library should have a dedicated slice of the total budget.
//
// Example: upstream has 128MB budget, allocates 32MB downstream:
//
//	downstream_memcontrol.ConfigureFromUpstreamWithPortion(128*MB, 192*MB, 0.25) // 25% = 32MB soft, 48MB hard
func ConfigureFromUpstreamWithPortion(upstreamSoft, upstreamHard int64, portion float64) {
	if portion <= 0 || portion > 1 {
		portion = 0.25 // Default to 25% if invalid
	}
	cfg := Config{
		SoftLimit: int64(float64(upstreamSoft) * portion),
		HardLimit: int64(float64(upstreamHard) * portion),
	}
	ConfigureMemory(cfg)
	logInfo("configured %.0f%% of upstream: soft=%dMB, hard=%dMB",
		portion*100, cfg.SoftLimit/(1024*1024), cfg.HardLimit/(1024*1024))
}

// LinkEvictionCallback links this library's eviction to upstream's eviction callback.
// When this library enters eviction mode, it triggers the upstream callback.
//
// This creates a cascade: this library's pressure → upstream shedding
func LinkEvictionCallback(upstreamCallback func()) {
	SetEvictionCallback(func() {
		// First, shed our own connections
		GetRegistry().Shed()
		// Then notify upstream
		if upstreamCallback != nil {
			upstreamCallback()
		}
	})
}
