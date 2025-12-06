package memcontrol

import (
	"sync"
	"sync/atomic"
	"time"
)

// Registry tracks all managed connections for resource management.
// Used by the buffer budget to shed connections under memory pressure.
type Registry struct {
	mu    sync.RWMutex
	conns map[uint64]*Conn

	// Fast count without lock
	count atomic.Int32

	// Per-tag counts
	tagsMu sync.RWMutex
	byTag  map[string]*atomic.Int32

	// Lifetime stats
	totalAccepted atomic.Uint64
	totalClosed   atomic.Uint64
	totalShed     atomic.Uint64
}

var globalRegistry = &Registry{
	conns: make(map[uint64]*Conn),
	byTag: make(map[string]*atomic.Int32),
}

// GetRegistry returns the global connection registry.
func GetRegistry() *Registry {
	return globalRegistry
}

func (r *Registry) register(c *Conn) {
	r.mu.Lock()
	r.conns[c.id] = c
	r.count.Add(1) // Move inside lock to prevent race
	r.mu.Unlock()

	// totalAccepted outside lock is OK (monotonic counter, no race consequences)
	r.totalAccepted.Add(1)

	// Update per-tag count
	r.tagsMu.Lock()
	counter, ok := r.byTag[c.tag]
	if !ok {
		counter = &atomic.Int32{}
		r.byTag[c.tag] = counter
	}
	counter.Add(1) // Move inside lock to prevent race
	r.tagsMu.Unlock()
}

func (r *Registry) unregister(id uint64) {
	r.mu.Lock()
	c, ok := r.conns[id]
	if ok {
		delete(r.conns, id)
		r.count.Add(-1) // Move inside lock to prevent race
	}
	r.mu.Unlock()

	if ok {
		// totalClosed outside lock is OK (monotonic counter)
		r.totalClosed.Add(1)

		// Update per-tag count and cleanup if zero
		r.tagsMu.Lock()
		if counter, exists := r.byTag[c.tag]; exists {
			newCount := counter.Add(-1)
			// Cleanup: remove entry if count reached zero to prevent memory leak
			if newCount <= 0 {
				delete(r.byTag, c.tag)
			}
		}
		r.tagsMu.Unlock()
	}
}

// Count returns the number of active connections.
func (r *Registry) Count() int32 {
	return r.count.Load()
}

// CountByTag returns connections for a specific inbound tag.
func (r *Registry) CountByTag(tag string) int32 {
	r.tagsMu.RLock()
	counter, ok := r.byTag[tag]
	r.tagsMu.RUnlock()

	if !ok {
		return 0
	}
	return counter.Load()
}

// CloseIdle closes connections idle longer than maxIdle.
// Returns the number of connections closed.
func (r *Registry) CloseIdle(maxIdle time.Duration) int {
	r.mu.RLock()
	var toClose []*Conn
	for _, c := range r.conns {
		if c.IdleDuration() > maxIdle {
			toClose = append(toClose, c)
		}
	}
	r.mu.RUnlock()

	// Only count connections we actually close (skip already-closed ones)
	closed := 0
	for _, c := range toClose {
		if !c.IsClosed() {
			logDebug("closing idle connection: id=%d tag=%s idle=%v",
				c.ID(), c.Tag(), c.IdleDuration())
			c.Close()
			closed++
		}
	}

	if closed > 0 {
		r.totalShed.Add(uint64(closed))
		logInfo("shed %d idle connections (threshold: %v)", closed, maxIdle)
	}
	return closed
}

// CloseSlowReaders closes connections with pending bytes over threshold.
// High pending bytes indicate the remote end isn't reading fast enough.
// Returns the number of connections closed.
func (r *Registry) CloseSlowReaders(maxPending int64) int {
	r.mu.RLock()
	var toClose []*Conn
	for _, c := range r.conns {
		if c.PendingBytes() > maxPending {
			toClose = append(toClose, c)
		}
	}
	r.mu.RUnlock()

	// Only count connections we actually close (skip already-closed ones)
	closed := 0
	for _, c := range toClose {
		if !c.IsClosed() {
			logDebug("closing slow reader: id=%d tag=%s pending=%dKB",
				c.ID(), c.Tag(), c.PendingBytes()/1024)
			c.Close()
			closed++
		}
	}

	if closed > 0 {
		r.totalShed.Add(uint64(closed))
		logInfo("shed %d slow reader connections (threshold: %dKB)", closed, maxPending/1024)
	}
	return closed
}

// Shed closes idle and slow connections.
// Called by buffer budget when entering eviction state.
// Uses conservative defaults: 30s idle, 64KB pending.
func (r *Registry) Shed() {
	// Close connections idle > 30 seconds
	r.CloseIdle(30 * time.Second)

	// Close slow readers with > 64KB pending
	r.CloseSlowReaders(64 * 1024)
}

// ShedAggressive performs more aggressive shedding under high pressure.
// Uses tighter thresholds: 10s idle, 16KB pending.
func (r *Registry) ShedAggressive() {
	r.CloseIdle(10 * time.Second)
	r.CloseSlowReaders(16 * 1024)
}

// RegistryState contains registry statistics snapshot.
type RegistryState struct {
	Active        int32
	TotalAccepted uint64
	TotalClosed   uint64
	TotalShed     uint64
	ByTag         map[string]int32
}

// State returns current registry state.
func (r *Registry) State() RegistryState {
	r.tagsMu.RLock()
	byTag := make(map[string]int32, len(r.byTag))
	for tag, counter := range r.byTag {
		count := counter.Load()
		if count > 0 {
			byTag[tag] = count
		}
	}
	r.tagsMu.RUnlock()

	return RegistryState{
		Active:        r.count.Load(),
		TotalAccepted: r.totalAccepted.Load(),
		TotalClosed:   r.totalClosed.Load(),
		TotalShed:     r.totalShed.Load(),
		ByTag:         byTag,
	}
}

// ForEach iterates over all connections with the given function.
// The function MAY call c.Close() or other methods that modify the registry.
// To prevent deadlock, we collect a snapshot first, then iterate without holding locks.
func (r *Registry) ForEach(fn func(*Conn)) {
	// Collect snapshot of connections
	r.mu.RLock()
	snapshot := make([]*Conn, 0, len(r.conns))
	for _, c := range r.conns {
		snapshot = append(snapshot, c)
	}
	r.mu.RUnlock()

	// Now safe to call user function (can call Close() without deadlock)
	for _, c := range snapshot {
		fn(c)
	}
}

// Get returns a connection by ID, or nil if not found.
func (r *Registry) Get(id uint64) *Conn {
	r.mu.RLock()
	c := r.conns[id]
	r.mu.RUnlock()
	return c
}
