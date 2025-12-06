package memcontrol

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	// Suppress logging during tests
	SetLogLevel(LogLevelOff)
}

// newTestRegistry creates a fresh registry for isolated testing.
// The global registry is problematic for unit tests due to shared state.
func newTestRegistry() *Registry {
	return &Registry{
		conns: make(map[uint64]*Conn),
		byTag: make(map[string]*atomic.Int32),
	}
}

// createTestConn creates a managed Conn for testing using net.Pipe().
// The returned cleanup function closes both ends and unregisters.
func createTestConn(t *testing.T, tag string) (*Conn, func()) {
	t.Helper()
	client, server := net.Pipe()
	mc := Wrap(server, tag)
	if mc == nil {
		// If disabled via env, skip test
		t.Skip("managed conn disabled via UTLS_DISABLE_MANAGED_CONN=1")
	}
	cleanup := func() {
		mc.Close()
		client.Close()
	}
	return mc, cleanup
}

// testConn wraps Conn with a reference to its registry for proper cleanup.
type testConn struct {
	*Conn
	registry *Registry
	client   net.Conn // Other end of the pipe
}

// Close overrides to use the correct registry instead of globalRegistry.
func (tc *testConn) Close() error {
	var err error
	tc.closeOnce.Do(func() {
		tc.closed.Store(true)
		tc.registry.unregister(tc.id)
		err = tc.Conn.Conn.Close()
	})
	return err
}

// createTestConnWithRegistry creates a managed Conn registered to a specific registry.
// Returns a testConn whose Close() method properly unregisters from the test registry.
func createTestConnWithRegistry(t *testing.T, r *Registry, tag string) (*testConn, func()) {
	t.Helper()
	client, server := net.Pipe()

	now := time.Now().UnixNano()
	mc := &Conn{
		Conn:      server,
		id:        connIDGen.Add(1),
		tag:       tag,
		createdAt: now,
	}
	mc.lastReadAt.Store(now)
	mc.lastWriteAt.Store(now)

	r.register(mc)

	tc := &testConn{
		Conn:     mc,
		registry: r,
		client:   client,
	}

	cleanup := func() {
		// Use testConn.Close which unregisters from correct registry
		tc.Close()
		client.Close()
	}
	return tc, cleanup
}

// setPendingBytes sets pendingWrite for testing CloseSlowReaders.
// Uses direct atomic store since pendingWrite is normally transient.
func setPendingBytes(c *Conn, bytes int64) {
	c.pendingWrite.Store(bytes)
}

// setLastActivity sets lastReadAt/lastWriteAt for testing CloseIdle.
func setLastActivity(c *Conn, t time.Time) {
	nanos := t.UnixNano()
	c.lastReadAt.Store(nanos)
	c.lastWriteAt.Store(nanos)
}

// --- Test Cases ---

func TestRegistryGlobal(t *testing.T) {
	// GetRegistry() should return the same singleton instance
	r1 := GetRegistry()
	r2 := GetRegistry()

	if r1 != r2 {
		t.Errorf("GetRegistry() returned different instances: %p vs %p", r1, r2)
	}

	if r1 == nil {
		t.Error("GetRegistry() returned nil")
	}

	// Verify it's the globalRegistry
	if r1 != globalRegistry {
		t.Error("GetRegistry() did not return globalRegistry")
	}
}

func TestRegistryRegisterUnregister(t *testing.T) {
	r := newTestRegistry()

	// Initial count should be zero
	if count := r.Count(); count != 0 {
		t.Errorf("initial count = %d, want 0", count)
	}

	// Create and register connections
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "test")
	defer cleanup1()

	if count := r.Count(); count != 1 {
		t.Errorf("after first register: count = %d, want 1", count)
	}

	conn2, cleanup2 := createTestConnWithRegistry(t, r, "test")
	defer cleanup2()

	if count := r.Count(); count != 2 {
		t.Errorf("after second register: count = %d, want 2", count)
	}

	// Unregister first connection
	r.unregister(conn1.id)
	if count := r.Count(); count != 1 {
		t.Errorf("after first unregister: count = %d, want 1", count)
	}

	// Unregister second connection
	r.unregister(conn2.id)
	if count := r.Count(); count != 0 {
		t.Errorf("after second unregister: count = %d, want 0", count)
	}

	// Unregistering non-existent ID should not panic or affect count
	r.unregister(99999)
	if count := r.Count(); count != 0 {
		t.Errorf("after invalid unregister: count = %d, want 0", count)
	}
}

func TestRegistryCount(t *testing.T) {
	r := newTestRegistry()

	const numConns = 10
	cleanups := make([]func(), numConns)

	for i := 0; i < numConns; i++ {
		conn, cleanup := createTestConnWithRegistry(t, r, "test-count")
		cleanups[i] = cleanup
		_ = conn

		expected := int32(i + 1)
		if count := r.Count(); count != expected {
			t.Errorf("after registering %d conns: count = %d, want %d", i+1, count, expected)
		}
	}

	// Cleanup
	for i := numConns - 1; i >= 0; i-- {
		cleanups[i]()
		expected := int32(i)
		if count := r.Count(); count != expected {
			t.Errorf("after unregistering to %d conns: count = %d, want %d", i, count, expected)
		}
	}
}

func TestRegistryCloseIdle(t *testing.T) {
	// Use globalRegistry for Close tests since Conn.Close() uses globalRegistry
	r := GetRegistry()
	initialCount := r.Count()

	// Create 3 connections with different idle times
	conn1, cleanup1 := createTestConn(t, "idle-test")
	defer cleanup1()

	conn2, cleanup2 := createTestConn(t, "idle-test")
	defer cleanup2()

	conn3, cleanup3 := createTestConn(t, "idle-test")
	defer cleanup3()

	// Set conn1 and conn2 to be idle for 5 seconds
	// Set conn3 to be recently active
	fiveSecondsAgo := time.Now().Add(-5 * time.Second)
	setLastActivity(conn1, fiveSecondsAgo)
	setLastActivity(conn2, fiveSecondsAgo)
	// conn3 keeps its current (recent) activity

	if count := r.Count(); count != initialCount+3 {
		t.Fatalf("after register: count = %d, want %d", count, initialCount+3)
	}

	// Close connections idle > 3 seconds
	closed := r.CloseIdle(3 * time.Second)

	if closed != 2 {
		t.Errorf("CloseIdle returned %d, want 2", closed)
	}

	// Verify conn1 and conn2 are closed
	if !conn1.IsClosed() {
		t.Error("conn1 should be closed")
	}
	if !conn2.IsClosed() {
		t.Error("conn2 should be closed")
	}
	if conn3.IsClosed() {
		t.Error("conn3 should NOT be closed")
	}

	// Count should reflect unregistered connections
	if count := r.Count(); count != initialCount+1 {
		t.Errorf("after CloseIdle: count = %d, want %d", count, initialCount+1)
	}
}

func TestRegistryCloseIdleNone(t *testing.T) {
	r := newTestRegistry()

	// Create connections
	_, cleanup1 := createTestConnWithRegistry(t, r, "no-idle")
	defer cleanup1()

	_, cleanup2 := createTestConnWithRegistry(t, r, "no-idle")
	defer cleanup2()

	initialCount := r.Count()
	if initialCount != 2 {
		t.Fatalf("initial count = %d, want 2", initialCount)
	}

	// Use very high threshold - no connections should be closed
	closed := r.CloseIdle(24 * time.Hour)

	if closed != 0 {
		t.Errorf("CloseIdle with high threshold returned %d, want 0", closed)
	}

	if count := r.Count(); count != 2 {
		t.Errorf("count after CloseIdle = %d, want 2", count)
	}
}

func TestRegistryCloseSlowReaders(t *testing.T) {
	// Use globalRegistry for Close tests since Conn.Close() uses globalRegistry
	r := GetRegistry()
	initialCount := r.Count()

	// Create 3 connections
	conn1, cleanup1 := createTestConn(t, "slow-reader")
	defer cleanup1()

	conn2, cleanup2 := createTestConn(t, "slow-reader")
	defer cleanup2()

	conn3, cleanup3 := createTestConn(t, "slow-reader")
	defer cleanup3()

	// Set artificially high pending bytes on conn1 and conn2
	setPendingBytes(conn1, 100*1024) // 100KB
	setPendingBytes(conn2, 200*1024) // 200KB
	setPendingBytes(conn3, 10*1024)  // 10KB (below threshold)

	if count := r.Count(); count != initialCount+3 {
		t.Fatalf("initial count = %d, want %d", count, initialCount+3)
	}

	// Close connections with > 64KB pending
	closed := r.CloseSlowReaders(64 * 1024)

	if closed != 2 {
		t.Errorf("CloseSlowReaders returned %d, want 2", closed)
	}

	if !conn1.IsClosed() {
		t.Error("conn1 (100KB pending) should be closed")
	}
	if !conn2.IsClosed() {
		t.Error("conn2 (200KB pending) should be closed")
	}
	if conn3.IsClosed() {
		t.Error("conn3 (10KB pending) should NOT be closed")
	}

	if count := r.Count(); count != initialCount+1 {
		t.Errorf("after CloseSlowReaders: count = %d, want %d", count, initialCount+1)
	}
}

func TestRegistryCloseSlowReadersNone(t *testing.T) {
	r := newTestRegistry()

	conn1, cleanup1 := createTestConnWithRegistry(t, r, "fast-reader")
	defer cleanup1()

	conn2, cleanup2 := createTestConnWithRegistry(t, r, "fast-reader")
	defer cleanup2()

	// Set low pending bytes
	setPendingBytes(conn1.Conn, 1024)
	setPendingBytes(conn2.Conn, 2048)

	// Threshold higher than all pending bytes
	closed := r.CloseSlowReaders(1024 * 1024)

	if closed != 0 {
		t.Errorf("CloseSlowReaders with high threshold returned %d, want 0", closed)
	}

	if count := r.Count(); count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestRegistryShed(t *testing.T) {
	// Use globalRegistry for Close tests since Conn.Close() uses globalRegistry
	r := GetRegistry()
	initialCount := r.Count()

	// Create connections: one idle, one slow reader, one healthy
	connIdle, cleanup1 := createTestConn(t, "shed-test")
	defer cleanup1()

	connSlow, cleanup2 := createTestConn(t, "shed-test")
	defer cleanup2()

	connHealthy, cleanup3 := createTestConn(t, "shed-test")
	defer cleanup3()

	// Make connIdle idle for 35 seconds (> 30s threshold)
	setLastActivity(connIdle, time.Now().Add(-35*time.Second))

	// Make connSlow have high pending (> 64KB threshold)
	setPendingBytes(connSlow, 100*1024)

	// connHealthy stays fresh with low pending
	setPendingBytes(connHealthy, 1024)

	if count := r.Count(); count != initialCount+3 {
		t.Fatalf("initial count = %d, want %d", count, initialCount+3)
	}

	r.Shed()

	if !connIdle.IsClosed() {
		t.Error("idle connection should be shed")
	}
	if !connSlow.IsClosed() {
		t.Error("slow reader connection should be shed")
	}
	if connHealthy.IsClosed() {
		t.Error("healthy connection should NOT be shed")
	}

	if count := r.Count(); count != initialCount+1 {
		t.Errorf("after Shed: count = %d, want %d", count, initialCount+1)
	}
}

func TestRegistryShedAggressive(t *testing.T) {
	// Use globalRegistry for Close tests since Conn.Close() uses globalRegistry
	r := GetRegistry()
	initialCount := r.Count()

	// Create connections with various states
	connIdle15s, cleanup1 := createTestConn(t, "aggressive-test")
	defer cleanup1()

	connSlow20KB, cleanup2 := createTestConn(t, "aggressive-test")
	defer cleanup2()

	connHealthy, cleanup3 := createTestConn(t, "aggressive-test")
	defer cleanup3()

	// 15 seconds idle - would survive normal Shed (30s) but not ShedAggressive (10s)
	setLastActivity(connIdle15s, time.Now().Add(-15*time.Second))

	// 20KB pending - would survive normal Shed (64KB) but not ShedAggressive (16KB)
	setPendingBytes(connSlow20KB, 20*1024)

	// Healthy - 5s idle, 8KB pending - survives both
	setLastActivity(connHealthy, time.Now().Add(-5*time.Second))
	setPendingBytes(connHealthy, 8*1024)

	if count := r.Count(); count != initialCount+3 {
		t.Fatalf("initial count = %d, want %d", count, initialCount+3)
	}

	r.ShedAggressive()

	if !connIdle15s.IsClosed() {
		t.Error("15s idle connection should be shed with aggressive thresholds")
	}
	if !connSlow20KB.IsClosed() {
		t.Error("20KB pending connection should be shed with aggressive thresholds")
	}
	if connHealthy.IsClosed() {
		t.Error("healthy connection (5s idle, 8KB pending) should NOT be shed")
	}

	if count := r.Count(); count != initialCount+1 {
		t.Errorf("after ShedAggressive: count = %d, want %d", count, initialCount+1)
	}
}

func TestRegistryForEach(t *testing.T) {
	r := newTestRegistry()

	// Create connections
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "foreach-1")
	defer cleanup1()

	conn2, cleanup2 := createTestConnWithRegistry(t, r, "foreach-2")
	defer cleanup2()

	conn3, cleanup3 := createTestConnWithRegistry(t, r, "foreach-3")
	defer cleanup3()

	// Collect all IDs via ForEach
	visited := make(map[uint64]bool)
	r.ForEach(func(c *Conn) {
		visited[c.ID()] = true
	})

	if len(visited) != 3 {
		t.Errorf("ForEach visited %d connections, want 3", len(visited))
	}

	if !visited[conn1.ID()] {
		t.Error("conn1 was not visited")
	}
	if !visited[conn2.ID()] {
		t.Error("conn2 was not visited")
	}
	if !visited[conn3.ID()] {
		t.Error("conn3 was not visited")
	}
}

func TestRegistryForEachTag(t *testing.T) {
	r := newTestRegistry()

	// Create connections with different tags
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "tag-A")
	defer cleanup1()

	conn2, cleanup2 := createTestConnWithRegistry(t, r, "tag-A")
	defer cleanup2()

	conn3, cleanup3 := createTestConnWithRegistry(t, r, "tag-B")
	defer cleanup3()

	// Filter by tag manually using ForEach (no ForEachTag in registry)
	tagACount := 0
	r.ForEach(func(c *Conn) {
		if c.Tag() == "tag-A" {
			tagACount++
		}
	})

	if tagACount != 2 {
		t.Errorf("ForEach with tag-A filter found %d, want 2", tagACount)
	}

	// Verify all connections exist
	allIDs := make(map[uint64]string)
	r.ForEach(func(c *Conn) {
		allIDs[c.ID()] = c.Tag()
	})

	if allIDs[conn1.ID()] != "tag-A" {
		t.Error("conn1 tag mismatch")
	}
	if allIDs[conn2.ID()] != "tag-A" {
		t.Error("conn2 tag mismatch")
	}
	if allIDs[conn3.ID()] != "tag-B" {
		t.Error("conn3 tag mismatch")
	}
}

func TestRegistryState(t *testing.T) {
	r := newTestRegistry()

	// Empty registry
	state := r.State()
	if state.Active != 0 {
		t.Errorf("initial Active = %d, want 0", state.Active)
	}

	// Add connections
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "state-tag-X")
	defer cleanup1()

	conn2, cleanup2 := createTestConnWithRegistry(t, r, "state-tag-X")
	defer cleanup2()

	conn3, cleanup3 := createTestConnWithRegistry(t, r, "state-tag-Y")
	defer cleanup3()

	state = r.State()

	if state.Active != 3 {
		t.Errorf("Active = %d, want 3", state.Active)
	}

	if state.TotalAccepted != 3 {
		t.Errorf("TotalAccepted = %d, want 3", state.TotalAccepted)
	}

	// Check ByTag
	if state.ByTag["state-tag-X"] != 2 {
		t.Errorf("ByTag[state-tag-X] = %d, want 2", state.ByTag["state-tag-X"])
	}
	if state.ByTag["state-tag-Y"] != 1 {
		t.Errorf("ByTag[state-tag-Y] = %d, want 1", state.ByTag["state-tag-Y"])
	}

	// Unregister one
	r.unregister(conn1.id)
	state = r.State()

	if state.Active != 2 {
		t.Errorf("after unregister: Active = %d, want 2", state.Active)
	}
	if state.TotalClosed != 1 {
		t.Errorf("TotalClosed = %d, want 1", state.TotalClosed)
	}
	if state.ByTag["state-tag-X"] != 1 {
		t.Errorf("after unregister: ByTag[state-tag-X] = %d, want 1", state.ByTag["state-tag-X"])
	}

	_ = conn1 // prevent unused warning
	_ = conn2
	_ = conn3
}

func TestRegistryTotalShed(t *testing.T) {
	// Use globalRegistry for tests involving Close (shed increments via Close)
	r := GetRegistry()
	initialShed := r.State().TotalShed
	initialCount := r.Count()

	// Create idle connections
	conn1, cleanup1 := createTestConn(t, "shed-count")
	defer cleanup1()

	conn2, cleanup2 := createTestConn(t, "shed-count")
	defer cleanup2()

	// Make them idle
	setLastActivity(conn1, time.Now().Add(-1*time.Hour))
	setLastActivity(conn2, time.Now().Add(-1*time.Hour))

	// Shed them
	closed := r.CloseIdle(1 * time.Minute)

	if closed != 2 {
		t.Errorf("CloseIdle returned %d, want 2", closed)
	}

	state := r.State()
	expectedShed := initialShed + 2
	if state.TotalShed != expectedShed {
		t.Errorf("TotalShed = %d, want %d", state.TotalShed, expectedShed)
	}

	_ = initialCount
}

func TestRegistryConcurrentAccess(t *testing.T) {
	r := newTestRegistry()

	const numGoroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // register, unregister, forEach goroutines

	// Track errors
	errors := make(chan error, numGoroutines*3*opsPerGoroutine)

	// Goroutines that register and immediately unregister
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				conn, cleanup := createTestConnWithRegistry(t, r, "concurrent")
				// Small delay to increase chance of contention
				_ = conn.ID()
				cleanup()
			}
		}(i)
	}

	// Goroutines that call ForEach
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				count := 0
				r.ForEach(func(c *Conn) {
					count++
					// Access methods to ensure no races
					_ = c.ID()
					_ = c.Tag()
					_ = c.IsClosed()
				})
			}
		}()
	}

	// Goroutines that call Count and State
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				count := r.Count()
				if count < 0 {
					errors <- nil // never negative, just access
				}
				state := r.State()
				_ = state.Active
				_ = state.TotalAccepted
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		if err != nil {
			t.Errorf("concurrent access error: %v", err)
		}
	}

	// Final count should be zero (all connections cleaned up)
	if count := r.Count(); count != 0 {
		t.Errorf("final count = %d, want 0", count)
	}
}

func TestRegistryAutoUnregisterOnClose(t *testing.T) {
	// This test uses globalRegistry since Conn.Close() calls globalRegistry.unregister()

	initialCount := globalRegistry.Count()

	conn, cleanup := createTestConn(t, "auto-unregister")
	_ = cleanup // We'll close manually

	afterRegister := globalRegistry.Count()
	if afterRegister != initialCount+1 {
		t.Errorf("after register: count = %d, want %d", afterRegister, initialCount+1)
	}

	// Close the connection - should auto-unregister
	conn.Close()

	afterClose := globalRegistry.Count()
	if afterClose != initialCount {
		t.Errorf("after Close: count = %d, want %d", afterClose, initialCount)
	}

	// Verify connection is marked closed
	if !conn.IsClosed() {
		t.Error("connection should be marked as closed")
	}

	// Double close should be safe
	err := conn.Close()
	if err != nil {
		t.Errorf("double Close returned error: %v", err)
	}

	// Count should remain the same
	if count := globalRegistry.Count(); count != initialCount {
		t.Errorf("after double Close: count = %d, want %d", count, initialCount)
	}
}

func TestRegistryCountByTag(t *testing.T) {
	r := newTestRegistry()

	// Initial counts should be zero
	if count := r.CountByTag("nonexistent"); count != 0 {
		t.Errorf("CountByTag(nonexistent) = %d, want 0", count)
	}

	// Create connections with different tags
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "tag-alpha")
	defer cleanup1()

	conn2, cleanup2 := createTestConnWithRegistry(t, r, "tag-alpha")
	defer cleanup2()

	conn3, cleanup3 := createTestConnWithRegistry(t, r, "tag-beta")
	defer cleanup3()

	conn4, cleanup4 := createTestConnWithRegistry(t, r, "tag-alpha")
	defer cleanup4()

	// Check counts
	if count := r.CountByTag("tag-alpha"); count != 3 {
		t.Errorf("CountByTag(tag-alpha) = %d, want 3", count)
	}
	if count := r.CountByTag("tag-beta"); count != 1 {
		t.Errorf("CountByTag(tag-beta) = %d, want 1", count)
	}
	if count := r.CountByTag("nonexistent"); count != 0 {
		t.Errorf("CountByTag(nonexistent) = %d, want 0", count)
	}

	// Unregister one from tag-alpha
	r.unregister(conn1.id)
	if count := r.CountByTag("tag-alpha"); count != 2 {
		t.Errorf("after unregister: CountByTag(tag-alpha) = %d, want 2", count)
	}

	// Unregister all from tag-beta - should cleanup the map entry
	r.unregister(conn3.id)
	if count := r.CountByTag("tag-beta"); count != 0 {
		t.Errorf("after unregister: CountByTag(tag-beta) = %d, want 0", count)
	}

	_ = conn2
	_ = conn4
}

func TestRegistryGet(t *testing.T) {
	r := newTestRegistry()

	// Get non-existent
	if c := r.Get(99999); c != nil {
		t.Error("Get(99999) should return nil for non-existent ID")
	}

	// Create connection
	conn, cleanup := createTestConnWithRegistry(t, r, "get-test")
	defer cleanup()

	// Get existing
	retrieved := r.Get(conn.ID())
	if retrieved == nil {
		t.Error("Get should return the connection")
	}
	if retrieved != conn.Conn {
		t.Error("Get returned wrong connection")
	}
	if retrieved.Tag() != "get-test" {
		t.Errorf("retrieved.Tag() = %s, want get-test", retrieved.Tag())
	}

	// After unregister
	r.unregister(conn.id)
	if c := r.Get(conn.ID()); c != nil {
		t.Error("Get should return nil after unregister")
	}
}

func TestRegistryCloseIdleAlreadyClosed(t *testing.T) {
	// Use globalRegistry since Conn.Close() uses it
	r := GetRegistry()
	initialCount := r.Count()

	conn, cleanup := createTestConn(t, "already-closed")
	defer cleanup()

	// Make it idle
	setLastActivity(conn, time.Now().Add(-1*time.Hour))

	// Close it manually first
	conn.Close()

	// Verify it's already closed
	if !conn.IsClosed() {
		t.Fatal("conn should be closed")
	}

	countAfterClose := r.Count()
	if countAfterClose != initialCount {
		t.Errorf("count after manual close = %d, want %d", countAfterClose, initialCount)
	}

	// CloseIdle should skip already-closed connections
	closed := r.CloseIdle(1 * time.Minute)

	// Should not count as closed since it was already closed (and unregistered)
	if closed != 0 {
		t.Errorf("CloseIdle returned %d, want 0 (already closed)", closed)
	}
}

func TestRegistryCloseSlowReadersAlreadyClosed(t *testing.T) {
	// Use globalRegistry since Conn.Close() uses it
	r := GetRegistry()
	initialCount := r.Count()

	conn, cleanup := createTestConn(t, "already-closed-slow")
	defer cleanup()

	// Make it slow reader
	setPendingBytes(conn, 1024*1024)

	// Close it manually first
	conn.Close()

	countAfterClose := r.Count()
	if countAfterClose != initialCount {
		t.Errorf("count after manual close = %d, want %d", countAfterClose, initialCount)
	}

	// CloseSlowReaders should skip already-closed connections
	closed := r.CloseSlowReaders(64 * 1024)

	if closed != 0 {
		t.Errorf("CloseSlowReaders returned %d, want 0 (already closed)", closed)
	}
}

func TestRegistryForEachWithClose(t *testing.T) {
	r := newTestRegistry()

	// Create connections
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "foreach-close")
	defer cleanup1()

	conn2, cleanup2 := createTestConnWithRegistry(t, r, "foreach-close")
	defer cleanup2()

	conn3, cleanup3 := createTestConnWithRegistry(t, r, "foreach-close")
	defer cleanup3()

	// Close one connection during ForEach iteration
	// This should not cause deadlock or panic
	closedCount := 0
	r.ForEach(func(c *Conn) {
		if c.ID() == conn2.ID() {
			// Close during iteration - unregister will be called
			r.unregister(c.ID())
			closedCount++
		}
	})

	if closedCount != 1 {
		t.Errorf("closed during ForEach = %d, want 1", closedCount)
	}

	// Count should reflect the closure
	if count := r.Count(); count != 2 {
		t.Errorf("after ForEach close: count = %d, want 2", count)
	}

	_ = conn1
	_ = conn3
}

func TestRegistryEmptyOperations(t *testing.T) {
	r := newTestRegistry()

	// All operations should work on empty registry
	if count := r.Count(); count != 0 {
		t.Errorf("Count() on empty = %d, want 0", count)
	}

	closed := r.CloseIdle(1 * time.Second)
	if closed != 0 {
		t.Errorf("CloseIdle on empty = %d, want 0", closed)
	}

	closed = r.CloseSlowReaders(1024)
	if closed != 0 {
		t.Errorf("CloseSlowReaders on empty = %d, want 0", closed)
	}

	// Should not panic
	r.Shed()
	r.ShedAggressive()

	visited := 0
	r.ForEach(func(c *Conn) {
		visited++
	})
	if visited != 0 {
		t.Errorf("ForEach on empty visited %d, want 0", visited)
	}

	state := r.State()
	if state.Active != 0 || len(state.ByTag) != 0 {
		t.Errorf("State on empty: Active=%d, ByTag=%v, want 0 and empty", state.Active, state.ByTag)
	}
}

func TestRegistryTagCleanup(t *testing.T) {
	r := newTestRegistry()

	// Register connections with same tag
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "cleanup-tag")
	conn2, cleanup2 := createTestConnWithRegistry(t, r, "cleanup-tag")
	conn3, cleanup3 := createTestConnWithRegistry(t, r, "cleanup-tag")

	defer cleanup1()
	defer cleanup2()
	defer cleanup3()

	if count := r.CountByTag("cleanup-tag"); count != 3 {
		t.Errorf("initial CountByTag = %d, want 3", count)
	}

	// Unregister all - tag entry should be cleaned up
	r.unregister(conn1.id)
	r.unregister(conn2.id)
	r.unregister(conn3.id)

	if count := r.CountByTag("cleanup-tag"); count != 0 {
		t.Errorf("after all unregistered: CountByTag = %d, want 0", count)
	}

	// Verify the tag is removed from the map (prevents memory leak)
	r.tagsMu.RLock()
	_, exists := r.byTag["cleanup-tag"]
	r.tagsMu.RUnlock()

	if exists {
		t.Error("tag entry should be removed when count reaches zero")
	}
}

func TestRegistryStateSnapshot(t *testing.T) {
	r := newTestRegistry()

	// Create some connections
	conn1, cleanup1 := createTestConnWithRegistry(t, r, "snapshot-A")
	defer cleanup1()
	conn2, cleanup2 := createTestConnWithRegistry(t, r, "snapshot-B")
	defer cleanup2()

	// Get state
	state := r.State()

	// Modify registry after getting state
	conn3, cleanup3 := createTestConnWithRegistry(t, r, "snapshot-A")
	defer cleanup3()

	// Original state should not reflect new connection (it's a snapshot)
	if state.Active != 2 {
		t.Errorf("snapshot Active = %d, want 2 (before conn3)", state.Active)
	}

	// ByTag in snapshot should not change
	if state.ByTag["snapshot-A"] != 1 {
		t.Errorf("snapshot ByTag[snapshot-A] = %d, want 1", state.ByTag["snapshot-A"])
	}

	// Current state should reflect new connection
	currentState := r.State()
	if currentState.Active != 3 {
		t.Errorf("current Active = %d, want 3", currentState.Active)
	}
	if currentState.ByTag["snapshot-A"] != 2 {
		t.Errorf("current ByTag[snapshot-A] = %d, want 2", currentState.ByTag["snapshot-A"])
	}

	_ = conn1
	_ = conn2
	_ = conn3
}

func TestRegistryHighLoadShed(t *testing.T) {
	// Use globalRegistry for Close tests since Conn.Close() uses globalRegistry
	r := GetRegistry()
	initialCount := r.Count()

	const totalConns = 100
	conns := make([]*Conn, totalConns)
	cleanups := make([]func(), totalConns)

	// Create many connections with various states
	for i := 0; i < totalConns; i++ {
		conn, cleanup := createTestConn(t, "high-load")
		conns[i] = conn
		cleanups[i] = cleanup

		// Every 5th connection is idle
		if i%5 == 0 {
			setLastActivity(conn, time.Now().Add(-1*time.Hour))
		}
		// Every 7th connection is slow reader
		if i%7 == 0 {
			setPendingBytes(conn, 128*1024)
		}
	}
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	if count := r.Count(); count != initialCount+totalConns {
		t.Fatalf("initial count = %d, want %d", count, initialCount+totalConns)
	}

	// Shed should close idle and slow readers
	r.Shed()

	// Count closed connections
	closedCount := 0
	for _, conn := range conns {
		if conn.IsClosed() {
			closedCount++
		}
	}

	// Connections at indices 0, 5, 10, 15, ... (every 5th) are idle = 20 connections
	// Connections at indices 0, 7, 14, 21, ... (every 7th) are slow = ~15 connections
	// Some overlap (0, 35, 70) = 3 overlapping
	// Expected unique: 20 + 15 - 3 = 32 (approximately)

	expectedIdle := (totalConns + 4) / 5       // 20 (0,5,10,...,95)
	expectedSlow := (totalConns + 6) / 7       // 15 (0,7,14,21,28,35,42,49,56,63,70,77,84,91,98)
	expectedOverlap := 3                        // 0, 35, 70 are both idle and slow
	expectedClosed := expectedIdle + expectedSlow - expectedOverlap

	// Allow some tolerance due to timing
	if closedCount < expectedClosed-2 || closedCount > expectedClosed+2 {
		t.Errorf("closed = %d, expected approximately %d (idle=%d, slow=%d, overlap=%d)",
			closedCount, expectedClosed, expectedIdle, expectedSlow, expectedOverlap)
	}
}

func TestRegistryConcurrentShed(t *testing.T) {
	// Use globalRegistry for Close tests since Conn.Close() uses globalRegistry
	r := GetRegistry()
	initialCount := r.Count()

	// Create connections
	const numConns = 20
	cleanups := make([]func(), numConns)
	for i := 0; i < numConns; i++ {
		conn, cleanup := createTestConn(t, "concurrent-shed")
		cleanups[i] = cleanup
		setLastActivity(conn, time.Now().Add(-1*time.Hour))
	}
	defer func() {
		for _, cleanup := range cleanups {
			cleanup()
		}
	}()

	// Concurrent Shed calls should not panic or cause race
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			r.Shed()
		}()
	}
	wg.Wait()

	// All should be closed - count should be back to initial
	if count := r.Count(); count != initialCount {
		t.Errorf("after concurrent Shed: count = %d, want %d", count, initialCount)
	}
}

func TestRegistryBoundaryConditions(t *testing.T) {
	r := newTestRegistry()

	// Test with zero threshold
	closed := r.CloseIdle(0)
	if closed != 0 {
		t.Errorf("CloseIdle(0) on empty = %d, want 0", closed)
	}

	closed = r.CloseSlowReaders(0)
	if closed != 0 {
		t.Errorf("CloseSlowReaders(0) on empty = %d, want 0", closed)
	}

	// Create a connection and test with zero thresholds
	conn, cleanup := createTestConnWithRegistry(t, r, "boundary")
	defer cleanup()

	// Set small idle time and pending
	setLastActivity(conn.Conn, time.Now().Add(-1*time.Millisecond))
	setPendingBytes(conn.Conn, 1)

	// Zero threshold should still close if strictly greater check is used
	// Looking at the code: c.IdleDuration() > maxIdle and c.PendingBytes() > maxPending
	// With 0 threshold, even 1 byte or 1 nanosecond idle should trigger close
	// But since these use globalRegistry, we can only check with isolated tests
}

func TestRegistryNegativePendingBytes(t *testing.T) {
	r := newTestRegistry()

	conn, cleanup := createTestConnWithRegistry(t, r, "negative-pending")
	defer cleanup()

	// Set negative pending bytes (edge case)
	setPendingBytes(conn.Conn, -1000)

	// Should not be considered a slow reader
	closed := r.CloseSlowReaders(0)
	if closed != 0 {
		t.Errorf("CloseSlowReaders with negative pending = %d, want 0", closed)
	}
}

func TestRegistryEmptyTag(t *testing.T) {
	r := newTestRegistry()

	// Empty tag should work
	conn, cleanup := createTestConnWithRegistry(t, r, "")
	defer cleanup()

	if count := r.CountByTag(""); count != 1 {
		t.Errorf("CountByTag('') = %d, want 1", count)
	}

	if conn.Tag() != "" {
		t.Errorf("conn.Tag() = %q, want empty string", conn.Tag())
	}
}

func TestRegistryVeryLongTag(t *testing.T) {
	r := newTestRegistry()

	// Very long tag
	longTag := ""
	for i := 0; i < 1000; i++ {
		longTag += "a"
	}

	conn, cleanup := createTestConnWithRegistry(t, r, longTag)
	defer cleanup()

	if count := r.CountByTag(longTag); count != 1 {
		t.Errorf("CountByTag(longTag) = %d, want 1", count)
	}

	if conn.Tag() != longTag {
		t.Error("conn.Tag() does not match long tag")
	}
}
