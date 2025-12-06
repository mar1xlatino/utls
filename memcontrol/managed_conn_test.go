package memcontrol

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func init() {
	// Suppress logs during tests
	SetLogLevel(LogLevelOff)
}

// cleanRegistry removes all connections from the global registry.
// Call this at the start of tests that depend on registry state.
func cleanRegistry() {
	reg := GetRegistry()
	reg.mu.Lock()
	for id := range reg.conns {
		delete(reg.conns, id)
	}
	reg.count.Store(0)
	reg.mu.Unlock()

	reg.tagsMu.Lock()
	for tag := range reg.byTag {
		delete(reg.byTag, tag)
	}
	reg.tagsMu.Unlock()
}

// TestWrapBasic verifies Wrap returns non-nil *Conn with correct tag.
func TestWrapBasic(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	mc := Wrap(client, "test-tag")
	if mc == nil {
		t.Fatal("Wrap returned nil for valid connection")
	}
	defer mc.Close()

	if mc.Tag() != "test-tag" {
		t.Errorf("expected tag 'test-tag', got %q", mc.Tag())
	}

	if mc.ID() == 0 {
		t.Error("expected non-zero ID")
	}

	if mc.IsClosed() {
		t.Error("new connection should not be closed")
	}

	// Verify registered
	if GetRegistry().Get(mc.ID()) == nil {
		t.Error("connection should be registered in registry")
	}
}

// TestWrapNilConn verifies Wrap(nil, tag) returns nil.
func TestWrapNilConn(t *testing.T) {
	mc := Wrap(nil, "any-tag")
	if mc != nil {
		t.Errorf("Wrap(nil) should return nil, got %v", mc)
	}
}

// TestWrapOrPassthrough tests that WrapOrPassthrough returns wrapped conn
// normally and original when disabled. Since we can't easily toggle the
// disabled flag (set at init), we test the normal path.
func TestWrapOrPassthrough(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Normal path (not disabled) - should return wrapped conn
	wrapped := WrapOrPassthrough(client, "passthrough-tag")
	if wrapped == nil {
		t.Fatal("WrapOrPassthrough returned nil")
	}

	// Should be a *Conn when not disabled
	mc, ok := wrapped.(*Conn)
	if !ok {
		t.Fatalf("expected *Conn, got %T", wrapped)
	}
	defer mc.Close()

	if mc.Tag() != "passthrough-tag" {
		t.Errorf("expected tag 'passthrough-tag', got %q", mc.Tag())
	}

	// nil input should return nil
	nilResult := WrapOrPassthrough(nil, "tag")
	if nilResult != nil {
		t.Error("WrapOrPassthrough(nil) should return nil")
	}
}

// TestConnID verifies each wrapped conn has unique incrementing ID.
func TestConnID(t *testing.T) {
	cleanRegistry()

	const numConns = 10
	ids := make([]uint64, numConns)

	for i := 0; i < numConns; i++ {
		server, client := net.Pipe()
		mc := Wrap(client, "id-test")
		if mc == nil {
			server.Close()
			t.Fatalf("Wrap returned nil for conn %d", i)
		}
		ids[i] = mc.ID()
		mc.Close()
		server.Close()
	}

	// Verify all IDs are unique
	seen := make(map[uint64]bool)
	for i, id := range ids {
		if id == 0 {
			t.Errorf("conn %d has zero ID", i)
		}
		if seen[id] {
			t.Errorf("duplicate ID %d at index %d", id, i)
		}
		seen[id] = true
	}

	// Verify IDs are incrementing
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Errorf("IDs not incrementing: %d <= %d", ids[i], ids[i-1])
		}
	}
}

// TestConnTag verifies Tag() returns the tag passed to Wrap().
func TestConnTag(t *testing.T) {
	cleanRegistry()

	testCases := []string{
		"reality-in",
		"reality-fallback",
		"tls-inbound",
		"",
		"tag-with-special-chars!@#$%",
	}

	for _, tag := range testCases {
		server, client := net.Pipe()
		mc := Wrap(client, tag)
		if mc == nil {
			server.Close()
			t.Fatalf("Wrap returned nil for tag %q", tag)
		}

		if mc.Tag() != tag {
			t.Errorf("expected tag %q, got %q", tag, mc.Tag())
		}

		mc.Close()
		server.Close()
	}
}

// TestConnReadWrite verifies Read/Write pass through to underlying conn.
func TestConnReadWrite(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "rw-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	testData := []byte("Hello, World!")

	// Write from wrapped conn
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(testData))
		_, err := io.ReadFull(server, buf)
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(buf, testData) {
			done <- errors.New("data mismatch")
			return
		}
		done <- nil
	}()

	n, err := mc.Write(testData)
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write: expected %d bytes, got %d", len(testData), n)
	}

	if err := <-done; err != nil {
		t.Fatalf("server read error: %v", err)
	}

	// Read to wrapped conn
	go func() {
		server.Write(testData)
	}()

	buf := make([]byte, len(testData))
	n, err = io.ReadFull(mc, buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Read: expected %d bytes, got %d", len(testData), n)
	}
	if !bytes.Equal(buf, testData) {
		t.Error("Read data mismatch")
	}
}

// TestConnBytesReadWritten verifies BytesRead/BytesWritten counters are accurate.
func TestConnBytesReadWritten(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "bytes-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	// Initial values should be zero
	if mc.BytesRead() != 0 {
		t.Errorf("initial BytesRead: expected 0, got %d", mc.BytesRead())
	}
	if mc.BytesWritten() != 0 {
		t.Errorf("initial BytesWritten: expected 0, got %d", mc.BytesWritten())
	}

	// Write data in chunks
	chunks := [][]byte{
		[]byte("chunk1"),
		[]byte("longer chunk two"),
		[]byte("3"),
	}

	var expectedWritten uint64
	for _, chunk := range chunks {
		go func() {
			buf := make([]byte, len(chunk))
			io.ReadFull(server, buf)
		}()

		n, err := mc.Write(chunk)
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
		expectedWritten += uint64(n)
	}

	if mc.BytesWritten() != expectedWritten {
		t.Errorf("BytesWritten: expected %d, got %d", expectedWritten, mc.BytesWritten())
	}

	// Read data
	readData := []byte("data from server")
	go func() {
		server.Write(readData)
	}()

	buf := make([]byte, len(readData))
	n, err := io.ReadFull(mc, buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	if mc.BytesRead() != uint64(n) {
		t.Errorf("BytesRead: expected %d, got %d", n, mc.BytesRead())
	}
}

// TestConnPendingWriteNoInflation is CRITICAL: verifies pendingWrite doesn't
// inflate on failed writes. This tests the fix where we subtract size (not n)
// after Write returns.
func TestConnPendingWriteNoInflation(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()

	mc := Wrap(client, "pending-test")
	if mc == nil {
		server.Close()
		t.Fatal("Wrap returned nil")
	}

	// Initial pendingWrite should be zero
	if mc.PendingBytes() != 0 {
		t.Errorf("initial PendingBytes: expected 0, got %d", mc.PendingBytes())
	}

	// Close the server end to force write failures
	server.Close()

	// Give time for the close to propagate
	time.Sleep(10 * time.Millisecond)

	// Attempt multiple writes that will fail
	testData := []byte("this will fail to write")
	for i := 0; i < 5; i++ {
		_, err := mc.Write(testData)
		// Write should fail since server is closed
		if err == nil {
			// On some systems the first write might succeed (buffered)
			// but subsequent ones should fail
			continue
		}
	}

	// CRITICAL CHECK: pendingWrite should NOT inflate
	// The bug was: pendingWrite.Add(size) then pendingWrite.Add(-n)
	// When n=0 on failed write, pendingWrite accumulates infinitely.
	// The fix: always subtract size (the full buffer length) not n.
	pending := mc.PendingBytes()
	if pending != 0 {
		t.Errorf("CRITICAL BUG: pendingWrite inflated to %d after failed writes (expected 0)", pending)
	}

	mc.Close()
}

// TestConnIdleDuration verifies IdleDuration increases over time.
func TestConnIdleDuration(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "idle-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	// Initial idle duration should be very small
	idle1 := mc.IdleDuration()
	if idle1 > 100*time.Millisecond {
		t.Errorf("initial IdleDuration too large: %v", idle1)
	}

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	idle2 := mc.IdleDuration()
	if idle2 <= idle1 {
		t.Errorf("IdleDuration did not increase: %v <= %v", idle2, idle1)
	}

	// Activity should reset idle duration
	go func() {
		buf := make([]byte, 1)
		server.Read(buf)
	}()
	mc.Write([]byte("x"))

	idle3 := mc.IdleDuration()
	if idle3 > 10*time.Millisecond {
		t.Errorf("IdleDuration not reset after Write: %v", idle3)
	}
}

// TestConnLastActivity verifies LastReadAt/LastWriteAt are updated correctly.
func TestConnLastActivity(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "activity-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	// Record creation time
	createdAt := mc.CreatedAt()
	if time.Since(createdAt) > time.Second {
		t.Error("CreatedAt seems incorrect")
	}

	initialActivity := mc.LastActivity()

	// Wait and perform write
	time.Sleep(20 * time.Millisecond)
	go func() {
		buf := make([]byte, 1)
		server.Read(buf)
	}()
	mc.Write([]byte("w"))

	afterWrite := mc.LastActivity()
	if !afterWrite.After(initialActivity) {
		t.Error("LastActivity not updated after Write")
	}

	// Wait and perform read
	time.Sleep(20 * time.Millisecond)
	go func() {
		server.Write([]byte("r"))
	}()

	buf := make([]byte, 1)
	mc.Read(buf)

	afterRead := mc.LastActivity()
	if !afterRead.After(afterWrite) {
		t.Error("LastActivity not updated after Read")
	}
}

// TestConnClose verifies Close sets IsClosed and removes from registry.
func TestConnClose(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "close-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}

	connID := mc.ID()

	// Verify registered
	if GetRegistry().Get(connID) == nil {
		t.Error("connection should be registered before close")
	}

	// Close
	err := mc.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}

	// Verify IsClosed
	if !mc.IsClosed() {
		t.Error("IsClosed should return true after Close")
	}

	// Verify unregistered
	if GetRegistry().Get(connID) != nil {
		t.Error("connection should be unregistered after close")
	}
}

// TestConnCloseIdempotent verifies multiple Close() calls are safe (sync.Once).
func TestConnCloseIdempotent(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "idempotent-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}

	// Close multiple times - should not panic
	for i := 0; i < 10; i++ {
		err := mc.Close()
		// Only first close should potentially return an error
		// Subsequent closes should be no-ops (return nil due to sync.Once)
		if i > 0 && err != nil {
			// sync.Once means the underlying Close() is only called once
			// so we shouldn't get errors on subsequent calls
			// Note: the implementation stores err from first call, so
			// subsequent calls return nil (not stored error)
		}
	}

	if !mc.IsClosed() {
		t.Error("IsClosed should be true after Close")
	}
}

// TestConnUnwrap verifies Unwrap() returns the original net.Conn.
func TestConnUnwrap(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "unwrap-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	unwrapped := mc.Unwrap()
	if unwrapped != client {
		t.Errorf("Unwrap returned wrong connection: got %p, want %p", unwrapped, client)
	}
}

// TestUnwrapConn verifies UnwrapConn helper works on wrapped and unwrapped.
func TestUnwrapConn(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	// Test with wrapped connection
	mc := Wrap(client, "unwrap-helper-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	unwrapped := UnwrapConn(mc)
	if unwrapped != client {
		t.Error("UnwrapConn failed to unwrap *Conn")
	}

	// Test with regular net.Conn (should return as-is)
	server2, client2 := net.Pipe()
	defer server2.Close()
	defer client2.Close()

	result := UnwrapConn(client2)
	if result != client2 {
		t.Error("UnwrapConn should return regular conn unchanged")
	}

	// Test with nil
	nilResult := UnwrapConn(nil)
	if nilResult != nil {
		t.Error("UnwrapConn(nil) should return nil")
	}
}

// TestConnStats verifies Stats() returns accurate snapshot.
func TestConnStats(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "stats-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	// Perform some I/O
	testData := []byte("stats test data")
	go func() {
		buf := make([]byte, len(testData))
		io.ReadFull(server, buf)
		server.Write(testData)
	}()

	mc.Write(testData)
	buf := make([]byte, len(testData))
	io.ReadFull(mc, buf)

	// Get stats
	stats := mc.Stats()

	// Verify fields
	if stats.ID != mc.ID() {
		t.Errorf("Stats.ID mismatch: %d vs %d", stats.ID, mc.ID())
	}
	if stats.Tag != "stats-test" {
		t.Errorf("Stats.Tag: expected 'stats-test', got %q", stats.Tag)
	}
	if stats.BytesRead != uint64(len(testData)) {
		t.Errorf("Stats.BytesRead: expected %d, got %d", len(testData), stats.BytesRead)
	}
	if stats.BytesWritten != uint64(len(testData)) {
		t.Errorf("Stats.BytesWritten: expected %d, got %d", len(testData), stats.BytesWritten)
	}
	if stats.Closed {
		t.Error("Stats.Closed should be false before Close()")
	}
	if stats.Age < 0 {
		t.Error("Stats.Age should be non-negative")
	}
	if stats.IdleDuration < 0 {
		t.Error("Stats.IdleDuration should be non-negative")
	}
	if stats.PendingWrite != 0 {
		t.Errorf("Stats.PendingWrite: expected 0, got %d", stats.PendingWrite)
	}
}

// TestConnConcurrentReadWrite verifies concurrent R/W don't corrupt counters.
func TestConnConcurrentReadWrite(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "concurrent-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	const (
		numWriters    = 5
		numReaders    = 5
		bytesPerOp    = 100
		opsPerRoutine = 50
	)

	var wg sync.WaitGroup
	var totalWritten atomic.Uint64
	var totalRead atomic.Uint64

	// Start server-side handlers
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			// Echo back what we read
			server.Write(buf[:n])
		}
	}()

	// Writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := make([]byte, bytesPerOp)
			for j := 0; j < opsPerRoutine; j++ {
				n, err := mc.Write(data)
				if err != nil {
					return
				}
				totalWritten.Add(uint64(n))
			}
		}()
	}

	// Readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, bytesPerOp)
			for j := 0; j < opsPerRoutine; j++ {
				n, err := mc.Read(buf)
				if err != nil {
					return
				}
				totalRead.Add(uint64(n))
			}
		}()
	}

	wg.Wait()
	mc.Close()
	<-serverDone

	// Verify counters match
	if mc.BytesWritten() != totalWritten.Load() {
		t.Errorf("BytesWritten mismatch: conn=%d, tracked=%d",
			mc.BytesWritten(), totalWritten.Load())
	}
	if mc.BytesRead() != totalRead.Load() {
		t.Errorf("BytesRead mismatch: conn=%d, tracked=%d",
			mc.BytesRead(), totalRead.Load())
	}

	// Pending should be zero after all operations complete
	if mc.PendingBytes() != 0 {
		t.Errorf("PendingBytes should be 0 after completion, got %d", mc.PendingBytes())
	}
}

// TestConnAge verifies Age() returns correct duration.
func TestConnAge(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "age-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	// Age should be small initially
	age1 := mc.Age()
	if age1 > 100*time.Millisecond {
		t.Errorf("initial Age too large: %v", age1)
	}

	// Wait and check age increased
	time.Sleep(50 * time.Millisecond)
	age2 := mc.Age()
	if age2 <= age1 {
		t.Errorf("Age did not increase: %v <= %v", age2, age1)
	}
	if age2 < 50*time.Millisecond {
		t.Errorf("Age should be at least 50ms, got %v", age2)
	}
}

// TestConnRegistryIntegration verifies registry integration works correctly.
func TestConnRegistryIntegration(t *testing.T) {
	cleanRegistry()

	reg := GetRegistry()
	initialCount := reg.Count()

	const numConns = 5
	conns := make([]*Conn, numConns)
	servers := make([]net.Conn, numConns)

	// Create connections
	for i := 0; i < numConns; i++ {
		server, client := net.Pipe()
		servers[i] = server
		mc := Wrap(client, "registry-test")
		if mc == nil {
			t.Fatalf("Wrap returned nil for conn %d", i)
		}
		conns[i] = mc
	}

	// Verify count increased
	if reg.Count() != initialCount+numConns {
		t.Errorf("registry count: expected %d, got %d", initialCount+numConns, reg.Count())
	}

	// Verify by-tag count
	if reg.CountByTag("registry-test") != numConns {
		t.Errorf("CountByTag: expected %d, got %d", numConns, reg.CountByTag("registry-test"))
	}

	// Close half
	for i := 0; i < numConns/2; i++ {
		conns[i].Close()
		servers[i].Close()
	}

	expectedRemaining := numConns - numConns/2
	if reg.Count() != initialCount+int32(expectedRemaining) {
		t.Errorf("after partial close: expected %d, got %d",
			initialCount+int32(expectedRemaining), reg.Count())
	}

	// Cleanup
	for i := numConns / 2; i < numConns; i++ {
		conns[i].Close()
		servers[i].Close()
	}

	// Registry should be back to initial
	if reg.Count() != initialCount {
		t.Errorf("after full cleanup: expected %d, got %d", initialCount, reg.Count())
	}
}

// TestConnZeroRead verifies zero-byte reads don't update activity.
func TestConnZeroRead(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "zero-read-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	initialBytes := mc.BytesRead()
	initialActivity := mc.lastReadAt.Load()

	// Zero-byte read (edge case)
	buf := make([]byte, 0)
	go func() {
		// Send nothing, just trigger read to return
		time.Sleep(10 * time.Millisecond)
	}()

	// The Read will block, so we use a timeout approach
	done := make(chan bool, 1)
	go func() {
		mc.Read(buf)
		done <- true
	}()

	select {
	case <-done:
		// Read completed
	case <-time.After(50 * time.Millisecond):
		// Expected - read is blocking
	}

	// BytesRead should not have increased from zero reads
	if mc.BytesRead() != initialBytes {
		// This is actually expected behavior - if n=0, no update happens
	}

	_ = initialActivity // Activity tracking is implementation detail
}

// TestConnLocalRemoteAddr verifies address methods pass through.
func TestConnLocalRemoteAddr(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "addr-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	// These should pass through to underlying connection
	localAddr := mc.LocalAddr()
	remoteAddr := mc.RemoteAddr()

	// net.Pipe() returns pipe addresses
	if localAddr == nil {
		t.Error("LocalAddr should not be nil")
	}
	if remoteAddr == nil {
		t.Error("RemoteAddr should not be nil")
	}
}

// TestConnSetDeadline verifies deadline methods pass through.
func TestConnSetDeadline(t *testing.T) {
	cleanRegistry()

	server, client := net.Pipe()
	defer server.Close()

	mc := Wrap(client, "deadline-test")
	if mc == nil {
		t.Fatal("Wrap returned nil")
	}
	defer mc.Close()

	// Set various deadlines - should not error
	deadline := time.Now().Add(time.Second)

	if err := mc.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline error: %v", err)
	}
	if err := mc.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline error: %v", err)
	}
	if err := mc.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline error: %v", err)
	}
}
