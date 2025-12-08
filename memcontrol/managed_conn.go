package memcontrol

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

var (
	connIDGen atomic.Uint64
	// disabled is set once at init via env var
	disabled bool
)

func init() {
	// Support REALITY_*, XRAY_*, and UTLS_* prefixes for compatibility
	disabled = os.Getenv("REALITY_DISABLE_MANAGED_CONN") == "1" ||
		os.Getenv("XRAY_DISABLE_MANAGED_CONN") == "1" ||
		os.Getenv("UTLS_DISABLE_MANAGED_CONN") == "1"
}

// Conn wraps net.Conn with tracking for memory-aware management.
// Automatically registers with the global registry on creation.
type Conn struct {
	net.Conn

	id        uint64
	tag       string // Inbound tag (e.g., "reality-in", "reality-fallback")
	createdAt int64  // UnixNano

	lastReadAt  atomic.Int64 // UnixNano
	lastWriteAt atomic.Int64 // UnixNano

	bytesRead    atomic.Uint64
	bytesWritten atomic.Uint64
	pendingWrite atomic.Int64 // Bytes passed to Write but not yet returned

	closed    atomic.Bool
	closeOnce sync.Once
}

// Wrap wraps a net.Conn with tracking and registers it.
// The tag identifies the inbound source (e.g., "tls-in", "tls-fallback").
// Returns nil only if conn is nil.
// If disabled via env var (REALITY_*, XRAY_*, or UTLS_DISABLE_MANAGED_CONN=1),
// returns nil (caller should use WrapOrPassthrough for transparent fallback).
func Wrap(conn net.Conn, tag string) *Conn {
	if conn == nil {
		return nil
	}
	if disabled {
		return nil
	}

	now := time.Now().UnixNano()

	mc := &Conn{
		Conn:      conn,
		id:        connIDGen.Add(1),
		tag:       tag,
		createdAt: now,
	}
	mc.lastReadAt.Store(now)
	mc.lastWriteAt.Store(now)

	globalRegistry.register(mc)
	return mc
}

// Read implements net.Conn.Read with tracking.
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.lastReadAt.Store(time.Now().UnixNano())
		c.bytesRead.Add(uint64(n))
	}
	return n, err
}

// Write implements net.Conn.Write with tracking.
// Tracks pending bytes to detect slow readers.
func (c *Conn) Write(b []byte) (int, error) {
	size := int64(len(b))
	c.pendingWrite.Add(size)

	n, err := c.Conn.Write(b)

	// Always subtract full size - once Write() returns (success or error),
	// the data is no longer "pending" from the caller's perspective.
	// Previous code only subtracted n bytes, causing pendingWrite to inflate
	// on failed writes and incorrectly triggering slow reader detection.
	c.pendingWrite.Add(-size)

	if n > 0 {
		c.lastWriteAt.Store(time.Now().UnixNano())
		c.bytesWritten.Add(uint64(n))
	}
	return n, err
}

// Close implements net.Conn.Close with cleanup.
// Safe to call multiple times. Safe to call on nil receiver.
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		globalRegistry.unregister(c.id)
		err = c.Conn.Close()
	})
	return err
}

// ID returns the unique connection identifier.
// Returns 0 if receiver is nil.
func (c *Conn) ID() uint64 {
	if c == nil {
		return 0
	}
	return c.id
}

// Tag returns the inbound tag.
// Returns empty string if receiver is nil.
func (c *Conn) Tag() string {
	if c == nil {
		return ""
	}
	return c.tag
}

// CreatedAt returns when the connection was created.
// Returns zero time if receiver is nil.
func (c *Conn) CreatedAt() time.Time {
	if c == nil {
		return time.Time{}
	}
	return time.Unix(0, c.createdAt)
}

// Age returns how long the connection has existed.
// Returns 0 if receiver is nil.
func (c *Conn) Age() time.Duration {
	if c == nil {
		return 0
	}
	return time.Since(c.CreatedAt())
}

// LastActivity returns the most recent read or write time.
// Returns zero time if receiver is nil.
func (c *Conn) LastActivity() time.Time {
	if c == nil {
		return time.Time{}
	}
	lastRead := c.lastReadAt.Load()
	lastWrite := c.lastWriteAt.Load()

	last := lastRead
	if lastWrite > lastRead {
		last = lastWrite
	}
	return time.Unix(0, last)
}

// IdleDuration returns how long since last activity.
// Returns 0 if receiver is nil.
func (c *Conn) IdleDuration() time.Duration {
	if c == nil {
		return 0
	}
	return time.Since(c.LastActivity())
}

// BytesRead returns total bytes read.
// Returns 0 if receiver is nil.
func (c *Conn) BytesRead() uint64 {
	if c == nil {
		return 0
	}
	return c.bytesRead.Load()
}

// BytesWritten returns total bytes written.
// Returns 0 if receiver is nil.
func (c *Conn) BytesWritten() uint64 {
	if c == nil {
		return 0
	}
	return c.bytesWritten.Load()
}

// PendingBytes returns bytes waiting to be written.
// High values indicate a slow reader on the other end.
// Returns 0 if receiver is nil.
func (c *Conn) PendingBytes() int64 {
	if c == nil {
		return 0
	}
	return c.pendingWrite.Load()
}

// IsClosed returns whether the connection has been closed.
// Returns true if receiver is nil (nil connection is considered closed).
func (c *Conn) IsClosed() bool {
	if c == nil {
		return true
	}
	return c.closed.Load()
}

// Unwrap returns the underlying net.Conn.
// This allows type assertions on the wrapped connection to succeed.
// Returns nil if receiver is nil.
func (c *Conn) Unwrap() net.Conn {
	if c == nil {
		return nil
	}
	return c.Conn
}

// UnwrapConn unwraps a managed.Conn if present, otherwise returns the original.
func UnwrapConn(conn net.Conn) net.Conn {
	if mc, ok := conn.(*Conn); ok {
		return mc.Unwrap()
	}
	return conn
}

// WrapOrPassthrough wraps a connection with tracking, or returns the original
// connection unchanged if tracking is disabled. This is the recommended function
// to use when you want transparent fallback behavior.
//
// Unlike Wrap(), this never returns nil for a non-nil input connection.
func WrapOrPassthrough(conn net.Conn, tag string) net.Conn {
	if conn == nil {
		return nil
	}
	if disabled {
		return conn // Return original connection unchanged
	}
	return Wrap(conn, tag)
}

// Stats contains connection statistics snapshot.
type Stats struct {
	ID           uint64
	Tag          string
	Age          time.Duration
	IdleDuration time.Duration
	BytesRead    uint64
	BytesWritten uint64
	PendingWrite int64
	Closed       bool
}

// Stats returns a snapshot of connection statistics.
// Returns zero Stats with Closed=true if receiver is nil.
func (c *Conn) Stats() Stats {
	if c == nil {
		return Stats{Closed: true}
	}
	return Stats{
		ID:           c.id,
		Tag:          c.tag,
		Age:          c.Age(),
		IdleDuration: c.IdleDuration(),
		BytesRead:    c.bytesRead.Load(),
		BytesWritten: c.bytesWritten.Load(),
		PendingWrite: c.pendingWrite.Load(),
		Closed:       c.closed.Load(),
	}
}
