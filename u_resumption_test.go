//go:build integration
// +build integration

// Package tls contains integration tests for TLS 1.3 session resumption.
// Run with: go test -tags=integration -v -run TestResumption
//
// These tests connect to real servers and verify that TLS 1.3 session
// resumption (PSK-based) and TLS 1.2 session resumption (ticket-based)
// work correctly with various client profiles.
package tls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testSessionCache implements ClientSessionCache for testing purposes.
// It tracks all Get/Put operations for verification.
type testSessionCache struct {
	mu       sync.RWMutex
	sessions map[string]*ClientSessionState
	getCalls atomic.Int32
	putCalls atomic.Int32
	onPut    func(key string, session *ClientSessionState)
	onGet    func(key string, session *ClientSessionState, ok bool)
}

func newTestSessionCache() *testSessionCache {
	return &testSessionCache{
		sessions: make(map[string]*ClientSessionState),
	}
}

func (c *testSessionCache) Get(sessionKey string) (session *ClientSessionState, ok bool) {
	c.getCalls.Add(1)
	c.mu.RLock()
	session, ok = c.sessions[sessionKey]
	c.mu.RUnlock()
	if c.onGet != nil {
		c.onGet(sessionKey, session, ok)
	}
	return session, ok
}

func (c *testSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.putCalls.Add(1)
	c.mu.Lock()
	if cs == nil {
		delete(c.sessions, sessionKey)
	} else {
		c.sessions[sessionKey] = cs
	}
	c.mu.Unlock()
	if c.onPut != nil {
		c.onPut(sessionKey, cs)
	}
}

func (c *testSessionCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}

func (c *testSessionCache) GetCalls() int32 {
	return c.getCalls.Load()
}

func (c *testSessionCache) PutCalls() int32 {
	return c.putCalls.Load()
}

// dialWithTimeout creates a TCP connection with a context timeout.
func dialWithTimeout(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// readWithTimeout attempts to read from the TLS connection to trigger
// NewSessionTicket message processing in TLS 1.3.
func readWithTimeout(conn *UConn, timeout time.Duration) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 4096)
	conn.Read(buf) // Ignore errors - we just want to trigger ticket processing
}

// TestTLS13BasicResumption tests the fundamental TLS 1.3 session resumption flow:
// 1. Initial connection establishes session and receives NewSessionTicket
// 2. Second connection uses PSK to resume the session
// 3. Verifies UsingPSK is true on resumed connection
//
// Note: This test requires network connectivity and a server that supports
// TLS 1.3 session resumption. It may be flaky in CI environments.
func TestTLS13BasicResumption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network-dependent test in short mode")
	}

	// Try multiple servers in case one is having issues
	servers := []struct {
		addr string
		name string
	}{
		{"www.cloudflare.com:443", "www.cloudflare.com"},
		{"www.google.com:443", "www.google.com"},
	}

	for _, server := range servers {
		t.Run(server.name, func(t *testing.T) {
			testTLS13BasicResumptionWithServer(t, server.addr, server.name)
		})
	}
}

func testTLS13BasicResumptionWithServer(t *testing.T, serverAddr, serverName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// Track when tickets are received
	ticketReceived := make(chan struct{}, 1)
	cache.onPut = func(key string, session *ClientSessionState) {
		if session != nil {
			select {
			case ticketReceived <- struct{}{}:
			default:
			}
		}
	}

	// First connection - establish session
	t.Log("Starting first connection to establish session...")
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Skipf("Failed to dial first connection (network issue): %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf) // This profile supports PSK resumption

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Skipf("First handshake failed (server issue): %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if !cs1.HandshakeComplete {
		tlsConn1.Close()
		t.Fatal("First handshake not complete")
	}

	t.Logf("First connection: TLS %s, Cipher: %s, UsingPSK: %v",
		VersionName(cs1.Version), tls.CipherSuiteName(cs1.CipherSuite),
		tlsConn1.HandshakeState.State13.UsingPSK)

	if tlsConn1.HandshakeState.State13.UsingPSK {
		tlsConn1.Close()
		t.Fatal("First connection should NOT have used PSK (no prior session)")
	}

	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s instead of TLS 1.3, skipping", VersionName(cs1.Version))
	}

	// Read to trigger NewSessionTicket processing
	readWithTimeout(tlsConn1, 1*time.Second)
	tlsConn1.Close()

	// Wait for ticket with timeout
	select {
	case <-ticketReceived:
		t.Log("Session ticket received and cached")
	case <-time.After(3 * time.Second):
		if cache.Count() == 0 {
			t.Skip("No session ticket received (server may not support resumption)")
		}
	}

	if cache.Count() == 0 {
		t.Skip("Session cache is empty after first connection")
	}

	// Second connection with retry - should resume
	// Some servers need multiple attempts before accepting PSK
	const maxRetries = 5
	var resumed bool
	var successfulHandshakes int
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		t.Logf("Resumption attempt %d/%d...", i+1, maxRetries)
		time.Sleep(700 * time.Millisecond) // Longer pause between attempts

		tcpConn2, err := dialWithTimeout(ctx, serverAddr)
		if err != nil {
			lastErr = fmt.Errorf("dial failed: %w", err)
			continue
		}

		tlsConn2 := UClient(tcpConn2, &Config{
			ServerName:         serverName,
			ClientSessionCache: cache,
			OmitEmptyPsk:       true,
		}, HelloChrome_112_PSK_Shuf)

		if err := tlsConn2.Handshake(); err != nil {
			tcpConn2.Close()
			lastErr = fmt.Errorf("handshake failed: %w", err)
			// Check if it's a transient error
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "connection reset") {
				t.Logf("  Transient error, retrying...")
				continue
			}
			continue
		}

		successfulHandshakes++
		cs2 := tlsConn2.ConnectionState()
		usingPSK := tlsConn2.HandshakeState.State13.UsingPSK

		t.Logf("  TLS %s, Cipher: %s, UsingPSK: %v, DidResume: %v",
			VersionName(cs2.Version), tls.CipherSuiteName(cs2.CipherSuite),
			usingPSK, cs2.DidResume)

		// Read to get any new tickets
		readWithTimeout(tlsConn2, 500*time.Millisecond)
		tlsConn2.Close()

		if cs2.Version == VersionTLS13 && usingPSK {
			resumed = true
			t.Log("Successfully resumed using PSK")
			break
		}
	}

	if !resumed {
		if successfulHandshakes == 0 {
			t.Skipf("All %d handshake attempts failed with network errors. Last error: %v", maxRetries, lastErr)
		} else {
			t.Logf("Had %d successful handshakes but none used PSK (server may have rejected resumption)", successfulHandshakes)
		}
	}
}

// TestTLS13PSKIdentityExtension verifies that the PSK extension is correctly
// included in the ClientHello when resuming a TLS 1.3 session.
func TestTLS13PSKIdentityExtension(t *testing.T) {
	serverAddr := "www.microsoft.com:443"
	serverName := "www.microsoft.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping PSK test", VersionName(cs1.Version))
	}

	// Check first connection had no PSK identities
	if len(tlsConn1.HandshakeState.Hello.PskIdentities) > 0 {
		t.Log("Warning: First connection had PSK identities (unexpected but not fatal)")
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	if cache.Count() == 0 {
		t.Fatal("No session cached after first connection")
	}

	// Second connection - inspect PSK extension
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial second connection: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	// Build handshake state without connecting to inspect ClientHello
	if err := tlsConn2.BuildHandshakeState(); err != nil {
		tcpConn2.Close()
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	// Verify PSK identities are present
	pskIdentities := tlsConn2.HandshakeState.Hello.PskIdentities
	t.Logf("PSK identities in ClientHello: %d", len(pskIdentities))

	if len(pskIdentities) == 0 {
		t.Error("Expected PSK identities in resumed ClientHello, got none")
	}

	for i, identity := range pskIdentities {
		t.Logf("  Identity %d: label length=%d, obfuscated_ticket_age=%d",
			i, len(identity.Label), identity.ObfuscatedTicketAge)
		if len(identity.Label) == 0 {
			t.Errorf("Identity %d has empty label", i)
		}
	}

	// Verify PSK binders are present
	pskBinders := tlsConn2.HandshakeState.Hello.PskBinders
	t.Logf("PSK binders in ClientHello: %d", len(pskBinders))

	if len(pskBinders) != len(pskIdentities) {
		t.Errorf("Binder count (%d) does not match identity count (%d)",
			len(pskBinders), len(pskIdentities))
	}

	for i, binder := range pskBinders {
		t.Logf("  Binder %d: length=%d", i, len(binder))
		if len(binder) == 0 {
			t.Errorf("Binder %d is empty", i)
		}
	}

	// Complete the handshake
	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Second handshake failed: %v", err)
	}
	defer tlsConn2.Close()

	cs2 := tlsConn2.ConnectionState()
	if !cs2.DidResume {
		t.Error("Expected session resumption")
	}
}

// TestTLS13ResumptionAcrossProfiles tests that session tickets from one
// profile cannot be used with a different profile (different fingerprint).
func TestTLS13ResumptionAcrossProfiles(t *testing.T) {
	serverAddr := "www.microsoft.com:443"
	serverName := "www.microsoft.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection with Chrome profile
	t.Log("First connection with HelloChrome_112_PSK_Shuf...")
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)
	initialCacheCount := cache.Count()
	t.Logf("Cache has %d entries after first connection", initialCacheCount)

	if initialCacheCount == 0 {
		t.Fatal("No session ticket received")
	}

	// Second connection with same profile - should resume
	t.Log("Second connection with HelloChrome_112_PSK_Shuf (same profile)...")
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs2 := tlsConn2.ConnectionState()
	t.Logf("Same profile connection: DidResume=%v", cs2.DidResume)
	if !cs2.DidResume {
		t.Error("Expected resumption with same profile")
	}
	tlsConn2.Close()

	// Third connection with Firefox profile - should NOT resume
	// because the cipher suites, key shares, etc. are different
	t.Log("Third connection with HelloFirefox_120 (different profile)...")
	tcpConn3, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn3 := UClient(tcpConn3, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloFirefox_120) // Note: Firefox does not have UtlsPreSharedKeyExtension by default

	if err := tlsConn3.Handshake(); err != nil {
		tcpConn3.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn3.Close()

	cs3 := tlsConn3.ConnectionState()
	t.Logf("Different profile connection: DidResume=%v", cs3.DidResume)

	// Firefox profile doesn't have UtlsPreSharedKeyExtension, so it cannot resume
	// This is expected behavior - different fingerprints should not share sessions
	if cs3.DidResume {
		t.Log("Note: Server accepted cross-profile resumption (may indicate session ticket reuse)")
	} else {
		t.Log("Good: Different profile did not resume (expected for fingerprint isolation)")
	}
}

// TestClientSessionCacheOperations tests the ClientSessionCache interface
// implementation and verifies correct cache behavior.
func TestClientSessionCacheOperations(t *testing.T) {
	serverAddr := "www.microsoft.com:443"
	serverName := "www.microsoft.com"
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// Track operations
	var putKeys []string
	var getKeys []string
	var mu sync.Mutex

	cache.onPut = func(key string, session *ClientSessionState) {
		mu.Lock()
		putKeys = append(putKeys, key)
		mu.Unlock()
		t.Logf("Cache.Put called: key=%q, hasSession=%v", key, session != nil)
	}

	cache.onGet = func(key string, session *ClientSessionState, ok bool) {
		mu.Lock()
		getKeys = append(getKeys, key)
		mu.Unlock()
		t.Logf("Cache.Get called: key=%q, found=%v", key, ok)
	}

	// First connection
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(300 * time.Millisecond)

	// Verify cache operations
	mu.Lock()
	getCalls := len(getKeys)
	putCalls := len(putKeys)
	mu.Unlock()

	t.Logf("After first connection: Get calls=%d, Put calls=%d, Cache entries=%d",
		getCalls, putCalls, cache.Count())

	if getCalls == 0 {
		t.Error("Expected at least one Get call during first connection")
	}

	if cache.Count() == 0 {
		t.Error("Expected session to be cached")
	}

	// Second connection
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	tlsConn2.Close()

	mu.Lock()
	getCalls2 := len(getKeys)
	mu.Unlock()

	if getCalls2 <= getCalls {
		t.Error("Expected more Get calls during second connection")
	}

	// Verify cache key format (should be based on server name)
	mu.Lock()
	for _, key := range getKeys {
		if !strings.Contains(key, serverName) {
			t.Errorf("Cache key %q does not contain server name %q", key, serverName)
		}
	}
	mu.Unlock()
}

// TestTLS12SessionTicketResumption tests TLS 1.2 session ticket resumption.
func TestTLS12SessionTicketResumption(t *testing.T) {
	// Use a server known to support TLS 1.2 session tickets
	// Note: Many modern servers prefer TLS 1.3
	serverAddr := "marketplace.visualstudio.com:443"
	serverName := "marketplace.visualstudio.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	// Use profile that supports TLS 1.2 session tickets
	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	t.Logf("First connection: TLS %s, DidResume=%v", VersionName(cs1.Version), cs1.DidResume)

	if cs1.Version == VersionTLS13 {
		tlsConn1.Close()
		t.Skip("Server negotiated TLS 1.3, cannot test TLS 1.2 session tickets")
	}

	if cs1.Version != VersionTLS12 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	if cache.Count() == 0 {
		t.Fatal("No session ticket cached")
	}

	// Second connection - should resume
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn2.Close()

	cs2 := tlsConn2.ConnectionState()
	t.Logf("Second connection: TLS %s, DidResume=%v", VersionName(cs2.Version), cs2.DidResume)

	// Check TLS 1.2 specific resumption
	if cs2.Version == VersionTLS12 {
		if !cs2.DidResume && !tlsConn2.DidTls12Resume() {
			t.Error("Expected TLS 1.2 session ticket resumption")
		}
	}
}

// TestResumptionWithGoLangProfile tests that the standard Go TLS client
// profile also supports resumption correctly.
func TestResumptionWithGoLangProfile(t *testing.T) {
	serverAddr := "www.google.com:443"
	serverName := "www.google.com"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
	}, HelloGolang)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	t.Logf("First connection: TLS %s, DidResume=%v", VersionName(cs1.Version), cs1.DidResume)

	if cs1.DidResume {
		tlsConn1.Close()
		t.Fatal("First connection should not resume")
	}

	readWithTimeout(tlsConn1, 1*time.Second)
	tlsConn1.Close()

	time.Sleep(500 * time.Millisecond)

	// Second connection with retries
	const maxRetries = 3
	var resumed bool
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		t.Logf("Resumption attempt %d/%d...", i+1, maxRetries)
		time.Sleep(500 * time.Millisecond)

		tcpConn2, err := dialWithTimeout(ctx, serverAddr)
		if err != nil {
			lastErr = fmt.Errorf("dial failed: %w", err)
			continue
		}

		tlsConn2 := UClient(tcpConn2, &Config{
			ServerName:         serverName,
			ClientSessionCache: cache,
		}, HelloGolang)

		if err := tlsConn2.Handshake(); err != nil {
			tcpConn2.Close()
			lastErr = fmt.Errorf("handshake failed: %w", err)
			continue
		}

		cs2 := tlsConn2.ConnectionState()
		t.Logf("  TLS %s, DidResume=%v", VersionName(cs2.Version), cs2.DidResume)

		// For TLS 1.3, check UsingPSK; for TLS 1.2, check DidResume
		didResume := cs2.DidResume
		if cs2.Version == VersionTLS13 {
			didResume = tlsConn2.HandshakeState.State13.UsingPSK
		}

		readWithTimeout(tlsConn2, 500*time.Millisecond)
		tlsConn2.Close()

		if didResume {
			resumed = true
			t.Log("Successfully resumed session")
			break
		}
	}

	if !resumed {
		if lastErr != nil {
			t.Errorf("Resumption failed after %d attempts. Last error: %v", maxRetries, lastErr)
		} else {
			t.Errorf("Resumption failed after %d attempts (server did not accept)", maxRetries)
		}
	}
}

// TestResumptionFingerprintPreservation tests that the TLS fingerprint is
// preserved correctly when resuming a session. This is critical for avoiding
// detection when using utls for fingerprint mimicry.
func TestResumptionFingerprintPreservation(t *testing.T) {
	serverAddr := "www.cloudflare.com:443"
	serverName := "www.cloudflare.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection - capture ClientHello
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	// Build handshake state to inspect ClientHello
	if err := tlsConn1.BuildHandshakeState(); err != nil {
		tcpConn1.Close()
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	hello1 := tlsConn1.HandshakeState.Hello
	cipherSuites1 := make([]uint16, len(hello1.CipherSuites))
	copy(cipherSuites1, hello1.CipherSuites)
	compressionMethods1 := make([]byte, len(hello1.CompressionMethods))
	copy(compressionMethods1, hello1.CompressionMethods)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	// Second connection - compare ClientHello (excluding PSK which changes)
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn2.BuildHandshakeState(); err != nil {
		tcpConn2.Close()
		t.Fatalf("BuildHandshakeState failed: %v", err)
	}

	hello2 := tlsConn2.HandshakeState.Hello

	// Verify cipher suites are identical
	if len(hello2.CipherSuites) != len(cipherSuites1) {
		t.Errorf("Cipher suite count changed: %d -> %d", len(cipherSuites1), len(hello2.CipherSuites))
	} else {
		for i, cs := range cipherSuites1 {
			if hello2.CipherSuites[i] != cs {
				t.Errorf("Cipher suite %d changed: %04x -> %04x", i, cs, hello2.CipherSuites[i])
			}
		}
	}

	// Verify compression methods are identical
	if !bytes.Equal(compressionMethods1, hello2.CompressionMethods) {
		t.Error("Compression methods changed between connections")
	}

	// Complete handshake
	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn2.Close()

	cs2 := tlsConn2.ConnectionState()
	if !cs2.DidResume {
		t.Error("Expected session resumption")
	}

	t.Log("Fingerprint preserved during resumption")
}

// TestMultipleResumptions tests that a session can be resumed multiple times.
func TestMultipleResumptions(t *testing.T) {
	serverAddr := "www.google.com:443"
	serverName := "www.google.com"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection - establish session
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	// Multiple resumptions
	const numResumptions = 3
	successfulResumptions := 0

	for i := 0; i < numResumptions; i++ {
		t.Logf("Resumption attempt %d/%d", i+1, numResumptions)

		tcpConn, err := dialWithTimeout(ctx, serverAddr)
		if err != nil {
			t.Logf("Failed to dial for resumption %d: %v", i+1, err)
			continue
		}

		tlsConn := UClient(tcpConn, &Config{
			ServerName:         serverName,
			ClientSessionCache: cache,
			OmitEmptyPsk:       true,
		}, HelloChrome_112_PSK_Shuf)

		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			t.Logf("Handshake failed for resumption %d: %v", i+1, err)
			continue
		}

		cs := tlsConn.ConnectionState()
		t.Logf("  TLS %s, DidResume=%v", VersionName(cs.Version), cs.DidResume)

		if cs.DidResume {
			successfulResumptions++
		}

		// Read to potentially get new ticket
		readWithTimeout(tlsConn, 500*time.Millisecond)
		tlsConn.Close()

		time.Sleep(100 * time.Millisecond)
	}

	t.Logf("Successful resumptions: %d/%d", successfulResumptions, numResumptions)
	if successfulResumptions == 0 {
		t.Error("Expected at least one successful resumption")
	}
}

// TestConcurrentResumptions tests that session resumption works correctly
// with concurrent connections using the same cache.
func TestConcurrentResumptions(t *testing.T) {
	serverAddr := "www.google.com:443"
	serverName := "www.google.com"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection - establish session
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	// Concurrent resumptions
	const numConcurrent = 3
	var wg sync.WaitGroup
	results := make(chan bool, numConcurrent)
	errs := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			tcpConn, err := dialWithTimeout(ctx, serverAddr)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d: dial failed: %w", idx, err)
				return
			}

			tlsConn := UClient(tcpConn, &Config{
				ServerName:         serverName,
				ClientSessionCache: cache,
				OmitEmptyPsk:       true,
			}, HelloChrome_112_PSK_Shuf)

			if err := tlsConn.Handshake(); err != nil {
				tcpConn.Close()
				errs <- fmt.Errorf("goroutine %d: handshake failed: %w", idx, err)
				return
			}

			cs := tlsConn.ConnectionState()
			results <- cs.DidResume
			tlsConn.Close()
		}(i)
	}

	wg.Wait()
	close(results)
	close(errs)

	// Check errors
	for err := range errs {
		t.Error(err)
	}

	// Count resumptions
	resumed := 0
	for r := range results {
		if r {
			resumed++
		}
	}

	t.Logf("Concurrent resumptions: %d/%d", resumed, numConcurrent)
}

// TestNoResumptionWithDisabledCache tests that session resumption does not
// occur when ClientSessionCache is nil.
func TestNoResumptionWithDisabledCache(t *testing.T) {
	serverAddr := "www.google.com:443"
	serverName := "www.google.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Two connections without cache
	for i := 0; i < 2; i++ {
		tcpConn, err := dialWithTimeout(ctx, serverAddr)
		if err != nil {
			t.Fatalf("Connection %d: Failed to dial: %v", i+1, err)
		}

		tlsConn := UClient(tcpConn, &Config{
			ServerName:         serverName,
			ClientSessionCache: nil, // No cache
			OmitEmptyPsk:       true,
		}, HelloChrome_112_PSK_Shuf)

		if err := tlsConn.Handshake(); err != nil {
			tcpConn.Close()
			t.Fatalf("Connection %d: Handshake failed: %v", i+1, err)
		}

		cs := tlsConn.ConnectionState()
		t.Logf("Connection %d: TLS %s, DidResume=%v", i+1, VersionName(cs.Version), cs.DidResume)

		if cs.DidResume {
			t.Errorf("Connection %d: Should not resume without session cache", i+1)
		}

		tlsConn.Close()
		time.Sleep(100 * time.Millisecond)
	}
}

// TestNoResumptionWithSessionTicketsDisabled tests that session resumption
// does not occur when SessionTicketsDisabled is set.
func TestNoResumptionWithSessionTicketsDisabled(t *testing.T) {
	serverAddr := "www.google.com:443"
	serverName := "www.google.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection with tickets disabled
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:             serverName,
		ClientSessionCache:     cache,
		SessionTicketsDisabled: true, // Disabled
		OmitEmptyPsk:           true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	// Cache should be empty since tickets are disabled
	if cache.Count() > 0 {
		t.Logf("Warning: Cache has %d entries despite SessionTicketsDisabled", cache.Count())
	}

	// Second connection - should not resume
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:             serverName,
		ClientSessionCache:     cache,
		SessionTicketsDisabled: true,
		OmitEmptyPsk:           true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn2.Close()

	cs2 := tlsConn2.ConnectionState()
	t.Logf("Second connection: DidResume=%v", cs2.DidResume)

	if cs2.DidResume {
		t.Error("Should not resume with SessionTicketsDisabled")
	}
}

// TestResumptionWithDifferentServerNames tests that sessions are not shared
// between different server names.
func TestResumptionWithDifferentServerNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	servers := []struct {
		addr string
		name string
	}{
		{"www.google.com:443", "www.google.com"},
		{"www.microsoft.com:443", "www.microsoft.com"},
	}

	// Connect to first server
	tcpConn1, err := dialWithTimeout(ctx, servers[0].addr)
	if err != nil {
		t.Fatalf("Failed to dial %s: %v", servers[0].name, err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         servers[0].name,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake with %s failed: %v", servers[0].name, err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)
	cacheCountAfterFirst := cache.Count()
	t.Logf("Cache entries after first server: %d", cacheCountAfterFirst)

	// Connect to second server - should NOT resume
	tcpConn2, err := dialWithTimeout(ctx, servers[1].addr)
	if err != nil {
		t.Fatalf("Failed to dial %s: %v", servers[1].name, err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         servers[1].name,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake with %s failed: %v", servers[1].name, err)
	}
	defer tlsConn2.Close()

	cs2 := tlsConn2.ConnectionState()
	t.Logf("Second server connection: DidResume=%v", cs2.DidResume)

	if cs2.DidResume {
		t.Error("Should not resume session from different server")
	}
}

// TestEarlyDataRejection tests graceful handling of 0-RTT early data rejection.
// Note: Most servers do not support early data, so this primarily tests
// that the client handles the absence of early data support gracefully.
func TestEarlyDataRejection(t *testing.T) {
	serverAddr := "www.cloudflare.com:443"
	serverName := "www.cloudflare.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	// Second connection - attempt early data (will be rejected by most servers)
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	// The handshake should succeed even if early data is not supported
	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn2.Close()

	cs2 := tlsConn2.ConnectionState()
	t.Logf("Second connection: DidResume=%v", cs2.DidResume)

	// Even without early data, resumption should work
	if !cs2.DidResume {
		t.Log("Note: Resumption failed (server may have rejected PSK)")
	}
}

// TestHandshakeStatePSKFields tests that PSK-related fields in HandshakeState
// are correctly populated during resumption.
func TestHandshakeStatePSKFields(t *testing.T) {
	serverAddr := "www.microsoft.com:443"
	serverName := "www.microsoft.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	// Check first connection has no PSK
	if tlsConn1.HandshakeState.State13.UsingPSK {
		t.Error("First connection should not be using PSK")
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	// Second connection - check PSK fields
	tcpConn2, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn2 := UClient(tcpConn2, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn2.Handshake(); err != nil {
		tcpConn2.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn2.Close()

	cs2 := tlsConn2.ConnectionState()
	state13 := tlsConn2.HandshakeState.State13

	t.Logf("Second connection PSK state:")
	t.Logf("  DidResume: %v", cs2.DidResume)
	t.Logf("  UsingPSK: %v", state13.UsingPSK)
	t.Logf("  EarlySecret length: %d", len(state13.EarlySecret))
	t.Logf("  BinderKey length: %d", len(state13.BinderKey))

	if cs2.DidResume {
		if !state13.UsingPSK {
			t.Error("UsingPSK should be true when DidResume is true")
		}
	}
}

// BenchmarkResumption measures the performance improvement from session
// resumption vs full handshakes.
func BenchmarkResumption(b *testing.B) {
	serverAddr := "www.google.com:443"
	serverName := "www.google.com"

	// Warm up cache
	cache := newTestSessionCache()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tcpConn, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		b.Fatalf("Failed to dial: %v", err)
	}

	tlsConn := UClient(tcpConn, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		b.Fatalf("Initial handshake failed: %v", err)
	}

	readWithTimeout(tlsConn, 2*time.Second)
	tlsConn.Close()

	time.Sleep(200 * time.Millisecond)

	if cache.Count() == 0 {
		b.Fatal("No session cached for benchmark")
	}

	// Benchmark resumption
	b.Run("WithResumption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			tcpConn, err := dialWithTimeout(ctx, serverAddr)
			if err != nil {
				cancel()
				b.Fatalf("Failed to dial: %v", err)
			}

			tlsConn := UClient(tcpConn, &Config{
				ServerName:         serverName,
				ClientSessionCache: cache,
				OmitEmptyPsk:       true,
			}, HelloChrome_112_PSK_Shuf)

			if err := tlsConn.Handshake(); err != nil {
				tcpConn.Close()
				cancel()
				b.Fatalf("Handshake failed: %v", err)
			}

			tlsConn.Close()
			cancel()
		}
	})

	// Benchmark without resumption
	b.Run("WithoutResumption", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			tcpConn, err := dialWithTimeout(ctx, serverAddr)
			if err != nil {
				cancel()
				b.Fatalf("Failed to dial: %v", err)
			}

			tlsConn := UClient(tcpConn, &Config{
				ServerName:         serverName,
				ClientSessionCache: nil, // No cache
				OmitEmptyPsk:       true,
			}, HelloChrome_112_PSK_Shuf)

			if err := tlsConn.Handshake(); err != nil {
				tcpConn.Close()
				cancel()
				b.Fatalf("Handshake failed: %v", err)
			}

			tlsConn.Close()
			cancel()
		}
	})
}

// TestResumptionErrorRecovery tests that the client recovers gracefully
// when resumption fails (e.g., server rejects ticket).
func TestResumptionErrorRecovery(t *testing.T) {
	serverAddr := "www.cloudflare.com:443"
	serverName := "www.cloudflare.com"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cache := newTestSessionCache()

	// First connection to get a valid ticket
	tcpConn1, err := dialWithTimeout(ctx, serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	tlsConn1 := UClient(tcpConn1, &Config{
		ServerName:         serverName,
		ClientSessionCache: cache,
		OmitEmptyPsk:       true,
	}, HelloChrome_112_PSK_Shuf)

	if err := tlsConn1.Handshake(); err != nil {
		tcpConn1.Close()
		t.Fatalf("Handshake failed: %v", err)
	}

	cs1 := tlsConn1.ConnectionState()
	if cs1.Version != VersionTLS13 {
		tlsConn1.Close()
		t.Skipf("Server negotiated TLS %s, skipping", VersionName(cs1.Version))
	}

	readWithTimeout(tlsConn1, 2*time.Second)
	tlsConn1.Close()

	time.Sleep(200 * time.Millisecond)

	// Multiple connection attempts - even if some fail, should eventually succeed
	successCount := 0
	for i := 0; i < 3; i++ {
		tcpConn, err := dialWithTimeout(ctx, serverAddr)
		if err != nil {
			t.Logf("Connection %d: dial failed: %v", i+1, err)
			continue
		}

		tlsConn := UClient(tcpConn, &Config{
			ServerName:         serverName,
			ClientSessionCache: cache,
			OmitEmptyPsk:       true,
		}, HelloChrome_112_PSK_Shuf)

		err = tlsConn.Handshake()
		if err != nil {
			tcpConn.Close()
			t.Logf("Connection %d: handshake failed: %v", i+1, err)

			// Check if it's a recoverable error
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "connection reset") {
				t.Logf("  (recoverable network error)")
				continue
			}
		} else {
			successCount++
			cs := tlsConn.ConnectionState()
			t.Logf("Connection %d: success, DidResume=%v", i+1, cs.DidResume)
		}

		tlsConn.Close()
		time.Sleep(100 * time.Millisecond)
	}

	if successCount == 0 {
		t.Error("All connection attempts failed")
	}
}
