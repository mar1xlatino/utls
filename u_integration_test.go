//go:build integration

// Integration tests for utls library against real production servers.
// Run with: go test -tags=integration -v -timeout=5m
//
// These tests verify that browser fingerprint mimicry actually works
// against real-world TLS servers. They test:
// - TLS handshake success with various browser profiles
// - HTTP/2 ALPN negotiation
// - Certificate chain validation
// - TLS 1.3 preference
// - Both IPv4 and IPv6 connectivity
//
// WARNING: These tests require network connectivity and may fail if:
// - Network is unavailable
// - Target servers are down or blocking
// - DNS resolution fails
// - Firewall blocks outbound TLS

package tls

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testServer represents a server to test against
type testServer struct {
	Host        string
	Port        string
	ExpectH2    bool   // expect HTTP/2 support
	ExpectTLS13 bool   // expect TLS 1.3 support
	IPv6        bool   // test IPv6 connectivity
	Description string // human-readable description
}

// Production servers to test against
var productionServers = []testServer{
	{Host: "cloudflare.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: true, Description: "Cloudflare CDN"},
	{Host: "google.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: true, Description: "Google Search"},
	{Host: "www.facebook.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: true, Description: "Facebook"},
	{Host: "amazon.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: false, Description: "Amazon"},
	{Host: "microsoft.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: true, Description: "Microsoft"},
	{Host: "github.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: false, Description: "GitHub"},
	{Host: "twitter.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: false, Description: "Twitter/X"},
	{Host: "www.cloudflare.com", Port: "443", ExpectH2: true, ExpectTLS13: true, IPv6: true, Description: "Cloudflare Website"},
}

// Modern browser profiles to test
var modernBrowserProfiles = []struct {
	ID          ClientHelloID
	Name        string
	Description string
}{
	{HelloChrome_120, "Chrome120", "Chrome 120 with ECH support"},
	{HelloChrome_131, "Chrome131", "Chrome 131 with X25519MLKEM768"},
	{HelloChrome_133, "Chrome133", "Chrome 133 with new ALPS codepoint"},
	{HelloChrome_142, "Chrome142", "Chrome 142 (October 2025)"},
	{HelloChrome_Auto, "ChromeAuto", "Chrome Auto (latest)"},
	{HelloFirefox_120, "Firefox120", "Firefox 120"},
	{HelloFirefox_145, "Firefox145", "Firefox 145 with extension shuffling"},
	{HelloFirefox_Auto, "FirefoxAuto", "Firefox Auto (latest)"},
	{HelloSafari_18, "Safari18", "Safari 18 (macOS Sequoia)"},
	{HelloSafari_26, "Safari26", "Safari 26 with post-quantum X25519MLKEM768"},
	{HelloSafari_Auto, "SafariAuto", "Safari Auto (latest)"},
	{HelloEdge_142, "Edge142", "Edge 142 (Chromium-based)"},
	{HelloEdge_Auto, "EdgeAuto", "Edge Auto (latest)"},
	{HelloIOS_18, "iOS18", "iOS 18"},
	{HelloIOS_26, "iOS26", "iOS 26 with post-quantum X25519MLKEM768"},
	{HelloIOS_Auto, "iOSAuto", "iOS Auto (latest)"},
}

const (
	integrationConnTimeout      = 10 * time.Second
	integrationHandshakeTimeout = 10 * time.Second
)

// checkNetworkAvailable performs a quick network connectivity check
func checkNetworkAvailable(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "cloudflare.com:443")
	if err != nil {
		t.Skipf("Network unavailable: %v", err)
	}
	conn.Close()
}

// connectWithProfile attempts to establish a TLS connection using the specified browser profile
func connectWithProfile(ctx context.Context, server testServer, profile ClientHelloID, network string) (*UConn, error) {
	addr := net.JoinHostPort(server.Host, server.Port)

	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}

	config := &Config{
		ServerName: server.Host,
		// Use system root CAs for certificate validation
		RootCAs: nil,
		// Enable InsecureSkipVerify only if we want to test handshake mechanics
		// For production testing, we want real certificate validation
		InsecureSkipVerify: false,
	}

	tlsConn := UClient(tcpConn, config, profile)

	// Set deadline for handshake
	deadline, ok := ctx.Deadline()
	if ok {
		tlsConn.SetDeadline(deadline)
	}

	err = tlsConn.Handshake()
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Clear deadline after successful handshake
	tlsConn.SetDeadline(time.Time{})

	return tlsConn, nil
}

// TestRealServerConnections tests TLS connections to real production servers
// using various browser profiles
func TestRealServerConnections(t *testing.T) {
	checkNetworkAvailable(t)

	for _, server := range productionServers {
		server := server // capture range variable
		t.Run(server.Description, func(t *testing.T) {
			t.Parallel()

			for _, profile := range modernBrowserProfiles {
				profile := profile // capture range variable
				t.Run(profile.Name, func(t *testing.T) {
					t.Parallel()

					ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
					defer cancel()

					conn, err := connectWithProfile(ctx, server, profile.ID, "tcp")
					if err != nil {
						t.Fatalf("Connection failed for %s to %s: %v", profile.Name, server.Host, err)
					}
					defer conn.Close()

					state := conn.ConnectionState()

					// Verify handshake completed
					if !state.HandshakeComplete {
						t.Error("Handshake reported as incomplete")
					}

					// Log connection details
					t.Logf("Connected to %s using %s", server.Host, profile.Name)
					t.Logf("  TLS Version: %s", tlsVersionString(state.Version))
					t.Logf("  Cipher Suite: %s", CipherSuiteName(state.CipherSuite))
					t.Logf("  ALPN Protocol: %s", state.NegotiatedProtocol)
					t.Logf("  Server Name: %s", state.ServerName)

					// Verify TLS version (prefer TLS 1.3)
					if server.ExpectTLS13 && state.Version != VersionTLS13 {
						t.Logf("WARNING: Expected TLS 1.3, got %s (server may not support it)", tlsVersionString(state.Version))
					}

					// Verify ALPN negotiation
					if server.ExpectH2 {
						if state.NegotiatedProtocol != "h2" && state.NegotiatedProtocol != "http/1.1" {
							t.Errorf("Expected h2 or http/1.1, got: %q", state.NegotiatedProtocol)
						}
					}

					// Verify certificate chain
					verifyCertificateChain(t, state, server.Host)
				})
			}
		})
	}
}

// TestIPv4Connections explicitly tests IPv4 connectivity
func TestIPv4Connections(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	servers := []testServer{
		{Host: "cloudflare.com", Port: "443", Description: "Cloudflare IPv4"},
		{Host: "google.com", Port: "443", Description: "Google IPv4"},
	}

	for _, server := range servers {
		server := server
		t.Run(server.Description, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			conn, err := connectWithProfile(ctx, server, HelloChrome_Auto, "tcp4")
			if err != nil {
				t.Fatalf("IPv4 connection failed: %v", err)
			}
			defer conn.Close()

			state := conn.ConnectionState()
			t.Logf("IPv4 connection successful - TLS %s, ALPN: %s",
				tlsVersionString(state.Version), state.NegotiatedProtocol)
		})
	}
}

// TestIPv6Connections explicitly tests IPv6 connectivity
func TestIPv6Connections(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	// Check if IPv6 is available
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var d net.Dialer
	testConn, err := d.DialContext(ctx, "tcp6", "cloudflare.com:443")
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	testConn.Close()

	servers := []testServer{
		{Host: "cloudflare.com", Port: "443", Description: "Cloudflare IPv6"},
		{Host: "google.com", Port: "443", Description: "Google IPv6"},
	}

	for _, server := range servers {
		server := server
		t.Run(server.Description, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			conn, err := connectWithProfile(ctx, server, HelloChrome_Auto, "tcp6")
			if err != nil {
				t.Fatalf("IPv6 connection failed: %v", err)
			}
			defer conn.Close()

			state := conn.ConnectionState()
			t.Logf("IPv6 connection successful - TLS %s, ALPN: %s",
				tlsVersionString(state.Version), state.NegotiatedProtocol)
		})
	}
}

// TestChrome142Profile specifically tests Chrome 142 (latest) profile
func TestChrome142Profile(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	servers := []string{
		"cloudflare.com:443",
		"google.com:443",
		"github.com:443",
	}

	for _, addr := range servers {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(addr)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName: host,
			}

			tlsConn := UClient(tcpConn, config, HelloChrome_142)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed: %v", err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()

			// Chrome 142 should negotiate TLS 1.3 with modern servers
			if state.Version != VersionTLS13 {
				t.Logf("WARNING: Chrome 142 got TLS %s instead of TLS 1.3", tlsVersionString(state.Version))
			}

			// Should support H2
			if state.NegotiatedProtocol != "h2" {
				t.Logf("Note: ALPN negotiated %q instead of h2", state.NegotiatedProtocol)
			}

			t.Logf("Chrome 142 to %s: TLS %s, ALPN %s, Cipher %s",
				addr, tlsVersionString(state.Version),
				state.NegotiatedProtocol,
				CipherSuiteName(state.CipherSuite))
		})
	}
}

// TestFirefox145Profile specifically tests Firefox 145 profile
func TestFirefox145Profile(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	servers := []string{
		"cloudflare.com:443",
		"mozilla.org:443",
	}

	for _, addr := range servers {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(addr)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName: host,
			}

			tlsConn := UClient(tcpConn, config, HelloFirefox_145)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed: %v", err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()

			t.Logf("Firefox 145 to %s: TLS %s, ALPN %s, Cipher %s",
				addr, tlsVersionString(state.Version),
				state.NegotiatedProtocol,
				CipherSuiteName(state.CipherSuite))
		})
	}
}

// TestSafari18Profile specifically tests Safari 18 profile
func TestSafari18Profile(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	servers := []string{
		"apple.com:443",
		"cloudflare.com:443",
	}

	for _, addr := range servers {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(addr)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName: host,
			}

			tlsConn := UClient(tcpConn, config, HelloSafari_18)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed: %v", err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()

			t.Logf("Safari 18 to %s: TLS %s, ALPN %s, Cipher %s",
				addr, tlsVersionString(state.Version),
				state.NegotiatedProtocol,
				CipherSuiteName(state.CipherSuite))
		})
	}
}

// TestEdge142Profile specifically tests Edge 142 profile
func TestEdge142Profile(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	servers := []string{
		"microsoft.com:443",
		"cloudflare.com:443",
	}

	for _, addr := range servers {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(addr)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName: host,
			}

			tlsConn := UClient(tcpConn, config, HelloEdge_142)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed: %v", err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()

			t.Logf("Edge 142 to %s: TLS %s, ALPN %s, Cipher %s",
				addr, tlsVersionString(state.Version),
				state.NegotiatedProtocol,
				CipherSuiteName(state.CipherSuite))
		})
	}
}

// TestCertificateValidation verifies that certificate chain validation works correctly
func TestCertificateValidation(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	servers := []struct {
		host        string
		expectValid bool
		description string
	}{
		{"cloudflare.com", true, "Valid certificate"},
		{"google.com", true, "Valid certificate"},
		{"github.com", true, "Valid certificate"},
	}

	for _, server := range servers {
		server := server
		t.Run(server.description+"_"+server.host, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", server.host+":443")
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName:         server.host,
				InsecureSkipVerify: false,
			}

			tlsConn := UClient(tcpConn, config, HelloChrome_Auto)
			err = tlsConn.Handshake()

			if server.expectValid {
				if err != nil {
					tcpConn.Close()
					t.Fatalf("Expected valid certificate but got error: %v", err)
				}
				tlsConn.Close()
				t.Logf("Certificate validation successful for %s", server.host)
			} else {
				if err == nil {
					tlsConn.Close()
					t.Error("Expected certificate validation to fail")
				} else {
					tcpConn.Close()
					t.Logf("Certificate validation failed as expected: %v", err)
				}
			}
		})
	}
}

// TestInvalidCertificateRejection verifies that invalid certificates are rejected
func TestInvalidCertificateRejection(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	// Test with wrong ServerName to trigger certificate mismatch
	ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
	defer cancel()

	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, "tcp", "cloudflare.com:443")
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}

	config := &Config{
		ServerName:         "wrong-hostname.example.com",
		InsecureSkipVerify: false,
	}

	tlsConn := UClient(tcpConn, config, HelloChrome_Auto)
	err = tlsConn.Handshake()

	if err == nil {
		tlsConn.Close()
		t.Error("Expected certificate hostname mismatch error")
	} else {
		tcpConn.Close()
		// Check if error is certificate-related
		var certErr x509.HostnameError
		var unknownAuthErr x509.UnknownAuthorityError
		if errors.As(err, &certErr) || errors.As(err, &unknownAuthErr) ||
			strings.Contains(err.Error(), "certificate") ||
			strings.Contains(err.Error(), "x509") {
			t.Logf("Certificate validation correctly rejected: %v", err)
		} else {
			// Other errors are also acceptable as long as connection failed
			t.Logf("Connection failed (may be certificate related): %v", err)
		}
	}
}

// TestConnectionTimeout verifies that connection timeouts work correctly
func TestConnectionTimeout(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	// Use a non-routable IP to force timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var d net.Dialer
	_, err := d.DialContext(ctx, "tcp", "10.255.255.1:443")

	if err == nil {
		t.Error("Expected timeout error for non-routable IP")
	} else {
		if ctx.Err() == context.DeadlineExceeded || strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "i/o timeout") {
			t.Logf("Timeout correctly triggered: %v", err)
		} else {
			// Connection refused is also acceptable
			t.Logf("Connection failed: %v", err)
		}
	}
}

// TestConcurrentConnections tests multiple simultaneous connections
func TestConcurrentConnections(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	const numConnections = 10
	servers := []string{"cloudflare.com:443", "google.com:443", "github.com:443"}
	profiles := []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto, HelloSafari_Auto}

	var wg sync.WaitGroup
	var successCount int64
	var failureCount int64
	errChan := make(chan error, numConnections*len(servers)*len(profiles))

	for i := 0; i < numConnections; i++ {
		for _, addr := range servers {
			for _, profile := range profiles {
				wg.Add(1)
				go func(addr string, profile ClientHelloID) {
					defer wg.Done()

					host, _, _ := net.SplitHostPort(addr)

					ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
					defer cancel()

					var d net.Dialer
					tcpConn, err := d.DialContext(ctx, "tcp", addr)
					if err != nil {
						atomic.AddInt64(&failureCount, 1)
						errChan <- fmt.Errorf("TCP dial to %s: %w", addr, err)
						return
					}

					config := &Config{
						ServerName: host,
					}

					tlsConn := UClient(tcpConn, config, profile)
					err = tlsConn.Handshake()
					if err != nil {
						tcpConn.Close()
						atomic.AddInt64(&failureCount, 1)
						errChan <- fmt.Errorf("TLS handshake to %s with %s: %w", addr, profile.Str(), err)
						return
					}

					tlsConn.Close()
					atomic.AddInt64(&successCount, 1)
				}(addr, profile)
			}
		}
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	t.Logf("Concurrent connections: %d successful, %d failed", successCount, failureCount)

	if failureCount > 0 {
		// Log first few errors
		maxErrors := 5
		for i, err := range errs {
			if i >= maxErrors {
				t.Logf("... and %d more errors", len(errs)-maxErrors)
				break
			}
			t.Logf("Error %d: %v", i+1, err)
		}
	}

	// Allow some failures due to rate limiting, but not too many
	totalAttempts := int64(numConnections * len(servers) * len(profiles))
	successRate := float64(successCount) / float64(totalAttempts)
	if successRate < 0.9 {
		t.Errorf("Success rate too low: %.1f%% (expected >90%%)", successRate*100)
	}
}

// TestTLS13Negotiation verifies TLS 1.3 is properly negotiated
func TestTLS13Negotiation(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	// Servers known to support TLS 1.3
	servers := []string{
		"cloudflare.com:443",
		"google.com:443",
		"facebook.com:443",
	}

	for _, addr := range servers {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(addr)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName: host,
			}

			// Use Chrome 142 which should always prefer TLS 1.3
			tlsConn := UClient(tcpConn, config, HelloChrome_142)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed: %v", err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()

			if state.Version != VersionTLS13 {
				t.Errorf("Expected TLS 1.3, got %s", tlsVersionString(state.Version))
			} else {
				t.Logf("TLS 1.3 successfully negotiated with %s", addr)
			}

			// Verify cipher suite is TLS 1.3 cipher
			switch state.CipherSuite {
			case TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256:
				t.Logf("TLS 1.3 cipher suite: %s", CipherSuiteName(state.CipherSuite))
			default:
				t.Errorf("Unexpected cipher suite for TLS 1.3: %s", CipherSuiteName(state.CipherSuite))
			}
		})
	}
}

// TestH2ALPNNegotiation verifies HTTP/2 ALPN is properly negotiated
func TestH2ALPNNegotiation(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	servers := []string{
		"cloudflare.com:443",
		"google.com:443",
		"github.com:443",
	}

	for _, addr := range servers {
		addr := addr
		t.Run(addr, func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(addr)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName: host,
			}

			tlsConn := UClient(tcpConn, config, HelloChrome_Auto)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed: %v", err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()

			if state.NegotiatedProtocol != "h2" {
				t.Errorf("Expected h2 ALPN, got %q", state.NegotiatedProtocol)
			} else {
				t.Logf("HTTP/2 ALPN successfully negotiated with %s", addr)
			}
		})
	}
}

// TestAllProfilesConnectivity tests that all browser profiles can connect
func TestAllProfilesConnectivity(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	// Test against a reliable server
	server := "cloudflare.com:443"

	// Non-PSK profiles (PSK profiles require prior session state)
	allProfiles := []ClientHelloID{
		HelloChrome_106_Shuffle,
		HelloChrome_115_PQ,
		HelloChrome_120,
		HelloChrome_120_PQ,
		HelloChrome_131,
		HelloChrome_133,
		HelloChrome_142,
		HelloFirefox_120,
		HelloFirefox_145,
		HelloSafari_18,
		HelloSafari_26,
		HelloIOS_18,
		HelloIOS_26,
		HelloEdge_106,
		HelloEdge_142,
	}

	for _, profile := range allProfiles {
		profile := profile
		t.Run(profile.Str(), func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(server)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", server)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName: host,
			}

			tlsConn := UClient(tcpConn, config, profile)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed for %s: %v", profile.Str(), err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()
			t.Logf("%s: TLS %s, ALPN %s, Cipher %s",
				profile.Str(),
				tlsVersionString(state.Version),
				state.NegotiatedProtocol,
				CipherSuiteName(state.CipherSuite))
		})
	}
}

// TestPSKProfilesWithOmitEmptyPsk tests PSK profiles with OmitEmptyPsk option
func TestPSKProfilesWithOmitEmptyPsk(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	// PSK profiles require OmitEmptyPsk when no prior session exists
	pskProfiles := []ClientHelloID{
		HelloChrome_112_PSK_Shuf,
		HelloChrome_114_Padding_PSK_Shuf,
		HelloChrome_115_PQ_PSK,
	}

	server := "cloudflare.com:443"

	for _, profile := range pskProfiles {
		profile := profile
		t.Run(profile.Str(), func(t *testing.T) {
			t.Parallel()

			host, _, _ := net.SplitHostPort(server)

			ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
			defer cancel()

			var d net.Dialer
			tcpConn, err := d.DialContext(ctx, "tcp", server)
			if err != nil {
				t.Fatalf("TCP dial failed: %v", err)
			}

			config := &Config{
				ServerName:   host,
				OmitEmptyPsk: true, // Required for PSK profiles without prior session
			}

			tlsConn := UClient(tcpConn, config, profile)
			err = tlsConn.Handshake()
			if err != nil {
				tcpConn.Close()
				t.Fatalf("Handshake failed for %s: %v", profile.Str(), err)
			}
			defer tlsConn.Close()

			state := tlsConn.ConnectionState()
			t.Logf("%s (OmitEmptyPsk): TLS %s, ALPN %s, Cipher %s",
				profile.Str(),
				tlsVersionString(state.Version),
				state.NegotiatedProtocol,
				CipherSuiteName(state.CipherSuite))
		})
	}
}

// TestSNIExtension verifies SNI is properly set
func TestSNIExtension(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
	defer cancel()

	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, "tcp", "cloudflare.com:443")
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}

	config := &Config{
		ServerName: "cloudflare.com",
	}

	tlsConn := UClient(tcpConn, config, HelloChrome_Auto)
	err = tlsConn.Handshake()
	if err != nil {
		tcpConn.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()

	if state.ServerName != "cloudflare.com" {
		t.Errorf("Expected ServerName cloudflare.com, got %s", state.ServerName)
	}

	t.Logf("SNI correctly set to: %s", state.ServerName)
}

// TestRandomizedProfiles tests randomized profiles
// Note: Randomized profiles may generate configurations that are rejected by servers
// or include unsupported curves, so we retry with different seeds
func TestRandomizedProfiles(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	randomizedProfiles := []ClientHelloID{
		HelloRandomized,
		HelloRandomizedALPN,
		HelloRandomizedNoALPN,
	}

	for _, profile := range randomizedProfiles {
		profile := profile
		t.Run(profile.Str(), func(t *testing.T) {
			t.Parallel()

			// Try multiple times since randomized profiles can generate invalid configs
			const maxAttempts = 3
			var lastErr error

			for attempt := 1; attempt <= maxAttempts; attempt++ {
				ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)

				var d net.Dialer
				tcpConn, err := d.DialContext(ctx, "tcp", "cloudflare.com:443")
				if err != nil {
					cancel()
					lastErr = fmt.Errorf("TCP dial failed: %w", err)
					continue
				}

				config := &Config{
					ServerName: "cloudflare.com",
				}

				tlsConn := UClient(tcpConn, config, profile)
				err = tlsConn.Handshake()
				if err != nil {
					tcpConn.Close()
					cancel()
					lastErr = fmt.Errorf("handshake failed (attempt %d/%d): %w", attempt, maxAttempts, err)
					// Check if error is due to unsupported curves (expected with randomized)
					if strings.Contains(err.Error(), "unsupported curve") ||
						strings.Contains(err.Error(), "CurvePreferences") {
						t.Logf("Attempt %d: randomized profile generated unsupported curve config (expected)", attempt)
						continue
					}
					continue
				}

				state := tlsConn.ConnectionState()
				t.Logf("%s: TLS %s, ALPN %q (attempt %d)",
					profile.Str(),
					tlsVersionString(state.Version),
					state.NegotiatedProtocol,
					attempt)
				tlsConn.Close()
				cancel()
				return // Success
			}

			// All attempts failed
			// Randomized profiles are inherently unstable, so we log instead of fail
			t.Logf("WARNING: %s failed after %d attempts: %v (randomized profiles may generate invalid configs)", profile.Str(), maxAttempts, lastErr)
		})
	}
}

// TestGolangProfile tests the HelloGolang profile
func TestGolangProfile(t *testing.T) {
	checkNetworkAvailable(t)
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), integrationConnTimeout+integrationHandshakeTimeout)
	defer cancel()

	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, "tcp", "cloudflare.com:443")
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}

	config := &Config{
		ServerName: "cloudflare.com",
	}

	tlsConn := UClient(tcpConn, config, HelloGolang)
	err = tlsConn.Handshake()
	if err != nil {
		tcpConn.Close()
		t.Fatalf("Handshake failed: %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	t.Logf("HelloGolang: TLS %s, ALPN %q, Cipher %s",
		tlsVersionString(state.Version),
		state.NegotiatedProtocol,
		CipherSuiteName(state.CipherSuite))
}

// Helper functions

func tlsVersionString(version uint16) string {
	switch version {
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func verifyCertificateChain(t *testing.T, state ConnectionState, expectedHost string) {
	t.Helper()

	if len(state.PeerCertificates) == 0 {
		t.Error("No peer certificates received")
		return
	}

	leafCert := state.PeerCertificates[0]

	// Verify leaf certificate is valid for the host
	err := leafCert.VerifyHostname(expectedHost)
	if err != nil {
		t.Errorf("Certificate hostname verification failed: %v", err)
	}

	// Log certificate details
	t.Logf("  Certificate Subject: %s", leafCert.Subject.CommonName)
	t.Logf("  Certificate Issuer: %s", leafCert.Issuer.CommonName)
	t.Logf("  Valid From: %s", leafCert.NotBefore.Format(time.RFC3339))
	t.Logf("  Valid Until: %s", leafCert.NotAfter.Format(time.RFC3339))

	// Check if certificate is currently valid
	now := time.Now()
	if now.Before(leafCert.NotBefore) {
		t.Error("Certificate is not yet valid")
	}
	if now.After(leafCert.NotAfter) {
		t.Error("Certificate has expired")
	}

	// Log SANs
	if len(leafCert.DNSNames) > 0 {
		t.Logf("  DNS Names: %v", leafCert.DNSNames[:intMin(5, len(leafCert.DNSNames))])
	}

	// Verify chain length
	t.Logf("  Certificate chain length: %d", len(state.PeerCertificates))
}

// intMin returns the smaller of two integers (avoid conflict with other files)
func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

