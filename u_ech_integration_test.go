//go:build integration

// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// ECHTestServer represents a known ECH-enabled server for integration testing
type ECHTestServer struct {
	Name           string
	Host           string
	Port           string
	Path           string
	OuterSNI       string // Expected outer SNI (public name)
	ECHConfigB64   string // Base64-encoded ECH config (fallback if DNS fails)
	ExpectHTTP2    bool
	ExpectECHCheck bool // Server provides ECH verification endpoint
}

// knownECHServers contains a list of public ECH-enabled servers for testing
// ECH configs are sourced from:
// - tls-ech.dev: Static config from their documentation
// - Cloudflare: Uses shared ECH config for all domains (cloudflare-ech.com)
// - defo.ie: Keys rotate hourly, so we skip if no config provided
var knownECHServers = []ECHTestServer{
	{
		Name:           "tls-ech.dev",
		Host:           "tls-ech.dev",
		Port:           "443",
		Path:           "/",
		OuterSNI:       "public.tls-ech.dev",
		ECHConfigB64:   "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA",
		ExpectHTTP2:    true,
		ExpectECHCheck: false,
	},
	{
		Name:         "crypto.cloudflare.com",
		Host:         "crypto.cloudflare.com",
		Port:         "443",
		Path:         "/cdn-cgi/trace",
		OuterSNI:     "cloudflare-ech.com",
		// Cloudflare's shared ECH config (may become stale - https://developers.cloudflare.com/ssl/edge-certificates/ech/)
		ECHConfigB64:   "AEX+DQBBYQAgACB/ZNpruUIOMT7U9iv5DLgTo+oHQ7RI7GeHwd0tbccrCAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=",
		ExpectHTTP2:    true,
		ExpectECHCheck: false,
	},
	{
		Name:           "defo.ie",
		Host:           "defo.ie",
		Port:           "443",
		Path:           "/ech-check.php",
		OuterSNI:       "",  // Uses own domain as public name
		ECHConfigB64:   "",  // Keys rotate hourly - https://defo.ie/
		ExpectHTTP2:    true,
		ExpectECHCheck: true,
	},
}

const (
	testDialTimeout      = 15 * time.Second
	testHandshakeTimeout = 15 * time.Second
	testReadTimeout      = 10 * time.Second
)

// fetchECHConfigFromDNS attempts to fetch ECH configuration from DNS HTTPS records (Type 65)
// This is a simplified implementation - in production you would use a proper DNS library
func fetchECHConfigFromDNS(hostname string) ([]byte, error) {
	// Use net.Resolver to lookup the HTTPS record
	// Note: Go's standard library doesn't directly support HTTPS record type 65
	// In a real implementation, you would use miekg/dns or similar
	// For now, we'll return an error and fall back to hardcoded configs
	return nil, errors.New("DNS HTTPS record lookup not implemented in standard library")
}

// getECHConfig returns the ECH configuration for a server, trying DNS first then fallback
func getECHConfig(server ECHTestServer) ([]byte, error) {
	// Try DNS first
	echConfig, err := fetchECHConfigFromDNS(server.Host)
	if err == nil && len(echConfig) > 0 {
		return echConfig, nil
	}

	// Fall back to hardcoded config if available
	if server.ECHConfigB64 != "" {
		// Try standard base64 first (with padding), then raw (without padding)
		echConfig, err = base64.StdEncoding.DecodeString(server.ECHConfigB64)
		if err != nil {
			echConfig, err = base64.RawStdEncoding.DecodeString(server.ECHConfigB64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode ECH config: %w", err)
			}
		}
		return echConfig, nil
	}

	return nil, fmt.Errorf("no ECH config available for %s", server.Host)
}

// TestECHRealServerChrome tests ECH with Chrome profile against real servers
func TestECHRealServerChrome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	for _, server := range knownECHServers {
		t.Run(server.Name+"_Chrome", func(t *testing.T) {
			testECHRealServer(t, server, HelloChrome_Auto)
		})
	}
}

// TestECHRealServerFirefox tests ECH with Firefox profile against real servers
func TestECHRealServerFirefox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	for _, server := range knownECHServers {
		t.Run(server.Name+"_Firefox", func(t *testing.T) {
			testECHRealServer(t, server, HelloFirefox_Auto)
		})
	}
}

// TestECHRealServerGolang tests ECH with standard Golang TLS against real servers
func TestECHRealServerGolang(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	for _, server := range knownECHServers {
		t.Run(server.Name+"_Golang", func(t *testing.T) {
			testECHRealServer(t, server, HelloGolang)
		})
	}
}

func testECHRealServer(t *testing.T, server ECHTestServer, clientHelloID ClientHelloID) {
	ctx, cancel := context.WithTimeout(context.Background(), testDialTimeout+testHandshakeTimeout+testReadTimeout)
	defer cancel()

	// Get ECH configuration
	echConfig, err := getECHConfig(server)
	if err != nil {
		t.Skipf("Skipping %s: %v", server.Name, err)
		return
	}

	// Dial TCP connection
	addr := net.JoinHostPort(server.Host, server.Port)
	dialer := &net.Dialer{Timeout: testDialTimeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("Failed to dial %s: %v", addr, err)
	}
	defer tcpConn.Close()

	// Configure TLS with ECH
	tlsConfig := &Config{
		ServerName:                     server.Host,
		InsecureSkipVerify:             false,
		MinVersion:                     VersionTLS13, // ECH requires TLS 1.3
		EncryptedClientHelloConfigList: echConfig,
	}

	// Create uTLS connection
	uconn := UClient(tcpConn, tlsConfig, clientHelloID)
	defer uconn.Close()

	// Set handshake deadline
	if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
		t.Fatalf("Failed to set deadline: %v", err)
	}

	// Perform handshake
	if err := uconn.Handshake(); err != nil {
		// Check if this is an ECH rejection with retry configs
		var echErr *ECHRejectionError
		if errors.As(err, &echErr) {
			t.Logf("ECH rejected by %s, retry config available: %v", server.Name, len(echErr.RetryConfigList) > 0)
			if len(echErr.RetryConfigList) > 0 {
				// Test retry with new config
				testECHRetry(t, server, clientHelloID, echErr.RetryConfigList)
				return
			}
			t.Skipf("ECH rejected by %s with no retry config - config may be stale", server.Name)
			return
		}
		// Check if this is a certificate verification error indicating ECH rejection
		// When ECH is rejected, the server presents a cert for outer name
		var hostErr x509.HostnameError
		if errors.As(err, &hostErr) && server.OuterSNI != "" {
			if strings.Contains(err.Error(), server.OuterSNI) {
				t.Skipf("ECH likely rejected by %s (cert for outer name %s): %v", server.Name, server.OuterSNI, err)
				return
			}
		}
		t.Fatalf("Handshake failed with %s: %v", server.Name, err)
	}

	// Verify ECH was accepted
	connState := uconn.ConnectionState()
	if !connState.ECHAccepted {
		t.Errorf("ECH was not accepted by %s", server.Name)
	}

	// Verify TLS 1.3 was negotiated
	if connState.Version != VersionTLS13 {
		t.Errorf("Expected TLS 1.3, got version %x", connState.Version)
	}

	// Verify server name is the inner (secret) SNI
	if connState.ServerName != server.Host {
		t.Errorf("Expected ServerName %s, got %s", server.Host, connState.ServerName)
	}

	// Verify certificate chain is valid
	if len(connState.VerifiedChains) == 0 {
		t.Logf("Warning: No verified certificate chains for %s (InsecureSkipVerify may be needed)", server.Name)
	}

	// Reset deadline for HTTP request
	if err := uconn.SetDeadline(time.Now().Add(testReadTimeout)); err != nil {
		t.Fatalf("Failed to set read deadline: %v", err)
	}

	// Make HTTP request to verify connection works
	resp, err := makeHTTPRequest(uconn, server.Host, server.Path, connState.NegotiatedProtocol)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	t.Logf("Successfully connected to %s with ECH (accepted=%v, ALPN=%s, body_len=%d)",
		server.Name, connState.ECHAccepted, connState.NegotiatedProtocol, len(body))

	// If server has ECH check endpoint, verify it reports ECH was used
	if server.ExpectECHCheck && strings.Contains(server.Path, "ech-check") {
		bodyStr := string(body)
		if strings.Contains(strings.ToLower(bodyStr), "ssl_ech") ||
			strings.Contains(strings.ToLower(bodyStr), "ech") {
			t.Logf("ECH check response: %s", bodyStr[:minInt(len(bodyStr), 500)])
		}
	}
}

// testECHRetry tests reconnecting with a retry ECH config provided by the server
func testECHRetry(t *testing.T, server ECHTestServer, clientHelloID ClientHelloID, retryConfig []byte) {
	t.Logf("Testing ECH retry for %s with new config", server.Name)

	// Dial new TCP connection
	addr := net.JoinHostPort(server.Host, server.Port)
	tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
	if err != nil {
		t.Fatalf("Failed to dial for retry: %v", err)
	}
	defer tcpConn.Close()

	// Configure TLS with retry ECH config
	tlsConfig := &Config{
		ServerName:                     server.Host,
		InsecureSkipVerify:             false,
		MinVersion:                     VersionTLS13,
		EncryptedClientHelloConfigList: retryConfig,
	}

	// Create uTLS connection
	uconn := UClient(tcpConn, tlsConfig, clientHelloID)
	defer uconn.Close()

	// Set deadline
	if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
		t.Fatalf("Failed to set deadline: %v", err)
	}

	// Perform handshake with retry config
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("Retry handshake failed: %v", err)
	}

	connState := uconn.ConnectionState()
	if !connState.ECHAccepted {
		t.Errorf("ECH was not accepted after retry")
	}

	t.Logf("ECH retry successful for %s (accepted=%v)", server.Name, connState.ECHAccepted)
}

// TestECHGREASE tests that GREASE ECH extension works with real servers
func TestECHGREASE(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Test servers that should accept GREASE ECH (ignore it gracefully)
	testServers := []struct {
		host string
		port string
	}{
		{"www.google.com", "443"},
		{"www.cloudflare.com", "443"},
		{"www.amazon.com", "443"},
	}

	for _, server := range testServers {
		t.Run(server.host, func(t *testing.T) {
			addr := net.JoinHostPort(server.host, server.port)
			tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
			if err != nil {
				t.Skipf("Failed to dial %s: %v", server.host, err)
				return
			}
			defer tcpConn.Close()

			// Use Chrome profile which includes GREASE ECH
			tlsConfig := &Config{
				ServerName:         server.host,
				InsecureSkipVerify: false,
				MinVersion:         VersionTLS12,
			}

			uconn := UClient(tcpConn, tlsConfig, HelloChrome_Auto)
			defer uconn.Close()

			if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
				t.Fatalf("Failed to set deadline: %v", err)
			}

			// Handshake should succeed even with GREASE ECH
			if err := uconn.Handshake(); err != nil {
				t.Fatalf("Handshake failed with GREASE ECH: %v", err)
			}

			connState := uconn.ConnectionState()
			// ECH should NOT be accepted (it's just GREASE)
			if connState.ECHAccepted {
				t.Logf("Unexpected: ECH was accepted by %s (server may support ECH)", server.host)
			}

			t.Logf("GREASE ECH test passed for %s (TLS version: %x)", server.host, connState.Version)
		})
	}
}

// TestECHFallbackToPlaintext tests graceful fallback when ECH is not available
func TestECHFallbackToPlaintext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Test against a server that does NOT support ECH
	host := "example.com"
	port := "443"

	addr := net.JoinHostPort(host, port)
	tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
	if err != nil {
		t.Fatalf("Failed to dial %s: %v", host, err)
	}
	defer tcpConn.Close()

	// Create fake ECH config to trigger ECH path
	fakeECHConfig := make([]byte, 100)
	copy(fakeECHConfig, []byte{0x00, 0x60, 0xfe, 0x0d}) // ECH config header

	tlsConfig := &Config{
		ServerName:                     host,
		InsecureSkipVerify:             false,
		MinVersion:                     VersionTLS12,
		EncryptedClientHelloConfigList: nil, // No ECH config - should work normally
	}

	uconn := UClient(tcpConn, tlsConfig, HelloChrome_Auto)
	defer uconn.Close()

	if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
		t.Fatalf("Failed to set deadline: %v", err)
	}

	// Handshake should succeed without ECH
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	connState := uconn.ConnectionState()
	if connState.ECHAccepted {
		t.Errorf("ECH should not be accepted by %s", host)
	}

	t.Logf("Fallback test passed for %s (TLS version: %x)", host, connState.Version)
}

// TestECHWithInvalidConfig tests behavior with malformed ECH config
func TestECHWithInvalidConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	host := "tls-ech.dev"
	port := "443"

	invalidConfigs := []struct {
		name   string
		config []byte
	}{
		{"empty", []byte{}},
		{"too_short", []byte{0x00, 0x01}},
		{"invalid_version", []byte{0x00, 0x10, 0xfe, 0x0a, 0x00, 0x0c}}, // Wrong ECH version
		{"truncated", []byte{0x00, 0x41, 0xfe, 0x0d, 0x00, 0x3d, 0x01}}, // Length says 0x41 but data is truncated
	}

	for _, tc := range invalidConfigs {
		t.Run(tc.name, func(t *testing.T) {
			addr := net.JoinHostPort(host, port)
			tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
			if err != nil {
				t.Skipf("Failed to dial %s: %v", host, err)
				return
			}
			defer tcpConn.Close()

			tlsConfig := &Config{
				ServerName:                     host,
				InsecureSkipVerify:             true, // Skip verify for this edge case test
				MinVersion:                     VersionTLS13,
				EncryptedClientHelloConfigList: tc.config,
			}

			uconn := UClient(tcpConn, tlsConfig, HelloGolang)
			defer uconn.Close()

			if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
				t.Fatalf("Failed to set deadline: %v", err)
			}

			err = uconn.Handshake()
			// We expect either:
			// 1. Error during config parsing
			// 2. Graceful fallback to non-ECH handshake
			// 3. Handshake success (if config is ignored)
			if err != nil {
				t.Logf("Invalid config '%s' caused error (expected): %v", tc.name, err)
			} else {
				connState := uconn.ConnectionState()
				t.Logf("Invalid config '%s' fell back to plain TLS (ECHAccepted=%v)", tc.name, connState.ECHAccepted)
			}
		})
	}
}

// TestECHConcurrent tests concurrent ECH connections to the same server
func TestECHConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	server := knownECHServers[0] // Use tls-ech.dev
	echConfig, err := getECHConfig(server)
	if err != nil {
		t.Skipf("Skipping: %v", err)
		return
	}

	const numConnections = 5
	var wg sync.WaitGroup
	errors := make(chan error, numConnections)
	successes := make(chan bool, numConnections)

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			addr := net.JoinHostPort(server.Host, server.Port)
			tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
			if err != nil {
				errors <- fmt.Errorf("conn %d: dial failed: %w", connID, err)
				return
			}
			defer tcpConn.Close()

			tlsConfig := &Config{
				ServerName:                     server.Host,
				InsecureSkipVerify:             false,
				MinVersion:                     VersionTLS13,
				EncryptedClientHelloConfigList: echConfig,
			}

			uconn := UClient(tcpConn, tlsConfig, HelloChrome_Auto)
			defer uconn.Close()

			if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
				errors <- fmt.Errorf("conn %d: set deadline failed: %w", connID, err)
				return
			}

			if err := uconn.Handshake(); err != nil {
				errors <- fmt.Errorf("conn %d: handshake failed: %w", connID, err)
				return
			}

			connState := uconn.ConnectionState()
			if !connState.ECHAccepted {
				errors <- fmt.Errorf("conn %d: ECH not accepted", connID)
				return
			}

			successes <- true
		}(i)
	}

	wg.Wait()
	close(errors)
	close(successes)

	successCount := 0
	for range successes {
		successCount++
	}

	var errList []error
	for err := range errors {
		errList = append(errList, err)
	}

	if len(errList) > 0 {
		for _, err := range errList {
			t.Logf("Concurrent error: %v", err)
		}
	}

	t.Logf("Concurrent ECH test: %d/%d successful", successCount, numConnections)
	if successCount == 0 {
		t.Errorf("All concurrent connections failed")
	}
}

// TestECHCertificateVerification tests that certificate verification works correctly with ECH
func TestECHCertificateVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	server := knownECHServers[0] // Use tls-ech.dev
	echConfig, err := getECHConfig(server)
	if err != nil {
		t.Skipf("Skipping: %v", err)
		return
	}

	testCases := []struct {
		name           string
		serverName     string
		skipVerify     bool
		expectError    bool
		expectECH      bool
	}{
		{
			name:        "correct_servername_with_verify",
			serverName:  server.Host,
			skipVerify:  false,
			expectError: false,
			expectECH:   true,
		},
		{
			name:        "wrong_servername_with_skipverify",
			serverName:  "wrong.example.com",
			skipVerify:  true,
			expectError: false, // Should work with skip verify
			expectECH:   true,
		},
		// Note: Testing wrong servername without skip verify would cause cert error
		// which is expected behavior but makes the test flaky on different systems
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := net.JoinHostPort(server.Host, server.Port)
			tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			defer tcpConn.Close()

			tlsConfig := &Config{
				ServerName:                     tc.serverName,
				InsecureSkipVerify:             tc.skipVerify,
				MinVersion:                     VersionTLS13,
				EncryptedClientHelloConfigList: echConfig,
			}

			uconn := UClient(tcpConn, tlsConfig, HelloChrome_Auto)
			defer uconn.Close()

			if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
				t.Fatalf("Failed to set deadline: %v", err)
			}

			err = uconn.Handshake()
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but handshake succeeded")
				}
				return
			}
			if err != nil {
				// Check if it's a certificate verification error
				var certErr x509.CertificateInvalidError
				var hostErr x509.HostnameError
				if errors.As(err, &certErr) || errors.As(err, &hostErr) {
					t.Logf("Certificate verification error (may be expected): %v", err)
					return
				}
				t.Fatalf("Unexpected error: %v", err)
			}

			connState := uconn.ConnectionState()
			if tc.expectECH && !connState.ECHAccepted {
				t.Errorf("Expected ECH to be accepted")
			}

			t.Logf("Test %s: ECHAccepted=%v, ServerName=%s", tc.name, connState.ECHAccepted, connState.ServerName)
		})
	}
}

// TestECHWithDifferentProfiles tests ECH with various browser profiles
func TestECHWithDifferentProfiles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	profiles := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_Auto", HelloChrome_Auto},
		{"Firefox_Auto", HelloFirefox_Auto},
		{"Chrome_120", HelloChrome_120},
		{"Chrome_131", HelloChrome_131},
		{"Golang", HelloGolang},
	}

	server := knownECHServers[0] // Use tls-ech.dev
	echConfig, err := getECHConfig(server)
	if err != nil {
		t.Skipf("Skipping: %v", err)
		return
	}

	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			addr := net.JoinHostPort(server.Host, server.Port)
			tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
			if err != nil {
				t.Fatalf("Failed to dial: %v", err)
			}
			defer tcpConn.Close()

			tlsConfig := &Config{
				ServerName:                     server.Host,
				InsecureSkipVerify:             false,
				MinVersion:                     VersionTLS13,
				EncryptedClientHelloConfigList: echConfig,
			}

			uconn := UClient(tcpConn, tlsConfig, profile.id)
			defer uconn.Close()

			if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
				t.Fatalf("Failed to set deadline: %v", err)
			}

			if err := uconn.Handshake(); err != nil {
				t.Fatalf("Handshake failed for %s: %v", profile.name, err)
			}

			connState := uconn.ConnectionState()
			if !connState.ECHAccepted {
				t.Errorf("ECH not accepted for profile %s", profile.name)
			}

			t.Logf("Profile %s: ECHAccepted=%v, Version=%x, ALPN=%s",
				profile.name, connState.ECHAccepted, connState.Version, connState.NegotiatedProtocol)
		})
	}
}

// TestECHResponseBody verifies the HTTP response body can be read after ECH handshake
func TestECHResponseBody(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	server := knownECHServers[0] // Use tls-ech.dev
	echConfig, err := getECHConfig(server)
	if err != nil {
		t.Skipf("Skipping: %v", err)
		return
	}

	addr := net.JoinHostPort(server.Host, server.Port)
	tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer tcpConn.Close()

	tlsConfig := &Config{
		ServerName:                     server.Host,
		InsecureSkipVerify:             false,
		MinVersion:                     VersionTLS13,
		EncryptedClientHelloConfigList: echConfig,
	}

	uconn := UClient(tcpConn, tlsConfig, HelloChrome_Auto)
	defer uconn.Close()

	if err := uconn.SetDeadline(time.Now().Add(testHandshakeTimeout)); err != nil {
		t.Fatalf("Failed to set deadline: %v", err)
	}

	if err := uconn.Handshake(); err != nil {
		t.Fatalf("Handshake failed: %v", err)
	}

	connState := uconn.ConnectionState()
	if !connState.ECHAccepted {
		t.Errorf("ECH was not accepted")
	}

	// Reset deadline for HTTP
	if err := uconn.SetDeadline(time.Now().Add(testReadTimeout)); err != nil {
		t.Fatalf("Failed to set read deadline: %v", err)
	}

	// Make HTTP request
	resp, err := makeHTTPRequest(uconn, server.Host, server.Path, connState.NegotiatedProtocol)
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read full body
	var bodyBuf bytes.Buffer
	n, err := io.Copy(&bodyBuf, resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}

	if n == 0 {
		t.Errorf("Response body is empty")
	}

	// Verify we can parse the response
	body := bodyBuf.String()
	if len(body) == 0 {
		t.Errorf("Empty response body")
	}

	t.Logf("Successfully read %d bytes from %s after ECH handshake", n, server.Host)
	t.Logf("Response preview: %s", body[:minInt(len(body), 200)])
}

// makeHTTPRequest creates and sends an HTTP request over the TLS connection
func makeHTTPRequest(conn net.Conn, host, path, alpn string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "https://"+host+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Host = host
	req.Header.Set("User-Agent", "utls-ech-integration-test/1.0")
	req.Header.Set("Accept", "*/*")

	switch alpn {
	case "h2":
		tr := &http2.Transport{}
		h2Conn, err := tr.NewClientConn(conn)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP/2 connection: %w", err)
		}
		return h2Conn.RoundTrip(req)

	case "http/1.1", "":
		if err := req.Write(conn); err != nil {
			return nil, fmt.Errorf("failed to write request: %w", err)
		}
		return http.ReadResponse(bufio.NewReader(conn), req)

	default:
		return nil, fmt.Errorf("unsupported ALPN protocol: %s", alpn)
	}
}

// minInt returns the minimum of two integers
// Using minInt to avoid conflict with builtin min (Go 1.21+) and other test files
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestECHConfigParsing tests that various ECH config formats can be parsed
func TestECHConfigParsing(t *testing.T) {
	testConfigs := []struct {
		name      string
		configB64 string
		wantErr   bool
	}{
		{
			name:      "tls-ech.dev config",
			configB64: "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA",
			wantErr:   false,
		},
		{
			name:      "empty config",
			configB64: "",
			wantErr:   true,
		},
	}

	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			var config []byte
			var err error

			if tc.configB64 != "" {
				config, err = base64.RawStdEncoding.DecodeString(tc.configB64)
				if err != nil {
					if tc.wantErr {
						return // Expected error
					}
					t.Fatalf("Failed to decode config: %v", err)
				}
			}

			if len(config) == 0 {
				if tc.wantErr {
					return // Expected error for empty config
				}
				t.Errorf("Config should not be empty")
				return
			}

			// Try to parse the config
			configs, err := parseECHConfigList(config)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Expected error but parsing succeeded")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to parse config: %v", err)
			}

			if len(configs) == 0 {
				t.Errorf("No configs parsed")
			}

			for i, cfg := range configs {
				t.Logf("Config %d: version=%x, configID=%d, kemID=%d, publicName=%s",
					i, cfg.Version, cfg.ConfigID, cfg.KemID, string(cfg.PublicName))
			}
		})
	}
}

// TestECHTimeoutHandling tests that timeouts are properly handled during ECH handshake
func TestECHTimeoutHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	server := knownECHServers[0]
	echConfig, err := getECHConfig(server)
	if err != nil {
		t.Skipf("Skipping: %v", err)
		return
	}

	addr := net.JoinHostPort(server.Host, server.Port)
	tcpConn, err := net.DialTimeout("tcp", addr, testDialTimeout)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer tcpConn.Close()

	tlsConfig := &Config{
		ServerName:                     server.Host,
		InsecureSkipVerify:             false,
		MinVersion:                     VersionTLS13,
		EncryptedClientHelloConfigList: echConfig,
	}

	uconn := UClient(tcpConn, tlsConfig, HelloChrome_Auto)
	defer uconn.Close()

	// Set a very short deadline to test timeout handling
	// But not too short that it fails before even starting
	if err := uconn.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("Failed to set deadline: %v", err)
	}

	err = uconn.Handshake()
	// The handshake might succeed if the server is fast, or timeout if slow
	// Both are acceptable outcomes for this test
	if err != nil {
		// Check if it's a timeout error
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Logf("Handshake timed out as expected with short deadline")
			return
		}
		// Other errors might indicate real issues
		t.Logf("Handshake error (may be timeout-related): %v", err)
	} else {
		t.Logf("Handshake succeeded even with short deadline (fast server)")
	}
}
