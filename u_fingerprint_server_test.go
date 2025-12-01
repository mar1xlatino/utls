// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// ServerProfileRegistry Tests
// =============================================================================

// TestServerProfileRegistry_RegisterNilProfile verifies that registering nil profile returns error.
func TestServerProfileRegistry_RegisterNilProfile(t *testing.T) {
	registry := NewServerProfileRegistry()

	err := registry.Register(nil)
	if err == nil {
		t.Error("Register(nil) should return error, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "nil") {
		t.Errorf("Error message should mention 'nil', got: %v", err)
	}
}

// TestServerProfileRegistry_RegisterEmptyID verifies that registering profile with empty ID returns error.
func TestServerProfileRegistry_RegisterEmptyID(t *testing.T) {
	registry := NewServerProfileRegistry()

	profile := &ServerProfile{
		ID:   "",
		Name: "Test Profile",
	}

	err := registry.Register(profile)
	if err == nil {
		t.Error("Register() with empty ID should return error, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "empty") {
		t.Errorf("Error message should mention 'empty', got: %v", err)
	}
}

// TestServerProfileRegistry_GetReturnsRegisteredProfile verifies Get returns registered profile.
func TestServerProfileRegistry_GetReturnsRegisteredProfile(t *testing.T) {
	registry := NewServerProfileRegistry()

	profile := &ServerProfile{
		ID:          "test-profile",
		Name:        "Test Profile",
		Description: "A test server profile",
	}

	if err := registry.Register(profile); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	retrieved, ok := registry.Get("test-profile")
	if !ok {
		t.Fatal("Get should return true for registered profile")
	}
	if retrieved == nil {
		t.Fatal("Get should return non-nil profile")
	}
	if retrieved.ID != profile.ID {
		t.Errorf("Profile ID mismatch: got %s, want %s", retrieved.ID, profile.ID)
	}
	if retrieved.Name != profile.Name {
		t.Errorf("Profile Name mismatch: got %s, want %s", retrieved.Name, profile.Name)
	}
}

// TestServerProfileRegistry_GetReturnsFalseForUnknown verifies Get returns false for unknown profile.
func TestServerProfileRegistry_GetReturnsFalseForUnknown(t *testing.T) {
	registry := NewServerProfileRegistry()

	profile, ok := registry.Get("nonexistent-profile")
	if ok {
		t.Error("Get should return false for unknown profile")
	}
	if profile != nil {
		t.Error("Get should return nil profile for unknown ID")
	}
}

// TestServerProfileRegistry_ListReturnsAllIDs verifies List returns all registered profile IDs.
func TestServerProfileRegistry_ListReturnsAllIDs(t *testing.T) {
	registry := NewServerProfileRegistry()

	profiles := []string{"profile-a", "profile-b", "profile-c"}
	for _, id := range profiles {
		err := registry.Register(&ServerProfile{ID: id, Name: id})
		if err != nil {
			t.Fatalf("Register(%s) failed: %v", id, err)
		}
	}

	ids := registry.List()
	if len(ids) != len(profiles) {
		t.Errorf("List() returned %d IDs, want %d", len(ids), len(profiles))
	}

	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}
	for _, expected := range profiles {
		if !idSet[expected] {
			t.Errorf("List() missing expected ID: %s", expected)
		}
	}
}

// TestServerProfileRegistry_BuiltInProfilesExist verifies built-in profiles are registered.
func TestServerProfileRegistry_BuiltInProfilesExist(t *testing.T) {
	builtInProfiles := []string{"cloudflare", "nginx", "apache", "go-stdlib"}

	for _, id := range builtInProfiles {
		t.Run(id, func(t *testing.T) {
			profile, ok := DefaultServerProfileRegistry.Get(id)
			if !ok {
				t.Errorf("Built-in profile '%s' not found in DefaultServerProfileRegistry", id)
				return
			}
			if profile == nil {
				t.Errorf("Built-in profile '%s' is nil", id)
				return
			}
			if profile.ID != id {
				t.Errorf("Profile ID mismatch: got %s, want %s", profile.ID, id)
			}
		})
	}
}

// TestServerProfileRegistry_ConcurrentAccess verifies thread-safety of registry operations.
func TestServerProfileRegistry_ConcurrentAccess(t *testing.T) {
	registry := NewServerProfileRegistry()

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Concurrent registrations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			profile := &ServerProfile{
				ID:   "concurrent-" + string(rune('a'+idx%26)),
				Name: "Concurrent Profile",
			}
			// Ignore duplicate key errors
			_ = registry.Register(profile)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.List()
			_, _ = registry.Get("cloudflare")
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

// =============================================================================
// SelectCipher Tests
// =============================================================================

// TestSelectCipher_NilProfile verifies SelectCipher returns 0 with nil profile.
func TestSelectCipher_NilProfile(t *testing.T) {
	clientCiphers := []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384}

	result := SelectCipher(nil, clientCiphers)
	if result != 0 {
		t.Errorf("SelectCipher(nil, ciphers) should return 0, got %d", result)
	}
}

// TestSelectCipher_EmptyClientCiphers verifies SelectCipher returns 0 with empty client ciphers.
func TestSelectCipher_EmptyClientCiphers(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference:    []uint16{TLS_AES_128_GCM_SHA256},
		},
	}

	result := SelectCipher(profile, nil)
	if result != 0 {
		t.Errorf("SelectCipher(profile, nil) should return 0, got %d", result)
	}

	result = SelectCipher(profile, []uint16{})
	if result != 0 {
		t.Errorf("SelectCipher(profile, []) should return 0, got %d", result)
	}
}

// TestSelectCipher_FiltersGREASE verifies GREASE values are filtered from client ciphers.
func TestSelectCipher_FiltersGREASE(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "client",
			CipherPreference:    []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
		},
	}

	// Client sends GREASE values first
	clientCiphers := []uint16{
		0x0a0a, // GREASE
		0x1a1a, // GREASE
		TLS_AES_256_GCM_SHA384,
		TLS_AES_128_GCM_SHA256,
	}

	result := SelectCipher(profile, clientCiphers)
	if result == 0x0a0a || result == 0x1a1a {
		t.Error("SelectCipher should not select GREASE value")
	}
	// Client mode: first valid client cipher server supports
	if result != TLS_AES_256_GCM_SHA384 {
		t.Errorf("Expected TLS_AES_256_GCM_SHA384, got %04x", result)
	}
}

// TestSelectCipher_ServerModePreference verifies server mode returns first server cipher client supports.
func TestSelectCipher_ServerModePreference(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference: []uint16{
				TLS_AES_128_GCM_SHA256,        // Server prefers this
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
			},
		},
	}

	// Client lists in different order
	clientCiphers := []uint16{
		TLS_AES_256_GCM_SHA384,        // Client prefers this
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_AES_128_GCM_SHA256,
	}

	result := SelectCipher(profile, clientCiphers)
	// Server preference should win - first server cipher that client supports
	if result != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Server mode: expected TLS_AES_128_GCM_SHA256, got %04x", result)
	}
}

// TestSelectCipher_ClientModePreference verifies client mode returns first client cipher server supports.
func TestSelectCipher_ClientModePreference(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "client",
			CipherPreference: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
			},
		},
	}

	// Client lists in different order
	clientCiphers := []uint16{
		TLS_AES_256_GCM_SHA384,        // Client prefers this
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_AES_128_GCM_SHA256,
	}

	result := SelectCipher(profile, clientCiphers)
	// Client preference should win - first client cipher that server supports
	if result != TLS_AES_256_GCM_SHA384 {
		t.Errorf("Client mode: expected TLS_AES_256_GCM_SHA384, got %04x", result)
	}
}

// TestSelectCipher_ReturnsZeroWhenNoOverlap verifies 0 is returned when no cipher overlap.
func TestSelectCipher_ReturnsZeroWhenNoOverlap(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference:    []uint16{TLS_AES_128_GCM_SHA256},
		},
	}

	clientCiphers := []uint16{TLS_CHACHA20_POLY1305_SHA256}

	result := SelectCipher(profile, clientCiphers)
	if result != 0 {
		t.Errorf("Expected 0 when no cipher overlap, got %04x", result)
	}
}

// TestSelectCipher_EmptyServerPreferenceServerMode verifies fallback when server has no preference in server mode.
func TestSelectCipher_EmptyServerPreferenceServerMode(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference:    nil, // Empty
		},
	}

	clientCiphers := []uint16{TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256}

	result := SelectCipher(profile, clientCiphers)
	// Should fall back to first valid client cipher
	if result != TLS_AES_256_GCM_SHA384 {
		t.Errorf("Expected fallback to first client cipher, got %04x", result)
	}
}

// TestSelectCipher_OnlyGREASEInClientList verifies 0 when client only sends GREASE.
func TestSelectCipher_OnlyGREASEInClientList(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference:    []uint16{TLS_AES_128_GCM_SHA256},
		},
	}

	clientCiphers := []uint16{0x0a0a, 0x1a1a, 0x2a2a} // All GREASE

	result := SelectCipher(profile, clientCiphers)
	if result != 0 {
		t.Errorf("Expected 0 when client only sends GREASE, got %04x", result)
	}
}

// =============================================================================
// SelectALPN Tests
// =============================================================================

// TestSelectALPN_NilProfile verifies SelectALPN returns empty with nil profile.
func TestSelectALPN_NilProfile(t *testing.T) {
	result := SelectALPN(nil, []string{"h2", "http/1.1"})
	if result != "" {
		t.Errorf("SelectALPN(nil, protocols) should return empty, got %s", result)
	}
}

// TestSelectALPN_EmptyClientProtocols verifies SelectALPN returns empty with no client protocols.
func TestSelectALPN_EmptyClientProtocols(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			ALPNPreference: []string{"h2", "http/1.1"},
		},
	}

	result := SelectALPN(profile, nil)
	if result != "" {
		t.Errorf("SelectALPN(profile, nil) should return empty, got %s", result)
	}

	result = SelectALPN(profile, []string{})
	if result != "" {
		t.Errorf("SelectALPN(profile, []) should return empty, got %s", result)
	}
}

// TestSelectALPN_ReturnsFirstServerPreference verifies server preference order is respected.
func TestSelectALPN_ReturnsFirstServerPreference(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			ALPNPreference: []string{"h2", "http/1.1"},
		},
	}

	// Client offers in reverse order
	clientProtocols := []string{"http/1.1", "h2"}

	result := SelectALPN(profile, clientProtocols)
	if result != "h2" {
		t.Errorf("Expected 'h2' (server preference), got %s", result)
	}
}

// TestSelectALPN_ReturnsEmptyWhenNoOverlap verifies empty return when no protocol overlap.
func TestSelectALPN_ReturnsEmptyWhenNoOverlap(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			ALPNPreference: []string{"h2"},
		},
	}

	clientProtocols := []string{"http/1.1", "spdy/3.1"}

	result := SelectALPN(profile, clientProtocols)
	if result != "" {
		t.Errorf("Expected empty when no overlap, got %s", result)
	}
}

// TestSelectALPN_EmptyServerPreference verifies fallback when server has no preference.
func TestSelectALPN_EmptyServerPreference(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			ALPNPreference: nil, // Empty
		},
	}

	clientProtocols := []string{"h2", "http/1.1"}

	result := SelectALPN(profile, clientProtocols)
	// Should accept first client protocol
	if result != "h2" {
		t.Errorf("Expected first client protocol 'h2', got %s", result)
	}
}

// TestSelectALPN_SingleProtocolMatch verifies single protocol matching works.
func TestSelectALPN_SingleProtocolMatch(t *testing.T) {
	profile := &ServerProfile{
		ID: "test",
		ServerHello: ServerHelloConfig{
			ALPNPreference: []string{"http/1.1"},
		},
	}

	clientProtocols := []string{"http/1.1"}

	result := SelectALPN(profile, clientProtocols)
	if result != "http/1.1" {
		t.Errorf("Expected 'http/1.1', got %s", result)
	}
}

// =============================================================================
// GenerateCertificate Tests
// =============================================================================

// TestGenerateCertificate_NilConfig verifies nil config returns error.
func TestGenerateCertificate_NilConfig(t *testing.T) {
	cert, key, err := GenerateCertificate(nil, "example.com")
	if err == nil {
		t.Error("GenerateCertificate(nil) should return error")
	}
	if cert != nil || key != nil {
		t.Error("GenerateCertificate(nil) should return nil cert and key")
	}
}

// TestGenerateCertificate_ValidX509Certificate verifies generated certificate is valid x509.
func TestGenerateCertificate_ValidX509Certificate(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 24 * time.Hour,
	}

	cert, key, err := GenerateCertificate(config, "example.com")
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}
	if cert == nil {
		t.Fatal("Certificate should not be nil")
	}
	if key == nil {
		t.Fatal("Private key should not be nil")
	}

	// Verify certificate structure
	if cert.Subject.CommonName != "example.com" {
		t.Errorf("CommonName mismatch: got %s, want example.com", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "example.com" {
		t.Error("Certificate should have example.com in DNSNames")
	}
}

// TestGenerateCertificate_ECDSAKeyType verifies ECDSA key generation.
func TestGenerateCertificate_ECDSAKeyType(t *testing.T) {
	tests := []struct {
		keyType string
		curve   string
	}{
		{"ecdsa-p256", "P-256"},
		{"ecdsa-p384", "P-384"},
	}

	for _, tc := range tests {
		t.Run(tc.keyType, func(t *testing.T) {
			config := &CertificateConfig{
				KeyType:        tc.keyType,
				ValidityPeriod: 24 * time.Hour,
			}

			cert, key, err := GenerateCertificate(config, "example.com")
			if err != nil {
				t.Fatalf("GenerateCertificate failed: %v", err)
			}

			ecdsaKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("Expected *ecdsa.PrivateKey, got %T", key)
			}

			if ecdsaKey.Curve.Params().Name != tc.curve {
				t.Errorf("Curve mismatch: got %s, want %s",
					ecdsaKey.Curve.Params().Name, tc.curve)
			}

			if cert.PublicKeyAlgorithm != x509.ECDSA {
				t.Errorf("Certificate public key algorithm should be ECDSA, got %v",
					cert.PublicKeyAlgorithm)
			}
		})
	}
}

// TestGenerateCertificate_RSAKeyType verifies RSA key generation.
func TestGenerateCertificate_RSAKeyType(t *testing.T) {
	tests := []struct {
		keyType string
		bits    int
	}{
		{"rsa-2048", 2048},
		{"rsa-4096", 4096},
	}

	for _, tc := range tests {
		t.Run(tc.keyType, func(t *testing.T) {
			config := &CertificateConfig{
				KeyType:        tc.keyType,
				ValidityPeriod: 24 * time.Hour,
			}

			cert, key, err := GenerateCertificate(config, "example.com")
			if err != nil {
				t.Fatalf("GenerateCertificate failed: %v", err)
			}

			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("Expected *rsa.PrivateKey, got %T", key)
			}

			if rsaKey.Size()*8 != tc.bits {
				t.Errorf("Key size mismatch: got %d bits, want %d bits",
					rsaKey.Size()*8, tc.bits)
			}

			if cert.PublicKeyAlgorithm != x509.RSA {
				t.Errorf("Certificate public key algorithm should be RSA, got %v",
					cert.PublicKeyAlgorithm)
			}
		})
	}
}

// TestGenerateCertificate_Ed25519KeyType verifies Ed25519 key generation.
func TestGenerateCertificate_Ed25519KeyType(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ed25519",
		ValidityPeriod: 24 * time.Hour,
	}

	cert, key, err := GenerateCertificate(config, "example.com")
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	_, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Expected ed25519.PrivateKey, got %T", key)
	}

	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Errorf("Certificate public key algorithm should be Ed25519, got %v",
			cert.PublicKeyAlgorithm)
	}
}

// TestGenerateCertificate_ValidityPeriod verifies certificate validity period.
func TestGenerateCertificate_ValidityPeriod(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 7 * 24 * time.Hour, // 7 days
	}

	cert, _, err := GenerateCertificate(config, "example.com")
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	duration := cert.NotAfter.Sub(cert.NotBefore)
	expectedDuration := 7 * 24 * time.Hour

	// Allow small margin for test execution time
	if duration < expectedDuration-time.Minute || duration > expectedDuration+time.Minute {
		t.Errorf("Validity period mismatch: got %v, want ~%v", duration, expectedDuration)
	}
}

// TestGenerateCertificate_DefaultValidityPeriod verifies default validity period.
func TestGenerateCertificate_DefaultValidityPeriod(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 0, // Should default to 365 days
	}

	cert, _, err := GenerateCertificate(config, "example.com")
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	duration := cert.NotAfter.Sub(cert.NotBefore)
	expectedDuration := 365 * 24 * time.Hour

	if duration < expectedDuration-time.Minute || duration > expectedDuration+time.Minute {
		t.Errorf("Default validity period mismatch: got %v, want ~%v", duration, expectedDuration)
	}
}

// TestGenerateCertificate_UnsupportedKeyType verifies error for unsupported key type.
func TestGenerateCertificate_UnsupportedKeyType(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "invalid-key-type",
		ValidityPeriod: 24 * time.Hour,
	}

	cert, key, err := GenerateCertificate(config, "example.com")
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
	if cert != nil || key != nil {
		t.Error("Should return nil cert and key for unsupported key type")
	}
}

// TestGenerateCertificate_DefaultKeyType verifies default key type is used.
func TestGenerateCertificate_DefaultKeyType(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "", // Should default to ecdsa-p256
		ValidityPeriod: 24 * time.Hour,
	}

	cert, key, err := GenerateCertificate(config, "example.com")
	if err != nil {
		t.Fatalf("GenerateCertificate failed: %v", err)
	}

	_, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Default key type should be ECDSA, got %T", key)
	}

	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("Default certificate should use ECDSA, got %v", cert.PublicKeyAlgorithm)
	}
}

// =============================================================================
// GenerateCertificateChain Tests
// =============================================================================

// TestGenerateCertificateChain_SingleCert verifies chainLength=1 returns self-signed cert.
func TestGenerateCertificateChain_SingleCert(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 24 * time.Hour,
	}

	chain, key, err := GenerateCertificateChain(config, "example.com", 1)
	if err != nil {
		t.Fatalf("GenerateCertificateChain failed: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("Chain length mismatch: got %d, want 1", len(chain))
	}
	if key == nil {
		t.Error("Private key should not be nil")
	}

	// Self-signed: issuer == subject
	cert := chain[0]
	if cert.Issuer.String() != cert.Subject.String() {
		t.Errorf("Self-signed cert should have issuer == subject")
	}
}

// TestGenerateCertificateChain_TwoCerts verifies chainLength=2 returns [leaf, CA].
func TestGenerateCertificateChain_TwoCerts(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 24 * time.Hour,
		Issuer: RDNConfig{
			Fields: []RDNField{
				{OID: OIDCountry, Value: "US"},
				{OID: OIDOrganization, Value: "Test CA Inc"},
				{OID: OIDCommonName, Value: "Test Root CA"},
			},
		},
		Subject: RDNConfig{
			Fields: []RDNField{
				{OID: OIDCommonName, Value: "example.com"},
			},
		},
	}

	chain, key, err := GenerateCertificateChain(config, "example.com", 2)
	if err != nil {
		t.Fatalf("GenerateCertificateChain failed: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("Chain length mismatch: got %d, want 2", len(chain))
	}
	if key == nil {
		t.Error("Private key should not be nil")
	}

	leaf := chain[0]
	ca := chain[1]

	// Verify leaf is not CA
	if leaf.IsCA {
		t.Error("Leaf certificate should not be CA")
	}

	// Verify CA is CA
	if !ca.IsCA {
		t.Error("CA certificate should be marked as CA")
	}

	// Verify leaf's issuer matches CA's subject
	if leaf.Issuer.String() != ca.Subject.String() {
		t.Errorf("Leaf issuer should match CA subject:\n  Leaf issuer: %s\n  CA subject:  %s",
			leaf.Issuer.String(), ca.Subject.String())
	}
}

// TestGenerateCertificateChain_LeafSignedByCA verifies leaf certificate signature.
func TestGenerateCertificateChain_LeafSignedByCA(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 24 * time.Hour,
		Issuer: RDNConfig{
			Fields: []RDNField{
				{OID: OIDOrganization, Value: "Test CA"},
				{OID: OIDCommonName, Value: "Test Root CA"},
			},
		},
	}

	chain, _, err := GenerateCertificateChain(config, "example.com", 2)
	if err != nil {
		t.Fatalf("GenerateCertificateChain failed: %v", err)
	}

	leaf := chain[0]
	ca := chain[1]

	// Verify leaf is signed by CA
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	opts := x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	_, err = leaf.Verify(opts)
	if err != nil {
		t.Errorf("Leaf certificate verification failed: %v", err)
	}
}

// TestGenerateCertificateChain_ZeroLength verifies chainLength<1 defaults to 1.
func TestGenerateCertificateChain_ZeroLength(t *testing.T) {
	config := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 24 * time.Hour,
	}

	chain, _, err := GenerateCertificateChain(config, "example.com", 0)
	if err != nil {
		t.Fatalf("GenerateCertificateChain failed: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("Chain length for 0 input should be 1, got %d", len(chain))
	}

	chain, _, err = GenerateCertificateChain(config, "example.com", -5)
	if err != nil {
		t.Fatalf("GenerateCertificateChain failed: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("Chain length for negative input should be 1, got %d", len(chain))
	}
}

// =============================================================================
// ServerHelloBuilder Tests
// =============================================================================

// TestServerHelloBuilder_BuildNoCipher verifies error when no cipher is selected.
func TestServerHelloBuilder_BuildNoCipher(t *testing.T) {
	builder := NewServerHelloBuilder(nil)

	hello, err := builder.Build()
	if err == nil {
		t.Error("Build() with no cipher should return error")
	}
	if hello != nil {
		t.Error("Build() with no cipher should return nil hello")
	}
}

// TestServerHelloBuilder_ExplicitCipher verifies explicit cipher is used.
func TestServerHelloBuilder_ExplicitCipher(t *testing.T) {
	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_256_GCM_SHA384)

	hello, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
	if hello.cipherSuite != TLS_AES_256_GCM_SHA384 {
		t.Errorf("Cipher mismatch: got %04x, want %04x",
			hello.cipherSuite, TLS_AES_256_GCM_SHA384)
	}
}

// TestServerHelloBuilder_TLS13NoKeyShareData verifies error for TLS 1.3 without key share data.
func TestServerHelloBuilder_TLS13NoKeyShareData(t *testing.T) {
	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithVersion(VersionTLS13).
		WithKeyShare(X25519, nil) // Group set but no data

	hello, err := builder.Build()
	if err == nil {
		t.Error("Build() with TLS 1.3 and no key share data should return error")
	}
	if hello != nil {
		t.Error("Build() should return nil hello on error")
	}
}

// TestServerHelloBuilder_TLS13WithKeyShare verifies TLS 1.3 with proper key share.
func TestServerHelloBuilder_TLS13WithKeyShare(t *testing.T) {
	keyShareData := make([]byte, 32)
	for i := range keyShareData {
		keyShareData[i] = byte(i)
	}

	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithVersion(VersionTLS13).
		WithKeyShare(X25519, keyShareData)

	hello, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
	if hello.serverShare.group != X25519 {
		t.Errorf("Key share group mismatch: got %d, want %d",
			hello.serverShare.group, X25519)
	}
	if !bytes.Equal(hello.serverShare.data, keyShareData) {
		t.Error("Key share data mismatch")
	}
}

// TestServerHelloBuilder_WithExtensionOrder verifies extension order affects JA4S hash.
func TestServerHelloBuilder_WithExtensionOrder(t *testing.T) {
	keyShareData := make([]byte, 32)

	// Build with order [43, 51]
	builder1 := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithVersion(VersionTLS13).
		WithKeyShare(X25519, keyShareData).
		WithExtensionOrder([]uint16{43, 51})

	fp1, err := builder1.PreviewFingerprint()
	if err != nil {
		t.Fatalf("PreviewFingerprint failed: %v", err)
	}

	// Build with order [51, 43]
	builder2 := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithVersion(VersionTLS13).
		WithKeyShare(X25519, keyShareData).
		WithExtensionOrder([]uint16{51, 43})

	fp2, err := builder2.PreviewFingerprint()
	if err != nil {
		t.Fatalf("PreviewFingerprint failed: %v", err)
	}

	// Different extension orders should produce different JA4S hashes
	// (specifically the JA4S_c component which is the extension hash)
	parts1 := strings.Split(fp1.JA4S, "_")
	parts2 := strings.Split(fp2.JA4S, "_")

	if len(parts1) != 3 || len(parts2) != 3 {
		t.Fatalf("Invalid JA4S format")
	}

	// JA4S_a and JA4S_b should be the same
	if parts1[0] != parts2[0] {
		t.Errorf("JA4S_a should be the same: %s vs %s", parts1[0], parts2[0])
	}
	if parts1[1] != parts2[1] {
		t.Errorf("JA4S_b should be the same: %s vs %s", parts1[1], parts2[1])
	}

	// JA4S_c (extension hash) should differ
	if parts1[2] == parts2[2] {
		t.Errorf("JA4S_c should differ with different extension order: %s", parts1[2])
	}
}

// TestServerHelloBuilder_PreviewFingerprint verifies fingerprint preview is valid.
func TestServerHelloBuilder_PreviewFingerprint(t *testing.T) {
	keyShareData := make([]byte, 32)

	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithVersion(VersionTLS13).
		WithKeyShare(X25519, keyShareData).
		WithALPN("h2")

	fp, err := builder.PreviewFingerprint()
	if err != nil {
		t.Fatalf("PreviewFingerprint failed: %v", err)
	}
	if fp.JA4S == "" {
		t.Error("JA4S should not be empty")
	}

	// Verify JA4S format: JA4S_a_JA4S_b_JA4S_c
	parts := strings.Split(fp.JA4S, "_")
	if len(parts) != 3 {
		t.Errorf("JA4S format wrong: expected 3 parts, got %d", len(parts))
	}

	// Verify cipher in JA4S_b (should be 1301 for TLS_AES_128_GCM_SHA256)
	if parts[1] != "1301" {
		t.Errorf("JA4S_b cipher mismatch: got %s, want 1301", parts[1])
	}
}

// TestServerHelloBuilder_JA4S verifies JA4S() method returns valid fingerprint.
func TestServerHelloBuilder_JA4S(t *testing.T) {
	keyShareData := make([]byte, 32)

	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_256_GCM_SHA384).
		WithVersion(VersionTLS13).
		WithKeyShare(X25519, keyShareData)

	ja4s, err := builder.JA4S()
	if err != nil {
		t.Fatalf("JA4S() failed: %v", err)
	}
	if ja4s == "" {
		t.Error("JA4S() should return non-empty string")
	}

	// Verify format
	parts := strings.Split(ja4s, "_")
	if len(parts) != 3 {
		t.Errorf("JA4S format invalid: %s", ja4s)
	}

	// JA4S_b should be cipher hex (1302 for TLS_AES_256_GCM_SHA384)
	if parts[1] != "1302" {
		t.Errorf("JA4S_b should be 1302, got %s", parts[1])
	}
}

// TestServerHelloBuilder_SessionIDModes verifies different session ID modes.
func TestServerHelloBuilder_SessionIDModes(t *testing.T) {
	tests := []struct {
		mode           string
		expectNil      bool
		expectLength   int
		expectEcho     bool
	}{
		{"none", true, 0, false},
		{"random", false, 32, false},
		{"echo", false, 0, true},
	}

	clientSessionID := []byte("client-session-id-12345678901234")

	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			profile := &ServerProfile{
				ID: "test",
				ServerHello: ServerHelloConfig{
					SessionIDMode:   tc.mode,
					SessionIDLength: 32,
					CipherPreference: []uint16{TLS_AES_128_GCM_SHA256},
				},
			}

			clientHello := &clientHelloMsg{
				sessionId:    clientSessionID,
				cipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
			}

			builder := NewServerHelloBuilder(profile).
				ForClientHello(clientHello)

			hello, err := builder.Build()
			if err != nil {
				t.Fatalf("Build() failed: %v", err)
			}

			if tc.expectNil && hello.sessionId != nil {
				t.Error("Session ID should be nil for 'none' mode")
			}
			if tc.expectEcho && !bytes.Equal(hello.sessionId, clientSessionID) {
				t.Error("Session ID should echo client's session ID")
			}
			if !tc.expectNil && !tc.expectEcho && len(hello.sessionId) != tc.expectLength {
				t.Errorf("Session ID length mismatch: got %d, want %d",
					len(hello.sessionId), tc.expectLength)
			}
		})
	}
}

// TestServerHelloBuilder_BuildRaw verifies BuildRaw returns valid bytes.
func TestServerHelloBuilder_BuildRaw(t *testing.T) {
	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithVersion(VersionTLS12)

	raw, err := builder.BuildRaw()
	if err != nil {
		t.Fatalf("BuildRaw() failed: %v", err)
	}
	if len(raw) == 0 {
		t.Error("BuildRaw() should return non-empty bytes")
	}
}

// TestServerHelloBuilder_FromProfile verifies builder from profile ID.
func TestServerHelloBuilder_FromProfile(t *testing.T) {
	builder, err := ServerHelloBuilderFromProfile("cloudflare")
	if err != nil {
		t.Fatalf("ServerHelloBuilderFromProfile failed: %v", err)
	}
	if builder == nil {
		t.Fatal("Builder should not be nil")
	}
	if builder.profile == nil {
		t.Fatal("Builder should have profile set")
	}
	if builder.profile.ID != "cloudflare" {
		t.Errorf("Profile ID mismatch: got %s, want cloudflare", builder.profile.ID)
	}
}

// TestServerHelloBuilder_FromUnknownProfile verifies error for unknown profile.
func TestServerHelloBuilder_FromUnknownProfile(t *testing.T) {
	builder, err := ServerHelloBuilderFromProfile("nonexistent")
	if err == nil {
		t.Error("Expected error for unknown profile")
	}
	if builder != nil {
		t.Error("Builder should be nil for unknown profile")
	}
}

// TestServerHelloBuilder_WithRandom verifies custom random bytes.
func TestServerHelloBuilder_WithRandom(t *testing.T) {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}

	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithRandom(random)

	hello, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() failed: %v", err)
	}
	if !bytes.Equal(hello.random, random) {
		t.Error("Random bytes mismatch")
	}
}

// TestServerHelloBuilder_InvalidRandomLength verifies error for invalid random length.
func TestServerHelloBuilder_InvalidRandomLength(t *testing.T) {
	builder := NewServerHelloBuilder(nil).
		WithCipher(TLS_AES_128_GCM_SHA256).
		WithRandom(make([]byte, 16)) // Wrong length

	hello, err := builder.Build()
	if err == nil {
		t.Error("Expected error for invalid random length")
	}
	if hello != nil {
		t.Error("Hello should be nil on error")
	}
}

// =============================================================================
// matchWildcard Tests
// =============================================================================

// TestMatchWildcard_StarMatchesEverything verifies "*" matches any string.
func TestMatchWildcard_StarMatchesEverything(t *testing.T) {
	tests := []string{
		"",
		"a",
		"hello",
		"t13d0107h2",
		"very long string with spaces and special chars !@#$%",
	}

	for _, s := range tests {
		if !matchWildcard(s, "*") {
			t.Errorf("matchWildcard(%q, \"*\") should be true", s)
		}
	}
}

// TestMatchWildcard_PrefixMatch verifies "prefix*" matches strings starting with prefix.
func TestMatchWildcard_PrefixMatch(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"hello", "hel*", true},
		{"hello", "hello*", true},
		{"hello", "hellox*", false},
		{"t13d0107h2", "t13*", true},
		{"t13d0107h2", "t12*", false},
		{"abc", "abc*", true},
		{"ab", "abc*", false},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.s, tc.pattern)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}

// TestMatchWildcard_SuffixMatch verifies "*suffix" matches strings ending with suffix.
func TestMatchWildcard_SuffixMatch(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"hello", "*llo", true},
		{"hello", "*lo", true},
		{"hello", "*hello", true},
		{"hello", "*x", false},
		{"t13d0107h2", "*h2", true},
		{"t13d0107h1", "*h2", false},
		{"abc", "*abc", true},
		{"abc", "*abcd", false},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.s, tc.pattern)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}

// TestMatchWildcard_InteriorWildcard verifies "pre*suf" matches interior wildcard.
func TestMatchWildcard_InteriorWildcard(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"hello", "h*o", true},
		{"hello", "he*lo", true},
		{"hello", "h*llo", true},
		{"hello", "h*x", false},
		{"t13d0107h2", "t13*h2", true},
		{"t13d0107h1", "t13*h2", false},
		{"t13d0107h2", "t*d*h*", true},
		{"abcdef", "a*f", true},
		{"abcdef", "a*e*f", true},
		{"abcdef", "a*x*f", false},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.s, tc.pattern)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}

// TestMatchWildcard_ExactMatch verifies exact string matching works.
func TestMatchWildcard_ExactMatch(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"hello", "hello", true},
		{"hello", "Hello", false}, // Case sensitive
		{"", "", true},
		{"t13d0107h2", "t13d0107h2", true},
		{"t13d0107h2", "t13d0107h1", false},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.s, tc.pattern)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}

// TestMatchWildcard_NonMatch verifies non-matching cases return false.
func TestMatchWildcard_NonMatch(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
	}{
		{"hello", "world"},
		{"abc", "xyz"},
		{"short", "verylongpattern"},
		{"", "nonempty"},
		{"nonempty", ""},
	}

	for _, tc := range tests {
		if matchWildcard(tc.s, tc.pattern) {
			t.Errorf("matchWildcard(%q, %q) should be false", tc.s, tc.pattern)
		}
	}
}

// TestMatchWildcard_MultipleWildcards verifies multiple wildcards work.
func TestMatchWildcard_MultipleWildcards(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"abcdefgh", "a*c*e*g*", true},
		{"abcdefgh", "a*d*h", true},
		{"abcdefgh", "*b*d*f*h*", true},
		{"abcdefgh", "**", true},
		{"abcdefgh", "*****", true},
		{"abc", "a**c", true},
		{"abc", "*a*b*c*", true},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.s, tc.pattern)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}

// TestMatchWildcard_QuestionMark verifies '?' matches single character.
func TestMatchWildcard_QuestionMark(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"hello", "h?llo", true},
		{"hello", "?ello", true},
		{"hello", "hell?", true},
		{"hello", "h???o", true},
		{"hello", "?????", true},
		{"hello", "??????", false},
		{"hello", "????", false},
		{"", "?", false},
		{"a", "?", true},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.s, tc.pattern)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}

// TestMatchWildcard_CombinedWildcards verifies combined * and ? wildcards.
func TestMatchWildcard_CombinedWildcards(t *testing.T) {
	tests := []struct {
		s       string
		pattern string
		want    bool
	}{
		{"hello", "h*?o", true},
		{"hello", "?*o", true},
		{"hello", "*?", true},
		{"hello", "?*", true},
		{"hello", "h?l*", true},
		{"t13d0107h2", "t??d*h?", true},
		{"t13d0107h2", "???d????h?", true},
	}

	for _, tc := range tests {
		got := matchWildcard(tc.s, tc.pattern)
		if got != tc.want {
			t.Errorf("matchWildcard(%q, %q) = %v, want %v", tc.s, tc.pattern, got, tc.want)
		}
	}
}

// =============================================================================
// ServerFingerprintController Tests
// =============================================================================

// TestServerFingerprintController_NewWithUnknownProfile verifies error for unknown profile.
func TestServerFingerprintController_NewWithUnknownProfile(t *testing.T) {
	ctrl, err := NewServerFingerprintController("nonexistent-profile")
	if err == nil {
		t.Error("Expected error for unknown profile")
	}
	if ctrl != nil {
		t.Error("Controller should be nil for unknown profile")
	}
}

// TestServerFingerprintController_NewFromBuiltInProfiles verifies creation from built-in profiles.
func TestServerFingerprintController_NewFromBuiltInProfiles(t *testing.T) {
	profiles := []string{"cloudflare", "nginx", "apache", "go-stdlib"}

	for _, id := range profiles {
		t.Run(id, func(t *testing.T) {
			ctrl, err := NewServerFingerprintController(id)
			if err != nil {
				t.Fatalf("NewServerFingerprintController(%s) failed: %v", id, err)
			}
			if ctrl == nil {
				t.Fatal("Controller should not be nil")
			}
			if ctrl.Profile() == nil {
				t.Fatal("Profile should not be nil")
			}
			if ctrl.Profile().ID != id {
				t.Errorf("Profile ID mismatch: got %s, want %s", ctrl.Profile().ID, id)
			}
		})
	}
}

// TestServerFingerprintController_FromNilProfile verifies nil profile handling.
func TestServerFingerprintController_FromNilProfile(t *testing.T) {
	ctrl := NewServerFingerprintControllerFromProfile(nil, DefaultServerFingerprintControllerOptions())
	if ctrl != nil {
		t.Error("Controller should be nil for nil profile")
	}
}

// TestServerFingerprintController_SelectCipher verifies cipher selection via controller.
func TestServerFingerprintController_SelectCipher(t *testing.T) {
	ctrl, err := NewServerFingerprintController("cloudflare")
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	clientCiphers := []uint16{
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_AES_128_GCM_SHA256,
	}

	cipher := ctrl.SelectCipher(clientCiphers)
	// Cloudflare prefers AES-128-GCM
	if cipher != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected TLS_AES_128_GCM_SHA256, got %04x", cipher)
	}
}

// TestServerFingerprintController_SelectALPN verifies ALPN selection via controller.
func TestServerFingerprintController_SelectALPN(t *testing.T) {
	ctrl, err := NewServerFingerprintController("cloudflare")
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	clientProtocols := []string{"http/1.1", "h2"}

	alpn := ctrl.SelectALPN(clientProtocols)
	// Cloudflare prefers h2
	if alpn != "h2" {
		t.Errorf("Expected 'h2', got %s", alpn)
	}
}

// TestServerFingerprintController_Stats verifies statistics tracking.
func TestServerFingerprintController_Stats(t *testing.T) {
	ctrl, err := NewServerFingerprintController("cloudflare")
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	initialStats := ctrl.Stats()
	if initialStats.ClientHellosReceived != 0 {
		t.Errorf("Initial ClientHellosReceived should be 0, got %d",
			initialStats.ClientHellosReceived)
	}
}

// TestServerFingerprintController_Hooks verifies hook chain access.
func TestServerFingerprintController_Hooks(t *testing.T) {
	ctrl, err := NewServerFingerprintController("cloudflare")
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	hooks := ctrl.Hooks()
	if hooks == nil {
		t.Error("Hooks() should not return nil")
	}
}

// TestServerFingerprintController_AddHook verifies hook addition.
func TestServerFingerprintController_AddHook(t *testing.T) {
	ctrl, err := NewServerFingerprintController("cloudflare")
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	hook := &FingerprintHooks{
		OnProfileSelected: func(p *FingerprintProfile) error {
			return nil
		},
	}

	ctrl.AddHook(hook)
	// Hook chain should have the hook - we verify it's added by checking it doesn't panic
	if ctrl.Hooks() == nil {
		t.Error("Hooks should not be nil after adding hook")
	}
}

// TestServerFingerprintController_ExpectedJA4S verifies ExpectedJA4S accessor.
func TestServerFingerprintController_ExpectedJA4S(t *testing.T) {
	profile := &ServerProfile{
		ID:           "test",
		ExpectedJA4S: "t13d02h2_1301_abc123def456",
	}

	ctrl := NewServerFingerprintControllerFromProfile(profile, DefaultServerFingerprintControllerOptions())
	if ctrl == nil {
		t.Fatal("Controller should not be nil")
	}

	ja4s := ctrl.ExpectedJA4S()
	if ja4s != profile.ExpectedJA4S {
		t.Errorf("ExpectedJA4S mismatch: got %s, want %s", ja4s, profile.ExpectedJA4S)
	}
}

// TestServerFingerprintController_GenerateCertificateChain verifies certificate chain generation.
func TestServerFingerprintController_GenerateCertificateChain(t *testing.T) {
	// Profile with custom issuer should generate 2-cert chain
	profile := &ServerProfile{
		ID: "test",
		Certificate: CertificateConfig{
			KeyType:        "ecdsa-p256",
			ValidityPeriod: 24 * time.Hour,
			Issuer: RDNConfig{
				Fields: []RDNField{
					{OID: OIDOrganization, Value: "Test CA"},
					{OID: OIDCommonName, Value: "Test Root CA"},
				},
			},
		},
	}

	ctrl := NewServerFingerprintControllerFromProfile(profile, DefaultServerFingerprintControllerOptions())
	if ctrl == nil {
		t.Fatal("Controller should not be nil")
	}

	chain, key, err := ctrl.GenerateCertificateChain("example.com")
	if err != nil {
		t.Fatalf("GenerateCertificateChain failed: %v", err)
	}
	if len(chain) != 2 {
		t.Errorf("Expected 2-cert chain for custom issuer, got %d", len(chain))
	}
	if key == nil {
		t.Error("Private key should not be nil")
	}
}

// TestServerFingerprintController_AnalyzeClientHelloNil verifies nil handling.
func TestServerFingerprintController_AnalyzeClientHelloNil(t *testing.T) {
	ctrl, err := NewServerFingerprintController("cloudflare")
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	fp, err := ctrl.AnalyzeClientHello(nil)
	if err == nil {
		t.Error("Expected error for nil ClientHelloInfo")
	}
	if fp != nil {
		t.Error("Fingerprint should be nil for nil input")
	}
}

// TestServerFingerprintController_AnalyzeClientHello verifies JA4 approximation.
func TestServerFingerprintController_AnalyzeClientHello(t *testing.T) {
	ctrl, err := NewServerFingerprintController("cloudflare")
	if err != nil {
		t.Fatalf("Failed to create controller: %v", err)
	}

	chi := &ClientHelloInfo{
		SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		CipherSuites:      []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
		SupportedCurves:   []CurveID{X25519, CurveP256},
		SupportedProtos:   []string{"h2", "http/1.1"},
		ServerName:        "example.com",
		SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
	}

	fp, err := ctrl.AnalyzeClientHello(chi)
	if err != nil {
		t.Fatalf("AnalyzeClientHello failed: %v", err)
	}
	if fp == nil {
		t.Fatal("Fingerprint should not be nil")
	}
	if fp.JA4 == "" {
		t.Error("JA4 should not be empty")
	}

	// JA4 should start with 't' for TCP and contain '13' for TLS 1.3
	if !strings.HasPrefix(fp.JA4, "t13") {
		t.Errorf("JA4 should start with 't13', got %s", fp.JA4)
	}
	// Should have 'd' for domain SNI
	if !strings.Contains(fp.JA4, "d") {
		t.Errorf("JA4 should contain 'd' for domain SNI, got %s", fp.JA4)
	}
}

// =============================================================================
// ServerProfile Clone Tests
// =============================================================================

// TestServerProfile_Clone verifies deep cloning of profiles.
func TestServerProfile_Clone(t *testing.T) {
	original := &ServerProfile{
		ID:          "test",
		Name:        "Test Profile",
		Description: "A test profile",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference:    []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
			Extensions:          []uint16{43, 51},
			ALPNPreference:      []string{"h2", "http/1.1"},
		},
		Certificate: CertificateConfig{
			Issuer: RDNConfig{
				Fields: []RDNField{
					{OID: OIDCommonName, Value: "Test CA"},
				},
			},
		},
	}

	clone := original.Clone()
	if clone == nil {
		t.Fatal("Clone should not be nil")
	}

	// Modify original
	original.ID = "modified"
	original.ServerHello.CipherPreference[0] = TLS_CHACHA20_POLY1305_SHA256
	original.ServerHello.ALPNPreference[0] = "modified"
	original.Certificate.Issuer.Fields[0].Value = "Modified CA"

	// Clone should be unchanged
	if clone.ID != "test" {
		t.Errorf("Clone ID was modified: got %s, want test", clone.ID)
	}
	if clone.ServerHello.CipherPreference[0] != TLS_AES_128_GCM_SHA256 {
		t.Error("Clone CipherPreference was modified")
	}
	if clone.ServerHello.ALPNPreference[0] != "h2" {
		t.Error("Clone ALPNPreference was modified")
	}
	if clone.Certificate.Issuer.Fields[0].Value != "Test CA" {
		t.Error("Clone Issuer was modified")
	}
}

// TestServerProfile_CloneNil verifies nil clone returns empty profile (not nil).
func TestServerProfile_CloneNil(t *testing.T) {
	var p *ServerProfile
	clone := p.Clone()
	if clone == nil {
		t.Fatal("Clone of nil should return empty profile, not nil")
	}
	if clone.ID != "" {
		t.Error("Clone of nil should have empty ID")
	}
}

// =============================================================================
// QuickServerConfig Tests
// =============================================================================

// TestQuickServerConfig_Success verifies QuickServerConfig creates valid config.
func TestQuickServerConfig_Success(t *testing.T) {
	// Create a dummy certificate
	certConfig := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 24 * time.Hour,
	}
	x509Cert, privKey, err := GenerateCertificate(certConfig, "example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	cert := Certificate{
		Certificate: [][]byte{x509Cert.Raw},
		PrivateKey:  privKey,
		Leaf:        x509Cert,
	}

	config, err := QuickServerConfig("cloudflare", cert)
	if err != nil {
		t.Fatalf("QuickServerConfig failed: %v", err)
	}
	if config == nil {
		t.Fatal("Config should not be nil")
	}
	if config.GetConfigForClient == nil {
		t.Error("GetConfigForClient should be set")
	}
	if len(config.Certificates) != 1 {
		t.Error("Certificates should be set")
	}
}

// TestQuickServerConfig_UnknownProfile verifies error for unknown profile.
func TestQuickServerConfig_UnknownProfile(t *testing.T) {
	cert := Certificate{}
	config, err := QuickServerConfig("nonexistent", cert)
	if err == nil {
		t.Error("Expected error for unknown profile")
	}
	if config != nil {
		t.Error("Config should be nil for unknown profile")
	}
}

// TestQuickServerConfigWithController_ReturnsController verifies controller is returned.
func TestQuickServerConfigWithController_ReturnsController(t *testing.T) {
	certConfig := &CertificateConfig{
		KeyType:        "ecdsa-p256",
		ValidityPeriod: 24 * time.Hour,
	}
	x509Cert, privKey, err := GenerateCertificate(certConfig, "example.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	cert := Certificate{
		Certificate: [][]byte{x509Cert.Raw},
		PrivateKey:  privKey,
		Leaf:        x509Cert,
	}

	config, ctrl, err := QuickServerConfigWithController("cloudflare", cert)
	if err != nil {
		t.Fatalf("QuickServerConfigWithController failed: %v", err)
	}
	if config == nil {
		t.Fatal("Config should not be nil")
	}
	if ctrl == nil {
		t.Fatal("Controller should not be nil")
	}
	if ctrl.Profile().ID != "cloudflare" {
		t.Errorf("Controller profile ID mismatch: got %s, want cloudflare", ctrl.Profile().ID)
	}
}

// =============================================================================
// isTLS13CipherSuite Tests
// =============================================================================

// TestIsTLS13CipherSuite verifies TLS 1.3 cipher detection.
func TestIsTLS13CipherSuite(t *testing.T) {
	tls13Ciphers := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}

	for _, c := range tls13Ciphers {
		if !isTLS13CipherSuite(c) {
			t.Errorf("isTLS13CipherSuite(%04x) should be true", c)
		}
	}

	nonTLS13Ciphers := []uint16{
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	for _, c := range nonTLS13Ciphers {
		if isTLS13CipherSuite(c) {
			t.Errorf("isTLS13CipherSuite(%04x) should be false", c)
		}
	}
}

// =============================================================================
// formatCipherSuite and formatExtension Tests
// =============================================================================

// TestFormatCipherSuite verifies hex formatting of cipher suites.
func TestFormatCipherSuite(t *testing.T) {
	tests := []struct {
		suite    uint16
		expected string
	}{
		{0x1301, "1301"},
		{0x1302, "1302"},
		{0x1303, "1303"},
		{0xc02f, "c02f"},
		{0xc030, "c030"},
		{0x0000, "0000"},
		{0xffff, "ffff"},
		{0x0a0a, "0a0a"}, // GREASE
	}

	for _, tc := range tests {
		result := formatCipherSuite(tc.suite)
		if result != tc.expected {
			t.Errorf("formatCipherSuite(%04x) = %s, want %s", tc.suite, result, tc.expected)
		}
	}
}

// TestFormatExtension verifies hex formatting of extensions.
func TestFormatExtension(t *testing.T) {
	tests := []struct {
		ext      uint16
		expected string
	}{
		{0, "0000"},
		{10, "000a"},
		{11, "000b"},
		{16, "0010"}, // ALPN
		{43, "002b"}, // supported_versions
		{51, "0033"}, // key_share
		{255, "00ff"},
		{0xffff, "ffff"},
	}

	for _, tc := range tests {
		result := formatExtension(tc.ext)
		if result != tc.expected {
			t.Errorf("formatExtension(%d) = %s, want %s", tc.ext, result, tc.expected)
		}
	}
}

// =============================================================================
// isValidKeyShareGroupForServer Tests
// =============================================================================

// TestIsValidKeyShareGroupForServer verifies key share group validation.
func TestIsValidKeyShareGroupForServer(t *testing.T) {
	validGroups := []CurveID{CurveP256, CurveP384, CurveP521, X25519, X25519MLKEM768}

	for _, g := range validGroups {
		if !isValidKeyShareGroupForServer(g) {
			t.Errorf("isValidKeyShareGroupForServer(%d) should be true", g)
		}
	}

	// GREASE values should be rejected
	greaseValues := []CurveID{0x0a0a, 0x1a1a, 0x2a2a}
	for _, g := range greaseValues {
		if isValidKeyShareGroupForServer(g) {
			t.Errorf("isValidKeyShareGroupForServer(GREASE %04x) should be false", g)
		}
	}
}

// =============================================================================
// selectVersion Tests
// =============================================================================

// TestSelectVersion verifies TLS version selection.
func TestSelectVersion(t *testing.T) {
	tests := []struct {
		clientVersions []uint16
		expected       uint16
	}{
		{[]uint16{VersionTLS13, VersionTLS12}, VersionTLS13},
		{[]uint16{VersionTLS12, VersionTLS11}, VersionTLS12},
		{[]uint16{VersionTLS11, VersionTLS10}, VersionTLS12}, // Defaults to 1.2
		{[]uint16{VersionTLS13}, VersionTLS13},
		{[]uint16{VersionTLS12}, VersionTLS12},
		{[]uint16{}, VersionTLS12},
	}

	for _, tc := range tests {
		result := selectVersion(tc.clientVersions)
		if result != tc.expected {
			t.Errorf("selectVersion(%v) = %04x, want %04x", tc.clientVersions, result, tc.expected)
		}
	}
}

// =============================================================================
// computeExtensionHash Tests
// =============================================================================

// TestComputeExtensionHash verifies extension hash computation.
func TestComputeExtensionHash(t *testing.T) {
	// Empty extensions should return fixed value
	emptyHash := computeExtensionHash(nil)
	if emptyHash != "000000000000" {
		t.Errorf("Empty extension hash should be '000000000000', got %s", emptyHash)
	}

	emptyHash2 := computeExtensionHash([]uint16{})
	if emptyHash2 != "000000000000" {
		t.Errorf("Empty slice extension hash should be '000000000000', got %s", emptyHash2)
	}

	// Non-empty should produce 12-char hash
	hash := computeExtensionHash([]uint16{43, 51})
	if len(hash) != 12 {
		t.Errorf("Extension hash should be 12 chars, got %d", len(hash))
	}

	// Different orders should produce different hashes
	hash1 := computeExtensionHash([]uint16{43, 51})
	hash2 := computeExtensionHash([]uint16{51, 43})
	if hash1 == hash2 {
		t.Error("Different extension orders should produce different hashes")
	}
}
