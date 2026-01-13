// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// Type assertions to ensure interface compatibility
var _ = &Config{WrapSession: (&Config{}).EncryptTicket}
var _ = &Config{UnwrapSession: (&Config{}).DecryptTicket}

// testTicketKey generates a random 32-byte key for testing
func testTicketKey() [32]byte {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		panic(err)
	}
	return key
}

// testSessionState creates a minimal server session state for testing
func testSessionState(version uint16, cipherSuite uint16) *SessionState {
	return &SessionState{
		version:         version,
		isClient:        false,
		cipherSuite:     cipherSuite,
		createdAt:       uint64(time.Now().Unix()),
		secret:          []byte("test-master-secret-32-bytes!!!!"),
		extMasterSecret: true,
		EarlyData:       false,
	}
}

// TestTicketEncryptDecrypt tests round-trip encryption and decryption
func TestTicketEncryptDecrypt(t *testing.T) {
	key1 := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	testCases := []struct {
		name        string
		version     uint16
		cipherSuite uint16
	}{
		{"TLS12_AES128", VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		{"TLS12_AES256", VersionTLS12, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		{"TLS12_CHACHA", VersionTLS12, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ss := testSessionState(tc.version, tc.cipherSuite)

			// Encrypt the session state
			encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
			if err != nil {
				t.Fatalf("EncryptTicket failed: %v", err)
			}

			// Verify minimum length: IV (16) + at least some ciphertext + MAC (32)
			minLen := aes.BlockSize + sha256.Size
			if len(encrypted) < minLen {
				t.Fatalf("encrypted ticket too short: got %d, want at least %d", len(encrypted), minLen)
			}

			// Decrypt the ticket
			decrypted, err := config.DecryptTicket(encrypted, ConnectionState{})
			if err != nil {
				t.Fatalf("DecryptTicket failed: %v", err)
			}
			if decrypted == nil {
				t.Fatal("DecryptTicket returned nil without error")
			}

			// Verify the session state matches
			if decrypted.version != ss.version {
				t.Errorf("version mismatch: got %d, want %d", decrypted.version, ss.version)
			}
			if decrypted.cipherSuite != ss.cipherSuite {
				t.Errorf("cipherSuite mismatch: got %d, want %d", decrypted.cipherSuite, ss.cipherSuite)
			}
			if !bytes.Equal(decrypted.secret, ss.secret) {
				t.Errorf("secret mismatch: got %x, want %x", decrypted.secret, ss.secret)
			}
			if decrypted.extMasterSecret != ss.extMasterSecret {
				t.Errorf("extMasterSecret mismatch: got %v, want %v", decrypted.extMasterSecret, ss.extMasterSecret)
			}
		})
	}
}

// TestTicketKeyRotation tests that tickets can still be decrypted after key rotation
func TestTicketKeyRotation(t *testing.T) {
	key1 := testTicketKey()
	key2 := testTicketKey()
	config := &Config{}

	// Create ticket with key1
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}
	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		t.Fatalf("EncryptTicket failed: %v", err)
	}

	// Rotate to key2, but keep key1 for decryption
	if err := config.SetSessionTicketKeys([][32]byte{key2, key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	// Decrypt should still work with key1 in rotation
	decrypted, err := config.DecryptTicket(encrypted, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket after rotation failed: %v", err)
	}
	if decrypted == nil {
		t.Fatal("DecryptTicket returned nil after key rotation")
	}

	// Verify the decrypted state
	if decrypted.version != ss.version {
		t.Errorf("version mismatch after rotation: got %d, want %d", decrypted.version, ss.version)
	}
	if !bytes.Equal(decrypted.secret, ss.secret) {
		t.Errorf("secret mismatch after rotation")
	}
}

// TestTicketKeyRotationRemoved tests that tickets fail when the key is completely removed
func TestTicketKeyRotationRemoved(t *testing.T) {
	key1 := testTicketKey()
	key2 := testTicketKey()
	config := &Config{}

	// Create ticket with key1
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}
	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		t.Fatalf("EncryptTicket failed: %v", err)
	}

	// Replace with completely different key (key1 not in rotation)
	if err := config.SetSessionTicketKeys([][32]byte{key2}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	// Decrypt should fail (return nil, nil per the API contract)
	decrypted, err := config.DecryptTicket(encrypted, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket should not return error for invalid key, got: %v", err)
	}
	if decrypted != nil {
		t.Fatal("DecryptTicket should return nil when key is not in rotation")
	}
}

// TestTicketCorruptedMAC tests that corrupted MACs are rejected
func TestTicketCorruptedMAC(t *testing.T) {
	key1 := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		t.Fatalf("EncryptTicket failed: %v", err)
	}

	// Corrupt the MAC (last 32 bytes)
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[len(corrupted)-1] ^= 0xFF // Flip bits in last byte of MAC

	// Decrypt should fail
	decrypted, err := config.DecryptTicket(corrupted, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket should not return error for corrupted MAC, got: %v", err)
	}
	if decrypted != nil {
		t.Fatal("DecryptTicket should return nil for corrupted MAC")
	}
}

// TestTicketCorruptedIV tests that corrupted IV causes decryption to produce garbage
// which should fail during parsing
func TestTicketCorruptedIV(t *testing.T) {
	key1 := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		t.Fatalf("EncryptTicket failed: %v", err)
	}

	// Corrupt the IV (first 16 bytes)
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[0] ^= 0xFF // Flip bits in first byte of IV

	// MAC will fail because IV is part of authenticated data
	decrypted, err := config.DecryptTicket(corrupted, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket should not return error, got: %v", err)
	}
	if decrypted != nil {
		t.Fatal("DecryptTicket should return nil for corrupted IV (MAC should fail)")
	}
}

// TestTicketCorruptedCiphertext tests that corrupted ciphertext fails MAC
func TestTicketCorruptedCiphertext(t *testing.T) {
	key1 := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		t.Fatalf("EncryptTicket failed: %v", err)
	}

	// Corrupt ciphertext (between IV and MAC)
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	midpoint := aes.BlockSize + (len(encrypted)-aes.BlockSize-sha256.Size)/2
	corrupted[midpoint] ^= 0xFF

	// MAC should fail because ciphertext is authenticated
	decrypted, err := config.DecryptTicket(corrupted, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket should not return error, got: %v", err)
	}
	if decrypted != nil {
		t.Fatal("DecryptTicket should return nil for corrupted ciphertext (MAC should fail)")
	}
}

// TestTicketTooShort tests that short tickets are rejected
func TestTicketTooShort(t *testing.T) {
	key1 := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	testCases := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"half_block", aes.BlockSize / 2},
		{"just_block", aes.BlockSize},
		{"block_plus_half_mac", aes.BlockSize + sha256.Size/2},
		{"just_under_minimum", aes.BlockSize + sha256.Size - 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shortTicket := make([]byte, tc.length)
			rand.Read(shortTicket)

			decrypted, err := config.DecryptTicket(shortTicket, ConnectionState{})
			if err != nil {
				t.Fatalf("DecryptTicket should not return error for short ticket, got: %v", err)
			}
			if decrypted != nil {
				t.Fatalf("DecryptTicket should return nil for ticket of length %d", tc.length)
			}
		})
	}
}

// TestTicketMinimumValidLength tests the minimum valid ticket length
func TestTicketMinimumValidLength(t *testing.T) {
	key1 := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	// Minimum length is IV (16) + MAC (32) = 48 bytes
	// This would represent zero-length plaintext
	minLength := aes.BlockSize + sha256.Size
	ticket := make([]byte, minLength)
	rand.Read(ticket)

	// This should not panic, but will likely fail MAC
	decrypted, err := config.DecryptTicket(ticket, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket should not return error, got: %v", err)
	}
	// Random bytes won't have valid MAC
	if decrypted != nil {
		t.Fatal("Random bytes should not decrypt successfully")
	}
}

// TestParseSessionStateValid tests parsing valid session states
func TestParseSessionStateValid(t *testing.T) {
	// Create a valid server session state and serialize it
	original := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	data, err := original.Bytes()
	if err != nil {
		t.Fatalf("SessionState.Bytes() failed: %v", err)
	}

	// Parse it back
	parsed, err := ParseSessionState(data)
	if err != nil {
		t.Fatalf("ParseSessionState failed: %v", err)
	}

	// Verify fields
	if parsed.version != original.version {
		t.Errorf("version mismatch: got %d, want %d", parsed.version, original.version)
	}
	if parsed.cipherSuite != original.cipherSuite {
		t.Errorf("cipherSuite mismatch: got %d, want %d", parsed.cipherSuite, original.cipherSuite)
	}
	if !bytes.Equal(parsed.secret, original.secret) {
		t.Errorf("secret mismatch")
	}
	if parsed.extMasterSecret != original.extMasterSecret {
		t.Errorf("extMasterSecret mismatch")
	}
	if parsed.EarlyData != original.EarlyData {
		t.Errorf("EarlyData mismatch")
	}
	if parsed.isClient != original.isClient {
		t.Errorf("isClient mismatch")
	}
}

// TestParseSessionStateTruncated tests that truncated data is rejected
func TestParseSessionStateTruncated(t *testing.T) {
	original := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	data, err := original.Bytes()
	if err != nil {
		t.Fatalf("SessionState.Bytes() failed: %v", err)
	}

	// Test truncation at various points
	testCases := []struct {
		name   string
		length int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"partial_version", 1},
		{"version_only", 2},
		{"version_and_type", 3},
		{"through_cipher", 5},
		{"half_data", len(data) / 2},
		{"almost_complete", len(data) - 1},
	}

	for _, tc := range testCases {
		if tc.length >= len(data) {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			truncated := data[:tc.length]
			_, err := ParseSessionState(truncated)
			if err == nil {
				t.Errorf("ParseSessionState should fail for truncated data of length %d", tc.length)
			}
		})
	}
}

// TestParseSessionStateInvalidType tests that invalid type values are rejected
func TestParseSessionStateInvalidType(t *testing.T) {
	original := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	data, err := original.Bytes()
	if err != nil {
		t.Fatalf("SessionState.Bytes() failed: %v", err)
	}

	// Type byte is at offset 2 (after 2-byte version)
	// Valid values are 1 (server) and 2 (client)
	invalidTypes := []byte{0, 3, 4, 255}

	for _, invalidType := range invalidTypes {
		t.Run("type_"+string(rune('0'+invalidType)), func(t *testing.T) {
			corrupted := make([]byte, len(data))
			copy(corrupted, data)
			corrupted[2] = invalidType

			_, err := ParseSessionState(corrupted)
			if err == nil {
				t.Errorf("ParseSessionState should fail for invalid type %d", invalidType)
			}
		})
	}
}

// TestParseSessionStateInvalidExtMasterSecret tests invalid extMasterSecret values
func TestParseSessionStateInvalidExtMasterSecret(t *testing.T) {
	original := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	data, err := original.Bytes()
	if err != nil {
		t.Fatalf("SessionState.Bytes() failed: %v", err)
	}

	// Calculate the exact offset of extMasterSecret in serialized data.
	// Format for server session (isClient=false) with no Extra data:
	//   version(2) + type(1) + cipher(2) + createdAt(8) + secretLen(1) + secret(len) + extraLen(3) + extMasterSecret(1) + ...
	//
	// testSessionState creates:
	//   - secret = "test-master-secret-32-bytes!!!!" (31 bytes)
	//   - Extra = nil (serializes as 3 bytes: 0x00, 0x00, 0x00)
	//
	// So extMasterSecret is at offset: 2 + 1 + 2 + 8 + 1 + 31 + 3 = 48
	secretLen := len(original.secret)
	extMasterSecretOffset := 2 + 1 + 2 + 8 + 1 + secretLen + 3

	if extMasterSecretOffset >= len(data) {
		t.Fatalf("extMasterSecret offset %d exceeds data length %d", extMasterSecretOffset, len(data))
	}

	// Verify we found the right byte by checking it's 0 or 1
	originalValue := data[extMasterSecretOffset]
	if originalValue != 0 && originalValue != 1 {
		t.Fatalf("Expected extMasterSecret byte at offset %d to be 0 or 1, got %d - format may have changed",
			extMasterSecretOffset, originalValue)
	}

	// Test invalid extMasterSecret values (valid values are 0 and 1)
	invalidValues := []byte{2, 3, 127, 255}
	for _, invalidValue := range invalidValues {
		t.Run("value_"+string(rune('0'+invalidValue)), func(t *testing.T) {
			corrupted := make([]byte, len(data))
			copy(corrupted, data)
			corrupted[extMasterSecretOffset] = invalidValue

			_, err := ParseSessionState(corrupted)
			if err == nil {
				t.Errorf("ParseSessionState should fail for invalid extMasterSecret value %d", invalidValue)
			}
		})
	}
}

// TestParseSessionStateEmptySecret tests that empty secrets are rejected
func TestParseSessionStateEmptySecret(t *testing.T) {
	// Create a session state with empty secret
	ss := &SessionState{
		version:     VersionTLS12,
		isClient:    false,
		cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		createdAt:   uint64(time.Now().Unix()),
		secret:      []byte{}, // Empty secret should be rejected
	}

	data, err := ss.Bytes()
	if err != nil {
		t.Fatalf("SessionState.Bytes() failed: %v", err)
	}

	// ParseSessionState should reject empty secret
	_, err = ParseSessionState(data)
	if err == nil {
		t.Error("ParseSessionState should fail for empty secret")
	}
}

// TestParseSessionStateExtraData tests handling of Extra field
func TestParseSessionStateExtraData(t *testing.T) {
	original := &SessionState{
		version:         VersionTLS12,
		isClient:        false,
		cipherSuite:     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		createdAt:       uint64(time.Now().Unix()),
		secret:          []byte("test-master-secret-32-bytes!!!!"),
		extMasterSecret: true,
		Extra:           [][]byte{[]byte("extra1"), []byte("extra2"), []byte("extra3")},
	}

	data, err := original.Bytes()
	if err != nil {
		t.Fatalf("SessionState.Bytes() failed: %v", err)
	}

	parsed, err := ParseSessionState(data)
	if err != nil {
		t.Fatalf("ParseSessionState failed: %v", err)
	}

	if len(parsed.Extra) != len(original.Extra) {
		t.Errorf("Extra count mismatch: got %d, want %d", len(parsed.Extra), len(original.Extra))
	}

	for i := range original.Extra {
		if !bytes.Equal(parsed.Extra[i], original.Extra[i]) {
			t.Errorf("Extra[%d] mismatch: got %v, want %v", i, parsed.Extra[i], original.Extra[i])
		}
	}
}

// TestSessionStateBytes tests Bytes() with various configurations
func TestSessionStateBytes(t *testing.T) {
	testCases := []struct {
		name string
		ss   *SessionState
	}{
		{
			name: "minimal_server_tls12",
			ss: &SessionState{
				version:     VersionTLS12,
				isClient:    false,
				cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				createdAt:   uint64(time.Now().Unix()),
				secret:      []byte("test-secret-minimum-16-bytes"),
			},
		},
		{
			name: "server_with_extra",
			ss: &SessionState{
				version:         VersionTLS12,
				isClient:        false,
				cipherSuite:     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				createdAt:       uint64(time.Now().Unix()),
				secret:          []byte("test-secret-256-bit-length!!!!"),
				extMasterSecret: true,
				Extra:           [][]byte{[]byte("application-data")},
			},
		},
		{
			name: "server_with_early_data",
			ss: &SessionState{
				version:         VersionTLS13,
				isClient:        false,
				cipherSuite:     TLS_AES_128_GCM_SHA256,
				createdAt:       uint64(time.Now().Unix()),
				secret:          []byte("tls13-psk-secret-32-bytes-long"),
				extMasterSecret: true,
				EarlyData:       true,
				alpnProtocol:    "h2",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.ss.Bytes()
			if err != nil {
				t.Fatalf("Bytes() failed: %v", err)
			}

			if len(data) == 0 {
				t.Fatal("Bytes() returned empty data")
			}

			// Verify round-trip
			parsed, err := ParseSessionState(data)
			if err != nil {
				t.Fatalf("ParseSessionState failed: %v", err)
			}

			if parsed.version != tc.ss.version {
				t.Errorf("version mismatch after round-trip")
			}
			if parsed.cipherSuite != tc.ss.cipherSuite {
				t.Errorf("cipherSuite mismatch after round-trip")
			}
			if !bytes.Equal(parsed.secret, tc.ss.secret) {
				t.Errorf("secret mismatch after round-trip")
			}
			if parsed.EarlyData != tc.ss.EarlyData {
				t.Errorf("EarlyData mismatch after round-trip")
			}
			if tc.ss.EarlyData && parsed.alpnProtocol != tc.ss.alpnProtocol {
				t.Errorf("alpnProtocol mismatch after round-trip: got %q, want %q",
					parsed.alpnProtocol, tc.ss.alpnProtocol)
			}
		})
	}
}

// TestTicketMultipleKeys tests decryption with multiple keys in rotation
func TestTicketMultipleKeys(t *testing.T) {
	keys := make([][32]byte, 5)
	for i := range keys {
		keys[i] = testTicketKey()
	}

	config := &Config{}

	// Create tickets with each key as primary
	tickets := make([][]byte, len(keys))
	for i := range keys {
		// Set only this key as primary
		if err := config.SetSessionTicketKeys([][32]byte{keys[i]}); err != nil {
			t.Fatalf("SetSessionTicketKeys failed: %v", err)
		}
		ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

		var err error
		tickets[i], err = config.EncryptTicket(ConnectionState{}, ss)
		if err != nil {
			t.Fatalf("EncryptTicket with key %d failed: %v", i, err)
		}
	}

	// Now set all keys in rotation
	if err := config.SetSessionTicketKeys(keys); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	// All tickets should decrypt successfully
	for i, ticket := range tickets {
		decrypted, err := config.DecryptTicket(ticket, ConnectionState{})
		if err != nil {
			t.Fatalf("DecryptTicket for key %d failed: %v", i, err)
		}
		if decrypted == nil {
			t.Errorf("DecryptTicket for key %d returned nil", i)
		}
	}
}

// TestTicketNewKeyUsedForEncryption tests that the first key is always used for encryption
func TestTicketNewKeyUsedForEncryption(t *testing.T) {
	key1 := testTicketKey()
	key2 := testTicketKey()
	config := &Config{}

	// Set key2 as primary, key1 as backup
	if err := config.SetSessionTicketKeys([][32]byte{key2, key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		t.Fatalf("EncryptTicket failed: %v", err)
	}

	// Set only key2 (should work - ticket was encrypted with key2)
	if err := config.SetSessionTicketKeys([][32]byte{key2}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}
	decrypted, err := config.DecryptTicket(encrypted, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket with key2 only failed: %v", err)
	}
	if decrypted == nil {
		t.Error("DecryptTicket with key2 only returned nil - expected success")
	}

	// Set only key1 (should fail - ticket was encrypted with key2)
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}
	decrypted, err = config.DecryptTicket(encrypted, ConnectionState{})
	if err != nil {
		t.Fatalf("DecryptTicket should not return error, got: %v", err)
	}
	if decrypted != nil {
		t.Error("DecryptTicket with key1 only should return nil - ticket was encrypted with key2")
	}
}

// TestTicketDecryptionError tests that parsing failures after successful MAC return error
func TestTicketDecryptionError(t *testing.T) {
	key1 := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key1}); err != nil {
		t.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	// Get the ticket keys to use for encryption
	ticketKeys, err := config.ticketKeys(nil)
	if err != nil {
		t.Fatalf("ticketKeys failed: %v", err)
	}
	if len(ticketKeys) == 0 {
		t.Fatal("No ticket keys available")
	}

	// Test 1: Encrypt garbage that won't parse as valid SessionState
	// This creates a ticket with valid MAC but invalid session content
	garbagePayloads := []struct {
		name    string
		payload []byte
	}{
		{
			name: "completely_random",
			payload: []byte{
				0xFF, 0xFF, // Invalid version
				0xFF,       // Invalid type (not 1 or 2)
				0x00, 0x00, // Cipher suite
				// Missing rest of required fields
			},
		},
		{
			name: "valid_version_invalid_type",
			payload: []byte{
				0x03, 0x03, // TLS 1.2 version
				0x00,       // Invalid type (0 is not valid, only 1 or 2)
				0x00, 0x2F, // Cipher suite
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // createdAt
				0x10, // secret length = 16
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // secret
				0x00, 0x00, 0x00, // extra length = 0
				0x01, // extMasterSecret = true
				0x00, // earlyData = false
			},
		},
		{
			name: "truncated_data",
			payload: []byte{
				0x03, 0x03, // TLS 1.2 version
				0x01,       // Type = server
				0x00, 0x2F, // Cipher suite
				// Missing createdAt, secret, etc.
			},
		},
		{
			name: "empty_secret",
			payload: []byte{
				0x03, 0x03, // TLS 1.2 version
				0x01,       // Type = server
				0x00, 0x2F, // Cipher suite
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // createdAt
				0x00,             // secret length = 0 (INVALID - secret must be non-empty)
				0x00, 0x00, 0x00, // extra length = 0
				0x01, // extMasterSecret = true
				0x00, // earlyData = false
			},
		},
	}

	for _, tc := range garbagePayloads {
		t.Run(tc.name, func(t *testing.T) {
			// Use internal encryptTicket to create ticket with valid MAC but garbage content
			encryptedTicket, err := config.encryptTicket(tc.payload, ticketKeys)
			if err != nil {
				t.Fatalf("encryptTicket failed: %v", err)
			}

			// DecryptTicket should return ErrTicketParsingFailed
			result, err := config.DecryptTicket(encryptedTicket, ConnectionState{})
			if err == nil {
				t.Error("DecryptTicket should return error for invalid session state")
			} else if !errors.Is(err, ErrTicketParsingFailed) {
				t.Errorf("DecryptTicket should return ErrTicketParsingFailed, got: %v", err)
			}
			if result != nil {
				t.Error("DecryptTicket should return nil session state for parsing failure")
			}
		})
	}

	// Test 2: Verify sentinel errors are distinct
	if errors.Is(ErrTicketDecryptionFailed, ErrTicketParsingFailed) {
		t.Error("ErrTicketDecryptionFailed should not equal ErrTicketParsingFailed")
	}
	if errors.Is(ErrTicketTooShort, ErrTicketParsingFailed) {
		t.Error("ErrTicketTooShort should not equal ErrTicketParsingFailed")
	}
}

// TestResumptionState tests ClientSessionState methods
func TestResumptionState(t *testing.T) {
	ticket := []byte("test-ticket-identity")
	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	css, err := NewResumptionState(ticket, ss)
	if err != nil {
		t.Fatalf("NewResumptionState failed: %v", err)
	}

	gotTicket, gotState, err := css.ResumptionState()
	if err != nil {
		t.Fatalf("ResumptionState failed: %v", err)
	}

	if !bytes.Equal(gotTicket, ticket) {
		t.Errorf("ticket mismatch: got %v, want %v", gotTicket, ticket)
	}

	if gotState.version != ss.version {
		t.Errorf("version mismatch: got %d, want %d", gotState.version, ss.version)
	}
}

// TestResumptionStateNil tests that nil ClientSessionState is handled
func TestResumptionStateNil(t *testing.T) {
	var css *ClientSessionState

	ticket, state, err := css.ResumptionState()
	if err != nil {
		t.Fatalf("ResumptionState on nil should not fail: %v", err)
	}
	if ticket != nil {
		t.Error("ticket should be nil for nil ClientSessionState")
	}
	if state != nil {
		t.Error("state should be nil for nil ClientSessionState")
	}
}

// TestSessionStateMaxLifetime tests that sessions with excessive lifetime are rejected
func TestSessionStateMaxLifetime(t *testing.T) {
	// Parse the test certificate to use for client session
	testCert, err := x509.ParseCertificate(testRSACertificate)
	if err != nil {
		t.Fatalf("failed to parse test certificate: %v", err)
	}

	now := uint64(time.Now().Unix())

	// Test 1: TLS 1.3 client session with excessive lifetime (> 7 days) should be rejected
	t.Run("excessive_lifetime_rejected", func(t *testing.T) {
		ss := &SessionState{
			version:          VersionTLS13,
			isClient:         true,
			cipherSuite:      TLS_AES_128_GCM_SHA256,
			createdAt:        now,
			secret:           []byte("test-psk-secret-32-bytes-long!!!"),
			extMasterSecret:  true,
			useBy:            now + 8*24*60*60, // 8 days - exceeds RFC 8446 maximum of 7 days
			ageAdd:           12345,
			peerCertificates: []*x509.Certificate{testCert}, // Required for client session
		}

		// Serialize the session
		data, err := ss.Bytes()
		if err != nil {
			t.Fatalf("SessionState.Bytes() failed: %v", err)
		}

		// Parse should fail due to excessive lifetime (RFC 8446 Section 4.6.1)
		_, err = ParseSessionState(data)
		if err == nil {
			t.Error("ParseSessionState should reject session with lifetime > 7 days")
		}
	})

	// Test 2: TLS 1.3 client session with valid lifetime (7 days exactly) should be accepted
	t.Run("valid_lifetime_accepted", func(t *testing.T) {
		ss := &SessionState{
			version:          VersionTLS13,
			isClient:         true,
			cipherSuite:      TLS_AES_128_GCM_SHA256,
			createdAt:        now,
			secret:           []byte("test-psk-secret-32-bytes-long!!!"),
			extMasterSecret:  true,
			useBy:            now + 7*24*60*60, // Exactly 7 days - RFC 8446 maximum
			ageAdd:           12345,
			peerCertificates: []*x509.Certificate{testCert},
		}

		// Serialize the session
		data, err := ss.Bytes()
		if err != nil {
			t.Fatalf("SessionState.Bytes() failed: %v", err)
		}

		// Parse should succeed for 7-day lifetime
		parsed, err := ParseSessionState(data)
		if err != nil {
			t.Fatalf("ParseSessionState failed for 7-day lifetime: %v", err)
		}

		// Verify the lifetime was preserved
		if parsed.useBy != ss.useBy {
			t.Errorf("useBy mismatch: got %d, want %d", parsed.useBy, ss.useBy)
		}
	})

	// Test 3: TLS 1.3 client session with shorter lifetime should be accepted
	t.Run("short_lifetime_accepted", func(t *testing.T) {
		ss := &SessionState{
			version:          VersionTLS13,
			isClient:         true,
			cipherSuite:      TLS_AES_128_GCM_SHA256,
			createdAt:        now,
			secret:           []byte("test-psk-secret-32-bytes-long!!!"),
			extMasterSecret:  true,
			useBy:            now + 1*24*60*60, // 1 day
			ageAdd:           12345,
			peerCertificates: []*x509.Certificate{testCert},
		}

		data, err := ss.Bytes()
		if err != nil {
			t.Fatalf("SessionState.Bytes() failed: %v", err)
		}

		parsed, err := ParseSessionState(data)
		if err != nil {
			t.Fatalf("ParseSessionState failed for 1-day lifetime: %v", err)
		}

		if parsed.useBy != ss.useBy {
			t.Errorf("useBy mismatch: got %d, want %d", parsed.useBy, ss.useBy)
		}
	})

	// Test 4: TLS 1.2 sessions don't have useBy field, so no lifetime check
	t.Run("tls12_no_lifetime_check", func(t *testing.T) {
		ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		data, err := ss.Bytes()
		if err != nil {
			t.Fatalf("SessionState.Bytes() failed: %v", err)
		}

		_, err = ParseSessionState(data)
		if err != nil {
			t.Fatalf("ParseSessionState failed for TLS 1.2 session: %v", err)
		}
	})
}

// TestTicketEncryptionWithDisabledTickets tests behavior when tickets are disabled
func TestTicketEncryptionWithDisabledTickets(t *testing.T) {
	config := &Config{
		SessionTicketsDisabled: true,
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	// EncryptTicket should fail when tickets are disabled and no keys are set
	_, err := config.EncryptTicket(ConnectionState{}, ss)
	if err == nil {
		t.Error("EncryptTicket should fail when tickets are disabled")
	}
}

// TestSetSessionTicketKeysEmptyError tests that SetSessionTicketKeys returns error for empty keys
func TestSetSessionTicketKeysEmptyError(t *testing.T) {
	config := &Config{}

	// Empty keys should return an error
	err := config.SetSessionTicketKeys([][32]byte{})
	if err == nil {
		t.Fatal("SetSessionTicketKeys should return error for empty keys")
	}

	// Verify the error message
	expectedMsg := "tls: keys must have at least one key"
	if err.Error() != expectedMsg {
		t.Errorf("expected error message %q, got %q", expectedMsg, err.Error())
	}

	// nil slice should also return an error
	err = config.SetSessionTicketKeys(nil)
	if err == nil {
		t.Fatal("SetSessionTicketKeys should return error for nil keys")
	}
}

// TestSentinelErrors tests that sentinel errors are properly defined
func TestSentinelErrors(t *testing.T) {
	// Verify sentinel errors are non-nil and have expected messages
	if ErrTicketDecryptionFailed == nil {
		t.Fatal("ErrTicketDecryptionFailed is nil")
	}
	if ErrTicketTooShort == nil {
		t.Fatal("ErrTicketTooShort is nil")
	}
	if ErrTicketParsingFailed == nil {
		t.Fatal("ErrTicketParsingFailed is nil")
	}

	// Verify they are distinct errors
	if errors.Is(ErrTicketDecryptionFailed, ErrTicketTooShort) {
		t.Error("ErrTicketDecryptionFailed should not be ErrTicketTooShort")
	}
	if errors.Is(ErrTicketDecryptionFailed, ErrTicketParsingFailed) {
		t.Error("ErrTicketDecryptionFailed should not be ErrTicketParsingFailed")
	}

	// Verify error messages are descriptive
	if len(ErrTicketDecryptionFailed.Error()) < 10 {
		t.Error("ErrTicketDecryptionFailed message too short")
	}
	if len(ErrTicketTooShort.Error()) < 10 {
		t.Error("ErrTicketTooShort message too short")
	}
	if len(ErrTicketParsingFailed.Error()) < 10 {
		t.Error("ErrTicketParsingFailed message too short")
	}
}

// Benchmark for encryption performance
func BenchmarkTicketEncrypt(b *testing.B) {
	key := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key}); err != nil {
		b.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := config.EncryptTicket(ConnectionState{}, ss)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for decryption performance
func BenchmarkTicketDecrypt(b *testing.B) {
	key := testTicketKey()
	config := &Config{}
	if err := config.SetSessionTicketKeys([][32]byte{key}); err != nil {
		b.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := config.DecryptTicket(encrypted, ConnectionState{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for decryption with key rotation (multiple keys)
func BenchmarkTicketDecryptWithRotation(b *testing.B) {
	keys := make([][32]byte, 5)
	for i := range keys {
		keys[i] = testTicketKey()
	}

	config := &Config{}
	if err := config.SetSessionTicketKeys(keys); err != nil {
		b.Fatalf("SetSessionTicketKeys failed: %v", err)
	}

	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	encrypted, err := config.EncryptTicket(ConnectionState{}, ss)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := config.DecryptTicket(encrypted, ConnectionState{})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for SessionState serialization
func BenchmarkSessionStateBytes(b *testing.B) {
	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ss.Bytes()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for SessionState parsing
func BenchmarkParseSessionState(b *testing.B) {
	ss := testSessionState(VersionTLS12, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	data, err := ss.Bytes()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseSessionState(data)
		if err != nil {
			b.Fatal(err)
		}
	}
}
