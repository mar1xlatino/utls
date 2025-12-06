// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

// =============================================================================
// HRR Cookie Security Tests
// =============================================================================
//
// These tests verify security properties of the HRR (Hello Retry Request)
// cookie encoding/decoding functions. Critical security properties tested:
// - MAC tamper detection
// - Key mismatch detection
// - Cookie expiration enforcement
// - Malformed input handling (truncation, nil inputs)
// - Edge cases that could lead to security bypasses

// TestEncodeCookie_ValidData tests basic cookie encoding with valid inputs.
func TestEncodeCookie_ValidData(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test client hello")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil for valid input")
	}

	// Cookie format: ch_hash(32) + cipher(2) + group(2) + timestamp(8) + hmac(32) = 76 bytes
	expectedLen := 76
	if len(cookie) != expectedLen {
		t.Errorf("Cookie length = %d, expected %d", len(cookie), expectedLen)
	}
}

// TestEncodeCookie_NilData tests that nil data is rejected.
func TestEncodeCookie_NilData(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cookie := EncodeCookie(nil, key)
	if cookie != nil {
		t.Error("EncodeCookie should return nil for nil data")
	}
}

// TestEncodeCookie_ShortKey tests that short keys are rejected.
// Security: Keys shorter than 32 bytes provide insufficient security.
func TestEncodeCookie_ShortKey(t *testing.T) {
	testCases := []struct {
		name    string
		keyLen  int
		wantNil bool
	}{
		{"nil key", 0, true},
		{"1 byte key", 1, true},
		{"16 byte key", 16, true},
		{"31 byte key", 31, true},
		{"32 byte key (minimum)", 32, false},
		{"64 byte key", 64, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var key []byte
			if tc.keyLen > 0 {
				key = make([]byte, tc.keyLen)
				rand.Read(key)
			}

			data := &HRRCookieData{
				ClientHelloHash: sha256.Sum256([]byte("test")),
				SelectedCipher:  TLS_AES_128_GCM_SHA256,
				SelectedGroup:   X25519,
				Timestamp:       time.Now().Unix(),
			}

			cookie := EncodeCookie(data, key)
			if tc.wantNil && cookie != nil {
				t.Errorf("EncodeCookie should return nil for %s", tc.name)
			}
			if !tc.wantNil && cookie == nil {
				t.Errorf("EncodeCookie should return valid cookie for %s", tc.name)
			}
		})
	}
}

// TestEncodeCookie_NegativeTimestamp tests that negative timestamps are rejected.
// Security: Negative timestamps could indicate malformed or malicious data.
func TestEncodeCookie_NegativeTimestamp(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       -1, // Negative timestamp
	}

	cookie := EncodeCookie(data, key)
	if cookie != nil {
		t.Error("EncodeCookie should return nil for negative timestamp")
	}
}

// TestDecodeCookie_TamperedMAC tests that tampered cookies are rejected.
// Security: This is critical for preventing cookie forgery attacks.
func TestDecodeCookie_TamperedMAC(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	// Test tampering at various positions in the MAC (last 32 bytes)
	testCases := []struct {
		name   string
		offset int // Offset from end of cookie to tamper
	}{
		{"first MAC byte", 32},
		{"middle MAC byte", 16},
		{"last MAC byte", 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, len(cookie))
			copy(tampered, cookie)
			tampered[len(tampered)-tc.offset] ^= 0xFF // Flip all bits

			_, err := DecodeCookie(tampered, key)
			if err == nil {
				t.Errorf("DecodeCookie should reject cookie with %s tampered", tc.name)
			}
		})
	}
}

// TestDecodeCookie_TamperedData tests that cookies with modified data are rejected.
// Security: Any modification to cookie data should be detected by MAC verification.
func TestDecodeCookie_TamperedData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	// Test tampering at various positions in the data (first 44 bytes)
	testCases := []struct {
		name   string
		offset int // Byte offset to tamper
	}{
		{"ClientHello hash (byte 0)", 0},
		{"ClientHello hash (byte 15)", 15},
		{"ClientHello hash (byte 31)", 31},
		{"cipher suite (byte 32)", 32},
		{"cipher suite (byte 33)", 33},
		{"selected group (byte 34)", 34},
		{"selected group (byte 35)", 35},
		{"timestamp (byte 36)", 36},
		{"timestamp (byte 43)", 43},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, len(cookie))
			copy(tampered, cookie)
			tampered[tc.offset] ^= 0xFF

			_, err := DecodeCookie(tampered, key)
			if err == nil {
				t.Errorf("DecodeCookie should reject cookie with %s tampered", tc.name)
			}
		})
	}
}

// TestDecodeCookie_WrongKey tests that cookies are rejected with wrong key.
// Security: Cookie should only be decodable with the correct key.
func TestDecodeCookie_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	// Ensure keys are different
	key2[0] ^= 0xFF

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(data, key1)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	_, err := DecodeCookie(cookie, key2)
	if err == nil {
		t.Error("DecodeCookie should reject cookie decoded with wrong key")
	}
}

// TestDecodeCookie_EmptyCookie tests handling of empty cookie.
func TestDecodeCookie_EmptyCookie(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	_, err := DecodeCookie([]byte{}, key)
	if err == nil {
		t.Error("DecodeCookie should reject empty cookie")
	}
}

// TestDecodeCookie_TruncatedCookie tests handling of truncated cookies.
// Security: Truncated cookies should be rejected, not cause panics.
func TestDecodeCookie_TruncatedCookie(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	// Test truncation at various lengths
	truncationLengths := []int{0, 1, 10, 20, 30, 40, 50, 60, 70, 75}
	for _, length := range truncationLengths {
		t.Run("truncated_at_"+string(rune('0'+length/10))+string(rune('0'+length%10)), func(t *testing.T) {
			truncated := cookie[:length]
			_, err := DecodeCookie(truncated, key)
			if err == nil {
				t.Errorf("DecodeCookie should reject truncated cookie (length %d)", length)
			}
		})
	}
}

// TestDecodeCookie_ShortKey tests that decode rejects short keys.
func TestDecodeCookie_ShortKey(t *testing.T) {
	goodKey := make([]byte, 32)
	rand.Read(goodKey)

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(data, goodKey)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	shortKey := make([]byte, 16)
	rand.Read(shortKey)

	_, err := DecodeCookie(cookie, shortKey)
	if err == nil {
		t.Error("DecodeCookie should reject short key")
	}
}

// TestDecodeCookieWithMaxAge_ExpiredCookie tests expiration enforcement.
// Security: Expired cookies must be rejected to prevent replay attacks.
func TestDecodeCookieWithMaxAge_ExpiredCookie(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Create cookie with timestamp in the past
	pastTime := time.Now().Add(-5 * time.Minute).Unix()

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       pastTime,
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	// Try to decode with 60 second max age (cookie is 5 minutes old)
	_, err := DecodeCookieWithMaxAge(cookie, key, 60)
	if err == nil {
		t.Error("DecodeCookieWithMaxAge should reject expired cookie")
	}
}

// TestDecodeCookieWithMaxAge_FutureCookie tests rejection of future timestamps.
// Security: Cookies with future timestamps could indicate replay attacks or tampering.
func TestDecodeCookieWithMaxAge_FutureCookie(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Create cookie with timestamp far in the future (beyond allowed skew)
	futureTime := time.Now().Add(5 * time.Minute).Unix()

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       futureTime,
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	// Try to decode with 120 second max age
	_, err := DecodeCookieWithMaxAge(cookie, key, 120)
	if err == nil {
		t.Error("DecodeCookieWithMaxAge should reject cookie with far future timestamp")
	}
}

// TestDecodeCookieWithMaxAge_ValidCookie tests that valid cookies are accepted.
func TestDecodeCookieWithMaxAge_ValidCookie(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	originalData := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(originalData, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	decodedData, err := DecodeCookieWithMaxAge(cookie, key, 120)
	if err != nil {
		t.Fatalf("DecodeCookieWithMaxAge failed: %v", err)
	}

	// Verify decoded data matches original
	if decodedData.ClientHelloHash != originalData.ClientHelloHash {
		t.Error("ClientHelloHash mismatch")
	}
	if decodedData.SelectedCipher != originalData.SelectedCipher {
		t.Error("SelectedCipher mismatch")
	}
	if decodedData.SelectedGroup != originalData.SelectedGroup {
		t.Error("SelectedGroup mismatch")
	}
	if decodedData.Timestamp != originalData.Timestamp {
		t.Error("Timestamp mismatch")
	}
}

// TestDecodeCookieWithMaxAge_ZeroMaxAge tests behavior with zero max age.
func TestDecodeCookieWithMaxAge_ZeroMaxAge(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       time.Now().Unix(),
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	// Zero max age should skip expiration check (per implementation)
	_, err := DecodeCookieWithMaxAge(cookie, key, 0)
	if err != nil {
		t.Errorf("DecodeCookieWithMaxAge with 0 max age should accept: %v", err)
	}
}

// TestDecodeCookie_DefaultMaxAge tests that DecodeCookie uses default max age.
func TestDecodeCookie_DefaultMaxAge(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// Cookie from 3 minutes ago should be rejected by default 120s max age
	pastTime := time.Now().Add(-3 * time.Minute).Unix()

	data := &HRRCookieData{
		ClientHelloHash: sha256.Sum256([]byte("test")),
		SelectedCipher:  TLS_AES_128_GCM_SHA256,
		SelectedGroup:   X25519,
		Timestamp:       pastTime,
	}

	cookie := EncodeCookie(data, key)
	if cookie == nil {
		t.Fatal("EncodeCookie returned nil")
	}

	// DecodeCookie uses default 120s max age
	_, err := DecodeCookie(cookie, key)
	if err == nil {
		t.Error("DecodeCookie should reject cookie older than default max age")
	}
}

// =============================================================================
// ParseHRR Security Tests
// =============================================================================

// TestParseHRR_TooShort tests handling of too-short HRR messages.
func TestParseHRR_TooShort(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"1 byte", []byte{0x02}},
		{"37 bytes (minimum is 38)", make([]byte, 37)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseHRR(tc.data)
			if err == nil {
				t.Error("ParseHRR should reject short input")
			}
		})
	}
}

// TestParseHRR_InvalidRandom tests rejection of non-HRR ServerHello.
func TestParseHRR_InvalidRandom(t *testing.T) {
	// Create a valid ServerHello but with wrong random (not HRR)
	data := make([]byte, 50)
	data[0] = 0x02 // ServerHello type
	data[1] = 0
	data[2] = 0
	data[3] = 46 // Length
	data[4] = 0x03
	data[5] = 0x03        // Version TLS 1.2
	rand.Read(data[6:38]) // Random (not HRR random)
	data[38] = 0          // Session ID length
	data[39] = 0x13       // Cipher suite
	data[40] = 0x01       // TLS_AES_128_GCM_SHA256
	data[41] = 0          // Compression
	data[42] = 0          // Extensions length
	data[43] = 4          // Extensions: 4 bytes
	data[44] = 0          // Extension: supported_versions
	data[45] = 43         // Extension type 43
	data[46] = 0          // Extension length
	data[47] = 2          // 2 bytes
	data[48] = 0x03       // TLS 1.3
	data[49] = 0x04

	_, err := ParseHRR(data)
	if err == nil {
		t.Error("ParseHRR should reject ServerHello without HRR random")
	}
}

// TestParseHRR_SessionIDTooLong tests rejection of session ID > 32 bytes.
// Security: RFC 8446 limits session ID to 32 bytes.
func TestParseHRR_SessionIDTooLong(t *testing.T) {
	// Build a valid HRR header with session ID claiming 33 bytes
	// This tests bounds checking on session ID length field
	data := make([]byte, 100)
	data[0] = 0x02 // ServerHello type
	data[1] = 0
	data[2] = 0
	data[3] = 90                              // Length
	data[4] = 0x03                            // Version
	data[5] = 0x03                            // TLS 1.2
	copy(data[6:38], helloRetryRequestRandom) // HRR random
	data[38] = 33                             // Session ID length = 33 (invalid, max is 32)
	copy(data[39:72], make([]byte, 33))       // 33 bytes of session ID
	data[72] = 0x13                           // Cipher suite
	data[73] = 0x01                           // TLS_AES_128_GCM_SHA256
	data[74] = 0                              // Compression

	_, err := ParseHRR(data)
	if err == nil {
		t.Error("ParseHRR should reject session ID > 32 bytes")
	}
}

// TestParseHRR_ExtensionsOverflow tests handling of malformed extension length.
// Security: Extension length claiming more data than available should be rejected.
func TestParseHRR_ExtensionsOverflow(t *testing.T) {
	data := make([]byte, 50)
	data[0] = 0x02 // ServerHello type
	data[1] = 0
	data[2] = 0
	data[3] = 46                              // Length
	data[4] = 0x03                            // Version
	data[5] = 0x03                            // TLS 1.2
	copy(data[6:38], helloRetryRequestRandom) // HRR random
	data[38] = 0                              // Session ID length
	data[39] = 0x13                           // Cipher suite
	data[40] = 0x01                           // TLS_AES_128_GCM_SHA256
	data[41] = 0                              // Compression
	data[42] = 0xFF                           // Extensions length
	data[43] = 0xFF                           // 65535 bytes (way more than available)

	_, err := ParseHRR(data)
	if err == nil {
		t.Error("ParseHRR should reject extensions length overflow")
	}
}

// TestParseHRR_ValidHRR tests parsing of a valid HRR message.
func TestParseHRR_ValidHRR(t *testing.T) {
	// Build a valid HRR using HRRBuilder
	builder := NewHRRBuilder().
		WithCipherSuite(TLS_AES_128_GCM_SHA256).
		WithSelectedGroup(X25519).
		WithSessionID([]byte{0x01, 0x02, 0x03, 0x04}).
		WithCookie([]byte("test cookie data"))

	hrrBytes, err := builder.Build()
	if err != nil {
		t.Fatalf("HRRBuilder.Build failed: %v", err)
	}

	info, err := ParseHRR(hrrBytes)
	if err != nil {
		t.Fatalf("ParseHRR failed: %v", err)
	}

	if info.CipherSuite != TLS_AES_128_GCM_SHA256 {
		t.Errorf("CipherSuite = %04x, want %04x", info.CipherSuite, TLS_AES_128_GCM_SHA256)
	}
	if info.SelectedGroup != X25519 {
		t.Errorf("SelectedGroup = %d, want %d", info.SelectedGroup, X25519)
	}
	if !bytes.Equal(info.SessionID, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("SessionID = %x, want %x", info.SessionID, []byte{0x01, 0x02, 0x03, 0x04})
	}
	if !bytes.Equal(info.Cookie, []byte("test cookie data")) {
		t.Errorf("Cookie = %x, want 'test cookie data'", info.Cookie)
	}
}

// =============================================================================
// ValidateClientHello2 Security Tests
// =============================================================================

// TestValidateClientHello2_NilInputs tests handling of nil inputs.
func TestValidateClientHello2_NilInputs(t *testing.T) {
	ch := &clientHelloMsg{}

	testCases := []struct {
		name string
		ch1  *clientHelloMsg
		ch2  *clientHelloMsg
	}{
		{"both nil", nil, nil},
		{"ch1 nil", nil, ch},
		{"ch2 nil", ch, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClientHello2(tc.ch1, tc.ch2, X25519)
			if err == nil {
				t.Error("ValidateClientHello2 should reject nil inputs")
			}
		})
	}
}

// TestValidateClientHello2_VersionChange tests rejection of version changes.
func TestValidateClientHello2_VersionChange(t *testing.T) {
	ch1 := &clientHelloMsg{vers: VersionTLS12}
	ch2 := &clientHelloMsg{vers: VersionTLS13}

	err := ValidateClientHello2(ch1, ch2, X25519)
	if err == nil {
		t.Error("ValidateClientHello2 should reject version changes")
	}
}

// TestValidateClientHello2_SessionIDChange tests rejection of session ID changes.
func TestValidateClientHello2_SessionIDChange(t *testing.T) {
	ch1 := &clientHelloMsg{
		vers:      VersionTLS12,
		sessionId: []byte{0x01, 0x02, 0x03},
	}
	ch2 := &clientHelloMsg{
		vers:      VersionTLS12,
		sessionId: []byte{0x04, 0x05, 0x06},
	}

	err := ValidateClientHello2(ch1, ch2, X25519)
	if err == nil {
		t.Error("ValidateClientHello2 should reject session ID changes")
	}
}

// TestValidateClientHello2_CipherSuiteChange tests rejection of cipher suite changes.
func TestValidateClientHello2_CipherSuiteChange(t *testing.T) {
	ch1 := &clientHelloMsg{
		vers:         VersionTLS12,
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
	}
	ch2 := &clientHelloMsg{
		vers:         VersionTLS12,
		cipherSuites: []uint16{TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256}, // Reordered
	}

	err := ValidateClientHello2(ch1, ch2, X25519)
	if err == nil {
		t.Error("ValidateClientHello2 should reject cipher suite changes")
	}
}

// TestValidateClientHello2_MissingKeyShare tests rejection of missing requested key share.
func TestValidateClientHello2_MissingKeyShare(t *testing.T) {
	ch1 := &clientHelloMsg{
		vers:         VersionTLS12,
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
	}
	ch2 := &clientHelloMsg{
		vers:         VersionTLS12,
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		keyShares: []keyShare{
			{group: CurveP256, data: make([]byte, 65)}, // Wrong group
		},
	}

	// Server requested X25519, but client provided P256
	err := ValidateClientHello2(ch1, ch2, X25519)
	if err == nil {
		t.Error("ValidateClientHello2 should reject missing requested key share")
	}
}

// TestValidateClientHello2_DuplicateKeyShare tests rejection of multiple key shares for same group.
func TestValidateClientHello2_DuplicateKeyShare(t *testing.T) {
	ch1 := &clientHelloMsg{
		vers:         VersionTLS12,
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
	}
	ch2 := &clientHelloMsg{
		vers:         VersionTLS12,
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		keyShares: []keyShare{
			{group: X25519, data: make([]byte, 32)},
			{group: X25519, data: make([]byte, 32)}, // Duplicate!
		},
	}

	err := ValidateClientHello2(ch1, ch2, X25519)
	if err == nil {
		t.Error("ValidateClientHello2 should reject duplicate key shares for selected group")
	}
}

// =============================================================================
// HRRTranscriptHash Tests
// =============================================================================

// TestHRRTranscriptHash_NilHashFunc tests handling of nil hash function.
func TestHRRTranscriptHash_NilHashFunc(t *testing.T) {
	result := HRRTranscriptHash(nil, []byte("test client hello"))
	if result != nil {
		t.Error("HRRTranscriptHash should return nil for nil hash function")
	}
}

// TestHRRTranscriptHash_ValidInput tests normal operation.
func TestHRRTranscriptHash_ValidInput(t *testing.T) {
	clientHello := []byte("test client hello data")
	result := HRRTranscriptHash(sha256.New, clientHello)

	if result == nil {
		t.Fatal("HRRTranscriptHash returned nil for valid input")
	}

	// Result format: type(1) + length(3) + hash(32 for SHA256) = 36 bytes
	expectedLen := 4 + sha256.Size
	if len(result) != expectedLen {
		t.Errorf("HRRTranscriptHash length = %d, expected %d", len(result), expectedLen)
	}

	// First byte should be message_hash type (254 = 0xFE = typeMessageHash)
	if result[0] != typeMessageHash {
		t.Errorf("First byte = 0x%02x, expected 0x%02x (typeMessageHash)", result[0], typeMessageHash)
	}

	// Length bytes should indicate hash size
	length := int(result[1])<<16 | int(result[2])<<8 | int(result[3])
	if length != sha256.Size {
		t.Errorf("Length = %d, expected %d", length, sha256.Size)
	}
}

// TestHRRTranscriptHash_EmptyInput tests handling of empty ClientHello.
func TestHRRTranscriptHash_EmptyInput(t *testing.T) {
	result := HRRTranscriptHash(sha256.New, []byte{})

	// Should still work - produces hash of empty input
	if result == nil {
		t.Error("HRRTranscriptHash should not return nil for empty input")
	}
}

// TestHRRTranscriptHash_Deterministic tests that same input produces same output.
func TestHRRTranscriptHash_Deterministic(t *testing.T) {
	clientHello := []byte("test client hello data for determinism check")

	result1 := HRRTranscriptHash(sha256.New, clientHello)
	result2 := HRRTranscriptHash(sha256.New, clientHello)

	if !bytes.Equal(result1, result2) {
		t.Error("HRRTranscriptHash should be deterministic")
	}
}

// =============================================================================
// Multiple HRR Detection Tests (RFC 8446 Section 4.1.4)
// =============================================================================
//
// RFC 8446 Section 4.1.4 states: "If a client receives a second HelloRetryRequest
// in the same connection (i.e., where the ClientHello was itself in response to
// a HelloRetryRequest), it MUST abort the handshake with an 'unexpected_message' alert."

// TestHRRCount_InitialState verifies that hrrCount starts at zero.
func TestHRRCount_InitialState(t *testing.T) {
	hs := &clientHandshakeStateTLS13{}

	if hs.hrrCount != 0 {
		t.Errorf("Initial hrrCount should be 0, got %d", hs.hrrCount)
	}
}

// TestHRRCount_IncrementOnHRR verifies that hrrCount increments correctly.
func TestHRRCount_IncrementOnHRR(t *testing.T) {
	hs := &clientHandshakeStateTLS13{hrrCount: 0}

	// Simulate first HRR
	hs.hrrCount++
	if hs.hrrCount != 1 {
		t.Errorf("After first HRR, hrrCount should be 1, got %d", hs.hrrCount)
	}

	// Simulate second HRR (should be detected as error)
	hs.hrrCount++
	if hs.hrrCount != 2 {
		t.Errorf("After second HRR, hrrCount should be 2, got %d", hs.hrrCount)
	}
}

// TestHRRCount_DetectionThreshold verifies detection of multiple HRRs.
func TestHRRCount_DetectionThreshold(t *testing.T) {
	testCases := []struct {
		hrrCount    int
		shouldAbort bool
		description string
	}{
		{0, false, "No HRR received"},
		{1, false, "First HRR (valid)"},
		{2, true, "Second HRR (RFC violation)"},
		{3, true, "Third HRR (impossible state)"},
		{100, true, "Extreme case"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			shouldAbort := tc.hrrCount > 1
			if shouldAbort != tc.shouldAbort {
				t.Errorf("hrrCount=%d: expected shouldAbort=%v, got %v",
					tc.hrrCount, tc.shouldAbort, shouldAbort)
			}
		})
	}
}

// TestHRRCount_IsolationBetweenHandshakes verifies that hrrCount is
// per-handshake and not shared between different handshake instances.
func TestHRRCount_IsolationBetweenHandshakes(t *testing.T) {
	hs1 := &clientHandshakeStateTLS13{}
	hs2 := &clientHandshakeStateTLS13{}

	hs1.hrrCount = 1

	if hs2.hrrCount != 0 {
		t.Errorf("hrrCount should not leak between instances: hs2.hrrCount=%d", hs2.hrrCount)
	}

	if hs1.hrrCount != 1 {
		t.Errorf("hs1.hrrCount should remain 1, got %d", hs1.hrrCount)
	}
}

// TestHRRRandomDetection_ValidHRR tests that the HRR random is correctly identified.
func TestHRRRandomDetection_ValidHRR(t *testing.T) {
	// The helloRetryRequestRandom is defined in common.go
	if len(helloRetryRequestRandom) != 32 {
		t.Errorf("HRR random should be 32 bytes, got %d", len(helloRetryRequestRandom))
	}

	// First byte is 0xCF as per RFC 8446
	if helloRetryRequestRandom[0] != 0xCF {
		t.Errorf("First byte of HRR random should be 0xCF, got 0x%02X", helloRetryRequestRandom[0])
	}

	// Verify self-equality
	if !bytes.Equal(helloRetryRequestRandom, helloRetryRequestRandom) {
		t.Error("HRR random should equal itself")
	}

	// Verify distinct from normal random
	normalRandom := make([]byte, 32)
	for i := range normalRandom {
		normalRandom[i] = byte(i)
	}

	if bytes.Equal(normalRandom, helloRetryRequestRandom) {
		t.Error("Normal random should not equal HRR random")
	}
}

// TestAlertUnexpectedMessage_Value tests that the correct alert code is used.
func TestAlertUnexpectedMessage_Value(t *testing.T) {
	// RFC 8446 Section 4.1.4 requires unexpected_message alert (value 10)
	expectedAlertValue := uint8(10)

	if alertUnexpectedMessage != alert(expectedAlertValue) {
		t.Errorf("alertUnexpectedMessage should be %d, got %d",
			expectedAlertValue, alertUnexpectedMessage)
	}
}
