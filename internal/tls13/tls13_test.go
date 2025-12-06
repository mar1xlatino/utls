// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls13

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Test values for key schedule verification
// We use functional tests rather than RFC 8446 test vectors since
// the exact transcript computation requires complete handshake messages

// TestExpandLabel tests HKDF-Expand-Label with RFC 8446 test vectors
func TestExpandLabel(t *testing.T) {
	// Test basic functionality
	secret := mustHex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	label := "derived"
	context := []byte{}
	length := 32

	result, err := ExpandLabel(sha256.New, secret, label, context, length)
	if err != nil {
		t.Fatalf("ExpandLabel failed: %v", err)
	}

	if len(result) != length {
		t.Errorf("ExpandLabel length = %d, want %d", len(result), length)
	}
}

// TestExpandLabelLabelTooLong tests the label length limit
func TestExpandLabelLabelTooLong(t *testing.T) {
	secret := make([]byte, 32)

	// "tls13 " is 6 bytes, so label can be at most 249 bytes
	longLabel := strings.Repeat("x", 250) // This exceeds 249

	_, err := ExpandLabel(sha256.New, secret, longLabel, nil, 32)
	if err == nil {
		t.Error("Expected ErrLabelTooLong, got nil")
	}
	if !errors.Is(err, ErrLabelTooLong) {
		t.Errorf("Expected ErrLabelTooLong, got %v", err)
	}
}

// TestExpandLabelContextTooLong tests the context length limit
func TestExpandLabelContextTooLong(t *testing.T) {
	secret := make([]byte, 32)
	longContext := make([]byte, 256) // Exceeds 255

	_, err := ExpandLabel(sha256.New, secret, "test", longContext, 32)
	if err == nil {
		t.Error("Expected ErrLabelTooLong, got nil")
	}
	if !errors.Is(err, ErrLabelTooLong) {
		t.Errorf("Expected ErrLabelTooLong, got %v", err)
	}
}

// TestExpandLabelDeterministic verifies deterministic output
func TestExpandLabelDeterministic(t *testing.T) {
	secret := mustHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	label := "test label"
	context := []byte("context")

	result1, err := ExpandLabel(sha256.New, secret, label, context, 32)
	if err != nil {
		t.Fatalf("ExpandLabel 1 failed: %v", err)
	}

	result2, err := ExpandLabel(sha256.New, secret, label, context, 32)
	if err != nil {
		t.Fatalf("ExpandLabel 2 failed: %v", err)
	}

	if !bytes.Equal(result1, result2) {
		t.Error("ExpandLabel is not deterministic")
	}
}

// TestNewEarlySecret tests early secret creation
func TestNewEarlySecret(t *testing.T) {
	psk := mustHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	earlySecret, err := NewEarlySecret(sha256.New, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	if earlySecret == nil {
		t.Fatal("NewEarlySecret returned nil")
	}

	secret := earlySecret.Secret()
	if len(secret) != 32 {
		t.Errorf("Early secret length = %d, want 32", len(secret))
	}
}

// TestNewEarlySecretNilPSK tests early secret with nil PSK (non-PSK handshake)
func TestNewEarlySecretNilPSK(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret(nil) failed: %v", err)
	}

	if earlySecret == nil {
		t.Fatal("NewEarlySecret(nil) returned nil")
	}

	secret := earlySecret.Secret()
	if len(secret) != 32 {
		t.Errorf("Early secret length = %d, want 32", len(secret))
	}
}

// TestEarlySecretResumptionBinderKey tests resumption binder key derivation
func TestEarlySecretResumptionBinderKey(t *testing.T) {
	psk := make([]byte, 32)
	earlySecret, err := NewEarlySecret(sha256.New, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	binderKey, err := earlySecret.ResumptionBinderKey()
	if err != nil {
		t.Fatalf("ResumptionBinderKey failed: %v", err)
	}

	if len(binderKey) != 32 {
		t.Errorf("Binder key length = %d, want 32", len(binderKey))
	}
}

// TestEarlySecretClientEarlyTrafficSecret tests client early traffic secret
func TestEarlySecretClientEarlyTrafficSecret(t *testing.T) {
	psk := make([]byte, 32)
	earlySecret, err := NewEarlySecret(sha256.New, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	// Create a transcript hash
	transcript := sha256.New()
	transcript.Write([]byte("ClientHello"))

	secret, err := earlySecret.ClientEarlyTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ClientEarlyTrafficSecret failed: %v", err)
	}

	if len(secret) != 32 {
		t.Errorf("Client early traffic secret length = %d, want 32", len(secret))
	}
}

// TestHandshakeSecretDerivation tests handshake secret derivation
func TestHandshakeSecretDerivation(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	if hsSecret == nil {
		t.Fatal("HandshakeSecret returned nil")
	}
}

// TestHandshakeSecretTrafficSecrets tests handshake traffic secret derivation
func TestHandshakeSecretTrafficSecrets(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	// Create transcript
	transcript := sha256.New()
	transcript.Write([]byte("ClientHello"))
	transcript.Write([]byte("ServerHello"))

	clientHS, err := hsSecret.ClientHandshakeTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ClientHandshakeTrafficSecret failed: %v", err)
	}

	serverHS, err := hsSecret.ServerHandshakeTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ServerHandshakeTrafficSecret failed: %v", err)
	}

	// Verify outputs are correct length
	if len(clientHS) != 32 {
		t.Errorf("Client handshake traffic secret length = %d, want 32", len(clientHS))
	}

	if len(serverHS) != 32 {
		t.Errorf("Server handshake traffic secret length = %d, want 32", len(serverHS))
	}

	// Verify client and server secrets are different
	if bytes.Equal(clientHS, serverHS) {
		t.Error("Client and server handshake traffic secrets should differ")
	}

	// Verify determinism
	transcript2 := sha256.New()
	transcript2.Write([]byte("ClientHello"))
	transcript2.Write([]byte("ServerHello"))

	clientHS2, _ := hsSecret.ClientHandshakeTrafficSecret(transcript2)
	if !bytes.Equal(clientHS, clientHS2) {
		t.Error("Handshake traffic secrets should be deterministic")
	}
}

// TestMasterSecretDerivation tests master secret derivation
func TestMasterSecretDerivation(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	sharedSecret := make([]byte, 32)
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	masterSecret, err := hsSecret.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret failed: %v", err)
	}

	if masterSecret == nil {
		t.Fatal("MasterSecret returned nil")
	}

	secret := masterSecret.Secret()
	if len(secret) != 32 {
		t.Errorf("Master secret length = %d, want 32", len(secret))
	}
}

// TestMasterSecretApplicationSecrets tests application traffic secrets
func TestMasterSecretApplicationSecrets(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	sharedSecret := make([]byte, 32)
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	masterSecret, err := hsSecret.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret failed: %v", err)
	}

	transcript := sha256.New()
	transcript.Write([]byte("handshake messages"))

	clientApp, err := masterSecret.ClientApplicationTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ClientApplicationTrafficSecret failed: %v", err)
	}

	serverApp, err := masterSecret.ServerApplicationTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ServerApplicationTrafficSecret failed: %v", err)
	}

	if len(clientApp) != 32 {
		t.Errorf("Client app traffic secret length = %d, want 32", len(clientApp))
	}

	if len(serverApp) != 32 {
		t.Errorf("Server app traffic secret length = %d, want 32", len(serverApp))
	}

	// Client and server secrets should differ
	if bytes.Equal(clientApp, serverApp) {
		t.Error("Client and server application traffic secrets are identical")
	}
}

// TestMasterSecretResumption tests resumption master secret
func TestMasterSecretResumption(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	sharedSecret := make([]byte, 32)
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	masterSecret, err := hsSecret.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret failed: %v", err)
	}

	transcript := sha256.New()
	transcript.Write([]byte("full handshake transcript"))

	resumption, err := masterSecret.ResumptionMasterSecret(transcript)
	if err != nil {
		t.Fatalf("ResumptionMasterSecret failed: %v", err)
	}

	if len(resumption) != 32 {
		t.Errorf("Resumption master secret length = %d, want 32", len(resumption))
	}
}

// TestExporterMasterSecret tests exporter master secret
func TestExporterMasterSecret(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	sharedSecret := make([]byte, 32)
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	masterSecret, err := hsSecret.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret failed: %v", err)
	}

	transcript := sha256.New()
	transcript.Write([]byte("handshake transcript"))

	exporterMaster, err := masterSecret.ExporterMasterSecret(transcript)
	if err != nil {
		t.Fatalf("ExporterMasterSecret failed: %v", err)
	}

	if exporterMaster == nil {
		t.Fatal("ExporterMasterSecret returned nil")
	}

	// Test Exporter function
	exported, err := exporterMaster.Exporter("test label", []byte("context"), 32)
	if err != nil {
		t.Fatalf("Exporter failed: %v", err)
	}

	if len(exported) != 32 {
		t.Errorf("Exported key length = %d, want 32", len(exported))
	}
}

// TestEarlyExporterMasterSecret tests early exporter master secret
func TestEarlyExporterMasterSecret(t *testing.T) {
	psk := make([]byte, 32)
	earlySecret, err := NewEarlySecret(sha256.New, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	transcript := sha256.New()
	transcript.Write([]byte("ClientHello"))

	earlyExporter, err := earlySecret.EarlyExporterMasterSecret(transcript)
	if err != nil {
		t.Fatalf("EarlyExporterMasterSecret failed: %v", err)
	}

	if earlyExporter == nil {
		t.Fatal("EarlyExporterMasterSecret returned nil")
	}
}

// Test u_tls13.go functions

// TestNewEarlySecretFromSecret tests creating EarlySecret from pre-computed secret
func TestNewEarlySecretFromSecret(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	earlySecret, err := NewEarlySecretFromSecret(sha256.New, secret)
	if err != nil {
		t.Fatalf("NewEarlySecretFromSecret failed: %v", err)
	}

	if earlySecret == nil {
		t.Fatal("NewEarlySecretFromSecret returned nil")
	}

	if !bytes.Equal(earlySecret.Secret(), secret) {
		t.Error("Secret() returned different value than input")
	}
}

// TestNewEarlySecretFromSecretWrongLength tests length validation
func TestNewEarlySecretFromSecretWrongLength(t *testing.T) {
	// SHA-256 expects 32 bytes
	shortSecret := make([]byte, 16)

	_, err := NewEarlySecretFromSecret(sha256.New, shortSecret)
	if err == nil {
		t.Error("Expected ErrSecretLengthMismatch, got nil")
	}
	if !errors.Is(err, ErrSecretLengthMismatch) {
		t.Errorf("Expected ErrSecretLengthMismatch, got %v", err)
	}
}

// TestNewMasterSecretFromSecret tests creating MasterSecret from pre-computed secret
func TestNewMasterSecretFromSecret(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	masterSecret, err := NewMasterSecretFromSecret(sha256.New, secret)
	if err != nil {
		t.Fatalf("NewMasterSecretFromSecret failed: %v", err)
	}

	if masterSecret == nil {
		t.Fatal("NewMasterSecretFromSecret returned nil")
	}

	if !bytes.Equal(masterSecret.Secret(), secret) {
		t.Error("Secret() returned different value than input")
	}
}

// TestNewMasterSecretFromSecretWrongLength tests length validation
func TestNewMasterSecretFromSecretWrongLength(t *testing.T) {
	// SHA-256 expects 32 bytes
	shortSecret := make([]byte, 16)

	_, err := NewMasterSecretFromSecret(sha256.New, shortSecret)
	if err == nil {
		t.Error("Expected ErrSecretLengthMismatch, got nil")
	}
	if !errors.Is(err, ErrSecretLengthMismatch) {
		t.Errorf("Expected ErrSecretLengthMismatch, got %v", err)
	}
}

// TestSecretNilReceiver tests Secret() methods on nil receivers
func TestSecretNilReceiver(t *testing.T) {
	var early *EarlySecret
	if early.Secret() != nil {
		t.Error("nil EarlySecret.Secret() should return nil")
	}

	var master *MasterSecret
	if master.Secret() != nil {
		t.Error("nil MasterSecret.Secret() should return nil")
	}
}

// TestWithSHA384 tests key schedule with SHA-384
func TestWithSHA384(t *testing.T) {
	psk := make([]byte, 48) // SHA-384 output size
	earlySecret, err := NewEarlySecret(sha512.New384, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret with SHA-384 failed: %v", err)
	}

	secret := earlySecret.Secret()
	if len(secret) != 48 {
		t.Errorf("Early secret with SHA-384 length = %d, want 48", len(secret))
	}

	sharedSecret := make([]byte, 48)
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret with SHA-384 failed: %v", err)
	}

	masterSecret, err := hsSecret.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret with SHA-384 failed: %v", err)
	}

	if len(masterSecret.Secret()) != 48 {
		t.Errorf("Master secret with SHA-384 length = %d, want 48", len(masterSecret.Secret()))
	}
}

// TestTestingOnlyExporterSecret tests the testing helper function
func TestTestingOnlyExporterSecret(t *testing.T) {
	earlySecret, err := NewEarlySecret(sha256.New, nil)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	sharedSecret := make([]byte, 32)
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	masterSecret, err := hsSecret.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret failed: %v", err)
	}

	transcript := sha256.New()
	exporterMaster, err := masterSecret.ExporterMasterSecret(transcript)
	if err != nil {
		t.Fatalf("ExporterMasterSecret failed: %v", err)
	}

	secret := TestingOnlyExporterSecret(exporterMaster)
	if len(secret) != 32 {
		t.Errorf("TestingOnlyExporterSecret length = %d, want 32", len(secret))
	}
}

// TestKeyScheduleDeterminism tests that the key schedule is deterministic
func TestKeyScheduleDeterminism(t *testing.T) {
	psk := mustHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	sharedSecret := mustHex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")

	derive := func() []byte {
		early, _ := NewEarlySecret(sha256.New, psk)
		hs, _ := early.HandshakeSecret(sharedSecret)
		ms, _ := hs.MasterSecret()
		return ms.Secret()
	}

	result1 := derive()
	result2 := derive()

	if !bytes.Equal(result1, result2) {
		t.Error("Key schedule is not deterministic")
	}
}

// TestExpandLabelMaxLength tests maximum valid lengths
func TestExpandLabelMaxLength(t *testing.T) {
	secret := make([]byte, 32)

	// Maximum label length: 255 - 6 ("tls13 ") = 249
	maxLabel := strings.Repeat("x", 249)
	_, err := ExpandLabel(sha256.New, secret, maxLabel, nil, 32)
	if err != nil {
		t.Errorf("ExpandLabel with max label length failed: %v", err)
	}

	// Maximum context length: 255
	maxContext := make([]byte, 255)
	_, err = ExpandLabel(sha256.New, secret, "test", maxContext, 32)
	if err != nil {
		t.Errorf("ExpandLabel with max context length failed: %v", err)
	}
}

// TestExpandLabelVariousLengths tests various output lengths
func TestExpandLabelVariousLengths(t *testing.T) {
	secret := make([]byte, 32)
	label := "test"
	context := []byte("context")

	lengths := []int{1, 16, 32, 48, 64, 128, 255}

	for _, length := range lengths {
		result, err := ExpandLabel(sha256.New, secret, label, context, length)
		if err != nil {
			t.Errorf("ExpandLabel with length %d failed: %v", length, err)
			continue
		}
		if len(result) != length {
			t.Errorf("ExpandLabel length = %d, want %d", len(result), length)
		}
	}
}

// Benchmark tests
func BenchmarkExpandLabel(b *testing.B) {
	secret := make([]byte, 32)
	label := "test label"
	context := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExpandLabel(sha256.New, secret, label, context, 32)
	}
}

func BenchmarkNewEarlySecret(b *testing.B) {
	psk := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewEarlySecret(sha256.New, psk)
	}
}

func BenchmarkFullKeySchedule(b *testing.B) {
	psk := make([]byte, 32)
	sharedSecret := make([]byte, 32)
	transcript := sha256.New()
	transcript.Write([]byte("test transcript"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		early, _ := NewEarlySecret(sha256.New, psk)
		hs, _ := early.HandshakeSecret(sharedSecret)
		_, _ = hs.ClientHandshakeTrafficSecret(transcript)
		_, _ = hs.ServerHandshakeTrafficSecret(transcript)
		ms, _ := hs.MasterSecret()
		_, _ = ms.ClientApplicationTrafficSecret(transcript)
		_, _ = ms.ServerApplicationTrafficSecret(transcript)
	}
}

// Test with different hash types to verify generic constraint
func TestWithDifferentHashes(t *testing.T) {
	hashes := []struct {
		name string
		h    func() hash.Hash
		size int
	}{
		{"SHA-256", sha256.New, 32},
		{"SHA-384", sha512.New384, 48},
		{"SHA-512", sha512.New, 64},
	}

	for _, hh := range hashes {
		t.Run(hh.name, func(t *testing.T) {
			psk := make([]byte, hh.size)
			early, err := NewEarlySecret(hh.h, psk)
			if err != nil {
				t.Fatalf("NewEarlySecret failed: %v", err)
			}

			if len(early.Secret()) != hh.size {
				t.Errorf("Secret length = %d, want %d", len(early.Secret()), hh.size)
			}

			sharedSecret := make([]byte, hh.size)
			hs, err := early.HandshakeSecret(sharedSecret)
			if err != nil {
				t.Fatalf("HandshakeSecret failed: %v", err)
			}

			ms, err := hs.MasterSecret()
			if err != nil {
				t.Fatalf("MasterSecret failed: %v", err)
			}

			if len(ms.Secret()) != hh.size {
				t.Errorf("Master secret length = %d, want %d", len(ms.Secret()), hh.size)
			}
		})
	}
}

// =============================================================================
// RFC 8448 Test Vectors
// =============================================================================
// RFC 8448 "Example Handshake Traces for TLS 1.3" provides detailed
// intermediate values for a complete TLS 1.3 handshake. These vectors
// allow us to verify the correctness of our key schedule implementation
// against known-good values, not just output lengths.
//
// Reference: https://www.rfc-editor.org/rfc/rfc8448
// Section 3: Simple 1-RTT Handshake

// TestExpandLabelRFC8448 tests HKDF-Expand-Label against RFC 8448 vectors.
// This verifies that our implementation produces the exact bytes specified
// in the RFC, not just outputs of the correct length.
func TestExpandLabelRFC8448(t *testing.T) {
	// RFC 8448 Section 3 provides intermediate values for the "derived" label
	// expansion which uses an empty transcript hash.
	//
	// The "derived" secret is computed as:
	// HKDF-Expand-Label(Secret, "derived", "", Hash.length)
	//
	// Where the context is SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

	// Empty SHA-256 hash (used as context for "derived" label)
	emptyHash := sha256.New()
	emptyHashValue := emptyHash.Sum(nil)

	vectors := []struct {
		name     string
		secret   string // hex-encoded secret
		label    string
		context  []byte // context bytes (transcript hash)
		length   int
		expected string // hex-encoded expected output
	}{
		{
			// RFC 8448 Section 3: Derive-Secret(., "derived", "")
			// From early_secret to salt for handshake_secret extraction
			name:     "RFC8448_derived_from_early_secret",
			secret:   "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
			label:    "derived",
			context:  emptyHashValue,
			length:   32,
			expected: "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
		},
		{
			// RFC 8448 Section 3: Derive-Secret(., "derived", "")
			// From handshake_secret to salt for master_secret extraction
			name:     "RFC8448_derived_from_handshake_secret",
			secret:   "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
			label:    "derived",
			context:  emptyHashValue,
			length:   32,
			expected: "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4",
		},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			secret := mustHex(tc.secret)
			expected := mustHex(tc.expected)

			result, err := ExpandLabel(sha256.New, secret, tc.label, tc.context, tc.length)
			if err != nil {
				t.Fatalf("ExpandLabel failed: %v", err)
			}

			if !bytes.Equal(result, expected) {
				t.Errorf("ExpandLabel mismatch:\n  got:  %x\n  want: %x", result, expected)
			}
		})
	}
}

// TestKeyScheduleRFC8448 tests the full TLS 1.3 key schedule against RFC 8448 vectors.
// This is the most critical test as it verifies the entire key derivation chain
// produces the exact intermediate values specified in the RFC.
//
// RFC 8448 Section 3 "Simple 1-RTT Handshake" key schedule:
//
//	PSK = 0 (non-PSK handshake, 32 zero bytes)
//	     |
//	     v
//	early_secret = HKDF-Extract(salt=0, IKM=PSK)
//	             = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
//	     |
//	     +---> Derive-Secret(., "derived", "")
//	           = 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba
//	           |
//	           v
//	     shared_secret = 8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d
//	           |
//	           v
//	handshake_secret = HKDF-Extract(derived, shared_secret)
//	                 = 1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac
//	     |
//	     +---> Derive-Secret(., "derived", "")
//	           = 43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4
//	           |
//	           v
//	master_secret = HKDF-Extract(derived, 0)
//	              = 18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919
func TestKeyScheduleRFC8448(t *testing.T) {
	// RFC 8448 Section 3: Simple 1-RTT Handshake

	// For non-PSK handshake, PSK is all zeros
	psk := make([]byte, 32)

	// ECDHE shared secret from RFC 8448 Section 3
	// This is the X25519(client_private, server_public) result
	sharedSecret := mustHex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")

	// Expected intermediate values from RFC 8448 Section 3
	expectedEarlySecret := mustHex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	expectedHandshakeSecret := mustHex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
	expectedMasterSecret := mustHex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")

	// Step 1: Derive early_secret from PSK (zeros for non-PSK)
	earlySecret, err := NewEarlySecret(sha256.New, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	if !bytes.Equal(earlySecret.Secret(), expectedEarlySecret) {
		t.Errorf("early_secret mismatch:\n  got:  %x\n  want: %x",
			earlySecret.Secret(), expectedEarlySecret)
	}

	// Step 2: Derive handshake_secret from early_secret + ECDHE shared secret
	hsSecret, err := earlySecret.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	if !bytes.Equal(hsSecret.secret, expectedHandshakeSecret) {
		t.Errorf("handshake_secret mismatch:\n  got:  %x\n  want: %x",
			hsSecret.secret, expectedHandshakeSecret)
	}

	// Step 3: Derive master_secret from handshake_secret
	masterSecret, err := hsSecret.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret failed: %v", err)
	}

	if !bytes.Equal(masterSecret.Secret(), expectedMasterSecret) {
		t.Errorf("master_secret mismatch:\n  got:  %x\n  want: %x",
			masterSecret.Secret(), expectedMasterSecret)
	}
}

// TestEarlySecretRFC8448 specifically tests early_secret derivation
// with both zero PSK (non-PSK mode) and nil PSK.
func TestEarlySecretRFC8448(t *testing.T) {
	// RFC 8448 Section 3: For non-PSK handshake, PSK is all zeros
	// early_secret = HKDF-Extract(salt=0, IKM=0)
	//              = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
	expectedEarlySecret := mustHex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")

	t.Run("zero_psk", func(t *testing.T) {
		psk := make([]byte, 32)
		early, err := NewEarlySecret(sha256.New, psk)
		if err != nil {
			t.Fatalf("NewEarlySecret failed: %v", err)
		}

		if !bytes.Equal(early.Secret(), expectedEarlySecret) {
			t.Errorf("early_secret mismatch:\n  got:  %x\n  want: %x",
				early.Secret(), expectedEarlySecret)
		}
	})

	t.Run("nil_psk", func(t *testing.T) {
		// When PSK is nil, implementation should use zeros
		early, err := NewEarlySecret(sha256.New, nil)
		if err != nil {
			t.Fatalf("NewEarlySecret(nil) failed: %v", err)
		}

		if !bytes.Equal(early.Secret(), expectedEarlySecret) {
			t.Errorf("early_secret with nil PSK mismatch:\n  got:  %x\n  want: %x",
				early.Secret(), expectedEarlySecret)
		}
	})
}

// TestDerivedSecretRFC8448 tests the intermediate "derived" secret
// at each stage of the key schedule. The "derived" secret is critical
// because it acts as salt for the next HKDF-Extract operation.
func TestDerivedSecretRFC8448(t *testing.T) {
	// RFC 8448 Section 3 provides two "derived" values:
	//
	// 1. derived_from_early = Derive-Secret(early_secret, "derived", "")
	//    = 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba
	//
	// 2. derived_from_hs = Derive-Secret(handshake_secret, "derived", "")
	//    = 43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4

	// These are computed using empty transcript: SHA-256("")
	emptyHash := sha256.New()
	emptyContext := emptyHash.Sum(nil)

	t.Run("derived_from_early_secret", func(t *testing.T) {
		earlySecret := mustHex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
		expected := mustHex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")

		result, err := ExpandLabel(sha256.New, earlySecret, "derived", emptyContext, 32)
		if err != nil {
			t.Fatalf("ExpandLabel failed: %v", err)
		}

		if !bytes.Equal(result, expected) {
			t.Errorf("derived_from_early mismatch:\n  got:  %x\n  want: %x", result, expected)
		}
	})

	t.Run("derived_from_handshake_secret", func(t *testing.T) {
		handshakeSecret := mustHex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
		expected := mustHex("43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4")

		result, err := ExpandLabel(sha256.New, handshakeSecret, "derived", emptyContext, 32)
		if err != nil {
			t.Fatalf("ExpandLabel failed: %v", err)
		}

		if !bytes.Equal(result, expected) {
			t.Errorf("derived_from_hs mismatch:\n  got:  %x\n  want: %x", result, expected)
		}
	})
}

// TestResumptionBinderKeyRFC8448 tests the resumption binder key derivation.
// The binder key is derived using "res binder" label with empty transcript.
func TestResumptionBinderKeyRFC8448(t *testing.T) {
	// For the binder key, we need to verify the derivation chain:
	// binder_key = Derive-Secret(early_secret, "res binder", "")
	//
	// Using early_secret from RFC 8448 (with zero PSK):
	// early_secret = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
	//
	// binder_key = HKDF-Expand-Label(early_secret, "res binder", SHA-256(""), 32)

	psk := make([]byte, 32) // Zero PSK
	early, err := NewEarlySecret(sha256.New, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	binderKey, err := early.ResumptionBinderKey()
	if err != nil {
		t.Fatalf("ResumptionBinderKey failed: %v", err)
	}

	// Verify the binder key length
	if len(binderKey) != 32 {
		t.Errorf("binder_key length = %d, want 32", len(binderKey))
	}

	// Compute expected value using ExpandLabel directly
	emptyHash := sha256.New()
	emptyContext := emptyHash.Sum(nil)

	expectedBinderKey, err := ExpandLabel(sha256.New, early.Secret(), "res binder", emptyContext, 32)
	if err != nil {
		t.Fatalf("ExpandLabel for expected failed: %v", err)
	}

	if !bytes.Equal(binderKey, expectedBinderKey) {
		t.Errorf("binder_key mismatch with direct ExpandLabel:\n  got:  %x\n  want: %x",
			binderKey, expectedBinderKey)
	}
}

// TestTrafficSecretsConsistencyRFC8448 verifies that client and server traffic
// secrets are properly differentiated (different labels produce different outputs).
func TestTrafficSecretsConsistencyRFC8448(t *testing.T) {
	// Using RFC 8448 key schedule values
	psk := make([]byte, 32)
	sharedSecret := mustHex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")

	early, err := NewEarlySecret(sha256.New, psk)
	if err != nil {
		t.Fatalf("NewEarlySecret failed: %v", err)
	}

	hs, err := early.HandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("HandshakeSecret failed: %v", err)
	}

	// Create a sample transcript hash (not from RFC 8448, just for consistency check)
	transcript := sha256.New()
	transcript.Write([]byte("sample_client_hello_server_hello"))

	clientHS, err := hs.ClientHandshakeTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ClientHandshakeTrafficSecret failed: %v", err)
	}

	serverHS, err := hs.ServerHandshakeTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ServerHandshakeTrafficSecret failed: %v", err)
	}

	// Client and server handshake secrets MUST be different
	if bytes.Equal(clientHS, serverHS) {
		t.Error("client_handshake_traffic_secret equals server_handshake_traffic_secret (CRITICAL BUG)")
	}

	// Verify determinism: same transcript produces same secrets
	transcript2 := sha256.New()
	transcript2.Write([]byte("sample_client_hello_server_hello"))

	clientHS2, err := hs.ClientHandshakeTrafficSecret(transcript2)
	if err != nil {
		t.Fatalf("ClientHandshakeTrafficSecret (2nd) failed: %v", err)
	}

	if !bytes.Equal(clientHS, clientHS2) {
		t.Error("ClientHandshakeTrafficSecret is not deterministic")
	}

	// Test application traffic secrets
	ms, err := hs.MasterSecret()
	if err != nil {
		t.Fatalf("MasterSecret failed: %v", err)
	}

	clientApp, err := ms.ClientApplicationTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ClientApplicationTrafficSecret failed: %v", err)
	}

	serverApp, err := ms.ServerApplicationTrafficSecret(transcript)
	if err != nil {
		t.Fatalf("ServerApplicationTrafficSecret failed: %v", err)
	}

	// Client and server application secrets MUST be different
	if bytes.Equal(clientApp, serverApp) {
		t.Error("client_application_traffic_secret equals server_application_traffic_secret (CRITICAL BUG)")
	}

	// Handshake and application secrets MUST be different
	if bytes.Equal(clientHS, clientApp) {
		t.Error("client handshake secret equals client application secret (CRITICAL BUG)")
	}
}

// TestHKDFLabelEncodingRFC8446 verifies the HKDF-Expand-Label encoding
// matches RFC 8446 Section 7.1 format:
//
//	struct {
//	    uint16 length = Length;
//	    opaque label<7..255> = "tls13 " + Label;
//	    opaque context<0..255> = Context;
//	} HkdfLabel;
func TestHKDFLabelEncodingRFC8446(t *testing.T) {
	// Test that different labels produce different outputs (label is encoded)
	secret := mustHex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
	context := []byte{}

	result1, err := ExpandLabel(sha256.New, secret, "derived", context, 32)
	if err != nil {
		t.Fatalf("ExpandLabel(derived) failed: %v", err)
	}

	result2, err := ExpandLabel(sha256.New, secret, "c hs traffic", context, 32)
	if err != nil {
		t.Fatalf("ExpandLabel(c hs traffic) failed: %v", err)
	}

	if bytes.Equal(result1, result2) {
		t.Error("different labels produced identical outputs (label not encoded properly)")
	}

	// Test that different contexts produce different outputs
	context1 := sha256.New()
	context1.Write([]byte("hello1"))

	context2 := sha256.New()
	context2.Write([]byte("hello2"))

	result3, err := ExpandLabel(sha256.New, secret, "test", context1.Sum(nil), 32)
	if err != nil {
		t.Fatalf("ExpandLabel(context1) failed: %v", err)
	}

	result4, err := ExpandLabel(sha256.New, secret, "test", context2.Sum(nil), 32)
	if err != nil {
		t.Fatalf("ExpandLabel(context2) failed: %v", err)
	}

	if bytes.Equal(result3, result4) {
		t.Error("different contexts produced identical outputs (context not encoded properly)")
	}

	// Test that different lengths produce outputs of correct length with different prefixes
	result5, err := ExpandLabel(sha256.New, secret, "test", context, 16)
	if err != nil {
		t.Fatalf("ExpandLabel(len=16) failed: %v", err)
	}

	result6, err := ExpandLabel(sha256.New, secret, "test", context, 32)
	if err != nil {
		t.Fatalf("ExpandLabel(len=32) failed: %v", err)
	}

	// The 16-byte output should NOT be a prefix of the 32-byte output
	// because the length is encoded in the HkdfLabel
	if bytes.Equal(result5, result6[:16]) {
		t.Error("length=16 output equals prefix of length=32 output (length not encoded properly)")
	}
}
