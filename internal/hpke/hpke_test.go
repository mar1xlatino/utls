// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestDeterministicKeyGeneration tests that using a fixed ephemeral key produces
// consistent results and that sender/recipient derive the same keys.
// NOTE: This test modifies testingOnlyGenerateKey global, so it cannot run in parallel.
func TestDeterministicKeyGeneration(t *testing.T) {

	// Fixed test keys
	skRm := mustHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
	skEm := mustHex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")

	// Parse recipient key
	recipientPriv, err := ParseHPKEPrivateKey(DHKEM_X25519_HKDF_SHA256, skRm)
	if err != nil {
		t.Fatalf("ParseHPKEPrivateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	// Set up test key generator for deterministic ephemeral key
	ephPriv, err := ecdh.X25519().NewPrivateKey(skEm)
	if err != nil {
		t.Fatalf("NewPrivateKey failed: %v", err)
	}
	testingOnlyGenerateKey = func() (*ecdh.PrivateKey, error) {
		return ephPriv, nil
	}
	defer func() { testingOnlyGenerateKey = nil }()

	info := []byte("test info")

	// Setup sender
	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Verify encapsulated key is the ephemeral public key
	expectedEnc := ephPriv.PublicKey().Bytes()
	if !bytes.Equal(enc, expectedEnc) {
		t.Errorf("enc mismatch:\n  got:  %x\n  want: %x", enc, expectedEnc)
	}

	// Setup recipient should derive the same keys
	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Verify sender and recipient derived the same key
	if !bytes.Equal(sender.key, recipient.key) {
		t.Errorf("key mismatch: sender=%x, recipient=%x", sender.key, recipient.key)
	}

	// Verify sender and recipient have the same base nonce
	if !bytes.Equal(sender.baseNonce, recipient.baseNonce) {
		t.Errorf("baseNonce mismatch: sender=%x, recipient=%x", sender.baseNonce, recipient.baseNonce)
	}

	// Verify key and nonce have correct lengths for AES-128-GCM
	if len(sender.key) != 16 {
		t.Errorf("key length = %d, want 16", len(sender.key))
	}
	if len(sender.baseNonce) != 12 {
		t.Errorf("baseNonce length = %d, want 12", len(sender.baseNonce))
	}
}

// Test encryption/decryption round-trip
func TestSealOpen(t *testing.T) {
	t.Parallel()

	// Generate a random recipient key pair
	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	info := []byte("test info")

	// Setup sender
	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Setup recipient
	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Test multiple messages
	messages := []struct {
		aad       []byte
		plaintext []byte
	}{
		{[]byte("aad1"), []byte("first message")},
		{[]byte("aad2"), []byte("second message with more content")},
		{nil, []byte("message with no aad")},
		{[]byte("aad4"), nil}, // empty plaintext
	}

	for i, msg := range messages {
		ciphertext, err := sender.Seal(msg.aad, msg.plaintext)
		if err != nil {
			t.Fatalf("Seal message %d failed: %v", i, err)
		}

		plaintext, err := recipient.Open(msg.aad, ciphertext)
		if err != nil {
			t.Fatalf("Open message %d failed: %v", i, err)
		}

		if !bytes.Equal(plaintext, msg.plaintext) {
			t.Errorf("Message %d mismatch:\n  got:  %s\n  want: %s", i, plaintext, msg.plaintext)
		}
	}
}

// Test with different AEAD algorithms
func TestDifferentAEADs(t *testing.T) {
	t.Parallel()

	aeads := []struct {
		name   string
		aeadID uint16
	}{
		{"AES-128-GCM", AEAD_AES_128_GCM},
		{"AES-256-GCM", AEAD_AES_256_GCM},
		{"ChaCha20-Poly1305", AEAD_ChaCha20Poly1305},
	}

	for _, aead := range aeads {
		t.Run(aead.name, func(t *testing.T) {
			t.Parallel()

			recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			recipientPub := recipientPriv.PublicKey()

			info := []byte("test info for " + aead.name)

			enc, sender, err := SetupSender(
				DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				aead.aeadID,
				recipientPub,
				info,
			)
			if err != nil {
				t.Fatalf("SetupSender failed: %v", err)
			}

			recipient, err := SetupRecipient(
				DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				aead.aeadID,
				recipientPriv,
				info,
				enc,
			)
			if err != nil {
				t.Fatalf("SetupRecipient failed: %v", err)
			}

			plaintext := []byte("Hello, HPKE!")
			aadData := []byte("additional authenticated data")

			ciphertext, err := sender.Seal(aadData, plaintext)
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}

			decrypted, err := recipient.Open(aadData, ciphertext)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decryption mismatch:\n  got:  %s\n  want: %s", decrypted, plaintext)
			}
		})
	}
}

// TestAuthenticationFailures tests authentication failures with wrong AAD and modified ciphertext
func TestAuthenticationFailures(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	info := []byte("test info")

	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	t.Run("WrongAAD", func(t *testing.T) {
		plaintext := []byte("secret message")
		aad := []byte("correct aad")

		ciphertext, err := sender.Seal(aad, plaintext)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		// Try to open with wrong AAD
		_, err = recipient.Open([]byte("wrong aad"), ciphertext)
		if err == nil {
			t.Error("Expected error when opening with wrong AAD, got nil")
		}
	})

	t.Run("ModifiedCiphertext", func(t *testing.T) {
		plaintext := []byte("secret message")
		aad := []byte("aad")

		ciphertext, err := sender.Seal(aad, plaintext)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		// Modify ciphertext
		modified := make([]byte, len(ciphertext))
		copy(modified, ciphertext)
		modified[0] ^= 0xff

		_, err = recipient.Open(aad, modified)
		if err == nil {
			t.Error("Expected error when opening modified ciphertext, got nil")
		}
	})
}

// TestUnsupportedIDs tests error handling for unsupported KEM/KDF/AEAD IDs
func TestUnsupportedIDs(t *testing.T) {
	t.Parallel()

	t.Run("UnsupportedKEM", func(t *testing.T) {
		t.Parallel()
		key := make([]byte, 32)
		_, err := ParseHPKEPublicKey(0xFFFF, key)
		if err == nil {
			t.Error("Expected error for unsupported KEM ID")
		}

		_, err = ParseHPKEPrivateKey(0xFFFF, key)
		if err == nil {
			t.Error("Expected error for unsupported KEM ID")
		}
	})

	t.Run("UnsupportedKDF", func(t *testing.T) {
		t.Parallel()
		recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		recipientPub := recipientPriv.PublicKey()

		_, _, err = SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			0xFFFF, // Invalid KDF ID
			AEAD_AES_128_GCM,
			recipientPub,
			nil,
		)
		if err == nil {
			t.Error("Expected error for unsupported KDF ID")
		}
	})

	t.Run("UnsupportedAEAD", func(t *testing.T) {
		t.Parallel()
		recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		recipientPub := recipientPriv.PublicKey()

		_, _, err = SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			0xFFFE, // Invalid AEAD ID (0xFFFF is now valid Export-only mode)
			recipientPub,
			nil,
		)
		if err == nil {
			t.Error("Expected error for unsupported AEAD ID")
		}
	})
}

// TestExportOnlyMode tests the Export-only AEAD mode (0xFFFF) per RFC 9180 Section 7.3
func TestExportOnlyMode(t *testing.T) {
	t.Parallel()

	t.Run("SetupSucceeds", func(t *testing.T) {
		t.Parallel()
		recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		recipientPub := recipientPriv.PublicKey()

		enc, sender, err := SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPub,
			[]byte("test info"),
		)
		if err != nil {
			t.Fatalf("SetupSender with Export-only failed: %v", err)
		}
		if enc == nil {
			t.Error("Encapsulated key should not be nil")
		}
		if sender == nil {
			t.Error("Sender should not be nil")
		}
		if !sender.IsExportOnly() {
			t.Error("Sender should report IsExportOnly() = true")
		}

		recipient, err := SetupRecipient(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPriv,
			[]byte("test info"),
			enc,
		)
		if err != nil {
			t.Fatalf("SetupRecipient with Export-only failed: %v", err)
		}
		if recipient == nil {
			t.Error("Recipient should not be nil")
		}
		if !recipient.IsExportOnly() {
			t.Error("Recipient should report IsExportOnly() = true")
		}
	})

	t.Run("SealFails", func(t *testing.T) {
		t.Parallel()
		recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		recipientPub := recipientPriv.PublicKey()

		_, sender, err := SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPub,
			nil,
		)
		if err != nil {
			t.Fatalf("SetupSender failed: %v", err)
		}

		_, err = sender.Seal([]byte("aad"), []byte("plaintext"))
		if err != ErrExportOnlyMode {
			t.Errorf("Seal should return ErrExportOnlyMode, got: %v", err)
		}
	})

	t.Run("OpenFails", func(t *testing.T) {
		t.Parallel()
		recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		enc, _, err := SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPriv.PublicKey(),
			nil,
		)
		if err != nil {
			t.Fatalf("SetupSender failed: %v", err)
		}

		recipient, err := SetupRecipient(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPriv,
			nil,
			enc,
		)
		if err != nil {
			t.Fatalf("SetupRecipient failed: %v", err)
		}

		_, err = recipient.Open([]byte("aad"), []byte("ciphertext"))
		if err != ErrExportOnlyMode {
			t.Errorf("Open should return ErrExportOnlyMode, got: %v", err)
		}
	})

	t.Run("ExportWorks", func(t *testing.T) {
		t.Parallel()
		recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		recipientPub := recipientPriv.PublicKey()

		info := []byte("test info")
		exporterContext := []byte("exporter context")

		enc, sender, err := SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPub,
			info,
		)
		if err != nil {
			t.Fatalf("SetupSender failed: %v", err)
		}

		recipient, err := SetupRecipient(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPriv,
			info,
			enc,
		)
		if err != nil {
			t.Fatalf("SetupRecipient failed: %v", err)
		}

		// Export secrets of various lengths
		for _, length := range []uint16{16, 32, 64, 128} {
			senderSecret, err := sender.Export(exporterContext, length)
			if err != nil {
				t.Fatalf("Sender Export(%d) failed: %v", length, err)
			}
			if len(senderSecret) != int(length) {
				t.Errorf("Sender Export length = %d, want %d", len(senderSecret), length)
			}

			recipientSecret, err := recipient.Export(exporterContext, length)
			if err != nil {
				t.Fatalf("Recipient Export(%d) failed: %v", length, err)
			}
			if len(recipientSecret) != int(length) {
				t.Errorf("Recipient Export length = %d, want %d", len(recipientSecret), length)
			}

			// Sender and recipient should derive the same secret
			if !bytes.Equal(senderSecret, recipientSecret) {
				t.Errorf("Export secrets mismatch for length %d:\n  sender:    %x\n  recipient: %x",
					length, senderSecret, recipientSecret)
			}
		}

		// Different contexts should produce different secrets
		ctx1, _ := sender.Export([]byte("context1"), 32)
		ctx2, _ := sender.Export([]byte("context2"), 32)
		if bytes.Equal(ctx1, ctx2) {
			t.Error("Different export contexts should produce different secrets")
		}
	})

	t.Run("OverheadIsZero", func(t *testing.T) {
		t.Parallel()
		recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}

		enc, sender, err := SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPriv.PublicKey(),
			nil,
		)
		if err != nil {
			t.Fatalf("SetupSender failed: %v", err)
		}

		recipient, err := SetupRecipient(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_EXPORT_ONLY,
			recipientPriv,
			nil,
			enc,
		)
		if err != nil {
			t.Fatalf("SetupRecipient failed: %v", err)
		}

		if sender.Overhead() != 0 {
			t.Errorf("Sender Overhead() = %d, want 0 for export-only mode", sender.Overhead())
		}
		if recipient.Overhead() != 0 {
			t.Errorf("Recipient Overhead() = %d, want 0 for export-only mode", recipient.Overhead())
		}
	})

	t.Run("DifferentKEMs", func(t *testing.T) {
		t.Parallel()

		kems := []struct {
			name  string
			kemID uint16
			kdfID uint16
			curve ecdh.Curve
		}{
			{"X25519", DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, ecdh.X25519()},
			{"P-256", DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, ecdh.P256()},
			{"P-384", DHKEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, ecdh.P384()},
		}

		for _, kem := range kems {
			t.Run(kem.name, func(t *testing.T) {
				t.Parallel()

				recipientPriv, err := kem.curve.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey failed: %v", err)
				}

				enc, sender, err := SetupSender(
					kem.kemID,
					kem.kdfID,
					AEAD_EXPORT_ONLY,
					recipientPriv.PublicKey(),
					[]byte("test"),
				)
				if err != nil {
					t.Fatalf("SetupSender failed: %v", err)
				}

				recipient, err := SetupRecipient(
					kem.kemID,
					kem.kdfID,
					AEAD_EXPORT_ONLY,
					recipientPriv,
					[]byte("test"),
					enc,
				)
				if err != nil {
					t.Fatalf("SetupRecipient failed: %v", err)
				}

				// Verify Export works
				senderSecret, err := sender.Export([]byte("ctx"), 32)
				if err != nil {
					t.Fatalf("Sender Export failed: %v", err)
				}
				recipientSecret, err := recipient.Export([]byte("ctx"), 32)
				if err != nil {
					t.Fatalf("Recipient Export failed: %v", err)
				}
				if !bytes.Equal(senderSecret, recipientSecret) {
					t.Error("Sender and recipient should derive same secret")
				}

				// Verify Seal fails
				_, err = sender.Seal(nil, []byte("test"))
				if err != ErrExportOnlyMode {
					t.Errorf("Seal should fail with ErrExportOnlyMode")
				}
			})
		}
	})
}

// TestExportFunction tests the Export function with regular AEAD modes
func TestExportFunction(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM, // Regular AEAD mode
		recipientPub,
		[]byte("test info"),
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		[]byte("test info"),
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Test that Export works even with regular AEAD
	exporterContext := []byte("exporter context")
	senderSecret, err := sender.Export(exporterContext, 32)
	if err != nil {
		t.Fatalf("Sender Export failed: %v", err)
	}
	recipientSecret, err := recipient.Export(exporterContext, 32)
	if err != nil {
		t.Fatalf("Recipient Export failed: %v", err)
	}
	if !bytes.Equal(senderSecret, recipientSecret) {
		t.Error("Export secrets should match between sender and recipient")
	}

	// Test that Seal/Open still work (not export-only mode)
	if sender.IsExportOnly() {
		t.Error("Regular AEAD sender should not be export-only")
	}
	plaintext := []byte("hello world")
	ciphertext, err := sender.Seal(nil, plaintext)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	decrypted, err := recipient.Open(nil, ciphertext)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted plaintext mismatch")
	}
}

// TestUint128Operations tests uint128 arithmetic
func TestUint128Operations(t *testing.T) {
	t.Parallel()

	t.Run("AddOne", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name   string
			input  uint128
			expect uint128
		}{
			{"zero", uint128{0, 0}, uint128{0, 1}},
			{"one", uint128{0, 1}, uint128{0, 2}},
			{"carry", uint128{0, ^uint64(0)}, uint128{1, 0}},
			{"max lo", uint128{1, ^uint64(0)}, uint128{2, 0}},
			{"large", uint128{100, 200}, uint128{100, 201}},
		}

		for _, tt := range tests {
			result := tt.input.addOne()
			if result != tt.expect {
				t.Errorf("%s: addOne() = {%d, %d}, want {%d, %d}",
					tt.name, result.hi, result.lo, tt.expect.hi, tt.expect.lo)
			}
		}
	})

	t.Run("BitLen", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name   string
			input  uint128
			expect int
		}{
			{"zero", uint128{0, 0}, 0},
			{"one", uint128{0, 1}, 1},
			{"two", uint128{0, 2}, 2},
			{"255", uint128{0, 255}, 8},
			{"256", uint128{0, 256}, 9},
			{"max lo", uint128{0, ^uint64(0)}, 64},
			{"hi=1", uint128{1, 0}, 65},
			{"hi=2", uint128{2, 0}, 66},
			{"hi=255", uint128{255, 0}, 72},
			{"hi max", uint128{^uint64(0), ^uint64(0)}, 128},
		}

		for _, tt := range tests {
			result := tt.input.bitLen()
			if result != tt.expect {
				t.Errorf("%s: bitLen() = %d, want %d", tt.name, result, tt.expect)
			}
		}
	})

	t.Run("Bytes", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name   string
			input  uint128
			expect []byte
		}{
			{"zero", uint128{0, 0}, make([]byte, 16)},
			{"one", uint128{0, 1}, append(make([]byte, 15), 1)},
			{"hi=1", uint128{1, 0}, append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, make([]byte, 8)...)},
		}

		for _, tt := range tests {
			result := tt.input.bytes()
			if !bytes.Equal(result, tt.expect) {
				t.Errorf("%s: bytes() = %x, want %x", tt.name, result, tt.expect)
			}
		}
	})
}

// TestOverhead tests that Overhead returns correct tag size
func TestOverhead(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		nil,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		nil,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// AES-GCM has 16-byte tag
	if sender.Overhead() != 16 {
		t.Errorf("Sender Overhead() = %d, want 16", sender.Overhead())
	}

	if recipient.Overhead() != 16 {
		t.Errorf("Recipient Overhead() = %d, want 16", recipient.Overhead())
	}
}

// TestNonceSequence tests nonce increment behavior
// In -short mode, only 10 messages are tested instead of 100.
func TestNonceSequence(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		nil,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		nil,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Send multiple messages to exercise nonce increment
	numMessages := 100
	if testing.Short() {
		numMessages = 10
	}

	for i := 0; i < numMessages; i++ {
		plaintext := []byte("message")
		ciphertext, err := sender.Seal(nil, plaintext)
		if err != nil {
			t.Fatalf("Seal message %d failed: %v", i, err)
		}

		decrypted, err := recipient.Open(nil, ciphertext)
		if err != nil {
			t.Fatalf("Open message %d failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Message %d mismatch", i)
		}
	}
}

// TestDecapInvalidKey tests invalid encapsulated key handling
func TestDecapInvalidKey(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	info := []byte("test info")

	t.Run("TooShort", func(t *testing.T) {
		t.Parallel()
		_, err := SetupRecipient(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPriv,
			info,
			[]byte("short"),
		)
		if err == nil {
			t.Error("Expected error for short encapsulated key")
		}
	})

	t.Run("LowOrderPoint", func(t *testing.T) {
		t.Parallel()
		_, err := SetupRecipient(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPriv,
			info,
			make([]byte, 32), // all zeros - low order point
		)
		if err == nil {
			t.Error("Expected error for low-order point encapsulated key")
		}
	})
}

// TestRFC9180BaseMode tests against RFC 9180 Appendix A.1 test vectors
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (Base Mode)
// NOTE: This test modifies testingOnlyGenerateKey global, so it cannot run in parallel.
func TestRFC9180BaseMode(t *testing.T) {

	// RFC 9180 A.1 Base Setup Information
	skEm := mustHex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
	skRm := mustHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
	pkRm := mustHex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
	info := mustHex("4f6465206f6e2061204772656369616e2055726e") // "Ode on a Grecian Urn"

	// Expected outputs from RFC 9180 A.1
	expectedEnc := mustHex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431")
	expectedKey := mustHex("4531685d41d65f03dc48f6b8302c05b0")
	expectedBaseNonce := mustHex("56d890e5accaaf011cff4b7d")

	// Set up deterministic ephemeral key from skEm
	ephPriv, err := ecdh.X25519().NewPrivateKey(skEm)
	if err != nil {
		t.Fatalf("NewPrivateKey(skEm) failed: %v", err)
	}
	testingOnlyGenerateKey = func() (*ecdh.PrivateKey, error) {
		return ephPriv, nil
	}
	defer func() { testingOnlyGenerateKey = nil }()

	// Parse recipient public key
	recipientPub, err := ParseHPKEPublicKey(DHKEM_X25519_HKDF_SHA256, pkRm)
	if err != nil {
		t.Fatalf("ParseHPKEPublicKey failed: %v", err)
	}

	// Setup sender
	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Verify encapsulated key matches RFC expected value
	if !bytes.Equal(enc, expectedEnc) {
		t.Errorf("enc mismatch:\n  got:  %x\n  want: %x", enc, expectedEnc)
	}

	// Verify derived key matches RFC expected value
	if !bytes.Equal(sender.key, expectedKey) {
		t.Errorf("key mismatch:\n  got:  %x\n  want: %x", sender.key, expectedKey)
	}

	// Verify base nonce matches RFC expected value
	if !bytes.Equal(sender.baseNonce, expectedBaseNonce) {
		t.Errorf("baseNonce mismatch:\n  got:  %x\n  want: %x", sender.baseNonce, expectedBaseNonce)
	}

	// Also verify recipient derives the same keys
	recipientPriv, err := ParseHPKEPrivateKey(DHKEM_X25519_HKDF_SHA256, skRm)
	if err != nil {
		t.Fatalf("ParseHPKEPrivateKey failed: %v", err)
	}

	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Verify recipient derives same key
	if !bytes.Equal(recipient.key, expectedKey) {
		t.Errorf("recipient key mismatch:\n  got:  %x\n  want: %x", recipient.key, expectedKey)
	}

	// Verify recipient derives same base nonce
	if !bytes.Equal(recipient.baseNonce, expectedBaseNonce) {
		t.Errorf("recipient baseNonce mismatch:\n  got:  %x\n  want: %x", recipient.baseNonce, expectedBaseNonce)
	}
}

// TestRFC9180Encryption tests encryption vectors from RFC 9180 A.1
// In -short mode, only the first vector is tested.
// NOTE: This test modifies testingOnlyGenerateKey global, so it cannot run in parallel.
func TestRFC9180Encryption(t *testing.T) {

	vectors := []struct {
		name       string
		seqNum     int
		aad        string // hex
		plaintext  string // hex
		ciphertext string // hex
	}{
		{
			name:       "sequence_0",
			seqNum:     0,
			aad:        "436f756e742d30",                                                   // "Count-0"
			plaintext:  "4265617574792069732074727574682c20747275746820626561757479",       // "Beauty is truth, truth beauty"
			ciphertext: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
		},
		{
			name:       "sequence_1",
			seqNum:     1,
			aad:        "436f756e742d31",
			plaintext:  "4265617574792069732074727574682c20747275746820626561757479",
			ciphertext: "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
		},
		{
			name:       "sequence_2",
			seqNum:     2,
			aad:        "436f756e742d32",
			plaintext:  "4265617574792069732074727574682c20747275746820626561757479",
			ciphertext: "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
		},
	}

	// In short mode, only test first vector
	if testing.Short() {
		vectors = vectors[:1]
	}

	// Setup keys from RFC 9180 A.1
	skEm := mustHex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
	skRm := mustHex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
	pkRm := mustHex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
	info := mustHex("4f6465206f6e2061204772656369616e2055726e")

	// Set up deterministic ephemeral key
	ephPriv, err := ecdh.X25519().NewPrivateKey(skEm)
	if err != nil {
		t.Fatalf("NewPrivateKey(skEm) failed: %v", err)
	}
	testingOnlyGenerateKey = func() (*ecdh.PrivateKey, error) {
		return ephPriv, nil
	}
	defer func() { testingOnlyGenerateKey = nil }()

	// Parse recipient keys
	recipientPub, err := ParseHPKEPublicKey(DHKEM_X25519_HKDF_SHA256, pkRm)
	if err != nil {
		t.Fatalf("ParseHPKEPublicKey failed: %v", err)
	}
	recipientPriv, err := ParseHPKEPrivateKey(DHKEM_X25519_HKDF_SHA256, skRm)
	if err != nil {
		t.Fatalf("ParseHPKEPrivateKey failed: %v", err)
	}

	// Setup sender
	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Setup recipient
	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			aad := mustHex(tc.aad)
			plaintext := mustHex(tc.plaintext)
			expectedCiphertext := mustHex(tc.ciphertext)

			// Encrypt with sender
			ciphertext, err := sender.Seal(aad, plaintext)
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}

			// Verify ciphertext matches RFC expected value
			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Errorf("ciphertext mismatch:\n  got:  %x\n  want: %x", ciphertext, expectedCiphertext)
			}

			// Verify recipient can decrypt and get original plaintext
			decrypted, err := recipient.Open(aad, ciphertext)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted plaintext mismatch:\n  got:  %x\n  want: %x", decrypted, plaintext)
			}
		})
	}
}

// TestRFC9180SharedSecret verifies the intermediate shared secret value
// NOTE: This test modifies testingOnlyGenerateKey global, so it cannot run in parallel.
func TestRFC9180SharedSecret(t *testing.T) {

	skEm := mustHex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
	pkRm := mustHex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
	expectedSharedSecret := mustHex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc")

	// Set up deterministic ephemeral key
	ephPriv, err := ecdh.X25519().NewPrivateKey(skEm)
	if err != nil {
		t.Fatalf("NewPrivateKey(skEm) failed: %v", err)
	}
	testingOnlyGenerateKey = func() (*ecdh.PrivateKey, error) {
		return ephPriv, nil
	}
	defer func() { testingOnlyGenerateKey = nil }()

	// Create KEM and perform encapsulation
	kem, err := newDHKem(DHKEM_X25519_HKDF_SHA256)
	if err != nil {
		t.Fatalf("newDHKem failed: %v", err)
	}

	recipientPub, err := kem.dh.NewPublicKey(pkRm)
	if err != nil {
		t.Fatalf("NewPublicKey failed: %v", err)
	}

	sharedSecret, _, err := kem.Encap(recipientPub)
	if err != nil {
		t.Fatalf("Encap failed: %v", err)
	}

	// Verify shared secret matches RFC expected value
	if !bytes.Equal(sharedSecret, expectedSharedSecret) {
		t.Errorf("shared_secret mismatch:\n  got:  %x\n  want: %x", sharedSecret, expectedSharedSecret)
	}
}

// TestP256RoundTrip verifies P-256 KEM encryption/decryption
func TestP256RoundTrip(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	info := []byte("P-256 test info")

	enc, sender, err := SetupSender(
		DHKEM_P256_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Verify encapsulated key is 65 bytes (uncompressed P-256 point)
	if len(enc) != 65 {
		t.Errorf("enc length = %d, want 65 for P-256", len(enc))
	}

	// Verify enc starts with 0x04 (uncompressed point indicator)
	if enc[0] != 0x04 {
		t.Errorf("enc[0] = 0x%02x, want 0x04 for uncompressed point", enc[0])
	}

	recipient, err := SetupRecipient(
		DHKEM_P256_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Verify sender and recipient derived the same keys
	if !bytes.Equal(sender.key, recipient.key) {
		t.Errorf("key mismatch: sender=%x, recipient=%x", sender.key, recipient.key)
	}

	// Test encryption/decryption
	plaintext := []byte("Hello P-256 HPKE!")
	aad := []byte("additional data")

	ciphertext, err := sender.Seal(aad, plaintext)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	decrypted, err := recipient.Open(aad, ciphertext)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption mismatch:\n  got:  %s\n  want: %s", decrypted, plaintext)
	}
}

// TestP384RoundTrip verifies P-384 KEM encryption/decryption
func TestP384RoundTrip(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	info := []byte("P-384 test info")

	enc, sender, err := SetupSender(
		DHKEM_P384_HKDF_SHA384,
		KDF_HKDF_SHA384,
		AEAD_AES_256_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Verify encapsulated key is 97 bytes (uncompressed P-384 point)
	if len(enc) != 97 {
		t.Errorf("enc length = %d, want 97 for P-384", len(enc))
	}

	// Verify enc starts with 0x04
	if enc[0] != 0x04 {
		t.Errorf("enc[0] = 0x%02x, want 0x04 for uncompressed point", enc[0])
	}

	recipient, err := SetupRecipient(
		DHKEM_P384_HKDF_SHA384,
		KDF_HKDF_SHA384,
		AEAD_AES_256_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Verify sender and recipient derived the same keys
	if !bytes.Equal(sender.key, recipient.key) {
		t.Errorf("key mismatch: sender=%x, recipient=%x", sender.key, recipient.key)
	}

	// Test encryption/decryption
	plaintext := []byte("Hello P-384 HPKE!")
	aad := []byte("additional data")

	ciphertext, err := sender.Seal(aad, plaintext)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	decrypted, err := recipient.Open(aad, ciphertext)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption mismatch:\n  got:  %s\n  want: %s", decrypted, plaintext)
	}
}

// TestP521RoundTrip verifies P-521 KEM encryption/decryption
// RFC 9180 Section 7.1: P-521 has Nenc=133 (uncompressed point = 1 + 2*66 = 133 bytes)
func TestP521RoundTrip(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.P521().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	info := []byte("P-521 test info")

	enc, sender, err := SetupSender(
		DHKEM_P521_HKDF_SHA512,
		KDF_HKDF_SHA512,
		AEAD_AES_256_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Verify encapsulated key is 133 bytes (uncompressed P-521 point)
	// RFC 9180 Table 2: Nenc = 133 for P-521
	if len(enc) != 133 {
		t.Errorf("enc length = %d, want 133 for P-521", len(enc))
	}

	// Verify enc starts with 0x04 (uncompressed point indicator)
	if enc[0] != 0x04 {
		t.Errorf("enc[0] = 0x%02x, want 0x04 for uncompressed point", enc[0])
	}

	recipient, err := SetupRecipient(
		DHKEM_P521_HKDF_SHA512,
		KDF_HKDF_SHA512,
		AEAD_AES_256_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	// Verify sender and recipient derived the same keys
	if !bytes.Equal(sender.key, recipient.key) {
		t.Errorf("key mismatch: sender=%x, recipient=%x", sender.key, recipient.key)
	}

	// Test encryption/decryption
	plaintext := []byte("Hello P-521 HPKE!")
	aad := []byte("additional data")

	ciphertext, err := sender.Seal(aad, plaintext)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	decrypted, err := recipient.Open(aad, ciphertext)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decryption mismatch:\n  got:  %s\n  want: %s", decrypted, plaintext)
	}
}

// TestP521WithDifferentKDFs tests P-521 KEM with different KDF algorithms
func TestP521WithDifferentKDFs(t *testing.T) {
	t.Parallel()

	kdfs := []struct {
		name  string
		kdfID uint16
	}{
		{"HKDF-SHA256", KDF_HKDF_SHA256},
		{"HKDF-SHA384", KDF_HKDF_SHA384},
		{"HKDF-SHA512", KDF_HKDF_SHA512},
	}

	for _, kdf := range kdfs {
		t.Run(kdf.name, func(t *testing.T) {
			t.Parallel()

			recipientPriv, err := ecdh.P521().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			recipientPub := recipientPriv.PublicKey()

			info := []byte("P-521 test with " + kdf.name)

			enc, sender, err := SetupSender(
				DHKEM_P521_HKDF_SHA512,
				kdf.kdfID,
				AEAD_AES_256_GCM,
				recipientPub,
				info,
			)
			if err != nil {
				t.Fatalf("SetupSender failed: %v", err)
			}

			recipient, err := SetupRecipient(
				DHKEM_P521_HKDF_SHA512,
				kdf.kdfID,
				AEAD_AES_256_GCM,
				recipientPriv,
				info,
				enc,
			)
			if err != nil {
				t.Fatalf("SetupRecipient failed: %v", err)
			}

			plaintext := []byte("Test message for P-521 with " + kdf.name)
			aad := []byte("aad")

			ciphertext, err := sender.Seal(aad, plaintext)
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}

			decrypted, err := recipient.Open(aad, ciphertext)
			if err != nil {
				t.Fatalf("Open failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("Decryption mismatch:\n  got:  %s\n  want: %s", decrypted, plaintext)
			}
		})
	}
}

// TestAllKEMsWithAllAEADs tests all supported KEM/AEAD combinations
// In -short mode, only X25519 with AES-128-GCM is tested.
func TestAllKEMsWithAllAEADs(t *testing.T) {
	t.Parallel()

	kems := []struct {
		name   string
		kemID  uint16
		kdfID  uint16
		curve  ecdh.Curve
		encLen int
	}{
		{"X25519", DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, ecdh.X25519(), 32},
		{"P-256", DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, ecdh.P256(), 65},
		{"P-384", DHKEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, ecdh.P384(), 97},
		{"P-521", DHKEM_P521_HKDF_SHA512, KDF_HKDF_SHA512, ecdh.P521(), 133},
	}

	aeads := []struct {
		name   string
		aeadID uint16
	}{
		{"AES-128-GCM", AEAD_AES_128_GCM},
		{"AES-256-GCM", AEAD_AES_256_GCM},
		{"ChaCha20-Poly1305", AEAD_ChaCha20Poly1305},
	}

	// In short mode, only test X25519 with AES-128-GCM
	if testing.Short() {
		kems = kems[:1]
		aeads = aeads[:1]
	}

	for _, kem := range kems {
		for _, aead := range aeads {
			t.Run(kem.name+"/"+aead.name, func(t *testing.T) {
				t.Parallel()

				recipientPriv, err := kem.curve.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey failed: %v", err)
				}
				recipientPub := recipientPriv.PublicKey()

				info := []byte("test info for " + kem.name + " " + aead.name)

				enc, sender, err := SetupSender(
					kem.kemID,
					kem.kdfID,
					aead.aeadID,
					recipientPub,
					info,
				)
				if err != nil {
					t.Fatalf("SetupSender failed: %v", err)
				}

				if len(enc) != kem.encLen {
					t.Errorf("enc length = %d, want %d", len(enc), kem.encLen)
				}

				recipient, err := SetupRecipient(
					kem.kemID,
					kem.kdfID,
					aead.aeadID,
					recipientPriv,
					info,
					enc,
				)
				if err != nil {
					t.Fatalf("SetupRecipient failed: %v", err)
				}

				plaintext := []byte("Test message for " + kem.name)
				aadData := []byte("aad for " + aead.name)

				ciphertext, err := sender.Seal(aadData, plaintext)
				if err != nil {
					t.Fatalf("Seal failed: %v", err)
				}

				decrypted, err := recipient.Open(aadData, ciphertext)
				if err != nil {
					t.Fatalf("Open failed: %v", err)
				}

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("Decryption mismatch:\n  got:  %s\n  want: %s", decrypted, plaintext)
				}
			})
		}
	}
}

// TestInvalidPublicKeys tests rejection of malformed public keys
func TestInvalidPublicKeys(t *testing.T) {
	t.Parallel()

	t.Run("P256", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			key  []byte
		}{
			{"empty", []byte{}},
			{"too short", make([]byte, 32)},
			{"wrong prefix", append([]byte{0x02}, make([]byte, 64)...)},
			{"too long", make([]byte, 100)},
		}

		for _, tc := range tests {
			_, err := ParseHPKEPublicKey(DHKEM_P256_HKDF_SHA256, tc.key)
			if err == nil {
				t.Errorf("%s: Expected error for invalid P-256 public key", tc.name)
			}
		}
	})

	t.Run("P384", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			key  []byte
		}{
			{"empty", []byte{}},
			{"too short", make([]byte, 65)},
			{"wrong prefix", append([]byte{0x02}, make([]byte, 96)...)},
			{"too long", make([]byte, 150)},
		}

		for _, tc := range tests {
			_, err := ParseHPKEPublicKey(DHKEM_P384_HKDF_SHA384, tc.key)
			if err == nil {
				t.Errorf("%s: Expected error for invalid P-384 public key", tc.name)
			}
		}
	})

	t.Run("P521", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name string
			key  []byte
		}{
			{"empty", []byte{}},
			{"too short", make([]byte, 97)},
			{"wrong prefix", append([]byte{0x02}, make([]byte, 132)...)},
			{"too long", make([]byte, 200)},
		}

		for _, tc := range tests {
			_, err := ParseHPKEPublicKey(DHKEM_P521_HKDF_SHA512, tc.key)
			if err == nil {
				t.Errorf("%s: Expected error for invalid P-521 public key", tc.name)
			}
		}
	})
}

// TestParseHPKEKeys tests key parsing for all supported KEMs
func TestParseHPKEKeys(t *testing.T) {
	t.Parallel()

	kems := []struct {
		name  string
		kemID uint16
		curve ecdh.Curve
	}{
		{"P-256", DHKEM_P256_HKDF_SHA256, ecdh.P256()},
		{"P-384", DHKEM_P384_HKDF_SHA384, ecdh.P384()},
		{"P-521", DHKEM_P521_HKDF_SHA512, ecdh.P521()},
		{"X25519", DHKEM_X25519_HKDF_SHA256, ecdh.X25519()},
	}

	for _, kem := range kems {
		t.Run(kem.name, func(t *testing.T) {
			t.Parallel()

			// Generate key pair
			priv, err := kem.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			// Serialize and parse public key
			pubBytes := priv.PublicKey().Bytes()
			parsedPub, err := ParseHPKEPublicKey(kem.kemID, pubBytes)
			if err != nil {
				t.Fatalf("ParseHPKEPublicKey failed: %v", err)
			}
			if !bytes.Equal(parsedPub.Bytes(), pubBytes) {
				t.Error("Parsed public key doesn't match original")
			}

			// Serialize and parse private key
			privBytes := priv.Bytes()
			parsedPriv, err := ParseHPKEPrivateKey(kem.kemID, privBytes)
			if err != nil {
				t.Fatalf("ParseHPKEPrivateKey failed: %v", err)
			}
			if !bytes.Equal(parsedPriv.Bytes(), privBytes) {
				t.Error("Parsed private key doesn't match original")
			}
		})
	}
}

// TestMultipleMessages tests sending multiple messages with all KEMs
// In -short mode, only X25519 is tested with 10 messages instead of 100.
func TestMultipleMessages(t *testing.T) {
	t.Parallel()

	kems := []struct {
		name  string
		kemID uint16
		kdfID uint16
		curve ecdh.Curve
	}{
		{"X25519", DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, ecdh.X25519()},
		{"P-256", DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, ecdh.P256()},
		{"P-384", DHKEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, ecdh.P384()},
		{"P-521", DHKEM_P521_HKDF_SHA512, KDF_HKDF_SHA512, ecdh.P521()},
	}

	numMessages := 100
	if testing.Short() {
		kems = kems[:1]
		numMessages = 10
	}

	for _, kem := range kems {
		t.Run(kem.name, func(t *testing.T) {
			t.Parallel()

			recipientPriv, err := kem.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}

			enc, sender, err := SetupSender(
				kem.kemID,
				kem.kdfID,
				AEAD_AES_128_GCM,
				recipientPriv.PublicKey(),
				nil,
			)
			if err != nil {
				t.Fatalf("SetupSender failed: %v", err)
			}

			recipient, err := SetupRecipient(
				kem.kemID,
				kem.kdfID,
				AEAD_AES_128_GCM,
				recipientPriv,
				nil,
				enc,
			)
			if err != nil {
				t.Fatalf("SetupRecipient failed: %v", err)
			}

			// Send messages
			for i := 0; i < numMessages; i++ {
				plaintext := []byte("message " + string(rune('A'+i%26)))
				ciphertext, err := sender.Seal(nil, plaintext)
				if err != nil {
					t.Fatalf("Seal message %d failed: %v", i, err)
				}

				decrypted, err := recipient.Open(nil, ciphertext)
				if err != nil {
					t.Fatalf("Open message %d failed: %v", i, err)
				}

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("Message %d mismatch", i)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkSetupSender(b *testing.B) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()
	info := []byte("benchmark info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPub,
			info,
		)
	}
}

func BenchmarkSeal(b *testing.B) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()

	plaintext := make([]byte, 1024)
	aad := []byte("aad")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, sender, _ := SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPub,
			nil,
		)
		_, _ = sender.Seal(aad, plaintext)
	}
}

func BenchmarkOpen(b *testing.B) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()

	plaintext := make([]byte, 1024)
	aad := []byte("aad")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		enc, sender, _ := SetupSender(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPub,
			nil,
		)
		ciphertext, _ := sender.Seal(aad, plaintext)

		recipient, _ := SetupRecipient(
			DHKEM_X25519_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPriv,
			nil,
			enc,
		)
		b.StartTimer()

		_, _ = recipient.Open(aad, ciphertext)
	}
}

func BenchmarkSetupSenderP256(b *testing.B) {
	recipientPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()
	info := []byte("benchmark info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = SetupSender(
			DHKEM_P256_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPub,
			info,
		)
	}
}

func BenchmarkSetupRecipientP256(b *testing.B) {
	recipientPriv, _ := ecdh.P256().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()
	info := []byte("benchmark info")

	enc, _, _ := SetupSender(
		DHKEM_P256_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetupRecipient(
			DHKEM_P256_HKDF_SHA256,
			KDF_HKDF_SHA256,
			AEAD_AES_128_GCM,
			recipientPriv,
			info,
			enc,
		)
	}
}

func BenchmarkSetupSenderP384(b *testing.B) {
	recipientPriv, _ := ecdh.P384().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()
	info := []byte("benchmark info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = SetupSender(
			DHKEM_P384_HKDF_SHA384,
			KDF_HKDF_SHA384,
			AEAD_AES_256_GCM,
			recipientPub,
			info,
		)
	}
}

func BenchmarkSetupRecipientP384(b *testing.B) {
	recipientPriv, _ := ecdh.P384().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()
	info := []byte("benchmark info")

	enc, _, _ := SetupSender(
		DHKEM_P384_HKDF_SHA384,
		KDF_HKDF_SHA384,
		AEAD_AES_256_GCM,
		recipientPub,
		info,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetupRecipient(
			DHKEM_P384_HKDF_SHA384,
			KDF_HKDF_SHA384,
			AEAD_AES_256_GCM,
			recipientPriv,
			info,
			enc,
		)
	}
}

func BenchmarkSetupSenderP521(b *testing.B) {
	recipientPriv, _ := ecdh.P521().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()
	info := []byte("benchmark info")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = SetupSender(
			DHKEM_P521_HKDF_SHA512,
			KDF_HKDF_SHA512,
			AEAD_AES_256_GCM,
			recipientPub,
			info,
		)
	}
}

func BenchmarkSetupRecipientP521(b *testing.B) {
	recipientPriv, _ := ecdh.P521().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()
	info := []byte("benchmark info")

	enc, _, _ := SetupSender(
		DHKEM_P521_HKDF_SHA512,
		KDF_HKDF_SHA512,
		AEAD_AES_256_GCM,
		recipientPub,
		info,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SetupRecipient(
			DHKEM_P521_HKDF_SHA512,
			KDF_HKDF_SHA512,
			AEAD_AES_256_GCM,
			recipientPriv,
			info,
			enc,
		)
	}
}

// TestConcurrentSeal tests that concurrent Seal operations are thread-safe.
// Without proper mutex protection, concurrent calls would cause nonce reuse,
// which is a catastrophic security failure for AEAD encryption.
func TestConcurrentSeal(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	_, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		nil,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	const numGoroutines = 100
	const messagesPerGoroutine = 10

	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines*messagesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < messagesPerGoroutine; j++ {
				plaintext := []byte("message from goroutine")
				_, err := sender.Seal(nil, plaintext)
				if err != nil {
					errCh <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Seal failed: %v", err)
	}
}

// TestConcurrentSenderRecipientPairs tests that multiple sender/recipient pairs
// can be used concurrently without issues.
func TestConcurrentSenderRecipientPairs(t *testing.T) {
	t.Parallel()

	const numPairs = 50
	const messagesPerPair = 20

	var wg sync.WaitGroup
	errCh := make(chan error, numPairs*messagesPerPair)

	for i := 0; i < numPairs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				errCh <- err
				return
			}
			recipientPub := recipientPriv.PublicKey()

			enc, sender, err := SetupSender(
				DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				AEAD_AES_128_GCM,
				recipientPub,
				nil,
			)
			if err != nil {
				errCh <- err
				return
			}

			recipient, err := SetupRecipient(
				DHKEM_X25519_HKDF_SHA256,
				KDF_HKDF_SHA256,
				AEAD_AES_128_GCM,
				recipientPriv,
				nil,
				enc,
			)
			if err != nil {
				errCh <- err
				return
			}

			plaintext := []byte("test message for concurrent pair")
			for j := 0; j < messagesPerPair; j++ {
				ciphertext, err := sender.Seal(nil, plaintext)
				if err != nil {
					errCh <- err
					continue
				}

				decrypted, err := recipient.Open(nil, ciphertext)
				if err != nil {
					errCh <- err
					continue
				}

				if !bytes.Equal(decrypted, plaintext) {
					errCh <- errors.New("decrypted plaintext mismatch")
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent operation failed: %v", err)
	}
}

// TestRFC9180Export tests the Export function against RFC 9180 Appendix A.1 test vectors.
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (Base Mode)
// NOTE: This test modifies testingOnlyGenerateKey global, so it cannot run in parallel.
func TestRFC9180Export(t *testing.T) {
	// RFC 9180 A.1 Base Setup Information
	skEm := mustHex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
	pkRm := mustHex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
	info := mustHex("4f6465206f6e2061204772656369616e2055726e") // "Ode on a Grecian Urn"

	// Expected exporter_secret from RFC 9180 A.1
	expectedExporterSecret := mustHex("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8")

	// Export test vectors from RFC 9180 A.1
	exportTests := []struct {
		name            string
		exporterContext string // hex
		length          uint16
		expected        string // hex
	}{
		{
			name:            "empty_context",
			exporterContext: "",
			length:          32,
			expected:        "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
		},
		{
			name:            "single_byte_context",
			exporterContext: "00",
			length:          32,
			expected:        "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
		},
		{
			name:            "TestContext",
			exporterContext: "54657374436f6e74657874", // "TestContext"
			length:          32,
			expected:        "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931",
		},
	}

	// Set up deterministic ephemeral key from skEm
	ephPriv, err := ecdh.X25519().NewPrivateKey(skEm)
	if err != nil {
		t.Fatalf("NewPrivateKey(skEm) failed: %v", err)
	}
	testingOnlyGenerateKey = func() (*ecdh.PrivateKey, error) {
		return ephPriv, nil
	}
	defer func() { testingOnlyGenerateKey = nil }()

	// Parse recipient public key
	recipientPub, err := ParseHPKEPublicKey(DHKEM_X25519_HKDF_SHA256, pkRm)
	if err != nil {
		t.Fatalf("ParseHPKEPublicKey failed: %v", err)
	}

	// Setup sender
	_, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Verify the exporter secret matches the expected value from RFC 9180
	if !bytes.Equal(sender.exporterSecret, expectedExporterSecret) {
		t.Errorf("exporter_secret mismatch:\n  got:  %x\n  want: %x", sender.exporterSecret, expectedExporterSecret)
	}

	// Run export test vectors
	for _, tc := range exportTests {
		t.Run(tc.name, func(t *testing.T) {
			exporterContext := mustHex(tc.exporterContext)
			expected := mustHex(tc.expected)

			exported, err := sender.Export(exporterContext, tc.length)
			if err != nil {
				t.Fatalf("Export failed: %v", err)
			}

			if !bytes.Equal(exported, expected) {
				t.Errorf("exported value mismatch:\n  got:  %x\n  want: %x", exported, expected)
			}
		})
	}
}

// TestExportSenderRecipientMatch verifies that sender and recipient derive
// the same exported secrets.
func TestExportSenderRecipientMatch(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	info := []byte("export test info")

	enc, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		info,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	recipient, err := SetupRecipient(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPriv,
		info,
		enc,
	)
	if err != nil {
		t.Fatalf("SetupRecipient failed: %v", err)
	}

	testCases := []struct {
		name            string
		exporterContext []byte
		length          uint16
	}{
		{"empty_context_32", nil, 32},
		{"empty_context_64", []byte{}, 64},
		{"simple_context", []byte("test"), 32},
		{"long_context", []byte("a longer context string for testing"), 48},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			senderExport, err := sender.Export(tc.exporterContext, tc.length)
			if err != nil {
				t.Fatalf("sender.Export failed: %v", err)
			}

			recipientExport, err := recipient.Export(tc.exporterContext, tc.length)
			if err != nil {
				t.Fatalf("recipient.Export failed: %v", err)
			}

			if !bytes.Equal(senderExport, recipientExport) {
				t.Errorf("sender and recipient exports don't match:\n  sender:    %x\n  recipient: %x",
					senderExport, recipientExport)
			}

			if len(senderExport) != int(tc.length) {
				t.Errorf("export length = %d, want %d", len(senderExport), tc.length)
			}
		})
	}
}

// TestExportDifferentContexts verifies that different exporter contexts
// produce different (independent) secrets.
func TestExportDifferentContexts(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	_, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		nil,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	// Export with different contexts
	export1, err := sender.Export([]byte("context1"), 32)
	if err != nil {
		t.Fatalf("Export context1 failed: %v", err)
	}

	export2, err := sender.Export([]byte("context2"), 32)
	if err != nil {
		t.Fatalf("Export context2 failed: %v", err)
	}

	export3, err := sender.Export(nil, 32)
	if err != nil {
		t.Fatalf("Export nil context failed: %v", err)
	}

	// All exports should be different
	if bytes.Equal(export1, export2) {
		t.Error("export1 and export2 should be different")
	}
	if bytes.Equal(export1, export3) {
		t.Error("export1 and export3 should be different")
	}
	if bytes.Equal(export2, export3) {
		t.Error("export2 and export3 should be different")
	}
}

// TestExportIdempotent verifies that calling Export multiple times with
// the same parameters produces the same result (Export doesn't modify state).
func TestExportIdempotent(t *testing.T) {
	t.Parallel()

	recipientPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	recipientPub := recipientPriv.PublicKey()

	_, sender, err := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		nil,
	)
	if err != nil {
		t.Fatalf("SetupSender failed: %v", err)
	}

	context := []byte("test context")

	// Call Export multiple times
	export1, err := sender.Export(context, 32)
	if err != nil {
		t.Fatalf("Export 1 failed: %v", err)
	}

	export2, err := sender.Export(context, 32)
	if err != nil {
		t.Fatalf("Export 2 failed: %v", err)
	}

	export3, err := sender.Export(context, 32)
	if err != nil {
		t.Fatalf("Export 3 failed: %v", err)
	}

	if !bytes.Equal(export1, export2) {
		t.Error("export1 and export2 should be equal")
	}
	if !bytes.Equal(export2, export3) {
		t.Error("export2 and export3 should be equal")
	}
}

// TestExportAllKDFs tests Export functionality with all supported KDFs.
func TestExportAllKDFs(t *testing.T) {
	t.Parallel()

	kdfTests := []struct {
		name  string
		kemID uint16
		kdfID uint16
		curve ecdh.Curve
	}{
		{"SHA256", DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, ecdh.X25519()},
		{"SHA384", DHKEM_P384_HKDF_SHA384, KDF_HKDF_SHA384, ecdh.P384()},
	}

	for _, tc := range kdfTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			recipientPriv, err := tc.curve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			recipientPub := recipientPriv.PublicKey()

			enc, sender, err := SetupSender(
				tc.kemID,
				tc.kdfID,
				AEAD_AES_128_GCM,
				recipientPub,
				nil,
			)
			if err != nil {
				t.Fatalf("SetupSender failed: %v", err)
			}

			recipient, err := SetupRecipient(
				tc.kemID,
				tc.kdfID,
				AEAD_AES_128_GCM,
				recipientPriv,
				nil,
				enc,
			)
			if err != nil {
				t.Fatalf("SetupRecipient failed: %v", err)
			}

			exporterContext := []byte("KDF test")
			senderExport, err := sender.Export(exporterContext, 64)
			if err != nil {
				t.Fatalf("sender.Export failed: %v", err)
			}

			recipientExport, err := recipient.Export(exporterContext, 64)
			if err != nil {
				t.Fatalf("recipient.Export failed: %v", err)
			}

			if !bytes.Equal(senderExport, recipientExport) {
				t.Errorf("sender and recipient exports don't match")
			}

			if len(senderExport) != 64 {
				t.Errorf("export length = %d, want 64", len(senderExport))
			}
		})
	}
}

// BenchmarkExport benchmarks the Export function.
func BenchmarkExport(b *testing.B) {
	recipientPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	recipientPub := recipientPriv.PublicKey()

	_, sender, _ := SetupSender(
		DHKEM_X25519_HKDF_SHA256,
		KDF_HKDF_SHA256,
		AEAD_AES_128_GCM,
		recipientPub,
		nil,
	)

	exporterContext := []byte("benchmark context")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sender.Export(exporterContext, 32)
	}
}
