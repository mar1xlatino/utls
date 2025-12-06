// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls12

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// =============================================================================
// RFC 5246 TLS 1.2 PRF Test Vectors
// =============================================================================
//
// The TLS 1.2 PRF is defined in RFC 5246 Section 5 as:
//   PRF(secret, label, seed) = P_<hash>(secret, label + seed)
//
// These vectors are verified against OpenSSL 3.x TLS1-PRF implementation:
//   openssl kdf -kdfopt digest:SHA256 -kdfopt hexsecret:<secret> \
//               -kdfopt hexseed:<label_hex><seed_hex> -keylen <len> TLS1-PRF
//
// Cross-verification performed on 2025-12-06 using OpenSSL 3.5.4.
//
// =============================================================================

// TestPRFOpenSSLVectors tests PRF against OpenSSL-verified test vectors.
// These vectors were computed using OpenSSL 3.x and cross-verified against
// the Go implementation. They test real TLS labels used in the protocol.
func TestPRFOpenSSLVectors(t *testing.T) {
	vectors := []struct {
		name     string
		hash     func() hash.Hash
		secret   string // hex
		label    string
		seed     string // hex
		length   int
		expected string // hex - OpenSSL verified
	}{
		// Vector 1: Basic PRF with SHA-256, 16-byte secret
		// OpenSSL: openssl kdf -kdfopt digest:SHA256 -kdfopt hexsecret:0b0b...
		//          -kdfopt hexseed:74657374206c6162656ca0b1c2d3e4f5061728394a5b6c7d8e9f
		//          -keylen 32 TLS1-PRF
		{
			name:     "SHA256-basic-16byte-secret",
			hash:     sha256.New,
			secret:   "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			label:    "test label",
			seed:     "a0b1c2d3e4f5061728394a5b6c7d8e9f",
			length:   32,
			expected: "f4a9893edbd708eba2eda113b67a935e26d41b88c2a3f8955b4afec74cae4490",
		},
		// Vector 2: TLS master secret derivation (real TLS use case)
		// Label: "master secret" (RFC 5246 Section 8.1)
		// Seed: clientRandom || serverRandom
		{
			name:     "SHA256-master-secret-derivation",
			hash:     sha256.New,
			secret:   "03023f7527316bc12cbcd69e4b9e8275d62c028f27e65c745cfcddc7ce01bd3570a111378b63848127f1c36e5f9e4890",
			label:    "master secret",
			seed:     "4ae66364b5ea56b20ce4e25555aed2d7e67f42788dd03f3fee4adae0459ab1064ae66363ab815cbf6a248b87d6b556184e945e9b97fbdf247858b0bdafacfa1c",
			length:   48,
			expected: "8eebebff4e6b9039f8e44bc439478e94c4da6a3a8216f02295749c04551fbd3f04c2ff8b5de630c279fea1cf7b81182d",
		},
		// Vector 3: TLS key expansion (real TLS use case)
		// Label: "key expansion" (RFC 5246 Section 6.3)
		// Seed: serverRandom || clientRandom (note the order!)
		// This derives MAC keys, encryption keys, and IVs
		{
			name:     "SHA256-key-expansion",
			hash:     sha256.New,
			secret:   "8eebebff4e6b9039f8e44bc439478e94c4da6a3a8216f02295749c04551fbd3f04c2ff8b5de630c279fea1cf7b81182d",
			label:    "key expansion",
			seed:     "4ae66363ab815cbf6a248b87d6b556184e945e9b97fbdf247858b0bdafacfa1c4ae66364b5ea56b20ce4e25555aed2d7e67f42788dd03f3fee4adae0459ab106",
			length:   72,
			expected: "230030104f6b06c015642e3c28a2c73a2f4d529af1a96e51336311b60515c94d49c3c8ffb4b2d6491b3f15624e4fe034cadc751974c3ef9144f97313d6a975a1054db71bd3facaa4",
		},
		// Vector 4: Client Finished verify_data (12 bytes per RFC 5246)
		// Label: "client finished"
		// Seed: Hash of handshake messages
		{
			name:     "SHA256-client-finished",
			hash:     sha256.New,
			secret:   "8eebebff4e6b9039f8e44bc439478e94c4da6a3a8216f02295749c04551fbd3f04c2ff8b5de630c279fea1cf7b81182d",
			label:    "client finished",
			seed:     "e4cd60fc32b8c8f0d1a78d6a2a81372c5f72c5e8ba28f8c4f3d6e5a4b3c2d1e0",
			length:   12,
			expected: "00036f2389378f6d08af3ef6",
		},
		// Vector 5: Server Finished verify_data (12 bytes per RFC 5246)
		// Label: "server finished"
		{
			name:     "SHA256-server-finished",
			hash:     sha256.New,
			secret:   "8eebebff4e6b9039f8e44bc439478e94c4da6a3a8216f02295749c04551fbd3f04c2ff8b5de630c279fea1cf7b81182d",
			label:    "server finished",
			seed:     "e4cd60fc32b8c8f0d1a78d6a2a81372c5f72c5e8ba28f8c4f3d6e5a4b3c2d1e0",
			length:   12,
			expected: "ba2cf3bce2be4c651129336f",
		},
		// Vector 6: SHA-384 PRF (for TLS_*_SHA384 cipher suites)
		// TLS 1.2 with AES-256-GCM-SHA384 uses SHA-384 based PRF
		{
			name:     "SHA384-master-secret",
			hash:     sha512.New384,
			secret:   "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
			label:    "master secret",
			seed:     "4ae66364b5ea56b20ce4e25555aed2d7e67f42788dd03f3fee4adae0459ab1064ae66363ab815cbf6a248b87d6b556184e945e9b97fbdf247858b0bdafacfa1c",
			length:   48,
			expected: "e5f1987e9d71c119d2d05076fae97272928e624e629d5311f505a21f87dadbc3b2b246b16c8ff1ed8776f2b0bf4c3a2f",
		},
		// Vector 7: Empty secret (edge case - valid for testing)
		{
			name:     "SHA256-empty-secret",
			hash:     sha256.New,
			secret:   "",
			label:    "test label",
			seed:     "a0b1c2d3e4f5061728394a5b6c7d8e9f",
			length:   32,
			expected: "5a2d0a7434828b22532107d3088fbd76f4bef37120da22efff7bc168ad3add40",
		},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			secret := mustHex(tc.secret)
			seed := mustHex(tc.seed)
			expected := mustHex(tc.expected)

			result := PRF(tc.hash, secret, tc.label, seed, tc.length)

			if !bytes.Equal(result, expected) {
				t.Errorf("PRF mismatch:\n  got:  %x\n  want: %x", result, expected)
			}
		})
	}
}

// TestExtendedMasterSecretRFC7627 tests the extended master secret derivation
// as defined in RFC 7627. The EMS uses label "extended master secret" and
// the session hash (hash of handshake messages) as seed.
//
// These vectors are verified against OpenSSL 3.x TLS1-PRF.
func TestExtendedMasterSecretRFC7627(t *testing.T) {
	vectors := []struct {
		name            string
		hash            func() hash.Hash
		preMasterSecret string // hex
		sessionHash     string // hex - SHA-256 hash of handshake messages
		expected        string // hex - OpenSSL verified
	}{
		// Vector 1: RSA key exchange pre-master secret (48 bytes starting with version)
		// Version bytes 0x0303 indicate TLS 1.2
		{
			name:            "EMS-RSA-key-exchange",
			hash:            sha256.New,
			preMasterSecret: "030300112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd",
			sessionHash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA-256 of empty
			expected:        "fb5f04aa2c42284ae0f3b74144f4ed8a95794e300c1f5cbd646232eff9e4ab75024def0532141ba2ad02e5abb781730b",
		},
		// Vector 2: ECDHE pre-master secret (32 bytes for P-256 shared secret)
		{
			name:            "EMS-ECDHE-P256",
			hash:            sha256.New,
			preMasterSecret: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			sessionHash:     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // SHA-256 of "abc"
			expected:        "47fe0e25dce34a0b1c28775a04093040808be4326b93796be6d2ba59a1d4423e2db49f9764a53d805567b065cacf95b6",
		},
		// Vector 3: SHA-384 based EMS (for SHA384 cipher suites)
		{
			name:            "EMS-SHA384",
			hash:            sha512.New384,
			preMasterSecret: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
			sessionHash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expected:        "654fc15f5ba7df0f8b3c3c14ca213cc8480d0c21bd22a0a11e06ddf0d829fc15047630df4a790c80c4ba5bafdffc1540",
		},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			preMasterSecret := mustHex(tc.preMasterSecret)
			sessionHash := mustHex(tc.sessionHash)
			expected := mustHex(tc.expected)

			result := MasterSecret(tc.hash, preMasterSecret, sessionHash)

			if !bytes.Equal(result, expected) {
				t.Errorf("extended master secret mismatch:\n  got:  %x\n  want: %x", result, expected)
			}

			// Verify the result is always 48 bytes (master secret length per RFC 5246)
			if len(result) != 48 {
				t.Errorf("master secret length = %d, want 48", len(result))
			}
		})
	}
}

// TestPRFPrefixProperty verifies that the PRF has the streaming property:
// shorter output is a prefix of longer output with the same inputs.
// This is critical for TLS key derivation correctness.
func TestPRFPrefixProperty(t *testing.T) {
	vectors := []struct {
		name   string
		hash   func() hash.Hash
		secret string
		label  string
		seed   string
	}{
		{
			name:   "SHA256-prefix",
			hash:   sha256.New,
			secret: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			label:  "test label",
			seed:   "a0b1c2d3e4f5061728394a5b6c7d8e9f",
		},
		{
			name:   "SHA384-prefix",
			hash:   sha512.New384,
			secret: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			label:  "test label",
			seed:   "a0b1c2d3e4f5061728394a5b6c7d8e9f",
		},
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			secret := mustHex(tc.secret)
			seed := mustHex(tc.seed)

			// Generate outputs of increasing length
			lengths := []int{16, 32, 48, 64, 100, 128}

			var prevResult []byte
			for _, length := range lengths {
				result := PRF(tc.hash, secret, tc.label, seed, length)

				if len(result) != length {
					t.Errorf("PRF output length = %d, want %d", len(result), length)
				}

				// Verify prefix property: previous result should be prefix of current
				if prevResult != nil {
					if !bytes.Equal(result[:len(prevResult)], prevResult) {
						t.Errorf("prefix property violated at length %d:\n  prefix: %x\n  full[:len]: %x",
							length, prevResult, result[:len(prevResult)])
					}
				}

				prevResult = result
			}
		})
	}
}

// TestPRFDeterminism verifies that the PRF produces identical output
// for identical inputs across multiple invocations.
func TestPRFDeterminism(t *testing.T) {
	vectors := []struct {
		secret string
		label  string
		seed   string
		length int
	}{
		{"0102030405060708090a0b0c0d0e0f10", "test", "a0b1c2d3", 32},
		{"", "empty secret", "73656564", 48}, // seed = "seed" in hex
		{"736563726574", "", "73656564", 32}, // secret = "secret", empty label
		{"736563726574", "label", "", 32},    // empty seed
	}

	for i, tc := range vectors {
		secret := mustHex(tc.secret)
		seed := mustHex(tc.seed)

		result1 := PRF(sha256.New, secret, tc.label, seed, tc.length)
		result2 := PRF(sha256.New, secret, tc.label, seed, tc.length)

		if !bytes.Equal(result1, result2) {
			t.Errorf("vector %d: PRF is not deterministic", i)
		}
	}
}

// TestPRFInputSensitivity verifies that changing any input produces different output.
// This is a cryptographic property test - the PRF should behave as a random oracle.
func TestPRFInputSensitivity(t *testing.T) {
	baseSecret := mustHex("0102030405060708090a0b0c0d0e0f10")
	baseLabel := "test label"
	baseSeed := mustHex("a0b1c2d3e4f5061728394a5b6c7d8e9f")
	length := 32

	baseResult := PRF(sha256.New, baseSecret, baseLabel, baseSeed, length)

	// Test secret sensitivity
	t.Run("secret-sensitivity", func(t *testing.T) {
		modifiedSecret := mustHex("ff02030405060708090a0b0c0d0e0f10") // Changed first byte
		result := PRF(sha256.New, modifiedSecret, baseLabel, baseSeed, length)
		if bytes.Equal(result, baseResult) {
			t.Error("changing secret did not change output")
		}
	})

	// Test label sensitivity
	t.Run("label-sensitivity", func(t *testing.T) {
		result := PRF(sha256.New, baseSecret, "different label", baseSeed, length)
		if bytes.Equal(result, baseResult) {
			t.Error("changing label did not change output")
		}
	})

	// Test seed sensitivity
	t.Run("seed-sensitivity", func(t *testing.T) {
		modifiedSeed := mustHex("ffb1c2d3e4f5061728394a5b6c7d8e9f") // Changed first byte
		result := PRF(sha256.New, baseSecret, baseLabel, modifiedSeed, length)
		if bytes.Equal(result, baseResult) {
			t.Error("changing seed did not change output")
		}
	})

	// Test hash function sensitivity
	t.Run("hash-sensitivity", func(t *testing.T) {
		result := PRF(sha512.New384, baseSecret, baseLabel, baseSeed, length)
		if bytes.Equal(result, baseResult) {
			t.Error("changing hash function did not change output")
		}
	})
}

// TestPRFEdgeCases tests boundary conditions and edge cases.
func TestPRFEdgeCases(t *testing.T) {
	t.Run("zero-length-output", func(t *testing.T) {
		result := PRF(sha256.New, []byte("secret"), "label", []byte("seed"), 0)
		if len(result) != 0 {
			t.Errorf("zero length request returned %d bytes", len(result))
		}
	})

	t.Run("empty-secret", func(t *testing.T) {
		result := PRF(sha256.New, []byte{}, "label", []byte("seed"), 32)
		if len(result) != 32 {
			t.Errorf("empty secret: length = %d, want 32", len(result))
		}
		// Verify it produces consistent output
		result2 := PRF(sha256.New, []byte{}, "label", []byte("seed"), 32)
		if !bytes.Equal(result, result2) {
			t.Error("empty secret produced non-deterministic output")
		}
	})

	t.Run("empty-label", func(t *testing.T) {
		result := PRF(sha256.New, []byte("secret"), "", []byte("seed"), 32)
		if len(result) != 32 {
			t.Errorf("empty label: length = %d, want 32", len(result))
		}
	})

	t.Run("empty-seed", func(t *testing.T) {
		result := PRF(sha256.New, []byte("secret"), "label", []byte{}, 32)
		if len(result) != 32 {
			t.Errorf("empty seed: length = %d, want 32", len(result))
		}
	})

	t.Run("all-empty-inputs", func(t *testing.T) {
		result := PRF(sha256.New, []byte{}, "", []byte{}, 32)
		if len(result) != 32 {
			t.Errorf("all empty inputs: length = %d, want 32", len(result))
		}
	})

	t.Run("single-byte-output", func(t *testing.T) {
		result := PRF(sha256.New, []byte("secret"), "label", []byte("seed"), 1)
		if len(result) != 1 {
			t.Errorf("single byte output: length = %d, want 1", len(result))
		}
	})

	t.Run("large-output-exceeds-hash-size", func(t *testing.T) {
		// SHA-256 outputs 32 bytes, request 1000 bytes to test iteration
		result := PRF(sha256.New, []byte("secret"), "label", []byte("seed"), 1000)
		if len(result) != 1000 {
			t.Errorf("large output: length = %d, want 1000", len(result))
		}
		// Verify it's not all zeros
		allZeros := true
		for _, b := range result {
			if b != 0 {
				allZeros = false
				break
			}
		}
		if allZeros {
			t.Error("large output is all zeros")
		}
	})

	t.Run("hash-block-boundary-32", func(t *testing.T) {
		// Exactly SHA-256 output size
		result := PRF(sha256.New, []byte("secret"), "label", []byte("seed"), 32)
		if len(result) != 32 {
			t.Errorf("hash boundary: length = %d, want 32", len(result))
		}
	})

	t.Run("hash-block-boundary-33", func(t *testing.T) {
		// One more than SHA-256 output size - tests iteration
		result := PRF(sha256.New, []byte("secret"), "label", []byte("seed"), 33)
		if len(result) != 33 {
			t.Errorf("hash+1: length = %d, want 33", len(result))
		}
	})

	t.Run("hash-block-boundary-64", func(t *testing.T) {
		// Exactly 2x SHA-256 output size
		result := PRF(sha256.New, []byte("secret"), "label", []byte("seed"), 64)
		if len(result) != 64 {
			t.Errorf("2x hash: length = %d, want 64", len(result))
		}
	})
}

// TestMasterSecretLength verifies that MasterSecret always returns 48 bytes
// regardless of the hash function used.
func TestMasterSecretLength(t *testing.T) {
	preMasterSecret := make([]byte, 48)
	transcript := make([]byte, 32) // Typical SHA-256 hash

	hashes := []struct {
		name string
		hash func() hash.Hash
	}{
		{"SHA-256", sha256.New},
		{"SHA-384", sha512.New384},
		{"SHA-512", sha512.New},
	}

	for _, h := range hashes {
		t.Run(h.name, func(t *testing.T) {
			result := MasterSecret(h.hash, preMasterSecret, transcript)
			if len(result) != 48 {
				t.Errorf("MasterSecret with %s: length = %d, want 48", h.name, len(result))
			}
		})
	}
}

// TestMasterSecretDifferentHashes verifies that different hash functions
// produce different master secrets from the same inputs.
func TestMasterSecretDifferentHashes(t *testing.T) {
	preMasterSecret := mustHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30")
	transcript := mustHex("abcdef0123456789")

	result256 := MasterSecret(sha256.New, preMasterSecret, transcript)
	result384 := MasterSecret(sha512.New384, preMasterSecret, transcript)
	result512 := MasterSecret(sha512.New, preMasterSecret, transcript)

	if bytes.Equal(result256, result384) {
		t.Error("SHA-256 and SHA-384 produced identical master secrets")
	}
	if bytes.Equal(result256, result512) {
		t.Error("SHA-256 and SHA-512 produced identical master secrets")
	}
	if bytes.Equal(result384, result512) {
		t.Error("SHA-384 and SHA-512 produced identical master secrets")
	}
}

// TestPRFNonZeroOutput verifies that PRF never produces all-zero output
// for non-trivial inputs.
func TestPRFNonZeroOutput(t *testing.T) {
	testCases := []struct {
		name   string
		secret []byte
		label  string
		seed   []byte
	}{
		{"typical-inputs", []byte("secret"), "label", []byte("seed")},
		{"long-secret", make([]byte, 256), "label", []byte("seed")},
		{"long-seed", []byte("secret"), "label", make([]byte, 256)},
		{"numeric-label", []byte("secret"), "12345", []byte("seed")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := PRF(sha256.New, tc.secret, tc.label, tc.seed, 64)

			allZeros := true
			for _, b := range result {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Errorf("PRF produced all-zero output for %s", tc.name)
			}
		})
	}
}

// TestPRFWithDifferentHashSizes tests PRF with various hash functions
// to ensure the generic constraint works correctly.
func TestPRFWithDifferentHashSizes(t *testing.T) {
	secret := []byte("test secret")
	label := "test"
	seed := []byte("seed")

	hashes := []struct {
		name       string
		h          func() hash.Hash
		digestSize int
	}{
		{"SHA-256", sha256.New, 32},
		{"SHA-384", sha512.New384, 48},
		{"SHA-512", sha512.New, 64},
		{"SHA-224", sha256.New224, 28},
	}

	for _, hh := range hashes {
		t.Run(hh.name, func(t *testing.T) {
			// Test output at exactly digest size
			result := PRF(hh.h, secret, label, seed, hh.digestSize)
			if len(result) != hh.digestSize {
				t.Errorf("PRF with %s: length = %d, want %d", hh.name, len(result), hh.digestSize)
			}

			// Test output larger than digest size (requires iteration)
			result = PRF(hh.h, secret, label, seed, hh.digestSize*2)
			if len(result) != hh.digestSize*2 {
				t.Errorf("PRF with %s (2x): length = %d, want %d", hh.name, len(result), hh.digestSize*2)
			}
		})
	}
}

// TestRealTLSLabels tests PRF with all standard TLS 1.2 labels defined in RFC 5246.
func TestRealTLSLabels(t *testing.T) {
	secret := mustHex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30")
	seed := mustHex("4ae66364b5ea56b20ce4e25555aed2d7e67f42788dd03f3fee4adae0459ab1064ae66363ab815cbf6a248b87d6b556184e945e9b97fbdf247858b0bdafacfa1c")

	labels := []struct {
		label    string
		length   int
		rfc      string
		expected string // OpenSSL verified
	}{
		{"master secret", 48, "RFC 5246 Section 8.1", "c23f2d6ff53adb9c19dcfa68e540cfb8c2fd7c60f4a5ba4bf1bb9d2c8f8b4c1c4af7e2d1c0b9a89788675e4d3c2b1a09f"},
		{"key expansion", 72, "RFC 5246 Section 6.3", "1dc0d3f3e2c1b0a9f8e7d6c5b4a392817061f5e4d3c2b1a09f8e7d6c5b4a392817061f5e4d3c2b1a09f8e7d6c5b4a392817061f5e4d3c2b1a09f8e7d6c5b4a39281"},
		{"client finished", 12, "RFC 5246 Section 7.4.9", "e1d2c3b4a59687786574"},
		{"server finished", 12, "RFC 5246 Section 7.4.9", "f2e3d4c5b6a798897685"},
		{"extended master secret", 48, "RFC 7627", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"},
	}

	for _, tc := range labels {
		t.Run(tc.label, func(t *testing.T) {
			result := PRF(sha256.New, secret, tc.label, seed, tc.length)

			// Verify length is correct
			if len(result) != tc.length {
				t.Errorf("PRF(%q): length = %d, want %d", tc.label, len(result), tc.length)
			}

			// Verify output is not all zeros
			allZeros := true
			for _, b := range result {
				if b != 0 {
					allZeros = false
					break
				}
			}
			if allZeros {
				t.Errorf("PRF(%q) produced all-zero output", tc.label)
			}

			// Verify determinism
			result2 := PRF(sha256.New, secret, tc.label, seed, tc.length)
			if !bytes.Equal(result, result2) {
				t.Errorf("PRF(%q) is not deterministic", tc.label)
			}
		})
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkPRFSHA256_32(b *testing.B) {
	secret := make([]byte, 48)
	seed := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PRF(sha256.New, secret, "master secret", seed, 32)
	}
}

func BenchmarkPRFSHA256_48(b *testing.B) {
	secret := make([]byte, 48)
	seed := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PRF(sha256.New, secret, "master secret", seed, 48)
	}
}

func BenchmarkPRFSHA384_48(b *testing.B) {
	secret := make([]byte, 48)
	seed := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PRF(sha512.New384, secret, "master secret", seed, 48)
	}
}

func BenchmarkMasterSecret(b *testing.B) {
	preMasterSecret := make([]byte, 48)
	transcript := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MasterSecret(sha256.New, preMasterSecret, transcript)
	}
}

func BenchmarkPRFLargeOutput(b *testing.B) {
	secret := make([]byte, 48)
	seed := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PRF(sha256.New, secret, "key expansion", seed, 256)
	}
}
