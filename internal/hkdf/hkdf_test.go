// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hkdf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"
)

// RFC 5869 Test Vectors
// https://www.rfc-editor.org/rfc/rfc5869#appendix-A

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestRFC5869Vectors tests all RFC 5869 SHA-256 test vectors in a single table-driven test.
// In -short mode, only the first two vectors are tested.
func TestRFC5869Vectors(t *testing.T) {
	t.Parallel()

	vectors := []struct {
		name        string
		ikm         string
		salt        string
		info        string
		prkExpected string
		okmExpected string
		okmLen      int
	}{
		{
			name:        "Case1_Basic",
			ikm:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "000102030405060708090a0b0c",
			info:        "f0f1f2f3f4f5f6f7f8f9",
			prkExpected: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			okmExpected: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
			okmLen:      42,
		},
		{
			name:        "Case2_LongerInputs",
			ikm:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt:        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info:        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			prkExpected: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			okmExpected: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
			okmLen:      82,
		},
		{
			name:        "Case3_ZeroLengthSaltInfo",
			ikm:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "", // Empty salt
			info:        "", // Empty info
			prkExpected: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			okmExpected: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
			okmLen:      42,
		},
	}

	// In short mode, only test first 2 vectors
	if testing.Short() {
		vectors = vectors[:2]
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ikm := mustHex(tc.ikm)
			var salt []byte
			if tc.salt != "" {
				salt = mustHex(tc.salt)
			}
			expectedPRK := mustHex(tc.prkExpected)
			expectedOKM := mustHex(tc.okmExpected)

			// Test Extract
			prk, err := Extract(sha256.New, ikm, salt)
			if err != nil {
				t.Fatalf("Extract failed: %v", err)
			}
			if !bytes.Equal(prk, expectedPRK) {
				t.Errorf("PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
			}

			// Test Expand
			info := ""
			if tc.info != "" {
				info = string(mustHex(tc.info))
			}
			okm, err := Expand(sha256.New, prk, info, tc.okmLen)
			if err != nil {
				t.Fatalf("Expand failed: %v", err)
			}
			if !bytes.Equal(okm, expectedOKM) {
				t.Errorf("OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
			}
		})
	}
}

// TestSHA512Vectors tests SHA-512 HKDF with known vectors.
// In -short mode, only the first vector is tested.
func TestSHA512Vectors(t *testing.T) {
	t.Parallel()

	vectors := []struct {
		name        string
		ikm         string
		salt        string
		info        string
		prkExpected string
		okmExpected string
		okmLen      int
	}{
		{
			name:        "Case1_Basic",
			ikm:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "000102030405060708090a0b0c",
			info:        "f0f1f2f3f4f5f6f7f8f9",
			prkExpected: "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
			okmExpected: "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137",
			okmLen:      64,
		},
		{
			name:        "Case2_NilSalt",
			ikm:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "", // nil salt
			info:        "", // empty info
			prkExpected: "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
			okmExpected: "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bacc4e7cb6045faaa698e0e3b3eb91331306def1db8319e",
			okmLen:      64,
		},
		{
			name:        "Case3_LongerInputs",
			ikm:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt:        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info:        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			prkExpected: "35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a",
			okmExpected: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93",
			okmLen:      82,
		},
	}

	// In short mode, only test first vector
	if testing.Short() {
		vectors = vectors[:1]
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ikm := mustHex(tc.ikm)
			var salt []byte
			if tc.salt != "" {
				salt = mustHex(tc.salt)
			}
			expectedPRK := mustHex(tc.prkExpected)
			expectedOKM := mustHex(tc.okmExpected)

			prk, err := Extract(sha512.New, ikm, salt)
			if err != nil {
				t.Fatalf("Extract with SHA-512 failed: %v", err)
			}
			if !bytes.Equal(prk, expectedPRK) {
				t.Errorf("SHA-512 PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
			}

			info := ""
			if tc.info != "" {
				info = string(mustHex(tc.info))
			}
			okm, err := Expand(sha512.New, prk, info, tc.okmLen)
			if err != nil {
				t.Fatalf("Expand with SHA-512 failed: %v", err)
			}
			if !bytes.Equal(okm, expectedOKM) {
				t.Errorf("SHA-512 OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
			}
		})
	}
}

// TestSHA384Vectors tests SHA-384 HKDF with known vectors.
// In -short mode, only the first vector is tested.
func TestSHA384Vectors(t *testing.T) {
	t.Parallel()

	vectors := []struct {
		name        string
		ikm         string
		salt        string
		info        string
		prkExpected string
		okmExpected string
		okmLen      int
	}{
		{
			name:        "Case1_Basic",
			ikm:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "000102030405060708090a0b0c",
			info:        "f0f1f2f3f4f5f6f7f8f9",
			prkExpected: "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade",
			okmExpected: "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5d95d1da3e625",
			okmLen:      48,
		},
		{
			name:        "Case2_NilSalt",
			ikm:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:        "",
			info:        "",
			prkExpected: "10e40cf072a4c5626e43dd22c1cf727d4bb140975c9ad0cbc8e45b40068f8f0ba57cdb598af9dfa6963a96899af047e5",
			okmExpected: "c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242daacc1cea5670415b52849c97c4e787c1f2",
			okmLen:      48,
		},
		{
			name:        "Case3_LongerInputs",
			ikm:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
			salt:        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info:        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			prkExpected: "b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c901efd7de737c85b62e676d4dc87b0895c6a7dc97b52cebb",
			okmExpected: "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649eebf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6f4c09c5500dca24a56222fea53d8967a8b2e",
			okmLen:      82,
		},
	}

	// In short mode, only test first vector
	if testing.Short() {
		vectors = vectors[:1]
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ikm := mustHex(tc.ikm)
			var salt []byte
			if tc.salt != "" {
				salt = mustHex(tc.salt)
			}
			expectedPRK := mustHex(tc.prkExpected)
			expectedOKM := mustHex(tc.okmExpected)

			prk, err := Extract(sha512.New384, ikm, salt)
			if err != nil {
				t.Fatalf("Extract with SHA-384 failed: %v", err)
			}
			if !bytes.Equal(prk, expectedPRK) {
				t.Errorf("SHA-384 PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
			}

			info := ""
			if tc.info != "" {
				info = string(mustHex(tc.info))
			}
			okm, err := Expand(sha512.New384, prk, info, tc.okmLen)
			if err != nil {
				t.Fatalf("Expand with SHA-384 failed: %v", err)
			}
			if !bytes.Equal(okm, expectedOKM) {
				t.Errorf("SHA-384 OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
			}
		})
	}
}

// TestExpandMultipleOutputLengths tests Expand with various output lengths
func TestExpandMultipleOutputLengths(t *testing.T) {
	t.Parallel()

	// SHA-512 PRK from longer inputs test
	prk := mustHex("35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a")
	info := string(mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

	tests := []struct {
		name     string
		length   int
		expected string
	}{
		{
			name:     "L=64_OneSHA512Block",
			length:   64,
			expected: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235",
		},
		{
			name:     "L=128_TwoSHA512Blocks",
			length:   128,
			expected: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a9354e5796284151c2dd39c39b3cd3d8e50fcc383ebdec37476e03b721ef5efef873c281f018b8ca42e1245b2271f87",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expected := mustHex(tc.expected)

			okm, err := Expand(sha512.New, prk, info, tc.length)
			if err != nil {
				t.Fatalf("Expand failed: %v", err)
			}
			if !bytes.Equal(okm, expected) {
				t.Errorf("OKM mismatch:\n  got:  %x\n  want: %x", okm, expected)
			}
		})
	}
}

// TestExpandTooLongOutput tests error handling for excessive output lengths
func TestExpandTooLongOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hashFunc func() hash.Hash
		prk      string
		maxLen   int
	}{
		{
			name:     "SHA256",
			hashFunc: sha256.New,
			prk:      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			maxLen:   255 * 32, // 8160 bytes
		},
		{
			name:     "SHA512",
			hashFunc: sha512.New,
			prk:      "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
			maxLen:   255 * 64, // 16320 bytes
		},
		{
			name:     "SHA384",
			hashFunc: sha512.New384,
			prk:      "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade",
			maxLen:   255 * 48, // 12240 bytes
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prk := mustHex(tc.prk)

			_, err := Expand(tc.hashFunc, prk, "info", tc.maxLen+1)
			if err == nil {
				t.Error("Expected error for length > 255*hash.Size(), got nil")
			}
		})
	}
}

// TestExpandMaximumValidOutput tests the maximum valid output length boundary
func TestExpandMaximumValidOutput(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Skipping maximum output test in short mode")
	}

	prk := mustHex("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")
	maxLen := 255 * 64 // SHA-512 max valid output

	okm, err := Expand(sha512.New, prk, "max output test", maxLen)
	if err != nil {
		t.Fatalf("Expand at max length failed: %v", err)
	}
	if len(okm) != maxLen {
		t.Errorf("OKM length mismatch: got %d, want %d", len(okm), maxLen)
	}

	// Verify first and last 32 bytes
	expectedFirst32 := mustHex("324b9dc70b2be30f12206d3525e3d9d936f09bb9530bbbf8c8f713d1956dfd0a")
	expectedLast32 := mustHex("17bbc29efae5e72dcf5b58be3c86cb4ca6cc6b49b21fe53a8a550be5eb7161d0")

	if !bytes.Equal(okm[:32], expectedFirst32) {
		t.Errorf("First 32 bytes mismatch:\n  got:  %x\n  want: %x", okm[:32], expectedFirst32)
	}
	if !bytes.Equal(okm[len(okm)-32:], expectedLast32) {
		t.Errorf("Last 32 bytes mismatch:\n  got:  %x\n  want: %x", okm[len(okm)-32:], expectedLast32)
	}
}

// TestGenericHashConstraint tests that Extract/Expand work with different hash functions
func TestGenericHashConstraint(t *testing.T) {
	t.Parallel()

	ikm := []byte("input key material")
	salt := []byte("salt")

	tests := []struct {
		name     string
		hashFunc func() hash.Hash
		expected int
	}{
		{"SHA-256", sha256.New, 32},
		{"SHA-384", sha512.New384, 48},
		{"SHA-512", sha512.New, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prk, err := Extract(tt.hashFunc, ikm, salt)
			if err != nil {
				t.Fatalf("Extract failed: %v", err)
			}
			if len(prk) != tt.expected {
				t.Errorf("PRK length mismatch: got %d, want %d", len(prk), tt.expected)
			}

			okm, err := Expand(tt.hashFunc, prk, "info", tt.expected)
			if err != nil {
				t.Fatalf("Expand failed: %v", err)
			}
			if len(okm) != tt.expected {
				t.Errorf("OKM length mismatch: got %d, want %d", len(okm), tt.expected)
			}
		})
	}
}

// TestExtractThenExpand tests determinism of Extract + Expand round-trip
func TestExtractThenExpand(t *testing.T) {
	t.Parallel()

	ikm := []byte("secret input key material for testing purposes")
	salt := []byte("optional salt value")
	info := "application specific context"

	prk, err := Extract(sha256.New, ikm, salt)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	okm1, err := Expand(sha256.New, prk, info, 64)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}

	// Same inputs should produce same output (deterministic)
	prk2, err := Extract(sha256.New, ikm, salt)
	if err != nil {
		t.Fatalf("Extract (2nd call) failed: %v", err)
	}

	okm2, err := Expand(sha256.New, prk2, info, 64)
	if err != nil {
		t.Fatalf("Expand (2nd call) failed: %v", err)
	}

	if !bytes.Equal(okm1, okm2) {
		t.Error("HKDF is not deterministic - same inputs produced different outputs")
	}
}

// TestDifferentInfoProducesDifferentOutput tests that different info produces different output
func TestDifferentInfoProducesDifferentOutput(t *testing.T) {
	t.Parallel()

	prk := mustHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

	okm1, err := Expand(sha256.New, prk, "info1", 32)
	if err != nil {
		t.Fatalf("Expand 1 failed: %v", err)
	}

	okm2, err := Expand(sha256.New, prk, "info2", 32)
	if err != nil {
		t.Fatalf("Expand 2 failed: %v", err)
	}

	if bytes.Equal(okm1, okm2) {
		t.Error("Different info strings produced identical output")
	}
}

// Benchmark tests
func BenchmarkExtractSHA256(b *testing.B) {
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex("000102030405060708090a0b0c")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Extract(sha256.New, ikm, salt)
	}
}

func BenchmarkExpandSHA256_32(b *testing.B) {
	prk := mustHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	info := "test info"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Expand(sha256.New, prk, info, 32)
	}
}

func BenchmarkExpandSHA256_128(b *testing.B) {
	prk := mustHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	info := "test info"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Expand(sha256.New, prk, info, 128)
	}
}
