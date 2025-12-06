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

// Test Case 1 from RFC 5869
func TestExtractRFC5869Case1(t *testing.T) {
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex("000102030405060708090a0b0c")
	expectedPRK := mustHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

	prk, err := Extract(sha256.New, ikm, salt)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandRFC5869Case1(t *testing.T) {
	prk := mustHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	info := string(mustHex("f0f1f2f3f4f5f6f7f8f9"))
	expectedOKM := mustHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	okm, err := Expand(sha256.New, prk, info, 42)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
	}
}

// Test Case 2 from RFC 5869 - Longer inputs/outputs
func TestExtractRFC5869Case2(t *testing.T) {
	ikm := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt := mustHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	expectedPRK := mustHex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")

	prk, err := Extract(sha256.New, ikm, salt)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandRFC5869Case2(t *testing.T) {
	prk := mustHex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
	info := string(mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
	expectedOKM := mustHex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")

	okm, err := Expand(sha256.New, prk, info, 82)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
	}
}

// Test Case 3 from RFC 5869 - Zero-length salt/info
func TestExtractRFC5869Case3(t *testing.T) {
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	expectedPRK := mustHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")

	// Empty salt
	prk, err := Extract(sha256.New, ikm, nil)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandRFC5869Case3(t *testing.T) {
	prk := mustHex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
	expectedOKM := mustHex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")

	// Empty info
	okm, err := Expand(sha256.New, prk, "", 42)
	if err != nil {
		t.Fatalf("Expand failed: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
	}
}

// Test Case 4 from RFC 5869 - SHA-1 (for completeness, but we mainly use SHA-256/384)
// Skipped as crypto/hkdf uses sha1 differently

// Test Case 5 from RFC 5869 - SHA-1 with longer inputs
// Skipped for the same reason

// SHA-512 Known Vector Tests
// These vectors use RFC 5869 Case 1 inputs applied to SHA-512.
// Expected values independently verified with:
// - Go's crypto/hkdf package (Go 1.25+)
// - Python's cryptography library (HKDF and HMAC modules)
// Cross-verification confirms cryptographic correctness.

func TestExtractSHA512KnownVector(t *testing.T) {
	// Using RFC 5869 Case 1 inputs with SHA-512
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex("000102030405060708090a0b0c")

	// Expected PRK computed with Python: hmac.new(salt, ikm, hashlib.sha512).digest()
	// Cross-verified with Go's crypto/hkdf.Extract
	expectedPRK := mustHex("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")

	prk, err := Extract(sha512.New, ikm, salt)
	if err != nil {
		t.Fatalf("Extract with SHA-512 failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("SHA-512 PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandSHA512KnownVector(t *testing.T) {
	// PRK from TestExtractSHA512KnownVector
	prk := mustHex("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")
	info := string(mustHex("f0f1f2f3f4f5f6f7f8f9"))

	// Expected OKM computed with Python's cryptography.hazmat.primitives.kdf.hkdf
	// Cross-verified with Go's crypto/hkdf.Expand
	expectedOKM := mustHex("832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137")

	okm, err := Expand(sha512.New, prk, info, 64)
	if err != nil {
		t.Fatalf("Expand with SHA-512 failed: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("SHA-512 OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
	}
}

// SHA-512 with nil salt (RFC 5869 Case 3 pattern)
func TestExtractSHA512NilSalt(t *testing.T) {
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")

	// When salt is nil, HKDF uses a string of zeros of hash length
	// Expected PRK computed with Python: hmac.new(bytes(64), ikm, hashlib.sha512).digest()
	expectedPRK := mustHex("fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6")

	prk, err := Extract(sha512.New, ikm, nil)
	if err != nil {
		t.Fatalf("Extract with SHA-512 nil salt failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("SHA-512 PRK (nil salt) mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandSHA512EmptyInfo(t *testing.T) {
	// PRK from TestExtractSHA512NilSalt
	prk := mustHex("fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6")

	// Expected OKM with empty info
	expectedOKM := mustHex("f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90fff22d04836d0e2343bacc4e7cb6045faaa698e0e3b3eb91331306def1db8319e")

	okm, err := Expand(sha512.New, prk, "", 64)
	if err != nil {
		t.Fatalf("Expand with SHA-512 empty info failed: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("SHA-512 OKM (empty info) mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
	}
}

// SHA-512 Case 2 Pattern: Longer inputs/outputs
// Using RFC 5869 Appendix A Case 2 inputs applied to SHA-512.
// Expected values computed with Go's crypto/hkdf and cross-verified with Python's cryptography library.

func TestExtractSHA512LongerInputs(t *testing.T) {
	// RFC 5869 Case 2 inputs (80 bytes each)
	ikm := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt := mustHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	// Expected PRK computed with Go crypto/hkdf and Python cryptography library
	expectedPRK := mustHex("35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a")

	prk, err := Extract(sha512.New, ikm, salt)
	if err != nil {
		t.Fatalf("Extract with SHA-512 (longer inputs) failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("SHA-512 PRK (longer inputs) mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandSHA512LongerInputs(t *testing.T) {
	// PRK from TestExtractSHA512LongerInputs
	prk := mustHex("35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a")
	// RFC 5869 Case 2 info (80 bytes)
	info := string(mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

	// Test L=82 (same as RFC 5869 Case 2)
	expectedOKM82 := mustHex("ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a93")

	okm82, err := Expand(sha512.New, prk, info, 82)
	if err != nil {
		t.Fatalf("Expand with SHA-512 L=82 failed: %v", err)
	}
	if !bytes.Equal(okm82, expectedOKM82) {
		t.Errorf("SHA-512 OKM L=82 mismatch:\n  got:  %x\n  want: %x", okm82, expectedOKM82)
	}
}

func TestExpandSHA512MultipleOutputLengths(t *testing.T) {
	// PRK from TestExtractSHA512LongerInputs
	prk := mustHex("35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a")
	info := string(mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

	tests := []struct {
		name     string
		length   int
		expected string
	}{
		{
			name:     "L=64 (one SHA-512 block)",
			length:   64,
			expected: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235",
		},
		{
			name:     "L=128 (two SHA-512 blocks)",
			length:   128,
			expected: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a9354e5796284151c2dd39c39b3cd3d8e50fcc383ebdec37476e03b721ef5efef873c281f018b8ca42e1245b2271f87",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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

// SHA-384 Known Vector Tests
// These vectors use RFC 5869 Case 1 inputs applied to SHA-384.
// Expected values independently verified with Python's cryptography library.

func TestExtractSHA384KnownVector(t *testing.T) {
	// Using RFC 5869 Case 1 inputs with SHA-384
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex("000102030405060708090a0b0c")

	// Expected PRK computed with Python: hmac.new(salt, ikm, hashlib.sha384).digest()
	expectedPRK := mustHex("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade")

	prk, err := Extract(sha512.New384, ikm, salt)
	if err != nil {
		t.Fatalf("Extract with SHA-384 failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("SHA-384 PRK mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandSHA384KnownVector(t *testing.T) {
	// PRK from TestExtractSHA384KnownVector
	prk := mustHex("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade")
	info := string(mustHex("f0f1f2f3f4f5f6f7f8f9"))

	// Expected OKM computed with Python's cryptography.hazmat.primitives.kdf.hkdf
	expectedOKM := mustHex("9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5d95d1da3e625")

	okm, err := Expand(sha512.New384, prk, info, 48)
	if err != nil {
		t.Fatalf("Expand with SHA-384 failed: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("SHA-384 OKM mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
	}
}

// SHA-384 with nil salt (RFC 5869 Case 3 pattern)
func TestExtractSHA384NilSalt(t *testing.T) {
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")

	// When salt is nil, HKDF uses a string of zeros of hash length
	// Expected PRK computed with Python: hmac.new(bytes(48), ikm, hashlib.sha384).digest()
	expectedPRK := mustHex("10e40cf072a4c5626e43dd22c1cf727d4bb140975c9ad0cbc8e45b40068f8f0ba57cdb598af9dfa6963a96899af047e5")

	prk, err := Extract(sha512.New384, ikm, nil)
	if err != nil {
		t.Fatalf("Extract with SHA-384 nil salt failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("SHA-384 PRK (nil salt) mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandSHA384EmptyInfo(t *testing.T) {
	// PRK from TestExtractSHA384NilSalt
	prk := mustHex("10e40cf072a4c5626e43dd22c1cf727d4bb140975c9ad0cbc8e45b40068f8f0ba57cdb598af9dfa6963a96899af047e5")

	// Expected OKM with empty info
	expectedOKM := mustHex("c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242daacc1cea5670415b52849c97c4e787c1f2")

	okm, err := Expand(sha512.New384, prk, "", 48)
	if err != nil {
		t.Fatalf("Expand with SHA-384 empty info failed: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Errorf("SHA-384 OKM (empty info) mismatch:\n  got:  %x\n  want: %x", okm, expectedOKM)
	}
}

// SHA-384 Case 2 Pattern: Longer inputs/outputs
// Using RFC 5869 Appendix A Case 2 inputs applied to SHA-384.
// Expected values computed with Go's crypto/hkdf and cross-verified with Python's cryptography library.

func TestExtractSHA384LongerInputs(t *testing.T) {
	// RFC 5869 Case 2 inputs (80 bytes each)
	ikm := mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
	salt := mustHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")

	// Expected PRK computed with Go crypto/hkdf and Python cryptography library
	expectedPRK := mustHex("b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c901efd7de737c85b62e676d4dc87b0895c6a7dc97b52cebb")

	prk, err := Extract(sha512.New384, ikm, salt)
	if err != nil {
		t.Fatalf("Extract with SHA-384 (longer inputs) failed: %v", err)
	}
	if !bytes.Equal(prk, expectedPRK) {
		t.Errorf("SHA-384 PRK (longer inputs) mismatch:\n  got:  %x\n  want: %x", prk, expectedPRK)
	}
}

func TestExpandSHA384LongerInputs(t *testing.T) {
	// PRK from TestExtractSHA384LongerInputs
	prk := mustHex("b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c901efd7de737c85b62e676d4dc87b0895c6a7dc97b52cebb")
	// RFC 5869 Case 2 info (80 bytes)
	info := string(mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

	// Test L=82 (same as RFC 5869 Case 2)
	expectedOKM82 := mustHex("484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649eebf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6f4c09c5500dca24a56222fea53d8967a8b2e")

	okm82, err := Expand(sha512.New384, prk, info, 82)
	if err != nil {
		t.Fatalf("Expand with SHA-384 L=82 failed: %v", err)
	}
	if !bytes.Equal(okm82, expectedOKM82) {
		t.Errorf("SHA-384 OKM L=82 mismatch:\n  got:  %x\n  want: %x", okm82, expectedOKM82)
	}
}

func TestExpandSHA384MultipleOutputLengths(t *testing.T) {
	// PRK from TestExtractSHA384LongerInputs
	prk := mustHex("b319f6831dff9314efb643baa29263b30e4a8d779fe31e9c901efd7de737c85b62e676d4dc87b0895c6a7dc97b52cebb")
	info := string(mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))

	tests := []struct {
		name     string
		length   int
		expected string
	}{
		{
			name:     "L=48 (one SHA-384 block)",
			length:   48,
			expected: "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649eebf69f8d5c832856bf4e4fbc17967d549",
		},
		{
			name:     "L=96 (two SHA-384 blocks)",
			length:   96,
			expected: "484ca052b8cc724fd1c4ec64d57b4e818c7e25a8e0f4569ed72a6a05fe0649eebf69f8d5c832856bf4e4fbc17967d54975324a94987f7f41835817d8994fdbd6f4c09c5500dca24a56222fea53d8967a8b2e2a125bbbd822a84eb77be82dfd76",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expected := mustHex(tc.expected)

			okm, err := Expand(sha512.New384, prk, info, tc.length)
			if err != nil {
				t.Fatalf("Expand failed: %v", err)
			}
			if !bytes.Equal(okm, expected) {
				t.Errorf("OKM mismatch:\n  got:  %x\n  want: %x", okm, expected)
			}
		})
	}
}

// Edge cases and error conditions
// Note: Go's underlying crypto/hkdf library panics on invalid lengths (<=0 or >255*hashSize)
// rather than returning errors. We test only for the too-long case which returns an error.

func TestExpandTooLongOutput(t *testing.T) {
	prk := mustHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

	// SHA-256 max output = 255 * 32 = 8160 bytes
	// Requesting more should fail
	_, err := Expand(sha256.New, prk, "info", 255*32+1)
	if err == nil {
		t.Error("Expected error for length > 255*hash.Size(), got nil")
	}
}

func TestExpandTooLongOutputSHA512(t *testing.T) {
	prk := mustHex("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")

	// SHA-512 max output = 255 * 64 = 16320 bytes
	// Requesting more should fail
	_, err := Expand(sha512.New, prk, "info", 255*64+1)
	if err == nil {
		t.Error("Expected error for SHA-512 length > 255*hash.Size(), got nil")
	}
}

func TestExpandTooLongOutputSHA384(t *testing.T) {
	prk := mustHex("704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade")

	// SHA-384 max output = 255 * 48 = 12240 bytes
	// Requesting more should fail
	_, err := Expand(sha512.New384, prk, "info", 255*48+1)
	if err == nil {
		t.Error("Expected error for SHA-384 length > 255*hash.Size(), got nil")
	}
}

// Test maximum valid output length for SHA-512
// This verifies the boundary condition (255 * hashSize)
func TestExpandMaximumValidOutputSHA512(t *testing.T) {
	// Use PRK from Case 1 SHA-512 test
	prk := mustHex("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")

	// SHA-512 max valid output = 255 * 64 = 16320 bytes
	maxLen := 255 * 64

	okm, err := Expand(sha512.New, prk, "max output test", maxLen)
	if err != nil {
		t.Fatalf("Expand at max length failed: %v", err)
	}
	if len(okm) != maxLen {
		t.Errorf("OKM length mismatch: got %d, want %d", len(okm), maxLen)
	}

	// Verify first 32 bytes match expected value (computed with Go crypto/hkdf)
	expectedFirst32 := mustHex("324b9dc70b2be30f12206d3525e3d9d936f09bb9530bbbf8c8f713d1956dfd0a")
	if !bytes.Equal(okm[:32], expectedFirst32) {
		t.Errorf("First 32 bytes mismatch:\n  got:  %x\n  want: %x", okm[:32], expectedFirst32)
	}

	// Verify last 32 bytes match expected value (computed with Go crypto/hkdf)
	expectedLast32 := mustHex("17bbc29efae5e72dcf5b58be3c86cb4ca6cc6b49b21fe53a8a550be5eb7161d0")
	if !bytes.Equal(okm[len(okm)-32:], expectedLast32) {
		t.Errorf("Last 32 bytes mismatch:\n  got:  %x\n  want: %x", okm[len(okm)-32:], expectedLast32)
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

// Test with different hash function types to verify generic constraint
func TestGenericHashConstraint(t *testing.T) {
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

// Test ExtractThenExpand round-trip
func TestExtractThenExpand(t *testing.T) {
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

// Test that different info produces different output
func TestDifferentInfoProducesDifferentOutput(t *testing.T) {
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
