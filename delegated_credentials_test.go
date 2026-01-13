// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestDCParseMalformedInputs tests parsing with various malformed inputs
func TestDCParseMalformedInputs(t *testing.T) {
	testCases := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "too short",
		},
		{
			name:    "exactly 8 bytes (below minimum)",
			data:    make([]byte, 8),
			wantErr: "too short",
		},
		{
			name:    "9 bytes with zero SPKI length",
			data:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0},
			wantErr: "SPKI length",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDelegatedCredential(tc.data)
			if err == nil {
				t.Errorf("expected error containing %q, got nil", tc.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestDCParseValidECDSA tests parsing a valid ECDSA-based DC
func TestDCParseValidECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	validTime := uint32(3600)
	expectedAlgo := uint16(ECDSAWithP256AndSHA256)
	sigAlgo := uint16(ECDSAWithP256AndSHA256)
	signature := make([]byte, 71)
	rand.Read(signature)

	// Build wire format
	credLen := 4 + 2 + 3 + len(spki)
	totalLen := credLen + 2 + 2 + len(signature)
	data := make([]byte, totalLen)

	offset := 0
	binary.BigEndian.PutUint32(data[offset:], validTime)
	offset += 4
	binary.BigEndian.PutUint16(data[offset:], expectedAlgo)
	offset += 2
	data[offset] = byte(len(spki) >> 16)
	data[offset+1] = byte(len(spki) >> 8)
	data[offset+2] = byte(len(spki))
	offset += 3
	copy(data[offset:], spki)
	offset += len(spki)
	binary.BigEndian.PutUint16(data[offset:], sigAlgo)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(signature)))
	offset += 2
	copy(data[offset:], signature)

	dc, err := parseDelegatedCredential(data)
	if err != nil {
		t.Fatalf("Failed to parse DC: %v", err)
	}

	if dc.ValidTime != validTime {
		t.Errorf("ValidTime = %d, want %d", dc.ValidTime, validTime)
	}
	if dc.ExpectedCertVerifyAlgorithm != SignatureScheme(expectedAlgo) {
		t.Errorf("ExpectedCertVerifyAlgorithm = %d, want %d", dc.ExpectedCertVerifyAlgorithm, expectedAlgo)
	}
	if dc.Algorithm != SignatureScheme(sigAlgo) {
		t.Errorf("Algorithm = %d, want %d", dc.Algorithm, sigAlgo)
	}
	if dc.PublicKey() == nil {
		t.Error("PublicKey() returned nil")
	}
	if _, ok := dc.PublicKey().(*ecdsa.PublicKey); !ok {
		t.Errorf("PublicKey type = %T, want *ecdsa.PublicKey", dc.PublicKey())
	}
}

// TestDCParseTrailingData verifies trailing data is rejected
func TestDCParseTrailingData(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	validTime := uint32(3600)
	expectedAlgo := uint16(ECDSAWithP256AndSHA256)
	sigAlgo := uint16(ECDSAWithP256AndSHA256)
	signature := make([]byte, 71)
	rand.Read(signature)

	// Build wire format with trailing garbage
	credLen := 4 + 2 + 3 + len(spki)
	totalLen := credLen + 2 + 2 + len(signature)
	data := make([]byte, totalLen+10) // Extra 10 bytes

	offset := 0
	binary.BigEndian.PutUint32(data[offset:], validTime)
	offset += 4
	binary.BigEndian.PutUint16(data[offset:], expectedAlgo)
	offset += 2
	data[offset] = byte(len(spki) >> 16)
	data[offset+1] = byte(len(spki) >> 8)
	data[offset+2] = byte(len(spki))
	offset += 3
	copy(data[offset:], spki)
	offset += len(spki)
	binary.BigEndian.PutUint16(data[offset:], sigAlgo)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(signature)))
	offset += 2
	copy(data[offset:], signature)

	_, err = parseDelegatedCredential(data)
	if err == nil {
		t.Error("Expected error for trailing data, got nil")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Errorf("Error should mention trailing data: %v", err)
	}
}

// TestDCValidityPeriod tests the IsValid method
func TestDCValidityPeriod(t *testing.T) {
	dc := &DelegatedCredential{
		ValidTime: 3600, // 1 hour
	}

	certNotBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	testCases := []struct {
		name      string
		now       time.Time
		wantValid bool
	}{
		{
			name:      "exactly at notBefore",
			now:       certNotBefore,
			wantValid: true,
		},
		{
			name:      "1 second before notBefore",
			now:       certNotBefore.Add(-time.Second),
			wantValid: false,
		},
		{
			name:      "middle of validity period",
			now:       certNotBefore.Add(30 * time.Minute),
			wantValid: true,
		},
		{
			name:      "exactly at expiry",
			now:       certNotBefore.Add(time.Duration(dc.ValidTime) * time.Second),
			wantValid: false,
		},
		{
			name:      "1 second after expiry",
			now:       certNotBefore.Add(time.Duration(dc.ValidTime)*time.Second + time.Second),
			wantValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid := dc.IsValid(certNotBefore, tc.now)
			if valid != tc.wantValid {
				t.Errorf("IsValid() = %v, want %v", valid, tc.wantValid)
			}
		})
	}
}

// TestDCTTLValidation tests the IsValidTTL method
func TestDCTTLValidation(t *testing.T) {
	testCases := []struct {
		name      string
		validTime uint32
		wantValid bool
	}{
		{
			name:      "zero TTL",
			validTime: 0,
			wantValid: true,
		},
		{
			name:      "1 hour",
			validTime: 3600,
			wantValid: true,
		},
		{
			name:      "exactly 7 days",
			validTime: 7 * 24 * 60 * 60,
			wantValid: true,
		},
		{
			name:      "7 days + 1 second",
			validTime: 7*24*60*60 + 1,
			wantValid: false,
		},
		{
			name:      "max uint32",
			validTime: 0xFFFFFFFF,
			wantValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := &DelegatedCredential{ValidTime: tc.validTime}
			valid := dc.IsValidTTL()
			if valid != tc.wantValid {
				t.Errorf("IsValidTTL() = %v, want %v", valid, tc.wantValid)
			}
		})
	}
}

// TestDCAlgorithmCompatibility tests algorithm compatibility checking
func TestDCAlgorithmCompatibility(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader) // Note: first return is public key
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	testCases := []struct {
		name      string
		pubKey    interface{}
		sigAlgo   SignatureScheme
		wantError bool
	}{
		{
			name:      "ECDSA key with ECDSA algo",
			pubKey:    &ecdsaKey.PublicKey,
			sigAlgo:   ECDSAWithP256AndSHA256,
			wantError: false,
		},
		{
			name:      "ECDSA key with RSA algo",
			pubKey:    &ecdsaKey.PublicKey,
			sigAlgo:   PSSWithSHA256,
			wantError: true,
		},
		{
			name:      "RSA key with PSS algo",
			pubKey:    &rsaKey.PublicKey,
			sigAlgo:   PSSWithSHA256,
			wantError: false,
		},
		{
			name:      "RSA key with ECDSA algo",
			pubKey:    &rsaKey.PublicKey,
			sigAlgo:   ECDSAWithP256AndSHA256,
			wantError: true,
		},
		{
			name:      "Ed25519 key with Ed25519 algo",
			pubKey:    ed25519PubKey,
			sigAlgo:   Ed25519,
			wantError: false,
		},
		{
			name:      "Ed25519 key with ECDSA algo",
			pubKey:    ed25519PubKey,
			sigAlgo:   ECDSAWithP256AndSHA256,
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := &DelegatedCredential{
				ExpectedCertVerifyAlgorithm: tc.sigAlgo,
				publicKey:                   tc.pubKey,
			}
			err := verifyDCCertVerifyAlgorithm(dc)
			hasError := err != nil
			if hasError != tc.wantError {
				t.Errorf("verifyDCCertVerifyAlgorithm() error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}

// TestDCHasDelegationUsage tests the DelegationUsage extension and digitalSignature KeyUsage check.
// Per RFC 9345 Section 4.2, certificates used for delegated credentials MUST have:
// 1. The digitalSignature KeyUsage bit set
// 2. The DelegationUsage extension present
func TestDCHasDelegationUsage(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testCases := []struct {
		name           string
		keyUsage       x509.KeyUsage
		hasDUExtension bool
		expectResult   bool
	}{
		{
			name:           "no DelegationUsage, no digitalSignature",
			keyUsage:       0,
			hasDUExtension: false,
			expectResult:   false,
		},
		{
			name:           "with DelegationUsage, no digitalSignature",
			keyUsage:       0,
			hasDUExtension: true,
			expectResult:   false, // RFC 9345: digitalSignature KeyUsage is required
		},
		{
			name:           "no DelegationUsage, with digitalSignature",
			keyUsage:       x509.KeyUsageDigitalSignature,
			hasDUExtension: false,
			expectResult:   false, // DelegationUsage extension is required
		},
		{
			name:           "with DelegationUsage, with digitalSignature",
			keyUsage:       x509.KeyUsageDigitalSignature,
			hasDUExtension: true,
			expectResult:   true, // Both requirements satisfied
		},
		{
			name:           "with DelegationUsage, with digitalSignature and other usages",
			keyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			hasDUExtension: true,
			expectResult:   true, // digitalSignature is present, other usages don't affect it
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "Test " + tc.name},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:     tc.keyUsage,
			}

			if tc.hasDUExtension {
				template.ExtraExtensions = []pkix.Extension{
					{
						Id:       delegationUsageOID,
						Critical: false,
						Value:    []byte{},
					},
				}
			}

			certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
			if err != nil {
				t.Fatalf("Failed to create certificate: %v", err)
			}
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("Failed to parse certificate: %v", err)
			}

			result := hasDelegationUsage(cert)
			if result != tc.expectResult {
				t.Errorf("hasDelegationUsage() = %v, want %v", result, tc.expectResult)
			}
		})
	}
}

// TestDCCredentialBytes tests the credential serialization
func TestDCCredentialBytes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	dc := &DelegatedCredential{
		ValidTime:                   3600,
		ExpectedCertVerifyAlgorithm: ECDSAWithP256AndSHA256,
		SubjectPublicKeyInfo:        spki,
	}

	cred := dc.credentialBytes()

	expectedLen := 4 + 2 + 3 + len(spki)
	if len(cred) != expectedLen {
		t.Errorf("credentialBytes() len = %d, want %d", len(cred), expectedLen)
	}

	validTime := binary.BigEndian.Uint32(cred[0:4])
	if validTime != dc.ValidTime {
		t.Errorf("ValidTime = %d, want %d", validTime, dc.ValidTime)
	}

	algo := SignatureScheme(binary.BigEndian.Uint16(cred[4:6]))
	if algo != dc.ExpectedCertVerifyAlgorithm {
		t.Errorf("Algorithm = %d, want %d", algo, dc.ExpectedCertVerifyAlgorithm)
	}

	spkiLen := int(cred[6])<<16 | int(cred[7])<<8 | int(cred[8])
	if spkiLen != len(spki) {
		t.Errorf("SPKI length = %d, want %d", spkiLen, len(spki))
	}
}

// TestDCVerifyWithoutDelegationUsage tests that verification fails without DelegationUsage
func TestDCVerifyWithoutDelegationUsage(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Certificate without DelegationUsage
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test No DU"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	dc := &DelegatedCredential{
		ValidTime:                   3600,
		ExpectedCertVerifyAlgorithm: ECDSAWithP256AndSHA256,
		Algorithm:                   ECDSAWithP256AndSHA256,
	}

	err = dc.Verify(cert)
	if err == nil {
		t.Error("Expected error when verifying DC against cert without DelegationUsage")
	}
	if !strings.Contains(err.Error(), "DelegationUsage") {
		t.Errorf("Error should mention DelegationUsage: %v", err)
	}
}

// TestDCParseEd25519 tests parsing an Ed25519-based DC
func TestDCParseEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	validTime := uint32(3600)
	expectedAlgo := uint16(Ed25519)
	sigAlgo := uint16(Ed25519)
	signature := make([]byte, 64) // Ed25519 signature size
	rand.Read(signature)

	// Build wire format
	credLen := 4 + 2 + 3 + len(spki)
	totalLen := credLen + 2 + 2 + len(signature)
	data := make([]byte, totalLen)

	offset := 0
	binary.BigEndian.PutUint32(data[offset:], validTime)
	offset += 4
	binary.BigEndian.PutUint16(data[offset:], expectedAlgo)
	offset += 2
	data[offset] = byte(len(spki) >> 16)
	data[offset+1] = byte(len(spki) >> 8)
	data[offset+2] = byte(len(spki))
	offset += 3
	copy(data[offset:], spki)
	offset += len(spki)
	binary.BigEndian.PutUint16(data[offset:], sigAlgo)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(signature)))
	offset += 2
	copy(data[offset:], signature)

	dc, err := parseDelegatedCredential(data)
	if err != nil {
		t.Fatalf("Failed to parse DC: %v", err)
	}

	if _, ok := dc.PublicKey().(ed25519.PublicKey); !ok {
		t.Errorf("PublicKey type = %T, want ed25519.PublicKey", dc.PublicKey())
	}
}

// TestDCParseRSA tests parsing an RSA-based DC
func TestDCParseRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	validTime := uint32(3600)
	expectedAlgo := uint16(PSSWithSHA256)
	sigAlgo := uint16(PSSWithSHA256)
	signature := make([]byte, 256) // RSA-2048 signature size
	rand.Read(signature)

	// Build wire format
	credLen := 4 + 2 + 3 + len(spki)
	totalLen := credLen + 2 + 2 + len(signature)
	data := make([]byte, totalLen)

	offset := 0
	binary.BigEndian.PutUint32(data[offset:], validTime)
	offset += 4
	binary.BigEndian.PutUint16(data[offset:], expectedAlgo)
	offset += 2
	data[offset] = byte(len(spki) >> 16)
	data[offset+1] = byte(len(spki) >> 8)
	data[offset+2] = byte(len(spki))
	offset += 3
	copy(data[offset:], spki)
	offset += len(spki)
	binary.BigEndian.PutUint16(data[offset:], sigAlgo)
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(signature)))
	offset += 2
	copy(data[offset:], signature)

	dc, err := parseDelegatedCredential(data)
	if err != nil {
		t.Fatalf("Failed to parse DC: %v", err)
	}

	if _, ok := dc.PublicKey().(*rsa.PublicKey); !ok {
		t.Errorf("PublicKey type = %T, want *rsa.PublicKey", dc.PublicKey())
	}
}
