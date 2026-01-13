// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// delegationUsageOID is the OID for the DelegationUsage X.509 extension
// that marks a certificate as eligible to issue delegated credentials.
// OID: 1.3.6.1.4.1.44363.44 per RFC 9345 Section 4.2
var delegationUsageOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}

// dcMaxTTLSeconds is the maximum allowed validity period for a delegated credential.
// RFC 9345 Section 4.1 specifies 7 days maximum.
const dcMaxTTLSeconds = 7 * 24 * 60 * 60

// dcSignaturePrefix is the 64-byte prefix of 0x20 (space) used in DC signature computation.
// Per RFC 9345 Section 4.1.1, the signature is computed over this prefix followed by
// the context string, a null byte, the certificate, credential, and algorithm.
var dcSignaturePrefix = bytes.Repeat([]byte{0x20}, 64)

// dcServerContextString is the context string for server delegated credentials.
// Per RFC 9345 Section 4.1.1: "TLS, server delegated credentials" (33 bytes).
var dcServerContextString = []byte("TLS, server delegated credentials")

// dcClientContextString is the context string for client delegated credentials.
// Per RFC 9345 Section 4.1.1: "TLS, client delegated credentials" (33 bytes).
var dcClientContextString = []byte("TLS, client delegated credentials")

// DelegatedCredential represents a delegated credential per RFC 9345.
// A delegated credential allows a TLS server to use a short-lived key pair
// that is delegated from the main certificate's key, enabling more flexible
// key management and limiting the exposure window of compromised keys.
type DelegatedCredential struct {
	// ValidTime is the validity period in seconds from the certificate's notBefore.
	// Maximum allowed is 7 days (604800 seconds) per RFC 9345.
	ValidTime uint32

	// ExpectedCertVerifyAlgorithm is the signature algorithm that the DC
	// credential public key will use in CertificateVerify.
	ExpectedCertVerifyAlgorithm SignatureScheme

	// SubjectPublicKeyInfo is the DER-encoded SPKI of the DC's public key.
	SubjectPublicKeyInfo []byte

	// Algorithm is the signature algorithm used to sign the DC.
	Algorithm SignatureScheme

	// Signature is the signature over the credential by the certificate's key.
	Signature []byte

	// Raw is the raw wire format of the entire DC (credential + signature).
	Raw []byte

	// publicKey is the cached parsed public key from SubjectPublicKeyInfo.
	publicKey crypto.PublicKey
}

// parseDelegatedCredential parses a DC from wire format per RFC 9345 Section 4.
// Wire format:
//
//	struct {
//	    Credential cred;
//	    SignatureScheme algorithm;
//	    opaque signature<0..2^16-1>;
//	} DelegatedCredential;
//
//	struct {
//	    uint32 valid_time;
//	    SignatureScheme dc_cert_verify_algorithm;
//	    opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
//	} Credential;
func parseDelegatedCredential(data []byte) (*DelegatedCredential, error) {
	if len(data) < 4+2+3 { // valid_time + algo + min SPKI len prefix
		return nil, errors.New("tls: delegated credential too short")
	}

	dc := &DelegatedCredential{
		Raw: data,
	}

	offset := 0

	// ValidTime (4 bytes)
	dc.ValidTime = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// ExpectedCertVerifyAlgorithm (2 bytes)
	dc.ExpectedCertVerifyAlgorithm = SignatureScheme(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// SubjectPublicKeyInfo length (3 bytes) + data
	if len(data) < offset+3 {
		return nil, errors.New("tls: delegated credential truncated at SPKI length")
	}
	spkiLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	if spkiLen == 0 || spkiLen > 0xFFFFFF {
		return nil, errors.New("tls: invalid delegated credential SPKI length")
	}
	if len(data) < offset+spkiLen {
		return nil, errors.New("tls: delegated credential SPKI truncated")
	}
	dc.SubjectPublicKeyInfo = data[offset : offset+spkiLen]
	offset += spkiLen

	// Parse the public key from SPKI
	pub, err := x509.ParsePKIXPublicKey(dc.SubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("tls: invalid delegated credential public key: %w", err)
	}
	dc.publicKey = pub

	// Signature algorithm (2 bytes)
	if len(data) < offset+2 {
		return nil, errors.New("tls: delegated credential truncated at signature algorithm")
	}
	dc.Algorithm = SignatureScheme(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Signature length (2 bytes) + signature data
	if len(data) < offset+2 {
		return nil, errors.New("tls: delegated credential truncated at signature length")
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if len(data) < offset+sigLen {
		return nil, errors.New("tls: delegated credential signature truncated")
	}
	dc.Signature = data[offset : offset+sigLen]
	offset += sigLen

	// Verify we consumed all data (no trailing garbage)
	if offset != len(data) {
		return nil, errors.New("tls: delegated credential has trailing data")
	}

	return dc, nil
}

// credentialBytes returns the credential portion of the DC (without signature).
// This is used to construct the signed message for verification.
func (dc *DelegatedCredential) credentialBytes() []byte {
	// Credential = valid_time || dc_cert_verify_algorithm || SPKI
	// SPKI is prefixed with 3-byte length
	credLen := 4 + 2 + 3 + len(dc.SubjectPublicKeyInfo)
	cred := make([]byte, credLen)

	offset := 0
	binary.BigEndian.PutUint32(cred[offset:], dc.ValidTime)
	offset += 4
	binary.BigEndian.PutUint16(cred[offset:], uint16(dc.ExpectedCertVerifyAlgorithm))
	offset += 2
	cred[offset] = byte(len(dc.SubjectPublicKeyInfo) >> 16)
	cred[offset+1] = byte(len(dc.SubjectPublicKeyInfo) >> 8)
	cred[offset+2] = byte(len(dc.SubjectPublicKeyInfo))
	offset += 3
	copy(cred[offset:], dc.SubjectPublicKeyInfo)

	return cred
}

// Verify verifies the DC signature against the parent certificate.
// Per RFC 9345 Section 4.1.1, the signed message is computed over:
//  1. 64 bytes of 0x20 (space character)
//  2. Context string "TLS, server delegated credentials" (33 bytes)
//  3. Single 0x00 byte separator
//  4. DER-encoded X.509 end-entity certificate
//  5. DelegatedCredential.cred (valid_time + expected_cert_verify_algorithm + SPKI)
//  6. DelegatedCredential.algorithm (2 bytes)
func (dc *DelegatedCredential) Verify(cert *x509.Certificate) error {
	return dc.verify(cert, false)
}

// VerifyClient verifies the DC signature for client-side delegated credentials.
// Uses the client context string per RFC 9345 Section 4.1.1.
func (dc *DelegatedCredential) VerifyClient(cert *x509.Certificate) error {
	return dc.verify(cert, true)
}

// verify is the internal verification function that handles both server and client DCs.
func (dc *DelegatedCredential) verify(cert *x509.Certificate, isClient bool) error {
	// RFC 9345 Section 4.2: rsaEncryption OID certificates cannot sign DCs.
	// The rsa_pss_rsae_* algorithms use rsaEncryption OID and are prohibited.
	switch dc.Algorithm {
	case PSSWithSHA256, PSSWithSHA384, PSSWithSHA512: // 0x0804, 0x0805, 0x0806 - rsa_pss_rsae_*
		return errors.New("tls: rsa_pss_rsae_* algorithms not allowed for delegated credentials per RFC 9345")
	}

	// Check that the certificate has the DelegationUsage extension and digitalSignature KeyUsage
	if !hasDelegationUsage(cert) {
		return errors.New("tls: certificate does not have DelegationUsage extension or digitalSignature KeyUsage")
	}

	// Build the signed message per RFC 9345 Section 4.1.1:
	// 64 bytes of 0x20 || context string || 0x00 || certificate || credential || algorithm
	credential := dc.credentialBytes()

	// Select context string based on whether this is a client or server DC
	contextString := dcServerContextString
	if isClient {
		contextString = dcClientContextString
	}

	// Total length: 64 (prefix) + 33 (context) + 1 (null) + cert + credential + 2 (algorithm)
	signedLen := 64 + len(contextString) + 1 + len(cert.Raw) + len(credential) + 2
	signed := make([]byte, 0, signedLen)

	// 1. 64 bytes of 0x20
	signed = append(signed, dcSignaturePrefix...)
	// 2. Context string
	signed = append(signed, contextString...)
	// 3. 0x00 separator
	signed = append(signed, 0x00)
	// 4. DER-encoded certificate
	signed = append(signed, cert.Raw...)
	// 5. Credential (valid_time + expected_cert_verify_algorithm + SPKI with length prefix)
	signed = append(signed, credential...)
	// 6. Algorithm (2 bytes big-endian)
	signed = append(signed, byte(dc.Algorithm>>8), byte(dc.Algorithm))

	// Verify signature using certificate's public key
	sigType, sigHash, err := typeAndHashFromSignatureScheme(dc.Algorithm)
	if err != nil {
		return fmt.Errorf("tls: unsupported DC signature algorithm: %w", err)
	}

	// Hash the message for signature verification (unless Ed25519 which hashes internally)
	var digest []byte
	if sigHash != crypto.Hash(0) {
		h := sigHash.New()
		h.Write(signed)
		digest = h.Sum(nil)
	} else {
		digest = signed
	}

	// Verify based on signature type
	switch sigType {
	case signatureECDSA:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("tls: DC signature requires ECDSA key but certificate has different key type")
		}
		if !ecdsa.VerifyASN1(pubKey, digest, dc.Signature) {
			return errors.New("tls: invalid delegated credential signature")
		}

	case signatureRSAPSS:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: DC signature requires RSA key but certificate has different key type")
		}
		if err := rsa.VerifyPSS(pubKey, sigHash, digest, dc.Signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}); err != nil {
			return fmt.Errorf("tls: invalid delegated credential RSA-PSS signature: %w", err)
		}

	case signaturePKCS1v15:
		// RFC 8446 Section 4.2.3: PKCS#1 v1.5 signatures MUST NOT be used with TLS 1.3.
		// Delegated Credentials are TLS 1.3 only per RFC 9345.
		return errors.New("tls: PKCS#1 v1.5 signatures not allowed for delegated credentials in TLS 1.3")

	case signatureEd25519:
		pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("tls: DC signature requires Ed25519 key but certificate has different key type")
		}
		if !ed25519.Verify(pubKey, signed, dc.Signature) {
			return errors.New("tls: invalid delegated credential Ed25519 signature")
		}

	default:
		return fmt.Errorf("tls: unsupported DC signature type: %d", sigType)
	}

	return nil
}

// IsValid checks if the DC is within its validity period.
// Per RFC 9345 Section 4.1, the DC is valid from the certificate's notBefore
// until notBefore + ValidTime seconds.
func (dc *DelegatedCredential) IsValid(certNotBefore time.Time, now time.Time) bool {
	// Validity check per RFC 9345:
	// DC is valid if: notBefore <= now < notBefore + valid_time
	validUntil := certNotBefore.Add(time.Duration(dc.ValidTime) * time.Second)
	return !now.Before(certNotBefore) && now.Before(validUntil)
}

// IsValidTTL checks if the DC's TTL is within the allowed maximum (7 days).
// Per RFC 9345 Section 4.1.
func (dc *DelegatedCredential) IsValidTTL() bool {
	return dc.ValidTime <= dcMaxTTLSeconds
}

// PublicKey returns the DC's public key for use in CertificateVerify.
func (dc *DelegatedCredential) PublicKey() crypto.PublicKey {
	return dc.publicKey
}

// hasDelegationUsage checks if the certificate has the DelegationUsage extension
// and the required digitalSignature KeyUsage bit set.
// Per RFC 9345 Section 4.2:
// - The certificate MUST have the digitalSignature KeyUsage set
// - The DelegationUsage extension MUST be present
func hasDelegationUsage(cert *x509.Certificate) bool {
	// RFC 9345 Section 4.2: Certificate MUST have digitalSignature KeyUsage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	// Check for DelegationUsage extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(delegationUsageOID) {
			return true
		}
	}
	return false
}

// verifyDCCertVerifyAlgorithm checks if the DC's expected CertificateVerify algorithm
// is compatible with its public key type.
func verifyDCCertVerifyAlgorithm(dc *DelegatedCredential) error {
	sigType, _, err := typeAndHashFromSignatureScheme(dc.ExpectedCertVerifyAlgorithm)
	if err != nil {
		return fmt.Errorf("tls: unsupported DC CertificateVerify algorithm: %w", err)
	}

	switch dc.publicKey.(type) {
	case *ecdsa.PublicKey:
		if sigType != signatureECDSA {
			return errors.New("tls: DC public key type (ECDSA) incompatible with expected signature algorithm")
		}
	case *rsa.PublicKey:
		if sigType != signatureRSAPSS && sigType != signaturePKCS1v15 {
			return errors.New("tls: DC public key type (RSA) incompatible with expected signature algorithm")
		}
	case ed25519.PublicKey:
		if sigType != signatureEd25519 {
			return errors.New("tls: DC public key type (Ed25519) incompatible with expected signature algorithm")
		}
	default:
		return errors.New("tls: unsupported DC public key type")
	}

	return nil
}
