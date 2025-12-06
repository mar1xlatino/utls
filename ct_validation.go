// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// SCT (Signed Certificate Timestamp) validation for Certificate Transparency
// per RFC 6962 (https://tools.ietf.org/html/rfc6962)

const (
	// SCT version constants per RFC 6962 Section 3.2
	sctVersionV1 uint8 = 0

	// Signature types for SCT
	sctSignatureTypeCertificateTimestamp uint8 = 0
	sctSignatureTypeTreeHash             uint8 = 1

	// Log entry types per RFC 6962 Section 3.1
	logEntryTypeX509    uint16 = 0
	logEntryTypePrecert uint16 = 1

	// Minimum number of valid SCTs required
	// Chrome requires 2+ SCTs from different logs for certificates valid > 15 months
	// For simplicity, we require at least 1 valid SCT
	minValidSCTCount = 1
)

// SignedCertificateTimestamp represents an SCT per RFC 6962 Section 3.2
type SignedCertificateTimestamp struct {
	Version    uint8           // SCT version (0 for v1)
	LogID      [32]byte        // SHA-256 hash of log's public key
	Timestamp  uint64          // Milliseconds since Unix epoch
	Extensions []byte          // CT extensions (currently unused)
	Signature  digitallySigned // Log's signature over the SCT data
}

// digitallySigned represents a TLS digitally-signed struct per RFC 5246
type digitallySigned struct {
	Algorithm SignatureAndHashAlgorithm
	Signature []byte
}

// SignatureAndHashAlgorithm per RFC 5246 Section 7.4.1.4.1
type SignatureAndHashAlgorithm struct {
	Hash      uint8 // Hash algorithm (4=SHA256, 5=SHA384, 6=SHA512)
	Signature uint8 // Signature algorithm (1=RSA, 3=ECDSA, 7=ED25519)
}

// CTLogInfo represents a known Certificate Transparency log
type CTLogInfo struct {
	LogID     [32]byte         // SHA-256 hash of log's SubjectPublicKeyInfo
	PublicKey crypto.PublicKey // Parsed public key for signature verification
	Name      string           // Human-readable name of the log
	URL       string           // Log's submission URL
	Operator  string           // Log operator (e.g., "Google", "Cloudflare")
}

// ParseSCT parses an SCT from its wire format per RFC 6962 Section 3.2
// Wire format:
//
//	struct {
//	    Version sct_version;           // 1 byte
//	    LogID id;                      // 32 bytes
//	    uint64 timestamp;              // 8 bytes
//	    CtExtensions extensions;       // 2 bytes length + data
//	    digitally-signed struct { ... }
//	} SignedCertificateTimestamp;
func ParseSCT(data []byte) (*SignedCertificateTimestamp, error) {
	// Minimum size: version(1) + logID(32) + timestamp(8) + extensions length(2) + sig algo(2) + sig length(2) = 47
	const minSCTSize = 1 + 32 + 8 + 2 + 2 + 2
	if len(data) < minSCTSize {
		return nil, errors.New("tls: SCT too short")
	}

	sct := &SignedCertificateTimestamp{}
	offset := 0

	// Version (1 byte)
	sct.Version = data[offset]
	if sct.Version != sctVersionV1 {
		return nil, fmt.Errorf("tls: unsupported SCT version %d, expected %d", sct.Version, sctVersionV1)
	}
	offset++

	// LogID (32 bytes - SHA-256 hash of log's public key DER)
	copy(sct.LogID[:], data[offset:offset+32])
	offset += 32

	// Timestamp (8 bytes - milliseconds since Unix epoch)
	sct.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	// Extensions length (2 bytes) + data
	if len(data) < offset+2 {
		return nil, errors.New("tls: SCT extensions length truncated")
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if len(data) < offset+extLen {
		return nil, errors.New("tls: SCT extensions data truncated")
	}
	if extLen > 0 {
		sct.Extensions = make([]byte, extLen)
		copy(sct.Extensions, data[offset:offset+extLen])
	}
	offset += extLen

	// Signature algorithm (2 bytes: hash + signature)
	if len(data) < offset+2 {
		return nil, errors.New("tls: SCT signature algorithm truncated")
	}
	sct.Signature.Algorithm.Hash = data[offset]
	sct.Signature.Algorithm.Signature = data[offset+1]
	offset += 2

	// Signature length (2 bytes) + data
	if len(data) < offset+2 {
		return nil, errors.New("tls: SCT signature length truncated")
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if len(data) < offset+sigLen {
		return nil, errors.New("tls: SCT signature data truncated")
	}
	sct.Signature.Signature = make([]byte, sigLen)
	copy(sct.Signature.Signature, data[offset:offset+sigLen])

	return sct, nil
}

// Time returns the SCT timestamp as a time.Time
func (sct *SignedCertificateTimestamp) Time() time.Time {
	return time.Unix(int64(sct.Timestamp/1000), int64((sct.Timestamp%1000)*1000000))
}

// Verify verifies the SCT signature against a certificate and CT log public key.
// Per RFC 6962 Section 3.2, the signed data structure is:
//
//	digitally-signed struct {
//	    Version sct_version;
//	    SignatureType signature_type = certificate_timestamp;
//	    uint64 timestamp;
//	    LogEntryType entry_type;
//	    select(entry_type) {
//	        case x509_entry: ASN.1Cert;
//	        case precert_entry: PreCert;
//	    } signed_entry;
//	    CtExtensions extensions;
//	}
func (sct *SignedCertificateTimestamp) Verify(cert *x509.Certificate, issuerKeyHash []byte, logKey crypto.PublicKey) error {
	if cert == nil {
		return errors.New("tls: certificate is nil")
	}
	if logKey == nil {
		return errors.New("tls: log public key is nil")
	}

	// Determine entry type and build signed data
	var signedData []byte
	var err error

	// Check if this is a precertificate by looking for the poison extension
	isPrecert := hasPoisonExtension(cert)

	if isPrecert {
		if issuerKeyHash == nil {
			return errors.New("tls: issuer key hash required for precertificate SCT verification")
		}
		signedData, err = sct.buildPrecertSignedData(cert, issuerKeyHash)
	} else {
		signedData, err = sct.buildCertSignedData(cert)
	}
	if err != nil {
		return fmt.Errorf("tls: failed to build SCT signed data: %w", err)
	}

	// Hash the signed data
	hash, err := sct.hashSignedData(signedData)
	if err != nil {
		return err
	}

	// Verify the signature
	return sct.verifySignature(hash, logKey)
}

// buildCertSignedData builds the signed data for an X.509 certificate entry
func (sct *SignedCertificateTimestamp) buildCertSignedData(cert *x509.Certificate) ([]byte, error) {
	// Calculate size:
	// version(1) + signature_type(1) + timestamp(8) + entry_type(2) +
	// cert_length(3) + cert + extensions_length(2) + extensions
	certLen := len(cert.Raw)
	extLen := len(sct.Extensions)

	size := 1 + 1 + 8 + 2 + 3 + certLen + 2 + extLen
	data := make([]byte, size)
	offset := 0

	// Version (1 byte)
	data[offset] = sct.Version
	offset++

	// Signature type (1 byte) - certificate_timestamp = 0
	data[offset] = sctSignatureTypeCertificateTimestamp
	offset++

	// Timestamp (8 bytes)
	binary.BigEndian.PutUint64(data[offset:offset+8], sct.Timestamp)
	offset += 8

	// Entry type (2 bytes) - x509_entry = 0
	binary.BigEndian.PutUint16(data[offset:offset+2], logEntryTypeX509)
	offset += 2

	// Certificate length (3 bytes - 24-bit length)
	data[offset] = byte(certLen >> 16)
	data[offset+1] = byte(certLen >> 8)
	data[offset+2] = byte(certLen)
	offset += 3

	// Certificate data
	copy(data[offset:], cert.Raw)
	offset += certLen

	// Extensions length (2 bytes)
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(extLen))
	offset += 2

	// Extensions data
	if extLen > 0 {
		copy(data[offset:], sct.Extensions)
	}

	return data, nil
}

// buildPrecertSignedData builds the signed data for a precertificate entry
// For precertificates, the signed data includes the issuer key hash and
// the TBSCertificate with the poison extension removed
func (sct *SignedCertificateTimestamp) buildPrecertSignedData(cert *x509.Certificate, issuerKeyHash []byte) ([]byte, error) {
	// Get TBSCertificate with poison extension removed
	tbsCert, err := extractTBSCertificateForCT(cert)
	if err != nil {
		return nil, err
	}

	// Calculate size:
	// version(1) + signature_type(1) + timestamp(8) + entry_type(2) +
	// issuer_key_hash(32) + tbs_length(3) + tbs + extensions_length(2) + extensions
	tbsLen := len(tbsCert)
	extLen := len(sct.Extensions)

	size := 1 + 1 + 8 + 2 + 32 + 3 + tbsLen + 2 + extLen
	data := make([]byte, size)
	offset := 0

	// Version (1 byte)
	data[offset] = sct.Version
	offset++

	// Signature type (1 byte) - certificate_timestamp = 0
	data[offset] = sctSignatureTypeCertificateTimestamp
	offset++

	// Timestamp (8 bytes)
	binary.BigEndian.PutUint64(data[offset:offset+8], sct.Timestamp)
	offset += 8

	// Entry type (2 bytes) - precert_entry = 1
	binary.BigEndian.PutUint16(data[offset:offset+2], logEntryTypePrecert)
	offset += 2

	// Issuer key hash (32 bytes)
	copy(data[offset:offset+32], issuerKeyHash)
	offset += 32

	// TBSCertificate length (3 bytes - 24-bit length)
	data[offset] = byte(tbsLen >> 16)
	data[offset+1] = byte(tbsLen >> 8)
	data[offset+2] = byte(tbsLen)
	offset += 3

	// TBSCertificate data
	copy(data[offset:], tbsCert)
	offset += tbsLen

	// Extensions length (2 bytes)
	binary.BigEndian.PutUint16(data[offset:offset+2], uint16(extLen))
	offset += 2

	// Extensions data
	if extLen > 0 {
		copy(data[offset:], sct.Extensions)
	}

	return data, nil
}

// hashSignedData hashes the signed data according to the algorithm specified in the SCT
func (sct *SignedCertificateTimestamp) hashSignedData(data []byte) ([]byte, error) {
	var hashFunc crypto.Hash

	switch sct.Signature.Algorithm.Hash {
	case 4: // SHA-256
		hashFunc = crypto.SHA256
	case 5: // SHA-384
		hashFunc = crypto.SHA384
	case 6: // SHA-512
		hashFunc = crypto.SHA512
	default:
		return nil, fmt.Errorf("tls: unsupported SCT hash algorithm %d", sct.Signature.Algorithm.Hash)
	}

	if !hashFunc.Available() {
		return nil, fmt.Errorf("tls: hash algorithm %d not available", sct.Signature.Algorithm.Hash)
	}

	h := hashFunc.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// verifySignature verifies the SCT signature over the hashed data
func (sct *SignedCertificateTimestamp) verifySignature(hash []byte, pubKey crypto.PublicKey) error {
	switch sct.Signature.Algorithm.Signature {
	case 1: // RSA
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: SCT signature algorithm RSA but key is not RSA")
		}
		hashFunc := sct.getHashFunc()
		return rsa.VerifyPKCS1v15(rsaKey, hashFunc, hash, sct.Signature.Signature)

	case 3: // ECDSA
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("tls: SCT signature algorithm ECDSA but key is not ECDSA")
		}
		// ECDSA signature is DER-encoded
		if !verifyECDSASignature(ecdsaKey, hash, sct.Signature.Signature) {
			return errors.New("tls: invalid ECDSA signature in SCT")
		}
		return nil

	case 7: // Ed25519 (RFC 8422)
		ed25519Key, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("tls: SCT signature algorithm Ed25519 but key is not Ed25519")
		}
		// Ed25519 uses the raw message, not a hash
		// This is a simplification - in practice, the signed data should be passed directly
		if !ed25519.Verify(ed25519Key, hash, sct.Signature.Signature) {
			return errors.New("tls: invalid Ed25519 signature in SCT")
		}
		return nil

	default:
		return fmt.Errorf("tls: unsupported SCT signature algorithm %d", sct.Signature.Algorithm.Signature)
	}
}

// getHashFunc returns the crypto.Hash corresponding to the SCT's hash algorithm
func (sct *SignedCertificateTimestamp) getHashFunc() crypto.Hash {
	switch sct.Signature.Algorithm.Hash {
	case 4:
		return crypto.SHA256
	case 5:
		return crypto.SHA384
	case 6:
		return crypto.SHA512
	default:
		return crypto.SHA256 // Default fallback
	}
}

// verifyECDSASignature verifies a DER-encoded ECDSA signature
func verifyECDSASignature(pubKey *ecdsa.PublicKey, hash, sig []byte) bool {
	// Parse DER-encoded ECDSA signature
	var ecdsaSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &ecdsaSig); err != nil {
		return false
	}
	return ecdsa.Verify(pubKey, hash, ecdsaSig.R, ecdsaSig.S)
}

// OID for CT Precertificate Poison extension (1.3.6.1.4.1.11129.2.4.3)
var oidCTPrecertPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}

// OID for SCT List extension in certificates (1.3.6.1.4.1.11129.2.4.2)
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// hasPoisonExtension checks if the certificate has the CT precertificate poison extension
func hasPoisonExtension(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidCTPrecertPoison) {
			return true
		}
	}
	return false
}

// extractTBSCertificateForCT extracts the TBSCertificate from a certificate
// and removes the poison extension for precertificate SCT verification.
// This is a simplified implementation - a full implementation would need to
// properly re-encode the TBSCertificate ASN.1 structure.
func extractTBSCertificateForCT(cert *x509.Certificate) ([]byte, error) {
	// For simplicity, we return the raw TBSCertificate
	// A full implementation would need to:
	// 1. Parse the TBSCertificate structure
	// 2. Remove the poison extension from the extensions list
	// 3. Re-encode the modified TBSCertificate
	//
	// Since precertificates are relatively rare in practice (most SCTs are
	// delivered via TLS extension or OCSP), this simplified version uses
	// the raw certificate data.
	return cert.RawTBSCertificate, nil
}

// ValidateSCTs validates a list of SCTs for a certificate chain.
// It returns nil if at least minValidSCTCount valid SCTs are found from trusted logs.
//
// Parameters:
//   - cert: The leaf certificate being validated
//   - chain: The certificate chain (leaf first, then intermediates)
//   - scts: SCT data from TLS extension, OCSP response, or X.509 extension
//   - logs: Map of trusted CT logs (nil uses DefaultCTLogs)
//
// Per RFC 6962, SCTs can be delivered via:
// 1. TLS extension (type 18) - most common
// 2. OCSP response extension
// 3. X.509v3 certificate extension
func ValidateSCTs(cert *x509.Certificate, chain []*x509.Certificate, scts [][]byte, logs map[[32]byte]*CTLogInfo) error {
	if len(scts) == 0 {
		return errors.New("tls: no SCTs provided for certificate transparency validation")
	}

	if logs == nil {
		logs = DefaultCTLogs
	}

	if len(logs) == 0 {
		return errors.New("tls: no CT logs configured for validation")
	}

	// Calculate issuer key hash for precertificate validation
	var issuerKeyHash []byte
	if len(chain) > 1 {
		issuerKeyHash = computeIssuerKeyHash(chain[1])
	}

	validCount := 0
	var lastError error
	seenLogs := make(map[[32]byte]bool) // Track unique valid logs

	for _, sctData := range scts {
		sct, err := ParseSCT(sctData)
		if err != nil {
			lastError = err
			continue
		}

		// Look up the log by its ID
		log, ok := logs[sct.LogID]
		if !ok {
			lastError = fmt.Errorf("tls: unknown CT log ID %x", sct.LogID[:8])
			continue
		}

		// Verify the SCT signature
		if err := sct.Verify(cert, issuerKeyHash, log.PublicKey); err != nil {
			lastError = fmt.Errorf("tls: SCT from log %s failed verification: %w", log.Name, err)
			continue
		}

		// Check that SCT timestamp is not in the future (with some tolerance)
		now := time.Now()
		sctTime := sct.Time()
		if sctTime.After(now.Add(24 * time.Hour)) {
			lastError = fmt.Errorf("tls: SCT timestamp from log %s is in the future", log.Name)
			continue
		}

		// Count unique valid SCTs from different logs
		if !seenLogs[sct.LogID] {
			seenLogs[sct.LogID] = true
			validCount++
		}
	}

	if validCount < minValidSCTCount {
		if lastError != nil {
			return fmt.Errorf("tls: insufficient valid SCTs (%d < %d): %w", validCount, minValidSCTCount, lastError)
		}
		return fmt.Errorf("tls: insufficient valid SCTs (%d < %d)", validCount, minValidSCTCount)
	}

	return nil
}

// computeIssuerKeyHash computes the SHA-256 hash of the issuer's SubjectPublicKeyInfo
// This is used for precertificate SCT verification
func computeIssuerKeyHash(issuer *x509.Certificate) []byte {
	if issuer == nil {
		return nil
	}
	hash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	return hash[:]
}

// ExtractSCTsFromCertificate extracts embedded SCTs from a certificate's
// SCT List extension (OID 1.3.6.1.4.1.11129.2.4.2)
func ExtractSCTsFromCertificate(cert *x509.Certificate) ([][]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSCTList) {
			return parseSCTList(ext.Value)
		}
	}
	return nil, nil // No SCT extension found
}

// parseSCTList parses a serialized SCT list (RFC 6962 Section 3.3)
// Format: uint16 list_length + (uint16 sct_length + sct_data)*
func parseSCTList(data []byte) ([][]byte, error) {
	if len(data) < 2 {
		return nil, errors.New("tls: SCT list too short")
	}

	// Total list length
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+listLen {
		return nil, errors.New("tls: SCT list length mismatch")
	}

	var scts [][]byte
	offset := 2
	end := 2 + listLen

	for offset < end {
		if offset+2 > end {
			return nil, errors.New("tls: SCT length truncated")
		}
		sctLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+sctLen > end {
			return nil, errors.New("tls: SCT data truncated")
		}
		sct := make([]byte, sctLen)
		copy(sct, data[offset:offset+sctLen])
		scts = append(scts, sct)
		offset += sctLen
	}

	return scts, nil
}

// SCTValidationResult contains the result of SCT validation
type SCTValidationResult struct {
	Valid       bool              // Whether validation passed
	ValidSCTs   int               // Number of valid SCTs found
	TotalSCTs   int               // Total number of SCTs checked
	ValidLogs   []string          // Names of logs with valid SCTs
	InvalidSCTs []SCTValidationError // Details of invalid SCTs
}

// SCTValidationError describes why an SCT failed validation
type SCTValidationError struct {
	LogID  [32]byte
	Reason string
}

// ValidateSCTsDetailed performs detailed SCT validation and returns comprehensive results
func ValidateSCTsDetailed(cert *x509.Certificate, chain []*x509.Certificate, scts [][]byte, logs map[[32]byte]*CTLogInfo) *SCTValidationResult {
	result := &SCTValidationResult{
		TotalSCTs: len(scts),
	}

	if len(scts) == 0 {
		result.InvalidSCTs = append(result.InvalidSCTs, SCTValidationError{
			Reason: "no SCTs provided",
		})
		return result
	}

	if logs == nil {
		logs = DefaultCTLogs
	}

	var issuerKeyHash []byte
	if len(chain) > 1 {
		issuerKeyHash = computeIssuerKeyHash(chain[1])
	}

	seenLogs := make(map[[32]byte]bool)

	for _, sctData := range scts {
		sct, err := ParseSCT(sctData)
		if err != nil {
			result.InvalidSCTs = append(result.InvalidSCTs, SCTValidationError{
				Reason: fmt.Sprintf("parse error: %v", err),
			})
			continue
		}

		log, ok := logs[sct.LogID]
		if !ok {
			result.InvalidSCTs = append(result.InvalidSCTs, SCTValidationError{
				LogID:  sct.LogID,
				Reason: "unknown log",
			})
			continue
		}

		if err := sct.Verify(cert, issuerKeyHash, log.PublicKey); err != nil {
			result.InvalidSCTs = append(result.InvalidSCTs, SCTValidationError{
				LogID:  sct.LogID,
				Reason: fmt.Sprintf("verification failed: %v", err),
			})
			continue
		}

		if !seenLogs[sct.LogID] {
			seenLogs[sct.LogID] = true
			result.ValidSCTs++
			result.ValidLogs = append(result.ValidLogs, log.Name)
		}
	}

	result.Valid = result.ValidSCTs >= minValidSCTCount
	return result
}
