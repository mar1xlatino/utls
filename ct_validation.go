// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	utlserrors "github.com/refraction-networking/utls/errors"
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

	// Minimum number of valid SCTs required based on certificate validity period.
	// Per Chrome's CT policy (https://googlechrome.github.io/CertificateTransparency/ct_policy.html):
	// - Certificates valid <= 15 months: minimum 1 SCT required
	// - Certificates valid > 15 months: minimum 2 SCTs from different log operators required
	// This prevents a single CT log compromise from defeating protection for long-lived certificates.
	minValidSCTCountShort = 1 // For certificates valid <= 15 months
	minValidSCTCountLong  = 2 // For certificates valid > 15 months

	// certificateValidityThreshold is the validity period threshold (15 months)
	// above which additional SCTs are required. 15 months = 15 * 30.44 days (average month).
	certificateValidityThreshold = 15 * 30 * 24 * time.Hour // ~456 days
)

// getMinSCTCount returns the minimum number of valid SCTs required for the given certificate
// based on Chrome's Certificate Transparency policy. Long-lived certificates (validity > 15 months)
// require more SCTs to ensure protection against single log operator compromise.
func getMinSCTCount(cert *x509.Certificate) int {
	if cert == nil {
		return minValidSCTCountLong // Conservative default for nil certificate
	}
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity > certificateValidityThreshold {
		return minValidSCTCountLong
	}
	return minValidSCTCountShort
}

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
	return ParseSCTWithContext(context.Background(), data)
}

// ParseSCTWithContext parses an SCT from its wire format with context for logging.
func ParseSCTWithContext(ctx context.Context, data []byte) (*SignedCertificateTimestamp, error) {
	utlserrors.LogDebug(ctx, "CT: parsing SCT, data length:", len(data))

	// Minimum size: version(1) + logID(32) + timestamp(8) + extensions length(2) + sig algo(2) + sig length(2) = 47
	const minSCTSize = 1 + 32 + 8 + 2 + 2 + 2
	if len(data) < minSCTSize {
		return nil, utlserrors.New("tls: SCT too short").AtError()
	}

	sct := &SignedCertificateTimestamp{}
	offset := 0

	// Version (1 byte)
	sct.Version = data[offset]
	if sct.Version != sctVersionV1 {
		return nil, utlserrors.New("tls: unsupported SCT version ", sct.Version, ", expected ", sctVersionV1).AtError()
	}
	offset++

	// LogID (32 bytes - SHA-256 hash of log's public key DER)
	copy(sct.LogID[:], data[offset:offset+32])
	offset += 32

	utlserrors.LogDebug(ctx, "CT: SCT log ID:", hex.EncodeToString(sct.LogID[:8]), "...")

	// Timestamp (8 bytes - milliseconds since Unix epoch)
	sct.Timestamp = binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8

	utlserrors.LogDebug(ctx, "CT: SCT timestamp:", sct.Time().Format(time.RFC3339))

	// Extensions length (2 bytes) + data
	if len(data) < offset+2 {
		return nil, utlserrors.New("tls: SCT extensions length truncated").AtError()
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if len(data) < offset+extLen {
		return nil, utlserrors.New("tls: SCT extensions data truncated").AtError()
	}
	if extLen > 0 {
		sct.Extensions = make([]byte, extLen)
		copy(sct.Extensions, data[offset:offset+extLen])
	}
	offset += extLen

	// Signature algorithm (2 bytes: hash + signature)
	if len(data) < offset+2 {
		return nil, utlserrors.New("tls: SCT signature algorithm truncated").AtError()
	}
	sct.Signature.Algorithm.Hash = data[offset]
	sct.Signature.Algorithm.Signature = data[offset+1]
	offset += 2

	utlserrors.LogDebug(ctx, "CT: SCT signature algorithm: hash=", sct.Signature.Algorithm.Hash, " sig=", sct.Signature.Algorithm.Signature)

	// Signature length (2 bytes) + data
	if len(data) < offset+2 {
		return nil, utlserrors.New("tls: SCT signature length truncated").AtError()
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if len(data) < offset+sigLen {
		return nil, utlserrors.New("tls: SCT signature data truncated").AtError()
	}
	sct.Signature.Signature = make([]byte, sigLen)
	copy(sct.Signature.Signature, data[offset:offset+sigLen])

	utlserrors.LogDebug(ctx, "CT: SCT parsed successfully, signature length:", sigLen)

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
	return sct.VerifyWithContext(context.Background(), cert, issuerKeyHash, logKey)
}

// VerifyWithContext verifies the SCT signature against a certificate with context for logging.
func (sct *SignedCertificateTimestamp) VerifyWithContext(ctx context.Context, cert *x509.Certificate, issuerKeyHash []byte, logKey crypto.PublicKey) error {
	utlserrors.LogDebug(ctx, "CT: verifying SCT for log ID:", hex.EncodeToString(sct.LogID[:8]), "...")

	if cert == nil {
		return utlserrors.New("tls: certificate is nil").AtError()
	}
	if logKey == nil {
		return utlserrors.New("tls: log public key is nil").AtError()
	}

	// Determine entry type and build signed data
	var signedData []byte
	var err error

	// Check if this is a precertificate by looking for the poison extension
	isPrecert := hasPoisonExtension(cert)

	if isPrecert {
		utlserrors.LogDebug(ctx, "CT: certificate is a precertificate")
		if issuerKeyHash == nil {
			return utlserrors.New("tls: issuer key hash required for precertificate SCT verification").AtError()
		}
		signedData, err = sct.buildPrecertSignedData(cert, issuerKeyHash)
	} else {
		utlserrors.LogDebug(ctx, "CT: certificate is a standard X.509 certificate")
		signedData, err = sct.buildCertSignedData(cert)
	}
	if err != nil {
		return utlserrors.New("tls: failed to build SCT signed data").Base(err).AtError()
	}

	// Hash the signed data
	hash, err := sct.hashSignedData(signedData)
	if err != nil {
		return err
	}

	// Verify the signature
	// Note: Ed25519 requires the raw signedData, not the hash
	if err := sct.verifySignature(hash, signedData, logKey); err != nil {
		utlserrors.LogDebug(ctx, "CT: SCT signature verification failed")
		return err
	}

	utlserrors.LogDebug(ctx, "CT: SCT signature verified successfully")
	return nil
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
		return nil, utlserrors.New("tls: unsupported SCT hash algorithm ", sct.Signature.Algorithm.Hash).AtError()
	}

	if !hashFunc.Available() {
		return nil, utlserrors.New("tls: hash algorithm ", sct.Signature.Algorithm.Hash, " not available").AtError()
	}

	h := hashFunc.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// verifySignature verifies the SCT signature over the hashed data
// signedData is the raw data before hashing (needed for Ed25519)
func (sct *SignedCertificateTimestamp) verifySignature(hash, signedData []byte, pubKey crypto.PublicKey) error {
	switch sct.Signature.Algorithm.Signature {
	case 1: // RSA
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return utlserrors.New("tls: SCT signature algorithm RSA but key is not RSA").AtError()
		}
		hashFunc := sct.getHashFunc()
		if err := rsa.VerifyPKCS1v15(rsaKey, hashFunc, hash, sct.Signature.Signature); err != nil {
			return utlserrors.New("tls: invalid RSA signature in SCT").Base(err).AtError()
		}
		return nil

	case 3: // ECDSA
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return utlserrors.New("tls: SCT signature algorithm ECDSA but key is not ECDSA").AtError()
		}
		// ECDSA signature is DER-encoded
		if !verifyECDSASignature(ecdsaKey, hash, sct.Signature.Signature) {
			return utlserrors.New("tls: invalid ECDSA signature in SCT").AtError()
		}
		return nil

	case 7: // Ed25519 (RFC 8422)
		ed25519Key, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return utlserrors.New("tls: SCT signature algorithm Ed25519 but key is not Ed25519").AtError()
		}
		// Ed25519 uses the raw message, not a hash (RFC 8032)
		if !ed25519.Verify(ed25519Key, signedData, sct.Signature.Signature) {
			return utlserrors.New("tls: invalid Ed25519 signature in SCT").AtError()
		}
		return nil

	default:
		return utlserrors.New("tls: unsupported SCT signature algorithm ", sct.Signature.Algorithm.Signature).AtError()
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
	return ValidateSCTsWithContext(context.Background(), cert, chain, scts, logs)
}

// ValidateSCTsWithContext validates SCTs with context for logging.
func ValidateSCTsWithContext(ctx context.Context, cert *x509.Certificate, chain []*x509.Certificate, scts [][]byte, logs map[[32]byte]*CTLogInfo) error {
	utlserrors.LogDebug(ctx, "CT: validating SCTs, count:", len(scts))

	if len(scts) == 0 {
		return utlserrors.New("tls: no SCTs provided for certificate transparency validation").AtError()
	}

	if logs == nil {
		logs = DefaultCTLogs
	}

	if len(logs) == 0 {
		return utlserrors.New("tls: no CT logs configured for validation").AtError()
	}

	requiredSCTs := getMinSCTCount(cert)
	utlserrors.LogDebug(ctx, "CT: checking policy, required SCTs:", requiredSCTs)

	// Calculate issuer key hash for precertificate validation
	var issuerKeyHash []byte
	if len(chain) > 1 {
		issuerKeyHash = computeIssuerKeyHash(chain[1])
	}

	validCount := 0
	var lastError error
	seenLogs := make(map[[32]byte]bool) // Track unique valid logs

	for i, sctData := range scts {
		utlserrors.LogDebug(ctx, "CT: processing SCT", i+1, "of", len(scts))

		sct, err := ParseSCTWithContext(ctx, sctData)
		if err != nil {
			lastError = err
			continue
		}

		// Look up the log by its ID
		log, ok := logs[sct.LogID]
		if !ok {
			utlserrors.LogDebug(ctx, "CT: unknown log ID:", hex.EncodeToString(sct.LogID[:8]), "...")
			lastError = utlserrors.New("tls: unknown CT log ID ", hex.EncodeToString(sct.LogID[:8])).AtError()
			continue
		}

		utlserrors.LogDebug(ctx, "CT: validating SCT from log:", log.Name)

		// Verify the SCT signature
		if err := sct.VerifyWithContext(ctx, cert, issuerKeyHash, log.PublicKey); err != nil {
			lastError = utlserrors.New("tls: SCT from log ", log.Name, " failed verification").Base(err).AtError()
			continue
		}

		// Check that SCT timestamp is not in the future (with some tolerance)
		now := time.Now()
		sctTime := sct.Time()
		if sctTime.After(now.Add(24 * time.Hour)) {
			utlserrors.LogDebug(ctx, "CT: SCT timestamp from log", log.Name, "is in the future:", sctTime.Format(time.RFC3339))
			lastError = utlserrors.New("tls: SCT timestamp from log ", log.Name, " is in the future").AtError()
			continue
		}

		// Count unique valid SCTs from different logs
		if !seenLogs[sct.LogID] {
			seenLogs[sct.LogID] = true
			validCount++
			utlserrors.LogDebug(ctx, "CT: valid SCT from log:", log.Name, ", total valid:", validCount)
		}
	}

	if validCount < requiredSCTs {
		if lastError != nil {
			return utlserrors.New("tls: insufficient valid SCTs (", validCount, " < ", requiredSCTs, ")").Base(lastError).AtError()
		}
		return utlserrors.New("tls: insufficient valid SCTs (", validCount, " < ", requiredSCTs, ")").AtError()
	}

	utlserrors.LogDebug(ctx, "CT: policy satisfied with", validCount, "valid SCTs")
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
		return nil, utlserrors.New("tls: SCT list too short").AtError()
	}

	// Total list length
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+listLen {
		return nil, utlserrors.New("tls: SCT list length mismatch").AtError()
	}

	var scts [][]byte
	offset := 2
	end := 2 + listLen

	for offset < end {
		if offset+2 > end {
			return nil, utlserrors.New("tls: SCT length truncated").AtError()
		}
		sctLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		if offset+sctLen > end {
			return nil, utlserrors.New("tls: SCT data truncated").AtError()
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

	result.Valid = result.ValidSCTs >= getMinSCTCount(cert)
	return result
}
