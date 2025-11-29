// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// TLSFingerprint contains all JA3 and JA4 fingerprint variants.
type TLSFingerprint struct {
	// JA3 fingerprints (MD5-based, widely used for TLS fingerprinting)
	JA3   string // MD5 hash of JA3_r (original extension order)
	JA3r  string // Raw: "version,ciphers,extensions,curves,points" (original order)
	JA3n  string // MD5 hash of JA3_rn (normalized/sorted extensions)
	JA3rn string // Raw with sorted extensions

	// JA4 fingerprints (SHA256-based, handles extension shuffling)
	JA4   string // Sorted ciphers/extensions (excl SNI/ALPN), hashed
	JA4r  string // Sorted ciphers/extensions (excl SNI/ALPN), raw values
	JA4o  string // Original order (incl SNI/ALPN), hashed
	JA4ro string // Original order (incl SNI/ALPN), raw values
}

// clientHelloData holds parsed ClientHello fields for fingerprint calculation.
type clientHelloData struct {
	version             uint16   // From ClientHello version field
	supportedVersions   []uint16 // From supported_versions extension (43)
	cipherSuites        []uint16 // GREASE filtered, original order
	extensions          []uint16 // GREASE filtered, original order
	curves              []uint16 // From supported_groups (ext 10)
	pointFormats        []uint8  // From ec_point_formats (ext 11)
	signatureAlgorithms []uint16 // From signature_algorithms (ext 13)
	hasSNI              bool
	alpnFirst           string // First ALPN protocol
}

// parseClientHelloData extracts fingerprint-relevant data from raw ClientHello.
// Raw bytes must include handshake header (type + length).
func parseClientHelloData(raw []byte) (*clientHelloData, error) {
	if len(raw) < 5 {
		return nil, errors.New("tls: ClientHello too short")
	}

	data := &clientHelloData{}
	s := cryptobyte.String(raw)

	// Skip handshake type (1) and length (3)
	if !s.Skip(4) {
		return nil, errors.New("tls: failed to skip handshake header")
	}

	// Version (2 bytes)
	if !s.ReadUint16(&data.version) {
		return nil, errors.New("tls: failed to read version")
	}

	// Random (32 bytes)
	if !s.Skip(32) {
		return nil, errors.New("tls: failed to skip random")
	}

	// Session ID (variable)
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("tls: failed to read session ID")
	}

	// Cipher suites
	var cipherBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherBytes) {
		return nil, errors.New("tls: failed to read cipher suites")
	}
	for !cipherBytes.Empty() {
		var cipher uint16
		if !cipherBytes.ReadUint16(&cipher) {
			return nil, errors.New("tls: failed to parse cipher suite")
		}
		if !isGREASEUint16(cipher) {
			data.cipherSuites = append(data.cipherSuites, cipher)
		}
	}

	// Compression methods
	var compression cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compression) {
		return nil, errors.New("tls: failed to read compression methods")
	}

	// Extensions (optional)
	if s.Empty() {
		return data, nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("tls: failed to read extensions")
	}

	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("tls: failed to parse extension")
		}

		if isGREASEUint16(extType) {
			continue
		}

		data.extensions = append(data.extensions, extType)

		switch extType {
		case 0: // server_name (SNI)
			data.hasSNI = true

		case 10: // supported_groups (elliptic_curves)
			var groups cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&groups) {
				for !groups.Empty() {
					var group uint16
					if groups.ReadUint16(&group) && !isGREASEUint16(group) {
						data.curves = append(data.curves, group)
					}
				}
			}

		case 11: // ec_point_formats
			var formats cryptobyte.String
			if extData.ReadUint8LengthPrefixed(&formats) {
				for !formats.Empty() {
					var format uint8
					if formats.ReadUint8(&format) {
						data.pointFormats = append(data.pointFormats, format)
					}
				}
			}

		case 13: // signature_algorithms
			var sigAlgs cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&sigAlgs) {
				for !sigAlgs.Empty() {
					var sigAlg uint16
					if sigAlgs.ReadUint16(&sigAlg) {
						data.signatureAlgorithms = append(data.signatureAlgorithms, sigAlg)
					}
				}
			}

		case 16: // application_layer_protocol_negotiation (ALPN)
			var alpnList cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&alpnList) && !alpnList.Empty() {
				var protoLen uint8
				if alpnList.ReadUint8(&protoLen) && protoLen > 0 {
					proto := make([]byte, protoLen)
					if alpnList.CopyBytes(proto) {
						data.alpnFirst = string(proto)
					}
				}
			}

		case 43: // supported_versions
			var versions cryptobyte.String
			if extData.ReadUint8LengthPrefixed(&versions) {
				for !versions.Empty() {
					var ver uint16
					if versions.ReadUint16(&ver) && !isGREASEUint16(ver) {
						data.supportedVersions = append(data.supportedVersions, ver)
					}
				}
			}
		}
	}

	return data, nil
}

// CalculateFingerprints computes all JA3/JA4 fingerprints from raw ClientHello bytes.
func CalculateFingerprints(raw []byte) (*TLSFingerprint, error) {
	data, err := parseClientHelloData(raw)
	if err != nil {
		return nil, err
	}

	fp := &TLSFingerprint{}

	// JA3 (original extension order)
	fp.JA3r = buildJA3String(data, false)
	hash := md5.Sum([]byte(fp.JA3r))
	fp.JA3 = hex.EncodeToString(hash[:])

	// JA3n (normalized/sorted extensions)
	fp.JA3rn = buildJA3String(data, true)
	hashN := md5.Sum([]byte(fp.JA3rn))
	fp.JA3n = hex.EncodeToString(hashN[:])

	// JA4 variants
	ja4a := buildJA4a(data)
	fp.JA4 = buildJA4(ja4a, data, true, true)
	fp.JA4r = buildJA4(ja4a, data, true, false)
	fp.JA4o = buildJA4(ja4a, data, false, true)
	fp.JA4ro = buildJA4(ja4a, data, false, false)

	return fp, nil
}

// buildJA3String creates the raw JA3 string.
// Format: version,ciphers,extensions,curves,points (all decimal, dash-separated)
// sortExtensions: if true, sorts extensions for JA3_rn (normalized variant)
func buildJA3String(data *clientHelloData, sortExtensions bool) string {
	// Version
	version := strconv.FormatUint(uint64(data.version), 10)

	// Ciphers (decimal, dash-separated, original order)
	ciphers := joinUint16Decimal(data.cipherSuites, "-")

	// Extensions (decimal, dash-separated)
	exts := make([]uint16, len(data.extensions))
	copy(exts, data.extensions)
	if sortExtensions {
		sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	}
	extensions := joinUint16Decimal(exts, "-")

	// Curves (decimal, dash-separated, original order)
	curves := joinUint16Decimal(data.curves, "-")

	// Point formats (decimal, dash-separated)
	points := joinUint8Decimal(data.pointFormats, "-")

	return fmt.Sprintf("%s,%s,%s,%s,%s", version, ciphers, extensions, curves, points)
}

// buildJA4a creates the JA4_a component.
// Format: [protocol][version][sni][cipher_count][ext_count][alpn]
func buildJA4a(data *clientHelloData) string {
	// Protocol: t=TCP, q=QUIC, d=DTLS
	protocol := "t"

	// TLS version (2 chars)
	// Per JA4 spec: use highest version from supported_versions extension, else use version field
	version := data.version
	if len(data.supportedVersions) > 0 {
		// Find highest supported version (first non-GREASE is typically highest)
		version = data.supportedVersions[0]
		for _, v := range data.supportedVersions {
			if v > version {
				version = v
			}
		}
	}

	var tlsVer string
	switch version {
	case VersionTLS13:
		tlsVer = "13"
	case VersionTLS12:
		tlsVer = "12"
	case VersionTLS11:
		tlsVer = "11"
	case VersionTLS10:
		tlsVer = "10"
	case VersionSSL30:
		tlsVer = "s3"
	default:
		tlsVer = "00"
	}

	// SNI indicator: d=domain, i=IP/none
	sni := "i"
	if data.hasSNI {
		sni = "d"
	}

	// Cipher count (excluding GREASE, capped at 99)
	cipherCount := len(data.cipherSuites)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (excluding GREASE only, capped at 99)
	// Per JA4 spec: "Same as counting ciphers. Ignore GREASE. Include SNI and ALPN."
	extCount := len(data.extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN: first and last char of first protocol, or "00"
	// Per JA4 spec: if non-alphanumeric, use hex of first and last bytes
	alpn := "00"
	if len(data.alpnFirst) >= 1 {
		first := data.alpnFirst[0]
		last := data.alpnFirst[len(data.alpnFirst)-1]
		if isAlphanumeric(first) && isAlphanumeric(last) {
			alpn = string(first) + string(last)
		} else {
			// Use hex representation for non-alphanumeric
			// JA4 spec: first char of hex(first byte) + last char of hex(last byte)
			firstHex := fmt.Sprintf("%02x", first)
			lastHex := fmt.Sprintf("%02x", last)
			alpn = string(firstHex[0]) + string(lastHex[1])
		}
	}

	return fmt.Sprintf("%s%s%s%02d%02d%s", protocol, tlsVer, sni, cipherCount, extCount, alpn)
}

// buildJA4 creates a JA4 fingerprint string.
// sorted: whether to sort ciphers/extensions
// hashed: whether to hash the b/c components (false = raw values)
func buildJA4(ja4a string, data *clientHelloData, sorted, hashed bool) string {
	// Build JA4_b (ciphers)
	ciphers := make([]uint16, len(data.cipherSuites))
	copy(ciphers, data.cipherSuites)
	if sorted {
		sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	}

	var ja4b string
	cipherHex := joinUint16Hex(ciphers, ",")
	if hashed {
		if cipherHex == "" {
			ja4b = "000000000000"
		} else {
			h := sha256.Sum256([]byte(cipherHex))
			ja4b = hex.EncodeToString(h[:])[:12]
		}
	} else {
		ja4b = cipherHex
	}

	// Build JA4_c (extensions + signature algorithms)
	// For sorted variant: exclude SNI (0) and ALPN (16)
	// For original order variant: include all extensions
	var exts []uint16
	for _, ext := range data.extensions {
		if sorted && (ext == 0 || ext == 16) {
			continue // Exclude SNI and ALPN for sorted variants
		}
		exts = append(exts, ext)
	}
	if sorted {
		sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
	}

	extHex := joinUint16Hex(exts, ",")

	// Append signature algorithms (always in original order, after underscore)
	sigAlgHex := joinUint16Hex(data.signatureAlgorithms, ",")
	var extAndSigAlg string
	if sigAlgHex != "" {
		if extHex != "" {
			extAndSigAlg = extHex + "_" + sigAlgHex
		} else {
			extAndSigAlg = "_" + sigAlgHex
		}
	} else {
		extAndSigAlg = extHex
	}

	var ja4c string
	if hashed {
		if extAndSigAlg == "" {
			ja4c = "000000000000"
		} else {
			h := sha256.Sum256([]byte(extAndSigAlg))
			ja4c = hex.EncodeToString(h[:])[:12]
		}
	} else {
		ja4c = extAndSigAlg
	}

	return fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)
}

// Helper functions

func joinUint16Decimal(vals []uint16, sep string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, sep)
}

func joinUint8Decimal(vals []uint8, sep string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, sep)
}

func joinUint16Hex(vals []uint16, sep string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, sep)
}

// isAlphanumeric returns true if byte is 0-9, A-Z, or a-z.
func isAlphanumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// Fingerprint computes and returns TLS fingerprints for this connection.
// Must be called after BuildHandshakeState().
func (uconn *UConn) Fingerprint() (*TLSFingerprint, error) {
	if uconn.HandshakeState.Hello == nil {
		return nil, errors.New("tls: ClientHello not built; call BuildHandshakeState() first")
	}
	if len(uconn.HandshakeState.Hello.Raw) == 0 {
		return nil, errors.New("tls: ClientHello.Raw is empty")
	}
	return CalculateFingerprints(uconn.HandshakeState.Hello.Raw)
}

// JA3 returns the JA3 fingerprint hash for this connection.
func (uconn *UConn) JA3() (string, error) {
	fp, err := uconn.Fingerprint()
	if err != nil {
		return "", err
	}
	return fp.JA3, nil
}

// JA3Raw returns the raw JA3 string (before hashing).
func (uconn *UConn) JA3Raw() (string, error) {
	fp, err := uconn.Fingerprint()
	if err != nil {
		return "", err
	}
	return fp.JA3r, nil
}

// JA4 returns the JA4 fingerprint for this connection.
func (uconn *UConn) JA4() (string, error) {
	fp, err := uconn.Fingerprint()
	if err != nil {
		return "", err
	}
	return fp.JA4, nil
}

// =============================================================================
// JA4S - ServerHello Fingerprinting
// =============================================================================
//
// JA4S fingerprints the TLS ServerHello response.
// Format: {protocol}{version}{ext_count}{alpn}_{cipher}_{extensions_hash}
// Example: t1302h2_1301_a56c5b993250

// ServerHelloFingerprint contains JA4S fingerprint data.
type ServerHelloFingerprint struct {
	JA4S  string // Hashed: t130200_1301_a56c5b993250
	JA4Sr string // Raw: t130200_1301_002b,0033,... (extensions in hex)
}

// serverHelloData holds parsed ServerHello fields for JA4S calculation.
type serverHelloData struct {
	version          uint16   // From ServerHello or supported_versions ext
	cipherSuite      uint16   // Selected cipher suite
	extensions       []uint16 // Extension types present (GREASE filtered)
	hasALPN          bool
	alpnProtocol     string
	compressionNone  bool
}

// parseServerHelloForJA4S extracts fingerprint data from raw ServerHello.
// Raw bytes must include handshake header (type + length).
func parseServerHelloForJA4S(raw []byte) (*serverHelloData, error) {
	if len(raw) < 5 {
		return nil, errors.New("tls: ServerHello too short")
	}

	// Validate handshake type is ServerHello (0x02)
	if raw[0] != 0x02 {
		return nil, fmt.Errorf("tls: expected ServerHello (0x02), got 0x%02x", raw[0])
	}

	data := &serverHelloData{}
	s := cryptobyte.String(raw)

	// Skip handshake type (1) and length (3)
	if !s.Skip(4) {
		return nil, errors.New("tls: failed to skip handshake header")
	}

	// Version (2 bytes) - legacy for TLS 1.3
	if !s.ReadUint16(&data.version) {
		return nil, errors.New("tls: failed to read version")
	}

	// Random (32 bytes)
	if !s.Skip(32) {
		return nil, errors.New("tls: failed to skip random")
	}

	// Session ID (variable)
	var sessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("tls: failed to read session ID")
	}

	// Cipher suite (2 bytes)
	if !s.ReadUint16(&data.cipherSuite) {
		return nil, errors.New("tls: failed to read cipher suite")
	}

	// Compression method (1 byte)
	var compression uint8
	if !s.ReadUint8(&compression) {
		return nil, errors.New("tls: failed to read compression")
	}
	data.compressionNone = compression == 0

	// Extensions (optional)
	if s.Empty() {
		return data, nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("tls: failed to read extensions")
	}

	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("tls: failed to parse extension")
		}

		if isGREASEUint16(extType) {
			continue
		}

		data.extensions = append(data.extensions, extType)

		switch extType {
		case 16: // ALPN
			data.hasALPN = true
			var alpnList cryptobyte.String
			if extData.ReadUint16LengthPrefixed(&alpnList) && !alpnList.Empty() {
				var protoLen uint8
				if alpnList.ReadUint8(&protoLen) && protoLen > 0 {
					proto := make([]byte, protoLen)
					if alpnList.CopyBytes(proto) {
						data.alpnProtocol = string(proto)
					}
				}
			}

		case 43: // supported_versions - real version for TLS 1.3
			var ver uint16
			if extData.ReadUint16(&ver) {
				data.version = ver // Override legacy version
			}
		}
	}

	// Verify no trailing data after extensions
	if !s.Empty() {
		return nil, errors.New("tls: ServerHello has trailing data after extensions")
	}

	return data, nil
}

// CalculateJA4S computes JA4S fingerprint from raw ServerHello bytes.
func CalculateJA4S(raw []byte) (*ServerHelloFingerprint, error) {
	data, err := parseServerHelloForJA4S(raw)
	if err != nil {
		return nil, err
	}

	fp := &ServerHelloFingerprint{}

	// Build JA4S_a: {protocol}{version}{ext_count}
	protocol := "t" // TCP (QUIC would be q, DTLS would be d)

	var tlsVer string
	switch data.version {
	case VersionTLS13:
		tlsVer = "13"
	case VersionTLS12:
		tlsVer = "12"
	case VersionTLS11:
		tlsVer = "11"
	case VersionTLS10:
		tlsVer = "10"
	case VersionSSL30:
		tlsVer = "s3"
	default:
		// Handle draft TLS 1.3 versions (0x7f01-0x7f1c = drafts 1-28)
		// These should be treated as TLS 1.3 for fingerprinting purposes
		if data.version >= 0x7f01 && data.version <= 0x7f1c {
			tlsVer = "13"
		} else {
			tlsVer = "00"
		}
	}

	extCount := len(data.extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN indicator for JA4S
	alpn := "00"
	if len(data.alpnProtocol) >= 1 {
		first := data.alpnProtocol[0]
		last := data.alpnProtocol[len(data.alpnProtocol)-1]
		if isAlphanumeric(first) && isAlphanumeric(last) {
			alpn = string(first) + string(last)
		} else {
			// JA4 spec: first char of hex(first byte) + last char of hex(last byte)
			firstHex := fmt.Sprintf("%02x", first)
			lastHex := fmt.Sprintf("%02x", last)
			alpn = string(firstHex[0]) + string(lastHex[1])
		}
	}

	ja4sA := fmt.Sprintf("%s%s%02d%s", protocol, tlsVer, extCount, alpn)

	// Build JA4S_b: cipher in hex (4 chars)
	ja4sB := fmt.Sprintf("%04x", data.cipherSuite)

	// Build JA4S_c: extensions hash
	// Sort extensions, hash with SHA256, take first 12 chars
	sortedExts := make([]uint16, len(data.extensions))
	copy(sortedExts, data.extensions)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })

	extHex := joinUint16Hex(sortedExts, ",")
	var ja4sC string
	if extHex == "" {
		ja4sC = "000000000000"
	} else {
		h := sha256.Sum256([]byte(extHex))
		ja4sC = hex.EncodeToString(h[:])[:12]
	}

	fp.JA4S = fmt.Sprintf("%s_%s_%s", ja4sA, ja4sB, ja4sC)
	fp.JA4Sr = fmt.Sprintf("%s_%s_%s", ja4sA, ja4sB, extHex)

	return fp, nil
}

// =============================================================================
// JA4X - X.509 Certificate Fingerprinting
// =============================================================================
//
// JA4X fingerprints how certificates are structured, NOT the values in them.
// Format: {issuer_hash}_{subject_hash}_{extensions_hash}
// Example: 2bab15409345_af684594efb4_000000000000
//
// Each hash is SHA256[:12] of comma-separated OID hex strings in DER encoding.
// This identifies certificate generation patterns regardless of field values.

// CertificateFingerprint contains JA4X fingerprint data.
type CertificateFingerprint struct {
	JA4X  string // Hashed: 2bab15409345_af684594efb4_000000000000
	JA4Xr string // Raw: issuer_oids_subject_oids_ext_oids

	// Individual components for analysis
	IssuerOIDs    []string // OIDs in issuer RDN
	SubjectOIDs   []string // OIDs in subject RDN
	ExtensionOIDs []string // OIDs of certificate extensions
}

// CalculateJA4X computes JA4X fingerprint from an x509.Certificate.
func CalculateJA4X(cert *x509.Certificate) *CertificateFingerprint {
	if cert == nil {
		return &CertificateFingerprint{
			JA4X: "000000000000_000000000000_000000000000",
		}
	}

	fp := &CertificateFingerprint{}

	// Extract Issuer RDN OIDs
	fp.IssuerOIDs = extractRDNOIDs(cert.Issuer)

	// Extract Subject RDN OIDs
	fp.SubjectOIDs = extractRDNOIDs(cert.Subject)

	// Extract Extension OIDs
	fp.ExtensionOIDs = extractExtensionOIDs(cert)

	// Hash each component
	issuerHash := hashOIDList(fp.IssuerOIDs)
	subjectHash := hashOIDList(fp.SubjectOIDs)
	extHash := hashOIDList(fp.ExtensionOIDs)

	fp.JA4X = fmt.Sprintf("%s_%s_%s", issuerHash, subjectHash, extHash)
	fp.JA4Xr = fmt.Sprintf("%s_%s_%s",
		strings.Join(fp.IssuerOIDs, ","),
		strings.Join(fp.SubjectOIDs, ","),
		strings.Join(fp.ExtensionOIDs, ","))

	return fp
}

// extractRDNOIDs extracts OID hex strings from a pkix.Name in order.
func extractRDNOIDs(name pkix.Name) []string {
	var oids []string

	// Iterate through RDN sequence in order
	for _, rdn := range name.Names {
		oidHex := oidToHex(rdn.Type)
		oids = append(oids, oidHex)
	}

	return oids
}

// extractExtensionOIDs extracts OID hex strings from certificate extensions.
func extractExtensionOIDs(cert *x509.Certificate) []string {
	var oids []string

	for _, ext := range cert.Extensions {
		oidHex := oidToHex(ext.Id)
		oids = append(oids, oidHex)
	}

	return oids
}

// oidToHex converts an ASN.1 OID to its DER-encoded hex string.
// Per JA4X spec: encode OID in DER format, return hex without wrapper.
func oidToHex(oid asn1.ObjectIdentifier) string {
	if len(oid) < 2 {
		return ""
	}

	// DER encoding of OID:
	// First two arcs combined = first_arc * 40 + second_arc
	// If combined > 127, use variable-length encoding
	// Subsequent arcs = variable-length encoding
	var encoded []byte

	// First two arcs combined - use variable-length encoding if > 127
	// This handles edge cases like OID 2.999 where 2*40+999=1079
	combined := oid[0]*40 + oid[1]
	encoded = append(encoded, encodeVarInt(combined)...)

	// Encode remaining arcs using variable-length encoding
	for _, arc := range oid[2:] {
		encoded = append(encoded, encodeVarInt(arc)...)
	}

	return hex.EncodeToString(encoded)
}

// encodeVarInt encodes an integer using ASN.1 variable-length encoding.
func encodeVarInt(val int) []byte {
	if val == 0 {
		return []byte{0}
	}

	var result []byte
	first := true

	for val > 0 {
		b := byte(val & 0x7F)
		val >>= 7
		if !first {
			b |= 0x80
		}
		result = append([]byte{b}, result...)
		first = false
	}

	// Set continuation bit on all but last byte
	for i := 0; i < len(result)-1; i++ {
		result[i] |= 0x80
	}

	return result
}

// hashOIDList hashes a list of OID hex strings per JA4X spec.
func hashOIDList(oids []string) string {
	if len(oids) == 0 {
		return "000000000000"
	}

	combined := strings.Join(oids, ",")
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:])[:12]
}

// =============================================================================
// Connection Fingerprint Summary
// =============================================================================
//
// TLSConnectionFingerprint aggregates all fingerprints for a TLS connection,
// including client-side (ClientHello) and server-side (certificates) data.

// TLSConnectionFingerprint contains all fingerprints for a TLS connection.
type TLSConnectionFingerprint struct {
	// Client-side (what we sent)
	Client *TLSFingerprint

	// Server-side (what we received) - available after handshake
	Server *ServerHelloFingerprint

	// Certificate fingerprints - available after handshake
	// First element is leaf certificate, others are chain
	Certificates []*CertificateFingerprint
}

// ConnectionFingerprint returns comprehensive fingerprints for this connection.
// For client fingerprints: call after BuildHandshakeState()
// For server/cert fingerprints: call after Handshake() completes
func (uconn *UConn) ConnectionFingerprint() (*TLSConnectionFingerprint, error) {
	result := &TLSConnectionFingerprint{}

	// Client fingerprints (from our ClientHello)
	if uconn.HandshakeState.Hello != nil && len(uconn.HandshakeState.Hello.Raw) > 0 {
		clientFP, err := CalculateFingerprints(uconn.HandshakeState.Hello.Raw)
		if err != nil {
			return nil, fmt.Errorf("client fingerprint: %w", err)
		}
		result.Client = clientFP
	}

	// Server and certificate fingerprints require completed handshake
	state := uconn.ConnectionState()
	if state.HandshakeComplete {
		for _, cert := range state.PeerCertificates {
			result.Certificates = append(result.Certificates, CalculateJA4X(cert))
		}
	}

	return result, nil
}

// ServerJA4S returns the JA4S fingerprint of the server's response.
// Must be called after Handshake() completes.
//
// Returns the JA4S fingerprint string in format: {a}_{b}_{c}
// where:
//   - {a} = protocol + version + extension_count + alpn
//   - {b} = cipher suite in hex (4 chars)
//   - {c} = SHA256 hash of sorted extensions (first 12 chars)
//
// Example: "t130200_1301_a56c5b993250"
func (uconn *UConn) ServerJA4S() (string, error) {
	fp, err := uconn.ServerJA4SFull()
	if err != nil {
		return "", err
	}
	return fp.JA4S, nil
}

// ServerJA4SFull returns the full ServerHelloFingerprint including both
// JA4S (hashed) and JA4Sr (raw/unhashed) fingerprints.
// Must be called after Handshake() completes.
//
// Note: Call ClearRawServerHello() after extracting fingerprints to free memory
// if the raw ServerHello bytes are no longer needed.
func (uconn *UConn) ServerJA4SFull() (*ServerHelloFingerprint, error) {
	state := uconn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New("tls: handshake not complete")
	}

	if len(uconn.rawServerHello) == 0 {
		return nil, errors.New("tls: ServerHello raw bytes not captured")
	}

	return CalculateJA4S(uconn.rawServerHello)
}

// ClearRawServerHello releases the memory used by the captured raw ServerHello.
// Call this after extracting JA4S fingerprints if you no longer need them.
// After calling this, ServerJA4S() and ServerJA4SFull() will return an error.
func (uconn *UConn) ClearRawServerHello() {
	uconn.rawServerHello = nil
}

// CertificateJA4X returns JA4X fingerprints for the server's certificate chain.
// Must be called after Handshake() completes.
func (uconn *UConn) CertificateJA4X() ([]*CertificateFingerprint, error) {
	state := uconn.ConnectionState()
	if !state.HandshakeComplete {
		return nil, errors.New("tls: handshake not complete")
	}

	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("tls: no peer certificates")
	}

	var fps []*CertificateFingerprint
	for _, cert := range state.PeerCertificates {
		fps = append(fps, CalculateJA4X(cert))
	}

	return fps, nil
}

// LeafCertificateJA4X returns JA4X fingerprint for the leaf certificate only.
// Must be called after Handshake() completes.
func (uconn *UConn) LeafCertificateJA4X() (*CertificateFingerprint, error) {
	fps, err := uconn.CertificateJA4X()
	if err != nil {
		return nil, err
	}
	return fps[0], nil
}
