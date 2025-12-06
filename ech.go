// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/refraction-networking/utls/internal/hpke"

	"golang.org/x/crypto/cryptobyte"
)

// sortedSupportedAEADs is just a sorted version of hpke.SupportedAEADS.
// We need this so that when we insert them into ECHConfigs the ordering
// is stable.
var sortedSupportedAEADs []uint16

func init() {
	for aeadID := range hpke.SupportedAEADs {
		sortedSupportedAEADs = append(sortedSupportedAEADs, aeadID)
	}
	slices.Sort(sortedSupportedAEADs)
}

// sniExtensionOverhead is the byte overhead of the SNI extension structure
// excluding the actual server name bytes:
//   - 2 bytes: extension type
//   - 2 bytes: extension length
//   - 2 bytes: server name list length
//   - 1 byte:  server name type (host_name = 0)
//   - 2 bytes: server name length
//
// Total: 9 bytes. Used in ECH padding calculations to ensure consistent
// ClientHello sizes regardless of whether SNI is present.
const sniExtensionOverhead = 9

type echCipher struct {
	KDFID  uint16
	AEADID uint16
}

type echExtension struct {
	Type uint16
	Data []byte
}

type echConfig struct {
	raw []byte

	Version uint16
	Length  uint16

	ConfigID             uint8
	KemID                uint16
	PublicKey            []byte
	SymmetricCipherSuite []echCipher

	MaxNameLength uint8
	PublicName    []byte
	Extensions    []echExtension
}

// Use generic error to avoid revealing ECH configuration parsing
var errMalformedECHConfig = errors.New("tls: malformed configuration")

func parseECHConfig(enc []byte) (skip bool, ec echConfig, err error) {
	s := cryptobyte.String(enc)
	ec.raw = []byte(enc)
	if !s.ReadUint16(&ec.Version) {
		return false, echConfig{}, errMalformedECHConfig
	}
	if !s.ReadUint16(&ec.Length) {
		return false, echConfig{}, errMalformedECHConfig
	}
	// Use int arithmetic to prevent uint16 overflow when ec.Length is near MaxUint16.
	// Without this, ec.Length+4 could wrap around (e.g., 65535+4=3 in uint16).
	totalLen := int(ec.Length) + 4
	if len(ec.raw) < totalLen {
		return false, echConfig{}, errMalformedECHConfig
	}
	ec.raw = ec.raw[:totalLen]
	if ec.Version != extensionEncryptedClientHello {
		s.Skip(int(ec.Length))
		return true, echConfig{}, nil
	}
	if !s.ReadUint8(&ec.ConfigID) {
		return false, echConfig{}, errMalformedECHConfig
	}
	if !s.ReadUint16(&ec.KemID) {
		return false, echConfig{}, errMalformedECHConfig
	}
	if !readUint16LengthPrefixed(&s, &ec.PublicKey) {
		return false, echConfig{}, errMalformedECHConfig
	}
	// Validate public key is not empty
	if len(ec.PublicKey) == 0 {
		return false, echConfig{}, errors.New("tls: config has empty public key")
	}
	// Validate public key length based on KEM type.
	// This prevents cryptographic errors when SetupSender() is called.
	switch ec.KemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		// P-256 uncompressed point: 0x04 prefix + 32 bytes X + 32 bytes Y = 65 bytes
		if len(ec.PublicKey) != 65 {
			return false, echConfig{}, errors.New("tls: config has invalid P-256 public key length")
		}
	case 0x0011: // DHKEM(P-384, HKDF-SHA384)
		// P-384 uncompressed point: 0x04 prefix + 48 bytes X + 48 bytes Y = 97 bytes
		if len(ec.PublicKey) != 97 {
			return false, echConfig{}, errors.New("tls: config has invalid P-384 public key length")
		}
	case 0x0020: // DHKEM(X25519, HKDF-SHA256)
		// X25519 public key is exactly 32 bytes
		if len(ec.PublicKey) != 32 {
			return false, echConfig{}, errors.New("tls: config has invalid X25519 public key length")
		}
	}
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return false, echConfig{}, errMalformedECHConfig
	}
	for !cipherSuites.Empty() {
		var c echCipher
		if !cipherSuites.ReadUint16(&c.KDFID) {
			return false, echConfig{}, errMalformedECHConfig
		}
		if !cipherSuites.ReadUint16(&c.AEADID) {
			return false, echConfig{}, errMalformedECHConfig
		}
		ec.SymmetricCipherSuite = append(ec.SymmetricCipherSuite, c)
	}
	if !s.ReadUint8(&ec.MaxNameLength) {
		return false, echConfig{}, errMalformedECHConfig
	}
	// Note: MaxNameLength=0 is allowed for backwards compatibility with real-world
	// configs (e.g., Cloudflare). When MaxNameLength=0, the padding calculation
	// in encodeInnerClientHello handles it gracefully:
	// - If serverName is set: namePadding = max(0, 0 - len(serverName)) = 0
	// - If serverName is empty: namePadding = 0 + sniExtensionOverhead = 9 bytes
	// This effectively means "no padding hint" which is acceptable behavior.
	var publicName cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&publicName) {
		return false, echConfig{}, errMalformedECHConfig
	}
	ec.PublicName = publicName
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return false, echConfig{}, errMalformedECHConfig
	}
	for !extensions.Empty() {
		var e echExtension
		if !extensions.ReadUint16(&e.Type) {
			return false, echConfig{}, errMalformedECHConfig
		}
		if !extensions.ReadUint16LengthPrefixed((*cryptobyte.String)(&e.Data)) {
			return false, echConfig{}, errMalformedECHConfig
		}
		ec.Extensions = append(ec.Extensions, e)
	}

	return false, ec, nil
}

// parseECHConfigList parses a draft-ietf-tls-esni-18 ECHConfigList, returning a
// slice of parsed ECHConfigs, in the same order they were parsed, or an error
// if the list is malformed.
func parseECHConfigList(data []byte) ([]echConfig, error) {
	s := cryptobyte.String(data)
	var length uint16
	if !s.ReadUint16(&length) {
		return nil, errMalformedECHConfig
	}
	if length != uint16(len(data)-2) {
		return nil, errMalformedECHConfig
	}
	var configs []echConfig
	for len(s) > 0 {
		if len(s) < 4 {
			return nil, errors.New("tls: malformed configuration")
		}
		configLen := uint16(s[2])<<8 | uint16(s[3])
		// Bounds check: ensure we have enough data before reslicing
		totalLen := int(configLen) + 4
		if totalLen > len(s) {
			return nil, errors.New("tls: ECH config length exceeds available data")
		}
		skip, ec, err := parseECHConfig(s)
		if err != nil {
			return nil, err
		}
		s = s[totalLen:]
		if !skip {
			configs = append(configs, ec)
		}
	}
	return configs, nil
}

func pickECHConfig(list []echConfig) *echConfig {
	for _, ec := range list {
		if _, ok := hpke.SupportedKEMs[ec.KemID]; !ok {
			continue
		}
		var validSCS bool
		for _, cs := range ec.SymmetricCipherSuite {
			if _, ok := hpke.SupportedAEADs[cs.AEADID]; !ok {
				continue
			}
			if _, ok := hpke.SupportedKDFs[cs.KDFID]; !ok {
				continue
			}
			validSCS = true
			break
		}
		if !validSCS {
			continue
		}
		if !validDNSName(string(ec.PublicName)) {
			continue
		}
		var unsupportedExt bool
		for _, ext := range ec.Extensions {
			// If high order bit is set to 1 the extension is mandatory.
			// Since we don't support any extensions, if we see a mandatory
			// bit, we skip the config.
			if ext.Type&uint16(1<<15) != 0 {
				unsupportedExt = true
			}
		}
		if unsupportedExt {
			continue
		}
		return &ec
	}
	return nil
}

func pickECHCipherSuite(suites []echCipher) (echCipher, error) {
	for _, s := range suites {
		// NOTE: all of the supported AEADs and KDFs are fine, rather than
		// imposing some sort of preference here, we just pick the first valid
		// suite.
		if _, ok := hpke.SupportedAEADs[s.AEADID]; !ok {
			continue
		}
		if _, ok := hpke.SupportedKDFs[s.KDFID]; !ok {
			continue
		}
		return s, nil
	}
	return echCipher{}, errors.New("tls: no supported symmetric ciphersuites for ECH")
}

// filterUsableECHConfigs parses and re-encodes only the usable ECH configs from
// the raw config list. This ensures that the RetryConfigList in ECHRejectionError
// only contains configs that the client can actually use.
//
// Returns nil if no usable configs exist or on parse errors.
func filterUsableECHConfigs(rawConfigs []byte) []byte {
	if len(rawConfigs) == 0 {
		return nil
	}

	configs, err := parseECHConfigList(rawConfigs)
	if err != nil {
		return nil
	}

	// Filter to only usable configs
	var usableRawConfigs []byte
	for _, ec := range configs {
		// Check KEM support
		if _, ok := hpke.SupportedKEMs[ec.KemID]; !ok {
			continue
		}

		// Check for at least one valid cipher suite
		var hasValidSuite bool
		for _, cs := range ec.SymmetricCipherSuite {
			if _, ok := hpke.SupportedAEADs[cs.AEADID]; !ok {
				continue
			}
			if _, ok := hpke.SupportedKDFs[cs.KDFID]; !ok {
				continue
			}
			hasValidSuite = true
			break
		}
		if !hasValidSuite {
			continue
		}

		// Check valid public name
		if !validDNSName(string(ec.PublicName)) {
			continue
		}

		// Check for unsupported mandatory extensions
		var unsupportedExt bool
		for _, ext := range ec.Extensions {
			if ext.Type&uint16(1<<15) != 0 {
				unsupportedExt = true
				break
			}
		}
		if unsupportedExt {
			continue
		}

		// This config is usable, include its raw bytes
		usableRawConfigs = append(usableRawConfigs, ec.raw...)
	}

	if len(usableRawConfigs) == 0 {
		return nil
	}

	// Re-encode with length prefix
	result := make([]byte, 2+len(usableRawConfigs))
	result[0] = byte(len(usableRawConfigs) >> 8)
	result[1] = byte(len(usableRawConfigs))
	copy(result[2:], usableRawConfigs)

	return result
}

// [uTLS SECTION BEGIN]
func encodeInnerClientHello(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	return encodeInnerClientHelloReorderOuterExts(inner, maxNameLength, nil)
}

// [uTLS SECTION END]

func encodeInnerClientHelloReorderOuterExts(inner *clientHelloMsg, maxNameLength int, outerExts []uint16) ([]byte, error) { // uTLS
	h, err := inner.marshalMsgReorderOuterExts(true, outerExts)
	if err != nil {
		return nil, err
	}
	h = h[4:] // strip four byte prefix

	// Compute padding to hide server name length and align to 32-byte boundary.
	// The padding consists of two parts:
	// 1. Name padding: makes encoded size consistent regardless of actual server name length
	// 2. Alignment padding: rounds up to nearest 32-byte boundary
	var namePadding int
	if inner.serverName != "" {
		namePadding = max(0, maxNameLength-len(inner.serverName))
	} else {
		// When serverName is empty (no SNI extension), we still need to pad to
		// maxNameLength plus the SNI extension structure overhead. This ensures
		// consistent ClientHello sizes regardless of whether SNI is present.
		namePadding = maxNameLength + sniExtensionOverhead
	}
	// Calculate alignment padding: how many bytes to add to reach next 32-byte boundary
	// after accounting for name padding
	baseLen := len(h) + namePadding
	alignPadding := (32 - (baseLen % 32)) % 32
	// Total padding is the sum of name padding and alignment padding
	paddingLen := namePadding + alignPadding

	return append(h, make([]byte, paddingLen)...), nil
}

func skipUint8LengthPrefixed(s *cryptobyte.String) bool {
	var skip uint8
	if !s.ReadUint8(&skip) {
		return false
	}
	return s.Skip(int(skip))
}

func skipUint16LengthPrefixed(s *cryptobyte.String) bool {
	var skip uint16
	if !s.ReadUint16(&skip) {
		return false
	}
	return s.Skip(int(skip))
}

type rawExtension struct {
	extType uint16
	data    []byte
}

func extractRawExtensions(hello *clientHelloMsg) ([]rawExtension, error) {
	s := cryptobyte.String(hello.original)
	if !s.Skip(4+2+32) || // header, version, random
		!skipUint8LengthPrefixed(&s) || // session ID
		!skipUint16LengthPrefixed(&s) || // cipher suites
		!skipUint8LengthPrefixed(&s) { // compression methods
		return nil, errors.New("tls: malformed outer client hello")
	}
	var rawExtensions []rawExtension
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("tls: malformed outer client hello")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("tls: invalid inner client hello")
		}
		rawExtensions = append(rawExtensions, rawExtension{extension, extData})
	}
	return rawExtensions, nil
}

func decodeInnerClientHello(outer *clientHelloMsg, encoded []byte) (*clientHelloMsg, error) {
	// Reconstructing the inner client hello from its encoded form is somewhat
	// complicated. It is missing its header (message type and length), session
	// ID, and the extensions may be compressed. Since we need to put the
	// extensions back in the same order as they were in the raw outer hello,
	// and since we don't store the raw extensions, or the order we parsed them
	// in, we need to reparse the raw extensions from the outer hello in order
	// to properly insert them into the inner hello. This _should_ result in raw
	// bytes which match the hello as it was generated by the client.
	innerReader := cryptobyte.String(encoded)
	var versionAndRandom, sessionID, cipherSuites, compressionMethods []byte
	var extensions cryptobyte.String
	if !innerReader.ReadBytes(&versionAndRandom, 2+32) ||
		!readUint8LengthPrefixed(&innerReader, &sessionID) ||
		len(sessionID) != 0 ||
		!readUint16LengthPrefixed(&innerReader, &cipherSuites) ||
		!readUint8LengthPrefixed(&innerReader, &compressionMethods) ||
		!innerReader.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("tls: invalid inner client hello")
	}

	// The specification says we must verify that the trailing padding is all
	// zeros. This is kind of weird for TLS messages, where we generally just
	// throw away any trailing garbage.
	//
	// Limit maximum padding to prevent memory exhaustion attacks.
	// 16KB is more than sufficient for any realistic ECH padding.
	const maxECHPadding = 16384
	if len(innerReader) > maxECHPadding {
		return nil, errors.New("tls: padding too large")
	}
	for _, p := range innerReader {
		if p != 0 {
			return nil, errors.New("tls: invalid inner client hello")
		}
	}

	rawOuterExts, err := extractRawExtensions(outer)
	if err != nil {
		return nil, err
	}

	recon := cryptobyte.NewBuilder(nil)
	recon.AddUint8(typeClientHello)
	recon.AddUint24LengthPrefixed(func(recon *cryptobyte.Builder) {
		recon.AddBytes(versionAndRandom)
		recon.AddUint8LengthPrefixed(func(recon *cryptobyte.Builder) {
			recon.AddBytes(outer.sessionId)
		})
		recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
			recon.AddBytes(cipherSuites)
		})
		recon.AddUint8LengthPrefixed(func(recon *cryptobyte.Builder) {
			recon.AddBytes(compressionMethods)
		})
		recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
			for !extensions.Empty() {
				var extension uint16
				var extData cryptobyte.String
				if !extensions.ReadUint16(&extension) ||
					!extensions.ReadUint16LengthPrefixed(&extData) {
					recon.SetError(errors.New("tls: invalid inner client hello"))
					return
				}
				if extension == extensionECHOuterExtensions {
					if !extData.ReadUint8LengthPrefixed(&extData) {
						recon.SetError(errors.New("tls: invalid inner client hello"))
						return
					}
					var i int
					for !extData.Empty() {
						var extType uint16
						if !extData.ReadUint16(&extType) {
							recon.SetError(errors.New("tls: invalid inner client hello"))
							return
						}
						if extType == extensionEncryptedClientHello {
							recon.SetError(errors.New("tls: invalid outer extensions"))
							return
						}
						for ; i <= len(rawOuterExts); i++ {
							if i == len(rawOuterExts) {
								recon.SetError(errors.New("tls: invalid outer extensions"))
								return
							}
							if rawOuterExts[i].extType == extType {
								break
							}
						}
						recon.AddUint16(rawOuterExts[i].extType)
						recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
							recon.AddBytes(rawOuterExts[i].data)
						})
					}
				} else {
					recon.AddUint16(extension)
					recon.AddUint16LengthPrefixed(func(recon *cryptobyte.Builder) {
						recon.AddBytes(extData)
					})
				}
			}
		})
	})

	reconBytes, err := recon.Bytes()
	if err != nil {
		return nil, err
	}
	inner := &clientHelloMsg{}
	if !inner.unmarshal(reconBytes) {
		return nil, errors.New("tls: invalid reconstructed inner client hello")
	}

	if !bytes.Equal(inner.encryptedClientHello, []byte{uint8(innerECHExt)}) {
		return nil, errInvalidECHExt
	}

	// Inner ClientHello MUST offer exactly one version, and it MUST be TLS 1.3.
	// The second condition is simplified: if len != 1, we fail; otherwise len == 1,
	// so we can safely check supportedVersions[0] without the redundant length check.
	if len(inner.supportedVersions) != 1 || inner.supportedVersions[0] != VersionTLS13 {
		return nil, errors.New("tls: incompatible protocol versions")
	}

	return inner, nil
}

// findECHPayloadPosition finds the byte offset of the ECH payload within the
// ClientHello message (starting from byte 4, after the header). Returns the
// position relative to hello[4:], or -1 if not found.
func findECHPayloadPosition(hello []byte, payloadLen int) int {
	if len(hello) < 4+2+32+1 { // header + version + random + min session id len
		return -1
	}

	s := cryptobyte.String(hello[4:]) // skip header
	originalLen := len(s)

	// Skip: version (2), random (32), session ID, cipher suites, compression methods
	if !s.Skip(2+32) ||
		!skipUint8LengthPrefixed(&s) || // session ID
		!skipUint16LengthPrefixed(&s) || // cipher suites
		!skipUint8LengthPrefixed(&s) { // compression methods
		return -1
	}

	var extensionsLen uint16
	if !s.ReadUint16(&extensionsLen) {
		return -1
	}

	for len(s) > 0 {
		extStart := originalLen - len(s)
		var extType uint16
		var extLen uint16
		if !s.ReadUint16(&extType) || !s.ReadUint16(&extLen) {
			return -1
		}

		if extType == extensionEncryptedClientHello {
			// Found ECH extension. Parse to find payload position.
			// ECH outer structure: type(1) + kdf(2) + aead(2) + configId(1) + encapKeyLen(2) + encapKey + payloadLen(2) + payload
			if int(extLen) < 10 { // minimum ECH extension size
				return -1
			}
			echData := s[:extLen]
			if len(echData) < 1 {
				return -1
			}
			// Skip: type(1) + kdf(2) + aead(2) + configId(1)
			echData = echData[6:]
			if len(echData) < 2 {
				return -1
			}
			encapKeyLen := int(echData[0])<<8 | int(echData[1])
			echData = echData[2:]
			if len(echData) < encapKeyLen+2 {
				return -1
			}
			// Skip encapsulated key
			echData = echData[encapKeyLen:]
			// Now at payload length prefix
			payloadLenFromExt := int(echData[0])<<8 | int(echData[1])
			if payloadLenFromExt != payloadLen {
				return -1 // payload length mismatch
			}
			// Payload position: extStart + 4(type+len) + 6(type+kdf+aead+configId) + 2(encapKeyLen) + encapKeyLen + 2(payloadLen)
			payloadOffset := extStart + 4 + 6 + 2 + encapKeyLen + 2
			return payloadOffset
		}

		if !s.Skip(int(extLen)) {
			return -1
		}
	}

	return -1
}

func decryptECHPayload(context *hpke.Recipient, hello, payload []byte) ([]byte, error) {
	// Create AAD by zeroing out the ECH payload at its exact position.
	// This is safer than bytes.Replace which could match wrong bytes.
	payloadPos := findECHPayloadPosition(hello, len(payload))

	outerAAD := make([]byte, len(hello)-4)
	copy(outerAAD, hello[4:])

	if payloadPos >= 0 && payloadPos+len(payload) <= len(outerAAD) {
		// Zero out payload at the correct position
		copy(outerAAD[payloadPos:], make([]byte, len(payload)))
	} else {
		// Fallback to bytes.Replace if position-based approach fails.
		// This maintains backward compatibility while logging the issue.
		outerAAD = bytes.Replace(hello[4:], payload, make([]byte, len(payload)), 1)
	}

	return context.Open(outerAAD, payload)
}

func generateOuterECHExt(id uint8, kdfID, aeadID uint16, encodedKey []byte, payload []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(0) // outer
	b.AddUint16(kdfID)
	b.AddUint16(aeadID)
	b.AddUint8(id)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(encodedKey) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(payload) })
	return b.Bytes()
}

func computeAndUpdateOuterECHExtension(outer, inner *clientHelloMsg, ech *echClientContext, useKey bool) error {
	var encapKey []byte
	if useKey {
		encapKey = ech.encapsulatedKey
	}
	encodedInner, err := encodeInnerClientHello(inner, int(ech.config.MaxNameLength))
	if err != nil {
		return err
	}
	// Use the AEAD's Overhead() method to get the tag length dynamically.
	// This ensures correct operation if AEADs with different tag lengths
	// are added in the future.
	encryptedLen := len(encodedInner) + ech.hpkeContext.Overhead()
	outer.encryptedClientHello, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, make([]byte, encryptedLen))
	if err != nil {
		return err
	}
	serializedOuter, err := outer.marshal()
	if err != nil {
		return err
	}
	serializedOuter = serializedOuter[4:] // strip the four byte prefix
	encryptedInner, err := ech.hpkeContext.Seal(serializedOuter, encodedInner)
	if err != nil {
		return err
	}
	outer.encryptedClientHello, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, encryptedInner)
	if err != nil {
		return err
	}
	return nil
}

// validDNSName is a rather rudimentary check for the validity of a DNS name.
// This is used to check if the public_name in a ECHConfig is valid when we are
// picking a config. This can be somewhat lax because even if we pick a
// valid-looking name, the DNS layer will later reject it anyway.
func validDNSName(name string) bool {
	if len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) <= 1 {
		return false
	}
	for _, l := range labels {
		labelLen := len(l)
		if labelLen == 0 {
			return false
		}
		// RFC 1035 Section 2.3.4: labels must be 63 octets or less
		if labelLen > 63 {
			return false
		}
		for i, r := range l {
			if r == '-' && (i == 0 || i == labelLen-1) {
				return false
			}
			if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
				return false
			}
		}
	}
	return true
}

// ECHRejectionError is the error type returned when ECH is rejected by a remote
// server. If the server offered a ECHConfigList to use for retries, the
// RetryConfigList field will contain this list.
//
// The client may treat an ECHRejectionError with an empty set of RetryConfigs
// as a secure signal from the server.
type ECHRejectionError struct {
	RetryConfigList []byte
}

func (e *ECHRejectionError) Error() string {
	return "tls: server rejected ECH"
}

// Use generic error messages to avoid revealing ECH usage in logs/error reports.
// Specific ECH-related errors could be used to fingerprint clients using ECH.
var errMalformedECHExt = errors.New("tls: malformed extension")
var errInvalidECHExt = errors.New("tls: invalid extension")

type echExtType uint8

const (
	innerECHExt echExtType = 1
	outerECHExt echExtType = 0
)

func parseECHExt(ext []byte) (echType echExtType, cs echCipher, configID uint8, encap []byte, payload []byte, err error) {
	data := make([]byte, len(ext))
	copy(data, ext)
	s := cryptobyte.String(data)
	var echInt uint8
	if !s.ReadUint8(&echInt) {
		err = errMalformedECHExt
		return
	}
	echType = echExtType(echInt)
	if echType == innerECHExt {
		if !s.Empty() {
			err = errMalformedECHExt
			return
		}
		return echType, cs, 0, nil, nil, nil
	}
	if echType != outerECHExt {
		err = errInvalidECHExt
		return
	}
	if !s.ReadUint16(&cs.KDFID) {
		err = errMalformedECHExt
		return
	}
	if !s.ReadUint16(&cs.AEADID) {
		err = errMalformedECHExt
		return
	}
	if !s.ReadUint8(&configID) {
		err = errMalformedECHExt
		return
	}
	if !readUint16LengthPrefixed(&s, &encap) {
		err = errMalformedECHExt
		return
	}
	if !readUint16LengthPrefixed(&s, &payload) {
		err = errMalformedECHExt
		return
	}

	// NOTE: clone encap and payload so that mutating them does not mutate the
	// raw extension bytes.
	return echType, cs, configID, bytes.Clone(encap), bytes.Clone(payload), nil
}

func (c *Conn) processECHClientHello(outer *clientHelloMsg) (*clientHelloMsg, *echServerContext, error) {
	echType, echCiphersuite, configID, encap, payload, err := parseECHExt(outer.encryptedClientHello)
	if err != nil {
		if errors.Is(err, errInvalidECHExt) {
			c.sendAlert(alertIllegalParameter)
		} else {
			c.sendAlert(alertDecodeError)
		}

		return nil, nil, errInvalidECHExt
	}

	if echType == innerECHExt {
		return outer, &echServerContext{inner: true}, nil
	}

	if len(c.config.EncryptedClientHelloKeys) == 0 {
		return outer, nil, nil
	}

	// Limit trial decryption attempts to prevent CPU exhaustion attacks.
	// An attacker could send many requests with different encapsulated keys
	// to force the server to perform expensive HPKE operations.
	const maxTrialDecryptions = 10
	var trialAttempts int

	for _, echKey := range c.config.EncryptedClientHelloKeys {
		skip, config, err := parseECHConfig(echKey.Config)
		if err != nil {
			c.sendAlert(alertInternalError)
			return nil, nil, fmt.Errorf("tls: invalid EncryptedClientHelloKeys Config: %s", err)
		}
		if skip {
			// Config version is not supported (not extensionEncryptedClientHello),
			// skip to next config without error
			continue
		}
		// Optimization: skip configs that don't match the client's configID.
		// This avoids unnecessary cryptographic operations.
		// Note: configID is only 1 byte, so we still do trial decryption
		// for matching configs in case of misconfiguration.
		if config.ConfigID != configID {
			continue
		}

		// Check trial decryption limit before expensive operations
		trialAttempts++
		if trialAttempts > maxTrialDecryptions {
			// Return outer ClientHello without decryption on limit exceeded.
			// This is safer than returning an error that could reveal ECH usage.
			return outer, nil, nil
		}

		echPriv, err := hpke.ParseHPKEPrivateKey(config.KemID, echKey.PrivateKey)
		if err != nil {
			c.sendAlert(alertInternalError)
			return nil, nil, fmt.Errorf("tls: invalid EncryptedClientHelloKeys PrivateKey: %s", err)
		}
		info := append([]byte("tls ech\x00"), echKey.Config...)
		// Use config.KemID instead of hardcoded DHKEM_X25519_HKDF_SHA256
		// to support configs with different KEM algorithms
		hpkeContext, err := hpke.SetupRecipient(config.KemID, echCiphersuite.KDFID, echCiphersuite.AEADID, echPriv, info, encap)
		if err != nil {
			// attempt next trial decryption
			continue
		}

		encodedInner, err := decryptECHPayload(hpkeContext, outer.original, payload)
		if err != nil {
			// attempt next trial decryption
			continue
		}

		// NOTE: we do not enforce that the sent server_name matches the ECH
		// configs PublicName, since this is not particularly important, and
		// the client already had to know what it was in order to properly
		// encrypt the payload. This is only a MAY in the spec, so we're not
		// doing anything revolutionary.

		echInner, err := decodeInnerClientHello(outer, encodedInner)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return nil, nil, errInvalidECHExt
		}

		c.echAccepted = true

		return echInner, &echServerContext{
			hpkeContext: hpkeContext,
			configID:    configID,
			ciphersuite: echCiphersuite,
		}, nil
	}

	return outer, nil, nil
}

func buildRetryConfigList(keys []EncryptedClientHelloKey) ([]byte, error) {
	var atLeastOneRetryConfig bool
	var retryBuilder cryptobyte.Builder
	retryBuilder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range keys {
			if !c.SendAsRetry {
				continue
			}
			atLeastOneRetryConfig = true
			b.AddBytes(c.Config)
		}
	})
	if !atLeastOneRetryConfig {
		return nil, nil
	}
	return retryBuilder.Bytes()
}
