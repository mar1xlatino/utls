// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	utlserrors "github.com/refraction-networking/utls/errors"
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
var errMalformedECHConfig = utlserrors.New("tls: malformed configuration").AtError()

func parseECHConfig(enc []byte) (skip bool, ec echConfig, err error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: parsing config, input length=", len(enc))

	s := cryptobyte.String(enc)
	ec.raw = []byte(enc)
	if !s.ReadUint16(&ec.Version) {
		utlserrors.LogDebug(ctx, "ECH: failed to read config version")
		return false, echConfig{}, errMalformedECHConfig
	}
	if !s.ReadUint16(&ec.Length) {
		utlserrors.LogDebug(ctx, "ECH: failed to read config length")
		return false, echConfig{}, errMalformedECHConfig
	}
	// Use int arithmetic to prevent uint16 overflow when ec.Length is near MaxUint16.
	// Without this, ec.Length+4 could wrap around (e.g., 65535+4=3 in uint16).
	totalLen := int(ec.Length) + 4
	if len(ec.raw) < totalLen {
		utlserrors.LogDebug(ctx, "ECH: config data too short, have=", len(ec.raw), " need=", totalLen)
		return false, echConfig{}, errMalformedECHConfig
	}
	ec.raw = ec.raw[:totalLen]
	if ec.Version != extensionEncryptedClientHello {
		utlserrors.LogDebug(ctx, "ECH: skipping config with unsupported version=0x", fmt.Sprintf("%04x", ec.Version))
		s.Skip(int(ec.Length))
		return true, echConfig{}, nil
	}
	if !s.ReadUint8(&ec.ConfigID) {
		utlserrors.LogDebug(ctx, "ECH: failed to read config ID")
		return false, echConfig{}, errMalformedECHConfig
	}
	if !s.ReadUint16(&ec.KemID) {
		utlserrors.LogDebug(ctx, "ECH: failed to read KEM ID")
		return false, echConfig{}, errMalformedECHConfig
	}
	if !readUint16LengthPrefixed(&s, &ec.PublicKey) {
		utlserrors.LogDebug(ctx, "ECH: failed to read public key")
		return false, echConfig{}, errMalformedECHConfig
	}
	// Validate public key is not empty
	if len(ec.PublicKey) == 0 {
		utlserrors.LogDebug(ctx, "ECH: config has empty public key")
		return false, echConfig{}, utlserrors.New("tls: config has empty public key").AtError()
	}
	// Validate public key length based on KEM type.
	// This prevents cryptographic errors when SetupSender() is called.
	switch ec.KemID {
	case 0x0010: // DHKEM(P-256, HKDF-SHA256)
		// P-256 uncompressed point: 0x04 prefix + 32 bytes X + 32 bytes Y = 65 bytes
		if len(ec.PublicKey) != 65 {
			utlserrors.LogDebug(ctx, "ECH: invalid P-256 public key length=", len(ec.PublicKey), " expected=65")
			return false, echConfig{}, utlserrors.New("tls: config has invalid P-256 public key length").AtError()
		}
	case 0x0011: // DHKEM(P-384, HKDF-SHA384)
		// P-384 uncompressed point: 0x04 prefix + 48 bytes X + 48 bytes Y = 97 bytes
		if len(ec.PublicKey) != 97 {
			utlserrors.LogDebug(ctx, "ECH: invalid P-384 public key length=", len(ec.PublicKey), " expected=97")
			return false, echConfig{}, utlserrors.New("tls: config has invalid P-384 public key length").AtError()
		}
	case 0x0020: // DHKEM(X25519, HKDF-SHA256)
		// X25519 public key is exactly 32 bytes
		if len(ec.PublicKey) != 32 {
			utlserrors.LogDebug(ctx, "ECH: invalid X25519 public key length=", len(ec.PublicKey), " expected=32")
			return false, echConfig{}, utlserrors.New("tls: config has invalid X25519 public key length").AtError()
		}
	}
	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		utlserrors.LogDebug(ctx, "ECH: failed to read cipher suites")
		return false, echConfig{}, errMalformedECHConfig
	}
	for !cipherSuites.Empty() {
		var c echCipher
		if !cipherSuites.ReadUint16(&c.KDFID) {
			utlserrors.LogDebug(ctx, "ECH: failed to read KDF ID from cipher suite")
			return false, echConfig{}, errMalformedECHConfig
		}
		if !cipherSuites.ReadUint16(&c.AEADID) {
			utlserrors.LogDebug(ctx, "ECH: failed to read AEAD ID from cipher suite")
			return false, echConfig{}, errMalformedECHConfig
		}
		ec.SymmetricCipherSuite = append(ec.SymmetricCipherSuite, c)
	}
	if !s.ReadUint8(&ec.MaxNameLength) {
		utlserrors.LogDebug(ctx, "ECH: failed to read max name length")
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
		utlserrors.LogDebug(ctx, "ECH: failed to read public name")
		return false, echConfig{}, errMalformedECHConfig
	}
	ec.PublicName = publicName
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		utlserrors.LogDebug(ctx, "ECH: failed to read extensions")
		return false, echConfig{}, errMalformedECHConfig
	}
	for !extensions.Empty() {
		var e echExtension
		if !extensions.ReadUint16(&e.Type) {
			utlserrors.LogDebug(ctx, "ECH: failed to read extension type")
			return false, echConfig{}, errMalformedECHConfig
		}
		if !extensions.ReadUint16LengthPrefixed((*cryptobyte.String)(&e.Data)) {
			utlserrors.LogDebug(ctx, "ECH: failed to read extension data")
			return false, echConfig{}, errMalformedECHConfig
		}
		ec.Extensions = append(ec.Extensions, e)
	}

	utlserrors.LogDebug(ctx, "ECH: parsed config successfully, configID=", ec.ConfigID,
		" kemID=0x", fmt.Sprintf("%04x", ec.KemID),
		" publicName=", string(ec.PublicName),
		" cipherSuites=", len(ec.SymmetricCipherSuite))

	return false, ec, nil
}

// parseECHConfigList parses a draft-ietf-tls-esni-18 ECHConfigList, returning a
// slice of parsed ECHConfigs, in the same order they were parsed, or an error
// if the list is malformed.
func parseECHConfigList(data []byte) ([]echConfig, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: parsing config list, length=", len(data))

	s := cryptobyte.String(data)
	var length uint16
	if !s.ReadUint16(&length) {
		utlserrors.LogDebug(ctx, "ECH: failed to read config list length prefix")
		return nil, errMalformedECHConfig
	}
	if length != uint16(len(data)-2) {
		utlserrors.LogDebug(ctx, "ECH: config list length mismatch, declared=", length, " actual=", len(data)-2)
		return nil, errMalformedECHConfig
	}
	var configs []echConfig
	configIndex := 0
	for len(s) > 0 {
		if len(s) < 4 {
			utlserrors.LogDebug(ctx, "ECH: config list truncated at index=", configIndex)
			return nil, utlserrors.New("tls: malformed configuration").AtError()
		}
		configLen := uint16(s[2])<<8 | uint16(s[3])
		// Bounds check: ensure we have enough data before reslicing
		totalLen := int(configLen) + 4
		if totalLen > len(s) {
			utlserrors.LogDebug(ctx, "ECH: config length exceeds available data at index=", configIndex,
				" configLen=", configLen, " available=", len(s))
			return nil, utlserrors.New("tls: ECH config length exceeds available data").AtError()
		}
		skip, ec, err := parseECHConfig(s)
		if err != nil {
			return nil, err
		}
		s = s[totalLen:]
		if !skip {
			configs = append(configs, ec)
		}
		configIndex++
	}

	utlserrors.LogDebug(ctx, "ECH: parsed config list successfully, totalConfigs=", configIndex, " usableConfigs=", len(configs))
	return configs, nil
}

func pickECHConfig(list []echConfig) *echConfig {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: picking config from list of ", len(list), " configs")

	for i, ec := range list {
		if _, ok := hpke.SupportedKEMs[ec.KemID]; !ok {
			utlserrors.LogDebug(ctx, "ECH: skipping config[", i, "] configID=", ec.ConfigID,
				" unsupported KEM=0x", fmt.Sprintf("%04x", ec.KemID))
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
			utlserrors.LogDebug(ctx, "ECH: skipping config[", i, "] configID=", ec.ConfigID,
				" no supported cipher suite")
			continue
		}
		if !validDNSName(string(ec.PublicName)) {
			utlserrors.LogDebug(ctx, "ECH: skipping config[", i, "] configID=", ec.ConfigID,
				" invalid public name=", string(ec.PublicName))
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
			utlserrors.LogDebug(ctx, "ECH: skipping config[", i, "] configID=", ec.ConfigID,
				" has unsupported mandatory extension")
			continue
		}
		utlserrors.LogDebug(ctx, "ECH: selected config[", i, "] configID=", ec.ConfigID,
			" publicName=", string(ec.PublicName))
		return &ec
	}

	utlserrors.LogDebug(ctx, "ECH: no suitable config found in list")
	return nil
}

func pickECHCipherSuite(suites []echCipher) (echCipher, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: picking cipher suite from ", len(suites), " candidates")

	for i, s := range suites {
		// NOTE: all of the supported AEADs and KDFs are fine, rather than
		// imposing some sort of preference here, we just pick the first valid
		// suite.
		if _, ok := hpke.SupportedAEADs[s.AEADID]; !ok {
			utlserrors.LogDebug(ctx, "ECH: skipping cipher suite[", i, "] unsupported AEAD=0x",
				fmt.Sprintf("%04x", s.AEADID))
			continue
		}
		if _, ok := hpke.SupportedKDFs[s.KDFID]; !ok {
			utlserrors.LogDebug(ctx, "ECH: skipping cipher suite[", i, "] unsupported KDF=0x",
				fmt.Sprintf("%04x", s.KDFID))
			continue
		}
		utlserrors.LogDebug(ctx, "ECH: selected cipher suite KDF=0x", fmt.Sprintf("%04x", s.KDFID),
			" AEAD=0x", fmt.Sprintf("%04x", s.AEADID))
		return s, nil
	}

	utlserrors.LogDebug(ctx, "ECH: no supported cipher suite found")
	return echCipher{}, utlserrors.New("tls: no supported symmetric ciphersuites for ECH").AtError()
}

// filterUsableECHConfigs parses and re-encodes only the usable ECH configs from
// the raw config list. This ensures that the RetryConfigList in ECHRejectionError
// only contains configs that the client can actually use.
//
// Returns nil if no usable configs exist or on parse errors.
func filterUsableECHConfigs(rawConfigs []byte) []byte {
	ctx := context.Background()

	if len(rawConfigs) == 0 {
		utlserrors.LogDebug(ctx, "ECH: filterUsableECHConfigs called with empty input")
		return nil
	}

	utlserrors.LogDebug(ctx, "ECH: filtering usable configs from ", len(rawConfigs), " bytes")

	configs, err := parseECHConfigList(rawConfigs)
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to parse config list for filtering")
		return nil
	}

	// Filter to only usable configs
	var usableRawConfigs []byte
	usableCount := 0
	for i, ec := range configs {
		// Check KEM support
		if _, ok := hpke.SupportedKEMs[ec.KemID]; !ok {
			utlserrors.LogDebug(ctx, "ECH: filter skipping config[", i, "] unsupported KEM")
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
			utlserrors.LogDebug(ctx, "ECH: filter skipping config[", i, "] no valid cipher suite")
			continue
		}

		// Check valid public name
		if !validDNSName(string(ec.PublicName)) {
			utlserrors.LogDebug(ctx, "ECH: filter skipping config[", i, "] invalid public name")
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
			utlserrors.LogDebug(ctx, "ECH: filter skipping config[", i, "] unsupported mandatory extension")
			continue
		}

		// This config is usable, include its raw bytes
		usableRawConfigs = append(usableRawConfigs, ec.raw...)
		usableCount++
	}

	if len(usableRawConfigs) == 0 {
		utlserrors.LogDebug(ctx, "ECH: no usable configs found after filtering")
		return nil
	}

	// Re-encode with length prefix
	result := make([]byte, 2+len(usableRawConfigs))
	result[0] = byte(len(usableRawConfigs) >> 8)
	result[1] = byte(len(usableRawConfigs))
	copy(result[2:], usableRawConfigs)

	utlserrors.LogDebug(ctx, "ECH: filtered to ", usableCount, " usable configs, result length=", len(result))
	return result
}

// [uTLS SECTION BEGIN]
func encodeInnerClientHello(inner *clientHelloMsg, maxNameLength int) ([]byte, error) {
	return encodeInnerClientHelloReorderOuterExts(inner, maxNameLength, nil)
}

// [uTLS SECTION END]

func encodeInnerClientHelloReorderOuterExts(inner *clientHelloMsg, maxNameLength int, outerExts []uint16) ([]byte, error) { // uTLS
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: encoding inner ClientHello, serverName=", inner.serverName,
		" maxNameLength=", maxNameLength)

	h, err := inner.marshalMsgReorderOuterExts(true, outerExts)
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to marshal inner ClientHello")
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

	utlserrors.LogDebug(ctx, "ECH: inner ClientHello encoded, baseLen=", len(h),
		" namePadding=", namePadding, " alignPadding=", alignPadding, " totalLen=", len(h)+paddingLen)

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
	ctx := context.Background()

	s := cryptobyte.String(hello.original)
	if !s.Skip(4+2+32) || // header, version, random
		!skipUint8LengthPrefixed(&s) || // session ID
		!skipUint16LengthPrefixed(&s) || // cipher suites
		!skipUint8LengthPrefixed(&s) { // compression methods
		utlserrors.LogDebug(ctx, "ECH: failed to skip fixed fields in outer ClientHello")
		return nil, utlserrors.New("tls: malformed outer client hello").AtError()
	}
	var rawExtensions []rawExtension
	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		utlserrors.LogDebug(ctx, "ECH: failed to read extensions from outer ClientHello")
		return nil, utlserrors.New("tls: malformed outer client hello").AtError()
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			utlserrors.LogDebug(ctx, "ECH: failed to parse extension in outer ClientHello")
			return nil, utlserrors.New("tls: invalid inner client hello").AtError()
		}
		rawExtensions = append(rawExtensions, rawExtension{extension, extData})
	}

	utlserrors.LogDebug(ctx, "ECH: extracted ", len(rawExtensions), " raw extensions from outer ClientHello")
	return rawExtensions, nil
}

func decodeInnerClientHello(outer *clientHelloMsg, encoded []byte) (*clientHelloMsg, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: decoding inner ClientHello, encoded length=", len(encoded))

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
		utlserrors.LogDebug(ctx, "ECH: failed to parse inner ClientHello structure")
		return nil, utlserrors.New("tls: invalid inner client hello").AtError()
	}

	// The specification says we must verify that the trailing padding is all
	// zeros. This is kind of weird for TLS messages, where we generally just
	// throw away any trailing garbage.
	//
	// Limit maximum padding to prevent memory exhaustion attacks.
	// 16KB is more than sufficient for any realistic ECH padding.
	const maxECHPadding = 16384
	if len(innerReader) > maxECHPadding {
		utlserrors.LogDebug(ctx, "ECH: inner ClientHello padding too large=", len(innerReader))
		return nil, utlserrors.New("tls: padding too large").AtError()
	}
	for _, p := range innerReader {
		if p != 0 {
			utlserrors.LogDebug(ctx, "ECH: inner ClientHello has non-zero padding")
			return nil, utlserrors.New("tls: invalid inner client hello").AtError()
		}
	}

	rawOuterExts, err := extractRawExtensions(outer)
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to extract raw extensions from outer ClientHello")
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
					recon.SetError(utlserrors.New("tls: invalid inner client hello").AtError())
					return
				}
				if extension == extensionECHOuterExtensions {
					if !extData.ReadUint8LengthPrefixed(&extData) {
						recon.SetError(utlserrors.New("tls: invalid inner client hello").AtError())
						return
					}
					var i int
					for !extData.Empty() {
						var extType uint16
						if !extData.ReadUint16(&extType) {
							recon.SetError(utlserrors.New("tls: invalid inner client hello").AtError())
							return
						}
						if extType == extensionEncryptedClientHello {
							recon.SetError(utlserrors.New("tls: invalid outer extensions").AtError())
							return
						}
						for ; i <= len(rawOuterExts); i++ {
							if i == len(rawOuterExts) {
								recon.SetError(utlserrors.New("tls: invalid outer extensions").AtError())
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
		utlserrors.LogDebug(ctx, "ECH: failed to reconstruct inner ClientHello")
		return nil, err
	}
	inner := &clientHelloMsg{}
	if !inner.unmarshal(reconBytes) {
		utlserrors.LogDebug(ctx, "ECH: failed to unmarshal reconstructed inner ClientHello")
		return nil, utlserrors.New("tls: invalid reconstructed inner client hello").AtError()
	}

	if !bytes.Equal(inner.encryptedClientHello, []byte{uint8(innerECHExt)}) {
		utlserrors.LogDebug(ctx, "ECH: inner ClientHello has invalid ECH extension marker")
		return nil, errInvalidECHExt
	}

	// Inner ClientHello MUST offer exactly one version, and it MUST be TLS 1.3.
	// The second condition is simplified: if len != 1, we fail; otherwise len == 1,
	// so we can safely check supportedVersions[0] without the redundant length check.
	if len(inner.supportedVersions) != 1 || inner.supportedVersions[0] != VersionTLS13 {
		utlserrors.LogDebug(ctx, "ECH: inner ClientHello has incompatible protocol versions")
		return nil, utlserrors.New("tls: incompatible protocol versions").AtError()
	}

	utlserrors.LogDebug(ctx, "ECH: successfully decoded inner ClientHello, serverName=", inner.serverName)
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

func decryptECHPayload(hpkeContext *hpke.Recipient, hello, payload []byte) ([]byte, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: decrypting payload, helloLen=", len(hello), " payloadLen=", len(payload))

	// SECURITY: Find the exact position of the ECH payload within the ClientHello.
	// Using position-based zeroing instead of bytes.Replace is critical for security:
	// bytes.Replace finds the FIRST occurrence of payload bytes, which could be in
	// SNI, ALPN, or other extensions if the same byte sequence happens to appear there.
	// This would cause AAD mismatch and decryption failure or potential security issues.
	payloadPos := findECHPayloadPosition(hello, len(payload))
	if payloadPos < 0 {
		utlserrors.LogDebug(ctx, "ECH: failed to find payload position in ClientHello")
		return nil, utlserrors.New("tls: failed to locate ECH payload position for AAD construction").AtError()
	}

	// Create AAD by copying hello[4:] (without the 4-byte header) and zeroing
	// out the ECH payload at its exact known position.
	outerAAD := make([]byte, len(hello)-4)
	copy(outerAAD, hello[4:])

	if payloadPos+len(payload) > len(outerAAD) {
		utlserrors.LogDebug(ctx, "ECH: payload position exceeds outerAAD bounds, pos=", payloadPos,
			" payloadLen=", len(payload), " outerAADLen=", len(outerAAD))
		return nil, utlserrors.New("tls: ECH payload position out of bounds").AtError()
	}

	// Zero out the payload at its exact position using direct memory copy.
	// This is safe because we have verified bounds and found the exact offset.
	copy(outerAAD[payloadPos:payloadPos+len(payload)], make([]byte, len(payload)))
	utlserrors.LogDebug(ctx, "ECH: zeroed payload at position=", payloadPos, " length=", len(payload))

	plaintext, err := hpkeContext.Open(outerAAD, payload)
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: HPKE decryption failed")
		return nil, err
	}

	utlserrors.LogDebug(ctx, "ECH: successfully decrypted payload, plaintext length=", len(plaintext))
	return plaintext, nil
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
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: computing outer ECH extension, configID=", ech.config.ConfigID,
		" useKey=", useKey)

	var encapKey []byte
	if useKey {
		encapKey = ech.encapsulatedKey
		utlserrors.LogDebug(ctx, "ECH: using encapsulated key, length=", len(encapKey))
	}
	encodedInner, err := encodeInnerClientHello(inner, int(ech.config.MaxNameLength))
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to encode inner ClientHello")
		return err
	}
	// Use the AEAD's Overhead() method to get the tag length dynamically.
	// This ensures correct operation if AEADs with different tag lengths
	// are added in the future.
	encryptedLen := len(encodedInner) + ech.hpkeContext.Overhead()
	utlserrors.LogDebug(ctx, "ECH: encoded inner length=", len(encodedInner), " encrypted length=", encryptedLen)

	outer.encryptedClientHello, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, make([]byte, encryptedLen))
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to generate placeholder outer extension")
		return err
	}
	serializedOuter, err := outer.marshal()
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to marshal outer ClientHello")
		return err
	}
	serializedOuter = serializedOuter[4:] // strip the four byte prefix
	encryptedInner, err := ech.hpkeContext.Seal(serializedOuter, encodedInner)
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: HPKE encryption failed")
		return err
	}
	outer.encryptedClientHello, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, encryptedInner)
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to generate final outer extension")
		return err
	}

	utlserrors.LogDebug(ctx, "ECH: successfully computed outer extension, length=", len(outer.encryptedClientHello))
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
var errMalformedECHExt = utlserrors.New("tls: malformed extension").AtError()
var errInvalidECHExt = utlserrors.New("tls: invalid extension").AtError()

type echExtType uint8

const (
	innerECHExt echExtType = 1
	outerECHExt echExtType = 0
)

func parseECHExt(ext []byte) (echType echExtType, cs echCipher, configID uint8, encap []byte, payload []byte, err error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: parsing ECH extension, length=", len(ext))

	data := make([]byte, len(ext))
	copy(data, ext)
	s := cryptobyte.String(data)
	var echInt uint8
	if !s.ReadUint8(&echInt) {
		utlserrors.LogDebug(ctx, "ECH: failed to read ECH type byte")
		err = errMalformedECHExt
		return
	}
	echType = echExtType(echInt)
	if echType == innerECHExt {
		if !s.Empty() {
			utlserrors.LogDebug(ctx, "ECH: inner ECH extension has trailing data")
			err = errMalformedECHExt
			return
		}
		utlserrors.LogDebug(ctx, "ECH: parsed inner ECH extension")
		return echType, cs, 0, nil, nil, nil
	}
	if echType != outerECHExt {
		utlserrors.LogDebug(ctx, "ECH: invalid ECH type=", echInt)
		err = errInvalidECHExt
		return
	}
	if !s.ReadUint16(&cs.KDFID) {
		utlserrors.LogDebug(ctx, "ECH: failed to read KDF ID")
		err = errMalformedECHExt
		return
	}
	if !s.ReadUint16(&cs.AEADID) {
		utlserrors.LogDebug(ctx, "ECH: failed to read AEAD ID")
		err = errMalformedECHExt
		return
	}
	if !s.ReadUint8(&configID) {
		utlserrors.LogDebug(ctx, "ECH: failed to read config ID")
		err = errMalformedECHExt
		return
	}
	if !readUint16LengthPrefixed(&s, &encap) {
		utlserrors.LogDebug(ctx, "ECH: failed to read encapsulated key")
		err = errMalformedECHExt
		return
	}
	if !readUint16LengthPrefixed(&s, &payload) {
		utlserrors.LogDebug(ctx, "ECH: failed to read payload")
		err = errMalformedECHExt
		return
	}

	utlserrors.LogDebug(ctx, "ECH: parsed outer extension, configID=", configID,
		" KDF=0x", fmt.Sprintf("%04x", cs.KDFID),
		" AEAD=0x", fmt.Sprintf("%04x", cs.AEADID),
		" encapLen=", len(encap), " payloadLen=", len(payload))

	// NOTE: clone encap and payload so that mutating them does not mutate the
	// raw extension bytes.
	return echType, cs, configID, bytes.Clone(encap), bytes.Clone(payload), nil
}

func (c *Conn) processECHClientHello(outer *clientHelloMsg) (*clientHelloMsg, *echServerContext, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH: server processing ClientHello with ECH extension")

	echType, echCiphersuite, configID, encap, payload, err := parseECHExt(outer.encryptedClientHello)
	if err != nil {
		utlserrors.LogDebug(ctx, "ECH: failed to parse ECH extension")
		if errors.Is(err, errInvalidECHExt) {
			c.sendAlert(alertIllegalParameter)
		} else {
			c.sendAlert(alertDecodeError)
		}

		return nil, nil, errInvalidECHExt
	}

	utlserrors.LogDebug(ctx, "ECH: parsed extension, type=", echType, " configID=", configID,
		" KDF=0x", fmt.Sprintf("%04x", echCiphersuite.KDFID),
		" AEAD=0x", fmt.Sprintf("%04x", echCiphersuite.AEADID))

	if echType == innerECHExt {
		utlserrors.LogDebug(ctx, "ECH: received inner ECH extension type, passing through")
		return outer, &echServerContext{inner: true}, nil
	}

	if len(c.config.EncryptedClientHelloKeys) == 0 {
		utlserrors.LogDebug(ctx, "ECH: no server ECH keys configured, passing through outer ClientHello")
		return outer, nil, nil
	}

	utlserrors.LogDebug(ctx, "ECH: attempting decryption with ", len(c.config.EncryptedClientHelloKeys), " server keys")

	// Limit trial decryption attempts to prevent CPU exhaustion attacks.
	// An attacker could send many requests with different encapsulated keys
	// to force the server to perform expensive HPKE operations.
	const maxTrialDecryptions = 10
	var trialAttempts int

	for keyIndex, echKey := range c.config.EncryptedClientHelloKeys {
		skip, config, err := parseECHConfig(echKey.Config)
		if err != nil {
			utlserrors.LogDebug(ctx, "ECH: invalid server config at index=", keyIndex)
			c.sendAlert(alertInternalError)
			return nil, nil, utlserrors.New("tls: invalid EncryptedClientHelloKeys Config").Base(err).AtError()
		}
		if skip {
			// Config version is not supported (not extensionEncryptedClientHello),
			// skip to next config without error
			utlserrors.LogDebug(ctx, "ECH: skipping unsupported config version at index=", keyIndex)
			continue
		}
		// Optimization: skip configs that don't match the client's configID.
		// This avoids unnecessary cryptographic operations.
		// Note: configID is only 1 byte, so we still do trial decryption
		// for matching configs in case of misconfiguration.
		if config.ConfigID != configID {
			utlserrors.LogDebug(ctx, "ECH: config ID mismatch at index=", keyIndex,
				" have=", config.ConfigID, " want=", configID)
			continue
		}

		// Check trial decryption limit before expensive operations
		trialAttempts++
		if trialAttempts > maxTrialDecryptions {
			// Return outer ClientHello without decryption on limit exceeded.
			// This is safer than returning an error that could reveal ECH usage.
			utlserrors.LogDebug(ctx, "ECH: trial decryption limit exceeded, passing through outer ClientHello")
			return outer, nil, nil
		}

		utlserrors.LogDebug(ctx, "ECH: trying decryption with key index=", keyIndex, " attempt=", trialAttempts)

		echPriv, err := hpke.ParseHPKEPrivateKey(config.KemID, echKey.PrivateKey)
		if err != nil {
			utlserrors.LogDebug(ctx, "ECH: invalid private key at index=", keyIndex)
			c.sendAlert(alertInternalError)
			return nil, nil, utlserrors.New("tls: invalid EncryptedClientHelloKeys PrivateKey").Base(err).AtError()
		}
		info := append([]byte("tls ech\x00"), echKey.Config...)
		// Use config.KemID instead of hardcoded DHKEM_X25519_HKDF_SHA256
		// to support configs with different KEM algorithms
		hpkeContext, err := hpke.SetupRecipient(config.KemID, echCiphersuite.KDFID, echCiphersuite.AEADID, echPriv, info, encap)
		if err != nil {
			// attempt next trial decryption
			utlserrors.LogDebug(ctx, "ECH: HPKE setup failed at index=", keyIndex, ", trying next")
			continue
		}

		encodedInner, err := decryptECHPayload(hpkeContext, outer.original, payload)
		if err != nil {
			// attempt next trial decryption
			utlserrors.LogDebug(ctx, "ECH: decryption failed at index=", keyIndex, ", trying next")
			continue
		}

		// NOTE: we do not enforce that the sent server_name matches the ECH
		// configs PublicName, since this is not particularly important, and
		// the client already had to know what it was in order to properly
		// encrypt the payload. This is only a MAY in the spec, so we're not
		// doing anything revolutionary.

		echInner, err := decodeInnerClientHello(outer, encodedInner)
		if err != nil {
			utlserrors.LogDebug(ctx, "ECH: failed to decode inner ClientHello")
			c.sendAlert(alertIllegalParameter)
			return nil, nil, errInvalidECHExt
		}

		c.echAccepted = true

		utlserrors.LogDebug(ctx, "ECH: successfully decrypted and accepted, configID=", configID,
			" innerServerName=", echInner.serverName)

		return echInner, &echServerContext{
			hpkeContext: hpkeContext,
			configID:    configID,
			ciphersuite: echCiphersuite,
		}, nil
	}

	utlserrors.LogDebug(ctx, "ECH: no matching config found, passing through outer ClientHello")
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
