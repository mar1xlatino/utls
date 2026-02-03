// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/mlkem"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sort"

	"github.com/refraction-networking/utls/dicttls"
	utlserrors "github.com/refraction-networking/utls/errors"
)

var ErrUnknownClientHelloID = utlserrors.New("tls: unknown ClientHelloID").AtError()

// Shared cipher suite lists to reduce code duplication across browser profiles.
// Chrome/Edge cipher suites (16 ciphers with GREASE)
var chromeCipherSuites = []uint16{
	GREASE_PLACEHOLDER,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
}

// Firefox cipher suites (17 ciphers, different order - ChaCha20 before AES-256)
var firefoxCipherSuites = []uint16{
	TLS_AES_128_GCM_SHA256,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_CBC_SHA,
}

// Safari/iOS cipher suites (20 ciphers including GREASE and 3DES - ECDSA preferred over RSA)
// Used by Safari 18, iOS 18 and earlier
var safariCipherSuites = []uint16{
	GREASE_PLACEHOLDER,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// Safari/iOS modern cipher suites (18 ciphers - no 3DES, used by Safari 26, iOS 26+)
var safariCipherSuitesModern = []uint16{
	GREASE_PLACEHOLDER,
	TLS_AES_128_GCM_SHA256,
	TLS_AES_256_GCM_SHA384,
	TLS_CHACHA20_POLY1305_SHA256,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	TLS_RSA_WITH_AES_256_GCM_SHA384,
	TLS_RSA_WITH_AES_128_GCM_SHA256,
	TLS_RSA_WITH_AES_256_CBC_SHA,
	TLS_RSA_WITH_AES_128_CBC_SHA,
}

// Common signature algorithms used by Chrome/Edge/Safari
var defaultSignatureAlgorithms = []SignatureScheme{
	ECDSAWithP256AndSHA256,
	PSSWithSHA256,
	PKCS1WithSHA256,
	ECDSAWithP384AndSHA384,
	PSSWithSHA384,
	PKCS1WithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA512,
}

// Safari signature algorithms (includes SHA1)
var safariSignatureAlgorithms = []SignatureScheme{
	ECDSAWithP256AndSHA256,
	PSSWithSHA256,
	PKCS1WithSHA256,
	ECDSAWithP384AndSHA384,
	ECDSAWithSHA1,
	PSSWithSHA384,
	PKCS1WithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA512,
	PKCS1WithSHA1,
}

// Firefox signature algorithms for older versions (includes SHA1)
var firefoxSignatureAlgorithmsLegacy = []SignatureScheme{
	ECDSAWithP256AndSHA256,
	ECDSAWithP384AndSHA384,
	ECDSAWithP521AndSHA512,
	PSSWithSHA256,
	PSSWithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA256,
	PKCS1WithSHA384,
	PKCS1WithSHA512,
	ECDSAWithSHA1,
	PKCS1WithSHA1,
}

// Firefox signature algorithms for latest versions (Firefox 145+, 2025)
// SHA1 removed: Modern Firefox (2025+) no longer includes deprecated SHA1 variants
// as they are considered cryptographically weak and anachronistic in fingerprints.
// Using SHA1 in modern browser fingerprints is a DPI detection vector.
var firefoxSignatureAlgorithmsModern = []SignatureScheme{
	ECDSAWithP256AndSHA256,
	ECDSAWithP384AndSHA384,
	ECDSAWithP521AndSHA512,
	PSSWithSHA256,
	PSSWithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA256,
	PKCS1WithSHA384,
	PKCS1WithSHA512,
}

// Safari/iOS signature algorithms for modern versions (Safari 26+, iOS 26+, 2025)
// SHA1 removed: Modern Safari/iOS (2025+) no longer includes deprecated SHA1 variants
// as they are considered cryptographically weak and anachronistic in fingerprints.
// Using SHA1 in modern browser fingerprints is a DPI detection vector.
var safariSignatureAlgorithmsModern = []SignatureScheme{
	ECDSAWithP256AndSHA256,
	PSSWithSHA256,
	PKCS1WithSHA256,
	ECDSAWithP384AndSHA384,
	PSSWithSHA384,
	PKCS1WithSHA384,
	PSSWithSHA512,
	PKCS1WithSHA512,
}

// =============================================================================
// Cipher Suite Ordering Based on Hardware Capabilities
// =============================================================================
//
// Real browsers (Chrome, Edge) reorder cipher suites based on AES-NI availability:
//   - With AES hardware: AES-GCM suites first (faster with hardware acceleration)
//   - Without AES hardware: ChaCha20 suites first (faster in software)
//
// This ordering is visible in the ClientHello and affects JA3/JA4 fingerprints.
// Static ordering across all connections is a detection vector since real
// browsers show variation based on the underlying hardware.
//
// The following functions implement dynamic cipher suite reordering.
// =============================================================================

// chachaCipherSuites contains all ChaCha20-Poly1305 cipher suite IDs.
// Used for dynamic reordering based on hardware capabilities.
var chachaCipherSuites = map[uint16]bool{
	TLS_CHACHA20_POLY1305_SHA256:           true, // TLS 1.3
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: true, // TLS 1.2
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:   true, // TLS 1.2
}

// aesGCMCipherSuites contains all AES-GCM cipher suite IDs.
// Used for dynamic reordering based on hardware capabilities.
var aesGCMCipherSuites = map[uint16]bool{
	// TLS 1.3
	TLS_AES_128_GCM_SHA256: true,
	TLS_AES_256_GCM_SHA384: true,
	// TLS 1.2
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	TLS_RSA_WITH_AES_128_GCM_SHA256:         true,
	TLS_RSA_WITH_AES_256_GCM_SHA384:         true,
}

// IsChaCha20CipherSuite returns true if the cipher suite is ChaCha20-Poly1305.
func IsChaCha20CipherSuite(id uint16) bool {
	return chachaCipherSuites[id]
}

// IsAESGCMCipherSuite returns true if the cipher suite is AES-GCM.
func IsAESGCMCipherSuite(id uint16) bool {
	return aesGCMCipherSuites[id]
}

// ReorderCipherSuitesForHardware reorders cipher suites based on hardware capabilities.
// This mimics real browser behavior where:
//   - With AES-NI: AES-GCM suites are placed before ChaCha20
//   - Without AES-NI: ChaCha20 suites are placed before AES-GCM
//
// The function preserves the relative order within AES-GCM and ChaCha20 groups,
// and keeps other cipher suites (CBC, RSA-only, etc.) in their original positions.
//
// Parameters:
//   - ciphers: The original cipher suite list
//   - preferAES: If true, order AES-GCM before ChaCha20; if false, reverse
//
// Returns a new slice with reordered cipher suites (does not modify input).
func ReorderCipherSuitesForHardware(ciphers []uint16, preferAES bool) []uint16 {
	if len(ciphers) == 0 {
		return ciphers
	}

	// Separate cipher suites into categories, preserving original order within each
	var aesGCM []uint16 // AES-GCM cipher suites
	var chacha []uint16 // ChaCha20-Poly1305 cipher suites
	var other []uint16  // Everything else (CBC, RSA-only, 3DES, etc.)

	// Track original GREASE positions for restoration
	greasePositions := make(map[int]uint16)

	for i, c := range ciphers {
		if isGREASEUint16(c) {
			greasePositions[i] = c
		} else if IsAESGCMCipherSuite(c) {
			aesGCM = append(aesGCM, c)
		} else if IsChaCha20CipherSuite(c) {
			chacha = append(chacha, c)
		} else {
			other = append(other, c)
		}
	}

	// Build reordered list: preferred algorithm first, then the other, then rest
	result := make([]uint16, 0, len(ciphers))

	if preferAES {
		// AES-GCM first (hardware accelerated), then ChaCha20, then others
		result = append(result, aesGCM...)
		result = append(result, chacha...)
	} else {
		// ChaCha20 first (faster in software), then AES-GCM, then others
		result = append(result, chacha...)
		result = append(result, aesGCM...)
	}
	result = append(result, other...)

	// Restore GREASE values at their original positions
	// GREASE is typically at position 0 for Chrome
	if len(greasePositions) > 0 {
		// Find the first GREASE position (usually 0 for Chrome)
		for pos, greaseVal := range greasePositions {
			if pos == 0 {
				// Insert GREASE at the beginning
				result = append([]uint16{greaseVal}, result...)
			}
			// Note: Chrome only has one GREASE at position 0 for cipher suites
			// If other positions are needed, expand this logic
		}
	}

	return result
}

// ApplyCipherSuiteOrder applies the cipher suite ordering hint to a cipher suite list.
// This is the main entry point for cipher suite reordering based on hardware.
//
// Parameters:
//   - ciphers: The original cipher suite list from the profile
//   - hint: The ordering hint (auto, aes-first, chacha-first, static)
//
// Returns a new slice with reordered cipher suites.
func ApplyCipherSuiteOrder(ciphers []uint16, hint CipherSuiteOrderHint) []uint16 {
	switch hint {
	case CipherSuiteOrderAuto:
		// Detect hardware and order accordingly
		return ReorderCipherSuitesForHardware(ciphers, HasAESGCMHardwareSupport())
	case CipherSuiteOrderAESFirst:
		// Force AES-GCM first
		return ReorderCipherSuitesForHardware(ciphers, true)
	case CipherSuiteOrderChaChaFirst:
		// Force ChaCha20 first
		return ReorderCipherSuitesForHardware(ciphers, false)
	case CipherSuiteOrderStatic, "":
		// Use profile's exact order (legacy behavior)
		return ciphers
	default:
		// Unknown hint, use static order for safety
		return ciphers
	}
}

// UTLSIdToSpec converts a ClientHelloID to a corresponding ClientHelloSpec.
func UTLSIdToSpec(id ClientHelloID) (ClientHelloSpec, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "parrot: resolving profile ID:", id.Str())

	switch id {
	case HelloChrome_106_Shuffle:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement
	case HelloChrome_115_PQ:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER,
					X25519Kyber768Draft00,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}),
		}, nil
	// Chrome ECH
	case HelloChrome_120:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement and ECH
	case HelloChrome_120_PQ:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519Kyber768Draft00, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_131:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_133:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_142:
		// Chrome 142 (October 2025) - Same TLS fingerprint as Chrome 133
		// X25519MLKEM768 (0x11EC), extension shuffling, new ALPS codepoint (17613)
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_143:
		// Chrome 143 (December 2025) - Same TLS fingerprint as Chrome 142
		// No cipher suite or extension changes were made in this version.
		// X25519MLKEM768 (0x11EC), extension shuffling, new ALPS codepoint (17613)
		return UTLSIdToSpec(HelloChrome_142)
	case HelloChrome_144:
		// Chrome 144 (January 2026) - Same TLS fingerprint as Chrome 142
		// No cipher suite or extension changes were made in this version.
		// X25519MLKEM768 (0x11EC), extension shuffling, new ALPS codepoint (17613)
		return UTLSIdToSpec(HelloChrome_142)
	case HelloFirefox_120:
		// Firefox 120 with FFDHE groups matching real Firefox.
		// FFDHE key exchange is fully implemented - HelloRetryRequest works correctly.
		return ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			SessionIDLength:    SessionIDLengthNone, // Firefox sends empty session ID for fresh TLS 1.3 connections
			CipherSuites:       firefoxCipherSuites,
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					X25519, CurveP256, CurveP384, CurveP521, CurveFFDHE2048, CurveFFDHE3072,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, ECDSAWithSHA1,
				}},
				&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}, {Group: CurveP256}}},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
				&CookieExtension{}, // Placeholder for HRR - Firefox places after supported_versions
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: firefoxSignatureAlgorithmsLegacy},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&FakeRecordSizeLimitExtension{Limit: 0x4001},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli, CertCompressionZlib}},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
				&GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: []HPKESymmetricCipherSuite{
						{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
						{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
					},
					CandidatePayloadLens: []uint16{223},
				},
			},
		}, nil
	case HelloFirefox_145:
		// Firefox 145 (November 2025) with extension shuffling and X25519MLKEM768
		// Includes FFDHE groups (CurveFFDHE2048, CurveFFDHE3072) matching real Firefox.
		// FFDHE key exchange is fully implemented - HelloRetryRequest works correctly.
		return ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			SessionIDLength:    32, // Firefox sends 32-byte session ID for TLS 1.3 middlebox compatibility (RFC 8446 Appendix D.4)
			CipherSuites:       firefoxCipherSuites,
			CompressionMethods: []uint8{0x0},
			Extensions: ShuffleFirefoxTLSExtensions([]TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521, CurveFFDHE2048, CurveFFDHE3072,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: X25519MLKEM768}, {Group: X25519}, {Group: CurveP256},
				}},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
				&CookieExtension{}, // Placeholder for HRR - Firefox places after supported_versions
				// SHA1 removed from Firefox 145+: Modern Firefox no longer includes deprecated SHA1
				// signature algorithms (ECDSAWithSHA1, PKCS1WithSHA1) as they are cryptographically weak.
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: firefoxSignatureAlgorithmsModern},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&FakeRecordSizeLimitExtension{Limit: 0x4001},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{
					CertCompressionZlib, CertCompressionBrotli, CertCompressionZstd,
				}},
				&GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: []HPKESymmetricCipherSuite{
						{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
						{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
					},
					CandidatePayloadLens: []uint16{223},
				},
			}),
		}, nil
	case HelloIOS_18:
		// iOS 18 (September 2024) - Same as Safari 18
		// No extension shuffling, no post-quantum yet
		// Safari/iOS uses GREASE in supported_groups (per captured profile GREASEConfig)
		return ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			SessionIDLength:    SessionIDLengthNone, // iOS sends empty session ID for fresh TLS 1.3 connections
			CipherSuites:       safariCipherSuites,
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384, CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: safariSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}}, {Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloIOS_26:
		// iOS 26 (November 2025) - Post-quantum support with X25519MLKEM768
		// No extension shuffling (Apple does not randomize)
		// Safari/iOS uses GREASE in supported_groups (per captured profile GREASEConfig)
		// Reference: https://support.apple.com/en-us/122756
		return ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			SessionIDLength:    SessionIDLengthNone, // iOS sends empty session ID for fresh TLS 1.3 connections
			CipherSuites:       safariCipherSuitesModern,
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				// SHA1 removed from iOS 26+: Modern iOS no longer includes deprecated SHA1
				// signature algorithms (ECDSAWithSHA1, PKCS1WithSHA1) as they are cryptographically weak.
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: safariSignatureAlgorithmsModern},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloEdge_106:
		// Edge 106 is Chromium-based and should shuffle extensions like Chrome 106+
		// FIXED: Added ShuffleChromeTLSExtensions to match Chrome's extension shuffling behavior
		return ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []uint8{0x0},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware (Edge is Chromium-based)
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}}, {Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}),
		}, nil
	case HelloEdge_142:
		// Edge 142 (October 2025) - follows Chrome 142 fingerprint
		// X25519MLKEM768, extension shuffling, new ALPS codepoint
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware (Edge is Chromium-based)
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloSafari_18:
		// Safari 18 (September 2024) - macOS Sequoia / iOS 18
		// JA4: t13d2014h2 = 20 ciphers, 14 extensions
		// Safari does NOT shuffle extensions (fixed order)
		// Safari/iOS uses GREASE in supported_groups (per captured profile GREASEConfig)
		return ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			SessionIDLength:    SessionIDLengthNone, // Safari sends empty session ID for fresh TLS 1.3 connections
			CipherSuites:       safariCipherSuites,
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384, CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: safariSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}}, {Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloSafari_26:
		// Safari 26 (November 2025) - macOS Tahoe / iOS 26 with post-quantum
		// No extension shuffling (Apple does not randomize)
		// Safari/iOS uses GREASE in supported_groups (per captured profile GREASEConfig)
		// X25519MLKEM768 for quantum-secure key exchange
		// Reference: https://support.apple.com/en-us/122756
		return ClientHelloSpec{
			TLSVersMin:         VersionTLS12,
			TLSVersMax:         VersionTLS13,
			SessionIDLength:    SessionIDLengthNone, // Safari sends empty session ID for fresh TLS 1.3 connections
			CipherSuites:       safariCipherSuitesModern,
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				// SHA1 removed from Safari 26+: Modern Safari no longer includes deprecated SHA1
				// signature algorithms (ECDSAWithSHA1, PKCS1WithSHA1) as they are cryptographically weak.
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: safariSignatureAlgorithmsModern},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_112_PSK_Shuf:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}}, {Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	case HelloChrome_114_Padding_PSK_Shuf:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}}, {Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement (Draft Kyber)
	case HelloChrome_115_PQ_PSK:
		return ClientHelloSpec{
			CipherSuites:       chromeCipherSuites,
			CompressionMethods: []byte{0x00},
			CipherSuiteOrder:   CipherSuiteOrderAuto, // Dynamic reordering based on hardware
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519Kyber768Draft00, X25519, CurveP256, CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&CookieExtension{}, // Placeholder for HRR
				&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	default:
		if id.Client == helloRandomized || id.Client == helloRandomizedALPN || id.Client == helloRandomizedNoALPN {
			utlserrors.LogDebug(ctx, "parrot: generating randomized spec for profile:", id.Str())
			// Use empty values as they can be filled later by UConn.ApplyPreset or manually.
			return generateRandomizedSpec(&id, "", nil)
		}

		utlserrors.LogDebug(ctx, "parrot: unknown profile ID:", id.Str())
		return ClientHelloSpec{}, utlserrors.New("tls: unknown ClientHelloID:", id.Str()).Base(ErrUnknownClientHelloID).AtError()
	}
}

// shuffleTLSExtensions is the core shuffle function used by browser-specific wrappers.
// It shuffles extensions in place, keeping padding and PSK in place (RFC compliance).
// Returns an error if cryptographic random number generation fails - this is a security
// requirement to prevent predictable extension ordering.
func shuffleTLSExtensions(exts []TLSExtension, skipGREASE bool) ([]TLSExtension, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "parrot: shuffling extensions, count:", len(exts), "skipGREASE:", skipGREASE)

	skipShuf := func(idx int) bool {
		switch exts[idx].(type) {
		case *UtlsPaddingExtension, PreSharedKeyExtension:
			return true
		case *UtlsGREASEExtension:
			return skipGREASE
		default:
			return false
		}
	}

	randInt64, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		// SECURITY: Never fall back to weak randomness - return error instead
		utlserrors.LogWarning(ctx, "parrot: crypto/rand failed for extension shuffle:", err)
		return nil, utlserrors.New("crypto/rand failed for extension shuffle").Base(err).AtError()
	}
	rng := rand.New(rand.NewSource(randInt64.Int64()))

	rng.Shuffle(len(exts), func(i, j int) {
		if skipShuf(i) || skipShuf(j) {
			return
		}
		exts[i], exts[j] = exts[j], exts[i]
	})

	utlserrors.LogDebug(ctx, "parrot: extension shuffle complete")
	return exts, nil
}

// ShuffleFirefoxTLSExtensions shuffles extensions like Firefox (NSS 3.84+).
// Skips: padding, pre_shared_key. GREASE is shuffled (Firefox has no GREASE).
// Returns unshuffled extensions if cryptographic random generation fails.
// For error handling, use ShuffleFirefoxTLSExtensionsWithError instead.
func ShuffleFirefoxTLSExtensions(exts []TLSExtension) []TLSExtension {
	result, err := shuffleTLSExtensions(exts, false)
	if err != nil {
		// Return unshuffled - shuffling is for fingerprinting, not security.
		// The TLS connection remains secure without shuffling.
		return exts
	}
	return result
}

// ShuffleChromeTLSExtensions shuffles extensions like Chrome 106+.
// Skips: GREASE, padding, pre_shared_key.
// Returns unshuffled extensions if cryptographic random generation fails.
// For error handling, use ShuffleChromeTLSExtensionsWithError instead.
func ShuffleChromeTLSExtensions(exts []TLSExtension) []TLSExtension {
	result, err := shuffleTLSExtensions(exts, true)
	if err != nil {
		// Return unshuffled - shuffling is for fingerprinting, not security.
		// The TLS connection remains secure without shuffling.
		return exts
	}
	return result
}

// ShuffleFirefoxTLSExtensionsWithError shuffles extensions like Firefox (NSS 3.84+).
// Returns an error if cryptographic random generation fails.
func ShuffleFirefoxTLSExtensionsWithError(exts []TLSExtension) ([]TLSExtension, error) {
	return shuffleTLSExtensions(exts, false)
}

// ShuffleChromeTLSExtensionsWithError shuffles extensions like Chrome 106+.
// Returns an error if cryptographic random generation fails.
func ShuffleChromeTLSExtensionsWithError(exts []TLSExtension) ([]TLSExtension, error) {
	return shuffleTLSExtensions(exts, true)
}

// ShuffleConfig provides fine-grained control over extension shuffling behavior.
// This allows advanced users to customize shuffling for anti-fingerprinting purposes.
type ShuffleConfig struct {
	// ShufflePadding allows padding extension to be shuffled (default: false).
	// WARNING: Padding position affects ClientHello size calculation. If enabled,
	// the padding length should be recalculated after shuffle using Update().
	ShufflePadding bool

	// ShuffleGREASE allows GREASE extensions to be shuffled (default: false for Chrome).
	// Chrome keeps GREASE at fixed positions, Firefox has no GREASE.
	// When true with RandomizeGREASEWithinRange, GREASE moves within constrained positions.
	ShuffleGREASE bool

	// RandomizeGREASEWithinRange enables Chrome-like GREASE position variation.
	// When true (and ShuffleGREASE is true):
	//   - First GREASE can move within the first GREASEStartRange positions
	//   - Last GREASE can move within the last GREASEEndRange positions
	//   - GREASERandomizeProbability controls how often randomization occurs
	// This mimics real Chrome behavior where GREASE usually stays at fixed
	// positions but occasionally varies.
	RandomizeGREASEWithinRange bool

	// GREASEStartRange defines how many positions from the start the first GREASE
	// can occupy (default: 3). Only used when RandomizeGREASEWithinRange is true.
	// Example: GREASEStartRange=3 means first GREASE can be at position 0, 1, or 2.
	GREASEStartRange int

	// GREASEEndRange defines how many positions from the end the last GREASE
	// can occupy (default: 3). Only used when RandomizeGREASEWithinRange is true.
	// Example: GREASEEndRange=3 means last GREASE can be at position n-1, n-2, or n-3
	// (where n is the length, excluding PSK if preserved).
	GREASEEndRange int

	// GREASERandomizeProbability is the probability (0.0-1.0) that GREASE positions
	// will be randomized within their allowed ranges. Default: 0.3 (30%).
	// - 0.0 means GREASE always stays at default positions (first and last)
	// - 1.0 means GREASE is always randomized within allowed range
	// - 0.3 mimics real Chrome: 70% at fixed positions, 30% varied
	GREASERandomizeProbability float64

	// PreservePSKLast ensures PSK extension stays last (RFC 8446 requirement).
	// This should almost always be true. Default: true.
	PreservePSKLast bool
}

// DefaultChromeShuffleConfig returns the default shuffle config for Chrome-like behavior.
// GREASE positions vary within constrained ranges (first 3 and last 3 positions) with
// 30% probability, mimicking real Chrome behavior. Padding stays fixed, PSK stays last.
func DefaultChromeShuffleConfig() ShuffleConfig {
	return ShuffleConfig{
		ShufflePadding:             false,
		ShuffleGREASE:              true, // Enable GREASE position variation
		RandomizeGREASEWithinRange: true, // Use Chrome-like constrained randomization
		GREASEStartRange:           3,    // First GREASE can be at positions 0, 1, or 2
		GREASEEndRange:             3,    // Last GREASE can be at last 3 positions
		GREASERandomizeProbability: 0.3,  // 30% chance to randomize, 70% stay fixed
		PreservePSKLast:            true,
	}
}

// DefaultFirefoxShuffleConfig returns the default shuffle config for Firefox-like behavior.
// GREASE is shuffled (Firefox has no GREASE anyway), Padding stays fixed, PSK stays last.
func DefaultFirefoxShuffleConfig() ShuffleConfig {
	return ShuffleConfig{
		ShufflePadding:  false,
		ShuffleGREASE:   true,
		PreservePSKLast: true,
	}
}

// AggressiveShuffleConfig returns a config for maximum anti-fingerprinting.
// All extensions except PSK can be shuffled. Use with caution - padding position
// affects ClientHello size and may require recalculation.
func AggressiveShuffleConfig() ShuffleConfig {
	return ShuffleConfig{
		ShufflePadding:  true,
		ShuffleGREASE:   true,
		PreservePSKLast: true,
	}
}

// shuffleTLSExtensionsWithConfig is the core shuffle function with configurable behavior.
// It shuffles extensions in place based on the provided configuration.
// Returns an error if cryptographic random number generation fails.
//
// When RandomizeGREASEWithinRange is enabled, GREASE extensions are moved within
// constrained ranges (start and end of the extension list) based on probability,
// mimicking real Chrome behavior where GREASE usually stays fixed but occasionally varies.
func shuffleTLSExtensionsWithConfig(exts []TLSExtension, cfg ShuffleConfig) ([]TLSExtension, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "parrot: shuffling extensions with config, count:", len(exts),
		"shuffleGREASE:", cfg.ShuffleGREASE, "shufflePadding:", cfg.ShufflePadding)

	if len(exts) < 2 {
		return exts, nil
	}

	// Generate cryptographically secure random seed
	randInt64, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		utlserrors.LogWarning(ctx, "parrot: crypto/rand failed for extension shuffle with config:", err)
		return nil, utlserrors.New("crypto/rand failed for extension shuffle").Base(err).AtError()
	}
	rng := rand.New(rand.NewSource(randInt64.Int64()))

	// Apply Chrome-like GREASE position randomization if configured
	if cfg.ShuffleGREASE && cfg.RandomizeGREASEWithinRange {
		exts, err = randomizeChromeGREASEPositions(exts, cfg, rng)
		if err != nil {
			return nil, err
		}
	}

	// Determine if GREASE should be skipped in the main shuffle
	// If we already randomized GREASE within range, skip it in main shuffle
	// to avoid moving it outside the allowed range
	skipGREASEInMainShuffle := cfg.RandomizeGREASEWithinRange

	skipShuf := func(idx int) bool {
		switch exts[idx].(type) {
		case *UtlsPaddingExtension:
			return !cfg.ShufflePadding
		case PreSharedKeyExtension:
			return cfg.PreservePSKLast
		case *UtlsGREASEExtension:
			if skipGREASEInMainShuffle {
				return true // Already handled by randomizeChromeGREASEPositions
			}
			return !cfg.ShuffleGREASE
		default:
			return false
		}
	}

	rng.Shuffle(len(exts), func(i, j int) {
		if skipShuf(i) || skipShuf(j) {
			return
		}
		exts[i], exts[j] = exts[j], exts[i]
	})

	return exts, nil
}

// randomizeChromeGREASEPositions implements Chrome-like GREASE position variation.
// Chrome typically has GREASE at position 0 (first) and near the end (before padding/PSK).
// Real Chrome sometimes varies these positions slightly, which this function mimics.
//
// Behavior:
//   - First GREASE: moves within first GREASEStartRange positions (default: 0-2)
//   - Last GREASE: moves within last GREASEEndRange positions (default: last 3)
//   - GREASERandomizeProbability controls how often variation occurs (default: 30%)
//
// This function is called before the main shuffle, so GREASE positions are established
// first, then other extensions are shuffled around them.
func randomizeChromeGREASEPositions(exts []TLSExtension, cfg ShuffleConfig, rng *rand.Rand) ([]TLSExtension, error) {
	// Roll probability - decide if we randomize at all
	if rng.Float64() >= cfg.GREASERandomizeProbability {
		// Keep GREASE at default positions (70% of the time with default config)
		return exts, nil
	}

	// Find GREASE extension indices
	greaseIndices := make([]int, 0, 3)
	for i, ext := range exts {
		if _, ok := ext.(*UtlsGREASEExtension); ok {
			greaseIndices = append(greaseIndices, i)
		}
	}

	if len(greaseIndices) == 0 {
		return exts, nil
	}

	// Determine valid end range (exclude PSK if it's last)
	endBoundary := len(exts)
	if cfg.PreservePSKLast && len(exts) > 0 {
		if _, ok := exts[len(exts)-1].(PreSharedKeyExtension); ok {
			endBoundary = len(exts) - 1
		}
	}

	// Also exclude padding from the end range if not shuffling padding
	if !cfg.ShufflePadding && endBoundary > 0 {
		if _, ok := exts[endBoundary-1].(*UtlsPaddingExtension); ok {
			endBoundary--
		}
	}

	// Apply default ranges if not set
	startRange := cfg.GREASEStartRange
	if startRange <= 0 {
		startRange = 3
	}
	endRange := cfg.GREASEEndRange
	if endRange <= 0 {
		endRange = 3
	}

	// Clamp ranges to valid bounds
	if startRange > endBoundary {
		startRange = endBoundary
	}
	if endRange > endBoundary {
		endRange = endBoundary
	}

	// Handle first GREASE (should be near the start)
	if len(greaseIndices) >= 1 {
		firstGreaseIdx := greaseIndices[0]

		// Only move if currently at position 0 and we have room
		if firstGreaseIdx == 0 && startRange > 1 {
			// Choose new position within first startRange positions
			newPos := rng.Intn(startRange)
			if newPos != firstGreaseIdx {
				exts = moveExtension(exts, firstGreaseIdx, newPos)
				// Update indices after move
				greaseIndices = updateIndicesAfterMove(greaseIndices, firstGreaseIdx, newPos)
			}
		}
	}

	// Handle last GREASE (should be near the end)
	if len(greaseIndices) >= 2 {
		lastGreaseIdx := greaseIndices[len(greaseIndices)-1]

		// Calculate the valid range for last GREASE
		// It should be within the last endRange positions (before padding/PSK)
		minEndPos := endBoundary - endRange
		if minEndPos < 0 {
			minEndPos = 0
		}
		// Ensure we don't overlap with start range
		if minEndPos < startRange {
			minEndPos = startRange
		}

		// Only move if there's room
		if minEndPos < endBoundary-1 {
			// Choose new position within the end range
			rangeSize := endBoundary - minEndPos
			if rangeSize > 0 {
				newPos := minEndPos + rng.Intn(rangeSize)
				if newPos != lastGreaseIdx && newPos < endBoundary {
					exts = moveExtension(exts, lastGreaseIdx, newPos)
				}
			}
		}
	}

	return exts, nil
}

// moveExtension moves an extension from srcIdx to dstIdx, shifting other elements.
func moveExtension(exts []TLSExtension, srcIdx, dstIdx int) []TLSExtension {
	if srcIdx == dstIdx {
		return exts
	}
	if srcIdx < 0 || srcIdx >= len(exts) || dstIdx < 0 || dstIdx >= len(exts) {
		return exts
	}

	ext := exts[srcIdx]

	if srcIdx < dstIdx {
		// Moving forward: shift elements left
		copy(exts[srcIdx:dstIdx], exts[srcIdx+1:dstIdx+1])
	} else {
		// Moving backward: shift elements right
		copy(exts[dstIdx+1:srcIdx+1], exts[dstIdx:srcIdx])
	}
	exts[dstIdx] = ext

	return exts
}

// updateIndicesAfterMove updates a list of indices after an element was moved.
func updateIndicesAfterMove(indices []int, srcIdx, dstIdx int) []int {
	result := make([]int, len(indices))
	for i, idx := range indices {
		if idx == srcIdx {
			result[i] = dstIdx
		} else if srcIdx < dstIdx {
			// Element moved forward
			if idx > srcIdx && idx <= dstIdx {
				result[i] = idx - 1
			} else {
				result[i] = idx
			}
		} else {
			// Element moved backward
			if idx >= dstIdx && idx < srcIdx {
				result[i] = idx + 1
			} else {
				result[i] = idx
			}
		}
	}
	return result
}

// ShuffleTLSExtensionsWithConfig shuffles extensions with the provided configuration.
// This is the most flexible shuffle function for advanced anti-fingerprinting needs.
// Returns the shuffled extensions and any error from random number generation.
//
// Example usage for aggressive anti-fingerprinting:
//
//	cfg := AggressiveShuffleConfig()
//	exts, err := ShuffleTLSExtensionsWithConfig(extensions, cfg)
//	if err != nil {
//	    // handle error
//	}
//	// If padding was shuffled, recalculate padding length
func ShuffleTLSExtensionsWithConfig(exts []TLSExtension, cfg ShuffleConfig) ([]TLSExtension, error) {
	return shuffleTLSExtensionsWithConfig(exts, cfg)
}

// RandomizeChromeGREASEPositions applies Chrome-like GREASE position randomization.
// This function implements the same behavior as DefaultChromeShuffleConfig():
//   - 70% chance: GREASE stays at fixed positions (first and second-to-last)
//   - 30% chance: First GREASE moves within positions 0-2, last GREASE moves within last 3
//
// This mimics real Chrome behavior where GREASE usually stays fixed but occasionally varies.
// Use this before ShuffleChromeTLSExtensions for complete Chrome-like extension shuffling.
//
// Example:
//
//	exts, err := RandomizeChromeGREASEPositions(extensions)
//	if err != nil { return err }
//	exts = ShuffleChromeTLSExtensions(exts)
func RandomizeChromeGREASEPositions(exts []TLSExtension) ([]TLSExtension, error) {
	cfg := DefaultChromeShuffleConfig()
	if len(exts) < 2 {
		return exts, nil
	}

	randInt64, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, fmt.Errorf("crypto/rand failed: %w", err)
	}
	rng := rand.New(rand.NewSource(randInt64.Int64()))

	return randomizeChromeGREASEPositions(exts, cfg, rng)
}

// RandomizeGREASEPositions moves GREASE extensions to random positions within the extension list.
// This helps reduce fingerprinting by varying where GREASE appears in the ClientHello.
// PSK extension (if present at the end) is preserved at the last position per RFC 8446.
// Returns error if cryptographic random generation fails.
//
// NOTE: For Chrome-like behavior where GREASE positions vary within constrained ranges,
// use RandomizeChromeGREASEPositions instead. This function moves GREASE to ANY random
// position, which may not match real browser behavior.
//
// Example:
//
//	exts, err := RandomizeGREASEPositions(extensions)
//	if err != nil { return err }
//	exts = ShuffleChromeTLSExtensions(exts)
func RandomizeGREASEPositions(exts []TLSExtension) ([]TLSExtension, error) {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "parrot: randomizing GREASE positions, extensions count:", len(exts))

	if len(exts) < 2 {
		return exts, nil
	}

	// Find GREASE extension indices
	greaseIndices := make([]int, 0, 3)
	for i, ext := range exts {
		if _, ok := ext.(*UtlsGREASEExtension); ok {
			greaseIndices = append(greaseIndices, i)
		}
	}

	if len(greaseIndices) == 0 {
		utlserrors.LogDebug(ctx, "parrot: no GREASE extensions found to randomize")
		return exts, nil
	}

	utlserrors.LogDebug(ctx, "parrot: found GREASE extensions at positions:", greaseIndices)

	// Determine valid range (exclude PSK if it's last)
	maxIdx := len(exts)
	if len(exts) > 0 {
		if _, ok := exts[len(exts)-1].(PreSharedKeyExtension); ok {
			maxIdx = len(exts) - 1
		}
	}

	// Generate cryptographically secure random seed
	randInt64, err := crand.Int(crand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, fmt.Errorf("crypto/rand failed: %w", err)
	}
	rng := rand.New(rand.NewSource(randInt64.Int64()))

	// Move each GREASE to a random valid position
	// We process from highest index to lowest to avoid index shifting issues
	sort.Sort(sort.Reverse(sort.IntSlice(greaseIndices)))

	for _, greaseIdx := range greaseIndices {
		if maxIdx <= 1 {
			break // Not enough room to move
		}

		// Generate new random position (0 to maxIdx-1)
		newPos := rng.Intn(maxIdx)

		if newPos == greaseIdx {
			continue // Already in place
		}

		// Extract the GREASE extension
		greaseExt := exts[greaseIdx]

		// Remove from current position
		exts = append(exts[:greaseIdx], exts[greaseIdx+1:]...)

		// Adjust newPos if it was after the removed position
		if newPos > greaseIdx {
			newPos--
		}

		// Insert at new position
		exts = append(exts[:newPos], append([]TLSExtension{greaseExt}, exts[newPos:]...)...)
	}

	return exts, nil
}

func (uconn *UConn) applyPresetByID(id ClientHelloID) (err error) {

	if uconn.clientHelloSpec == nil {
		var spec ClientHelloSpec
		uconn.ClientHelloID = id

		// choose/generate the spec
		switch id.Client {
		case helloRandomized, helloRandomizedNoALPN, helloRandomizedALPN:
			spec, err = uconn.generateRandomizedSpec()
			if err != nil {
				return err
			}
		case helloCustom:
			return nil
		default:
			spec, err = UTLSIdToSpec(id)
			if err != nil {
				return err
			}
		}

		uconn.clientHelloSpec = &spec
	}

	return uconn.ApplyPreset(uconn.clientHelloSpec)
}

// cloneExtension creates a deep copy of a TLSExtension to prevent shared state
// between connections. This is critical for thread safety when multiple goroutines
// use the same ClientHelloSpec.
func cloneExtension(ext TLSExtension) TLSExtension {
	if ext == nil {
		return nil
	}

	switch e := ext.(type) {
	case *SNIExtension:
		return &SNIExtension{ServerName: e.ServerName}
	case *StatusRequestExtension:
		return &StatusRequestExtension{}
	case *SupportedCurvesExtension:
		curves := make([]CurveID, len(e.Curves))
		copy(curves, e.Curves)
		return &SupportedCurvesExtension{Curves: curves}
	case *SupportedPointsExtension:
		points := make([]uint8, len(e.SupportedPoints))
		copy(points, e.SupportedPoints)
		return &SupportedPointsExtension{SupportedPoints: points}
	case *SignatureAlgorithmsExtension:
		algos := make([]SignatureScheme, len(e.SupportedSignatureAlgorithms))
		copy(algos, e.SupportedSignatureAlgorithms)
		return &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: algos}
	case *SignatureAlgorithmsCertExtension:
		algos := make([]SignatureScheme, len(e.SupportedSignatureAlgorithms))
		copy(algos, e.SupportedSignatureAlgorithms)
		return &SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: algos}
	case *StatusRequestV2Extension:
		return &StatusRequestV2Extension{}
	case *ALPNExtension:
		protos := make([]string, len(e.AlpnProtocols))
		copy(protos, e.AlpnProtocols)
		return &ALPNExtension{AlpnProtocols: protos}
	case *ApplicationSettingsExtension:
		protos := make([]string, len(e.SupportedProtocols))
		copy(protos, e.SupportedProtocols)
		return &ApplicationSettingsExtension{SupportedProtocols: protos}
	case *ApplicationSettingsExtensionNew:
		protos := make([]string, len(e.SupportedProtocols))
		copy(protos, e.SupportedProtocols)
		return &ApplicationSettingsExtensionNew{SupportedProtocols: protos}
	case *SCTExtension:
		// Deep clone SCTs (nested [][]byte)
		var scts [][]byte
		if len(e.SCTs) > 0 {
			scts = make([][]byte, len(e.SCTs))
			for i, sct := range e.SCTs {
				scts[i] = make([]byte, len(sct))
				copy(scts[i], sct)
			}
		}
		return &SCTExtension{SCTs: scts}
	case *GenericExtension:
		data := make([]byte, len(e.Data))
		copy(data, e.Data)
		return &GenericExtension{Id: e.Id, Data: data}
	case *ExtendedMasterSecretExtension:
		return &ExtendedMasterSecretExtension{}
	case *UtlsGREASEExtension:
		body := make([]byte, len(e.Body))
		copy(body, e.Body)
		return &UtlsGREASEExtension{Value: e.Value, Body: body}
	case *UtlsPaddingExtension:
		return &UtlsPaddingExtension{
			GetPaddingLen: e.GetPaddingLen,
			WillPad:       e.WillPad,
			PaddingLen:    e.PaddingLen,
		}
	case *UtlsCompressCertExtension:
		algos := make([]CertCompressionAlgo, len(e.Algorithms))
		copy(algos, e.Algorithms)
		return &UtlsCompressCertExtension{Algorithms: algos}
	case *KeyShareExtension:
		keyShares := make([]KeyShare, len(e.KeyShares))
		for i, ks := range e.KeyShares {
			data := make([]byte, len(ks.Data))
			copy(data, ks.Data)
			keyShares[i] = KeyShare{Group: ks.Group, Data: data}
		}
		return &KeyShareExtension{KeyShares: keyShares}
	case *QUICTransportParametersExtension:
		// Deep clone TransportParameters - must handle each concrete type
		params := make(TransportParameters, len(e.TransportParameters))
		for i, tp := range e.TransportParameters {
			switch p := tp.(type) {
			case *GREASETransportParameter:
				var valueOverride []byte
				if len(p.ValueOverride) > 0 {
					valueOverride = make([]byte, len(p.ValueOverride))
					copy(valueOverride, p.ValueOverride)
				}
				params[i] = &GREASETransportParameter{
					IdOverride:    p.IdOverride,
					Length:        p.Length,
					ValueOverride: valueOverride,
				}
			case *FakeQUICTransportParameter:
				var val []byte
				if len(p.Val) > 0 {
					val = make([]byte, len(p.Val))
					copy(val, p.Val)
				}
				params[i] = &FakeQUICTransportParameter{
					Id:  p.Id,
					Val: val,
				}
			case InitialSourceConnectionID:
				// Deep clone the []byte
				cloned := make(InitialSourceConnectionID, len(p))
				copy(cloned, p)
				params[i] = cloned
			case PaddingTransportParameter:
				// Deep clone the []byte
				cloned := make(PaddingTransportParameter, len(p))
				copy(cloned, p)
				params[i] = cloned
			case *VersionInformation:
				// Deep clone AvailableVersions slice
				var versions []uint32
				if len(p.AvailableVersions) > 0 {
					versions = make([]uint32, len(p.AvailableVersions))
					copy(versions, p.AvailableVersions)
				}
				params[i] = &VersionInformation{
					ChoosenVersion:    p.ChoosenVersion,
					AvailableVersions: versions,
					LegacyID:          p.LegacyID,
				}
			default:
				// Value types (uint64 aliases) and empty structs are safe to keep as-is
				// Examples: MaxIdleTimeout, MaxUDPPayloadSize, DisableActiveMigration, GREASEQUICBit
				params[i] = tp
			}
		}
		return &QUICTransportParametersExtension{TransportParameters: params}
	case *PSKKeyExchangeModesExtension:
		modes := make([]uint8, len(e.Modes))
		copy(modes, e.Modes)
		return &PSKKeyExchangeModesExtension{Modes: modes}
	case *SupportedVersionsExtension:
		versions := make([]uint16, len(e.Versions))
		copy(versions, e.Versions)
		return &SupportedVersionsExtension{Versions: versions}
	case *CookieExtension:
		cookie := make([]byte, len(e.Cookie))
		copy(cookie, e.Cookie)
		return &CookieExtension{Cookie: cookie}
	case *NPNExtension:
		protos := make([]string, len(e.NextProtos))
		copy(protos, e.NextProtos)
		return &NPNExtension{NextProtos: protos}
	case *RenegotiationInfoExtension:
		// Clone RenegotiatedConnection slice if present
		var renegConn []byte
		if len(e.RenegotiatedConnection) > 0 {
			renegConn = make([]byte, len(e.RenegotiatedConnection))
			copy(renegConn, e.RenegotiatedConnection)
		}
		return &RenegotiationInfoExtension{
			Renegotiation:          e.Renegotiation,
			RenegotiatedConnection: renegConn,
		}
	case *SessionTicketExtension:
		ticket := make([]byte, len(e.Ticket))
		copy(ticket, e.Ticket)
		return &SessionTicketExtension{
			Session:     e.Session, // Session is managed separately, keep reference
			Ticket:      ticket,
			Initialized: e.Initialized,
			InitError:   e.InitError,
		}
	case *FakeChannelIDExtension:
		return &FakeChannelIDExtension{OldExtensionID: e.OldExtensionID}
	case *FakeEncryptThenMACExtension:
		return &FakeEncryptThenMACExtension{}
	case *FakeRecordSizeLimitExtension:
		return &FakeRecordSizeLimitExtension{Limit: e.Limit}
	case *FakeTokenBindingExtension:
		keyParams := make([]uint8, len(e.KeyParameters))
		copy(keyParams, e.KeyParameters)
		return &FakeTokenBindingExtension{
			MajorVersion:  e.MajorVersion,
			MinorVersion:  e.MinorVersion,
			KeyParameters: keyParams,
		}
	case *FakeDelegatedCredentialsExtension:
		algos := make([]SignatureScheme, len(e.SupportedSignatureAlgorithms))
		copy(algos, e.SupportedSignatureAlgorithms)
		return &FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: algos}
	case *GREASEEncryptedClientHelloExtension:
		cipherSuites := make([]HPKESymmetricCipherSuite, len(e.CandidateCipherSuites))
		copy(cipherSuites, e.CandidateCipherSuites)
		configIds := make([]uint8, len(e.CandidateConfigIds))
		copy(configIds, e.CandidateConfigIds)
		payloadLens := make([]uint16, len(e.CandidatePayloadLens))
		copy(payloadLens, e.CandidatePayloadLens)
		// Also clone EncapsulatedKey to preserve fingerprint size during round-trip
		encapKey := make([]byte, len(e.EncapsulatedKey))
		copy(encapKey, e.EncapsulatedKey)
		return e.cloneWithState(cipherSuites, configIds, payloadLens, encapKey)
	case *UtlsPreSharedKeyExtension:
		// PSK extension needs special handling - it's typically rebuilt per-connection
		return &UtlsPreSharedKeyExtension{}
	case *FakePreSharedKeyExtension:
		// Clone identities
		identities := make([]PskIdentity, len(e.Identities))
		for i, id := range e.Identities {
			label := make([]byte, len(id.Label))
			copy(label, id.Label)
			identities[i] = PskIdentity{
				Label:               label,
				ObfuscatedTicketAge: id.ObfuscatedTicketAge,
			}
		}
		// Clone binders
		binders := make([][]byte, len(e.Binders))
		for i, b := range e.Binders {
			binder := make([]byte, len(b))
			copy(binder, b)
			binders[i] = binder
		}
		return &FakePreSharedKeyExtension{
			Identities: identities,
			Binders:    binders,
		}
	default:
		// For unknown extension types, return as-is with a warning
		// This maintains backwards compatibility but may not be thread-safe
		return ext
	}
}

// ApplyPreset should only be used in conjunction with HelloCustom to apply custom specs.
// Extensions are deep-cloned to prevent race conditions when multiple connections share
// the same ClientHelloSpec.
func (uconn *UConn) ApplyPreset(p *ClientHelloSpec) error {
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "parrot: applying preset, extensions count:", len(p.Extensions))

	var err error

	err = uconn.SetTLSVers(p.TLSVersMin, p.TLSVersMax, p.Extensions)
	if err != nil {
		utlserrors.LogDebug(ctx, "parrot: SetTLSVers failed:", err)
		return err
	}

	privateHello, clientKeySharePrivate, ech, err := uconn.makeClientHelloForApplyPreset()
	if err != nil {
		return err
	}
	uconn.HandshakeState.Hello = privateHello.getPublicPtr()
	if clientKeySharePrivate != nil {
		uconn.HandshakeState.State13.KeyShareKeys = clientKeySharePrivate.ToPublic()
	} else {
		uconn.HandshakeState.State13.KeyShareKeys = &KeySharePrivateKeys{}
	}
	uconn.echCtx.Store(ech)
	hello := uconn.HandshakeState.Hello

	switch len(hello.Random) {
	case 0:
		hello.Random = make([]byte, 32)
		_, err := io.ReadFull(uconn.config.rand(), hello.Random)
		if err != nil {
			return utlserrors.New("tls: short read from Rand").Base(err).AtError()
		}
	case 32:
	// carry on
	default:
		return utlserrors.New("tls: invalid client random length").AtError()
	}

	if len(hello.CompressionMethods) == 0 {
		hello.CompressionMethods = []uint8{compressionNone}
	}

	// Currently, GREASE is assumed to come from BoringSSL
	grease_bytes := make([]byte, 2*ssl_grease_last_index)
	grease_extensions_seen := 0
	// Track first GREASE extension value to detect collisions.
	// RFC 8446 Section 4.2 prohibits duplicate extension types.
	var firstGreaseExtValue uint16
	_, err = io.ReadFull(uconn.config.rand(), grease_bytes)
	if err != nil {
		return utlserrors.New("tls: short read from Rand").Base(err).AtError()
	}
	// Defensive check: ensure grease_bytes has sufficient length for greaseSeed.
	// Each greaseSeed element requires 2 bytes. This validates the allocation
	// matches the array size to prevent index out of bounds if constants change.
	requiredBytes := 2 * len(uconn.greaseSeed)
	if len(grease_bytes) < requiredBytes {
		return utlserrors.New("tls: insufficient random bytes for GREASE seed initialization").AtError()
	}
	for i := range uconn.greaseSeed {
		uconn.greaseSeed[i] = binary.LittleEndian.Uint16(grease_bytes[2*i : 2*i+2])
	}
	// GREASE collision handling: Chrome/BoringSSL generates extension1 and extension2
	// GREASE values from different seed indices. With 16 possible GREASE values
	// (0x0A0A through 0xFAFA), there's a 1/16 = 6.25% collision probability.
	// RFC 8446 Section 4.2 prohibits duplicate extension types, so real Chrome
	// must avoid collisions. We rotate to the next GREASE value on collision,
	// which stays within valid GREASE space and is undetectable.

	// Apply cipher suite ordering based on hardware capabilities.
	// Real browsers (Chrome, Edge) reorder cipher suites based on AES-NI availability:
	//   - With AES hardware: AES-GCM suites first (faster with hardware acceleration)
	//   - Without AES hardware: ChaCha20 suites first (faster in software)
	// This is controlled by the CipherSuiteOrder field in ClientHelloSpec.
	utlserrors.LogDebug(ctx, "parrot: applying cipher suite order:", string(p.CipherSuiteOrder), "count:", len(p.CipherSuites))
	orderedCiphers := ApplyCipherSuiteOrder(p.CipherSuites, p.CipherSuiteOrder)
	hello.CipherSuites = make([]uint16, len(orderedCiphers))
	copy(hello.CipherSuites, orderedCiphers)
	greaseCount := 0
	for i := range hello.CipherSuites {
		if isGREASEUint16(hello.CipherSuites[i]) { // just in case the user set a GREASE value instead of unGREASEd
			hello.CipherSuites[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_cipher)
			greaseCount++
		}
	}
	if utlserrors.DebugLoggingEnabled && greaseCount > 0 {
		utlserrors.LogDebug(ctx, "parrot: inserted GREASE cipher suites:", greaseCount)
	}

	// Session ID handling with configurable length per browser profile.
	//
	// Real browser behavior varies:
	//   - Chrome: 32 bytes (TLS 1.3 middlebox compatibility mode)
	//   - Firefox: 0 bytes for fresh TLS 1.3 connections
	//   - Safari/iOS: 0 bytes for fresh TLS 1.3 connections
	//
	// RFC 8446 Section 4.1.2 recommends 32-byte session ID for middlebox compatibility,
	// but not all browsers follow this. We now support per-profile configuration.
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if uconn.quic == nil {
		sessionIDLen := 32 // Default: 32 bytes for backward compatibility
		if p.SessionIDLength == SessionIDLengthNone {
			sessionIDLen = 0 // Firefox/Safari TLS 1.3 behavior
		} else if p.SessionIDLength > 0 && p.SessionIDLength <= 32 {
			sessionIDLen = p.SessionIDLength // Explicit length
		}
		// SessionIDLengthAuto (0) uses default 32 bytes

		if sessionIDLen > 0 {
			sessionID := make([]byte, sessionIDLen)
			_, err = io.ReadFull(uconn.config.rand(), sessionID)
			if err != nil {
				return err
			}
			uconn.HandshakeState.Hello.SessionId = sessionID
		} else {
			// Empty session ID (Firefox/Safari behavior for fresh TLS 1.3)
			uconn.HandshakeState.Hello.SessionId = nil
		}
	}

	// Deep clone extensions to prevent race conditions and shared state
	// between connections using the same ClientHelloSpec.
	// Filter out nil extensions to prevent nil pointer dereferences downstream.
	utlserrors.LogDebug(ctx, "parrot: cloning extensions, count:", len(p.Extensions))
	uconn.Extensions = make([]TLSExtension, 0, len(p.Extensions))
	for _, ext := range p.Extensions {
		cloned := cloneExtension(ext)
		if cloned != nil {
			uconn.Extensions = append(uconn.Extensions, cloned)
		}
	}

	// For QUIC connections, automatically add QUICTransportParametersExtension
	// if not already present in the extensions. This allows using regular TLS
	// presets (like HelloChrome_120) with QUIC connections.
	if uconn.quic != nil {
		hasQUICTransportParams := false
		for _, ext := range uconn.Extensions {
			if _, ok := ext.(*QUICTransportParametersExtension); ok {
				hasQUICTransportParams = true
				break
			}
		}
		if !hasQUICTransportParams {
			// Insert QUICTransportParametersExtension after ALPN extension
			// (per RFC 9001, transport parameters follow ALPN in practice)
			insertIdx := -1
			for i, ext := range uconn.Extensions {
				if _, ok := ext.(*ALPNExtension); ok {
					insertIdx = i + 1
					break
				}
			}
			qtpExt := &QUICTransportParametersExtension{}
			if insertIdx > 0 && insertIdx <= len(uconn.Extensions) {
				// Insert at the found position
				uconn.Extensions = append(uconn.Extensions[:insertIdx],
					append([]TLSExtension{qtpExt}, uconn.Extensions[insertIdx:]...)...)
			} else {
				// Append at the end if ALPN not found
				uconn.Extensions = append(uconn.Extensions, qtpExt)
			}
		}

		// RFC 9001 Section 8.1: QUIC connections MUST negotiate ALPN.
		// Update the ALPN extension to use QUIC-compatible protocols from config.
		// If config.NextProtos is set (e.g., ["h3"]), use that instead of the
		// preset's ALPN (e.g., ["h2", "http/1.1"] which is HTTP/2 over TCP).
		if len(uconn.config.NextProtos) > 0 {
			for _, ext := range uconn.Extensions {
				if alpn, ok := ext.(*ALPNExtension); ok {
					alpn.AlpnProtocols = uconn.config.NextProtos
					break
				}
			}
		}

		// RFC 9001: QUIC MUST use TLS 1.3 or later.
		// Filter the SupportedVersionsExtension to only include TLS 1.3+.
		// Presets like HelloChrome_120 include TLS 1.2 for TCP, but QUIC requires TLS 1.3.
		for _, ext := range uconn.Extensions {
			if sv, ok := ext.(*SupportedVersionsExtension); ok {
				var tls13Versions []uint16
				for _, v := range sv.Versions {
					// Keep GREASE values and TLS 1.3+
					if isGREASEUint16(v) || v >= VersionTLS13 {
						tls13Versions = append(tls13Versions, v)
					}
				}
				if len(tls13Versions) > 0 {
					sv.Versions = tls13Versions
				}
				break
			}
		}
	}

	// Apply curve order variation if configured.
	// This must be done BEFORE key share generation since key_share order must match
	// supported_groups order for TLS fingerprint consistency.
	if err := uconn.applyCurveOrderVariation(p.CurveOrder); err != nil {
		return err
	}

	// Check whether NPN extension actually exists
	var haveNPN bool

	// reGrease, and point things to each other
	for _, e := range uconn.Extensions {
		switch ext := e.(type) {
		case *SNIExtension:
			if ext.ServerName == "" {
				ext.ServerName = uconn.config.ServerName
			}
			if uconn.config.EncryptedClientHelloConfigList != nil {
				ext.ServerName = string(ech.config.PublicName)
			}
		case *UtlsGREASEExtension:
			switch grease_extensions_seen {
			case 0:
				// [uTLS] Chrome correlation: First GREASE extension uses same value as supported_versions
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_version)
				firstGreaseExtValue = ext.Value
			case 1:
				// [uTLS] Chrome correlation: Second GREASE extension uses same value as supported_groups/key_share
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group)
				// RFC 8446 Section 4.2: "A client MUST NOT offer more than one extension of the same type"
				// GREASE values have 16 possible values, so there's a 6.25% collision probability.
				// If collision detected, rotate to the next GREASE value to ensure uniqueness.
				if ext.Value == firstGreaseExtValue {
					ext.Value = NextGREASEValue(ext.Value)
				}
				ext.Body = []byte{0}
			default:
				return utlserrors.New("tls: too many reserved extensions").AtError()
			}
			grease_extensions_seen += 1
		case *SupportedCurvesExtension:
			for i := range ext.Curves {
				if isGREASEUint16(uint16(ext.Curves[i])) {
					ext.Curves[i] = CurveID(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
				}
			}
		case *KeyShareExtension:
			preferredCurveIsSet := false
			for i := range ext.KeyShares {
				curveID := ext.KeyShares[i].Group
				if isGREASEUint16(uint16(curveID)) { // just in case the user set a GREASE value instead of unGREASEd
					ext.KeyShares[i].Group = CurveID(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_group))
					// Generate random GREASE key share data if not already set.
					// Previous code always used exactly 1 byte with value 0x00, which is
					// a detectable fingerprint. Real browsers may use varying lengths
					// and random content. RFC 8701 allows any data for GREASE key shares.
					if len(ext.KeyShares[i].Data) == 0 {
						// Random length 1-32 bytes (common range observed in browsers)
						var lenByte [1]byte
						_, err = io.ReadFull(uconn.config.rand(), lenByte[:])
						if err != nil {
							return utlserrors.New("tls: short read from Rand").Base(err).AtError()
						}
						// Map 0-255 to 1-32: (lenByte % 32) + 1
						greaseDataLen := int(lenByte[0]%32) + 1
						greaseData := make([]byte, greaseDataLen)
						_, err = io.ReadFull(uconn.config.rand(), greaseData)
						if err != nil {
							return utlserrors.New("tls: short read from Rand").Base(err).AtError()
						}
						ext.KeyShares[i].Data = greaseData
					}
					continue
				}
				// DESIGN NOTE: Key shares with Data length > 1 are assumed to be pre-populated
				// by the caller and are kept as-is. Key shares with empty or minimal Data
				// (0 or 1 bytes) are treated as placeholders and auto-generated below.
				// This allows users to either:
				// 1. Provide empty Data for automatic key generation
				// 2. Provide complete Data to use a specific pre-generated key
				if len(ext.KeyShares[i].Data) > 1 {
					continue
				}

				if curveID == X25519MLKEM768 || curveID == X25519Kyber768Draft00 {
					ecdheKey, err := generateECDHEKey(uconn.config.rand(), X25519)
					if err != nil {
						return err
					}
					seed := make([]byte, mlkem.SeedSize)
					if _, err := io.ReadFull(uconn.config.rand(), seed); err != nil {
						return err
					}
					mlkemKey, err := mlkem.NewDecapsulationKey768(seed)
					if err != nil {
						return err
					}

					if curveID == X25519Kyber768Draft00 {
						ext.KeyShares[i].Data = append(ecdheKey.PublicKey().Bytes(), mlkemKey.EncapsulationKey().Bytes()...)
					} else {
						ext.KeyShares[i].Data = append(mlkemKey.EncapsulationKey().Bytes(), ecdheKey.PublicKey().Bytes()...)
					}
					uconn.HandshakeState.State13.KeyShareKeys.Mlkem = mlkemKey
					uconn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe = ecdheKey
				} else if curveID == SecP256r1MLKEM768 {
					// SecP256r1MLKEM768: P-256 + ML-KEM-768 hybrid (draft-ietf-tls-ecdhe-mlkem-03)
					// Key share format: P-256 point (65 bytes) || ML-KEM encapsulation key (1184 bytes)
					ecdheKey, err := generateECDHEKey(uconn.config.rand(), CurveP256)
					if err != nil {
						return err
					}
					seed := make([]byte, mlkem.SeedSize)
					if _, err := io.ReadFull(uconn.config.rand(), seed); err != nil {
						return err
					}
					mlkemKey, err := mlkem.NewDecapsulationKey768(seed)
					if err != nil {
						return err
					}
					// SecP256r1MLKEM768 format: P-256 point (65 bytes) || ML-KEM encapsulation key (1184 bytes)
					ext.KeyShares[i].Data = append(ecdheKey.PublicKey().Bytes(), mlkemKey.EncapsulationKey().Bytes()...)
					uconn.HandshakeState.State13.KeyShareKeys.Mlkem = mlkemKey
					uconn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe = ecdheKey
				} else if curveID == SecP384r1MLKEM1024 {
					// SecP384r1MLKEM1024: P-384 + ML-KEM-1024 hybrid (draft-ietf-tls-ecdhe-mlkem-03)
					// Key share format: P-384 point (97 bytes) || ML-KEM-1024 encapsulation key (1568 bytes) = 1665 bytes
					// Shared secret: ECDH_SS (48 bytes) || ML-KEM_SS (32 bytes) = 80 bytes
					ecdheKey, err := generateECDHEKey(uconn.config.rand(), CurveP384)
					if err != nil {
						return err
					}
					seed := make([]byte, mlkem.SeedSize)
					if _, err := io.ReadFull(uconn.config.rand(), seed); err != nil {
						return err
					}
					mlkemKey, err := mlkem.NewDecapsulationKey1024(seed)
					if err != nil {
						return err
					}
					// SecP384r1MLKEM1024 format: P-384 point (97 bytes) || ML-KEM-1024 encapsulation key (1568 bytes)
					ext.KeyShares[i].Data = append(ecdheKey.PublicKey().Bytes(), mlkemKey.EncapsulationKey().Bytes()...)
					uconn.HandshakeState.State13.KeyShareKeys.Mlkem1024 = mlkemKey
					uconn.HandshakeState.State13.KeyShareKeys.Ecdhe = ecdheKey
				} else if IsFFDHEGroup(curveID) {
					// Generate FFDHE key pair for RFC 7919 finite field groups
					ffdheKey, err := generateFFDHEKey(uconn.config.rand(), curveID)
					if err != nil {
						return fmt.Errorf("failed to generate FFDHE key for group %v: %w", curveID, err)
					}
					ext.KeyShares[i].Data = ffdheKey.PublicKeyBytes()
					if !preferredCurveIsSet {
						// Store FFDHE key for shared secret computation
						uconn.HandshakeState.State13.KeyShareKeys.Ffdhe = ffdheKey
						preferredCurveIsSet = true
					}
				} else {
					ecdheKey, err := generateECDHEKey(uconn.config.rand(), curveID)
					if err != nil {
						return fmt.Errorf("unsupported Curve in KeyShareExtension: %v."+
							"To mimic it, fill the Data(key) field manually", curveID)
					}

					ext.KeyShares[i].Data = ecdheKey.PublicKey().Bytes()
					if !preferredCurveIsSet {
						// only do this once for the first non-grease curve
						uconn.HandshakeState.State13.KeyShareKeys.Ecdhe = ecdheKey
						preferredCurveIsSet = true
					}
				}
			}
		case *SupportedVersionsExtension:
			for i := range ext.Versions {
				if isGREASEUint16(ext.Versions[i]) { // just in case the user set a GREASE value instead of unGREASEd
					ext.Versions[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_version)
				}
			}
		case *NPNExtension:
			haveNPN = true
		}
	}

	// The default golang behavior in makeClientHello always sets NextProtoNeg if NextProtos is set,
	// but NextProtos is also used by ALPN and our spec nmay not actually have a NPN extension
	hello.NextProtoNeg = haveNPN

	err = uconn.sessionController.syncSessionExts()
	if err != nil {
		utlserrors.LogDebug(ctx, "parrot: syncSessionExts failed:", err)
		return err
	}

	utlserrors.LogDebug(ctx, "parrot: preset applied successfully, extensions:", len(uconn.Extensions), "cipher suites:", len(hello.CipherSuites))
	return nil
}

func (uconn *UConn) generateRandomizedSpec() (ClientHelloSpec, error) {
	return generateRandomizedSpec(&uconn.ClientHelloID, uconn.serverName, uconn.config.NextProtos)
}

func generateRandomizedSpec(
	id *ClientHelloID,
	serverName string,
	nextProtos []string,
) (ClientHelloSpec, error) {
	p := ClientHelloSpec{}

	if id.Seed == nil {
		seed, err := NewPRNGSeed()
		if err != nil {
			return p, err
		}
		id.Seed = seed
	}

	r, err := newPRNGWithSeed(id.Seed)
	if err != nil {
		return p, err
	}

	if id.Weights == nil {
		id.Weights = &DefaultWeights
	}

	var WithALPN bool
	switch id.Client {
	case helloRandomizedALPN:
		WithALPN = true
	case helloRandomizedNoALPN:
		WithALPN = false
	case helloRandomized:
		if r.FlipWeightedCoin(id.Weights.Extensions_Append_ALPN) {
			WithALPN = true
		} else {
			WithALPN = false
		}
	default:
		return p, fmt.Errorf("using non-randomized ClientHelloID %v to generate randomized spec", id.Client)
	}

	p.CipherSuites = defaultCipherSuites()
	shuffledSuites, err := shuffledCiphers(r)
	if err != nil {
		return p, err
	}

	if r.FlipWeightedCoin(id.Weights.TLSVersMax_Set_VersionTLS13) {
		// randomize min TLS version
		minTLSVersCandidates := []uint16{VersionTLS10, VersionTLS12}
		p.TLSVersMin = minTLSVersCandidates[r.Intn(len(minTLSVersCandidates))]
		p.TLSVersMax = VersionTLS13
		tls13ciphers := make([]uint16, len(defaultCipherSuitesTLS13))
		copy(tls13ciphers, defaultCipherSuitesTLS13)
		r.Shuffle(len(tls13ciphers), func(i, j int) {
			tls13ciphers[i], tls13ciphers[j] = tls13ciphers[j], tls13ciphers[i]
		})
		// appending TLS 1.3 ciphers before TLS 1.2, since that's what popular implementations do
		shuffledSuites = append(tls13ciphers, shuffledSuites...)

		// TLS 1.3 forbids RC4 in any configurations
		shuffledSuites = removeRC4Ciphers(shuffledSuites)
	} else {
		p.TLSVersMin = VersionTLS10
		p.TLSVersMax = VersionTLS12
	}

	p.CipherSuites = removeRandomCiphers(r, shuffledSuites, id.Weights.CipherSuites_Remove_RandomCiphers)

	sni := SNIExtension{serverName}
	sessionTicket := SessionTicketExtension{}

	sigAndHashAlgos := []SignatureScheme{
		ECDSAWithP256AndSHA256,
		PKCS1WithSHA256,
		ECDSAWithP384AndSHA384,
		PKCS1WithSHA384,
		PKCS1WithSHA1,
		PKCS1WithSHA512,
	}

	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_ECDSAWithSHA1) {
		sigAndHashAlgos = append(sigAndHashAlgos, ECDSAWithSHA1)
	}
	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_ECDSAWithP521AndSHA512) {
		sigAndHashAlgos = append(sigAndHashAlgos, ECDSAWithP521AndSHA512)
	}
	if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_PSSWithSHA256) || p.TLSVersMax == VersionTLS13 {
		// https://tools.ietf.org/html/rfc8446 says "...RSASSA-PSS (which is mandatory in TLS 1.3)..."
		sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA256)
		if r.FlipWeightedCoin(id.Weights.SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512) {
			// these usually go together
			sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA384)
			sigAndHashAlgos = append(sigAndHashAlgos, PSSWithSHA512)
		}
	}

	r.Shuffle(len(sigAndHashAlgos), func(i, j int) {
		sigAndHashAlgos[i], sigAndHashAlgos[j] = sigAndHashAlgos[j], sigAndHashAlgos[i]
	})
	sigAndHash := SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAndHashAlgos}

	status := StatusRequestExtension{}
	sct := SCTExtension{}
	ems := ExtendedMasterSecretExtension{}
	points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}

	curveIDs := []CurveID{}
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_X25519) && p.TLSVersMax == VersionTLS13 {
		curveIDs = append(curveIDs, X25519MLKEM768)
	}
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_X25519) || p.TLSVersMax == VersionTLS13 {
		curveIDs = append(curveIDs, X25519)
	}
	curveIDs = append(curveIDs, CurveP256, CurveP384)
	if r.FlipWeightedCoin(id.Weights.CurveIDs_Append_CurveP521) {
		curveIDs = append(curveIDs, CurveP521)
	}

	curves := SupportedCurvesExtension{curveIDs}

	padding := UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}
	reneg := RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}

	p.Extensions = []TLSExtension{
		&sni,
		&sessionTicket,
		&sigAndHash,
		&points,
		&curves,
	}

	if WithALPN {
		if len(nextProtos) == 0 {
			// if user didn't specify alpn yet, choose something popular
			nextProtos = []string{"h2", "http/1.1"}
		}
		alpn := ALPNExtension{AlpnProtocols: nextProtos}
		p.Extensions = append(p.Extensions, &alpn)
	}

	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Padding) || p.TLSVersMax == VersionTLS13 {
		// always include for TLS 1.3, since TLS 1.3 ClientHellos are often over 256 bytes
		// and that's when padding is required to work around buggy middleboxes
		p.Extensions = append(p.Extensions, &padding)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Status) {
		p.Extensions = append(p.Extensions, &status)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_SCT) {
		p.Extensions = append(p.Extensions, &sct)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_Reneg) {
		p.Extensions = append(p.Extensions, &reneg)
	}
	if r.FlipWeightedCoin(id.Weights.Extensions_Append_EMS) {
		p.Extensions = append(p.Extensions, &ems)
	}
	if p.TLSVersMax == VersionTLS13 {
		ks := KeyShareExtension{[]KeyShare{
			{Group: X25519}, // the key for the group will be generated later
		}}
		if r.FlipWeightedCoin(id.Weights.FirstKeyShare_Set_CurveP256) { // legacy setting, not used by default
			ks.KeyShares[0].Group = CurveP256
		} else {
			if r.FlipWeightedCoin(id.Weights.KeyShare_Append_RandomGroups) {
				ks.KeyShares = append(ks.KeyShares, KeyShare{Group: CurveP256})
			}
			if r.FlipWeightedCoin(id.Weights.KeyShare_Append_RandomGroups) {
				ks.KeyShares = append([]KeyShare{{Group: X25519MLKEM768}}, ks.KeyShares...)
			}
		}
		pskExchangeModes := PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}}
		supportedVersionsExt := SupportedVersionsExtension{
			Versions: makeSupportedVersions(p.TLSVersMin, p.TLSVersMax),
		}
		p.Extensions = append(p.Extensions, &ks, &pskExchangeModes, &supportedVersionsExt)

		// Randomly add an ALPS extension. ALPS is TLS 1.3-only and may only
		// appear when an ALPN extension is present
		// (https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01#section-3).
		// ALPS is a draft specification at this time, but appears in
		// Chrome/BoringSSL.
		if WithALPN {

			// ALPS is a new addition to generateRandomizedSpec. Use a salted
			// seed to create a new, independent PRNG, so that a seed used
			// with the previous version of generateRandomizedSpec will
			// produce the exact same spec as long as ALPS isn't selected.
			r, err := newPRNGWithSaltedSeed(id.Seed, "ALPS")
			if err != nil {
				return p, err
			}
			if r.FlipWeightedCoin(id.Weights.Extensions_Append_ALPS) {
				// As with the ALPN case above, default to something popular
				// (unlike ALPN, ALPS can't yet be specified in uconn.config).
				alps := &ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
				p.Extensions = append(p.Extensions, alps)
			}
		}

		// TODO: randomly add DelegatedCredentialsExtension, once it is
		// sufficiently popular.
	}
	r.Shuffle(len(p.Extensions), func(i, j int) {
		p.Extensions[i], p.Extensions[j] = p.Extensions[j], p.Extensions[i]
	})

	return p, nil
}

func removeRandomCiphers(r *prng, s []uint16, maxRemovalProbability float64) []uint16 {
	// removes elements in place
	// probability to remove increases for further elements
	// never remove first cipher
	if len(s) <= 1 {
		return s
	}

	// remove random elements
	floatLen := float64(len(s))
	sliceLen := len(s)
	for i := 1; i < sliceLen; i++ {
		if r.FlipWeightedCoin(maxRemovalProbability * float64(i) / floatLen) {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}

func shuffledCiphers(r *prng) ([]uint16, error) {
	ciphers := make(sortableCiphers, len(cipherSuites))
	perm := r.Perm(len(cipherSuites))
	for i, suite := range cipherSuites {
		ciphers[i] = sortableCipher{suite: suite.id,
			isObsolete: ((suite.flags & suiteTLS12) == 0),
			randomTag:  perm[i]}
	}
	sort.Sort(ciphers)
	return ciphers.GetCiphers(), nil
}

type sortableCipher struct {
	isObsolete bool
	randomTag  int
	suite      uint16
}

type sortableCiphers []sortableCipher

func (ciphers sortableCiphers) Len() int {
	return len(ciphers)
}

func (ciphers sortableCiphers) Less(i, j int) bool {
	if ciphers[i].isObsolete && !ciphers[j].isObsolete {
		return false
	}
	if ciphers[j].isObsolete && !ciphers[i].isObsolete {
		return true
	}
	return ciphers[i].randomTag < ciphers[j].randomTag
}

func (ciphers sortableCiphers) Swap(i, j int) {
	ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
}

func (ciphers sortableCiphers) GetCiphers() []uint16 {
	cipherIDs := make([]uint16, len(ciphers))
	for i := range ciphers {
		cipherIDs[i] = ciphers[i].suite
	}
	return cipherIDs
}

func removeRC4Ciphers(s []uint16) []uint16 {
	// removes elements in place
	sliceLen := len(s)
	for i := 0; i < sliceLen; i++ {
		cipher := s[i]
		if cipher == TLS_ECDHE_ECDSA_WITH_RC4_128_SHA ||
			cipher == TLS_ECDHE_RSA_WITH_RC4_128_SHA ||
			cipher == TLS_RSA_WITH_RC4_128_SHA {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s[:sliceLen]
}
