// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/mlkem"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"strconv"

	"github.com/refraction-networking/utls/dicttls"
)

var ErrUnknownClientHelloID = errors.New("tls: unknown ClientHelloID")

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

// Safari/iOS cipher suites (18 ciphers - ECDSA preferred over RSA)
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

// UTLSIdToSpec converts a ClientHelloID to a corresponding ClientHelloSpec.
func UTLSIdToSpec(id ClientHelloID) (ClientHelloSpec, error) {
	switch id {
	case HelloChrome_106_Shuffle:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement
	case HelloChrome_115_PQ:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519Kyber768Draft00,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			}),
		}, nil
	// Chrome ECH
	case HelloChrome_120:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
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
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{
					CertCompressionBrotli,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement and ECH
	case HelloChrome_120_PQ:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519Kyber768Draft00,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_131:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_133:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloChrome_142:
		// Chrome 142 (October 2025) - Same TLS fingerprint as Chrome 133
		// X25519MLKEM768 (0x11EC), extension shuffling, new ALPS codepoint (17613)
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloFirefox_120:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
						FakeCurveFFDHE2048,
						FakeCurveFFDHE3072,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: X25519,
						},
						{
							Group: CurveP256,
						},
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						VersionTLS13,
						VersionTLS12,
					},
				},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
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
					},
				},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&FakeRecordSizeLimitExtension{
					Limit: 0x4001,
				},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZlib,
				}},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
				&GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: []HPKESymmetricCipherSuite{
						{
							KdfId:  dicttls.HKDF_SHA256,
							AeadId: dicttls.AEAD_AES_128_GCM,
						},
						{
							KdfId:  dicttls.HKDF_SHA256,
							AeadId: dicttls.AEAD_CHACHA20_POLY1305,
						},
					},
					CandidatePayloadLens: []uint16{223}, // +16: 239
				},
			},
		}, nil
	case HelloFirefox_145:
		// Firefox 145 (November 2025) with extension shuffling (NSS 3.84+)
		// Same cipher suites as Firefox 120, but extensions are shuffled per connection
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: ShuffleFirefoxTLSExtensions([]TLSExtension{
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
						FakeCurveFFDHE2048,
						FakeCurveFFDHE3072,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&FakeDelegatedCredentialsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						ECDSAWithP384AndSHA384,
						ECDSAWithP521AndSHA512,
						ECDSAWithSHA1,
					},
				},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: X25519,
						},
						{
							Group: CurveP256,
						},
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						VersionTLS13,
						VersionTLS12,
					},
				},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
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
					},
				},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&FakeRecordSizeLimitExtension{
					Limit: 0x4001,
				},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZlib,
				}},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
				&GREASEEncryptedClientHelloExtension{
					CandidateCipherSuites: []HPKESymmetricCipherSuite{
						{
							KdfId:  dicttls.HKDF_SHA256,
							AeadId: dicttls.AEAD_AES_128_GCM,
						},
						{
							KdfId:  dicttls.HKDF_SHA256,
							AeadId: dicttls.AEAD_CHACHA20_POLY1305,
						},
					},
					CandidatePayloadLens: []uint16{223},
				},
			}),
		}, nil
	case HelloIOS_18:
		// iOS 18 (September 2024) - Same as Safari 18
		// No extension shuffling, no post-quantum yet
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
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
				}},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloIOS_26:
		// iOS 26 (November 2025) - Post-quantum support with X25519MLKEM768
		// No extension shuffling (Apple does not randomize)
		// Reference: https://support.apple.com/en-us/122756
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768, // Post-quantum hybrid
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
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
				}},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: X25519MLKEM768}, // Post-quantum hybrid key share
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloEdge_106:
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []uint8{
				0x0, // no compression
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{
						0x0, // uncompressed
					},
				},
				&SessionTicketExtension{},
				&ALPNExtension{
					AlpnProtocols: []string{
						"h2",
						"http/1.1",
					},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
						ECDSAWithP256AndSHA256,
						PSSWithSHA256,
						PKCS1WithSHA256,
						ECDSAWithP384AndSHA384,
						PSSWithSHA384,
						PKCS1WithSHA384,
						PSSWithSHA512,
						PKCS1WithSHA512,
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{
							Group: GREASE_PLACEHOLDER,
							Data: []byte{
								0,
							},
						},
						{
							Group: X25519,
						},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{
						PskModeDHE,
					},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{
						CertCompressionBrotli,
					},
				},
				&ApplicationSettingsExtension{
					SupportedProtocols: []string{
						"h2",
					},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{
					GetPaddingLen: BoringPaddingStyle,
				},
			},
		}, nil
	case HelloEdge_142:
		// Edge 142 (October 2025) - follows Chrome 142 fingerprint
		// X25519MLKEM768, extension shuffling, new ALPS codepoint
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00,
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519MLKEM768},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{PskModeDHE}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{CertCompressionBrotli}},
				&ApplicationSettingsExtensionNew{SupportedProtocols: []string{"h2"}},
				BoringGREASEECH(),
				&UtlsGREASEExtension{},
			}),
		}, nil
	case HelloSafari_18:
		// Safari 18 (September 2024) - macOS Sequoia / iOS 18
		// JA4: t13d2014h2 = 20 ciphers, 14 extensions
		// Safari does NOT shuffle extensions (fixed order)
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []uint8{
				0x0,
			},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{
					Renegotiation: RenegotiateOnceAsClient,
				},
				&SupportedCurvesExtension{
					Curves: []CurveID{
						GREASE_PLACEHOLDER,
						X25519,
						CurveP256,
						CurveP384,
						CurveP521,
					},
				},
				&SupportedPointsExtension{
					SupportedPoints: []uint8{0x0},
				},
				&ALPNExtension{
					AlpnProtocols: []string{"h2", "http/1.1"},
				},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{
					SupportedSignatureAlgorithms: []SignatureScheme{
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
					},
				},
				&SCTExtension{},
				&KeyShareExtension{
					KeyShares: []KeyShare{
						{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
						{Group: X25519},
					},
				},
				&PSKKeyExchangeModesExtension{
					Modes: []uint8{PskModeDHE},
				},
				&SupportedVersionsExtension{
					Versions: []uint16{
						GREASE_PLACEHOLDER,
						VersionTLS13,
						VersionTLS12,
					},
				},
				&UtlsCompressCertExtension{
					Algorithms: []CertCompressionAlgo{CertCompressionZlib},
				},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloSafari_26:
		// Safari 26 (November 2025) - macOS Tahoe / iOS 26 with post-quantum
		// No extension shuffling (Apple does not randomize)
		// X25519MLKEM768 for quantum-secure key exchange
		// Reference: https://support.apple.com/en-us/122756
		return ClientHelloSpec{
			TLSVersMin: VersionTLS12,
			TLSVersMax: VersionTLS13,
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []uint8{0x0},
			Extensions: []TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER,
					X25519MLKEM768, // Post-quantum hybrid
					X25519,
					CurveP256,
					CurveP384,
					CurveP521,
				}},
				&SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
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
				}},
				&SCTExtension{},
				&KeyShareExtension{KeyShares: []KeyShare{
					{Group: GREASE_PLACEHOLDER, Data: []byte{0}},
					{Group: X25519MLKEM768}, // Post-quantum hybrid key share
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{PskModeDHE}},
				&SupportedVersionsExtension{Versions: []uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
			},
		}, nil
	case HelloChrome_112_PSK_Shuf:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	case HelloChrome_114_Padding_PSK_Shuf:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	// Chrome w/ Post-Quantum Key Agreement
	case HelloChrome_115_PQ_PSK:
		return ClientHelloSpec{
			CipherSuites: []uint16{
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
			},
			CompressionMethods: []byte{
				0x00, // compressionNone
			},
			Extensions: ShuffleChromeTLSExtensions([]TLSExtension{
				&UtlsGREASEExtension{},
				&SNIExtension{},
				&ExtendedMasterSecretExtension{},
				&RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient},
				&SupportedCurvesExtension{[]CurveID{
					GREASE_PLACEHOLDER,
					X25519Kyber768Draft00,
					X25519,
					CurveP256,
					CurveP384,
				}},
				&SupportedPointsExtension{SupportedPoints: []byte{
					0x00, // pointFormatUncompressed
				}},
				&SessionTicketExtension{},
				&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&StatusRequestExtension{},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
					ECDSAWithP384AndSHA384,
					PSSWithSHA384,
					PKCS1WithSHA384,
					PSSWithSHA512,
					PKCS1WithSHA512,
				}},
				&SCTExtension{},
				&KeyShareExtension{[]KeyShare{
					{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: X25519Kyber768Draft00},
					{Group: X25519},
				}},
				&PSKKeyExchangeModesExtension{[]uint8{
					PskModeDHE,
				}},
				&SupportedVersionsExtension{[]uint16{
					GREASE_PLACEHOLDER,
					VersionTLS13,
					VersionTLS12,
				}},
				&UtlsCompressCertExtension{[]CertCompressionAlgo{
					CertCompressionBrotli,
					CertCompressionZstd,
				}},
				&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
				&UtlsGREASEExtension{},
				&UtlsPreSharedKeyExtension{},
			}),
		}, nil
	default:
		if id.Client == helloRandomized || id.Client == helloRandomizedALPN || id.Client == helloRandomizedNoALPN {
			// Use empty values as they can be filled later by UConn.ApplyPreset or manually.
			return generateRandomizedSpec(&id, "", nil)
		}

		return ClientHelloSpec{}, fmt.Errorf("%w: %s", ErrUnknownClientHelloID, id.Str())
	}
}

// shuffleTLSExtensions is the core shuffle function used by browser-specific wrappers.
// It shuffles extensions in place, keeping padding and PSK in place (RFC compliance).
func shuffleTLSExtensions(exts []TLSExtension, skipGREASE bool) []TLSExtension {
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
	var rng *rand.Rand
	if err != nil {
		rng = rand.New(rand.NewSource(rand.Int63()))
	} else {
		rng = rand.New(rand.NewSource(randInt64.Int64()))
	}

	rng.Shuffle(len(exts), func(i, j int) {
		if skipShuf(i) || skipShuf(j) {
			return
		}
		exts[i], exts[j] = exts[j], exts[i]
	})

	return exts
}

// ShuffleFirefoxTLSExtensions shuffles extensions like Firefox (NSS 3.84+).
// Skips: padding, pre_shared_key. GREASE is shuffled (Firefox has no GREASE).
func ShuffleFirefoxTLSExtensions(exts []TLSExtension) []TLSExtension {
	return shuffleTLSExtensions(exts, false)
}

// ShuffleChromeTLSExtensions shuffles extensions like Chrome 106+.
// Skips: GREASE, padding, pre_shared_key.
func ShuffleChromeTLSExtensions(exts []TLSExtension) []TLSExtension {
	return shuffleTLSExtensions(exts, true)
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

// ApplyPreset should only be used in conjunction with HelloCustom to apply custom specs.
// Fields of TLSExtensions that are slices/pointers are shared across different connections with
// same ClientHelloSpec. It is advised to use different specs and avoid any shared state.
func (uconn *UConn) ApplyPreset(p *ClientHelloSpec) error {
	var err error

	err = uconn.SetTLSVers(p.TLSVersMin, p.TLSVersMax, p.Extensions)
	if err != nil {
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
	uconn.echCtx = ech
	hello := uconn.HandshakeState.Hello

	switch len(hello.Random) {
	case 0:
		hello.Random = make([]byte, 32)
		_, err := io.ReadFull(uconn.config.rand(), hello.Random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	case 32:
	// carry on
	default:
		return errors.New("ClientHello expected length: 32 bytes. Got: " +
			strconv.Itoa(len(hello.Random)) + " bytes")
	}

	if len(hello.CompressionMethods) == 0 {
		hello.CompressionMethods = []uint8{compressionNone}
	}

	// Currently, GREASE is assumed to come from BoringSSL
	grease_bytes := make([]byte, 2*ssl_grease_last_index)
	grease_extensions_seen := 0
	_, err = io.ReadFull(uconn.config.rand(), grease_bytes)
	if err != nil {
		return errors.New("tls: short read from Rand: " + err.Error())
	}
	for i := range uconn.greaseSeed {
		uconn.greaseSeed[i] = binary.LittleEndian.Uint16(grease_bytes[2*i : 2*i+2])
	}
	if GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1) == GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2) {
		// Generate a new random seed that produces a different GREASE value.
		// The original XOR by 0x1010 created a detectable fingerprint because
		// (grease_ext1 ^ grease_ext2) was always 0x0000 or 0x1010, whereas real
		// Chrome/BoringSSL generates independent random GREASE values.
		// GREASE values (0x?A?A pattern per RFC 8701) depend only on bits 4-7 of the seed.
		var newSeedBytes [2]byte
		_, err = io.ReadFull(uconn.config.rand(), newSeedBytes[:])
		if err != nil {
			return errors.New("tls: short read from Rand for GREASE dedup: " + err.Error())
		}
		newSeed := binary.LittleEndian.Uint16(newSeedBytes[:])
		ext1Nibble := uconn.greaseSeed[ssl_grease_extension1] & 0xf0
		// If the random seed would produce the same GREASE value, shift to next nibble
		if (newSeed & 0xf0) == ext1Nibble {
			newSeed = (newSeed &^ 0xf0) | (((newSeed & 0xf0) + 0x10) & 0xf0)
		}
		uconn.greaseSeed[ssl_grease_extension2] = newSeed
	}

	hello.CipherSuites = make([]uint16, len(p.CipherSuites))
	copy(hello.CipherSuites, p.CipherSuites)
	for i := range hello.CipherSuites {
		if isGREASEUint16(hello.CipherSuites[i]) { // just in case the user set a GREASE value instead of unGREASEd
			hello.CipherSuites[i] = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_cipher)
		}
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if uconn.quic == nil {
		var sessionID [32]byte
		_, err = io.ReadFull(uconn.config.rand(), sessionID[:])
		if err != nil {
			return err
		}
		uconn.HandshakeState.Hello.SessionId = sessionID[:]
	}

	uconn.Extensions = make([]TLSExtension, len(p.Extensions))
	copy(uconn.Extensions, p.Extensions)

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
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension1)
			case 1:
				ext.Value = GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_extension2)
				ext.Body = []byte{0}
			default:
				return errors.New("at most 2 grease extensions are supported")
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
					continue
				}
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
		return err
	}

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
