package tls

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/refraction-networking/utls/dicttls"
	"github.com/refraction-networking/utls/internal/hpke"
	"golang.org/x/crypto/cryptobyte"
)

// Unstable API: This is a work in progress and may change in the future. Using
// it in your application may cause your application to break when updating to
// a new version of uTLS.

const (
	OuterClientHello byte = 0x00
	InnerClientHello byte = 0x01
)

type EncryptedClientHelloExtension interface {
	// TLSExtension must be implemented by all EncryptedClientHelloExtension implementations.
	TLSExtension

	// MarshalClientHello is called by (*UConn).MarshalClientHello() when an ECH extension
	// is present to allow the ECH extension to take control of the generation of the
	// entire ClientHello message.
	MarshalClientHello(*UConn) error

	mustEmbedUnimplementedECHExtension()
}

type ECHExtension = EncryptedClientHelloExtension // alias

// type guard: GREASEEncryptedClientHelloExtension must implement EncryptedClientHelloExtension
var (
	_ EncryptedClientHelloExtension = (*GREASEEncryptedClientHelloExtension)(nil)

	_ EncryptedClientHelloExtension = (*UnimplementedECHExtension)(nil)
)

type GREASEEncryptedClientHelloExtension struct {
	CandidateCipherSuites []HPKESymmetricCipherSuite
	cipherSuite           HPKESymmetricCipherSuite // randomly picked from CandidateCipherSuites or generated if empty
	CandidateConfigIds    []uint8
	configId              uint8    // randomly picked from CandidateConfigIds or generated if empty
	EncapsulatedKey       []byte   // if empty, will generate random bytes
	CandidatePayloadLens  []uint16 // Pre-encryption. If 0, will pick 190(+16=206)
	payload               []byte   // payload should be calculated ONCE and stored here, HRR will reuse this

	initOnce sync.Once
	initErr  error // stores initialization error to return on subsequent calls

	UnimplementedECHExtension
}

type GREASEECHExtension = GREASEEncryptedClientHelloExtension // alias

// init initializes the GREASEEncryptedClientHelloExtension with random values if they are not set.
//
// Based on cloudflare/go's echGenerateGreaseExt()
// Note: The error is stored in g.initErr so subsequent calls return the same error.
func (g *GREASEEncryptedClientHelloExtension) init() error {
	g.initOnce.Do(func() {
		// Set the config_id field to a random byte.
		//
		// Note: must not reuse this extension unless for HRR. It is required
		// to generate new random bytes for config_id for each new ClientHello,
		// but reuse the same config_id for HRR.
		if len(g.CandidateConfigIds) == 0 {
			var b []byte = make([]byte, 1)
			_, err := rand.Read(b[:])
			if err != nil {
				g.initErr = fmt.Errorf("error generating random byte for config_id: %w", err)
				return
			}
			g.configId = b[0]
		} else {
			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateConfigIds))))
			if err != nil {
				g.initErr = fmt.Errorf("error generating random index for config_id: %w", err)
				return
			}
			g.configId = g.CandidateConfigIds[rndIndex.Int64()]
		}

		// Set the cipher_suite field to a supported HpkeSymmetricCipherSuite.
		// The selection SHOULD vary to exercise all supported configurations,
		// but MAY be held constant for successive connections to the same server
		// in the same session.
		if len(g.CandidateCipherSuites) == 0 {
			g.cipherSuite = HPKESymmetricCipherSuite{uint16(defaultHpkeKdf), uint16(defaultHpkeAead)}
		} else {
			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateCipherSuites))))
			if err != nil {
				g.initErr = fmt.Errorf("error generating random index for cipher_suite: %w", err)
				return
			}
			g.cipherSuite = HPKESymmetricCipherSuite{
				g.CandidateCipherSuites[rndIndex.Int64()].KdfId,
				g.CandidateCipherSuites[rndIndex.Int64()].AeadId,
			}
		}

		if len(g.EncapsulatedKey) == 0 {
			kem := uint16(defaultHpkeKem)

			echPK, err := hpke.ParseHPKEPublicKey(uint16(kem), dummyX25519PublicKey)
			if err != nil {
				g.initErr = fmt.Errorf("tls: ECH key parse error: %w", err)
				return
			}
			suite := echCipher{
				KDFID:  defaultHpkeKdf,
				AEADID: defaultHpkeAead,
			}
			g.EncapsulatedKey, _, err = hpke.SetupSender(kem, suite.KDFID, suite.AEADID, echPK, []byte{})
			if err != nil {
				g.initErr = fmt.Errorf("tls: ECH setup error: %w", err)
				return
			}
		}

		if len(g.payload) == 0 {
			if len(g.CandidatePayloadLens) == 0 {
				// Default payload lengths with irregular spacing to reduce fingerprinting.
				// Uses prime-offset spacing and varying gaps to avoid detectable patterns.
				// Range covers typical inner ClientHello sizes (128-512 bytes encoded).
				// Additional 0-15 byte jitter is added after selection to break patterns.
				g.CandidatePayloadLens = []uint16{
					128, 147, 168, 191, 216, 239, 264, 293,
					320, 349, 376, 407, 440, 471, 504,
				}
			}

			// randomly pick one from the list
			rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidatePayloadLens))))
			if err != nil {
				g.initErr = fmt.Errorf("error generating random index for payload length: %w", err)
				return
			}

			baseLen := g.CandidatePayloadLens[rndIndex.Int64()]

			// Add random jitter (0-15 bytes) to further reduce fingerprinting.
			// This prevents exact size matching even when the same base size is selected.
			jitterBig, err := rand.Int(rand.Reader, big.NewInt(16))
			if err != nil {
				g.initErr = fmt.Errorf("error generating random jitter for payload length: %w", err)
				return
			}
			finalLen := baseLen + uint16(jitterBig.Int64())

			g.initErr = g.randomizePayload(finalLen)
		}
	})

	return g.initErr
}

func (g *GREASEEncryptedClientHelloExtension) randomizePayload(encodedHelloInnerLen uint16) error {
	if len(g.payload) != 0 {
		return errors.New("tls: ECH extension already initialized")
	}

	payloadLen := cipherLen(g.cipherSuite.AeadId, int(encodedHelloInnerLen))
	if payloadLen < 0 {
		return errors.New("tls: invalid ECH cipher suite")
	}
	g.payload = make([]byte, payloadLen)
	_, err := rand.Read(g.payload)
	if err != nil {
		return fmt.Errorf("tls: ECH random generation error: %w", err)
	}
	return nil
}

// writeToUConn implements TLSExtension.
//
// For ECH extensions, writeToUConn simply points the ech field in UConn to the extension.
func (g *GREASEEncryptedClientHelloExtension) writeToUConn(uconn *UConn) error {
	uconn.ech = g
	return uconn.MarshalClientHelloNoECH()
}

// Len implements TLSExtension.
// Returns 0 if initialization fails, consistent with Read() which will return
// the error. Callers should handle the error from Read() to diagnose issues.
func (g *GREASEEncryptedClientHelloExtension) Len() int {
	if err := g.init(); err != nil {
		// Return 0 on error for consistency: Read() will return 0 bytes written
		// along with the actual error. Returning non-zero here while Read()
		// writes nothing would cause buffer allocation/usage inconsistencies.
		return 0
	}
	return 2 + 2 + 1 /* ClientHello Type */ + 4 /* CipherSuite */ + 1 /* Config ID */ + 2 + len(g.EncapsulatedKey) + 2 + len(g.payload)
}

// Read implements TLSExtension.
func (g *GREASEEncryptedClientHelloExtension) Read(b []byte) (int, error) {
	// Check for initialization errors first
	if err := g.init(); err != nil {
		return 0, fmt.Errorf("tls: ech extension initialization failed: %w", err)
	}

	extLen := 2 + 2 + 1 + 4 + 1 + 2 + len(g.EncapsulatedKey) + 2 + len(g.payload)
	if len(b) < extLen {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(utlsExtensionECH >> 8)
	b[1] = byte(utlsExtensionECH & 0xFF)
	b[2] = byte((extLen - 4) >> 8)
	b[3] = byte((extLen - 4) & 0xFF)
	b[4] = OuterClientHello
	b[5] = byte(g.cipherSuite.KdfId >> 8)
	b[6] = byte(g.cipherSuite.KdfId & 0xFF)
	b[7] = byte(g.cipherSuite.AeadId >> 8)
	b[8] = byte(g.cipherSuite.AeadId & 0xFF)
	b[9] = g.configId
	b[10] = byte(len(g.EncapsulatedKey) >> 8)
	b[11] = byte(len(g.EncapsulatedKey) & 0xFF)
	copy(b[12:], g.EncapsulatedKey)
	b[12+len(g.EncapsulatedKey)] = byte(len(g.payload) >> 8)
	b[12+len(g.EncapsulatedKey)+1] = byte(len(g.payload) & 0xFF)
	copy(b[12+len(g.EncapsulatedKey)+2:], g.payload)

	return extLen, io.EOF
}

// MarshalClientHello implements EncryptedClientHelloExtension.
func (*GREASEEncryptedClientHelloExtension) MarshalClientHello(*UConn) error {
	return errors.New("tls: ECH marshal not supported on this extension type")
}

// Write implements TLSExtensionWriter.
func (g *GREASEEncryptedClientHelloExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)

	// Check the extension type, it must be OuterClientHello otherwise we are not
	// parsing the correct extension
	var chType uint8 // 0: outer, 1: inner
	var ignored cryptobyte.String
	if !extData.ReadUint8(&chType) || chType != 0 {
		return fullLen, errors.New("bad Client Hello type, expected 0, got " + fmt.Sprintf("%d", chType))
	}

	// Parse the cipher suite
	if !extData.ReadUint16(&g.cipherSuite.KdfId) || !extData.ReadUint16(&g.cipherSuite.AeadId) {
		return fullLen, errors.New("bad cipher suite")
	}
	if g.cipherSuite.KdfId != dicttls.HKDF_SHA256 &&
		g.cipherSuite.KdfId != dicttls.HKDF_SHA384 &&
		g.cipherSuite.KdfId != dicttls.HKDF_SHA512 {
		return fullLen, errors.New("bad KDF ID: " + fmt.Sprintf("%d", g.cipherSuite.KdfId))
	}
	if g.cipherSuite.AeadId != dicttls.AEAD_AES_128_GCM &&
		g.cipherSuite.AeadId != dicttls.AEAD_AES_256_GCM &&
		g.cipherSuite.AeadId != dicttls.AEAD_CHACHA20_POLY1305 {
		return fullLen, errors.New("bad AEAD ID: " + fmt.Sprintf("%d", g.cipherSuite.AeadId))
	}
	g.CandidateCipherSuites = []HPKESymmetricCipherSuite{g.cipherSuite}

	// GREASE the ConfigId
	if !extData.ReadUint8(&g.configId) {
		return fullLen, errors.New("bad config ID")
	}
	// we don't write to CandidateConfigIds because we don't really want to reuse the same config_id

	// GREASE the EncapsulatedKey
	if !extData.ReadUint16LengthPrefixed(&ignored) {
		return fullLen, errors.New("bad encapsulated key")
	}
	// Validate encapsulated key size: must not be empty and must have reasonable bounds.
	// X25519 uses 32 bytes, P-256 uses 65 bytes, P-384/P-521 use more. 256 bytes covers all KEMs.
	const maxEncapsulatedKeyLen = 256
	if len(ignored) == 0 {
		return fullLen, errors.New("tls: empty encapsulated key")
	}
	if len(ignored) > maxEncapsulatedKeyLen {
		return fullLen, fmt.Errorf("tls: encapsulated key too large: %d > %d", len(ignored), maxEncapsulatedKeyLen)
	}
	g.EncapsulatedKey = make([]byte, len(ignored))
	n, err := rand.Read(g.EncapsulatedKey)
	if err != nil {
		return fullLen, fmt.Errorf("tls: generating ech key: %w", err)
	}
	if n != len(g.EncapsulatedKey) {
		return fullLen, fmt.Errorf("tls: short read generating ech key")
	}

	// GREASE the payload
	if !extData.ReadUint16LengthPrefixed(&ignored) {
		return fullLen, errors.New("bad payload")
	}
	// Validate payload size: must contain at least AEAD overhead + 1 byte of plaintext,
	// and must not exceed reasonable bounds to prevent memory exhaustion.
	const maxPayloadLen = 16384 // 16KB is sufficient for any realistic ECH payload
	cipherOverhead := cipherLen(g.cipherSuite.AeadId, 0)
	if cipherOverhead < 0 {
		return fullLen, errors.New("tls: invalid AEAD identifier")
	}
	if len(ignored) == 0 {
		return fullLen, errors.New("tls: empty ECH payload")
	}
	if len(ignored) <= cipherOverhead {
		return fullLen, fmt.Errorf("tls: payload too short for AEAD overhead: %d <= %d", len(ignored), cipherOverhead)
	}
	if len(ignored) > maxPayloadLen {
		return fullLen, fmt.Errorf("tls: ECH payload too large: %d > %d", len(ignored), maxPayloadLen)
	}
	// Set payload directly with exact size to preserve fingerprint during round-trip.
	// This bypasses the jitter logic in init() which would alter the size.
	g.payload = make([]byte, len(ignored))
	if _, err := rand.Read(g.payload); err != nil {
		return fullLen, fmt.Errorf("tls: generating ech payload: %w", err)
	}

	if !extData.Empty() {
		return fullLen, errors.New("tls: extension has trailing data")
	}

	return fullLen, nil
}

// cloneWithState creates a deep copy of the extension including internal state.
// This is used during ApplyPreset to preserve the exact fingerprint size when
// an extension has been populated via Write() during fingerprinting.
func (g *GREASEEncryptedClientHelloExtension) cloneWithState(
	cipherSuites []HPKESymmetricCipherSuite,
	configIds []uint8,
	payloadLens []uint16,
	encapKey []byte,
) *GREASEEncryptedClientHelloExtension {
	// Clone payload if present (set by Write() during fingerprinting)
	var payload []byte
	if len(g.payload) > 0 {
		payload = make([]byte, len(g.payload))
		copy(payload, g.payload)
	}

	return &GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: cipherSuites,
		cipherSuite:           g.cipherSuite,
		CandidateConfigIds:    configIds,
		configId:              g.configId,
		EncapsulatedKey:       encapKey,
		CandidatePayloadLens:  payloadLens,
		payload:               payload,
		// Note: initOnce is intentionally NOT copied - the new instance
		// should call init() but it will see that payload is already set
		// and skip regeneration, preserving the exact size.
	}
}

// UnimplementedECHExtension is a placeholder for an ECH extension that is not implemented.
// All implementations of EncryptedClientHelloExtension should embed this struct to ensure
// forward compatibility.
type UnimplementedECHExtension struct{}

// writeToUConn implements TLSExtension.
func (*UnimplementedECHExtension) writeToUConn(_ *UConn) error {
	return errors.New("tls: unimplemented ECHExtension")
}

// Len implements TLSExtension.
func (*UnimplementedECHExtension) Len() int {
	return 0
}

// Read implements TLSExtension.
func (*UnimplementedECHExtension) Read(_ []byte) (int, error) {
	return 0, errors.New("tls: unimplemented ECHExtension")
}

// MarshalClientHello implements EncryptedClientHelloExtension.
func (*UnimplementedECHExtension) MarshalClientHello(*UConn) error {
	return errors.New("tls: unimplemented ECHExtension")
}

// mustEmbedUnimplementedECHExtension is a noop function but is required to
// ensure forward compatibility.
func (*UnimplementedECHExtension) mustEmbedUnimplementedECHExtension() {
	// No-op: exists only for interface embedding and forward compatibility
}

// BoringGREASEECH returns a GREASE scheme BoringSSL uses by default.
// Payload lengths are varied to reduce fingerprintability. The lengths are
// based on realistic ECH payload sizes seen in the wild, covering a range
// that matches different ClientHello sizes and padding configurations.
// Based on BoringSSL ssl/encrypted_client_hello.cc GREASE ECH generation.
// Note: 0-15 byte jitter is added during init() to further obscure patterns.
func BoringGREASEECH() *GREASEEncryptedClientHelloExtension {
	return &GREASEEncryptedClientHelloExtension{
		CandidateCipherSuites: []HPKESymmetricCipherSuite{
			{
				KdfId:  dicttls.HKDF_SHA256,
				AeadId: dicttls.AEAD_AES_128_GCM,
			},
		},
		// Extended payload length options with irregular spacing to reduce fingerprintability.
		// Uses varying gaps (19-37 bytes) to avoid detectable 32-byte pattern.
		// After +16 AEAD overhead + 0-15 jitter: approximately 159-397+ bytes.
		CandidatePayloadLens: []uint16{
			143, 167, 189, 217, 241, 268, 293, 325, 351, 381,
		},
	}
}
