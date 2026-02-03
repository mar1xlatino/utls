package tls

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/refraction-networking/utls/dicttls"
	utlserrors "github.com/refraction-networking/utls/errors"
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
		ctx := context.Background()
		utlserrors.LogDebug(ctx, "ECH GREASE: initializing extension")

		// Skip configId and cipherSuite generation if EncapsulatedKey is already set.
		// This indicates the extension was created via cloneWithState from an already-
		// initialized extension, so we should preserve the copied values.
		// EncapsulatedKey is used as a sentinel because:
		// 1. It's always set after configId and cipherSuite during normal initialization
		// 2. It's never empty for an initialized extension
		// 3. It's always copied by cloneWithState
		alreadyInitialized := len(g.EncapsulatedKey) > 0

		if alreadyInitialized {
			utlserrors.LogDebug(ctx, "ECH GREASE: already initialized (cloned state)")
		}

		if !alreadyInitialized {
			// Set the config_id field to a random byte.
			//
			// Note: must not reuse this extension unless for HRR. It is required
			// to generate new random bytes for config_id for each new ClientHello,
			// but reuse the same config_id for HRR.
			if len(g.CandidateConfigIds) == 0 {
				var b []byte = make([]byte, 1)
				_, err := rand.Read(b[:])
				if err != nil {
					g.initErr = utlserrors.New("ECH GREASE: error generating random byte for config_id").Base(err).AtError()
					return
				}
				g.configId = b[0]
				utlserrors.LogDebug(ctx, "ECH GREASE: generated random configId=", g.configId)
			} else {
				// randomly pick one from the list
				rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateConfigIds))))
				if err != nil {
					g.initErr = utlserrors.New("ECH GREASE: error generating random index for config_id").Base(err).AtError()
					return
				}
				g.configId = g.CandidateConfigIds[rndIndex.Int64()]
				utlserrors.LogDebug(ctx, "ECH GREASE: selected configId=", g.configId, " from candidates")
			}

			// Set the cipher_suite field to a supported HpkeSymmetricCipherSuite.
			// The selection SHOULD vary to exercise all supported configurations,
			// but MAY be held constant for successive connections to the same server
			// in the same session.
			if len(g.CandidateCipherSuites) == 0 {
				g.cipherSuite = HPKESymmetricCipherSuite{uint16(defaultHpkeKdf), uint16(defaultHpkeAead)}
				utlserrors.LogDebug(ctx, "ECH GREASE: using default cipher suite KDF=0x",
					fmt.Sprintf("%04x", defaultHpkeKdf), " AEAD=0x", fmt.Sprintf("%04x", defaultHpkeAead))
			} else {
				// randomly pick one from the list
				rndIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(g.CandidateCipherSuites))))
				if err != nil {
					g.initErr = utlserrors.New("ECH GREASE: error generating random index for cipher_suite").Base(err).AtError()
					return
				}
				g.cipherSuite = HPKESymmetricCipherSuite{
					g.CandidateCipherSuites[rndIndex.Int64()].KdfId,
					g.CandidateCipherSuites[rndIndex.Int64()].AeadId,
				}
				utlserrors.LogDebug(ctx, "ECH GREASE: selected cipher suite KDF=0x",
					fmt.Sprintf("%04x", g.cipherSuite.KdfId), " AEAD=0x", fmt.Sprintf("%04x", g.cipherSuite.AeadId))
			}
		}

		if len(g.EncapsulatedKey) == 0 {
			kem := uint16(defaultHpkeKem)

			echPK, err := hpke.ParseHPKEPublicKey(uint16(kem), dummyX25519PublicKey)
			if err != nil {
				g.initErr = utlserrors.New("tls: ECH GREASE key parse error").Base(err).AtError()
				return
			}
			suite := echCipher{
				KDFID:  defaultHpkeKdf,
				AEADID: defaultHpkeAead,
			}
			g.EncapsulatedKey, _, err = hpke.SetupSender(kem, suite.KDFID, suite.AEADID, echPK, []byte{})
			if err != nil {
				g.initErr = utlserrors.New("tls: ECH GREASE setup error").Base(err).AtError()
				return
			}
			utlserrors.LogDebug(ctx, "ECH GREASE: generated encapsulated key, length=", len(g.EncapsulatedKey))
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
				g.initErr = utlserrors.New("ECH GREASE: error generating random index for payload length").Base(err).AtError()
				return
			}

			baseLen := g.CandidatePayloadLens[rndIndex.Int64()]

			// Add random jitter (0-15 bytes) to further reduce fingerprinting.
			// This prevents exact size matching even when the same base size is selected.
			jitterBig, err := rand.Int(rand.Reader, big.NewInt(16))
			if err != nil {
				g.initErr = utlserrors.New("ECH GREASE: error generating random jitter for payload length").Base(err).AtError()
				return
			}
			finalLen := baseLen + uint16(jitterBig.Int64())

			utlserrors.LogDebug(ctx, "ECH GREASE: generating payload, baseLen=", baseLen,
				" jitter=", jitterBig.Int64(), " finalLen=", finalLen)

			g.initErr = g.randomizePayload(finalLen)
			if g.initErr != nil {
				return
			}

			utlserrors.LogDebug(ctx, "ECH GREASE: initialization complete, payloadLen=", len(g.payload))
		}
	})

	return g.initErr
}

func (g *GREASEEncryptedClientHelloExtension) randomizePayload(encodedHelloInnerLen uint16) error {
	ctx := context.Background()

	if len(g.payload) != 0 {
		utlserrors.LogDebug(ctx, "ECH GREASE: payload already initialized")
		return utlserrors.New("tls: ECH extension already initialized").AtError()
	}

	payloadLen := cipherLen(g.cipherSuite.AeadId, int(encodedHelloInnerLen))
	if payloadLen < 0 {
		utlserrors.LogDebug(ctx, "ECH GREASE: invalid cipher suite AEAD=0x", fmt.Sprintf("%04x", g.cipherSuite.AeadId))
		return utlserrors.New("tls: invalid ECH cipher suite").AtError()
	}

	utlserrors.LogDebug(ctx, "ECH GREASE: randomizing payload, encodedLen=", encodedHelloInnerLen, " payloadLen=", payloadLen)

	g.payload = make([]byte, payloadLen)
	_, err := rand.Read(g.payload)
	if err != nil {
		return utlserrors.New("tls: ECH GREASE random generation error").Base(err).AtError()
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
	ctx := context.Background()

	if err := g.init(); err != nil {
		// Return 0 on error for consistency: Read() will return 0 bytes written
		// along with the actual error. Returning non-zero here while Read()
		// writes nothing would cause buffer allocation/usage inconsistencies.
		utlserrors.LogDebug(ctx, "ECH GREASE: Len returning 0 due to init error")
		return 0
	}
	extLen := 2 + 2 + 1 /* ClientHello Type */ + 4 /* CipherSuite */ + 1 /* Config ID */ + 2 + len(g.EncapsulatedKey) + 2 + len(g.payload)
	utlserrors.LogDebug(ctx, "ECH GREASE: Len=", extLen)
	return extLen
}

// Read implements TLSExtension.
func (g *GREASEEncryptedClientHelloExtension) Read(b []byte) (int, error) {
	ctx := context.Background()

	// Check for initialization errors first
	if err := g.init(); err != nil {
		utlserrors.LogDebug(ctx, "ECH GREASE: Read failed, initialization error")
		return 0, utlserrors.New("tls: ech extension initialization failed").Base(err).AtError()
	}

	extLen := 2 + 2 + 1 + 4 + 1 + 2 + len(g.EncapsulatedKey) + 2 + len(g.payload)
	if len(b) < extLen {
		utlserrors.LogDebug(ctx, "ECH GREASE: buffer too small, have=", len(b), " need=", extLen)
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

	utlserrors.LogDebug(ctx, "ECH GREASE: Read complete, extLen=", extLen,
		" configID=", g.configId, " payloadLen=", len(g.payload))

	return extLen, io.EOF
}

// MarshalClientHello implements EncryptedClientHelloExtension.
func (*GREASEEncryptedClientHelloExtension) MarshalClientHello(*UConn) error {
	return utlserrors.New("tls: ECH marshal not supported on this extension type").AtError()
}

// Write implements TLSExtensionWriter.
func (g *GREASEEncryptedClientHelloExtension) Write(b []byte) (int, error) {
	ctx := context.Background()
	fullLen := len(b)
	utlserrors.LogDebug(ctx, "ECH GREASE: parsing extension data, length=", fullLen)

	extData := cryptobyte.String(b)

	// Check the extension type, it must be OuterClientHello otherwise we are not
	// parsing the correct extension
	var chType uint8 // 0: outer, 1: inner
	var ignored cryptobyte.String
	if !extData.ReadUint8(&chType) || chType != 0 {
		utlserrors.LogDebug(ctx, "ECH GREASE: bad ClientHello type=", chType)
		return fullLen, utlserrors.New("bad Client Hello type, expected 0, got ", chType).AtError()
	}

	// Parse the cipher suite
	if !extData.ReadUint16(&g.cipherSuite.KdfId) || !extData.ReadUint16(&g.cipherSuite.AeadId) {
		utlserrors.LogDebug(ctx, "ECH GREASE: failed to read cipher suite")
		return fullLen, utlserrors.New("bad cipher suite").AtError()
	}
	if g.cipherSuite.KdfId != dicttls.HKDF_SHA256 &&
		g.cipherSuite.KdfId != dicttls.HKDF_SHA384 &&
		g.cipherSuite.KdfId != dicttls.HKDF_SHA512 {
		utlserrors.LogDebug(ctx, "ECH GREASE: unsupported KDF ID=", g.cipherSuite.KdfId)
		return fullLen, utlserrors.New("bad KDF ID: ", g.cipherSuite.KdfId).AtError()
	}
	if g.cipherSuite.AeadId != dicttls.AEAD_AES_128_GCM &&
		g.cipherSuite.AeadId != dicttls.AEAD_AES_256_GCM &&
		g.cipherSuite.AeadId != dicttls.AEAD_CHACHA20_POLY1305 {
		utlserrors.LogDebug(ctx, "ECH GREASE: unsupported AEAD ID=", g.cipherSuite.AeadId)
		return fullLen, utlserrors.New("bad AEAD ID: ", g.cipherSuite.AeadId).AtError()
	}
	g.CandidateCipherSuites = []HPKESymmetricCipherSuite{g.cipherSuite}

	utlserrors.LogDebug(ctx, "ECH GREASE: parsed cipher suite KDF=0x",
		fmt.Sprintf("%04x", g.cipherSuite.KdfId), " AEAD=0x", fmt.Sprintf("%04x", g.cipherSuite.AeadId))

	// GREASE the ConfigId
	if !extData.ReadUint8(&g.configId) {
		utlserrors.LogDebug(ctx, "ECH GREASE: failed to read config ID")
		return fullLen, utlserrors.New("bad config ID").AtError()
	}
	// we don't write to CandidateConfigIds because we don't really want to reuse the same config_id

	// GREASE the EncapsulatedKey
	if !extData.ReadUint16LengthPrefixed(&ignored) {
		utlserrors.LogDebug(ctx, "ECH GREASE: failed to read encapsulated key")
		return fullLen, utlserrors.New("bad encapsulated key").AtError()
	}
	// Validate encapsulated key size: must not be empty and must have reasonable bounds.
	// X25519 uses 32 bytes, P-256 uses 65 bytes, P-384/P-521 use more. 256 bytes covers all KEMs.
	const maxEncapsulatedKeyLen = 256
	if len(ignored) == 0 {
		utlserrors.LogDebug(ctx, "ECH GREASE: empty encapsulated key")
		return fullLen, utlserrors.New("tls: empty encapsulated key").AtError()
	}
	if len(ignored) > maxEncapsulatedKeyLen {
		utlserrors.LogDebug(ctx, "ECH GREASE: encapsulated key too large=", len(ignored))
		return fullLen, utlserrors.New("tls: encapsulated key too large: ", len(ignored), " > ", maxEncapsulatedKeyLen).AtError()
	}
	g.EncapsulatedKey = make([]byte, len(ignored))
	n, err := rand.Read(g.EncapsulatedKey)
	if err != nil {
		return fullLen, utlserrors.New("tls: generating ech key").Base(err).AtError()
	}
	if n != len(g.EncapsulatedKey) {
		return fullLen, utlserrors.New("tls: short read generating ech key").AtError()
	}

	utlserrors.LogDebug(ctx, "ECH GREASE: generated encapsulated key, length=", len(g.EncapsulatedKey))

	// GREASE the payload
	if !extData.ReadUint16LengthPrefixed(&ignored) {
		utlserrors.LogDebug(ctx, "ECH GREASE: failed to read payload")
		return fullLen, utlserrors.New("bad payload").AtError()
	}
	// Validate payload size: must contain at least AEAD overhead + 1 byte of plaintext,
	// and must not exceed reasonable bounds to prevent memory exhaustion.
	const maxPayloadLen = 16384 // 16KB is sufficient for any realistic ECH payload
	cipherOverhead := cipherLen(g.cipherSuite.AeadId, 0)
	if cipherOverhead < 0 {
		utlserrors.LogDebug(ctx, "ECH GREASE: invalid AEAD identifier")
		return fullLen, utlserrors.New("tls: invalid AEAD identifier").AtError()
	}
	if len(ignored) == 0 {
		utlserrors.LogDebug(ctx, "ECH GREASE: empty payload")
		return fullLen, utlserrors.New("tls: empty ECH payload").AtError()
	}
	if len(ignored) <= cipherOverhead {
		utlserrors.LogDebug(ctx, "ECH GREASE: payload too short=", len(ignored), " overhead=", cipherOverhead)
		return fullLen, utlserrors.New("tls: payload too short for AEAD overhead: ", len(ignored), " <= ", cipherOverhead).AtError()
	}
	if len(ignored) > maxPayloadLen {
		utlserrors.LogDebug(ctx, "ECH GREASE: payload too large=", len(ignored))
		return fullLen, utlserrors.New("tls: ECH payload too large: ", len(ignored), " > ", maxPayloadLen).AtError()
	}
	// Set payload directly with exact size to preserve fingerprint during round-trip.
	// This bypasses the jitter logic in init() which would alter the size.
	g.payload = make([]byte, len(ignored))
	if _, err := rand.Read(g.payload); err != nil {
		return fullLen, utlserrors.New("tls: generating ech payload").Base(err).AtError()
	}

	if !extData.Empty() {
		utlserrors.LogDebug(ctx, "ECH GREASE: extension has trailing data")
		return fullLen, utlserrors.New("tls: extension has trailing data").AtError()
	}

	utlserrors.LogDebug(ctx, "ECH GREASE: successfully parsed extension, configID=", g.configId,
		" payloadLen=", len(g.payload))

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
	ctx := context.Background()
	utlserrors.LogDebug(ctx, "ECH GREASE: cloning extension with state")

	// Ensure initialization is complete before reading internal state.
	// This prevents race conditions when cloneWithState is called concurrently
	// while another goroutine might be running init() via sync.Once.
	// The init() call is idempotent due to sync.Once, so this is safe.
	_ = g.init()

	// Clone payload if present (set by Write() during fingerprinting)
	var payload []byte
	if len(g.payload) > 0 {
		payload = make([]byte, len(g.payload))
		copy(payload, g.payload)
	}

	utlserrors.LogDebug(ctx, "ECH GREASE: cloned, configID=", g.configId, " payloadLen=", len(payload))

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
	return utlserrors.New("tls: unimplemented ECHExtension").AtError()
}

// Len implements TLSExtension.
func (*UnimplementedECHExtension) Len() int {
	return 0
}

// Read implements TLSExtension.
func (*UnimplementedECHExtension) Read(_ []byte) (int, error) {
	return 0, utlserrors.New("tls: unimplemented ECHExtension").AtError()
}

// MarshalClientHello implements EncryptedClientHelloExtension.
func (*UnimplementedECHExtension) MarshalClientHello(*UConn) error {
	return utlserrors.New("tls: unimplemented ECHExtension").AtError()
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
