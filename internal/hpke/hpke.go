// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hpke

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	_ "crypto/sha256" // Register SHA-256 hash for HKDF
	_ "crypto/sha512" // Register SHA-384 and SHA-512 hashes for HKDF
	"errors"
	"math/bits"

	"github.com/refraction-networking/utls/internal/byteorder"
	"github.com/refraction-networking/utls/internal/hkdf"
	"golang.org/x/crypto/chacha20poly1305"
)

// ErrMessageLimitReached is returned when the HPKE message limit has been reached.
// Per RFC 9180, the message limit is 2^(8*Nn - 1) where Nn is the nonce size.
// For 12-byte nonces (AES-GCM, ChaCha20-Poly1305), this is 2^95 messages.
// This error indicates a catastrophic failure - reaching this limit means
// continuing would result in nonce reuse and complete security compromise.
var ErrMessageLimitReached = errors.New("hpke: message limit reached")

// testingOnlyGenerateKey is only used during testing, to provide
// a fixed test key to use when checking the RFC 9180 vectors.
var testingOnlyGenerateKey func() (*ecdh.PrivateKey, error)

type hkdfKDF struct {
	hash crypto.Hash
}

func (kdf *hkdfKDF) LabeledExtract(sid []byte, salt []byte, label string, inputKey []byte) ([]byte, error) {
	labeledIKM := make([]byte, 0, 7+len(sid)+len(label)+len(inputKey))
	labeledIKM = append(labeledIKM, []byte("HPKE-v1")...)
	labeledIKM = append(labeledIKM, sid...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, inputKey...)
	return hkdf.Extract(kdf.hash.New, labeledIKM, salt)
}

func (kdf *hkdfKDF) LabeledExpand(suiteID []byte, randomKey []byte, label string, info []byte, length uint16) ([]byte, error) {
	labeledInfo := make([]byte, 0, 2+7+len(suiteID)+len(label)+len(info))
	labeledInfo = byteorder.BEAppendUint16(labeledInfo, length)
	labeledInfo = append(labeledInfo, []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(kdf.hash.New, randomKey, string(labeledInfo), int(length))
}

// dhKEM implements the KEM specified in RFC 9180, Section 4.1.
type dhKEM struct {
	dh  ecdh.Curve
	kdf hkdfKDF

	suiteID []byte
	nSecret uint16
}

type KemID uint16

// KEM identifiers from RFC 9180 Section 7.1
const (
	DHKEM_P256_HKDF_SHA256   uint16 = 0x0010
	DHKEM_P384_HKDF_SHA384   uint16 = 0x0011
	DHKEM_P521_HKDF_SHA512   uint16 = 0x0012 // Not implemented yet
	DHKEM_X25519_HKDF_SHA256 uint16 = 0x0020
)

var SupportedKEMs = map[uint16]struct {
	curve   ecdh.Curve
	hash    crypto.Hash
	nSecret uint16
}{
	// RFC 9180 Section 7.1
	// P-256: 32-byte shared secret, uses SHA-256 for key derivation
	DHKEM_P256_HKDF_SHA256: {ecdh.P256(), crypto.SHA256, 32},
	// P-384: 48-byte shared secret, uses SHA-384 for key derivation
	DHKEM_P384_HKDF_SHA384: {ecdh.P384(), crypto.SHA384, 48},
	// X25519: 32-byte shared secret, uses SHA-256 for key derivation
	DHKEM_X25519_HKDF_SHA256: {ecdh.X25519(), crypto.SHA256, 32},
}

func newDHKem(kemID uint16) (*dhKEM, error) {
	suite, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported suite ID")
	}
	return &dhKEM{
		dh:      suite.curve,
		kdf:     hkdfKDF{suite.hash},
		suiteID: byteorder.BEAppendUint16([]byte("KEM"), kemID),
		nSecret: suite.nSecret,
	}, nil
}

func (dh *dhKEM) ExtractAndExpand(dhKey, kemContext []byte) ([]byte, error) {
	eaePRK, err := dh.kdf.LabeledExtract(dh.suiteID[:], nil, "eae_prk", dhKey)
	if err != nil {
		return nil, err
	}
	return dh.kdf.LabeledExpand(dh.suiteID[:], eaePRK, "shared_secret", kemContext, dh.nSecret)
}

func (dh *dhKEM) Encap(pubRecipient *ecdh.PublicKey) (sharedSecret []byte, encapPub []byte, err error) {
	var privEph *ecdh.PrivateKey
	if testingOnlyGenerateKey != nil {
		privEph, err = testingOnlyGenerateKey()
	} else {
		privEph, err = dh.dh.GenerateKey(rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}
	dhVal, err := privEph.ECDH(pubRecipient)
	if err != nil {
		return nil, nil, err
	}
	encPubEph := privEph.PublicKey().Bytes()

	encPubRecip := pubRecipient.Bytes()
	kemContext := append(encPubEph, encPubRecip...)

	secret, err := dh.ExtractAndExpand(dhVal, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return secret, encPubEph, nil
}

func (dh *dhKEM) Decap(encPubEph []byte, secRecipient *ecdh.PrivateKey) ([]byte, error) {
	pubEph, err := dh.dh.NewPublicKey(encPubEph)
	if err != nil {
		return nil, err
	}
	dhVal, err := secRecipient.ECDH(pubEph)
	if err != nil {
		return nil, err
	}
	kemContext := append(encPubEph, secRecipient.PublicKey().Bytes()...)

	return dh.ExtractAndExpand(dhVal, kemContext)
}

type context struct {
	aead cipher.AEAD

	sharedSecret []byte

	suiteID []byte

	key            []byte
	baseNonce      []byte
	exporterSecret []byte

	seqNum uint128
}

type Sender struct {
	*context
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext for this AEAD. This value corresponds
// to the AEAD tag length.
func (s *Sender) Overhead() int {
	return s.aead.Overhead()
}

type Recipient struct {
	*context
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext for this AEAD. This value corresponds
// to the AEAD tag length.
func (r *Recipient) Overhead() int {
	return r.aead.Overhead()
}

var aesGCMNew = func(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type AEADID uint16

const (
	AEAD_AES_128_GCM      = 0x0001
	AEAD_AES_256_GCM      = 0x0002
	AEAD_ChaCha20Poly1305 = 0x0003
)

var SupportedAEADs = map[uint16]struct {
	keySize   int
	nonceSize int
	aead      func([]byte) (cipher.AEAD, error)
}{
	// RFC 9180, Section 7.3
	AEAD_AES_128_GCM:      {keySize: 16, nonceSize: 12, aead: aesGCMNew},
	AEAD_AES_256_GCM:      {keySize: 32, nonceSize: 12, aead: aesGCMNew},
	AEAD_ChaCha20Poly1305: {keySize: chacha20poly1305.KeySize, nonceSize: chacha20poly1305.NonceSize, aead: chacha20poly1305.New},
}

type KDFID uint16

// KDF identifiers from RFC 9180 Section 7.2
const (
	KDF_HKDF_SHA256 uint16 = 0x0001
	KDF_HKDF_SHA384 uint16 = 0x0002
	KDF_HKDF_SHA512 uint16 = 0x0003 // Not implemented yet
)

var SupportedKDFs = map[uint16]func() *hkdfKDF{
	// RFC 9180, Section 7.2
	KDF_HKDF_SHA256: func() *hkdfKDF { return &hkdfKDF{crypto.SHA256} },
	KDF_HKDF_SHA384: func() *hkdfKDF { return &hkdfKDF{crypto.SHA384} },
}

func newContext(sharedSecret []byte, kemID, kdfID, aeadID uint16, info []byte) (*context, error) {
	sid := suiteID(kemID, kdfID, aeadID)

	kdfInit, ok := SupportedKDFs[kdfID]
	if !ok {
		return nil, errors.New("unsupported KDF id")
	}
	kdf := kdfInit()

	aeadInfo, ok := SupportedAEADs[aeadID]
	if !ok {
		return nil, errors.New("unsupported AEAD id")
	}

	pskIDHash, err := kdf.LabeledExtract(sid, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, err
	}
	infoHash, err := kdf.LabeledExtract(sid, nil, "info_hash", info)
	if err != nil {
		return nil, err
	}
	ksContext := append([]byte{0}, pskIDHash...)
	ksContext = append(ksContext, infoHash...)

	secret, err := kdf.LabeledExtract(sid, sharedSecret, "secret", nil)
	if err != nil {
		return nil, err
	}

	key, err := kdf.LabeledExpand(sid, secret, "key", ksContext, uint16(aeadInfo.keySize))
	if err != nil {
		return nil, err
	}
	baseNonce, err := kdf.LabeledExpand(sid, secret, "base_nonce", ksContext, uint16(aeadInfo.nonceSize))
	if err != nil {
		return nil, err
	}
	exporterSecret, err := kdf.LabeledExpand(sid, secret, "exp", ksContext, uint16(kdf.hash.Size()))
	if err != nil {
		return nil, err
	}

	aead, err := aeadInfo.aead(key)
	if err != nil {
		return nil, err
	}

	return &context{
		aead:           aead,
		sharedSecret:   sharedSecret,
		suiteID:        sid,
		key:            key,
		baseNonce:      baseNonce,
		exporterSecret: exporterSecret,
	}, nil
}

func SetupSender(kemID, kdfID, aeadID uint16, pub *ecdh.PublicKey, info []byte) ([]byte, *Sender, error) {
	kem, err := newDHKem(kemID)
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, encapsulatedKey, err := kem.Encap(pub)
	if err != nil {
		return nil, nil, err
	}

	context, err := newContext(sharedSecret, kemID, kdfID, aeadID, info)
	if err != nil {
		return nil, nil, err
	}

	return encapsulatedKey, &Sender{context}, nil
}

func SetupRecipient(kemID, kdfID, aeadID uint16, priv *ecdh.PrivateKey, info, encPubEph []byte) (*Recipient, error) {
	kem, err := newDHKem(kemID)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := kem.Decap(encPubEph, priv)
	if err != nil {
		return nil, err
	}

	context, err := newContext(sharedSecret, kemID, kdfID, aeadID, info)
	if err != nil {
		return nil, err
	}

	return &Recipient{context}, nil
}

func (ctx *context) nextNonce() []byte {
	nonce := ctx.seqNum.bytes()[16-ctx.aead.NonceSize():]
	for i := range ctx.baseNonce {
		nonce[i] ^= ctx.baseNonce[i]
	}
	return nonce
}

// incrementNonce increments the sequence number and returns an error if the
// message limit has been reached.
//
// Message limit is, according to RFC 9180, 2^(8*Nn - 1) where Nn is the
// nonce size. For 12-byte nonces, this is 2^95 messages - an astronomically
// large number that cannot be reached in practice (would take longer than
// the age of the universe at any realistic message rate).
//
// However, if somehow reached, continuing would lead to nonce reuse and
// complete security loss, so we return an error rather than allowing that.
//
// The check is performed AFTER using the current nonce but BEFORE incrementing.
// We allow sequence numbers from 0 to 2^(8*Nn-1) - 1, meaning 2^(8*Nn-1) messages total.
// The error triggers when seqNum >= 2^(8*Nn-1), i.e., when bitLen >= 8*Nn.
func (ctx *context) incrementNonce() error {
	// Message limit: 2^(8*Nn - 1) messages allowed.
	// After sending the last valid message (seqNum = 2^(8*Nn-1) - 1, which has bitLen = 8*Nn-1),
	// incrementing would make seqNum = 2^(8*Nn-1), which has bitLen = 8*Nn.
	// We must check if the NEXT seqNum would exceed the limit.
	// Since we check BEFORE incrementing, we need to see if the incremented value would be valid.
	// A seqNum with bitLen = 8*Nn-1 is the last valid state (value 2^(8*Nn-2) to 2^(8*Nn-1)-1).
	// After using it and incrementing, we could reach 2^(8*Nn-1) which is invalid.
	//
	// To allow all 2^(8*Nn-1) messages (seqNums 0 through 2^(8*Nn-1)-1):
	// - Error when seqNum.bitLen() >= 8*Nn (means seqNum >= 2^(8*Nn-1))
	maxBits := ctx.aead.NonceSize() * 8 // For 12-byte nonce: 96 bits
	messageLimitBits := maxBits - 1     // For 12-byte nonce: 95 bits (limit is 2^95)
	// Error if seqNum >= 2^messageLimitBits, which means bitLen > messageLimitBits
	if ctx.seqNum.bitLen() > messageLimitBits {
		return ErrMessageLimitReached
	}
	ctx.seqNum = ctx.seqNum.addOne()
	return nil
}

// Seal encrypts and authenticates plaintext with associated additional data.
// Returns ErrMessageLimitReached if the HPKE message limit has been exceeded.
func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	ciphertext := s.aead.Seal(nil, s.nextNonce(), plaintext, aad)
	if err := s.incrementNonce(); err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Open decrypts and authenticates ciphertext with associated additional data.
// Returns ErrMessageLimitReached if the HPKE message limit has been exceeded.
func (r *Recipient) Open(aad, ciphertext []byte) ([]byte, error) {
	plaintext, err := r.aead.Open(nil, r.nextNonce(), ciphertext, aad)
	if err != nil {
		return nil, err
	}
	if err := r.incrementNonce(); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func suiteID(kemID, kdfID, aeadID uint16) []byte {
	suiteID := make([]byte, 0, 4+2+2+2)
	suiteID = append(suiteID, []byte("HPKE")...)
	suiteID = byteorder.BEAppendUint16(suiteID, kemID)
	suiteID = byteorder.BEAppendUint16(suiteID, kdfID)
	suiteID = byteorder.BEAppendUint16(suiteID, aeadID)
	return suiteID
}

func ParseHPKEPublicKey(kemID uint16, bytes []byte) (*ecdh.PublicKey, error) {
	kemInfo, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported KEM id")
	}
	return kemInfo.curve.NewPublicKey(bytes)
}

func ParseHPKEPrivateKey(kemID uint16, bytes []byte) (*ecdh.PrivateKey, error) {
	kemInfo, ok := SupportedKEMs[kemID]
	if !ok {
		return nil, errors.New("unsupported KEM id")
	}
	return kemInfo.curve.NewPrivateKey(bytes)
}

type uint128 struct {
	hi, lo uint64
}

func (u uint128) addOne() uint128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	return uint128{u.hi + carry, lo}
}

func (u uint128) bitLen() int {
	// When hi is non-zero, the total bit length is 64 (for lo's full width)
	// plus the significant bits in hi. When hi is zero, only count lo's bits.
	// Previous buggy implementation returned bits.Len64(u.hi) + bits.Len64(u.lo)
	// which gave wrong results, e.g., {hi:1, lo:0} returned 1 instead of 65.
	if u.hi != 0 {
		return 64 + bits.Len64(u.hi)
	}
	return bits.Len64(u.lo)
}

func (u uint128) bytes() []byte {
	b := make([]byte, 16)
	byteorder.BEPutUint64(b[0:], u.hi)
	byteorder.BEPutUint64(b[8:], u.lo)
	return b
}
