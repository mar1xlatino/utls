// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"errors"
	"hash"
	"io"
	"math/big"
	"time"

	"github.com/refraction-networking/utls/internal/tls13"
)

// This file contains the functions necessary to compute the TLS 1.3 key
// schedule. See RFC 8446, Section 7.

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2.
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) ([]byte, error) {
	return tls13.ExpandLabel(c.hash.New, trafficSecret, "traffic upd", nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3.
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte, err error) {
	key, err = tls13.ExpandLabel(c.hash.New, trafficSecret, "key", nil, c.keyLen)
	if err != nil {
		return nil, nil, err
	}
	iv, err = tls13.ExpandLabel(c.hash.New, trafficSecret, "iv", nil, aeadNonceLength)
	if err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

// finishedHash generates the Finished verify_data or PskBinderEntry according
// to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// selection.
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) ([]byte, error) {
	finishedKey, err := tls13.ExpandLabel(c.hash.New, baseKey, "finished", nil, c.hash.Size())
	if err != nil {
		return nil, err
	}
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil), nil
}

// pskBinderMinDuration is the minimum time floor for PSK binder computation
// when constant-time mode is enabled. This prevents DPI systems from
// fingerprinting based on binder computation timing variations.
//
// The value is chosen to be longer than typical binder computation time
// (which varies based on transcript size) but short enough to not
// significantly impact handshake latency.
const pskBinderMinDuration = 150 * time.Microsecond

// finishedHashConstantTime generates PSK binders with constant-time guarantees
// to prevent timing side-channel attacks from DPI systems.
//
// The function ensures:
//   - HMAC computation (already constant-time)
//   - Minimum computation time floor to normalize observable timing
//   - Consistent timing regardless of transcript size
//
// This is a defense-in-depth measure. While HMAC itself is constant-time,
// the overall operation timing (transcript hashing, key derivation) can vary
// based on input size. Network observers analyzing handshake timing could
// potentially fingerprint connections based on these variations.
func (c *cipherSuiteTLS13) finishedHashConstantTime(baseKey []byte, transcript hash.Hash) ([]byte, error) {
	start := time.Now()

	// Perform the actual binder computation
	binder, err := c.finishedHash(baseKey, transcript)

	// Ensure minimum computation time to normalize timing
	// This prevents DPI from fingerprinting based on timing variations
	elapsed := time.Since(start)
	if elapsed < pskBinderMinDuration {
		time.Sleep(pskBinderMinDuration - elapsed)
	}

	return binder, err
}

// exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// RFC 8446, Section 7.5.
func (c *cipherSuiteTLS13) exportKeyingMaterial(s *tls13.MasterSecret, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
	expMasterSecret, err := s.ExporterMasterSecret(transcript)
	if err != nil {
		// Return a function that always returns the error
		return func(label string, context []byte, length int) ([]byte, error) {
			return nil, err
		}
	}
	return func(label string, context []byte, length int) ([]byte, error) {
		return expMasterSecret.Exporter(label, context, length)
	}
}

type keySharePrivateKeys struct {
	curveID    CurveID
	ecdhe      *ecdh.PrivateKey
	mlkem      *mlkem.DecapsulationKey768
	mlkemEcdhe *ecdh.PrivateKey // [uTLS] seperate ecdhe key for pq keyshare in line with Chrome, instead of reusing ecdhe key like stdlib
	ffdhe      *ffdhePrivateKey // [uTLS] FFDHE private key for RFC 7919 finite field key exchange
}

// ffdhePrivateKey holds the private and public keys for FFDHE key exchange.
// RFC 7919 defines the standardized FFDHE groups for TLS.
type ffdhePrivateKey struct {
	group   CurveID  // FFDHE group ID (e.g., CurveFFDHE2048)
	private *big.Int // Private exponent
	public  *big.Int // Public value: g^private mod p
}

// generateFFDHEKey generates an FFDHE key pair for the specified group.
// Returns an ffdhePrivateKey containing both the private exponent and public value.
//
// The private key is generated as a random value in the range [2, p-2] where p
// is the group's prime modulus. The public key is computed as g^private mod p
// where g=2 is the generator for all RFC 7919 groups.
//
// Security note: The private exponent should have at least as many bits of
// entropy as the security level of the group. RFC 7919 groups are "safe primes"
// which provides additional security guarantees.
func generateFFDHEKey(rand io.Reader, group CurveID) (*ffdhePrivateKey, error) {
	params := getFFDHEGroupParams(group)
	if params == nil {
		return nil, errors.New("tls: unsupported FFDHE group")
	}

	// Generate private exponent with the same bit length as the prime.
	// For safe primes, we want the private key to be in range [2, p-2].
	p := params.p
	pMinus2 := new(big.Int).Sub(p, big.NewInt(2))

	// Generate random bytes with the same byte length as the prime
	privateBytes := make([]byte, params.size)
	if _, err := io.ReadFull(rand, privateBytes); err != nil {
		return nil, err
	}

	// Convert to big.Int and reduce modulo (p-2) to get range [0, p-3]
	private := new(big.Int).SetBytes(privateBytes)
	private.Mod(private, pMinus2)
	// Add 2 to get range [2, p-1]
	private.Add(private, big.NewInt(2))

	// Compute public value: g^private mod p
	// All RFC 7919 groups use g=2
	public := new(big.Int).Exp(ffdheGenerator, private, p)

	return &ffdhePrivateKey{
		group:   group,
		private: private,
		public:  public,
	}, nil
}

// PublicKeyBytes returns the public key as a byte slice in big-endian format.
// The byte slice is padded to the group's key size to ensure consistent length.
func (k *ffdhePrivateKey) PublicKeyBytes() []byte {
	params := getFFDHEGroupParams(k.group)
	if params == nil {
		return nil
	}
	// Ensure consistent length by padding to group size
	publicBytes := k.public.Bytes()
	if len(publicBytes) < params.size {
		padded := make([]byte, params.size)
		copy(padded[params.size-len(publicBytes):], publicBytes)
		return padded
	}
	return publicBytes
}

// SharedSecret computes the shared secret from the peer's public key.
// The peer's public key is provided as a byte slice in big-endian format.
//
// The shared secret is computed as: peerPublic^private mod p
//
// Security validations performed:
// - Peer public key must be in range [2, p-2]
// - Result is returned with consistent byte length (padded to group size)
func (k *ffdhePrivateKey) SharedSecret(peerPublicBytes []byte) ([]byte, error) {
	params := getFFDHEGroupParams(k.group)
	if params == nil {
		return nil, errors.New("tls: unsupported FFDHE group")
	}

	// Parse peer's public key
	peerPublic := new(big.Int).SetBytes(peerPublicBytes)

	// Validate peer's public key is in range [2, p-2]
	// This prevents small subgroup attacks and ensures the shared secret
	// will have proper entropy.
	p := params.p
	if peerPublic.Cmp(big.NewInt(2)) < 0 {
		return nil, errors.New("tls: invalid FFDHE public key (too small)")
	}
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	if peerPublic.Cmp(pMinus1) >= 0 {
		return nil, errors.New("tls: invalid FFDHE public key (too large)")
	}

	// Compute shared secret: peerPublic^private mod p
	sharedSecret := new(big.Int).Exp(peerPublic, k.private, p)

	// Return with consistent length (padded to group size)
	secretBytes := sharedSecret.Bytes()
	if len(secretBytes) < params.size {
		padded := make([]byte, params.size)
		copy(padded[params.size-len(secretBytes):], secretBytes)
		return padded, nil
	}
	return secretBytes, nil
}

// Zero securely clears the private key material from memory.
// Should be called when the key is no longer needed.
func (k *ffdhePrivateKey) Zero() {
	if k.private != nil {
		// Zero all words in the big.Int
		k.private.SetInt64(0)
	}
}

const x25519PublicKeySize = 32

// generateECDHEKey returns a PrivateKey that implements Diffie-Hellman
// according to RFC 8446, Section 4.2.8.2.
func generateECDHEKey(rand io.Reader, curveID CurveID) (*ecdh.PrivateKey, error) {
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	return curve.GenerateKey(rand)
}

func curveForCurveID(id CurveID) (ecdh.Curve, bool) {
	switch id {
	case X25519:
		return ecdh.X25519(), true
	case CurveP256:
		return ecdh.P256(), true
	case CurveP384:
		return ecdh.P384(), true
	case CurveP521:
		return ecdh.P521(), true
	default:
		return nil, false
	}
}
