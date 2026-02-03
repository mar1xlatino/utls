package tls13

import (
	"hash"

	utlserrors "github.com/refraction-networking/utls/errors"
)

// ErrSecretLengthMismatch is returned when a pre-computed secret has an
// incorrect length for the specified hash function.
var ErrSecretLengthMismatch = utlserrors.New("tls13: secret length does not match hash output size").AtError()

// NewEarlySecretFromSecret creates an EarlySecret from a pre-computed secret.
// This is used for session resumption where the secret was previously derived.
//
// The secret length MUST match the hash output size (e.g., 32 bytes for SHA-256,
// 48 bytes for SHA-384). Returns ErrSecretLengthMismatch if the secret has an
// incorrect length.
func NewEarlySecretFromSecret[H hash.Hash](h func() H, secret []byte) (*EarlySecret, error) {
	expectedSize := h().Size()
	if len(secret) != expectedSize {
		return nil, ErrSecretLengthMismatch
	}
	return &EarlySecret{
		secret: secret,
		hash:   func() hash.Hash { return h() },
	}, nil
}

func (s *EarlySecret) Secret() []byte {
	if s != nil {
		return s.secret
	}
	return nil
}

// NewMasterSecretFromSecret creates a MasterSecret from a pre-computed secret.
// This is used for session resumption where the secret was previously derived.
//
// The secret length MUST match the hash output size (e.g., 32 bytes for SHA-256,
// 48 bytes for SHA-384). Returns ErrSecretLengthMismatch if the secret has an
// incorrect length.
func NewMasterSecretFromSecret[H hash.Hash](h func() H, secret []byte) (*MasterSecret, error) {
	expectedSize := h().Size()
	if len(secret) != expectedSize {
		return nil, ErrSecretLengthMismatch
	}
	return &MasterSecret{
		secret: secret,
		hash:   func() hash.Hash { return h() },
	}, nil
}

func (s *MasterSecret) Secret() []byte {
	if s != nil {
		return s.secret
	}
	return nil
}
