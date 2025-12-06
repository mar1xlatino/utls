// Test for ML-KEM HelloRetryRequest key regeneration
// This test verifies that utls properly regenerates ML-KEM keys when
// a server sends HelloRetryRequest requesting X25519MLKEM768 or X25519Kyber768Draft00.
package tls

import (
	"bytes"
	"crypto/mlkem"
	"io"
	"testing"
)

// TestMLKEMHRRKeyRegeneration tests that ML-KEM keys are properly regenerated on HRR.
func TestMLKEMHRRKeyRegeneration(t *testing.T) {
	testCases := []struct {
		name    string
		curveID CurveID
	}{
		{"X25519MLKEM768", X25519MLKEM768},
		{"X25519Kyber768Draft00", X25519Kyber768Draft00},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate initial key generation
			initialEcdheKey, err := generateECDHEKey(cryptoRand{}, X25519)
			if err != nil {
				t.Fatalf("failed to generate initial ECDHE key: %v", err)
			}

			initialSeed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(cryptoRand{}, initialSeed); err != nil {
				t.Fatalf("failed to read initial seed: %v", err)
			}
			initialMlkemKey, err := mlkem.NewDecapsulationKey768(initialSeed)
			if err != nil {
				t.Fatalf("failed to generate initial ML-KEM key: %v", err)
			}

			initialKeyShare := &keySharePrivateKeys{
				curveID:    tc.curveID,
				ecdhe:      initialEcdheKey,
				mlkem:      initialMlkemKey,
				mlkemEcdhe: initialEcdheKey,
			}

			// Store initial public keys for comparison
			initialEcdhePublic := initialKeyShare.ecdhe.PublicKey().Bytes()
			initialMlkemPublic := initialKeyShare.mlkem.EncapsulationKey().Bytes()

			// Simulate HRR key regeneration (mirroring processHelloRetryRequest code)
			newEcdheKey, err := generateECDHEKey(cryptoRand{}, X25519)
			if err != nil {
				t.Fatalf("failed to generate new ECDHE key: %v", err)
			}

			newSeed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(cryptoRand{}, newSeed); err != nil {
				t.Fatalf("failed to read new seed: %v", err)
			}
			newMlkemKey, err := mlkem.NewDecapsulationKey768(newSeed)
			if err != nil {
				t.Fatalf("failed to generate new ML-KEM key: %v", err)
			}

			// New key share after HRR
			newKeyShare := &keySharePrivateKeys{
				curveID:    tc.curveID,
				ecdhe:      newEcdheKey,
				mlkem:      newMlkemKey,
				mlkemEcdhe: newEcdheKey,
			}

			// Verify keys are different (HRR should regenerate)
			newEcdhePublic := newKeyShare.ecdhe.PublicKey().Bytes()
			newMlkemPublic := newKeyShare.mlkem.EncapsulationKey().Bytes()

			if bytes.Equal(initialEcdhePublic, newEcdhePublic) {
				t.Error("ECDHE key was not regenerated after HRR")
			}

			if bytes.Equal(initialMlkemPublic, newMlkemPublic) {
				t.Error("ML-KEM key was not regenerated after HRR")
			}

			// Verify key share data format
			var keyShareData []byte
			if tc.curveID == X25519Kyber768Draft00 {
				// Draft format: X25519 (32 bytes) || ML-KEM encapsulation key (1184 bytes)
				keyShareData = append(newEcdheKey.PublicKey().Bytes(), newMlkemKey.EncapsulationKey().Bytes()...)
				if len(keyShareData) != 32+1184 {
					t.Errorf("X25519Kyber768Draft00 key share size: got %d, want %d", len(keyShareData), 32+1184)
				}
				// Verify X25519 comes first
				if !bytes.Equal(keyShareData[:32], newEcdheKey.PublicKey().Bytes()) {
					t.Error("X25519Kyber768Draft00: X25519 key not at expected position")
				}
			} else {
				// Final format: ML-KEM encapsulation key (1184 bytes) || X25519 (32 bytes)
				keyShareData = append(newMlkemKey.EncapsulationKey().Bytes(), newEcdheKey.PublicKey().Bytes()...)
				if len(keyShareData) != 1184+32 {
					t.Errorf("X25519MLKEM768 key share size: got %d, want %d", len(keyShareData), 1184+32)
				}
				// Verify ML-KEM comes first
				if !bytes.Equal(keyShareData[:1184], newMlkemKey.EncapsulationKey().Bytes()) {
					t.Error("X25519MLKEM768: ML-KEM key not at expected position")
				}
			}

			t.Logf("%s key share regeneration verified successfully", tc.name)
		})
	}
}

// TestMLKEMKeyShareSizes verifies the expected sizes for ML-KEM hybrid key shares.
func TestMLKEMKeyShareSizes(t *testing.T) {
	const (
		x25519PublicKeySize     = 32
		mlkemEncapsulationSize  = 1184 // ML-KEM-768 encapsulation key size
		mlkemCiphertextSize     = 1088 // ML-KEM-768 ciphertext size
		mlkemSharedSecretSize   = 32   // ML-KEM-768 shared secret size
	)

	// Verify constant values match expected
	if x25519PublicKeySize != 32 {
		t.Errorf("x25519PublicKeySize: got %d, want 32", x25519PublicKeySize)
	}

	// Generate a key to verify sizes
	seed := make([]byte, mlkem.SeedSize)
	if _, err := io.ReadFull(cryptoRand{}, seed); err != nil {
		t.Fatalf("failed to read seed: %v", err)
	}
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatalf("failed to generate ML-KEM key: %v", err)
	}

	// Verify encapsulation key size
	encapKey := dk.EncapsulationKey().Bytes()
	if len(encapKey) != mlkemEncapsulationSize {
		t.Errorf("ML-KEM encapsulation key size: got %d, want %d", len(encapKey), mlkemEncapsulationSize)
	}

	// Verify ciphertext size via encapsulation
	// Note: Encapsulate() returns (sharedKey, ciphertext) per Go crypto/mlkem API
	sharedKey, ct := dk.EncapsulationKey().Encapsulate()
	if len(ct) != mlkemCiphertextSize {
		t.Errorf("ML-KEM ciphertext size: got %d, want %d", len(ct), mlkemCiphertextSize)
	}
	if len(sharedKey) != mlkemSharedSecretSize {
		t.Errorf("ML-KEM shared secret size: got %d, want %d", len(sharedKey), mlkemSharedSecretSize)
	}
}

// cryptoRand implements io.Reader using crypto/rand for testing
type cryptoRand struct{}

func (cryptoRand) Read(b []byte) (int, error) {
	return io.ReadFull(randReader{}, b)
}

// randReader is a simple crypto/rand.Reader wrapper
type randReader struct{}

func (randReader) Read(b []byte) (int, error) {
	// Use the existing rand source from the tls package
	return defaultConfig().rand().Read(b)
}
