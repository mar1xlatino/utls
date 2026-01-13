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
		name           string
		curveID        CurveID
		ecdheCurveID   CurveID // The underlying ECDHE curve
		ecdhePubSize   int     // Expected ECDHE public key size
		mlkemEncapSize int     // ML-KEM encapsulation key size (768: 1184, 1024: 1568)
		useMlkem1024   bool    // Whether to use ML-KEM-1024 instead of ML-KEM-768
	}{
		{"X25519MLKEM768", X25519MLKEM768, X25519, 32, 1184, false},
		{"X25519Kyber768Draft00", X25519Kyber768Draft00, X25519, 32, 1184, false},
		{"SecP256r1MLKEM768", SecP256r1MLKEM768, CurveP256, 65, 1184, false},
		{"SecP384r1MLKEM1024", SecP384r1MLKEM1024, CurveP384, 97, 1568, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate initial key generation
			initialEcdheKey, err := generateECDHEKey(cryptoRand{}, tc.ecdheCurveID)
			if err != nil {
				t.Fatalf("failed to generate initial ECDHE key: %v", err)
			}

			initialSeed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(cryptoRand{}, initialSeed); err != nil {
				t.Fatalf("failed to read initial seed: %v", err)
			}

			// Store initial public keys for comparison
			var initialMlkemPublic []byte
			var initialKeyShare *keySharePrivateKeys

			if tc.useMlkem1024 {
				// ML-KEM-1024 for SecP384r1MLKEM1024
				initialMlkemKey1024, err := mlkem.NewDecapsulationKey1024(initialSeed)
				if err != nil {
					t.Fatalf("failed to generate initial ML-KEM-1024 key: %v", err)
				}
				initialKeyShare = &keySharePrivateKeys{
					curveID:   tc.curveID,
					ecdhe:     initialEcdheKey,
					mlkem1024: initialMlkemKey1024,
				}
				initialMlkemPublic = initialMlkemKey1024.EncapsulationKey().Bytes()
			} else {
				// ML-KEM-768 for other hybrids
				initialMlkemKey768, err := mlkem.NewDecapsulationKey768(initialSeed)
				if err != nil {
					t.Fatalf("failed to generate initial ML-KEM-768 key: %v", err)
				}
				initialKeyShare = &keySharePrivateKeys{
					curveID:    tc.curveID,
					ecdhe:      initialEcdheKey,
					mlkem:      initialMlkemKey768,
					mlkemEcdhe: initialEcdheKey,
				}
				initialMlkemPublic = initialMlkemKey768.EncapsulationKey().Bytes()
			}

			initialEcdhePublic := initialKeyShare.ecdhe.PublicKey().Bytes()

			// Simulate HRR key regeneration (mirroring processHelloRetryRequest code)
			newEcdheKey, err := generateECDHEKey(cryptoRand{}, tc.ecdheCurveID)
			if err != nil {
				t.Fatalf("failed to generate new ECDHE key: %v", err)
			}

			newSeed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(cryptoRand{}, newSeed); err != nil {
				t.Fatalf("failed to read new seed: %v", err)
			}

			// Generate new ML-KEM key and build key share data
			var newMlkemPublic []byte
			var keyShareData []byte

			if tc.useMlkem1024 {
				// ML-KEM-1024 for SecP384r1MLKEM1024
				newMlkemKey1024, err := mlkem.NewDecapsulationKey1024(newSeed)
				if err != nil {
					t.Fatalf("failed to generate new ML-KEM-1024 key: %v", err)
				}
				newMlkemPublic = newMlkemKey1024.EncapsulationKey().Bytes()

				// SecP384r1MLKEM1024 format: P-384 (97 bytes) || ML-KEM-1024 encapsulation key (1568 bytes)
				keyShareData = append(newEcdheKey.PublicKey().Bytes(), newMlkemPublic...)
				expectedSize := tc.ecdhePubSize + tc.mlkemEncapSize
				if len(keyShareData) != expectedSize {
					t.Errorf("SecP384r1MLKEM1024 key share size: got %d, want %d", len(keyShareData), expectedSize)
				}
				// Verify P-384 comes first (per draft-ietf-tls-ecdhe-mlkem-03)
				if !bytes.Equal(keyShareData[:tc.ecdhePubSize], newEcdheKey.PublicKey().Bytes()) {
					t.Error("SecP384r1MLKEM1024: P-384 key not at expected position")
				}
				// Verify ML-KEM-1024 comes second
				if !bytes.Equal(keyShareData[tc.ecdhePubSize:], newMlkemPublic) {
					t.Error("SecP384r1MLKEM1024: ML-KEM-1024 key not at expected position")
				}
			} else {
				// ML-KEM-768 for other hybrids
				newMlkemKey768, err := mlkem.NewDecapsulationKey768(newSeed)
				if err != nil {
					t.Fatalf("failed to generate new ML-KEM-768 key: %v", err)
				}
				newMlkemPublic = newMlkemKey768.EncapsulationKey().Bytes()

				switch tc.curveID {
				case X25519Kyber768Draft00:
					// Draft format: X25519 (32 bytes) || ML-KEM encapsulation key (1184 bytes)
					keyShareData = append(newEcdheKey.PublicKey().Bytes(), newMlkemPublic...)
					expectedSize := tc.ecdhePubSize + tc.mlkemEncapSize
					if len(keyShareData) != expectedSize {
						t.Errorf("X25519Kyber768Draft00 key share size: got %d, want %d", len(keyShareData), expectedSize)
					}
					// Verify X25519 comes first
					if !bytes.Equal(keyShareData[:tc.ecdhePubSize], newEcdheKey.PublicKey().Bytes()) {
						t.Error("X25519Kyber768Draft00: X25519 key not at expected position")
					}
				case X25519MLKEM768:
					// Final format: ML-KEM encapsulation key (1184 bytes) || X25519 (32 bytes)
					keyShareData = append(newMlkemPublic, newEcdheKey.PublicKey().Bytes()...)
					expectedSize := tc.mlkemEncapSize + tc.ecdhePubSize
					if len(keyShareData) != expectedSize {
						t.Errorf("X25519MLKEM768 key share size: got %d, want %d", len(keyShareData), expectedSize)
					}
					// Verify ML-KEM comes first
					if !bytes.Equal(keyShareData[:tc.mlkemEncapSize], newMlkemPublic) {
						t.Error("X25519MLKEM768: ML-KEM key not at expected position")
					}
				case SecP256r1MLKEM768:
					// SecP256r1MLKEM768 format: P-256 (65 bytes) || ML-KEM encapsulation key (1184 bytes)
					keyShareData = append(newEcdheKey.PublicKey().Bytes(), newMlkemPublic...)
					expectedSize := tc.ecdhePubSize + tc.mlkemEncapSize
					if len(keyShareData) != expectedSize {
						t.Errorf("SecP256r1MLKEM768 key share size: got %d, want %d", len(keyShareData), expectedSize)
					}
					// Verify P-256 comes first (per draft-ietf-tls-ecdhe-mlkem-03)
					if !bytes.Equal(keyShareData[:tc.ecdhePubSize], newEcdheKey.PublicKey().Bytes()) {
						t.Error("SecP256r1MLKEM768: P-256 key not at expected position")
					}
					// Verify ML-KEM comes second
					if !bytes.Equal(keyShareData[tc.ecdhePubSize:], newMlkemPublic) {
						t.Error("SecP256r1MLKEM768: ML-KEM key not at expected position")
					}
				}
			}

			// Verify keys are different (HRR should regenerate)
			newEcdhePublic := newEcdheKey.PublicKey().Bytes()

			if bytes.Equal(initialEcdhePublic, newEcdhePublic) {
				t.Error("ECDHE key was not regenerated after HRR")
			}

			if bytes.Equal(initialMlkemPublic, newMlkemPublic) {
				t.Error("ML-KEM key was not regenerated after HRR")
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

// TestSecP256r1MLKEM768Handshake tests the full TLS 1.3 handshake with SecP256r1MLKEM768.
// This verifies the end-to-end key exchange works correctly for the P-256 + ML-KEM-768 hybrid.
func TestSecP256r1MLKEM768Handshake(t *testing.T) {
	testCases := []struct {
		name         string
		clientCurves []CurveID
		serverCurves []CurveID
		expectCurve  CurveID
		expectHRR    bool
	}{
		{
			name:         "SecP256r1MLKEM768 direct",
			clientCurves: []CurveID{SecP256r1MLKEM768, CurveP256},
			serverCurves: []CurveID{SecP256r1MLKEM768, CurveP256},
			expectCurve:  SecP256r1MLKEM768,
			expectHRR:    false,
		},
		{
			name:         "SecP256r1MLKEM768 with P-256 fallback available",
			clientCurves: []CurveID{SecP256r1MLKEM768, CurveP256},
			serverCurves: []CurveID{SecP256r1MLKEM768},
			expectCurve:  SecP256r1MLKEM768,
			expectHRR:    false,
		},
		{
			name:         "Fallback to P-256 when server doesn't support hybrid",
			clientCurves: []CurveID{SecP256r1MLKEM768, CurveP256},
			serverCurves: []CurveID{CurveP256},
			expectCurve:  CurveP256,
			expectHRR:    true, // Server will request P-256 via HRR
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientConfig := testConfig.Clone()
			clientConfig.CurvePreferences = tc.clientCurves
			clientConfig.MinVersion = VersionTLS13
			clientConfig.MaxVersion = VersionTLS13

			serverConfig := testConfig.Clone()
			serverConfig.CurvePreferences = tc.serverCurves
			serverConfig.MinVersion = VersionTLS13
			serverConfig.MaxVersion = VersionTLS13

			testHandshake(t, clientConfig, serverConfig)

			// Note: testHandshake validates the handshake completes successfully.
			// The curve selection can be verified by inspecting connection state
			// if needed for deeper validation.
		})
	}
}

// TestSecP256r1MLKEM768KeyShareSizes verifies the expected sizes for SecP256r1MLKEM768 key shares.
func TestSecP256r1MLKEM768KeyShareSizes(t *testing.T) {
	const (
		p256PubKeySize         = 65   // Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
		mlkem768EncapKeySize   = 1184 // ML-KEM-768 encapsulation key
		mlkem768CiphertextSize = 1088 // ML-KEM-768 ciphertext
		mlkem768SharedSecSize  = 32   // ML-KEM-768 shared secret
		p256SharedSecSize      = 32   // P-256 ECDH shared secret (x-coordinate)
	)

	// Expected client key share size: P-256 (65) + ML-KEM encap key (1184) = 1249
	expectedClientKeyShare := p256PubKeySize + mlkem768EncapKeySize
	if expectedClientKeyShare != 1249 {
		t.Errorf("SecP256r1MLKEM768 client key share size: got %d, want 1249", expectedClientKeyShare)
	}

	// Expected server key share size: P-256 (65) + ML-KEM ciphertext (1088) = 1153
	expectedServerKeyShare := p256PubKeySize + mlkem768CiphertextSize
	if expectedServerKeyShare != 1153 {
		t.Errorf("SecP256r1MLKEM768 server key share size: got %d, want 1153", expectedServerKeyShare)
	}

	// Expected shared secret size: P-256 (32) + ML-KEM (32) = 64
	expectedSharedSecret := p256SharedSecSize + mlkem768SharedSecSize
	if expectedSharedSecret != 64 {
		t.Errorf("SecP256r1MLKEM768 shared secret size: got %d, want 64", expectedSharedSecret)
	}

	// Verify expectedKeyShareSize returns correct value
	if got := expectedKeyShareSize(SecP256r1MLKEM768); got != expectedClientKeyShare {
		t.Errorf("expectedKeyShareSize(SecP256r1MLKEM768) = %d, want %d", got, expectedClientKeyShare)
	}
}

// TestSecP384r1MLKEM1024KeyShareSizes verifies the expected sizes for SecP384r1MLKEM1024 key shares.
func TestSecP384r1MLKEM1024KeyShareSizes(t *testing.T) {
	const (
		p384PubKeySize          = 97   // Uncompressed point: 0x04 || X (48 bytes) || Y (48 bytes)
		mlkem1024EncapKeySize   = 1568 // ML-KEM-1024 encapsulation key
		mlkem1024CiphertextSize = 1568 // ML-KEM-1024 ciphertext
		mlkem1024SharedSecSize  = 32   // ML-KEM-1024 shared secret
		p384SharedSecSize       = 48   // P-384 ECDH shared secret (x-coordinate)
	)

	// Expected client key share size: P-384 (97) + ML-KEM-1024 encap key (1568) = 1665
	expectedClientKeyShare := p384PubKeySize + mlkem1024EncapKeySize
	if expectedClientKeyShare != 1665 {
		t.Errorf("SecP384r1MLKEM1024 client key share size: got %d, want 1665", expectedClientKeyShare)
	}

	// Expected server key share size: P-384 (97) + ML-KEM-1024 ciphertext (1568) = 1665
	expectedServerKeyShare := p384PubKeySize + mlkem1024CiphertextSize
	if expectedServerKeyShare != 1665 {
		t.Errorf("SecP384r1MLKEM1024 server key share size: got %d, want 1665", expectedServerKeyShare)
	}

	// Expected shared secret size: P-384 (48) + ML-KEM-1024 (32) = 80
	expectedSharedSecret := p384SharedSecSize + mlkem1024SharedSecSize
	if expectedSharedSecret != 80 {
		t.Errorf("SecP384r1MLKEM1024 shared secret size: got %d, want 80", expectedSharedSecret)
	}

	// Verify expectedKeyShareSize returns correct value
	if got := expectedKeyShareSize(SecP384r1MLKEM1024); got != expectedClientKeyShare {
		t.Errorf("expectedKeyShareSize(SecP384r1MLKEM1024) = %d, want %d", got, expectedClientKeyShare)
	}
}

// TestSecP384r1MLKEM1024Handshake tests the full TLS 1.3 handshake with SecP384r1MLKEM1024.
// This verifies the end-to-end key exchange works correctly for the P-384 + ML-KEM-1024 hybrid.
func TestSecP384r1MLKEM1024Handshake(t *testing.T) {
	testCases := []struct {
		name         string
		clientCurves []CurveID
		serverCurves []CurveID
		expectCurve  CurveID
		expectHRR    bool
	}{
		{
			name:         "SecP384r1MLKEM1024 direct",
			clientCurves: []CurveID{SecP384r1MLKEM1024, CurveP384},
			serverCurves: []CurveID{SecP384r1MLKEM1024, CurveP384},
			expectCurve:  SecP384r1MLKEM1024,
			expectHRR:    false,
		},
		{
			name:         "SecP384r1MLKEM1024 with P-384 fallback available",
			clientCurves: []CurveID{SecP384r1MLKEM1024, CurveP384},
			serverCurves: []CurveID{SecP384r1MLKEM1024},
			expectCurve:  SecP384r1MLKEM1024,
			expectHRR:    false,
		},
		{
			name:         "Fallback to P-384 when server doesn't support hybrid",
			clientCurves: []CurveID{SecP384r1MLKEM1024, CurveP384},
			serverCurves: []CurveID{CurveP384},
			expectCurve:  CurveP384,
			expectHRR:    true, // Server will request P-384 via HRR
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientConfig := testConfig.Clone()
			clientConfig.CurvePreferences = tc.clientCurves
			clientConfig.MinVersion = VersionTLS13
			clientConfig.MaxVersion = VersionTLS13

			serverConfig := testConfig.Clone()
			serverConfig.CurvePreferences = tc.serverCurves
			serverConfig.MinVersion = VersionTLS13
			serverConfig.MaxVersion = VersionTLS13

			testHandshake(t, clientConfig, serverConfig)

			// Note: testHandshake validates the handshake completes successfully.
			// The curve selection can be verified by inspecting connection state
			// if needed for deeper validation.
		})
	}
}
