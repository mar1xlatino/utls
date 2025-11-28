// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

func TestUTLSMarshalNoOp(t *testing.T) {
	str := "We rely on clientHelloMsg.marshal() not doing anything if clientHelloMsg.raw is set"
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "foobar"}, HelloGolang)
	msg, _, _, err := uconn.makeClientHello()
	if err != nil {
		t.Errorf("Got error: %s; expected to succeed", err)
	}
	msg.original = []byte(str)
	marshalledHello, err := msg.marshal()
	if err != nil {
		t.Errorf("clientHelloMsg.marshal() returned error: %s", err.Error())
	}
	if strings.Compare(string(marshalledHello), str) != 0 {
		t.Errorf("clientHelloMsg.marshal() is not NOOP! Expected to get: %s, got: %s", str, string(marshalledHello))
	}
}

func TestUTLSMakeConnWithCompleteHandshake(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	masterSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47}
	clientRandom := []byte{40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71}
	serverRandom := []byte{80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111}
	serverTls := MakeConnWithCompleteHandshake(serverConn, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		masterSecret, clientRandom, serverRandom, false)
	clientTls := MakeConnWithCompleteHandshake(clientConn, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		masterSecret, clientRandom, serverRandom, true)

	clientMsg := []byte("Hello, world!")
	serverMsg := []byte("Test response!")

	go func() {
		clientTls.Write(clientMsg)
		resp := make([]byte, 20)
		read, err := clientTls.Read(resp)
		if !bytes.Equal(resp[:read], serverMsg) {
			t.Errorf("client expected to receive: %v, got %v\n",
				serverMsg, resp[:read])
		}
		if err != nil {
			t.Errorf("error reading client: %+v\n", err)
		}
		clientConn.Close()
	}()

	buf := make([]byte, 20)
	read, err := serverTls.Read(buf)
	if !bytes.Equal(buf[:read], clientMsg) {
		t.Errorf("server expected to receive: %v, got %v\n",
			clientMsg, buf[:read])
	}
	if err != nil {
		t.Errorf("error reading client: %+v\n", err)
	}

	serverTls.Write(serverMsg)
}

func TestUTLSECH(t *testing.T) {
	chromeLatest, err := UTLSIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}

	firefoxLatest, err := UTLSIdToSpec(HelloFirefox_Auto)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name          string
		spec          *ClientHelloSpec
		expectSuccess bool
	}{
		{
			name:          "latest chrome",
			spec:          &chromeLatest,
			expectSuccess: true,
		},
		{
			name:          "latest firefox",
			spec:          &firefoxLatest,
			expectSuccess: true,
		},
		{
			name: "ech extension missing",
			spec: &ClientHelloSpec{
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
					}},
					&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
					&UtlsGREASEExtension{},
				}),
			},
			expectSuccess: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			testECHSpec(t, test.spec, test.expectSuccess)
		})
	}
}

var spec *ClientHelloSpec = nil

func TestDowngradeCanaryUTLS(t *testing.T) {

	chromeLatest, err := UTLSIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Fatal(err)
	}

	firefoxLatest, err := UTLSIdToSpec(HelloFirefox_Auto)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name          string
		spec          *ClientHelloSpec
		expectSuccess bool
	}{
		{
			name:          "latest chrome",
			spec:          &chromeLatest,
			expectSuccess: true,
		},
		{
			name:          "latest firefox",
			spec:          &firefoxLatest,
			expectSuccess: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec = test.spec
			if err := testDowngradeCanary(t, VersionTLS13, VersionTLS12); err == nil {
				t.Errorf("downgrade from TLS 1.3 to TLS 1.2 was not detected")
			}
			if testing.Short() {
				t.Skip("skipping the rest of the checks in short mode")
			}
			if err := testDowngradeCanary(t, VersionTLS13, VersionTLS11); err == nil {
				t.Errorf("downgrade from TLS 1.3 to TLS 1.1 was not detected")
			}
			if err := testDowngradeCanary(t, VersionTLS13, VersionTLS10); err == nil {
				t.Errorf("downgrade from TLS 1.3 to TLS 1.0 was not detected")
			}
			if err := testDowngradeCanary(t, VersionTLS12, VersionTLS11); err == nil {
				t.Errorf("downgrade from TLS 1.2 to TLS 1.1 was not detected")
			}
			if err := testDowngradeCanary(t, VersionTLS12, VersionTLS10); err == nil {
				t.Errorf("downgrade from TLS 1.2 to TLS 1.0 was not detected")
			}
			spec = nil
		})

	}
}

// TestDuplicateExtensionDetection verifies that MarshalClientHelloNoECH rejects
// duplicate extension types, matching the behavior of the parsing side
// (handshake_messages.go) which rejects duplicates per RFC 8446.
func TestDuplicateExtensionDetection(t *testing.T) {
	tests := []struct {
		name        string
		extensions  []TLSExtension
		expectError bool
		errorSubstr string
	}{
		{
			name: "no duplicates - should succeed",
			extensions: []TLSExtension{
				&SNIExtension{ServerName: "example.com"},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
				&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			},
			expectError: false,
		},
		{
			name: "duplicate SNI extension - should fail",
			extensions: []TLSExtension{
				&SNIExtension{ServerName: "example.com"},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
				&SNIExtension{ServerName: "other.com"}, // duplicate
			},
			expectError: true,
			errorSubstr: "duplicate extension type",
		},
		{
			name: "duplicate SupportedCurves - should fail",
			extensions: []TLSExtension{
				&SupportedCurvesExtension{Curves: []CurveID{X25519}},
				&SNIExtension{ServerName: "example.com"},
				&SupportedCurvesExtension{Curves: []CurveID{CurveP256}}, // duplicate
			},
			expectError: true,
			errorSubstr: "duplicate extension type",
		},
		{
			name: "duplicate GenericExtension with same ID - should fail",
			extensions: []TLSExtension{
				&GenericExtension{Id: 0x1234, Data: []byte{1, 2, 3}},
				&SNIExtension{ServerName: "example.com"},
				&GenericExtension{Id: 0x1234, Data: []byte{4, 5, 6}}, // duplicate ID
			},
			expectError: true,
			errorSubstr: "duplicate extension type",
		},
		{
			name: "different GenericExtension IDs - should succeed",
			extensions: []TLSExtension{
				&GenericExtension{Id: 0x1234, Data: []byte{1, 2, 3}},
				&GenericExtension{Id: 0x5678, Data: []byte{4, 5, 6}},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ServerName: "example.com",
			}
			uconn := UClient(&net.TCPConn{}, config, HelloCustom)

			// Set extensions directly on UConn to bypass ApplyPreset validation
			// This tests MarshalClientHelloNoECH's duplicate detection specifically
			uconn.Extensions = tt.extensions
			uconn.HandshakeState.Hello.CipherSuites = []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			}
			uconn.HandshakeState.Hello.CompressionMethods = []byte{0x00}
			uconn.HandshakeState.Hello.Random = make([]byte, 32)
			uconn.HandshakeState.Hello.SessionId = make([]byte, 32)
			uconn.HandshakeState.Hello.Vers = VersionTLS12

			// Try to marshal the ClientHello
			err := uconn.MarshalClientHelloNoECH()

			if tt.expectError {
				if err == nil {
					t.Error("expected error for duplicate extensions, got nil")
				} else if tt.errorSubstr != "" && !strings.Contains(err.Error(), tt.errorSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errorSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
