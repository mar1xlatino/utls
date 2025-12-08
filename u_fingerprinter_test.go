// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"reflect"
	"testing"
)

func assertEquality(t *testing.T, fieldName string, expected, actual interface{}) {
	if kActual, ok := actual.(KeyShare); ok {
		kExpected := expected.(KeyShare)
		assertEquality(t, fieldName, kExpected.Group, kActual.Group)
		return
	}

	if fieldName == "SupportedCurves" || fieldName == "KeyShares" {
		cExpected := expected.(CurveID)
		cActual := actual.(CurveID)
		if isGREASEUint16(uint16(cExpected)) && isGREASEUint16(uint16(cActual)) {
			return
		}
	}

	if fieldName == "SupportedVersions" || fieldName == "CipherSuites" {
		cExpected := expected.(uint16)
		cActual := actual.(uint16)
		if isGREASEUint16(cExpected) && isGREASEUint16(cActual) {
			return
		}
	}

	if expected != actual {
		t.Errorf("%v fields not equal, expected: %v, got: %v", fieldName, expected, actual)
	}
}

func compareClientHelloFields(t *testing.T, fieldName string, expected, actual *PubClientHelloMsg) {
	rExpected := reflect.ValueOf(expected)
	if rExpected.Kind() != reflect.Ptr || rExpected.Elem().Kind() != reflect.Struct {
		t.Errorf("Error using reflect to compare Hello fields")
	}
	rActual := reflect.ValueOf(actual)
	if rActual.Kind() != reflect.Ptr || rActual.Elem().Kind() != reflect.Struct {
		t.Errorf("Error using reflect to compare Hello fields")
	}

	rExpected = rExpected.Elem()
	rActual = rActual.Elem()

	fExpected := rExpected.FieldByName(fieldName)
	fActual := rActual.FieldByName(fieldName)
	if !(fExpected.IsValid() && fActual.IsValid()) {
		t.Errorf("Error using reflect to lookup Hello field name: %v", fieldName)
	}

	if fExpected.Kind() == reflect.Slice {
		sExpected := fExpected.Slice(0, fExpected.Len())
		sActual := fActual.Slice(0, fActual.Len())

		if sExpected.Len() != sActual.Len() {
			t.Errorf("%v fields slice length not equal, expected: %v, got: %v", fieldName, fExpected, fActual)
		}

		for i := 0; i < sExpected.Len(); i++ {
			assertEquality(t, fieldName, sExpected.Index(i).Interface(), sActual.Index(i).Interface())
		}
	} else {
		assertEquality(t, fieldName, fExpected.Interface(), fActual.Interface())
	}
}

func checkUTLSExtensionsEquality(t *testing.T, expected, actual TLSExtension) {
	if expectedGrease, ok := expected.(*UtlsGREASEExtension); ok {
		if actualGrease, ok := actual.(*UtlsGREASEExtension); ok {
			if bytes.Equal(expectedGrease.Body, actualGrease.Body) {
				return
			}
		}
	}

	if expected.Len() != actual.Len() {
		t.Errorf("extension types length not equal\nexpected: %#v\ngot: %#v", expected, actual)
	}

	actualBytes, err := io.ReadAll(actual)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	expectedBytes, err := io.ReadAll(expected)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	logInequality := func() {
		t.Errorf("extensions not equal\nexpected: %#v\nbytes:%#x\ngot: %#v\nbytes: %#x", expected, expectedBytes, actual, actualBytes)
	}

	if !bytes.Equal(expectedBytes, actualBytes) {
		// handle all the cases where GREASE or other factors can cause byte unalignment

		// at this point concrete types must match
		expectedType := reflect.TypeOf(expected)
		actualType := reflect.TypeOf(actual)
		if expectedType != actualType {
			t.Errorf("extensions not equal\nexpected: %#v\nbytes:%#x\ngot: %#v\nbytes: %#x", expected, expectedBytes, actual, actualBytes)
			return
		}

		switch expectedExtension := expected.(type) {
		case *SupportedCurvesExtension:
			actualExtension := expected.(*SupportedCurvesExtension)
			for i, expectedCurve := range expectedExtension.Curves {
				actualCurve := actualExtension.Curves[i]
				if expectedCurve == actualCurve {
					continue
				}
				if isGREASEUint16(uint16(expectedCurve)) && isGREASEUint16(uint16(actualCurve)) {
					continue
				}
				logInequality()
				return
			}
		case *KeyShareExtension:
			actualExtension := expected.(*KeyShareExtension)
			for i, expectedKeyShare := range expectedExtension.KeyShares {
				actualKeyShare := actualExtension.KeyShares[i]
				// KeyShare data is unique per connection
				if actualKeyShare.Group == expectedKeyShare.Group {
					continue
				}
				if isGREASEUint16(uint16(expectedKeyShare.Group)) && isGREASEUint16(uint16(actualKeyShare.Group)) {
					continue
				}
				logInequality()
				return
			}
		case *SupportedVersionsExtension:
			actualExtension := expected.(*SupportedVersionsExtension)
			for i, expectedVersion := range expectedExtension.Versions {
				actualVersion := actualExtension.Versions[i]
				if isGREASEUint16(expectedVersion) && isGREASEUint16(actualVersion) || actualVersion == expectedVersion {
					continue
				}
				logInequality()
				return
			}
		default:
			logInequality()
			return
		}
	}
}

// Conn.vers is sometimes left to zero which is unacceptable to uTLS' SetTLSVers
// https://github.com/refraction-networking/utls/blob/f7e7360167ed2903ef12898634512b66f8c3aad0/u_conn.go#L564-L566
// https://github.com/refraction-networking/utls/blob/f7e7360167ed2903ef12898634512b66f8c3aad0/conn.go#L945-L948
func createMinTLSVersion(vers uint16) uint16 {
	if vers == 0 {
		return VersionTLS10
	}
	return vers
}

// prependRecordHeader prepends a record header to a handshake messsage
// if attempting to mimic an existing connection the minTLSVersion can be found
// in the Conn.vers field
func prependRecordHeader(hello []byte, minTLSVersion uint16) []byte {
	l := len(hello)
	if minTLSVersion == 0 {
		minTLSVersion = VersionTLS10
	}
	header := []byte{
		uint8(recordTypeHandshake),                                    // type
		uint8(minTLSVersion >> 8 & 0xff), uint8(minTLSVersion & 0xff), // record version is the minimum supported
		uint8(l >> 8 & 0xff), uint8(l & 0xff), // length
	}
	return append(header, hello...)
}

func checkUTLSFingerPrintClientHello(t *testing.T, clientHelloID ClientHelloID, serverName string) {
	uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, clientHelloID)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
		return
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	generatedUConn, err := UClient(&net.TCPConn{}, &Config{ServerName: "foobar"}, HelloCustom)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
		return
	}
	fingerprinter := &Fingerprinter{}
	minTLSVers := createMinTLSVersion(uconn.vers)
	generatedSpec, err := fingerprinter.FingerprintClientHello(prependRecordHeader(uconn.HandshakeState.Hello.Raw, minTLSVers))
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := generatedUConn.ApplyPreset(generatedSpec); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := generatedUConn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	if len(uconn.HandshakeState.Hello.Raw) != len(generatedUConn.HandshakeState.Hello.Raw) {
		t.Errorf("UConn from fingerprint has %d length, should have %d", len(generatedUConn.HandshakeState.Hello.Raw), len(uconn.HandshakeState.Hello.Raw))
	}

	// We can't effectively check the extensions on randomized or shuffled client hello ids
	// Chrome 106+ and Firefox 106+ shuffle extensions, so order comparison doesn't work
	isShuffled := clientHelloID == HelloRandomized || clientHelloID == HelloRandomizedALPN || clientHelloID == HelloRandomizedNoALPN ||
		clientHelloID == HelloChrome_120 || clientHelloID == HelloChrome_142 ||
		clientHelloID == HelloFirefox_120 || clientHelloID == HelloFirefox_145
	if !isShuffled && len(uconn.Extensions) == len(generatedUConn.Extensions) {
		for i, originalExtension := range uconn.Extensions {
			if _, ok := originalExtension.(*UtlsPaddingExtension); ok {
				// We can't really compare padding extensions in this way
				continue
			}

			generatedExtension := generatedUConn.Extensions[i]
			checkUTLSExtensionsEquality(t, originalExtension, generatedExtension)
		}
	}

	fieldsToTest := []string{
		"Vers", "CipherSuites", "CompressionMethods", "NextProtoNeg", "ServerName", "OcspStapling", "Scts", "SupportedCurves",
		"SupportedPoints", "TicketSupported", "SupportedSignatureAlgorithms", "SecureRenegotiation", "SecureRenegotiationSupported", "AlpnProtocols",
		"SupportedSignatureAlgorithmsCert", "SupportedVersions", "KeyShares", "EarlyData", "PskModes", "PskIdentities", "PskBinders",
	}

	for _, field := range fieldsToTest {
		compareClientHelloFields(t, field, uconn.HandshakeState.Hello, generatedUConn.HandshakeState.Hello)
	}
}

func TestUTLSFingerprintClientHello(t *testing.T) {
	clientHellosToTest := []ClientHelloID{
		HelloChrome_120, HelloChrome_142, HelloFirefox_120, HelloFirefox_145, HelloIOS_18, HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN}

	serverNames := []string{"foobar"}

	for _, clientHello := range clientHellosToTest {
		for _, serverName := range serverNames {
			t.Logf("checking fingerprint generated client hello spec against %v and server name: %v", clientHello, serverName)
			checkUTLSFingerPrintClientHello(t, clientHello, "foobar")
		}
	}
}

func TestUTLSFingerprintClientHelloBluntMimicry(t *testing.T) {
	serverName := "foobar"
	var extensionId uint16 = 0xfeed
	extensionData := []byte("random data")

	specWithGeneric, err := UTLSIdToSpec(HelloChrome_Auto)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	specWithGeneric.Extensions = append(specWithGeneric.Extensions, &GenericExtension{extensionId, extensionData})

	uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
		return
	}

	if err := uconn.ApplyPreset(&specWithGeneric); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	f := &Fingerprinter{}
	minTLSVers := createMinTLSVersion(uconn.vers)
	_, err = f.FingerprintClientHello(prependRecordHeader(uconn.HandshakeState.Hello.Raw, minTLSVers))
	if err == nil {
		t.Errorf("expected error generating spec from client hello with GenericExtension")
	}

	f = &Fingerprinter{AllowBluntMimicry: true}
	generatedSpec, err := f.FingerprintClientHello(prependRecordHeader(uconn.HandshakeState.Hello.Raw, minTLSVers))
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	for _, ext := range generatedSpec.Extensions {
		if genericExtension, ok := (ext).(*GenericExtension); ok {
			if genericExtension.Id == extensionId && bytes.Equal(genericExtension.Data, extensionData) {
				return
			}
		}
	}
	t.Errorf("generated ClientHelloSpec with BluntMimicry did not correctly carry over generic extension")
}

func TestUTLSFingerprintClientHelloAlwaysAddPadding(t *testing.T) {
	serverName := "foobar"

	// Create a custom spec without padding
	specWithoutPadding := ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
				PKCS1WithSHA256,
			}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
		},
	}

	// Get a spec with padding from Chrome
	specWithPadding, err := UTLSIdToSpec(HelloChrome_120)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	uconnWithoutPadding, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}
	uconnWithPadding, err := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, HelloCustom)
	if err != nil {
		t.Fatalf("UClient failed: %v", err)
	}

	if err := uconnWithoutPadding.ApplyPreset(&specWithoutPadding); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := uconnWithoutPadding.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	if err := uconnWithPadding.ApplyPreset(&specWithPadding); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := uconnWithPadding.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	f := &Fingerprinter{}
	minTLSVersWithoutPadding := createMinTLSVersion(uconnWithoutPadding.vers)
	fingerprintedWithoutPadding, err := f.FingerprintClientHello(prependRecordHeader(uconnWithoutPadding.HandshakeState.Hello.Raw, minTLSVersWithoutPadding))
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	for _, ext := range fingerprintedWithoutPadding.Extensions {
		if _, ok := ext.(*UtlsPaddingExtension); ok {
			t.Errorf("padding extension should not be present on fingerprinted ClientHelloSpec without AlwaysAddPadding set")
			break
		}
	}

	f = &Fingerprinter{AlwaysAddPadding: true}
	generatedSpec, err := f.FingerprintClientHello(prependRecordHeader(uconnWithoutPadding.HandshakeState.Hello.Raw, minTLSVersWithoutPadding))
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	hasPadding := false
	for _, ext := range generatedSpec.Extensions {
		if _, ok := ext.(*UtlsPaddingExtension); ok {
			hasPadding = true
			break
		}
	}
	if !hasPadding {
		t.Errorf("expected padding extension on fingerprinted ClientHelloSpec with AlwaysAddPadding set")
	}

	f = &Fingerprinter{AlwaysAddPadding: true}
	minTLSVersWithPadding := createMinTLSVersion(uconnWithPadding.vers)
	generatedSpec, err = f.FingerprintClientHello(prependRecordHeader(uconnWithPadding.HandshakeState.Hello.Raw, minTLSVersWithPadding))
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	hasPadding = false
	for _, ext := range generatedSpec.Extensions {
		if _, ok := ext.(*UtlsPaddingExtension); ok {
			if hasPadding {
				t.Errorf("found double padding extension on fingerprinted ClientHelloSpec with AlwaysAddPadding set")
			}

			hasPadding = true
		}
	}
	if !hasPadding {
		t.Errorf("expected padding extension on fingerprinted ClientHelloSpec with AlwaysAddPadding set")
	}
}

func TestUTLSFingerprintClientHelloKeepPSK(t *testing.T) {
	// TLSv1.3 Record Layer: Handshake Protocol: Client Hello
	//     Content Type: Handshake (22)
	//     Version: TLS 1.0 (0x0301)
	//     Length: 576
	// Handshake Protocol: Client Hello
	// 		Handshake Type: Client Hello (1)
	// 		Length: 572
	// 		Version: TLS 1.2 (0x0303)
	// 		Random: 5cef5aa9122008e37f0f74d717cd4ae0f745daba4292e6fb…
	// 		Session ID Length: 32
	// 		Session ID: 8c4aa23444084eeb70097efe0b8f6e3a56c717abd67505c9…
	// 		Cipher Suites Length: 32
	// 		Cipher Suites (16 suites)
	// 		Compression Methods Length: 1
	// 		Compression Methods (1 method)
	// 		Extensions Length: 467
	// 		Extension: Reserved (GREASE) (len=0)
	// 				Type: Reserved (GREASE) (14906)
	// 				Length: 0
	// 				Data: <MISSING>
	// 		Extension: server_name (len=22)
	// 				Type: server_name (0)
	// 				Length: 22
	// 				Server Name Indication extension
	// 						Server Name list length: 20
	// 						Server Name Type: host_name (0)
	// 						Server Name length: 17
	// 						Server Name: edgeapi.slack.com
	// 		Extension: extended_master_secret (len=0)
	// 				Type: extended_master_secret (23)
	// 				Length: 0
	// 		Extension: renegotiation_info (len=1)
	// 				Type: renegotiation_info (65281)
	// 				Length: 1
	// 				Renegotiation Info extension
	// 						Renegotiation info extension length: 0
	// 		Extension: supported_groups (len=10)
	// 				Type: supported_groups (10)
	// 				Length: 10
	// 				Supported Groups List Length: 8
	// 				Supported Groups (4 groups)
	// 						Supported Group: Reserved (GREASE) (0xdada)
	// 						Supported Group: x25519 (0x001d)
	// 						Supported Group: secp256r1 (0x0017)
	// 						Supported Group: secp384r1 (0x0018)
	// 		Extension: ec_point_formats (len=2)
	// 				Type: ec_point_formats (11)
	// 				Length: 2
	// 				EC point formats Length: 1
	// 				Elliptic curves point formats (1)
	// 		Extension: session_ticket (len=0)
	// 				Type: session_ticket (35)
	// 				Length: 0
	// 				Data (0 bytes)
	// 		Extension: application_layer_protocol_negotiation (len=14)
	// 				Type: application_layer_protocol_negotiation (16)
	// 				Length: 14
	// 				ALPN Extension Length: 12
	// 				ALPN Protocol
	// 						ALPN string length: 2
	// 						ALPN Next Protocol: h2
	// 						ALPN string length: 8
	// 						ALPN Next Protocol: http/1.1
	// 		Extension: status_request (len=5)
	// 				Type: status_request (5)
	// 				Length: 5
	// 				Certificate Status Type: OCSP (1)
	// 				Responder ID list Length: 0
	// 				Request Extensions Length: 0
	// 		Extension: signature_algorithms (len=18)
	// 				Type: signature_algorithms (13)
	// 				Length: 18
	// 				Signature Hash Algorithms Length: 16
	// 				Signature Hash Algorithms (8 algorithms)
	// 		Extension: signed_certificate_timestamp (len=0)
	// 				Type: signed_certificate_timestamp (18)
	// 				Length: 0
	// 		Extension: key_share (len=43)
	// 				Type: key_share (51)
	// 				Length: 43
	// 				Key Share extension
	// 						Client Key Share Length: 41
	// 						Key Share Entry: Group: Reserved (GREASE), Key Exchange length: 1
	// 								Group: Reserved (GREASE) (56026)
	// 								Key Exchange Length: 1
	// 								Key Exchange: 00
	// 						Key Share Entry: Group: x25519, Key Exchange length: 32
	// 								Group: x25519 (29)
	// 								Key Exchange Length: 32
	// 								Key Exchange: e35e636d4e2dcd5f39309170285dab92dbe81fefe4926826…
	// 		Extension: psk_key_exchange_modes (len=2)
	// 				Type: psk_key_exchange_modes (45)
	// 				Length: 2
	// 				PSK Key Exchange Modes Length: 1
	// 				PSK Key Exchange Mode: PSK with (EC)DHE key establishment (psk_dhe_ke) (1)
	// 		Extension: supported_versions (len=11)
	// 				Type: supported_versions (43)
	// 				Length: 11
	// 				Supported Versions length: 10
	// 				Supported Version: Unknown (0x2a2a)
	// 				Supported Version: TLS 1.3 (0x0304)
	// 				Supported Version: TLS 1.2 (0x0303)
	// 				Supported Version: TLS 1.1 (0x0302)
	// 				Supported Version: TLS 1.0 (0x0301)
	// 		Extension: compress_certificate (len=3)
	// 				Type: compress_certificate (27)
	// 				Length: 3
	// 				Algorithms Length: 2
	// 				Algorithm: brotli (2)
	// 		Extension: Reserved (GREASE) (len=1)
	// 				Type: Reserved (GREASE) (19018)
	// 				Length: 1
	// 				Data: 00
	// 		Extension: pre_shared_key (len=267)
	// 				Type: pre_shared_key (41)
	// 				Length: 267
	// 				Pre-Shared Key extension

	byteString := []byte("16030102400100023c03035cef5aa9122008e37f0f74d717cd4ae0f745daba4292e6fbca3cd5bf9123498f208c4aa23444084eeb70097efe0b8f6e3a56c717abd67505c950aab314de59bd8f00204a4a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010001d33a3a0000000000160014000011656467656170692e736c61636b2e636f6d00170000ff01000100000a000a0008dada001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0012001004030804040105030805050108060601001200000033002b0029dada000100001d0020e35e636d4e2dcd5f39309170285dab92dbe81fefe4926826cec1ef881321687e002d00020101002b000b0a2a2a0304030303020301001b00030200024a4a0001000029010b00e600e017fab59672c1966ae78fc4dacd7efb42e735de956e3f96d342bb8e63a5233ce21c92d6d75036601d74ccbc3ca0085f3ac2ebbd83da13501ac3c6d612bcb453fb206a39a8112d768bea1976d7c14e6de9aa0ee70ea732554d3c57d1a993f1044a46c1fb371811039ef30582cacf41bd497121d67793b8ee4df7a60d525f7df052fd66cda7f141bb553d9253816752d923ac7c71426179db4f26a7d42f0d65a2dd2dbaafb86fa17b2da23fd57c5064c76551cfda86304051231e4da9e697fedbcb5ae8cb2f6cb92f71164acf2edff5bccc1266cd648a53cc46262eabf40727bcb6958a3d1300212083e99d791672d39919dcb387f2fa7aeee938ec32ecf4b861306f7df4f9a8a746")

	helloBytes := make([]byte, hex.DecodedLen(len(byteString)))
	_, err := hex.Decode(helloBytes, byteString)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
		return
	}

	f := &Fingerprinter{}
	generatedSpec, err := f.FingerprintClientHello(helloBytes)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
		return
	}

	for _, ext := range generatedSpec.Extensions {
		if _, ok := (ext).(*FakePreSharedKeyExtension); ok {
			return
		}
	}
	t.Errorf("generated ClientHelloSpec with KeepPSK does not include preshared key extension")
}


// FingerprintClientHello should work when the dump contains the client's greeting and subsequent frames.
// Lack of subsequent frames should not lead to inoperability of FingerprintClientHello.
func TestFingerprintDumpLargerThanExtensions(t *testing.T) {
	// Dump of curl/7.74.0 with some test request https://tlsfingerprint.io/id/37695dd988f0c8b8
	dump := "1603010200010001fc03032e763fe74cd8472de77d17eef1cf4cb9b18d0163196a69337d0d7c6c844a1b71202aef889ccf5bdef725185b7c0cc51a100311c7c3992b1d206beaef121a111cc5003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010001750000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018337400000010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d00204f21193633f4a0c751143f0084941995cc6fb7cb87545f56f07877c99615f074001500be000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001403030001011703030045f621cd4a3c52c89e0d94c6f6a79d5863274af09696811cb73c433aa05ea5bb7a266cbc11cdbd18a553c9b4ba02c202ec709faabfdd9e9b76c1b2162dd8296cdbc9e6451742170303005ff37ae5fd6c2f240472c6248abb2a82dd2e634d4da4f67d0db94cf56eebe7e9e3766f6458f87c82bdd70a4d75e0f904c368a7c57beba6d76ea9d3f6d06e26cdf1dcb4c6fa2067f269268e91e94ade464efdb2e5f5cf2f7930faeb6f2a4a3bc2"
	// shortDump := "1603010200010001fc03032e763fe74cd8472de77d17eef1cf4cb9b18d0163196a69337d0d7c6c844a1b71202aef889ccf5bdef725185b7c0cc51a100311c7c3992b1d206beaef121a111cc5003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010001750000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018337400000010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d00204f21193633f4a0c751143f0084941995cc6fb7cb87545f56f07877c99615f074001500be00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	helloBytes, err := hex.DecodeString(dump)
	if err != nil {
		t.Error(err)
		return
	}
	f := &Fingerprinter{
		AllowBluntMimicry: true,
	}
	clientHelloSpec, err := f.FingerprintClientHello(helloBytes)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if clientHelloSpec == nil {
		t.Error("clientHelloSpec cannot be nil")
	}
}
