// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Fuzz tests for TLS message parsing.
//
// CI Usage:
//   - go test -run='Fuzz' -v           # Run seed corpus only (fast, default in CI)
//   - go test -run='TestFuzz' -v       # Run wrapper tests with seed corpus
//   - go test -short -run='Fuzz'       # Skip fuzz tests entirely
//
// Local Fuzzing (not for CI):
//   - go test -fuzz=FuzzParseClientHello -fuzztime=30s  # Fuzz for 30 seconds
//   - go test -fuzz=. -fuzztime=1m                       # Fuzz all targets for 1 minute
//
// The seed corpus is defined inline via f.Add() calls. Crash inputs are stored
// in testdata/fuzz/<FuzzTestName>/ automatically by Go's fuzzing infrastructure.

package tls

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/refraction-networking/utls/internal/quicvarint"
)

// skipFuzzInShortMode skips fuzz tests if -short flag is set.
// Fuzz tests are fast (seed corpus only takes ~77ms total) but can be
// skipped in short mode if the test suite needs to be even faster.
func skipFuzzInShortMode(t testing.TB) {
	if testing.Short() {
		t.Skip("skipping fuzz test in short mode")
	}
}

// FuzzParseClientHello tests the clientHelloMsg.unmarshal function for panics
// and crashes when processing arbitrary input data.
//
// The ClientHello parser is a critical attack surface as it processes untrusted
// data from network clients. This fuzz test ensures the parser handles malformed
// input gracefully without panicking.
func FuzzParseClientHello(f *testing.F) {
	skipFuzzInShortMode(f)

	// Seed corpus: minimal valid ClientHello structure
	// Format: [1 byte type][3 bytes length][2 bytes version][32 bytes random][1 byte session_id_len][2 bytes cipher_suites_len][1 byte compression_len]
	minimalClientHello := []byte{
		0x01,             // handshake type: ClientHello
		0x00, 0x00, 0x26, // length: 38 bytes
		0x03, 0x03, // version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // session_id length: 0
		0x00, 0x02, // cipher_suites length: 2
		0x00, 0x2f, // cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
		0x01, // compression_methods length: 1
		0x00, // compression method: null
	}
	f.Add(minimalClientHello)

	// Add a ClientHello with extensions
	clientHelloWithExtensions := []byte{
		0x01,             // handshake type: ClientHello
		0x00, 0x00, 0x33, // length: 51 bytes
		0x03, 0x03, // version: TLS 1.2
		// 32 bytes random
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		0x00,       // session_id length: 0
		0x00, 0x02, // cipher_suites length: 2
		0x13, 0x01, // cipher suite: TLS_AES_128_GCM_SHA256
		0x01,       // compression_methods length: 1
		0x00,       // compression method: null
		0x00, 0x09, // extensions length: 9
		0x00, 0x00, // extension type: server_name
		0x00, 0x05, // extension length: 5
		0x00, 0x03, // server_name_list length: 3
		0x00,       // name_type: host_name
		0x00, 0x00, // host_name length: 0 (invalid but tests edge case)
	}
	f.Add(clientHelloWithExtensions)

	// Empty input
	f.Add([]byte{})

	// Too short inputs
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x00})
	f.Add([]byte{0x01, 0x00, 0x00})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})

	// Input with maximum length field
	f.Add([]byte{0x01, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during ClientHello parsing: %v\nInput: %x", r, data)
			}
		}()

		msg := &clientHelloMsg{}
		// We don't care about the return value - we only care that it doesn't panic
		msg.unmarshal(data)
	})
}

// FuzzParseServerHello tests the serverHelloMsg.unmarshal function for panics
// and crashes when processing arbitrary input data.
//
// The ServerHello parser processes data from servers during TLS handshakes.
// While typically server data is more trusted, a malicious or buggy server
// could send malformed ServerHello messages that should not crash the client.
func FuzzParseServerHello(f *testing.F) {
	skipFuzzInShortMode(f)

	// Seed corpus: minimal valid ServerHello structure
	// Format: [1 byte type][3 bytes length][2 bytes version][32 bytes random][1 byte session_id_len][2 bytes cipher_suite][1 byte compression]
	minimalServerHello := []byte{
		0x02,             // handshake type: ServerHello
		0x00, 0x00, 0x26, // length: 38 bytes
		0x03, 0x03, // version: TLS 1.2
		// 32 bytes random
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00,       // session_id length: 0
		0x00, 0x2f, // cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, // compression method: null
	}
	f.Add(minimalServerHello)

	// ServerHello with extensions
	serverHelloWithExtensions := []byte{
		0x02,             // handshake type: ServerHello
		0x00, 0x00, 0x30, // length: 48 bytes
		0x03, 0x03, // version: TLS 1.2
		// 32 bytes random
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0x00,       // session_id length: 0
		0x13, 0x01, // cipher suite: TLS_AES_128_GCM_SHA256
		0x00,       // compression method: null
		0x00, 0x06, // extensions length: 6
		0x00, 0x2b, // extension type: supported_versions
		0x00, 0x02, // extension length: 2
		0x03, 0x04, // TLS 1.3
	}
	f.Add(serverHelloWithExtensions)

	// TLS 1.3 HelloRetryRequest (special random value)
	helloRetryRequest := []byte{
		0x02,             // handshake type: ServerHello
		0x00, 0x00, 0x30, // length: 48 bytes
		0x03, 0x03, // version: TLS 1.2 (legacy)
		// 32 bytes: HelloRetryRequest magic random
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
		0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
		0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
		0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
		0x00,       // session_id length: 0
		0x13, 0x01, // cipher suite: TLS_AES_128_GCM_SHA256
		0x00,       // compression method: null
		0x00, 0x06, // extensions length: 6
		0x00, 0x2b, // extension type: supported_versions
		0x00, 0x02, // extension length: 2
		0x03, 0x04, // TLS 1.3
	}
	f.Add(helloRetryRequest)

	// Empty input
	f.Add([]byte{})

	// Too short inputs
	f.Add([]byte{0x02})
	f.Add([]byte{0x02, 0x00})
	f.Add([]byte{0x02, 0x00, 0x00})
	f.Add([]byte{0x02, 0x00, 0x00, 0x00})

	// Input with maximum length field
	f.Add([]byte{0x02, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during ServerHello parsing: %v\nInput: %x", r, data)
			}
		}()

		msg := &serverHelloMsg{}
		// We don't care about the return value - we only care that it doesn't panic
		msg.unmarshal(data)
	})
}

// FuzzParseECHConfig tests the parseECHConfig function for panics and crashes
// when processing arbitrary input data.
//
// ECH (Encrypted Client Hello) configuration parsing is particularly security-sensitive
// as it processes externally-provided cryptographic configuration data. Malformed
// ECH configs could be used to attack clients attempting to establish private connections.
func FuzzParseECHConfig(f *testing.F) {
	skipFuzzInShortMode(f)

	// Seed corpus from actual test data
	// Valid Cloudflare ECH config
	cloudflareConfig, _ := hex.DecodeString("fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000")
	f.Add(cloudflareConfig)

	// Valid ECH config with X25519 KEM
	x25519Config, _ := hex.DecodeString("fe0d003d00002000207d661615730214aeee70533366f36a609ead65c0c208e62322346ab5bcd8de1c000411112222400e7075626c69632e6578616d706c650000")
	f.Add(x25519Config)

	// ECH config with extensions
	configWithExtensions, _ := hex.DecodeString("fe0d004d000020002085bd6a03277c25427b52e269e0c77a8eb524ba1eb3d2f132662d4b0ac6cb7357000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374")
	f.Add(configWithExtensions)

	// Minimal ECH config structure
	minimalECHConfig := []byte{
		0xfe, 0x0d, // version: ECH draft
		0x00, 0x25, // length: 37 bytes
		0x00,       // config_id
		0x00, 0x20, // kem_id: X25519 (0x0020)
		0x00, 0x20, // public_key length: 32
		// 32 bytes public key (all zeros for testing)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x04, // cipher_suites length: 4
		0x00, 0x01, // kdf_id: HKDF-SHA256
		0x00, 0x01, // aead_id: AES-128-GCM
		0x00,       // max_name_length
		0x00,       // public_name length: 0
		0x00, 0x00, // extensions length: 0
	}
	f.Add(minimalECHConfig)

	// Unknown version (should be skipped)
	unknownVersionConfig := []byte{
		0xba, 0xdd, // unknown version
		0x00, 0x05, // length: 5
		0x05, 0x04, 0x03, 0x02, 0x01, // payload
	}
	f.Add(unknownVersionConfig)

	// Empty input
	f.Add([]byte{})

	// Too short inputs
	f.Add([]byte{0xfe})
	f.Add([]byte{0xfe, 0x0d})
	f.Add([]byte{0xfe, 0x0d, 0x00})
	f.Add([]byte{0xfe, 0x0d, 0x00, 0x00})

	// Input with maximum length field
	f.Add([]byte{0xfe, 0x0d, 0xff, 0xff})

	// Config with empty public key (should error)
	emptyPubKeyConfig := []byte{
		0xfe, 0x0d, // version: ECH draft
		0x00, 0x0a, // length
		0x00,       // config_id
		0x00, 0x20, // kem_id: X25519
		0x00, 0x00, // public_key length: 0 (invalid)
		0x00, 0x00, // cipher_suites length: 0
		0x00,       // max_name_length
		0x00,       // public_name length: 0
		0x00, 0x00, // extensions length: 0
	}
	f.Add(emptyPubKeyConfig)

	// Config with wrong public key length for X25519
	wrongPubKeyLen := []byte{
		0xfe, 0x0d, // version: ECH draft
		0x00, 0x10, // length
		0x00,       // config_id
		0x00, 0x20, // kem_id: X25519
		0x00, 0x10, // public_key length: 16 (invalid for X25519)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, // cipher_suites length: 0
		0x00,       // max_name_length
		0x00,       // public_name length: 0
		0x00, 0x00, // extensions length: 0
	}
	f.Add(wrongPubKeyLen)

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during ECHConfig parsing: %v\nInput: %x", r, data)
			}
		}()

		// We don't care about the return values - we only care that it doesn't panic
		parseECHConfig(data)
	})
}

// FuzzParseECHConfigList tests the parseECHConfigList function for panics
// when processing arbitrary ECH config list data.
//
// ECH config lists contain multiple ECH configurations and are typically
// retrieved from DNS HTTPS records. This is an additional attack surface
// that should be robust against malformed input.
func FuzzParseECHConfigList(f *testing.F) {
	skipFuzzInShortMode(f)

	// Valid single-config list from Cloudflare
	singleConfigList, _ := hex.DecodeString("0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000")
	f.Add(singleConfigList)

	// Valid multi-config list
	multiConfigList, _ := hex.DecodeString("0105badd00050504030201fe0d0066000010004104e62b69e2bf659f97be2f1e0d948a4cd5976bb7a91e0d46fbdda9a91e9ddcba5a01e7d697a80a18f9c3c4a31e56e27c8348db161a1cf51d7ef1942d4bcf7222c1000c000100010001000200010003400e7075626c69632e6578616d706c650000fe0d003d00002000207d661615730214aeee70533366f36a609ead65c0c208e62322346ab5bcd8de1c000411112222400e7075626c69632e6578616d706c650000fe0d004d000020002085bd6a03277c25427b52e269e0c77a8eb524ba1eb3d2f132662d4b0ac6cb7357000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374")
	f.Add(multiConfigList)

	// List with configs to skip (unknown versions)
	listWithSkips, _ := hex.DecodeString("00c8badd00050504030201fe0d0029006666000401020304000c000100010001000200010003400e7075626c69632e6578616d706c650000fe0d003d000020002072e8a23b7aef67832bcc89d652e3870a60f88ca684ec65d6eace6b61f136064c000411112222400e7075626c69632e6578616d706c650000fe0d004d00002000200ce95810a81d8023f41e83679bc92701b2acd46c75869f95c72bc61c6b12297c000c000100010001000200010003400e7075626c69632e6578616d706c650008aaaa000474657374")
	f.Add(listWithSkips)

	// Empty list
	f.Add([]byte{})

	// Just length bytes
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x01})

	// Length mismatch
	f.Add([]byte{0xff, 0xff})

	// Too short
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during ECHConfigList parsing: %v\nInput: %x", r, data)
			}
		}()

		// We don't care about the return values - we only care that it doesn't panic
		parseECHConfigList(data)
	})
}

// FuzzParseSessionState tests the ParseSessionState function for panics
// when processing arbitrary session state data.
//
// Session state parsing is critical for TLS session resumption. Malformed
// session states could be used to attack clients or servers attempting to
// resume sessions, potentially leading to denial of service or information
// disclosure.
func FuzzParseSessionState(f *testing.F) {
	skipFuzzInShortMode(f)

	// Minimal valid session state structure
	// Based on SessionState.Bytes() encoding
	minimalSessionState := []byte{
		0x03, 0x03, // version: TLS 1.2
		0x01,       // type: 1 (resumption)
		0x00, 0x2f, // cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // createdAt: 8 bytes
		0x20, // secret length: 32
		// 32 bytes secret
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, // extra length: 0 (3 bytes)
		0x01, // extMasterSecret: true
		0x00, // earlyData: false
		// Empty certificate chain
		0x00, 0x00, 0x00, // certificate list length: 0
		0x00, 0x00, 0x00, // chain list length: 0
	}
	f.Add(minimalSessionState)

	// Session state with TLS 1.3
	tls13SessionState := []byte{
		0x03, 0x04, // version: TLS 1.3
		0x02,       // type: 2 (PSK)
		0x13, 0x01, // cipher suite: TLS_AES_128_GCM_SHA256
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // createdAt
		0x30, // secret length: 48
		// 48 bytes secret
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x00, 0x00, 0x00, // extra length: 0
		0x01, // extMasterSecret: true
		0x01, // earlyData: true
		0x00, 0x00, 0x00, // certificate list length: 0
		0x00, 0x00, 0x00, // chain list length: 0
	}
	f.Add(tls13SessionState)

	// Empty input
	f.Add([]byte{})

	// Too short inputs
	f.Add([]byte{0x03})
	f.Add([]byte{0x03, 0x03})
	f.Add([]byte{0x03, 0x03, 0x01})

	// Invalid type field
	f.Add([]byte{0x03, 0x03, 0x00, 0x00, 0x2f})
	f.Add([]byte{0x03, 0x03, 0x03, 0x00, 0x2f})

	// Maximum length secret claim
	f.Add([]byte{
		0x03, 0x03, 0x01, 0x00, 0x2f,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, // secret length: 255 (larger than available)
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during SessionState parsing: %v\nInput: %x", r, data)
			}
		}()

		// We don't care about the return values - we only care that it doesn't panic
		ParseSessionState(data)
	})
}

// FuzzQUICVarint tests the QUIC variable-length integer parser for panics
// when processing arbitrary input data.
//
// QUIC varints are used throughout the QUIC protocol and in QUIC-based TLS.
// The parser must handle all possible input gracefully, including truncated
// data, non-minimal encodings, and maximum values.
func FuzzQUICVarint(f *testing.F) {
	skipFuzzInShortMode(f)

	// Single byte values (0-63)
	f.Add([]byte{0x00})
	f.Add([]byte{0x3f})

	// Two byte values (64-16383)
	f.Add([]byte{0x40, 0x40}) // 64 (minimal)
	f.Add([]byte{0x7f, 0xff}) // 16383 (max 2-byte)

	// Four byte values (16384-1073741823)
	f.Add([]byte{0x80, 0x00, 0x40, 0x00}) // 16384 (minimal)
	f.Add([]byte{0xbf, 0xff, 0xff, 0xff}) // 1073741823 (max 4-byte)

	// Eight byte values (1073741824-4611686018427387903)
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}) // 1073741824 (minimal)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // max value

	// Non-minimal encodings (should error with ErrNonMinimalEncoding)
	f.Add([]byte{0x40, 0x00}) // 0 encoded as 2 bytes
	f.Add([]byte{0x40, 0x3f}) // 63 encoded as 2 bytes
	f.Add([]byte{0x80, 0x00, 0x00, 0x00}) // 0 encoded as 4 bytes
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // 0 encoded as 8 bytes

	// Empty input
	f.Add([]byte{})

	// Truncated inputs
	f.Add([]byte{0x40})       // 2-byte encoding, only 1 byte
	f.Add([]byte{0x80, 0x00}) // 4-byte encoding, only 2 bytes
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00}) // 8-byte encoding, only 4 bytes

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during QUIC varint parsing: %v\nInput: %x", r, data)
			}
		}()

		// Test both strict and lenient readers
		quicvarint.Read(bytes.NewReader(data))
		quicvarint.ReadLenient(bytes.NewReader(data))
	})
}

// FuzzCertificateMsgTLS13 tests the certificateMsgTLS13.unmarshal function
// for panics when processing arbitrary certificate message data.
//
// Certificate message parsing is a critical attack surface as it processes
// potentially untrusted certificate chains. Malformed certificate messages
// could be used to attack TLS clients or servers, potentially leading to
// memory corruption or denial of service.
func FuzzCertificateMsgTLS13(f *testing.F) {
	skipFuzzInShortMode(f)

	// Minimal valid certificate message (empty certificate chain)
	minimalCertMsg := []byte{
		0x0b,             // handshake type: Certificate
		0x00, 0x00, 0x04, // length: 4 bytes
		0x00,             // certificate_request_context length: 0
		0x00, 0x00, 0x00, // certificate list length: 0
	}
	f.Add(minimalCertMsg)

	// Certificate message with a small dummy certificate
	certMsgWithCert := []byte{
		0x0b,             // handshake type: Certificate
		0x00, 0x00, 0x12, // length: 18 bytes
		0x00,             // certificate_request_context length: 0
		0x00, 0x00, 0x0e, // certificate list length: 14
		0x00, 0x00, 0x07, // cert entry length: 7
		0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00, // dummy ASN.1 DER cert
		0x00, 0x00, // extensions length: 0
	}
	f.Add(certMsgWithCert)

	// Certificate message with OCSP stapling extension
	certMsgWithOCSP := []byte{
		0x0b,             // handshake type: Certificate
		0x00, 0x00, 0x1b, // length: 27 bytes
		0x00,             // certificate_request_context length: 0
		0x00, 0x00, 0x17, // certificate list length: 23
		0x00, 0x00, 0x07, // cert entry length: 7
		0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00, // dummy ASN.1 DER cert
		0x00, 0x09, // extensions length: 9
		0x00, 0x05, // extension type: status_request
		0x00, 0x05, // extension length: 5
		0x01,       // status_type: ocsp
		0x00, 0x00, 0x01, // OCSP response length: 1
		0xaa, // dummy OCSP response
	}
	f.Add(certMsgWithOCSP)

	// Certificate message with SCT extension
	certMsgWithSCT := []byte{
		0x0b,             // handshake type: Certificate
		0x00, 0x00, 0x1d, // length: 29 bytes
		0x00,             // certificate_request_context length: 0
		0x00, 0x00, 0x19, // certificate list length: 25
		0x00, 0x00, 0x07, // cert entry length: 7
		0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00, // dummy ASN.1 DER cert
		0x00, 0x0b, // extensions length: 11
		0x00, 0x12, // extension type: signed_certificate_timestamp
		0x00, 0x07, // extension length: 7
		0x00, 0x05, // SCT list length: 5
		0x00, 0x03, // SCT entry length: 3
		0xaa, 0xbb, 0xcc, // dummy SCT
	}
	f.Add(certMsgWithSCT)

	// Empty input
	f.Add([]byte{})

	// Too short inputs
	f.Add([]byte{0x0b})
	f.Add([]byte{0x0b, 0x00})
	f.Add([]byte{0x0b, 0x00, 0x00})
	f.Add([]byte{0x0b, 0x00, 0x00, 0x00})

	// Certificate context not empty (should fail)
	f.Add([]byte{
		0x0b,
		0x00, 0x00, 0x06,
		0x01, 0xaa, // context length: 1, context: 0xaa
		0x00, 0x00, 0x00,
	})

	// Maximum length claims
	f.Add([]byte{0x0b, 0xff, 0xff, 0xff})

	// Truncated certificate entry
	f.Add([]byte{
		0x0b,
		0x00, 0x00, 0x07,
		0x00,
		0x00, 0x00, 0x03,
		0xff, 0xff, 0xff, // length claims 0xffffff bytes
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during CertificateMsgTLS13 parsing: %v\nInput: %x", r, data)
			}
		}()

		msg := &certificateMsgTLS13{}
		// We don't care about the return value - we only care that it doesn't panic
		msg.unmarshal(data)
	})
}

// FuzzNewSessionTicketMsgTLS13 tests the newSessionTicketMsgTLS13.unmarshal
// function for panics when processing arbitrary session ticket data.
//
// Session tickets are sent by servers and stored by clients for session
// resumption. A malicious server could send malformed session tickets to
// attack clients, potentially causing crashes or memory corruption.
func FuzzNewSessionTicketMsgTLS13(f *testing.F) {
	skipFuzzInShortMode(f)

	// Minimal valid session ticket message
	minimalTicket := []byte{
		0x04,             // handshake type: NewSessionTicket
		0x00, 0x00, 0x0c, // length: 12 bytes
		0x00, 0x00, 0x0e, 0x10, // ticket_lifetime: 3600 seconds
		0x00, 0x00, 0x00, 0x01, // ticket_age_add: 1
		0x00,             // ticket_nonce length: 0
		0x00, 0x01,       // ticket length: 1
		0xaa,             // ticket data
		0x00, 0x00,       // extensions length: 0
	}
	f.Add(minimalTicket)

	// Session ticket with early data extension
	ticketWithEarlyData := []byte{
		0x04,             // handshake type: NewSessionTicket
		0x00, 0x00, 0x16, // length: 22 bytes
		0x00, 0x01, 0x51, 0x80, // ticket_lifetime: 86400 seconds
		0xab, 0xcd, 0xef, 0x12, // ticket_age_add
		0x08,             // ticket_nonce length: 8
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // nonce
		0x00, 0x01,       // ticket length: 1
		0xbb,             // ticket data
		0x00, 0x06,       // extensions length: 6
		0x00, 0x2a,       // extension type: early_data
		0x00, 0x02,       // extension length: 2
		0x00, 0x00,       // max_early_data_size: 0
	}
	f.Add(ticketWithEarlyData)

	// Empty input
	f.Add([]byte{})

	// Too short inputs
	f.Add([]byte{0x04})
	f.Add([]byte{0x04, 0x00, 0x00, 0x00})

	// Maximum length claims
	f.Add([]byte{0x04, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during NewSessionTicketMsgTLS13 parsing: %v\nInput: %x", r, data)
			}
		}()

		msg := &newSessionTicketMsgTLS13{}
		msg.unmarshal(data)
	})
}

// FuzzCertificateRequestMsgTLS13 tests the certificateRequestMsgTLS13.unmarshal
// function for panics when processing arbitrary certificate request data.
//
// Certificate request messages are sent by servers during mutual TLS handshakes.
// A malicious server could send malformed certificate requests to attack clients.
func FuzzCertificateRequestMsgTLS13(f *testing.F) {
	skipFuzzInShortMode(f)

	// Minimal valid certificate request
	minimalCertReq := []byte{
		0x0d,             // handshake type: CertificateRequest
		0x00, 0x00, 0x04, // length: 4 bytes
		0x00,             // certificate_request_context length: 0
		0x00, 0x00,       // extensions length: 0
	}
	f.Add(minimalCertReq)

	// Certificate request with signature algorithms extension
	certReqWithSigAlgs := []byte{
		0x0d,             // handshake type: CertificateRequest
		0x00, 0x00, 0x10, // length: 16 bytes
		0x00,             // certificate_request_context length: 0
		0x00, 0x0c,       // extensions length: 12
		0x00, 0x0d,       // extension type: signature_algorithms
		0x00, 0x08,       // extension length: 8
		0x00, 0x06,       // signature algorithms length: 6
		0x04, 0x03,       // ecdsa_secp256r1_sha256
		0x05, 0x03,       // ecdsa_secp384r1_sha384
		0x08, 0x04,       // rsa_pss_rsae_sha256
	}
	f.Add(certReqWithSigAlgs)

	// Empty input
	f.Add([]byte{})

	// Too short inputs
	f.Add([]byte{0x0d})
	f.Add([]byte{0x0d, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during CertificateRequestMsgTLS13 parsing: %v\nInput: %x", r, data)
			}
		}()

		msg := &certificateRequestMsgTLS13{}
		msg.unmarshal(data)
	})
}

// FuzzEncryptedExtensionsMsg tests the encryptedExtensionsMsg.unmarshal
// function for panics when processing arbitrary encrypted extensions data.
//
// Encrypted extensions are sent by servers in TLS 1.3 and contain critical
// configuration data. Malformed encrypted extensions could crash clients.
func FuzzEncryptedExtensionsMsg(f *testing.F) {
	skipFuzzInShortMode(f)

	// Minimal valid encrypted extensions (empty)
	minimalEE := []byte{
		0x08,             // handshake type: EncryptedExtensions
		0x00, 0x00, 0x02, // length: 2 bytes
		0x00, 0x00,       // extensions length: 0
	}
	f.Add(minimalEE)

	// Encrypted extensions with ALPN
	eeWithALPN := []byte{
		0x08,             // handshake type: EncryptedExtensions
		0x00, 0x00, 0x0d, // length: 13 bytes
		0x00, 0x0b,       // extensions length: 11
		0x00, 0x10,       // extension type: ALPN
		0x00, 0x07,       // extension length: 7
		0x00, 0x05,       // ALPN list length: 5
		0x04,             // protocol length: 4
		0x68, 0x74, 0x74, 0x70, // "http"
	}
	f.Add(eeWithALPN)

	// Empty input
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic during EncryptedExtensionsMsg parsing: %v\nInput: %x", r, data)
			}
		}()

		msg := &encryptedExtensionsMsg{}
		msg.unmarshal(data)
	})
}

// =============================================================================
// TestFuzz* wrapper tests for CI compatibility
// =============================================================================
//
// These wrapper tests allow running fuzz test seed corpuses with:
//   go test -run 'TestFuzz' -v
//
// They provide explicit test coverage verification without requiring the -fuzz flag.

// TestFuzzParsersCI runs all parser fuzz tests with their seed corpus.
// This is a comprehensive CI test that verifies all parsers handle edge cases.
func TestFuzzParsersCI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping fuzz parser tests in short mode")
	}

	t.Run("ClientHello", testClientHelloParsing)
	t.Run("ServerHello", testServerHelloParsing)
	t.Run("ECHConfig", testECHConfigParsing)
	t.Run("ECHConfigList", testECHConfigListParsing)
	t.Run("SessionState", testSessionStateParsing)
	t.Run("QUICVarint", testQUICVarintParsing)
	t.Run("CertificateMsgTLS13", testCertificateMsgTLS13Parsing)
	t.Run("NewSessionTicketMsgTLS13", testNewSessionTicketMsgTLS13Parsing)
	t.Run("CertificateRequestMsgTLS13", testCertificateRequestMsgTLS13Parsing)
	t.Run("EncryptedExtensionsMsg", testEncryptedExtensionsMsgParsing)
}

// testClientHelloParsing tests ClientHello parsing with edge cases.
func testClientHelloParsing(t *testing.T) {
	testCases := [][]byte{
		// Minimal valid ClientHello
		{
			0x01, 0x00, 0x00, 0x26, 0x03, 0x03,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00,
		},
		// Edge cases
		{},
		{0x01},
		{0x01, 0x00, 0x00, 0x00},
		{0x01, 0xff, 0xff, 0xff},
	}
	for _, data := range testCases {
		msg := &clientHelloMsg{}
		msg.unmarshal(data) // Should not panic
	}
}

// testServerHelloParsing tests ServerHello parsing with edge cases.
func testServerHelloParsing(t *testing.T) {
	testCases := [][]byte{
		// Minimal valid ServerHello
		{
			0x02, 0x00, 0x00, 0x26, 0x03, 0x03,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x2f, 0x00,
		},
		// Edge cases
		{},
		{0x02},
		{0x02, 0x00, 0x00, 0x00},
		{0x02, 0xff, 0xff, 0xff},
	}
	for _, data := range testCases {
		msg := &serverHelloMsg{}
		msg.unmarshal(data) // Should not panic
	}
}

// testECHConfigParsing tests ECH config parsing with edge cases.
func testECHConfigParsing(t *testing.T) {
	testCases := [][]byte{
		// Edge cases
		{},
		{0xfe},
		{0xfe, 0x0d},
		{0xfe, 0x0d, 0x00, 0x00},
		{0xfe, 0x0d, 0xff, 0xff},
		{0xba, 0xdd, 0x00, 0x05, 0x05, 0x04, 0x03, 0x02, 0x01}, // Unknown version
	}
	for _, data := range testCases {
		parseECHConfig(data) // Should not panic
	}
}

// testECHConfigListParsing tests ECH config list parsing with edge cases.
func testECHConfigListParsing(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00},
		{0x00, 0x01},
		{0xff, 0xff},
	}
	for _, data := range testCases {
		parseECHConfigList(data) // Should not panic
	}
}

// testSessionStateParsing tests session state parsing with edge cases.
func testSessionStateParsing(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x03},
		{0x03, 0x03},
		{0x03, 0x03, 0x01},
		{0x03, 0x03, 0x00, 0x00, 0x2f},
		{0x03, 0x03, 0x03, 0x00, 0x2f},
		{0x03, 0x03, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff},
	}
	for _, data := range testCases {
		ParseSessionState(data) // Should not panic
	}
}

// testQUICVarintParsing tests QUIC varint parsing with edge cases.
func testQUICVarintParsing(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x00},
		{0x3f},
		{0x40, 0x40},
		{0x7f, 0xff},
		{0x40},                         // Truncated 2-byte
		{0x80, 0x00},                   // Truncated 4-byte
		{0xc0, 0x00, 0x00, 0x00},       // Truncated 8-byte
		{0x40, 0x00},                   // Non-minimal encoding
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Max value
	}
	for _, data := range testCases {
		quicvarint.Read(bytes.NewReader(data))
		quicvarint.ReadLenient(bytes.NewReader(data))
	}
}

// testCertificateMsgTLS13Parsing tests TLS 1.3 certificate message parsing.
func testCertificateMsgTLS13Parsing(t *testing.T) {
	testCases := [][]byte{
		{0x0b, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00}, // Minimal
		{},
		{0x0b},
		{0x0b, 0x00, 0x00, 0x00},
		{0x0b, 0xff, 0xff, 0xff},
	}
	for _, data := range testCases {
		msg := &certificateMsgTLS13{}
		msg.unmarshal(data)
	}
}

// testNewSessionTicketMsgTLS13Parsing tests TLS 1.3 session ticket parsing.
func testNewSessionTicketMsgTLS13Parsing(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x04},
		{0x04, 0x00, 0x00, 0x00},
		{0x04, 0xff, 0xff, 0xff},
	}
	for _, data := range testCases {
		msg := &newSessionTicketMsgTLS13{}
		msg.unmarshal(data)
	}
}

// testCertificateRequestMsgTLS13Parsing tests TLS 1.3 certificate request parsing.
func testCertificateRequestMsgTLS13Parsing(t *testing.T) {
	testCases := [][]byte{
		{0x0d, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00}, // Minimal
		{},
		{0x0d},
		{0x0d, 0x00, 0x00, 0x00},
	}
	for _, data := range testCases {
		msg := &certificateRequestMsgTLS13{}
		msg.unmarshal(data)
	}
}

// testEncryptedExtensionsMsgParsing tests encrypted extensions parsing.
func testEncryptedExtensionsMsgParsing(t *testing.T) {
	testCases := [][]byte{
		{0x08, 0x00, 0x00, 0x02, 0x00, 0x00}, // Minimal
		{},
	}
	for _, data := range testCases {
		msg := &encryptedExtensionsMsg{}
		msg.unmarshal(data)
	}
}
