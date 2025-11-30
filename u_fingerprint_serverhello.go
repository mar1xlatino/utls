// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ServerHelloBuilder constructs ServerHello messages with controlled JA4S fingerprint.
//
// Extension Order Note:
// ServerHello extensions are limited compared to ClientHello. In TLS 1.3, only these
// extensions can appear: supported_versions (43), key_share (51), and ALPN (16).
// The order is largely determined by the TLS library's marshal implementation.
// For fine-grained JA4S fingerprint control, use WithExtensionOrder() to specify
// which extensions to include and in what order (affects JA4S extension hash).
type ServerHelloBuilder struct {
	profile     *ServerProfile
	clientHello *clientHelloMsg
	config      *ServerHelloConfig

	// Override values
	cipherSuite     uint16
	version         uint16
	sessionID       []byte
	random          []byte
	keyShareGroup   CurveID
	keyShareData    []byte
	selectedALPN    string
	extensions      []uint16
	extensionOrder  []uint16 // explicit extension order for JA4S control
	compressionMode uint8
}

// NewServerHelloBuilder creates a builder for a server profile.
func NewServerHelloBuilder(profile *ServerProfile) *ServerHelloBuilder {
	b := &ServerHelloBuilder{
		profile: profile,
	}
	if profile != nil {
		cfg := profile.ServerHello
		b.config = &cfg
		// Use profile's extension order if configured
		if len(cfg.ExtensionOrder) > 0 {
			b.extensionOrder = make([]uint16, len(cfg.ExtensionOrder))
			copy(b.extensionOrder, cfg.ExtensionOrder)
		}
	}
	return b
}

// ForClientHello configures the builder based on received ClientHello.
func (b *ServerHelloBuilder) ForClientHello(ch *clientHelloMsg) *ServerHelloBuilder {
	b.clientHello = ch
	return b
}

// WithCipher sets a specific cipher suite.
func (b *ServerHelloBuilder) WithCipher(cipher uint16) *ServerHelloBuilder {
	b.cipherSuite = cipher
	return b
}

// WithVersion sets the TLS version.
func (b *ServerHelloBuilder) WithVersion(version uint16) *ServerHelloBuilder {
	b.version = version
	return b
}

// WithSessionID sets the session ID.
func (b *ServerHelloBuilder) WithSessionID(id []byte) *ServerHelloBuilder {
	b.sessionID = id
	return b
}

// WithRandom sets the server random.
func (b *ServerHelloBuilder) WithRandom(random []byte) *ServerHelloBuilder {
	b.random = random
	return b
}

// WithKeyShare sets the key share group and data.
func (b *ServerHelloBuilder) WithKeyShare(group CurveID, data []byte) *ServerHelloBuilder {
	b.keyShareGroup = group
	b.keyShareData = data
	return b
}

// WithALPN sets the selected ALPN protocol.
func (b *ServerHelloBuilder) WithALPN(protocol string) *ServerHelloBuilder {
	b.selectedALPN = protocol
	return b
}

// WithExtensions sets the extensions to include.
func (b *ServerHelloBuilder) WithExtensions(exts []uint16) *ServerHelloBuilder {
	b.extensions = exts
	return b
}

// WithCompression sets the compression method.
func (b *ServerHelloBuilder) WithCompression(method uint8) *ServerHelloBuilder {
	b.compressionMode = method
	return b
}

// WithExtensionOrder sets the explicit extension order for JA4S fingerprint control.
// This determines which extensions appear in the ServerHello and their order,
// which affects the JA4S extension hash component.
// Valid extension types for ServerHello: 16 (ALPN), 43 (supported_versions), 51 (key_share).
func (b *ServerHelloBuilder) WithExtensionOrder(order []uint16) *ServerHelloBuilder {
	b.extensionOrder = order
	return b
}

// Build creates the ServerHello message.
func (b *ServerHelloBuilder) Build() (*serverHelloMsg, error) {
	hello := &serverHelloMsg{}

	// Set version
	if b.version != 0 {
		hello.vers = b.version
	} else if b.clientHello != nil && len(b.clientHello.supportedVersions) > 0 {
		// Select highest mutually supported version
		hello.vers = selectVersion(b.clientHello.supportedVersions)
	} else {
		hello.vers = VersionTLS12
	}

	// Set random - allocate 32 bytes first since hello.random is []byte
	hello.random = make([]byte, 32)
	if b.random != nil {
		if len(b.random) != 32 {
			return nil, errors.New("server random must be 32 bytes")
		}
		copy(hello.random, b.random)
	} else {
		if _, err := rand.Read(hello.random); err != nil {
			return nil, err
		}
	}

	// Set session ID
	if b.sessionID != nil {
		hello.sessionId = b.sessionID
	} else if b.config != nil {
		switch b.config.SessionIDMode {
		case "echo":
			if b.clientHello != nil {
				hello.sessionId = b.clientHello.sessionId
			}
		case "random":
			length := b.config.SessionIDLength
			if length <= 0 {
				length = 32
			}
			if length > 32 {
				length = 32
			}
			hello.sessionId = make([]byte, length)
			if _, err := rand.Read(hello.sessionId); err != nil {
				return nil, err
			}
		case "none":
			hello.sessionId = nil
		default:
			// Default: echo client session ID
			if b.clientHello != nil {
				hello.sessionId = b.clientHello.sessionId
			}
		}
	}

	// Set cipher suite
	if b.cipherSuite != 0 {
		hello.cipherSuite = b.cipherSuite
	} else if b.clientHello != nil && b.profile != nil {
		hello.cipherSuite = SelectCipher(b.profile, b.clientHello.cipherSuites)
	}
	if hello.cipherSuite == 0 {
		return nil, errors.New("no cipher suite selected")
	}

	// Set compression (always null for TLS 1.3)
	hello.compressionMethod = b.compressionMode

	// Handle TLS 1.3 specific fields
	if hello.vers >= VersionTLS13 || isTLS13CipherSuite(hello.cipherSuite) {
		hello.supportedVersion = VersionTLS13

		// Set key share
		if b.keyShareGroup != 0 {
			// Explicit key share provided via WithKeyShare()
			if len(b.keyShareData) == 0 {
				return nil, errors.New("tls: TLS 1.3 requires key share data - use WithKeyShare(group, data)")
			}
			hello.serverShare = keyShare{
				group: b.keyShareGroup,
				data:  b.keyShareData,
			}
		} else if b.clientHello != nil {
			// Select from client's key shares
			// NOTE: For actual TLS 1.3 handshakes, key share data must be generated
			// by the caller using crypto/ecdh or similar. This builder only handles
			// fingerprint aspects - the actual key exchange is done by the TLS stack.
			selectedGroup := CurveID(0)
			for _, ks := range b.clientHello.keyShares {
				if isValidKeyShareGroupForServer(ks.group) {
					selectedGroup = ks.group
					break
				}
			}
			if selectedGroup != 0 {
				// For fingerprint preview purposes only - real handshakes must use
				// WithKeyShare() to provide actual key share data
				hello.serverShare = keyShare{
					group: selectedGroup,
					// data intentionally left nil - must be set by TLS handshake logic
				}
			}
		}
	}

	// Set ALPN
	if b.selectedALPN != "" {
		hello.alpnProtocol = b.selectedALPN
	} else if b.clientHello != nil && len(b.clientHello.alpnProtocols) > 0 && b.profile != nil {
		hello.alpnProtocol = SelectALPN(b.profile, b.clientHello.alpnProtocols)
	}

	return hello, nil
}

// BuildRaw creates the ServerHello and returns the raw bytes.
func (b *ServerHelloBuilder) BuildRaw() ([]byte, error) {
	hello, err := b.Build()
	if err != nil {
		return nil, err
	}
	return hello.marshal()
}

// PreviewFingerprint returns a preview of what the JA4S fingerprint would be.
func (b *ServerHelloBuilder) PreviewFingerprint() (*ServerHelloFingerprint, error) {
	hello, err := b.Build()
	if err != nil {
		return nil, err
	}
	return computeServerHelloFingerprintWithOrder(hello, b.extensionOrder), nil
}

// JA4S returns a preview of the JA4S fingerprint string.
func (b *ServerHelloBuilder) JA4S() (string, error) {
	fp, err := b.PreviewFingerprint()
	if err != nil {
		return "", err
	}
	return fp.JA4S, nil
}

// selectVersion selects the highest mutually supported TLS version.
func selectVersion(clientVersions []uint16) uint16 {
	// Prefer TLS 1.3, then 1.2
	for _, v := range clientVersions {
		if v == VersionTLS13 {
			return VersionTLS13
		}
	}
	for _, v := range clientVersions {
		if v == VersionTLS12 {
			return VersionTLS12
		}
	}
	// Default to TLS 1.2
	return VersionTLS12
}

// isTLS13CipherSuite returns true if the cipher suite is TLS 1.3 only.
func isTLS13CipherSuite(suite uint16) bool {
	switch suite {
	case TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256:
		return true
	}
	return false
}

// isValidKeyShareGroupForServer returns true if the curve is valid for server key shares.
func isValidKeyShareGroupForServer(group CurveID) bool {
	switch group {
	case CurveP256, CurveP384, CurveP521, X25519, X25519MLKEM768:
		return true
	}
	// Reject GREASE values
	if isGREASEUint16(uint16(group)) {
		return false
	}
	return false
}

// computeServerHelloFingerprintWithOrder computes fingerprint with explicit extension order.
func computeServerHelloFingerprintWithOrder(hello *serverHelloMsg, extOrder []uint16) *ServerHelloFingerprint {
	fp := &ServerHelloFingerprint{}

	// Determine version
	version := hello.vers
	if hello.supportedVersion != 0 {
		version = hello.supportedVersion
	}

	// Build JA4S components
	var versionStr string
	switch version {
	case VersionTLS13:
		versionStr = "13"
	case VersionTLS12:
		versionStr = "12"
	case VersionTLS11:
		versionStr = "11"
	case VersionTLS10:
		versionStr = "10"
	default:
		versionStr = "00"
	}

	// Determine which extensions are present and their order
	var extensions []uint16
	if len(extOrder) > 0 {
		// Use explicit order - filter to only include present extensions
		for _, ext := range extOrder {
			switch ext {
			case 16: // ALPN
				if hello.alpnProtocol != "" {
					extensions = append(extensions, ext)
				}
			case 43: // supported_versions
				if hello.supportedVersion != 0 {
					extensions = append(extensions, ext)
				}
			case 51: // key_share
				if hello.serverShare.group != 0 {
					extensions = append(extensions, ext)
				}
			}
		}
	} else {
		// Default order: supported_versions, key_share, ALPN
		if hello.supportedVersion != 0 {
			extensions = append(extensions, 43)
		}
		if hello.serverShare.group != 0 {
			extensions = append(extensions, 51)
		}
		if hello.alpnProtocol != "" {
			extensions = append(extensions, 16)
		}
	}

	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN indicator: first and last character of protocol per JA4 spec
	alpnChar := "00"
	if len(hello.alpnProtocol) >= 1 {
		first := hello.alpnProtocol[0]
		last := hello.alpnProtocol[len(hello.alpnProtocol)-1]
		if isAlphanumericByte(first) && isAlphanumericByte(last) {
			alpnChar = string(first) + string(last)
		} else {
			// Non-alphanumeric: use hex per JA4 spec
			firstHex := formatHexByte(first)
			lastHex := formatHexByte(last)
			alpnChar = string(firstHex[0]) + string(lastHex[1])
		}
	}

	// Build JA4S_a: t{version}{extcount}{alpn}
	// Format: protocol (t=TCP) + version (2 chars) + extension count (2 digits) + ALPN (2 chars)
	ja4sA := fmt.Sprintf("t%s%02d%s", versionStr, extCount, alpnChar)

	// JA4S_b: cipher suite in hex (4 chars)
	ja4sB := formatCipherSuite(hello.cipherSuite)

	// JA4S_c: sha256(sorted extensions)[:12]
	// For full JA4S compliance, we need to hash the extensions
	ja4sC := computeExtensionHash(extensions)

	// Build full JA4S: {a}_{b}_{c}
	fp.JA4S = ja4sA + "_" + ja4sB + "_" + ja4sC

	return fp
}

// computeExtensionHash computes SHA256 hash of extension list for JA4S_c component.
func computeExtensionHash(extensions []uint16) string {
	if len(extensions) == 0 {
		return "000000000000"
	}

	// Build comma-separated hex string of sorted extensions
	// Note: For JA4S, extensions are NOT sorted - order matters for fingerprint
	var extStr string
	for i, ext := range extensions {
		if i > 0 {
			extStr += ","
		}
		extStr += formatExtension(ext)
	}

	// SHA256 and take first 12 hex chars
	h := sha256.Sum256([]byte(extStr))
	return hex.EncodeToString(h[:])[:12]
}

// formatExtension formats an extension type as a 4-character hex string.
func formatExtension(ext uint16) string {
	const hexChars = "0123456789abcdef"
	return string([]byte{
		hexChars[(ext>>12)&0xf],
		hexChars[(ext>>8)&0xf],
		hexChars[(ext>>4)&0xf],
		hexChars[ext&0xf],
	})
}

// formatCipherSuite formats a cipher suite as a 4-character hex string.
func formatCipherSuite(suite uint16) string {
	const hex = "0123456789abcdef"
	return string([]byte{
		hex[(suite>>12)&0xf],
		hex[(suite>>8)&0xf],
		hex[(suite>>4)&0xf],
		hex[suite&0xf],
	})
}

// isAlphanumericByte returns true if byte is 0-9, A-Z, or a-z.
func isAlphanumericByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// formatHexByte formats a byte as a 2-character hex string.
func formatHexByte(b byte) string {
	const hexChars = "0123456789abcdef"
	return string([]byte{hexChars[b>>4], hexChars[b&0xf]})
}

// ServerHelloBuilderFromProfile creates a builder initialized from a profile ID.
func ServerHelloBuilderFromProfile(profileID string) (*ServerHelloBuilder, error) {
	profile, ok := DefaultServerProfileRegistry.Get(profileID)
	if !ok {
		return nil, errors.New("unknown server profile: " + profileID)
	}
	return NewServerHelloBuilder(profile), nil
}
