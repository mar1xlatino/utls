// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"time"

	utlserrors "github.com/refraction-networking/utls/errors"
)

// maxHRRCookieSize is the maximum allowed size for HRR cookies.
// RFC 8446 does not specify a limit, but practical limits prevent DoS.
// 16KB is generous for any legitimate use case.
const maxHRRCookieSize = 16384

// HRR FINGERPRINT CONSISTENCY NOTES:
//
// Per RFC 8446 Section 4.1.2, ClientHello2 (after HRR) must be largely identical
// to ClientHello1, with only specific allowed changes. uTLS preserves:
//
// - GREASE values: Stored in UConn.greaseSeed during ApplyPreset, used consistently
//   for both ClientHello1 and ClientHello2. Extension GREASE values are set in
//   UtlsGREASEExtension.Value and preserved during remarshalling.
//
// - Extension ordering: Generally preserved.
//
// - PSK binders: Properly recalculated after HRR using the correct transcript
//   (MessageHash(CH1) + HRR) per RFC 8446 Section 4.2.11. This works for both
//   standard library and custom ClientHelloSpecs.
//
// KNOWN LIMITATION - FINGERPRINT DETECTION VECTOR:
//
// When a cookie extension must be added after HRR (because the spec did not
// include a CookieExtension placeholder), the cookie is inserted at a
// DETERMINISTIC position: immediately after the key_share extension.
//
// This deterministic placement may be detectable by sophisticated TLS
// fingerprinting systems, as real browsers may place the cookie extension
// at different positions depending on their implementation.
//
// To mitigate this fingerprint detection vector, include an empty
// CookieExtension placeholder at the appropriate position in your
// ClientHelloSpec when HRR might occur. This allows the cookie data
// to be inserted in-place without changing extension order.
//
// Example: Add &CookieExtension{} to your extensions list at the position
// where real browsers place their cookie extension.

// HRRInfo contains information about a HelloRetryRequest.
type HRRInfo struct {
	// CipherSuite is the selected cipher suite.
	CipherSuite uint16

	// SelectedGroup is the group requested by the server.
	SelectedGroup CurveID

	// SessionID is the session ID from the HRR.
	SessionID []byte

	// SupportedVersion is the TLS version (should be TLS 1.3).
	SupportedVersion uint16

	// Cookie is the optional cookie from the HRR.
	Cookie []byte

	// Raw is the raw HRR bytes.
	Raw []byte
}

// IsHelloRetryRequest checks if raw bytes represent a HelloRetryRequest.
// HRR is identified by having the special helloRetryRequestRandom value.
func IsHelloRetryRequest(raw []byte) bool {
	if len(raw) < 38 {
		return false
	}

	offset := 0
	// Skip handshake type and length if present
	if raw[0] == typeServerHello {
		offset = 4
	}

	// Skip version (2 bytes)
	offset += 2

	// Check random (32 bytes)
	if offset+32 > len(raw) {
		return false
	}

	return bytes.Equal(raw[offset:offset+32], helloRetryRequestRandom)
}

// ParseHRR parses a HelloRetryRequest message.
func ParseHRR(raw []byte) (*HRRInfo, error) {
	return ParseHRRWithContext(context.Background(), raw)
}

// ParseHRRWithContext parses a HelloRetryRequest message with context for logging.
func ParseHRRWithContext(ctx context.Context, raw []byte) (*HRRInfo, error) {
	utlserrors.LogDebug(ctx, "HRR: parsing HelloRetryRequest, length=", len(raw))

	if len(raw) < 38 {
		return nil, utlserrors.New("tls: HRR too short").AtError()
	}

	info := &HRRInfo{
		Raw: make([]byte, len(raw)),
	}
	copy(info.Raw, raw)

	offset := 0
	// Skip handshake type and length if present
	if raw[0] == typeServerHello {
		offset = 4
	}

	// Skip version (2 bytes) - legacy version, always 0x0303
	offset += 2

	// Verify this is HRR by checking random
	if offset+32 > len(raw) {
		return nil, utlserrors.New("tls: HRR too short for random").AtError()
	}
	if !bytes.Equal(raw[offset:offset+32], helloRetryRequestRandom) {
		utlserrors.LogDebug(ctx, "HRR: random mismatch - not a HelloRetryRequest")
		return nil, utlserrors.New("tls: not a HelloRetryRequest (random mismatch)").AtError()
	}
	utlserrors.LogDebug(ctx, "HRR: detected HelloRetryRequest (magic random matched)")
	offset += 32

	// Session ID length
	if offset >= len(raw) {
		return nil, utlserrors.New("tls: HRR truncated at session ID length").AtError()
	}
	sessionIDLen := int(raw[offset])
	offset++

	// RFC 8446: legacy_session_id must be 0-32 bytes
	if sessionIDLen > 32 {
		return nil, utlserrors.New("tls: invalid session ID length").AtError()
	}

	if offset+sessionIDLen > len(raw) {
		return nil, utlserrors.New("tls: HRR truncated at session ID").AtError()
	}
	if sessionIDLen > 0 {
		info.SessionID = make([]byte, sessionIDLen)
		copy(info.SessionID, raw[offset:offset+sessionIDLen])
	}
	offset += sessionIDLen

	// Cipher suite
	if offset+2 > len(raw) {
		return nil, utlserrors.New("tls: HRR truncated at cipher suite").AtError()
	}
	info.CipherSuite = binary.BigEndian.Uint16(raw[offset:])
	utlserrors.LogDebug(ctx, "HRR: cipher suite=", fmt.Sprintf("0x%04x", info.CipherSuite))
	offset += 2

	// Compression method
	if offset >= len(raw) {
		return nil, utlserrors.New("tls: HRR truncated at compression").AtError()
	}
	offset++ // Skip compression method (always 0)

	// Extensions
	if offset+2 > len(raw) {
		// No extensions
		return info, nil
	}

	extLen := int(binary.BigEndian.Uint16(raw[offset:]))
	offset += 2

	// Security: Check for overflow and bounds
	if extLen > len(raw)-offset {
		return nil, utlserrors.New("tls: HRR extensions truncated").AtError()
	}

	utlserrors.LogDebug(ctx, "HRR: parsing extensions, length=", extLen)

	// Parse extensions
	extEnd := offset + extLen
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(raw[offset:])
		extDataLen := int(binary.BigEndian.Uint16(raw[offset+2:]))
		offset += 4

		if offset+extDataLen > extEnd {
			return nil, utlserrors.New("tls: HRR extension data truncated").AtError()
		}

		switch extType {
		case extensionSupportedVersions:
			// RFC 8446: In HRR, supported_versions MUST be exactly 2 bytes
			if extDataLen != 2 {
				return nil, utlserrors.New("tls: HRR supported_versions must be 2 bytes, got ", extDataLen).AtError()
			}
			info.SupportedVersion = binary.BigEndian.Uint16(raw[offset:])
			utlserrors.LogDebug(ctx, "HRR: supported version=", fmt.Sprintf("0x%04x", info.SupportedVersion))
		case extensionKeyShare:
			// RFC 8446: In HRR, key_share MUST be exactly 2 bytes (selected group only)
			if extDataLen != 2 {
				return nil, utlserrors.New("tls: HRR key_share must be 2 bytes, got ", extDataLen).AtError()
			}
			info.SelectedGroup = CurveID(binary.BigEndian.Uint16(raw[offset:]))
			utlserrors.LogDebug(ctx, "HRR: server requested curve=", info.SelectedGroup)
		case extensionCookie:
			if extDataLen >= 2 {
				cookieLen := int(binary.BigEndian.Uint16(raw[offset:]))
				// Security: Enforce maximum cookie size to prevent DoS attacks
				if cookieLen > maxHRRCookieSize {
					return nil, utlserrors.New("tls: HRR cookie exceeds maximum size (", cookieLen, " > ", maxHRRCookieSize, ")").AtError()
				}
				// Security: Validate bounds before copying
				if 2+cookieLen <= extDataLen && offset+2+cookieLen <= len(raw) {
					info.Cookie = make([]byte, cookieLen)
					copy(info.Cookie, raw[offset+2:offset+2+cookieLen])
					utlserrors.LogDebug(ctx, "HRR: cookie received, length=", cookieLen)
				}
			}
		}

		offset += extDataLen
	}

	utlserrors.LogDebug(ctx, "HRR: parsing complete, selectedGroup=", info.SelectedGroup)
	return info, nil
}

// HRRBuilder builds HelloRetryRequest messages.
type HRRBuilder struct {
	cipherSuite      uint16
	selectedGroup    CurveID
	sessionID        []byte
	supportedVersion uint16
	cookie           []byte
}

// NewHRRBuilder creates a new HRR builder.
func NewHRRBuilder() *HRRBuilder {
	return &HRRBuilder{
		supportedVersion: VersionTLS13,
	}
}

// WithCipherSuite sets the cipher suite.
func (b *HRRBuilder) WithCipherSuite(cs uint16) *HRRBuilder {
	b.cipherSuite = cs
	return b
}

// WithSelectedGroup sets the requested key share group.
func (b *HRRBuilder) WithSelectedGroup(group CurveID) *HRRBuilder {
	b.selectedGroup = group
	return b
}

// WithSessionID sets the session ID (should match ClientHello).
func (b *HRRBuilder) WithSessionID(id []byte) *HRRBuilder {
	b.sessionID = id
	return b
}

// WithCookie sets the cookie.
func (b *HRRBuilder) WithCookie(cookie []byte) *HRRBuilder {
	b.cookie = cookie
	return b
}

// Build creates the HRR message bytes.
func (b *HRRBuilder) Build() ([]byte, error) {
	if b.cipherSuite == 0 {
		return nil, utlserrors.New("tls: HRR requires cipher suite").AtError()
	}
	if b.selectedGroup == 0 {
		return nil, utlserrors.New("tls: HRR requires selected group").AtError()
	}

	// RFC 8446: legacy_session_id must be 0-32 bytes
	if len(b.sessionID) > 32 {
		return nil, utlserrors.New("tls: invalid session ID length").AtError()
	}

	// Calculate extensions length
	extLen := 0
	// supported_versions: type(2) + len(2) + version(2)
	extLen += 6
	// key_share: type(2) + len(2) + group(2)
	extLen += 6
	// cookie if present: type(2) + len(2) + cookie_len(2) + cookie
	if len(b.cookie) > 0 {
		// Security: Enforce maximum cookie size to prevent DoS attacks
		if len(b.cookie) > maxHRRCookieSize {
			return nil, utlserrors.New("tls: HRR cookie exceeds maximum size (", len(b.cookie), " > ", maxHRRCookieSize, ")").AtError()
		}
		// Security: Prevent integer overflow
		cookieExtLen := 6 + len(b.cookie)
		if cookieExtLen > 65535 || extLen+cookieExtLen > 65535 {
			return nil, utlserrors.New("tls: HRR cookie extension too large").AtError()
		}
		extLen += cookieExtLen
	}

	// Calculate total length
	// version(2) + random(32) + session_id_len(1) + session_id + cipher(2) + compression(1) + ext_len(2) + ext
	bodyLen := 2 + 32 + 1 + len(b.sessionID) + 2 + 1 + 2 + extLen

	// Allocate buffer (handshake type + length + body)
	buf := make([]byte, 4+bodyLen)
	offset := 0

	// Handshake type
	buf[offset] = typeServerHello
	offset++

	// Length (3 bytes)
	buf[offset] = byte(bodyLen >> 16)
	buf[offset+1] = byte(bodyLen >> 8)
	buf[offset+2] = byte(bodyLen)
	offset += 3

	// Legacy version (0x0303 = TLS 1.2)
	binary.BigEndian.PutUint16(buf[offset:], VersionTLS12)
	offset += 2

	// Random (special HRR random)
	copy(buf[offset:], helloRetryRequestRandom)
	offset += 32

	// Session ID
	buf[offset] = byte(len(b.sessionID))
	offset++
	if len(b.sessionID) > 0 {
		copy(buf[offset:], b.sessionID)
		offset += len(b.sessionID)
	}

	// Cipher suite
	binary.BigEndian.PutUint16(buf[offset:], b.cipherSuite)
	offset += 2

	// Compression method (always 0)
	buf[offset] = 0
	offset++

	// Extensions length
	binary.BigEndian.PutUint16(buf[offset:], uint16(extLen))
	offset += 2

	// supported_versions extension
	binary.BigEndian.PutUint16(buf[offset:], extensionSupportedVersions)
	binary.BigEndian.PutUint16(buf[offset+2:], 2)
	binary.BigEndian.PutUint16(buf[offset+4:], b.supportedVersion)
	offset += 6

	// key_share extension (selected group only)
	binary.BigEndian.PutUint16(buf[offset:], extensionKeyShare)
	binary.BigEndian.PutUint16(buf[offset+2:], 2)
	binary.BigEndian.PutUint16(buf[offset+4:], uint16(b.selectedGroup))
	offset += 6

	// cookie extension if present
	if len(b.cookie) > 0 {
		binary.BigEndian.PutUint16(buf[offset:], extensionCookie)
		binary.BigEndian.PutUint16(buf[offset+2:], uint16(2+len(b.cookie)))
		binary.BigEndian.PutUint16(buf[offset+4:], uint16(len(b.cookie)))
		copy(buf[offset+6:], b.cookie)
		offset += 6 + len(b.cookie)
	}

	return buf, nil
}

// HRRTranscriptHash computes the transcript hash for HRR.
// Per RFC 8446 Section 4.4.1, the first ClientHello is replaced with
// a special message_hash message containing its hash.
// Returns nil if hashFunc is nil.
func HRRTranscriptHash(hashFunc func() hash.Hash, clientHello1 []byte) []byte {
	// Security: Nil check to prevent panic
	if hashFunc == nil {
		return nil
	}

	h := hashFunc()
	h.Write(clientHello1)
	chHash := h.Sum(nil)

	// message_hash message: type(1) + length(3) + hash
	messageHash := make([]byte, 4+len(chHash))
	messageHash[0] = typeMessageHash
	messageHash[1] = 0
	messageHash[2] = 0
	messageHash[3] = byte(len(chHash))
	copy(messageHash[4:], chHash)

	return messageHash
}

// ValidateClientHello2 validates the second ClientHello after HRR.
// Per RFC 8446 Section 4.1.2, certain fields must remain unchanged.
func ValidateClientHello2(ch1, ch2 *clientHelloMsg, selectedGroup CurveID) error {
	return ValidateClientHello2WithContext(context.Background(), ch1, ch2, selectedGroup)
}

// ValidateClientHello2WithContext validates the second ClientHello after HRR with context for logging.
func ValidateClientHello2WithContext(ctx context.Context, ch1, ch2 *clientHelloMsg, selectedGroup CurveID) error {
	utlserrors.LogDebug(ctx, "HRR: validating second ClientHello")

	// Security: Nil check to prevent panic
	if ch1 == nil || ch2 == nil {
		return utlserrors.New("tls: cannot validate nil ClientHello messages").AtError()
	}

	// Version must match
	if ch1.vers != ch2.vers {
		utlserrors.LogDebug(ctx, "HRR: client changed version after HRR")
		return utlserrors.New("tls: client changed version after HRR").AtError()
	}

	// Session ID must match
	if !bytes.Equal(ch1.sessionId, ch2.sessionId) {
		utlserrors.LogDebug(ctx, "HRR: client changed session ID after HRR")
		return utlserrors.New("tls: client changed session ID after HRR").AtError()
	}

	// Cipher suites must be identical
	if len(ch1.cipherSuites) != len(ch2.cipherSuites) {
		utlserrors.LogDebug(ctx, "HRR: client changed cipher suites after HRR (count mismatch)")
		return utlserrors.New("tls: client changed cipher suites after HRR").AtError()
	}
	for i := range ch1.cipherSuites {
		if ch1.cipherSuites[i] != ch2.cipherSuites[i] {
			utlserrors.LogDebug(ctx, "HRR: client changed cipher suites after HRR")
			return utlserrors.New("tls: client changed cipher suites after HRR").AtError()
		}
	}

	// Compression methods must be identical
	if !bytes.Equal(ch1.compressionMethods, ch2.compressionMethods) {
		utlserrors.LogDebug(ctx, "HRR: client changed compression methods after HRR")
		return utlserrors.New("tls: client changed compression methods after HRR").AtError()
	}

	// RFC 8446 Section 4.1.2: supported_versions must remain unchanged
	if len(ch1.supportedVersions) != len(ch2.supportedVersions) {
		utlserrors.LogDebug(ctx, "HRR: client changed supported_versions after HRR")
		return utlserrors.New("tls: client changed supported_versions after HRR").AtError()
	}
	for i := range ch1.supportedVersions {
		if ch1.supportedVersions[i] != ch2.supportedVersions[i] {
			utlserrors.LogDebug(ctx, "HRR: client changed supported_versions after HRR")
			return utlserrors.New("tls: client changed supported_versions after HRR").AtError()
		}
	}

	// RFC 8446 Section 4.1.2: supported_groups must remain unchanged
	if len(ch1.supportedCurves) != len(ch2.supportedCurves) {
		utlserrors.LogDebug(ctx, "HRR: client changed supported_groups after HRR")
		return utlserrors.New("tls: client changed supported_groups after HRR").AtError()
	}
	for i := range ch1.supportedCurves {
		if ch1.supportedCurves[i] != ch2.supportedCurves[i] {
			utlserrors.LogDebug(ctx, "HRR: client changed supported_groups after HRR")
			return utlserrors.New("tls: client changed supported_groups after HRR").AtError()
		}
	}

	// RFC 8446 Section 4.1.2: signature_algorithms must remain unchanged
	if len(ch1.supportedSignatureAlgorithms) != len(ch2.supportedSignatureAlgorithms) {
		utlserrors.LogDebug(ctx, "HRR: client changed signature_algorithms after HRR")
		return utlserrors.New("tls: client changed signature_algorithms after HRR").AtError()
	}
	for i := range ch1.supportedSignatureAlgorithms {
		if ch1.supportedSignatureAlgorithms[i] != ch2.supportedSignatureAlgorithms[i] {
			utlserrors.LogDebug(ctx, "HRR: client changed signature_algorithms after HRR")
			return utlserrors.New("tls: client changed signature_algorithms after HRR").AtError()
		}
	}

	// Check that the requested group is now present in key shares
	// RFC 8446 Section 4.2.8: Client MUST provide exactly one key share for selected group
	keyShareCount := 0
	for _, ks := range ch2.keyShares {
		if ks.group == selectedGroup {
			keyShareCount++
		}
	}
	if keyShareCount == 0 {
		utlserrors.LogDebug(ctx, "HRR: client did not provide key share for requested group ", selectedGroup)
		return utlserrors.New("tls: client did not provide key share for requested group ", selectedGroup).AtError()
	}
	if keyShareCount > 1 {
		utlserrors.LogDebug(ctx, "HRR: client provided multiple key shares for selected group ", selectedGroup)
		return utlserrors.New("tls: client provided multiple key shares for selected group ", selectedGroup).AtError()
	}

	utlserrors.LogDebug(ctx, "HRR: second ClientHello validation passed, key share found for group ", selectedGroup)
	return nil
}

// HRRCookieData represents data that can be encoded in an HRR cookie.
type HRRCookieData struct {
	// ClientHelloHash is the hash of the original ClientHello.
	ClientHelloHash [32]byte

	// SelectedCipher is the selected cipher suite.
	SelectedCipher uint16

	// SelectedGroup is the requested key share group.
	SelectedGroup CurveID

	// Timestamp is when the HRR was sent.
	Timestamp int64
}

// EncodeCookie encodes HRR cookie data with authentication.
// Returns nil if data or key is invalid.
func EncodeCookie(data *HRRCookieData, key []byte) []byte {
	// Security: Validate inputs
	if data == nil {
		return nil
	}
	if len(key) < 32 {
		return nil // Security: Require minimum key length
	}
	if data.Timestamp < 0 {
		return nil // Security: Reject negative timestamps
	}

	// Cookie format: ch_hash(32) + cipher(2) + group(2) + timestamp(8) + hmac(32)
	buf := make([]byte, 32+2+2+8+32)

	copy(buf[0:32], data.ClientHelloHash[:])
	binary.BigEndian.PutUint16(buf[32:], data.SelectedCipher)
	binary.BigEndian.PutUint16(buf[34:], uint16(data.SelectedGroup))
	binary.BigEndian.PutUint64(buf[36:], uint64(data.Timestamp))

	// HMAC for authentication
	mac := ComputeAuthHMACSimple(key, buf[:44])
	if mac == nil {
		return nil // HMAC failed (empty key)
	}
	copy(buf[44:], mac[:32])

	return buf
}

// DecodeCookie decodes and verifies an HRR cookie.
// maxAgeSeconds specifies maximum cookie age (0 = no expiration check).
func DecodeCookie(cookie, key []byte) (*HRRCookieData, error) {
	return DecodeCookieWithMaxAge(cookie, key, 120) // Default 120s max age
}

// DecodeCookieWithMaxAge decodes cookie with custom max age.
func DecodeCookieWithMaxAge(cookie, key []byte, maxAgeSeconds int64) (*HRRCookieData, error) {
	return DecodeCookieWithMaxAgeAndContext(context.Background(), cookie, key, maxAgeSeconds)
}

// DecodeCookieWithMaxAgeAndContext decodes cookie with custom max age and context for logging.
func DecodeCookieWithMaxAgeAndContext(ctx context.Context, cookie, key []byte, maxAgeSeconds int64) (*HRRCookieData, error) {
	utlserrors.LogDebug(ctx, "HRR: decoding cookie, length=", len(cookie))

	if len(cookie) != 76 {
		return nil, utlserrors.New("tls: invalid cookie length: ", len(cookie)).AtError()
	}

	// Security: Validate key length
	if len(key) < 32 {
		return nil, utlserrors.New("tls: cookie key must be at least 32 bytes").AtError()
	}

	// Verify HMAC
	expectedMAC := ComputeAuthHMACSimple(key, cookie[:44])
	if expectedMAC == nil {
		return nil, utlserrors.New("tls: failed to compute expected MAC").AtError()
	}
	if !VerifyAuthHMAC(cookie[44:], expectedMAC[:32]) {
		utlserrors.LogDebug(ctx, "HRR: cookie authentication failed")
		return nil, utlserrors.New("tls: cookie authentication failed").AtError()
	}

	data := &HRRCookieData{
		SelectedCipher: binary.BigEndian.Uint16(cookie[32:]),
		SelectedGroup:  CurveID(binary.BigEndian.Uint16(cookie[34:])),
		Timestamp:      int64(binary.BigEndian.Uint64(cookie[36:])),
	}
	copy(data.ClientHelloHash[:], cookie[0:32])

	// Security: Reject negative timestamps (malformed or attack)
	if data.Timestamp < 0 {
		return nil, utlserrors.New("tls: invalid cookie timestamp").AtError()
	}

	// Security: Validate timestamp to prevent replay attacks
	if maxAgeSeconds > 0 {
		now := time.Now().Unix()
		age := now - data.Timestamp

		// Check for expired cookie
		if age > maxAgeSeconds {
			utlserrors.LogDebug(ctx, "HRR: cookie expired, age=", age, " seconds")
			return nil, utlserrors.New("tls: cookie expired (age: ", age, " seconds)").AtError()
		}

		// Check for future timestamp (clock skew tolerance: 60 seconds)
		if data.Timestamp > now+60 {
			utlserrors.LogDebug(ctx, "HRR: cookie timestamp in future")
			return nil, utlserrors.New("tls: cookie timestamp in future").AtError()
		}
	}

	utlserrors.LogDebug(ctx, "HRR: cookie decoded successfully, group=", data.SelectedGroup)
	return data, nil
}

// ComputeClientHelloHash computes SHA-256 hash of ClientHello.
func ComputeClientHelloHash(clientHello []byte) [32]byte {
	return sha256.Sum256(clientHello)
}
