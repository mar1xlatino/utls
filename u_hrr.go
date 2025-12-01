// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"
)

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
	if len(raw) < 38 {
		return nil, errors.New("tls: HRR too short")
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
		return nil, errors.New("tls: HRR too short for random")
	}
	if !bytes.Equal(raw[offset:offset+32], helloRetryRequestRandom) {
		return nil, errors.New("tls: not a HelloRetryRequest (random mismatch)")
	}
	offset += 32

	// Session ID length
	if offset >= len(raw) {
		return nil, errors.New("tls: HRR truncated at session ID length")
	}
	sessionIDLen := int(raw[offset])
	offset++

	// RFC 8446: legacy_session_id must be 0-32 bytes
	if sessionIDLen > 32 {
		return nil, errors.New("tls: HRR session ID exceeds maximum length (32 bytes)")
	}

	if offset+sessionIDLen > len(raw) {
		return nil, errors.New("tls: HRR truncated at session ID")
	}
	if sessionIDLen > 0 {
		info.SessionID = make([]byte, sessionIDLen)
		copy(info.SessionID, raw[offset:offset+sessionIDLen])
	}
	offset += sessionIDLen

	// Cipher suite
	if offset+2 > len(raw) {
		return nil, errors.New("tls: HRR truncated at cipher suite")
	}
	info.CipherSuite = binary.BigEndian.Uint16(raw[offset:])
	offset += 2

	// Compression method
	if offset >= len(raw) {
		return nil, errors.New("tls: HRR truncated at compression")
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
		return nil, errors.New("tls: HRR extensions truncated")
	}

	// Parse extensions
	extEnd := offset + extLen
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(raw[offset:])
		extDataLen := int(binary.BigEndian.Uint16(raw[offset+2:]))
		offset += 4

		if offset+extDataLen > extEnd {
			return nil, errors.New("tls: HRR extension data truncated")
		}

		switch extType {
		case extensionSupportedVersions:
			// RFC 8446: In HRR, supported_versions MUST be exactly 2 bytes
			if extDataLen != 2 {
				return nil, fmt.Errorf("tls: HRR supported_versions must be 2 bytes, got %d", extDataLen)
			}
			info.SupportedVersion = binary.BigEndian.Uint16(raw[offset:])
		case extensionKeyShare:
			// RFC 8446: In HRR, key_share MUST be exactly 2 bytes (selected group only)
			if extDataLen != 2 {
				return nil, fmt.Errorf("tls: HRR key_share must be 2 bytes, got %d", extDataLen)
			}
			info.SelectedGroup = CurveID(binary.BigEndian.Uint16(raw[offset:]))
		case extensionCookie:
			if extDataLen >= 2 {
				cookieLen := int(binary.BigEndian.Uint16(raw[offset:]))
				// Security: Validate bounds before copying
				if 2+cookieLen <= extDataLen && offset+2+cookieLen <= len(raw) {
					info.Cookie = make([]byte, cookieLen)
					copy(info.Cookie, raw[offset+2:offset+2+cookieLen])
				}
			}
		}

		offset += extDataLen
	}

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
		return nil, errors.New("tls: HRR requires cipher suite")
	}
	if b.selectedGroup == 0 {
		return nil, errors.New("tls: HRR requires selected group")
	}

	// RFC 8446: legacy_session_id must be 0-32 bytes
	if len(b.sessionID) > 32 {
		return nil, errors.New("tls: HRR session ID exceeds maximum length (32 bytes)")
	}

	// Calculate extensions length
	extLen := 0
	// supported_versions: type(2) + len(2) + version(2)
	extLen += 6
	// key_share: type(2) + len(2) + group(2)
	extLen += 6
	// cookie if present: type(2) + len(2) + cookie_len(2) + cookie
	if len(b.cookie) > 0 {
		// Security: Prevent integer overflow
		cookieExtLen := 6 + len(b.cookie)
		if cookieExtLen > 65535 || extLen+cookieExtLen > 65535 {
			return nil, errors.New("tls: HRR cookie too large")
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
	// Security: Nil check to prevent panic
	if ch1 == nil || ch2 == nil {
		return errors.New("tls: cannot validate nil ClientHello messages")
	}

	// Version must match
	if ch1.vers != ch2.vers {
		return errors.New("tls: client changed version after HRR")
	}

	// Session ID must match
	if !bytes.Equal(ch1.sessionId, ch2.sessionId) {
		return errors.New("tls: client changed session ID after HRR")
	}

	// Cipher suites must be identical
	if len(ch1.cipherSuites) != len(ch2.cipherSuites) {
		return errors.New("tls: client changed cipher suites after HRR")
	}
	for i := range ch1.cipherSuites {
		if ch1.cipherSuites[i] != ch2.cipherSuites[i] {
			return errors.New("tls: client changed cipher suites after HRR")
		}
	}

	// Compression methods must be identical
	if !bytes.Equal(ch1.compressionMethods, ch2.compressionMethods) {
		return errors.New("tls: client changed compression methods after HRR")
	}

	// RFC 8446 Section 4.1.2: supported_versions must remain unchanged
	if len(ch1.supportedVersions) != len(ch2.supportedVersions) {
		return errors.New("tls: client changed supported_versions after HRR")
	}
	for i := range ch1.supportedVersions {
		if ch1.supportedVersions[i] != ch2.supportedVersions[i] {
			return errors.New("tls: client changed supported_versions after HRR")
		}
	}

	// RFC 8446 Section 4.1.2: supported_groups must remain unchanged
	if len(ch1.supportedCurves) != len(ch2.supportedCurves) {
		return errors.New("tls: client changed supported_groups after HRR")
	}
	for i := range ch1.supportedCurves {
		if ch1.supportedCurves[i] != ch2.supportedCurves[i] {
			return errors.New("tls: client changed supported_groups after HRR")
		}
	}

	// RFC 8446 Section 4.1.2: signature_algorithms must remain unchanged
	if len(ch1.supportedSignatureAlgorithms) != len(ch2.supportedSignatureAlgorithms) {
		return errors.New("tls: client changed signature_algorithms after HRR")
	}
	for i := range ch1.supportedSignatureAlgorithms {
		if ch1.supportedSignatureAlgorithms[i] != ch2.supportedSignatureAlgorithms[i] {
			return errors.New("tls: client changed signature_algorithms after HRR")
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
		return fmt.Errorf("tls: client did not provide key share for requested group %d", selectedGroup)
	}
	if keyShareCount > 1 {
		return fmt.Errorf("tls: client provided multiple key shares for selected group %d", selectedGroup)
	}

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
	if len(cookie) != 76 {
		return nil, fmt.Errorf("tls: invalid cookie length: %d", len(cookie))
	}

	// Security: Validate key length
	if len(key) < 32 {
		return nil, errors.New("tls: cookie key must be at least 32 bytes")
	}

	// Verify HMAC
	expectedMAC := ComputeAuthHMACSimple(key, cookie[:44])
	if expectedMAC == nil {
		return nil, errors.New("tls: failed to compute expected MAC")
	}
	if !VerifyAuthHMAC(cookie[44:], expectedMAC[:32]) {
		return nil, errors.New("tls: cookie authentication failed")
	}

	data := &HRRCookieData{
		SelectedCipher: binary.BigEndian.Uint16(cookie[32:]),
		SelectedGroup:  CurveID(binary.BigEndian.Uint16(cookie[34:])),
		Timestamp:      int64(binary.BigEndian.Uint64(cookie[36:])),
	}
	copy(data.ClientHelloHash[:], cookie[0:32])

	// Security: Reject negative timestamps (malformed or attack)
	if data.Timestamp < 0 {
		return nil, errors.New("tls: invalid cookie timestamp")
	}

	// Security: Validate timestamp to prevent replay attacks
	if maxAgeSeconds > 0 {
		now := time.Now().Unix()
		age := now - data.Timestamp

		// Check for expired cookie
		if age > maxAgeSeconds {
			return nil, fmt.Errorf("tls: cookie expired (age: %d seconds)", age)
		}

		// Check for future timestamp (clock skew tolerance: 60 seconds)
		if data.Timestamp > now+60 {
			return nil, errors.New("tls: cookie timestamp in future")
		}
	}

	return data, nil
}

// ComputeClientHelloHash computes SHA-256 hash of ClientHello.
func ComputeClientHelloHash(clientHello []byte) [32]byte {
	return sha256.Sum256(clientHello)
}
