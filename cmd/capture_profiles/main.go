// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// capture_profiles is a tool for capturing real browser TLS fingerprints.
//
// Usage:
//
//  1. Run this server: go run main.go
//  2. Open browsers and navigate to https://localhost:8443
//  3. The tool will output FingerprintProfile Go code for each browser
//
// For automated capture with Selenium, create a script that:
//   - Launches browsers with --ignore-certificate-errors (Chrome)
//   - Navigates to https://localhost:8443
//   - The captured profile will be printed to stdout
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	tls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// CapturedProfile holds TLS fingerprint data from a ClientHello
// Comprehensive capture of all fingerprint-relevant data
type CapturedProfile struct {
	// Metadata
	Timestamp  time.Time `json:"timestamp"`
	UserAgent  string    `json:"user_agent"`
	RemoteAddr string    `json:"remote_addr"`

	// TLS Record Layer (fingerprint relevant!)
	RecordVersion uint16 `json:"record_version"` // TLS record header version (usually 0x0301)

	// ClientHello Core Fields
	ClientVersion   uint16 `json:"client_version"`    // Legacy version (usually 0x0303)
	SessionIDLength int    `json:"session_id_length"` // 0 or 32
	SessionID       string `json:"session_id"`        // Hex-encoded session ID (for analysis)

	// Cipher Suites (order matters for fingerprinting)
	CipherSuites []uint16 `json:"cipher_suites"` // With GREASE

	// Compression Methods
	CompressionMethods []uint8 `json:"compression_methods"`

	// Extensions (order matters!)
	Extensions []uint16 `json:"extensions"` // With GREASE, original order

	// GREASE Tracking (critical for accurate replay)
	GREASE GREASEInfo `json:"grease"`

	// Parsed Extension Data
	ServerName       string          `json:"server_name"`
	SupportedGroups  []uint16        `json:"supported_groups"`  // With GREASE
	ECPointFormats   []uint8         `json:"ec_point_formats"`
	SignatureAlgos   []uint16        `json:"signature_algorithms"`
	SignatureAlgsCert []uint16       `json:"signature_algorithms_cert"` // 0x0032
	ALPNProtocols    []string        `json:"alpn_protocols"`
	SupportedVers    []uint16        `json:"supported_versions"` // With GREASE
	KeyShares        []KeyShareEntry `json:"key_shares"`
	PSKModes         []uint8         `json:"psk_modes"`
	CertCompressAlgs []uint16        `json:"cert_compression_algs"`

	// ===========================================================================
	// 0-RTT / Session Resumption Extensions (CRITICAL)
	// ===========================================================================
	// early_data (0x002a) - TLS 1.3 0-RTT support
	EarlyDataEnabled bool `json:"early_data_enabled"`

	// pre_shared_key (0x0029) - PSK for session resumption
	PSKPresent         bool  `json:"psk_present"`
	PSKIdentitiesCount int   `json:"psk_identities_count"`
	PSKBindersCount    int   `json:"psk_binders_count"`
	PSKBinderLengths   []int `json:"psk_binder_lengths,omitempty"`

	// cookie (0x002c) - HRR cookie
	CookiePresent bool `json:"cookie_present"`
	CookieLength  int  `json:"cookie_length"`

	// ===========================================================================
	// Extension Flags (presence detection)
	// ===========================================================================
	StatusRequest        bool `json:"status_request"`          // OCSP (0x0005)
	StatusRequestV2      bool `json:"status_request_v2"`       // OCSP v2 (0x0011)
	SCTEnabled           bool `json:"sct_enabled"`             // SCT (0x0012)
	ExtendedMasterSecret bool `json:"extended_master_secret"`  // EMS (0x0017)
	EncryptThenMAC       bool `json:"encrypt_then_mac"`        // (0x0016)
	PostHandshakeAuth    bool `json:"post_handshake_auth"`     // PHA (0x0031)
	DelegatedCredentials bool `json:"delegated_credentials"`   // (0x0022)
	RenegotiationInfo    bool `json:"renegotiation_info"`      // (0xff01)
	RenegotiationLen     int  `json:"renegotiation_info_len"`  // Length of renegotiation_info

	// ALPS - Application Layer Protocol Settings
	ApplicationSettings     bool     `json:"application_settings"`      // ALPS new (0x44cd / 17613)
	ApplicationSettingsOld  bool     `json:"application_settings_old"`  // ALPS old (0x4469 / 17513)
	ALPSProtocols           []string `json:"alps_protocols,omitempty"`  // Protocols in ALPS extension

	// ECH - Encrypted Client Hello
	ECHEnabled       bool   `json:"ech_enabled"`        // Any ECH extension present
	ECHType          uint16 `json:"ech_type,omitempty"` // Which ECH extension (0xfe0d, etc.)
	ECHOuterExtsList bool   `json:"ech_outer_exts"`     // ech_outer_extensions (0xfd00)
	ECHIsGREASE      bool   `json:"ech_is_grease"`      // Is this GREASE ECH (random payload)?
	ECHConfigID      uint8  `json:"ech_config_id"`      // ECH config_id if present

	// Legacy/Deprecated Extensions
	NPNEnabled       bool `json:"npn_enabled"`        // NPN (0x3374 / 13172)
	ChannelIDEnabled bool `json:"channel_id_enabled"` // Channel ID (0x7550 / 30032)
	TokenBinding     bool `json:"token_binding"`      // Token Binding (0x0018)

	// Certificate Authorities (0x002f)
	CertAuthoritiesPresent bool `json:"cert_authorities_present"`
	CertAuthoritiesLength  int  `json:"cert_authorities_length"`

	// QUIC Transport Parameters (0x0039)
	QUICTransportParams bool `json:"quic_transport_params"`

	// ===========================================================================
	// Extension Values (when length/value matters)
	// ===========================================================================
	PaddingLength       int    `json:"padding_length"`        // Padding ext length
	RecordSizeLimit     uint16 `json:"record_size_limit"`     // (0x001c)
	SessionTicketLength int    `json:"session_ticket_length"` // 0 = empty ticket

	// Raw bytes (not in JSON, for forensics if needed)
	RawClientHello []byte `json:"-"`

	// Computed Fingerprints
	JA3   string `json:"ja3"`
	JA3r  string `json:"ja3_raw"`
	JA4   string `json:"ja4"`
	JA4r  string `json:"ja4_raw"`
	JA4o  string `json:"ja4_original"`     // Original order
	JA4ro string `json:"ja4_original_raw"`

	// Parse warnings (non-fatal issues during parsing)
	ParseWarnings []string `json:"parse_warnings,omitempty"`
}

// KeyShareEntry holds key share group and key length
type KeyShareEntry struct {
	Group     uint16 `json:"group"`
	KeyLength int    `json:"key_length"`
}

// GREASEInfo tracks GREASE values and positions (critical for replay)
type GREASEInfo struct {
	// Actual GREASE values used
	CipherSuite      uint16   `json:"cipher_suite,omitempty"`
	Extensions       []uint16 `json:"extensions,omitempty"`
	SupportedGroup   uint16   `json:"supported_group,omitempty"`
	SupportedVersion uint16   `json:"supported_version,omitempty"`
	KeyShare         uint16   `json:"key_share,omitempty"`

	// Positions in lists (-1 = not present)
	CipherSuitePos      int   `json:"cipher_suite_pos"`
	ExtensionPos        []int `json:"extension_pos"`
	SupportedGroupPos   int   `json:"supported_group_pos"`
	SupportedVersionPos int   `json:"supported_version_pos"`
	KeySharePos         int   `json:"key_share_pos"`
}

const (
	// Memory management limits
	maxCaptures      = 10000 // Limit memory growth
	maxSeenJA4       = 50000 // Limit deduplication map size
	maxParseWarnings = 50    // Limit parse warnings to prevent memory exhaustion
	maxExtensions    = 100   // Maximum number of extensions to parse (safety limit)
	maxCipherSuites  = 200   // Maximum cipher suites to parse (safety limit)

	// TLS record layer constraints per RFC 8446
	tlsRecordMaxLength    = 16384 // Maximum TLS record length (2^14)
	tlsRecordMinLength    = 38    // Minimum: handshake(4) + version(2) + random(32)
	sessionIDMaxLength    = 32    // Maximum session ID length per TLS spec
	maxSNINameLength      = 255   // Maximum SNI hostname length per RFC 6066
	maxALPNProtocolLength = 255   // Maximum ALPN protocol name length

	// HTTP handling limits
	maxHTTPHeaderLength = 8192 // Maximum HTTP header line length
	maxHTTPHeaderCount  = 100  // Maximum number of HTTP headers to read
	maxUserAgentLength  = 1024 // Maximum User-Agent length to store

	// Filename sanitization limits
	maxFilenameLength    = 200 // Maximum filename length
	maxBrowserNameLength = 50  // Maximum browser name length for filenames
	maxVersionLength     = 20  // Maximum version string length for filenames
)

var (
	captures      []CapturedProfile
	capturesMu    sync.Mutex
	seenJA4       = make(map[string]bool) // Deduplicate by JA4
	seenJA4Mu     sync.Mutex
	profilesDir   string
	autoSave      bool
	deduplicateUA bool

	// outputMu protects console output to prevent interleaving from concurrent goroutines.
	outputMu sync.Mutex

	// fileMu protects file writes to prevent concurrent writes to the same file.
	fileMu sync.Mutex
)

// BrowserInfo contains parsed browser information
type BrowserInfo struct {
	Browser      string
	Version      int
	VersionFull  string
	Platform     string
	OS           string
	OSVersion    string
	Architecture string
	Mobile       bool
	Bot          bool
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Command-line flags
	port := flag.Int("port", 443, "Port to listen on")
	flag.StringVar(&profilesDir, "dir", "profiles", "Directory to save profiles")
	flag.BoolVar(&autoSave, "save", true, "Auto-save profiles to files")
	flag.BoolVar(&deduplicateUA, "dedup", true, "Deduplicate captures by JA4 hash")
	flag.Parse()

	// Create profiles directory
	if autoSave {
		if err := os.MkdirAll(profilesDir, 0755); err != nil {
			log.Fatalf("Failed to create profiles directory: %v", err)
		}
		log.Printf("Profiles will be saved to: %s/", profilesDir)
	}

	// Generate self-signed certificate
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	log.Println("===========================================")
	log.Println("TLS Fingerprint Capture Server (Enhanced)")
	log.Println("===========================================")
	log.Printf("Listening on https://0.0.0.0:%d (all interfaces)\n", *port)
	log.Println("")
	log.Println("Access URLs:")
	log.Printf("  Local:    https://localhost:%d\n", *port)
	log.Printf("  External: https://<your-domain>:%d\n", *port)
	log.Println("")
	log.Println("Features:")
	log.Printf("  Auto-save:     %v (--save)\n", autoSave)
	log.Printf("  Deduplicate:   %v (--dedup)\n", deduplicateUA)
	log.Printf("  Profiles dir:  %s (--dir)\n", profilesDir)
	log.Println("")
	log.Println("Supported browsers:")
	log.Println("  Chrome, Firefox, Safari, Edge, Opera, Brave, Vivaldi")
	log.Println("  Samsung Internet, UC Browser, Yandex, QQ Browser, etc.")
	log.Println("")
	log.Println("Supported platforms:")
	log.Println("  Windows 10/11, macOS, Linux, Android, iOS, iPadOS, ChromeOS")
	log.Println("===========================================")

	// Create raw TCP listener to capture ClientHello
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn, tlsCert)
	}
}

func handleConnection(conn net.Conn, tlsCert tls.Certificate) {
	// Panic recovery to prevent server crashes from malicious input
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in handleConnection from %s: %v", conn.RemoteAddr(), r)
		}
	}()
	defer conn.Close()

	// Set overall connection deadline to prevent slowloris attacks
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// Set read deadline for ClientHello
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read the TLS record header and ClientHello
	rawClientHello, err := readClientHello(conn)
	if err != nil {
		log.Printf("Failed to read ClientHello from %s: %v", conn.RemoteAddr(), err)
		return
	}

	// Parse the ClientHello
	profile, err := parseClientHello(rawClientHello)
	if err != nil {
		log.Printf("Failed to parse ClientHello: %v", err)
		return
	}

	profile.RemoteAddr = conn.RemoteAddr().String()
	profile.Timestamp = time.Now()
	profile.RawClientHello = rawClientHello

	// Now proceed with normal TLS handshake
	// We need to "replay" the ClientHello we already read
	bufferedConn := &replayConn{
		Conn:   conn,
		replay: rawClientHello,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
	}

	tlsConn := tls.Server(bufferedConn, tlsConfig)
	defer tlsConn.Close()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		// Still output what we captured
		outputProfile(profile)
		return
	}

	// Handle HTTP request to get User-Agent
	handleHTTP(tlsConn, profile)
}

// replayConn replays previously read bytes before reading from the underlying connection
type replayConn struct {
	net.Conn
	replay []byte
	offset int
}

func (c *replayConn) Read(b []byte) (int, error) {
	if c.offset < len(c.replay) {
		n := copy(b, c.replay[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}

// Close implements net.Conn but does NOT close the underlying connection.
// This prevents double-close: the outer defer conn.Close() handles cleanup,
// while tlsConn.Close() only sends the TLS close_notify without closing the socket.
func (c *replayConn) Close() error {
	// Intentionally do nothing - let the caller's defer conn.Close() handle it.
	return nil
}

func readClientHello(conn net.Conn) ([]byte, error) {
	reader := bufio.NewReader(conn)

	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	n, err := io.ReadFull(reader, header)
	if err != nil {
		return nil, fmt.Errorf("read header: got %d bytes: %w", n, err)
	}

	// Verify it's a handshake record (content type 0x16)
	if header[0] != 0x16 {
		return nil, fmt.Errorf("not a handshake record: content type 0x%02x (expected 0x16)", header[0])
	}

	// Validate record version field (bytes 1-2) - should be TLS 1.0+ for ClientHello
	recordVersion := uint16(header[1])<<8 | uint16(header[2])
	if recordVersion < 0x0300 || recordVersion > 0x0304 {
		// Allow unusual versions but log warning (some implementations vary)
		log.Printf("WARNING: unusual record version 0x%04x from %s", recordVersion, conn.RemoteAddr())
	}

	// Get record length (bytes 3-4, big-endian)
	recordLen := int(header[3])<<8 | int(header[4])

	// Validate record length bounds
	if recordLen == 0 {
		return nil, fmt.Errorf("empty record (length 0)")
	}
	if recordLen < tlsRecordMinLength {
		return nil, fmt.Errorf("record too small for ClientHello: %d bytes (minimum %d)",
			recordLen, tlsRecordMinLength)
	}
	if recordLen > tlsRecordMaxLength {
		return nil, fmt.Errorf("record exceeds maximum TLS size: %d bytes (max %d)",
			recordLen, tlsRecordMaxLength)
	}

	// Read the handshake message payload
	payload := make([]byte, recordLen)
	n, err = io.ReadFull(reader, payload)
	if err != nil {
		return nil, fmt.Errorf("read payload: got %d of %d bytes: %w", n, recordLen, err)
	}

	// Verify handshake message type (byte 0 = ClientHello type 0x01)
	if payload[0] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: handshake type 0x%02x (expected 0x01)", payload[0])
	}

	// Validate handshake message length field (bytes 1-3, 24-bit big-endian)
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	expectedLen := recordLen - 4 // Record length minus handshake header (4 bytes)
	if handshakeLen != expectedLen {
		return nil, fmt.Errorf("handshake length mismatch: header says %d, record has %d bytes",
			handshakeLen, expectedLen)
	}

	// Sanity check: handshake length should accommodate at least minimal ClientHello
	minClientHelloBody := 2 + 32 + 1 // version(2) + random(32) + session_id_len(1)
	if handshakeLen < minClientHelloBody {
		return nil, fmt.Errorf("handshake message too small: %d bytes (minimum %d)",
			handshakeLen, minClientHelloBody)
	}

	// Return the complete record (header + payload)
	result := make([]byte, 5+recordLen)
	copy(result, header)
	copy(result[5:], payload)

	return result, nil
}

func parseClientHello(raw []byte) (*CapturedProfile, error) {
	if len(raw) < 5+4 {
		return nil, fmt.Errorf("too short")
	}

	profile := &CapturedProfile{
		GREASE: GREASEInfo{
			CipherSuitePos:      -1,
			SupportedGroupPos:   -1,
			SupportedVersionPos: -1,
			KeySharePos:         -1,
		},
	}

	// =========================================================================
	// TLS Record Layer (bytes 0-4)
	// =========================================================================
	// Byte 0: Content type (0x16 = handshake)
	// Bytes 1-2: Record version (fingerprint relevant!)
	// Bytes 3-4: Record length
	profile.RecordVersion = uint16(raw[1])<<8 | uint16(raw[2])

	// Skip TLS record header (5 bytes) + handshake header (4 bytes)
	data := raw[9:]

	if len(data) < 2+32+1 {
		return nil, fmt.Errorf("too short for version+random+session")
	}

	// Client version (2 bytes)
	profile.ClientVersion = uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]

	// Skip random (32 bytes) - no fingerprint value
	data = data[32:]

	// Session ID - capture both length AND content (for analysis)
	profile.SessionIDLength = int(data[0])

	// Validate session ID length per TLS spec (max 32 bytes)
	if profile.SessionIDLength > sessionIDMaxLength {
		addParseWarning(profile, fmt.Sprintf("session ID length %d exceeds max %d, truncating",
			profile.SessionIDLength, sessionIDMaxLength))
		profile.SessionIDLength = sessionIDMaxLength
	}

	if len(data) < 1+profile.SessionIDLength {
		return nil, fmt.Errorf("session ID length overflow: need %d bytes, have %d",
			1+profile.SessionIDLength, len(data))
	}
	if profile.SessionIDLength > 0 {
		profile.SessionID = hex.EncodeToString(data[1 : 1+profile.SessionIDLength])
	}
	data = data[1+profile.SessionIDLength:]

	// Cipher suites
	if len(data) < 2 {
		return nil, fmt.Errorf("too short for cipher suites length field")
	}
	cipherLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	// Validate cipher suites length
	if cipherLen == 0 {
		addParseWarning(profile, "cipher suites length is 0 (no cipher suites)")
	}
	if cipherLen%2 != 0 {
		return nil, fmt.Errorf("invalid cipher suites length %d: must be even", cipherLen)
	}
	if len(data) < cipherLen {
		return nil, fmt.Errorf("cipher suites truncated: need %d bytes, have %d", cipherLen, len(data))
	}

	// Limit cipher suite count to prevent memory exhaustion
	numCiphers := cipherLen / 2
	if numCiphers > maxCipherSuites {
		addParseWarning(profile, fmt.Sprintf("too many cipher suites: %d, limiting to %d", numCiphers, maxCipherSuites))
		numCiphers = maxCipherSuites
	}

	for i := 0; i < numCiphers*2; i += 2 {
		cs := uint16(data[i])<<8 | uint16(data[i+1])
		profile.CipherSuites = append(profile.CipherSuites, cs)
		if isGREASE(cs) && profile.GREASE.CipherSuite == 0 {
			profile.GREASE.CipherSuite = cs
			profile.GREASE.CipherSuitePos = len(profile.CipherSuites) - 1
		}
	}
	data = data[cipherLen:]

	// Compression methods
	if len(data) < 1 {
		return nil, fmt.Errorf("too short for compression methods length field")
	}
	compLen := int(data[0])

	// Validate compression methods
	if compLen == 0 {
		addParseWarning(profile, "compression methods length is 0 (no compression methods)")
	}
	if len(data) < 1+compLen {
		return nil, fmt.Errorf("compression methods truncated: need %d bytes, have %d", 1+compLen, len(data))
	}

	// Limit compression methods to prevent memory exhaustion (reasonable max: 255)
	for i := 1; i <= compLen && i < 256; i++ {
		profile.CompressionMethods = append(profile.CompressionMethods, data[i])
	}
	data = data[1+compLen:]

	// Extensions
	if len(data) < 2 {
		return profile, nil
	}
	extLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	if len(data) < extLen {
		return nil, fmt.Errorf("too short for extensions")
	}

	extData := data[:extLen]
	extIndex := 0

	// Parse extensions with safety limits
	for len(extData) >= 4 && extIndex < maxExtensions {
		extType := uint16(extData[0])<<8 | uint16(extData[1])
		extDataLen := int(extData[2])<<8 | int(extData[3])
		extData = extData[4:]

		// Validate extension length
		if extDataLen < 0 {
			addParseWarning(profile, fmt.Sprintf("extension 0x%04x has negative length", extType))
			break
		}
		if len(extData) < extDataLen {
			addParseWarning(profile,
				fmt.Sprintf("extension 0x%04x truncated: need %d bytes, have %d", extType, extDataLen, len(extData)))
			break
		}

		extPayload := extData[:extDataLen]
		profile.Extensions = append(profile.Extensions, extType)

		// Track GREASE
		if isGREASE(extType) {
			profile.GREASE.Extensions = append(profile.GREASE.Extensions, extType)
			profile.GREASE.ExtensionPos = append(profile.GREASE.ExtensionPos, extIndex)
		}

		// Parse specific extensions
		switch extType {
		case 0x0000: // SNI
			// SNI format: list_length(2) + name_type(1) + name_length(2) + name
			if len(extPayload) >= 5 {
				listLen := int(extPayload[0])<<8 | int(extPayload[1])
				// Validate list length
				if listLen > len(extPayload)-2 {
					addParseWarning(profile, fmt.Sprintf("SNI list length %d exceeds available data %d", listLen, len(extPayload)-2))
					break
				}
				nameType := extPayload[2]
				if nameType != 0 { // Only host_name (0) is valid per RFC 6066
					addParseWarning(profile, fmt.Sprintf("SNI has unsupported name type %d (expected 0)", nameType))
				}
				nameLen := int(extPayload[3])<<8 | int(extPayload[4])
				// Validate name length
				if nameLen > maxSNINameLength {
					addParseWarning(profile, fmt.Sprintf("SNI name length %d exceeds max %d", nameLen, maxSNINameLength))
					nameLen = maxSNINameLength
				}
				if len(extPayload) >= 5+nameLen {
					profile.ServerName = string(extPayload[5 : 5+nameLen])
				} else {
					addParseWarning(profile, fmt.Sprintf("SNI name truncated: need %d bytes, have %d", 5+nameLen, len(extPayload)))
				}
			} else if len(extPayload) > 0 {
				addParseWarning(profile, fmt.Sprintf("SNI extension too short: %d bytes", len(extPayload)))
			}

		case 0x0005: // status_request
			profile.StatusRequest = true

		case 0x000a: // supported_groups
			if len(extPayload) >= 2 {
				groupLen := int(extPayload[0])<<8 | int(extPayload[1])
				// Validate group list length
				if groupLen%2 != 0 {
					addParseWarning(profile, fmt.Sprintf("supported_groups length %d is odd, truncating", groupLen))
					groupLen-- // Make it even
				}
				if groupLen > len(extPayload)-2 {
					addParseWarning(profile, fmt.Sprintf("supported_groups truncated: need %d, have %d", groupLen, len(extPayload)-2))
					groupLen = len(extPayload) - 2
					if groupLen%2 != 0 {
						groupLen--
					}
				}
				groupIdx := 0
				for i := 2; i < 2+groupLen; i += 2 {
					g := uint16(extPayload[i])<<8 | uint16(extPayload[i+1])
					profile.SupportedGroups = append(profile.SupportedGroups, g)
					if isGREASE(g) && profile.GREASE.SupportedGroup == 0 {
						profile.GREASE.SupportedGroup = g
						profile.GREASE.SupportedGroupPos = groupIdx
					}
					groupIdx++
				}
			}

		case 0x000b: // ec_point_formats
			if len(extPayload) >= 1 {
				formatLen := int(extPayload[0])
				for i := 1; i < 1+formatLen && i < len(extPayload); i++ {
					profile.ECPointFormats = append(profile.ECPointFormats, extPayload[i])
				}
			}

		case 0x000d: // signature_algorithms
			if len(extPayload) >= 2 {
				sigLen := int(extPayload[0])<<8 | int(extPayload[1])
				// Validate signature algorithms list length
				if sigLen%2 != 0 {
					addParseWarning(profile, fmt.Sprintf("signature_algorithms length %d is odd, truncating", sigLen))
					sigLen-- // Make it even
				}
				if sigLen > len(extPayload)-2 {
					addParseWarning(profile, fmt.Sprintf("signature_algorithms truncated: need %d, have %d", sigLen, len(extPayload)-2))
					sigLen = len(extPayload) - 2
					if sigLen%2 != 0 {
						sigLen--
					}
				}
				for i := 2; i < 2+sigLen; i += 2 {
					profile.SignatureAlgos = append(profile.SignatureAlgos, uint16(extPayload[i])<<8|uint16(extPayload[i+1]))
				}
			}

		case 0x0010: // ALPN
			if len(extPayload) >= 2 {
				alpnLen := int(extPayload[0])<<8 | int(extPayload[1])
				if alpnLen > len(extPayload)-2 {
					addParseWarning(profile, fmt.Sprintf("ALPN list truncated: need %d, have %d", alpnLen, len(extPayload)-2))
					alpnLen = len(extPayload) - 2
				}
				if alpnLen > 0 {
					alpnData := extPayload[2 : 2+alpnLen]
					protocolCount := 0
					for len(alpnData) > 0 && protocolCount < 50 { // Limit protocols
						protoLen := int(alpnData[0])
						if protoLen == 0 {
							addParseWarning(profile, "ALPN protocol has zero length")
							alpnData = alpnData[1:]
							continue
						}
						if protoLen > maxALPNProtocolLength {
							addParseWarning(profile, fmt.Sprintf("ALPN protocol length %d exceeds max %d", protoLen, maxALPNProtocolLength))
							break
						}
						if len(alpnData) < 1+protoLen {
							addParseWarning(profile,
								fmt.Sprintf("ALPN protocol truncated: need %d bytes, have %d", 1+protoLen, len(alpnData)))
							break
						}
						profile.ALPNProtocols = append(profile.ALPNProtocols, string(alpnData[1:1+protoLen]))
						alpnData = alpnData[1+protoLen:]
						protocolCount++
					}
				}
			}

		case 0x0012: // SCT
			profile.SCTEnabled = true

		case 0x0015: // padding
			profile.PaddingLength = extDataLen

		case 0x0017: // extended_master_secret
			profile.ExtendedMasterSecret = true

		case 0x001b: // compress_certificate
			if len(extPayload) >= 1 {
				algLen := int(extPayload[0])
				// Ensure we have enough data and only read complete uint16 values
				// algLen is byte count, so we need pairs of bytes (algLen should be even)
				for i := 1; i+1 < 1+algLen && i+1 < len(extPayload); i += 2 {
					profile.CertCompressAlgs = append(profile.CertCompressAlgs, uint16(extPayload[i])<<8|uint16(extPayload[i+1]))
				}
			}

		case 0x001c: // record_size_limit
			if len(extPayload) >= 2 {
				profile.RecordSizeLimit = uint16(extPayload[0])<<8 | uint16(extPayload[1])
			}

		case 0x0022: // delegated_credentials
			profile.DelegatedCredentials = true

		case 0x0023: // session_ticket
			profile.SessionTicketLength = extDataLen

		case 0x002b: // supported_versions
			if len(extPayload) >= 1 {
				versLen := int(extPayload[0])
				// Validate versions list length
				if versLen%2 != 0 {
					addParseWarning(profile, fmt.Sprintf("supported_versions length %d is odd, truncating", versLen))
					versLen-- // Make it even
				}
				if versLen > len(extPayload)-1 {
					addParseWarning(profile, fmt.Sprintf("supported_versions truncated: need %d, have %d", versLen, len(extPayload)-1))
					versLen = len(extPayload) - 1
					if versLen%2 != 0 {
						versLen--
					}
				}
				versIdx := 0
				for i := 1; i < 1+versLen; i += 2 {
					v := uint16(extPayload[i])<<8 | uint16(extPayload[i+1])
					profile.SupportedVers = append(profile.SupportedVers, v)
					if isGREASE(v) && profile.GREASE.SupportedVersion == 0 {
						profile.GREASE.SupportedVersion = v
						profile.GREASE.SupportedVersionPos = versIdx
					}
					versIdx++
				}
			}

		case 0x002d: // psk_key_exchange_modes
			if len(extPayload) >= 1 {
				modeLen := int(extPayload[0])
				for i := 1; i < 1+modeLen && i < len(extPayload); i++ {
					profile.PSKModes = append(profile.PSKModes, extPayload[i])
				}
			}

		case 0x0031: // post_handshake_auth
			profile.PostHandshakeAuth = true

		case 0x0033: // key_share
			if len(extPayload) >= 2 {
				ksLen := int(extPayload[0])<<8 | int(extPayload[1])
				if len(extPayload) >= 2+ksLen {
					ksData := extPayload[2 : 2+ksLen]
					ksIdx := 0
					for len(ksData) >= 4 {
						group := uint16(ksData[0])<<8 | uint16(ksData[1])
						keyLen := int(ksData[2])<<8 | int(ksData[3])
						// Validate bounds BEFORE appending to avoid partial entries
						if len(ksData) < 4+keyLen {
							addParseWarning(profile,
								fmt.Sprintf("key_share entry truncated: group 0x%04x needs %d bytes, have %d", group, 4+keyLen, len(ksData)))
							break
						}
						profile.KeyShares = append(profile.KeyShares, KeyShareEntry{Group: group, KeyLength: keyLen})
						if isGREASE(group) && profile.GREASE.KeyShare == 0 {
							profile.GREASE.KeyShare = group
							profile.GREASE.KeySharePos = ksIdx
						}
						ksData = ksData[4+keyLen:]
						ksIdx++
					}
				}
			}

		// =====================================================================
		// 0-RTT / Session Resumption Extensions (CRITICAL)
		// =====================================================================

		case 0x0029: // pre_shared_key (41) - CRITICAL for session resumption
			profile.PSKPresent = true
			// Parse PSK identities and binders
			// Format: identities_length (2) + identities + binders_length (2) + binders
			if len(extPayload) >= 2 {
				identitiesLen := int(extPayload[0])<<8 | int(extPayload[1])
				offset := 2
				// Count identities
				identitiesData := extPayload[offset:]
				if len(identitiesData) >= identitiesLen {
					pos := 0
					for pos < identitiesLen && pos+2 <= len(identitiesData) {
						// Each identity: length (2) + identity + obfuscated_ticket_age (4)
						idLen := int(identitiesData[pos])<<8 | int(identitiesData[pos+1])
						requiredLen := 2 + idLen + 4 // identity_length + identity + obfuscated_ticket_age
						// Validate that the full identity record exists before counting
						if pos+requiredLen > identitiesLen || pos+requiredLen > len(identitiesData) {
							addParseWarning(profile, fmt.Sprintf("PSK identity truncated: need %d bytes at pos %d, have %d", requiredLen, pos, identitiesLen-pos))
							break
						}
						pos += requiredLen
						profile.PSKIdentitiesCount++
					}
					offset += identitiesLen
				}
				// Parse binders
				if offset+2 <= len(extPayload) {
					bindersLen := int(extPayload[offset])<<8 | int(extPayload[offset+1])
					offset += 2
					bindersData := extPayload[offset:]
					if len(bindersData) >= bindersLen {
						pos := 0
						for pos < bindersLen && pos < len(bindersData) {
							binderLen := int(bindersData[pos])
							requiredLen := 1 + binderLen // length_field + binder
							// Validate that the full binder record exists before counting
							if pos+requiredLen > bindersLen || pos+requiredLen > len(bindersData) {
								addParseWarning(profile, fmt.Sprintf("PSK binder truncated: need %d bytes at pos %d, have %d", requiredLen, pos, bindersLen-pos))
								break
							}
							profile.PSKBinderLengths = append(profile.PSKBinderLengths, binderLen)
							profile.PSKBindersCount++
							pos += requiredLen
						}
					}
				}
			}

		case 0x002a: // early_data (42) - CRITICAL for 0-RTT
			profile.EarlyDataEnabled = true

		case 0x002c: // cookie (44) - HRR cookie
			profile.CookiePresent = true
			profile.CookieLength = extDataLen

		// =====================================================================
		// Signature and Certificate Extensions
		// =====================================================================

		case 0x0011: // status_request_v2 (17)
			profile.StatusRequestV2 = true

		case 0x0016: // encrypt_then_mac (22)
			profile.EncryptThenMAC = true

		case 0x0018: // token_binding (24)
			profile.TokenBinding = true

		case 0x002f: // certificate_authorities (47)
			profile.CertAuthoritiesPresent = true
			profile.CertAuthoritiesLength = extDataLen

		case 0x0032: // signature_algorithms_cert (50)
			if len(extPayload) >= 2 {
				sigLen := int(extPayload[0])<<8 | int(extPayload[1])
				// Validate and adjust length if truncated
				if sigLen > len(extPayload)-2 {
					addParseWarning(profile, fmt.Sprintf("signature_algorithms_cert truncated: claimed %d, available %d", sigLen, len(extPayload)-2))
					sigLen = len(extPayload) - 2
				}
				// Ensure even length for 2-byte scheme parsing
				if sigLen%2 != 0 {
					sigLen--
				}
				for i := 2; i < 2+sigLen && i+1 < len(extPayload); i += 2 {
					profile.SignatureAlgsCert = append(profile.SignatureAlgsCert,
						uint16(extPayload[i])<<8|uint16(extPayload[i+1]))
				}
			}

		case 0x0039: // quic_transport_parameters (57)
			profile.QUICTransportParams = true

		// =====================================================================
		// ALPS - Application Layer Protocol Settings
		// =====================================================================

		case 0x4469: // ALPS old codepoint (17513) - Chrome <133
			profile.ApplicationSettingsOld = true
			// Parse ALPS protocols (same format as ALPN: length-prefixed list)
			if len(extPayload) >= 2 {
				alpsLen := int(extPayload[0])<<8 | int(extPayload[1])
				if len(extPayload) >= 2+alpsLen {
					alpsData := extPayload[2 : 2+alpsLen]
					protocolCount := 0
					for len(alpsData) > 0 && protocolCount < 50 { // Limit protocols (DoS protection)
						protoLen := int(alpsData[0])
						if protoLen == 0 {
							alpsData = alpsData[1:] // Skip empty protocol
							continue
						}
						if len(alpsData) < 1+protoLen {
							break
						}
						profile.ALPSProtocols = append(profile.ALPSProtocols, string(alpsData[1:1+protoLen]))
						alpsData = alpsData[1+protoLen:]
						protocolCount++
					}
				}
			}

		case 0x44cd: // ALPS new codepoint (17613) - Chrome 133+
			profile.ApplicationSettings = true
			// Parse ALPS protocols (same format as 0x4469)
			if len(extPayload) >= 2 {
				alpsLen := int(extPayload[0])<<8 | int(extPayload[1])
				if len(extPayload) >= 2+alpsLen {
					alpsData := extPayload[2 : 2+alpsLen]
					protocolCount := 0
					for len(alpsData) > 0 && protocolCount < 50 { // Limit protocols (DoS protection)
						protoLen := int(alpsData[0])
						if protoLen == 0 {
							alpsData = alpsData[1:] // Skip empty protocol
							continue
						}
						if len(alpsData) < 1+protoLen {
							break
						}
						profile.ALPSProtocols = append(profile.ALPSProtocols, string(alpsData[1:1+protoLen]))
						alpsData = alpsData[1+protoLen:]
						protocolCount++
					}
				}
			}

		// =====================================================================
		// Renegotiation
		// =====================================================================

		case 0xff01: // renegotiation_info (65281)
			profile.RenegotiationInfo = true
			profile.RenegotiationLen = extDataLen

		// =====================================================================
		// ECH - Encrypted Client Hello
		// =====================================================================

		case 0xfe0d: // encrypted_client_hello (draft-ietf-tls-esni-17+)
			profile.ECHEnabled = true
			profile.ECHType = 0xfe0d
			// ECH format per draft-ietf-tls-esni:
			// type (1) + kdf_id (2) + aead_id (2) + config_id (1) + enc_len (2) + enc + payload
			// GREASE ECH: type=0, random cipher suite, enc_len typically 0 or 1
			// Real ECH: proper enc with HPKE encapsulated key
			if len(extPayload) >= 9 {
				echType := extPayload[0]
				if echType == 0 { // ClientHelloOuter
					profile.ECHConfigID = extPayload[5]
					encLen := int(extPayload[6])<<8 | int(extPayload[7])
					// GREASE ECH detection:
					// 1. enc_len is 0 or 1 (GREASE uses minimal/empty enc)
					// 2. Real ECH has enc_len >= 32 for HPKE public key
					if encLen <= 1 {
						profile.ECHIsGREASE = true
					}
				}
			} else if len(extPayload) >= 6 {
				// Partial ECH data - extract what we can
				if extPayload[0] == 0 {
					profile.ECHConfigID = extPayload[5]
					profile.ECHIsGREASE = true // Short = likely GREASE
				}
			}

		case 0xfe09, 0xfe0a, 0xfe08: // ECH older drafts
			profile.ECHEnabled = true
			profile.ECHType = extType
			// Older drafts: similar structure but different offsets
			// For older drafts, check enc length if available
			if len(extPayload) >= 8 {
				encLen := int(extPayload[5])<<8 | int(extPayload[6])
				if encLen <= 1 {
					profile.ECHIsGREASE = true
				}
			} else if len(extPayload) < 20 {
				profile.ECHIsGREASE = true // Very short = likely GREASE
			}

		case 0xfd00: // ech_outer_extensions
			profile.ECHOuterExtsList = true

		// =====================================================================
		// Legacy/Deprecated Extensions
		// =====================================================================

		case 0x3374: // next_protocol_negotiation (13172) - NPN, deprecated
			profile.NPNEnabled = true

		case 0x7550: // channel_id (30032) - deprecated
			profile.ChannelIDEnabled = true

		case 0x754f: // channel_id old (30031) - deprecated
			profile.ChannelIDEnabled = true
		}

		extData = extData[extDataLen:]
		extIndex++
	}

	// Calculate fingerprints
	profile.JA3, profile.JA3r = calculateJA3Full(profile)
	profile.JA4, profile.JA4r, profile.JA4o, profile.JA4ro = calculateJA4Full(profile)

	return profile, nil
}

// addParseWarning safely adds a warning with a limit to prevent memory exhaustion
func addParseWarning(profile *CapturedProfile, warning string) {
	if len(profile.ParseWarnings) < maxParseWarnings {
		profile.ParseWarnings = append(profile.ParseWarnings, warning)
	} else if len(profile.ParseWarnings) == maxParseWarnings {
		profile.ParseWarnings = append(profile.ParseWarnings, "... additional warnings truncated")
	}
	// Beyond maxParseWarnings+1, silently ignore
}

// calculateJA3Full returns both JA3 hash and raw string
func calculateJA3Full(p *CapturedProfile) (hash, raw string) {
	// JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	// Filter out GREASE values
	ciphers := filterGREASE(p.CipherSuites)
	extensions := filterGREASE(p.Extensions)
	groups := filterGREASE(p.SupportedGroups)

	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s",
		p.ClientVersion,
		joinUint16(ciphers, "-"),
		joinUint16(extensions, "-"),
		joinUint16(groups, "-"),
		joinUint8(p.ECPointFormats, "-"),
	)

	h := md5.Sum([]byte(ja3String))
	return hex.EncodeToString(h[:]), ja3String
}

// calculateJA4Full returns all JA4 variants: sorted (ja4, ja4r) and original order (ja4o, ja4ro)
func calculateJA4Full(p *CapturedProfile) (ja4, ja4r, ja4o, ja4ro string) {
	// JA4 = {a}_{b}_{c}
	// a = protocol + version + SNI + cipher_count + ext_count + ALPN
	// b = hash of sorted ciphers
	// c = hash of sorted extensions (without SNI/ALPN) + signature algorithms

	ciphers := filterGREASE(p.CipherSuites)
	extensions := filterGREASE(p.Extensions)

	// Protocol (t=TCP, q=QUIC)
	proto := "t"

	// TLS Version - use first non-GREASE from supported_versions
	var tlsVer string
	var realVersion uint16
	supportedVersClean := filterGREASE(p.SupportedVers)
	if len(supportedVersClean) > 0 {
		realVersion = supportedVersClean[0]
	} else {
		realVersion = p.ClientVersion
	}
	switch realVersion {
	case 0x0304: // TLS 1.3
		tlsVer = "13"
	case 0x0303: // TLS 1.2
		tlsVer = "12"
	case 0x0302: // TLS 1.1
		tlsVer = "11"
	case 0x0301: // TLS 1.0
		tlsVer = "10"
	case 0x0300: // SSL 3.0
		tlsVer = "s3"
	default:
		// Handle draft TLS 1.3 versions (0x7f01 - 0x7f1c = drafts 1-28)
		if realVersion >= 0x7f01 && realVersion <= 0x7f1c {
			tlsVer = "13"
		} else {
			tlsVer = "00"
		}
	}

	// SNI indicator
	sni := "i" // IP address
	if p.ServerName != "" {
		sni = "d" // domain
	}

	// Cipher count (2 digits, excluding GREASE)
	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (2 digits, excluding GREASE)
	extCount := len(extensions)
	if extCount > 99 {
		extCount = 99
	}

	// ALPN first+last char
	// Per JA4 spec: if alphanumeric, use the character directly
	// If non-alphanumeric, use first/last char of hex representation
	alpn := "00"
	if len(p.ALPNProtocols) > 0 {
		first := p.ALPNProtocols[0]
		if len(first) > 0 {
			firstByte := first[0]
			lastByte := first[len(first)-1]

			var firstChar, lastChar string
			if isAlphanumeric(firstByte) {
				firstChar = string(firstByte)
			} else {
				// Use first character of hex representation
				firstChar = fmt.Sprintf("%02x", firstByte)[:1]
			}
			if isAlphanumeric(lastByte) {
				lastChar = string(lastByte)
			} else {
				// Use second (last) character of hex representation
				lastChar = fmt.Sprintf("%02x", lastByte)[1:]
			}
			alpn = firstChar + lastChar
		}
	}

	// JA4_a (same for all variants)
	ja4a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, tlsVer, sni, cipherCount, extCount, alpn)

	// Filter extensions (remove SNI 0x0000 and ALPN 0x0010 for JA4_c)
	filteredExts := make([]uint16, 0, len(extensions))
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 {
			filteredExts = append(filteredExts, e)
		}
	}

	// Signature algorithms string (original order, for JA4_c)
	sigAlgsStr := joinUint16Hex(p.SignatureAlgos, ",")

	// === SORTED VARIANTS (JA4, JA4r) ===

	// JA4_b: sorted ciphers hash
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	sortedCipherStr := joinUint16Hex(sortedCiphers, ",")
	cipherHash := sha256.Sum256([]byte(sortedCipherStr))
	ja4b := hex.EncodeToString(cipherHash[:])[:12]

	// JA4_c: sorted extensions hash + signature algorithms
	sortedExts := make([]uint16, len(filteredExts))
	copy(sortedExts, filteredExts)
	sort.Slice(sortedExts, func(i, j int) bool { return sortedExts[i] < sortedExts[j] })
	sortedExtStr := joinUint16Hex(sortedExts, ",")

	ja4cInput := sortedExtStr
	if sigAlgsStr != "" {
		ja4cInput += "_" + sigAlgsStr
	}
	var ja4c string
	if ja4cInput == "" || ja4cInput == "_" {
		ja4c = "000000000000"
	} else {
		extHash := sha256.Sum256([]byte(ja4cInput))
		ja4c = hex.EncodeToString(extHash[:])[:12]
	}

	ja4 = fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)
	ja4r = fmt.Sprintf("%s_%s_%s", ja4a, sortedCipherStr, ja4cInput)

	// === ORIGINAL ORDER VARIANTS (JA4o, JA4ro) ===

	// JA4_b for original order: hash of ciphers in original order
	origCipherStr := joinUint16Hex(ciphers, ",")
	origCipherHash := sha256.Sum256([]byte(origCipherStr))
	ja4bo := hex.EncodeToString(origCipherHash[:])[:12]

	// JA4_c for original order: hash of extensions in original order
	origExtStr := joinUint16Hex(filteredExts, ",")
	ja4coInput := origExtStr
	if sigAlgsStr != "" {
		ja4coInput += "_" + sigAlgsStr
	}
	var ja4co string
	if ja4coInput == "" || ja4coInput == "_" {
		ja4co = "000000000000"
	} else {
		origExtHash := sha256.Sum256([]byte(ja4coInput))
		ja4co = hex.EncodeToString(origExtHash[:])[:12]
	}

	ja4o = fmt.Sprintf("%s_%s_%s", ja4a, ja4bo, ja4co)
	ja4ro = fmt.Sprintf("%s_%s_%s", ja4a, origCipherStr, ja4coInput)

	return
}

func filterGREASE(values []uint16) []uint16 {
	result := make([]uint16, 0, len(values))
	for _, v := range values {
		if !isGREASE(v) {
			result = append(result, v)
		}
	}
	return result
}

func isGREASE(v uint16) bool {
	// GREASE values: 0x?a?a where ? is 0-f
	return (v&0x0f0f) == 0x0a0a && (v&0xf000)>>8 == (v&0x00f0)
}

// isAlphanumeric returns true if the byte is 0-9, A-Z, or a-z.
// Used for JA4 ALPN character handling per the specification.
func isAlphanumeric(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func joinUint16(values []uint16, sep string) string {
	strs := make([]string, len(values))
	for i, v := range values {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(strs, sep)
}

func joinUint8(values []uint8, sep string) string {
	strs := make([]string, len(values))
	for i, v := range values {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(strs, sep)
}

func joinUint16Hex(values []uint16, sep string) string {
	strs := make([]string, len(values))
	for i, v := range values {
		strs[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(strs, sep)
}

func handleHTTP(conn *tls.Conn, profile *CapturedProfile) {
	// Use a limited reader to prevent memory exhaustion from overly long lines
	reader := bufio.NewReaderSize(conn, maxHTTPHeaderLength)

	// Read HTTP request line with length limit
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		// Check if this is a timeout error for better debugging
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("HTTP request read timeout from %s", conn.RemoteAddr())
		} else if err != io.EOF {
			log.Printf("HTTP request read error from %s: %v", conn.RemoteAddr(), err)
		}
		// Still try to output captured profile even if HTTP read failed
		outputProfile(profile)
		return
	}
	// Warn about excessively long request lines
	if len(requestLine) > maxHTTPHeaderLength {
		log.Printf("HTTP request line very long from %s: %d bytes", conn.RemoteAddr(), len(requestLine))
	}

	// Read headers to get User-Agent with limits to prevent DoS
	headerCount := 0
	for headerCount < maxHTTPHeaderCount {
		header, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				// Log non-EOF errors that occur during header reading
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("HTTP header read timeout from %s", conn.RemoteAddr())
				}
			}
			break
		}
		if header == "\r\n" || header == "\n" {
			break
		}
		// Skip overly long headers to prevent memory exhaustion
		if len(header) > maxHTTPHeaderLength {
			log.Printf("HTTP header too long from %s: %d bytes, skipping", conn.RemoteAddr(), len(header))
			headerCount++
			continue
		}
		if strings.HasPrefix(strings.ToLower(header), "user-agent:") {
			ua := strings.TrimSpace(header[11:])
			// Truncate User-Agent if too long to prevent memory issues
			if len(ua) > maxUserAgentLength {
				ua = ua[:maxUserAgentLength]
			}
			profile.UserAgent = ua
		}
		headerCount++
	}
	if headerCount >= maxHTTPHeaderCount {
		log.Printf("Too many HTTP headers from %s: reached limit of %d", conn.RemoteAddr(), maxHTTPHeaderCount)
	}

	// Send response with proper CRLF per HTTP/1.1 RFC 2616
	// Escape User-Agent to prevent XSS attacks
	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>TLS Fingerprint Captured</title></head>
<body>
<h1>TLS Fingerprint Captured!</h1>
<h2>JA3: %s</h2>
<h2>JA4: %s</h2>
<p>User-Agent: %s</p>
<p>Check server console for full profile.</p>
</body>
</html>`, html.EscapeString(profile.JA3), html.EscapeString(profile.JA4), html.EscapeString(profile.UserAgent))

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Connection: close\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" +
		body

	// Handle write errors properly
	responseBytes := []byte(response)
	n, writeErr := conn.Write(responseBytes)
	if writeErr != nil {
		if netErr, ok := writeErr.(net.Error); ok && netErr.Timeout() {
			log.Printf("HTTP response write timeout to %s", conn.RemoteAddr())
		} else {
			log.Printf("HTTP response write error to %s: %v", conn.RemoteAddr(), writeErr)
		}
	} else if n < len(responseBytes) {
		log.Printf("HTTP response partial write to %s: wrote %d of %d bytes", conn.RemoteAddr(), n, len(responseBytes))
	}

	// Store and output (with memory limit)
	capturesMu.Lock()
	if len(captures) >= maxCaptures {
		// Discard oldest 10% to avoid frequent reallocations
		captures = captures[maxCaptures/10:]
	}
	captures = append(captures, *profile)
	capturesMu.Unlock()

	outputProfile(profile)
}

func outputProfile(profile *CapturedProfile) {
	// Skip profiles without User-Agent when saving (pre-cert-accept handshakes)
	if profile.UserAgent == "" && autoSave {
		log.Printf("SKIPPED: No User-Agent (pre-accept handshake from %s)", profile.RemoteAddr)
		return
	}

	// Parse User-Agent for browser info
	info := parseUserAgentFull(profile.UserAgent)
	browser := info.Browser
	version := fmt.Sprintf("%d", info.Version)
	platform := info.Platform

	// Check for duplicates
	if deduplicateUA {
		seenJA4Mu.Lock()
		key := fmt.Sprintf("%s_%s_%s_%s", profile.JA4, browser, version, platform)
		if seenJA4[key] {
			seenJA4Mu.Unlock()
			ja4Preview := profile.JA4
			if len(ja4Preview) > 20 {
				ja4Preview = ja4Preview[:20] + "..."
			}
			log.Printf("SKIPPED duplicate: %s %s on %s (JA4: %s)", browser, version, platform, ja4Preview)
			return
		}
		// Limit map size to prevent memory exhaustion
		if len(seenJA4) >= maxSeenJA4 {
			// Clear oldest entries (simple reset - could use LRU for production)
			seenJA4 = make(map[string]bool)
			log.Printf("INFO: Cleared deduplication cache (reached %d entries)", maxSeenJA4)
		}
		seenJA4[key] = true
		seenJA4Mu.Unlock()
	}

	// Protect console output from interleaving with concurrent goroutines
	outputMu.Lock()
	defer outputMu.Unlock()

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("CAPTURED: %s %s on %s\n", browser, version, platform)
	fmt.Printf("JA3: %s\n", profile.JA3)
	fmt.Printf("JA4: %s\n", profile.JA4)
	fmt.Printf("Record Version: 0x%04x | Client Version: 0x%04x\n", profile.RecordVersion, profile.ClientVersion)

	// Display important feature flags
	var features []string
	if info.Mobile {
		features = append(features, "Mobile")
	}
	if profile.EarlyDataEnabled {
		features = append(features, "0-RTT")
	}
	if profile.PSKPresent {
		features = append(features, fmt.Sprintf("PSK(%d ids)", profile.PSKIdentitiesCount))
	}
	if profile.ECHEnabled {
		features = append(features, fmt.Sprintf("ECH(0x%04x)", profile.ECHType))
	}
	if profile.RenegotiationInfo {
		features = append(features, "Renegotiation")
	}
	if profile.ApplicationSettings {
		features = append(features, "ALPS-new")
	}
	if profile.ApplicationSettingsOld {
		features = append(features, "ALPS-old")
	}
	if profile.CookiePresent {
		features = append(features, "Cookie/HRR")
	}
	if len(features) > 0 {
		fmt.Printf("Features: %s\n", strings.Join(features, ", "))
	}

	if len(profile.ParseWarnings) > 0 {
		fmt.Printf("WARNINGS: %d parse issues\n", len(profile.ParseWarnings))
		for _, w := range profile.ParseWarnings {
			fmt.Printf("  - %s\n", w)
		}
	}
	fmt.Println(strings.Repeat("=", 80))

	// JSON output
	fmt.Println("\n--- JSON ---")
	j, jsonErr := json.MarshalIndent(profile, "", "  ")
	if jsonErr != nil {
		log.Printf("Failed to marshal profile to JSON: %v", jsonErr)
		fmt.Println("{\"error\": \"JSON marshaling failed\"}")
	} else {
		fmt.Println(string(j))
	}

	// Filter GREASE for Go code
	ciphersClean := filterGREASE(profile.CipherSuites)
	extsClean := filterGREASE(profile.Extensions)
	groupsClean := filterGREASE(profile.SupportedGroups)
	versClean := filterGREASE(profile.SupportedVers)
	keyShareGroupsClean := make([]uint16, 0)
	for _, ks := range profile.KeyShares {
		if !isGREASE(ks.Group) {
			keyShareGroupsClean = append(keyShareGroupsClean, ks.Group)
		}
	}

	// Go code output - generate proper profiles package format
	id := fmt.Sprintf("%s_%s_%s", strings.ToLower(browser), version, strings.ToLower(platform))

	// CamelCase variable name for Go
	varName := toCamelCase(browser) + version + toCamelCase(platform)

	// Determine if Chrome-based (needs ShuffleExtensions)
	isChromeBased := isChromiumBrowser(browser)
	shuffleLine := ""
	if isChromeBased {
		shuffleLine = "\n\t\tShuffleExtensions: true,"
	}

	goCode := fmt.Sprintf(`// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profiles

import tls "github.com/refraction-networking/utls"

// %s captured from real %s %s on %s
// JA3: %s
// JA4: %s
// JA4o: %s (original order)
var %s = &tls.FingerprintProfile{
	ID:          "%s",
	Browser:     "%s",
	Version:     %s,
	Platform:    "%s",
	Description: "Captured from real %s %s",

	ClientHello: tls.ClientHelloConfig{
		LegacyVersion: 0x%04x,

		CipherSuites: %s,

		ExtensionOrder: %s,

		SupportedGroups: %s,

		SignatureAlgorithms: %s,

		ALPNProtocols: %s,

		SupportedVersions: %s,

		KeyShareGroups: %s,

		PSKModes: %s,

		CertCompressionAlgos: %s,

		CompressionMethods: []uint8{0x00},

		SessionIDLength: %d,%s

		GREASE: tls.GREASEConfig{
			Enabled:            %v,
			CipherSuites:       %v,
			Extensions:         %v,
			SupportedGroups:    %v,
			SupportedVersions:  %v,
			KeyShare:           %v,
			ExtensionPositions: %s,
		},
	},

	Expected: tls.ExpectedFingerprints{
		JA3:  "%s",
		JA4:  "%s",
		JA4o: "%s",
	},
}
`,
		varName, browser, version, platform,
		profile.JA3,
		profile.JA4,
		profile.JA4o,
		varName,
		id,
		strings.ToLower(browser),
		version,
		strings.ToLower(platform),
		browser, version,
		profile.ClientVersion,
		formatUint16Slice(ciphersClean),
		formatUint16Slice(extsClean),
		formatUint16SliceCurveID(groupsClean),
		formatUint16SliceSigScheme(profile.SignatureAlgos),
		formatStringSlice(profile.ALPNProtocols),
		formatUint16Slice(versClean),
		formatUint16SliceCurveID(keyShareGroupsClean),
		formatUint8Slice(profile.PSKModes),
		formatUint16SliceCertComp(profile.CertCompressAlgs),
		profile.SessionIDLength,
		shuffleLine,
		profile.GREASE.CipherSuite != 0,
		profile.GREASE.CipherSuite != 0,
		len(profile.GREASE.Extensions) > 0,
		profile.GREASE.SupportedGroup != 0,
		profile.GREASE.SupportedVersion != 0,
		profile.GREASE.KeyShare != 0,
		formatIntSlice(profile.GREASE.ExtensionPos),
		profile.JA3,
		profile.JA4,
		profile.JA4o,
	)

	fmt.Println("\n--- Go Code (for u_fingerprint_registry.go) ---")
	fmt.Print(goCode)
	fmt.Println(strings.Repeat("=", 80))

	// Auto-save if enabled
	if autoSave {
		saveProfile(profile, info, goCode)
	}
}

// safeWriteFile writes data to a file after verifying the directory is not a symlink.
// This prevents TOCTOU symlink attacks where an attacker could replace the directory
// with a symlink between MkdirAll and WriteFile, causing arbitrary file writes.
func safeWriteFile(dir, filename string, data []byte, perm os.FileMode) error {
	// Use Lstat to get info about the directory itself, not what it points to
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("failed to stat directory %s: %w", dir, err)
	}

	// Check if it's a symlink
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("security: directory %s is a symlink, refusing to write", dir)
	}

	// Verify it's actually a directory
	if !info.IsDir() {
		return fmt.Errorf("security: path %s is not a directory", dir)
	}

	path := filepath.Join(dir, filename)
	return os.WriteFile(path, data, perm)
}

// saveProfile saves the captured profile to files
func saveProfile(profile *CapturedProfile, info BrowserInfo, goCode string) {
	// Protect file writes from concurrent goroutines writing to the same file.
	// Even with deduplication, different JA4 hashes can generate the same
	// browser/version/platform filename.
	fileMu.Lock()
	defer fileMu.Unlock()

	// Verify profilesDir exists before each save operation
	// This handles cases where the directory might have been deleted since startup
	if err := os.MkdirAll(profilesDir, 0755); err != nil {
		log.Printf("Failed to create/verify profiles directory %s: %v", profilesDir, err)
		return
	}

	// Sanitize browser name and version to prevent path traversal and filesystem issues
	safeBrowser := sanitizeFilename(info.Browser, maxBrowserNameLength)
	safeVersion := sanitizeFilename(fmt.Sprintf("%d", info.Version), maxVersionLength)
	safePlatform := sanitizeFilename(info.Platform, maxBrowserNameLength)

	if safeBrowser == "" {
		safeBrowser = "unknown"
	}
	if safePlatform == "" {
		safePlatform = "unknown"
	}

	// CamelCase filename to avoid Go GOOS build constraints
	filename := toCamelCase(safeBrowser) + safeVersion + toCamelCase(safePlatform)
	// Ensure filename is not too long for filesystem
	if len(filename) > maxFilenameLength {
		filename = filename[:maxFilenameLength]
	}

	// Save JSON (with original snake_case name for readability)
	jsonName := fmt.Sprintf("%s_%s_%s", strings.ToLower(safeBrowser), safeVersion, strings.ToLower(safePlatform))
	if len(jsonName) > maxFilenameLength {
		jsonName = jsonName[:maxFilenameLength]
	}
	jsonFilename := jsonName + ".json"
	jsonPath := filepath.Join(profilesDir, jsonFilename)
	jsonData, jsonErr := json.MarshalIndent(profile, "", "  ")
	if jsonErr != nil {
		log.Printf("Failed to marshal profile to JSON for %s: %v", jsonPath, jsonErr)
	} else {
		if err := safeWriteFile(profilesDir, jsonFilename, jsonData, 0644); err != nil {
			log.Printf("Failed to save JSON %s: %v", jsonPath, err)
		} else {
			log.Printf("Saved JSON: %s", jsonPath)
		}
	}

	// Save Go code with CamelCase filename
	goFilename := filename + ".go"
	goPath := filepath.Join(profilesDir, goFilename)
	if err := safeWriteFile(profilesDir, goFilename, []byte(goCode), 0644); err != nil {
		log.Printf("Failed to save Go code %s: %v", goPath, err)
	} else {
		log.Printf("Saved Go code: %s", goPath)
	}
}

// sanitizeFilename removes or replaces characters that are problematic for filenames.
// This prevents path traversal attacks and filesystem errors from malicious input.
func sanitizeFilename(s string, maxLen int) string {
	if s == "" {
		return ""
	}
	var result strings.Builder
	for _, r := range s {
		// Only allow alphanumeric, dash, underscore, and dot (but not leading dots)
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || (r == '.' && result.Len() > 0) {
			result.WriteRune(r)
		} else if r == ' ' {
			result.WriteRune('_')
		}
		// Skip path separators, control characters, and other problematic chars
		if result.Len() >= maxLen {
			break
		}
	}
	// Remove any trailing dots or spaces
	return strings.TrimRight(result.String(), ". ")
}

// toCamelCase converts a string to CamelCase
func toCamelCase(s string) string {
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(words, "")
}

// isChromiumBrowser returns true if browser is Chromium-based
func isChromiumBrowser(browser string) bool {
	b := strings.ToLower(browser)
	chromiumBrowsers := []string{"chrome", "edge", "opera", "brave", "vivaldi", "samsung", "yandex", "uc", "whale", "qq"}
	for _, cb := range chromiumBrowsers {
		if strings.Contains(b, cb) {
			return true
		}
	}
	return false
}

// formatUint16SliceCurveID formats as tls.CurveID type
func formatUint16SliceCurveID(values []uint16) string {
	if len(values) == 0 {
		return "[]tls.CurveID{}"
	}
	var sb strings.Builder
	sb.WriteString("[]tls.CurveID{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString("\t\t\t")
		}
		sb.WriteString(fmt.Sprintf("0x%04x,", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		} else if i < len(values)-1 {
			sb.WriteString(" ")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString("\t\t}")
	return sb.String()
}

// formatUint16SliceSigScheme formats as tls.SignatureScheme type
func formatUint16SliceSigScheme(values []uint16) string {
	if len(values) == 0 {
		return "[]tls.SignatureScheme{}"
	}
	var sb strings.Builder
	sb.WriteString("[]tls.SignatureScheme{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString("\t\t\t")
		}
		sb.WriteString(fmt.Sprintf("0x%04x,", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		} else if i < len(values)-1 {
			sb.WriteString(" ")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString("\t\t}")
	return sb.String()
}

// formatUint16SliceCertComp formats as tls.CertCompressionAlgo type
func formatUint16SliceCertComp(values []uint16) string {
	if len(values) == 0 {
		return "[]tls.CertCompressionAlgo{}"
	}
	var sb strings.Builder
	sb.WriteString("[]tls.CertCompressionAlgo{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString("\t\t\t")
		}
		sb.WriteString(fmt.Sprintf("0x%04x,", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		} else if i < len(values)-1 {
			sb.WriteString(" ")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString("\t\t}")
	return sb.String()
}

// formatIntSlice formats an int slice
func formatIntSlice(values []int) string {
	if len(values) == 0 {
		return "[]int{}"
	}
	strs := make([]string, len(values))
	for i, v := range values {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return "[]int{" + strings.Join(strs, ", ") + "}"
}

// parseUserAgentFull performs comprehensive User-Agent parsing
func parseUserAgentFull(ua string) BrowserInfo {
	info := BrowserInfo{
		Browser:  "Unknown",
		Platform: "Unknown",
		OS:       "Unknown",
	}

	if ua == "" {
		return info
	}

	uaLower := strings.ToLower(ua)

	// Detect if mobile
	info.Mobile = strings.Contains(uaLower, "mobile") ||
		strings.Contains(uaLower, "android") ||
		strings.Contains(uaLower, "iphone") ||
		strings.Contains(uaLower, "ipad")

	// Detect if bot/crawler
	info.Bot = strings.Contains(uaLower, "bot") ||
		strings.Contains(uaLower, "crawler") ||
		strings.Contains(uaLower, "spider") ||
		strings.Contains(uaLower, "curl") ||
		strings.Contains(uaLower, "wget")

	// Detect platform/OS first
	info.Platform, info.OS, info.OSVersion, info.Architecture = detectPlatform(ua, uaLower)

	// Detect browser (order matters - check specific browsers before generic ones)
	info.Browser, info.Version, info.VersionFull = detectBrowser(ua, uaLower)

	return info
}

// detectPlatform extracts platform, OS, version and architecture
func detectPlatform(ua, uaLower string) (platform, os, osVersion, arch string) {
	platform = "Unknown"
	os = "Unknown"
	arch = ""

	// Architecture detection
	if strings.Contains(uaLower, "x86_64") || strings.Contains(uaLower, "x64") ||
		strings.Contains(uaLower, "win64") || strings.Contains(uaLower, "amd64") {
		arch = "x64"
	} else if strings.Contains(uaLower, "arm64") || strings.Contains(uaLower, "aarch64") {
		arch = "arm64"
	} else if strings.Contains(uaLower, "i686") || strings.Contains(uaLower, "i386") ||
		strings.Contains(uaLower, "x86") {
		arch = "x86"
	}

	// iOS/iPadOS detection (check before Mac since iPad may spoof Mac)
	if strings.Contains(uaLower, "iphone") {
		platform = "iOS"
		os = "iOS"
		if v := extractVersionPattern(ua, `iPhone OS (\d+)[_.](\d+)`); v != "" {
			osVersion = strings.ReplaceAll(v, "_", ".")
		}
		return
	}

	if strings.Contains(uaLower, "ipad") {
		// Check if iPad is in desktop mode (spoofing macOS)
		if strings.Contains(uaLower, "macintosh") && strings.Contains(uaLower, "ipad") {
			platform = "iPadOS"
			os = "iPadOS"
		} else {
			platform = "iPadOS"
			os = "iPadOS"
		}
		if v := extractVersionPattern(ua, `OS (\d+)[_.](\d+)`); v != "" {
			osVersion = strings.ReplaceAll(v, "_", ".")
		}
		return
	}

	// Android detection
	if strings.Contains(uaLower, "android") {
		platform = "Android"
		os = "Android"
		if v := extractVersionPattern(ua, `Android (\d+)(?:\.(\d+))?`); v != "" {
			osVersion = v
		}
		return
	}

	// Windows detection
	if strings.Contains(uaLower, "windows") {
		os = "Windows"
		// Windows NT version mapping
		if strings.Contains(ua, "Windows NT 10.0") {
			// Windows 10 and 11 both report "Windows NT 10.0" - indistinguishable via UA
			// Using "Windows_10" as default since it's the more common fingerprint target
			// Note: "Win64" is present on BOTH Windows 10 and 11 64-bit, not a differentiator
			platform = "Windows_10"
			osVersion = "10"
		} else if strings.Contains(ua, "Windows NT 6.3") {
			platform = "Windows_8.1"
			osVersion = "8.1"
		} else if strings.Contains(ua, "Windows NT 6.2") {
			platform = "Windows_8"
			osVersion = "8"
		} else if strings.Contains(ua, "Windows NT 6.1") {
			platform = "Windows_7"
			osVersion = "7"
		} else {
			platform = "Windows"
		}
		return
	}

	// macOS detection (check after iOS/iPadOS)
	if strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os x") {
		platform = "macOS"
		os = "macOS"
		if v := extractVersionPattern(ua, `Mac OS X (\d+)[_.](\d+)`); v != "" {
			osVersion = strings.ReplaceAll(v, "_", ".")
		}
		return
	}

	// ChromeOS detection
	if strings.Contains(uaLower, "cros") {
		platform = "ChromeOS"
		os = "ChromeOS"
		return
	}

	// Linux detection (check after Android and ChromeOS)
	if strings.Contains(uaLower, "linux") {
		os = "Linux"
		// Try to detect specific distros
		switch {
		case strings.Contains(uaLower, "ubuntu"):
			platform = "Linux_Ubuntu"
		case strings.Contains(uaLower, "fedora"):
			platform = "Linux_Fedora"
		case strings.Contains(uaLower, "debian"):
			platform = "Linux_Debian"
		case strings.Contains(uaLower, "arch"):
			platform = "Linux_Arch"
		default:
			platform = "Linux"
		}
		return
	}

	// FreeBSD detection
	if strings.Contains(uaLower, "freebsd") {
		platform = "FreeBSD"
		os = "FreeBSD"
		return
	}

	return
}

// detectBrowser extracts browser name and version
func detectBrowser(ua, uaLower string) (browser string, version int, versionFull string) {
	browser = "Unknown"
	version = 0
	versionFull = "0"

	// Check for specific browsers in order of specificity

	// Brave (check before Chrome)
	if strings.Contains(uaLower, "brave") {
		browser = "Brave"
		versionFull = extractVersionAfter(ua, "Brave/")
		if versionFull == "0" {
			// Brave often uses Chrome version
			versionFull = extractVersionAfter(ua, "Chrome/")
		}
		version = extractMajorVersion(versionFull)
		return
	}

	// Vivaldi (check before Chrome)
	if strings.Contains(uaLower, "vivaldi") {
		browser = "Vivaldi"
		versionFull = extractVersionAfter(ua, "Vivaldi/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Opera (check before Chrome - uses OPR/)
	if strings.Contains(uaLower, "opr/") || strings.Contains(uaLower, "opera") {
		browser = "Opera"
		if strings.Contains(uaLower, "opr/") {
			versionFull = extractVersionAfter(ua, "OPR/")
		} else {
			versionFull = extractVersionAfter(ua, "Opera/")
		}
		version = extractMajorVersion(versionFull)
		return
	}

	// Edge iOS (check before regular Edge)
	if strings.Contains(uaLower, "edgios/") {
		browser = "Edge"
		versionFull = extractVersionAfter(ua, "EdgiOS/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Edge (check before Chrome)
	if strings.Contains(uaLower, "edg/") || strings.Contains(uaLower, "edge/") {
		browser = "Edge"
		if strings.Contains(uaLower, "edg/") {
			versionFull = extractVersionAfter(ua, "Edg/")
		} else {
			versionFull = extractVersionAfter(ua, "Edge/")
		}
		version = extractMajorVersion(versionFull)
		return
	}

	// Samsung Internet (check before Chrome)
	if strings.Contains(uaLower, "samsungbrowser") {
		browser = "Samsung_Internet"
		versionFull = extractVersionAfter(ua, "SamsungBrowser/")
		version = extractMajorVersion(versionFull)
		return
	}

	// UC Browser (check before Chrome)
	if strings.Contains(uaLower, "ucbrowser") {
		browser = "UC_Browser"
		versionFull = extractVersionAfter(ua, "UCBrowser/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Yandex Browser (check before Chrome)
	if strings.Contains(uaLower, "yabrowser") {
		browser = "Yandex"
		versionFull = extractVersionAfter(ua, "YaBrowser/")
		version = extractMajorVersion(versionFull)
		return
	}

	// QQ Browser (check before Chrome)
	if strings.Contains(uaLower, "qqbrowser") {
		browser = "QQ_Browser"
		versionFull = extractVersionAfter(ua, "QQBrowser/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Whale Browser (check before Chrome)
	if strings.Contains(uaLower, "whale") {
		browser = "Whale"
		versionFull = extractVersionAfter(ua, "Whale/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Firefox iOS (check before regular Firefox)
	if strings.Contains(uaLower, "fxios/") {
		browser = "Firefox"
		versionFull = extractVersionAfter(ua, "FxiOS/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Firefox (check for various Firefox variants)
	if strings.Contains(uaLower, "firefox/") {
		browser = "Firefox"
		versionFull = extractVersionAfter(ua, "Firefox/")
		version = extractMajorVersion(versionFull)
		// Check for Firefox variants
		if strings.Contains(uaLower, "focus") {
			browser = "Firefox_Focus"
		} else if strings.Contains(uaLower, "klar") {
			browser = "Firefox_Klar"
		}
		return
	}

	// Chrome iOS (check before Safari and regular Chrome)
	if strings.Contains(uaLower, "crios/") {
		browser = "Chrome"
		versionFull = extractVersionAfter(ua, "CriOS/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Safari (real Safari, not iOS wrappers)
	if strings.Contains(uaLower, "safari/") &&
		!strings.Contains(uaLower, "chrome") &&
		!strings.Contains(uaLower, "chromium") &&
		!strings.Contains(uaLower, "fxios") &&
		!strings.Contains(uaLower, "crios") &&
		!strings.Contains(uaLower, "edgios") {
		browser = "Safari"
		versionFull = extractVersionAfter(ua, "Version/")
		version = extractMajorVersion(versionFull)
		return
	}

	// Chrome (check last among Chromium-based browsers)
	if strings.Contains(uaLower, "chrome/") || strings.Contains(uaLower, "chromium/") {
		if strings.Contains(uaLower, "chromium/") {
			browser = "Chromium"
			versionFull = extractVersionAfter(ua, "Chromium/")
		} else {
			browser = "Chrome"
			versionFull = extractVersionAfter(ua, "Chrome/")
		}
		version = extractMajorVersion(versionFull)
		return
	}

	// curl/wget/other command-line tools
	if strings.Contains(uaLower, "curl") {
		browser = "curl"
		versionFull = extractVersionAfter(ua, "curl/")
		version = extractMajorVersion(versionFull)
		return
	}
	if strings.Contains(uaLower, "wget") {
		browser = "wget"
		versionFull = extractVersionAfter(ua, "Wget/")
		version = extractMajorVersion(versionFull)
		return
	}

	return
}

// extractVersionPattern uses regex to extract version
func extractVersionPattern(ua, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(ua)
	if len(matches) >= 2 {
		version := matches[1]
		if len(matches) >= 3 && matches[2] != "" {
			version += "." + matches[2]
		}
		return version
	}
	return ""
}

// extractMajorVersion extracts the major version number from a version string
func extractMajorVersion(versionFull string) int {
	if versionFull == "" || versionFull == "0" {
		return 0
	}
	// Find first dot or end
	var numStr strings.Builder
	for _, c := range versionFull {
		if c >= '0' && c <= '9' {
			numStr.WriteRune(c)
		} else {
			break
		}
	}
	if numStr.Len() == 0 {
		return 0
	}
	var v int
	fmt.Sscanf(numStr.String(), "%d", &v)
	return v
}

// extractVersionAfter extracts a full version string (e.g., "142.0.6935.85") after a prefix
func extractVersionAfter(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return "0"
	}
	s = s[idx+len(prefix):]
	var ver strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' || c == '.' {
			ver.WriteRune(c)
		} else if c == ' ' || c == ')' || c == ';' {
			break
		}
	}
	result := ver.String()
	// Trim trailing dots
	result = strings.TrimRight(result, ".")
	if result == "" {
		return "0"
	}
	return result
}

func formatUint16Slice(values []uint16) string {
	if len(values) == 0 {
		return "[]uint16{}"
	}
	var sb strings.Builder
	sb.WriteString("[]uint16{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString("\t\t\t")
		}
		sb.WriteString(fmt.Sprintf("0x%04x,", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		} else if i < len(values)-1 {
			sb.WriteString(" ")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString("\t\t}")
	return sb.String()
}

func formatUint8Slice(values []uint8) string {
	if len(values) == 0 {
		return "[]uint8{}"
	}
	strs := make([]string, len(values))
	for i, v := range values {
		strs[i] = fmt.Sprintf("0x%02x", v)
	}
	return "[]uint8{" + strings.Join(strs, ", ") + "}"
}

func formatStringSlice(values []string) string {
	if len(values) == 0 {
		return "[]string{}"
	}
	strs := make([]string, len(values))
	for i, v := range values {
		// Use %q for proper escaping of special characters (quotes, backslashes, etc.)
		// This ensures the generated Go code is syntactically valid
		strs[i] = fmt.Sprintf("%q", v)
	}
	return "[]string{" + strings.Join(strs, ", ") + "}"
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"uTLS Fingerprint Capture"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
