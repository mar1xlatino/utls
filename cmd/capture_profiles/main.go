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
// Focused on fingerprint-relevant data only, no bloat
type CapturedProfile struct {
	// Metadata
	Timestamp  time.Time `json:"timestamp"`
	UserAgent  string    `json:"user_agent"`
	RemoteAddr string    `json:"remote_addr"`

	// ClientHello Core Fields
	ClientVersion   uint16 `json:"client_version"`    // Legacy version (usually 0x0303)
	SessionIDLength int    `json:"session_id_length"` // 0 or 32, content doesn't matter

	// Cipher Suites (order matters for fingerprinting)
	CipherSuites []uint16 `json:"cipher_suites"` // With GREASE

	// Compression Methods
	CompressionMethods []uint8 `json:"compression_methods"`

	// Extensions (order matters!)
	Extensions []uint16 `json:"extensions"` // With GREASE, original order

	// GREASE Tracking (critical for accurate replay)
	GREASE GREASEInfo `json:"grease"`

	// Parsed Extension Data
	ServerName      string   `json:"server_name"`
	SupportedGroups []uint16 `json:"supported_groups"` // With GREASE
	ECPointFormats  []uint8  `json:"ec_point_formats"`
	SignatureAlgos  []uint16 `json:"signature_algorithms"`
	ALPNProtocols   []string `json:"alpn_protocols"`
	SupportedVers   []uint16 `json:"supported_versions"` // With GREASE
	KeyShares       []KeyShareEntry `json:"key_shares"`
	PSKModes        []uint8  `json:"psk_modes"`
	CertCompressAlgs []uint16 `json:"cert_compression_algs"`

	// Extension Flags (presence detection)
	StatusRequest        bool `json:"status_request"`         // OCSP (0x0005)
	SCTEnabled           bool `json:"sct_enabled"`            // SCT (0x0012)
	ExtendedMasterSecret bool `json:"extended_master_secret"` // EMS (0x0017)
	PostHandshakeAuth    bool `json:"post_handshake_auth"`    // PHA (0x0031)
	DelegatedCredentials bool `json:"delegated_credentials"`  // (0x0022)
	ApplicationSettings  bool `json:"application_settings"`   // ALPS (0x44cd)
	ECHEnabled           bool `json:"ech_enabled"`            // ECH present

	// Extension Values (when length/value matters)
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
	maxCaptures = 10000 // Limit memory growth
	maxSeenJA4  = 50000 // Limit deduplication map size
)

var (
	captures      []CapturedProfile
	capturesMu    sync.Mutex
	seenJA4       = make(map[string]bool) // Deduplicate by JA4
	seenJA4Mu     sync.Mutex
	profilesDir   string
	autoSave      bool
	deduplicateUA bool
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

func readClientHello(conn net.Conn) ([]byte, error) {
	reader := bufio.NewReader(conn)

	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Verify it's a handshake record
	if header[0] != 0x16 { // Handshake
		return nil, fmt.Errorf("not a handshake record: 0x%02x", header[0])
	}

	// Get record length
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 {
		return nil, fmt.Errorf("record too large: %d", recordLen)
	}

	// Read the handshake message
	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}

	// Verify it's a ClientHello
	if len(payload) < 4 || payload[0] != 0x01 { // ClientHello
		return nil, fmt.Errorf("not a ClientHello: 0x%02x", payload[0])
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

	// Session ID - only length matters
	profile.SessionIDLength = int(data[0])
	if len(data) < 1+profile.SessionIDLength {
		return nil, fmt.Errorf("session ID length overflow")
	}
	data = data[1+profile.SessionIDLength:]

	// Cipher suites
	if len(data) < 2 {
		return nil, fmt.Errorf("too short for cipher suites")
	}
	cipherLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	if len(data) < cipherLen || cipherLen%2 != 0 {
		return nil, fmt.Errorf("invalid cipher suites")
	}

	for i := 0; i < cipherLen; i += 2 {
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
		return nil, fmt.Errorf("too short for compression")
	}
	compLen := int(data[0])
	if len(data) < 1+compLen {
		return nil, fmt.Errorf("compression overflow")
	}
	for i := 1; i <= compLen; i++ {
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
	for len(extData) >= 4 {
		extType := uint16(extData[0])<<8 | uint16(extData[1])
		extDataLen := int(extData[2])<<8 | int(extData[3])
		extData = extData[4:]

		if len(extData) < extDataLen {
			profile.ParseWarnings = append(profile.ParseWarnings,
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
			if len(extPayload) >= 5 && extPayload[2] == 0 {
				nameLen := int(extPayload[3])<<8 | int(extPayload[4])
				if len(extPayload) >= 5+nameLen {
					profile.ServerName = string(extPayload[5 : 5+nameLen])
				}
			}

		case 0x0005: // status_request
			profile.StatusRequest = true

		case 0x000a: // supported_groups
			if len(extPayload) >= 2 {
				groupLen := int(extPayload[0])<<8 | int(extPayload[1])
				groupIdx := 0
				for i := 2; i < 2+groupLen && i+1 < len(extPayload); i += 2 {
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
				for i := 2; i < 2+sigLen && i+1 < len(extPayload); i += 2 {
					profile.SignatureAlgos = append(profile.SignatureAlgos, uint16(extPayload[i])<<8|uint16(extPayload[i+1]))
				}
			}

		case 0x0010: // ALPN
			if len(extPayload) >= 2 {
				alpnLen := int(extPayload[0])<<8 | int(extPayload[1])
				if len(extPayload) >= 2+alpnLen {
					alpnData := extPayload[2 : 2+alpnLen]
					for len(alpnData) > 0 {
						protoLen := int(alpnData[0])
						if len(alpnData) < 1+protoLen {
							profile.ParseWarnings = append(profile.ParseWarnings,
								fmt.Sprintf("ALPN protocol truncated: need %d bytes, have %d", 1+protoLen, len(alpnData)))
							break
						}
						profile.ALPNProtocols = append(profile.ALPNProtocols, string(alpnData[1:1+protoLen]))
						alpnData = alpnData[1+protoLen:]
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
				versIdx := 0
				for i := 1; i < 1+versLen && i+1 < len(extPayload); i += 2 {
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
							profile.ParseWarnings = append(profile.ParseWarnings,
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

		case 0x44cd: // ALPS
			profile.ApplicationSettings = true

		case 0xfe0d, 0xfe09, 0xfe0a, 0xfe08: // ECH variants
			profile.ECHEnabled = true
		}

		extData = extData[extDataLen:]
		extIndex++
	}

	// Calculate fingerprints
	profile.JA3, profile.JA3r = calculateJA3Full(profile)
	profile.JA4, profile.JA4r, profile.JA4o, profile.JA4ro = calculateJA4Full(profile)

	return profile, nil
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
	case 0x0304:
		tlsVer = "13"
	case 0x0303:
		tlsVer = "12"
	case 0x0302:
		tlsVer = "11"
	case 0x0301:
		tlsVer = "10"
	default:
		// Handle draft TLS 1.3 versions (0x7f01 - 0x7f1c)
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
	alpn := "00"
	if len(p.ALPNProtocols) > 0 {
		first := p.ALPNProtocols[0]
		if len(first) > 0 {
			alpn = string(first[0]) + string(first[len(first)-1])
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
	reader := bufio.NewReader(conn)

	// Read HTTP request line
	_, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// Read headers to get User-Agent
	for {
		header, err := reader.ReadString('\n')
		if err != nil || header == "\r\n" || header == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(header), "user-agent:") {
			profile.UserAgent = strings.TrimSpace(header[11:])
		}
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

	conn.Write([]byte(response))

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

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("CAPTURED: %s %s on %s\n", browser, version, platform)
	fmt.Printf("JA3: %s\n", profile.JA3)
	fmt.Printf("JA4: %s\n", profile.JA4)
	if info.Mobile {
		fmt.Println("Mobile: Yes")
	}
	if profile.ECHEnabled {
		fmt.Println("ECH: Yes")
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
	j, _ := json.MarshalIndent(profile, "", "  ")
	fmt.Println(string(j))

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
		formatUint16Slice("\t\t", ciphersClean),
		formatUint16Slice("\t\t", extsClean),
		formatUint16SliceCurveID("\t\t", groupsClean),
		formatUint16SliceSigScheme("\t\t", profile.SignatureAlgos),
		formatStringSlice(profile.ALPNProtocols),
		formatUint16Slice("\t\t", versClean),
		formatUint16SliceCurveID("\t\t", keyShareGroupsClean),
		formatUint8Slice(profile.PSKModes),
		formatUint16SliceCertComp("\t\t", profile.CertCompressAlgs),
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

// saveProfile saves the captured profile to files
func saveProfile(profile *CapturedProfile, info BrowserInfo, goCode string) {
	// CamelCase filename to avoid Go GOOS build constraints
	filename := toCamelCase(info.Browser) + fmt.Sprintf("%d", info.Version) + toCamelCase(info.Platform)

	// Save JSON (with original snake_case name for readability)
	jsonName := fmt.Sprintf("%s_%d_%s", strings.ToLower(info.Browser), info.Version, strings.ToLower(info.Platform))
	jsonName = strings.ReplaceAll(jsonName, " ", "_")
	jsonPath := filepath.Join(profilesDir, jsonName+".json")
	jsonData, _ := json.MarshalIndent(profile, "", "  ")
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		log.Printf("Failed to save JSON: %v", err)
	} else {
		log.Printf("Saved JSON: %s", jsonPath)
	}

	// Save Go code with CamelCase filename
	goPath := filepath.Join(profilesDir, filename+".go")
	if err := os.WriteFile(goPath, []byte(goCode), 0644); err != nil {
		log.Printf("Failed to save Go code: %v", err)
	} else {
		log.Printf("Saved Go code: %s", goPath)
	}
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

// dedentOne removes one level of indentation (tab or 4 spaces)
func dedentOne(indent string) string {
	if strings.HasSuffix(indent, "\t") {
		return strings.TrimSuffix(indent, "\t")
	}
	if len(indent) >= 4 {
		return indent[:len(indent)-4]
	}
	return ""
}

// formatUint16SliceCurveID formats as tls.CurveID type
func formatUint16SliceCurveID(indent string, values []uint16) string {
	if len(values) == 0 {
		return "[]tls.CurveID{}"
	}
	var sb strings.Builder
	sb.WriteString("[]tls.CurveID{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString(indent)
		}
		sb.WriteString(fmt.Sprintf("0x%04x, ", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString(dedentOne(indent) + "}")
	return sb.String()
}

// formatUint16SliceSigScheme formats as tls.SignatureScheme type
func formatUint16SliceSigScheme(indent string, values []uint16) string {
	if len(values) == 0 {
		return "[]tls.SignatureScheme{}"
	}
	var sb strings.Builder
	sb.WriteString("[]tls.SignatureScheme{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString(indent)
		}
		sb.WriteString(fmt.Sprintf("0x%04x, ", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString(dedentOne(indent) + "}")
	return sb.String()
}

// formatUint16SliceCertComp formats as tls.CertCompressionAlgo type
func formatUint16SliceCertComp(indent string, values []uint16) string {
	if len(values) == 0 {
		return "[]tls.CertCompressionAlgo{}"
	}
	var sb strings.Builder
	sb.WriteString("[]tls.CertCompressionAlgo{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString(indent)
		}
		sb.WriteString(fmt.Sprintf("0x%04x, ", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString(dedentOne(indent) + "}")
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
			// Windows 10 or 11 - hard to distinguish, but recent builds are likely 11
			// Windows 11 build numbers start at 22000
			if strings.Contains(ua, "Windows NT 10.0; Win64") {
				platform = "Windows_11"
				osVersion = "11"
			} else {
				platform = "Windows_10"
				osVersion = "10"
			}
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

func formatUint16Slice(indent string, values []uint16) string {
	if len(values) == 0 {
		return "[]uint16{}"
	}
	var sb strings.Builder
	sb.WriteString("[]uint16{\n")
	for i, v := range values {
		if i%8 == 0 {
			sb.WriteString(indent)
		}
		sb.WriteString(fmt.Sprintf("0x%04x, ", v))
		if (i+1)%8 == 0 {
			sb.WriteString("\n")
		}
	}
	if len(values)%8 != 0 {
		sb.WriteString("\n")
	}
	sb.WriteString(dedentOne(indent) + "}")
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
		strs[i] = fmt.Sprintf(`"%s"`, v)
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
