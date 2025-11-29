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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// CapturedProfile holds the raw data captured from a ClientHello
type CapturedProfile struct {
	Timestamp        time.Time `json:"timestamp"`
	UserAgent        string    `json:"user_agent"`
	RemoteAddr       string    `json:"remote_addr"`
	TLSVersion       uint16    `json:"tls_version"`
	CipherSuites     []uint16  `json:"cipher_suites"`
	Extensions       []uint16  `json:"extensions"`
	SupportedGroups  []uint16  `json:"supported_groups"`
	ECPointFormats   []uint8   `json:"ec_point_formats"` // For JA3
	SignatureAlgos   []uint16  `json:"signature_algorithms"`
	ALPNProtocols    []string  `json:"alpn_protocols"`
	ServerName       string    `json:"server_name"`
	SupportedVers    []uint16  `json:"supported_versions"`
	KeyShareGroups   []uint16  `json:"key_share_groups"`
	PSKModes         []uint8   `json:"psk_modes"`
	CertCompressAlgs []uint16  `json:"cert_compression_algs"`

	// Raw bytes for verification
	RawClientHello []byte `json:"-"`

	// Computed fingerprints
	JA3  string `json:"ja3"`
	JA4  string `json:"ja4"`
	JA4r string `json:"ja4_raw"`
}

var (
	captures   []CapturedProfile
	capturesMu sync.Mutex
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Generate self-signed certificate
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	log.Println("===========================================")
	log.Println("TLS Fingerprint Capture Server")
	log.Println("===========================================")
	log.Println("Listening on https://0.0.0.0:443 (all interfaces)")
	log.Println("")
	log.Println("Access URLs:")
	log.Println("  Local:    https://localhost")
	log.Println("  External: https://<your-domain>")
	log.Println("")
	log.Println("Instructions:")
	log.Println("1. Open different browsers (Chrome, Firefox, Safari, Edge)")
	log.Println("2. Navigate to the URL above")
	log.Println("3. Accept the self-signed certificate warning")
	log.Println("4. Check this console for captured profiles")
	log.Println("")
	log.Println("For Selenium automation, use:")
	log.Println("  Chrome: --ignore-certificate-errors")
	log.Println("  Firefox: acceptInsecureCerts capability")
	log.Println("===========================================")

	// Create raw TCP listener to capture ClientHello
	ln, err := net.Listen("tcp", ":443")
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

	// Skip TLS record header (5 bytes) and handshake header (4 bytes)
	data := raw[5+4:]

	profile := &CapturedProfile{}

	if len(data) < 2+32+1 {
		return nil, fmt.Errorf("too short for version+random+session")
	}

	// Client version (2 bytes)
	profile.TLSVersion = uint16(data[0])<<8 | uint16(data[1])
	data = data[2:]

	// Random (32 bytes)
	data = data[32:]

	// Session ID
	sessionLen := int(data[0])
	if len(data) < 1+sessionLen {
		return nil, fmt.Errorf("session ID length overflow: need %d, have %d", 1+sessionLen, len(data))
	}
	data = data[1+sessionLen:]

	// Cipher suites
	if len(data) < 2 {
		return nil, fmt.Errorf("too short for cipher suites length")
	}
	cipherLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	if len(data) < cipherLen {
		return nil, fmt.Errorf("too short for cipher suites")
	}
	if cipherLen%2 != 0 {
		return nil, fmt.Errorf("odd cipher suites length: %d", cipherLen)
	}

	for i := 0; i < cipherLen; i += 2 {
		cs := uint16(data[i])<<8 | uint16(data[i+1])
		profile.CipherSuites = append(profile.CipherSuites, cs)
	}
	data = data[cipherLen:]

	// Compression methods
	if len(data) < 1 {
		return nil, fmt.Errorf("too short for compression")
	}
	compLen := int(data[0])
	if len(data) < 1+compLen {
		return nil, fmt.Errorf("compression methods length overflow: need %d, have %d", 1+compLen, len(data))
	}
	data = data[1+compLen:]

	// Extensions
	if len(data) < 2 {
		// No extensions
		return profile, nil
	}
	extLen := int(data[0])<<8 | int(data[1])
	data = data[2:]

	if len(data) < extLen {
		return nil, fmt.Errorf("too short for extensions")
	}

	extData := data[:extLen]
	for len(extData) >= 4 {
		extType := uint16(extData[0])<<8 | uint16(extData[1])
		extDataLen := int(extData[2])<<8 | int(extData[3])
		extData = extData[4:]

		if len(extData) < extDataLen {
			break
		}

		profile.Extensions = append(profile.Extensions, extType)

		// Parse specific extensions
		extPayload := extData[:extDataLen]
		switch extType {
		case 0x0000: // server_name (SNI)
			// Format: list_length(2) + name_type(1) + name_length(2) + name
			if len(extPayload) >= 5 {
				// listLen := int(extPayload[0])<<8 | int(extPayload[1])
				nameType := extPayload[2]
				if nameType != 0 { // 0 = host_name, only valid type
					break
				}
				nameLen := int(extPayload[3])<<8 | int(extPayload[4])
				if len(extPayload) >= 5+nameLen {
					profile.ServerName = string(extPayload[5 : 5+nameLen])
				}
			}
		case 0x000a: // supported_groups
			if len(extPayload) >= 2 {
				groupLen := int(extPayload[0])<<8 | int(extPayload[1])
				for i := 2; i < 2+groupLen && i+1 < len(extPayload); i += 2 {
					g := uint16(extPayload[i])<<8 | uint16(extPayload[i+1])
					profile.SupportedGroups = append(profile.SupportedGroups, g)
				}
			}
		case 0x000b: // ec_point_formats (for JA3)
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
					s := uint16(extPayload[i])<<8 | uint16(extPayload[i+1])
					profile.SignatureAlgos = append(profile.SignatureAlgos, s)
				}
			}
		case 0x0010: // ALPN
			if len(extPayload) >= 2 {
				alpnLen := int(extPayload[0])<<8 | int(extPayload[1])
				if len(extPayload) < 2+alpnLen {
					break // Not enough data
				}
				alpnData := extPayload[2 : 2+alpnLen]
				for len(alpnData) > 0 {
					protoLen := int(alpnData[0])
					if len(alpnData) < 1+protoLen {
						break
					}
					profile.ALPNProtocols = append(profile.ALPNProtocols, string(alpnData[1:1+protoLen]))
					alpnData = alpnData[1+protoLen:]
				}
			}
		case 0x002b: // supported_versions
			if len(extPayload) >= 1 {
				versLen := int(extPayload[0])
				for i := 1; i < 1+versLen && i+1 < len(extPayload); i += 2 {
					v := uint16(extPayload[i])<<8 | uint16(extPayload[i+1])
					profile.SupportedVers = append(profile.SupportedVers, v)
				}
			}
		case 0x0033: // key_share
			if len(extPayload) >= 2 {
				ksLen := int(extPayload[0])<<8 | int(extPayload[1])
				if len(extPayload) < 2+ksLen {
					break // Not enough data
				}
				ksData := extPayload[2 : 2+ksLen]
				for len(ksData) >= 4 {
					group := uint16(ksData[0])<<8 | uint16(ksData[1])
					keyLen := int(ksData[2])<<8 | int(ksData[3])
					profile.KeyShareGroups = append(profile.KeyShareGroups, group)
					if len(ksData) < 4+keyLen {
						break
					}
					ksData = ksData[4+keyLen:]
				}
			}
		case 0x002d: // psk_key_exchange_modes
			if len(extPayload) >= 1 {
				modeLen := int(extPayload[0])
				for i := 1; i < 1+modeLen && i < len(extPayload); i++ {
					profile.PSKModes = append(profile.PSKModes, extPayload[i])
				}
			}
		case 0x001b: // compress_certificate
			if len(extPayload) >= 1 {
				algLen := int(extPayload[0])
				for i := 1; i < 1+algLen && i+1 < len(extPayload); i += 2 {
					a := uint16(extPayload[i])<<8 | uint16(extPayload[i+1])
					profile.CertCompressAlgs = append(profile.CertCompressAlgs, a)
				}
			}
		}

		extData = extData[extDataLen:]
	}

	// Calculate JA3
	profile.JA3 = calculateJA3(profile)

	// Calculate JA4
	profile.JA4, profile.JA4r = calculateJA4(profile)

	return profile, nil
}

func calculateJA3(p *CapturedProfile) string {
	// JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	// Fields separated by comma, values within field separated by dash
	// Uses MD5 hash

	// Filter out GREASE values
	ciphers := filterGREASE(p.CipherSuites)
	extensions := filterGREASE(p.Extensions)
	groups := filterGREASE(p.SupportedGroups)

	// EC Point Formats (extension 0x000b) - no GREASE in these
	pointFormats := p.ECPointFormats

	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s",
		p.TLSVersion,
		joinUint16(ciphers, "-"),
		joinUint16(extensions, "-"),
		joinUint16(groups, "-"),
		joinUint8(pointFormats, "-"),
	)

	// JA3 uses MD5 hash
	hash := md5.Sum([]byte(ja3String))
	return hex.EncodeToString(hash[:])
}

func calculateJA4(p *CapturedProfile) (ja4, ja4r string) {
	// JA4 = {a}_{b}_{c}
	// a = protocol + version + SNI + cipher_count + ext_count + ALPN
	// b = hash of sorted ciphers
	// c = hash of sorted extensions (without SNI/ALPN)

	// Filter GREASE
	ciphers := filterGREASE(p.CipherSuites)
	extensions := filterGREASE(p.Extensions)

	// Protocol (t=TCP, q=QUIC)
	proto := "t"

	// TLS Version - skip GREASE values to find real version
	var tlsVer string
	var realVersion uint16
	for _, v := range p.SupportedVers {
		if !isGREASE(v) {
			realVersion = v
			break
		}
	}
	if realVersion == 0 {
		realVersion = p.TLSVersion
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
		tlsVer = "00"
	}

	// SNI indicator
	sni := "i" // IP address
	if p.ServerName != "" {
		sni = "d" // domain
	}

	// Cipher count (2 digits)
	cipherCount := len(ciphers)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (2 digits)
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

	// JA4_a
	ja4a := fmt.Sprintf("%s%s%s%02d%02d%s", proto, tlsVer, sni, cipherCount, extCount, alpn)

	// JA4_b: sorted ciphers hash
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherStr := joinUint16Hex(sortedCiphers, ",")
	cipherHash := sha256.Sum256([]byte(cipherStr))
	ja4b := hex.EncodeToString(cipherHash[:])[:12]

	// JA4_c: sorted extensions hash (without SNI 0x0000 and ALPN 0x0010)
	filteredExts := make([]uint16, 0, len(extensions))
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 {
			filteredExts = append(filteredExts, e)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })
	extStr := joinUint16Hex(filteredExts, ",")
	var ja4c string
	if extStr == "" {
		ja4c = "000000000000"
	} else {
		extHash := sha256.Sum256([]byte(extStr))
		ja4c = hex.EncodeToString(extHash[:])[:12]
	}

	ja4 = fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)
	ja4r = fmt.Sprintf("%s_%s_%s", ja4a, cipherStr, extStr)

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
</html>`, profile.JA3, profile.JA4, profile.UserAgent)

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Connection: close\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" +
		body

	conn.Write([]byte(response))

	// Store and output
	capturesMu.Lock()
	captures = append(captures, *profile)
	capturesMu.Unlock()

	outputProfile(profile)
}

func outputProfile(profile *CapturedProfile) {
	browser, version, platform := parseUserAgent(profile.UserAgent)

	// Recalculate JA4 with proper version detection
	profile.JA4, profile.JA4r = calculateJA4(profile)

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("CAPTURED: %s %s on %s\n", browser, version, platform)
	fmt.Printf("JA3: %s\n", profile.JA3)
	fmt.Printf("JA4: %s\n", profile.JA4)
	fmt.Println(strings.Repeat("=", 80))

	// JSON output (raw, includes GREASE)
	fmt.Println("\n--- JSON (raw with GREASE) ---")
	j, _ := json.MarshalIndent(profile, "", "  ")
	fmt.Println(string(j))

	// Filter GREASE for Go code output
	filtered := filterGREASEFromProfile(profile)

	// Go code output
	id := fmt.Sprintf("%s_%s_%s", strings.ToLower(browser), version, strings.ToLower(platform))

	fmt.Println("\n--- Go Code (for u_fingerprint_registry.go) ---")
	fmt.Printf(`
// %s captured from real %s %s on %s
// JA3: %s
// JA4: %s
var %s = &FingerprintProfile{
    ID:          "%s",
    Browser:     "%s",
    Version:     %s,
    Platform:    "%s",
    Description: "Captured from real %s %s",

    ClientHello: ClientHelloConfig{
        TLSVersionMin: 0x%04x,
        TLSVersionMax: 0x%04x,

        CipherSuites: %s,

        Extensions: %s,

        SupportedGroups: %s,

        SignatureAlgorithms: %s,

        ALPNProtocols: %s,

        SupportedVersions: %s,

        KeyShareGroups: %s,

        PSKModes: %s,

        CertCompressionAlgs: %s,
    },

    Expected: ExpectedFingerprints{
        JA3: "%s",
        JA4: "%s",
    },
}
`,
		id, browser, version, platform,
		profile.JA3,
		profile.JA4,
		id,
		id,
		strings.ToLower(browser),
		version,
		strings.ToLower(platform),
		browser, version,
		filtered.TLSVersion,
		getMaxVersion(filtered),
		formatUint16Slice("        ", filtered.CipherSuites),
		formatUint16Slice("        ", filtered.Extensions),
		formatUint16Slice("        ", filtered.SupportedGroups),
		formatUint16Slice("        ", filtered.SignatureAlgos),
		formatStringSlice(filtered.ALPNProtocols),
		formatUint16Slice("        ", filtered.SupportedVers),
		formatUint16Slice("        ", filtered.KeyShareGroups),
		formatUint8Slice(filtered.PSKModes),
		formatUint16Slice("        ", filtered.CertCompressAlgs),
		profile.JA3,
		profile.JA4,
	)

	fmt.Println(strings.Repeat("=", 80))
}

func getMaxVersion(p *CapturedProfile) uint16 {
	// Skip GREASE values to find real max version
	for _, v := range p.SupportedVers {
		if !isGREASE(v) {
			return v
		}
	}
	return p.TLSVersion
}

func filterGREASEFromProfile(p *CapturedProfile) *CapturedProfile {
	// Create a copy with GREASE filtered out for the profile definition
	filtered := &CapturedProfile{
		Timestamp:        p.Timestamp,
		UserAgent:        p.UserAgent,
		RemoteAddr:       p.RemoteAddr,
		TLSVersion:       p.TLSVersion,
		ServerName:       p.ServerName,
		ALPNProtocols:    p.ALPNProtocols,
		JA3:              p.JA3,
		JA4:              p.JA4,
		JA4r:             p.JA4r,
		RawClientHello:   p.RawClientHello,
		CipherSuites:     filterGREASE(p.CipherSuites),
		Extensions:       filterGREASE(p.Extensions),
		SupportedGroups:  filterGREASE(p.SupportedGroups),
		ECPointFormats:   p.ECPointFormats, // No GREASE in EC point formats
		SignatureAlgos:   p.SignatureAlgos, // No GREASE in sig algos
		SupportedVers:    filterGREASE(p.SupportedVers),
		KeyShareGroups:   filterGREASE(p.KeyShareGroups),
		PSKModes:         p.PSKModes,
		CertCompressAlgs: p.CertCompressAlgs,
	}
	return filtered
}

func parseUserAgent(ua string) (browser, version, platform string) {
	uaLower := strings.ToLower(ua)

	// Detect browser
	switch {
	case strings.Contains(uaLower, "firefox/"):
		browser = "Firefox"
		version = extractVersionAfter(ua, "Firefox/")
	case strings.Contains(uaLower, "edg/"):
		browser = "Edge"
		version = extractVersionAfter(ua, "Edg/")
	case strings.Contains(uaLower, "opr/"):
		browser = "Opera"
		version = extractVersionAfter(ua, "OPR/")
	case strings.Contains(uaLower, "chrome/"):
		browser = "Chrome"
		version = extractVersionAfter(ua, "Chrome/")
	case strings.Contains(uaLower, "safari/") && !strings.Contains(uaLower, "chrome"):
		browser = "Safari"
		version = extractVersionAfter(ua, "Version/")
	default:
		browser = "Unknown"
		version = "0"
	}

	// Detect platform
	switch {
	case strings.Contains(uaLower, "windows nt 10"):
		platform = "Windows_10"
	case strings.Contains(uaLower, "windows nt 11") || strings.Contains(ua, "Windows NT 10.0; Win64"):
		platform = "Windows_11"
	case strings.Contains(uaLower, "windows"):
		platform = "Windows"
	case strings.Contains(uaLower, "mac os x"):
		platform = "macOS"
	case strings.Contains(uaLower, "linux"):
		platform = "Linux"
	case strings.Contains(uaLower, "android"):
		platform = "Android"
	case strings.Contains(uaLower, "iphone"):
		platform = "iOS"
	case strings.Contains(uaLower, "ipad"):
		platform = "iPadOS"
	default:
		platform = "Unknown"
	}

	return
}

func extractVersionAfter(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return "0"
	}
	s = s[idx+len(prefix):]
	var ver strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			ver.WriteRune(c)
		} else if c == '.' || c == ' ' || c == ')' {
			break
		}
	}
	if ver.Len() == 0 {
		return "0"
	}
	return ver.String()
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
	sb.WriteString(indent[:len(indent)-4] + "}")
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
		return tls.Certificate{}, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

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
