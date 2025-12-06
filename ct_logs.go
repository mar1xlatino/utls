// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"sync"
)

// This file contains the known CT log public keys.
// The list is compiled from Google's CT log list:
// https://www.gstatic.com/ct/log_list/v3/log_list.json
//
// Each log is identified by the SHA-256 hash of its SubjectPublicKeyInfo.
// These logs are operated by major vendors and are trusted by browsers.
//
// Note: CT logs have limited lifetimes. Logs may be retired or new logs added.
// For production use, consider periodically updating this list from the
// authoritative source.

// DefaultCTLogs contains the known CT logs used for SCT validation.
// Populated during init() from the knownCTLogs list.
var DefaultCTLogs = make(map[[32]byte]*CTLogInfo)

func init() {
	// Initialize DefaultCTLogs with known CT logs
	for _, log := range knownCTLogs {
		pubKey, logID, err := parseLogKey(log.PublicKeyB64)
		if err != nil {
			continue // Skip logs with unparseable keys
		}
		DefaultCTLogs[logID] = &CTLogInfo{
			LogID:     logID,
			PublicKey: pubKey,
			Name:      log.Name,
			URL:       log.URL,
			Operator:  log.Operator,
		}
	}
}

// ctLogEntry is the internal representation of a CT log before parsing
type ctLogEntry struct {
	Name         string
	URL          string
	Operator     string
	PublicKeyB64 string // Base64-encoded SubjectPublicKeyInfo
}

// knownCTLogs contains the raw CT log data
// These are the active, qualified logs from major operators
var knownCTLogs = []ctLogEntry{
	// Google Argon logs (2024-2025)
	{
		Name:     "Google 'Argon2024' log",
		URL:      "https://ct.googleapis.com/logs/us1/argon2024/",
		Operator: "Google",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHblsqctplMVc5ramA7vSuNxUQxcomQ" +
			"wGAVAdnWTAWUYr3MgDHQW0LagJ95lB7bjLd5c6GzR0kNFYL6tSK0p5DA==",
	},
	{
		Name:     "Google 'Argon2025h1' log",
		URL:      "https://ct.googleapis.com/logs/us1/argon2025h1/",
		Operator: "Google",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIIKh+WdoqFLc5+pPYPDA/W/DXCbnP" +
			"nk5B4cNfl5wIReUlcRs8eHlFf/NL/fO0IYvCLf5xQZYl2m/k2X89s6AqA==",
	},
	{
		Name:     "Google 'Argon2025h2' log",
		URL:      "https://ct.googleapis.com/logs/us1/argon2025h2/",
		Operator: "Google",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr+TzlCzfpie1/rJhgxnIITojqKSg0" +
			"gLsxLhvGqqNxp1Qg0DG2xYazxaDHrSHZ0r6FiO1Ck4w2RfH10EaqD8c3g==",
	},

	// Google Xenon logs (2024-2025)
	{
		Name:     "Google 'Xenon2024' log",
		URL:      "https://ct.googleapis.com/logs/eu1/xenon2024/",
		Operator: "Google",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuWDgNB415GUAk0+QCb1a7ETdjA/O7" +
			"RE+KllGmjG2x5n33O89zY+GwjWlPtwpurvyVOKoDIMIUQbeIW02UI44TQ==",
	},
	{
		Name:     "Google 'Xenon2025h1' log",
		URL:      "https://ct.googleapis.com/logs/eu1/xenon2025h1/",
		Operator: "Google",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0JCPZFJOQqyEti5M8j13ALN3CAVHq" +
			"rv9O9uyOh/dD/DHAG5rXfNtKJQwI2v3v3K5gupM3QNyb5oLGqKnP8C7Yg==",
	},
	{
		Name:     "Google 'Xenon2025h2' log",
		URL:      "https://ct.googleapis.com/logs/eu1/xenon2025h2/",
		Operator: "Google",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4V1Vp9+2+HZY0jT4Ky2pAU1W0Xn3O" +
			"y6Xw7NRzl7WTt3AX+FQXzc+3QzYNOeNi+2H7qABLU5v+LnPaRXwl4AQQ==",
	},

	// Cloudflare Nimbus logs (2024-2025)
	{
		Name:     "Cloudflare 'Nimbus2024' Log",
		URL:      "https://ct.cloudflare.com/logs/nimbus2024/",
		Operator: "Cloudflare",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd7Gbe2/dUNhC9tMAsJD06qXpLVv1O" +
			"OKXH3XQ3hKcKIRycCMfJKZhEKhL8qJ47N7DahIlX1T8wBmBHN7e0B0XlA==",
	},
	{
		Name:     "Cloudflare 'Nimbus2025' Log",
		URL:      "https://ct.cloudflare.com/logs/nimbus2025/",
		Operator: "Cloudflare",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGoAaFRkZI3m0+qB5jo3Y/kqJDDU" +
			"uc3CFmVrIL+nPy9VNZNJqL7l+Fq9XnfwDEVLj/v0w7+p11Fhz+GQN3lOpqA==",
	},

	// DigiCert logs
	{
		Name:     "DigiCert Yeti2024 Log",
		URL:      "https://yeti2024.ct.digicert.com/log/",
		Operator: "DigiCert",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEV7jBbzCkfy7k8Ra6bw/+TEY3Gzn" +
			"0KrPflvJV/k8F/3Xue9NI7FLzE/0P3FZwBwEYNzflwL0F7slUVWn8Ixv/8A==",
	},
	{
		Name:     "DigiCert Yeti2025 Log",
		URL:      "https://yeti2025.ct.digicert.com/log/",
		Operator: "DigiCert",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE35UAXhDBAfc34xB00f+yypDtMplfD" +
			"i12FKjNOCCMzKA5G2WzL9Eu2TKoFPmLv2bwKZ7BwpGS3Wcm+jdrRLzUhA==",
	},
	{
		Name:     "DigiCert Nessie2024 Log",
		URL:      "https://nessie2024.ct.digicert.com/log/",
		Operator: "DigiCert",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELfyieza/VpHp/j/oPfzDp+BhUuos" +
			"r0XKe1t6W7d76vwR/qwQ/n7/Ag+WG5mvLgVT/OmDHH8wQv36kCYH8I2CwA==",
	},
	{
		Name:     "DigiCert Nessie2025 Log",
		URL:      "https://nessie2025.ct.digicert.com/log/",
		Operator: "DigiCert",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8vDwp4uBLgk4O8LNVfWKqz1G0Mo19" +
			"S13U/AFMNVxdv+bHfO+9f0zgA/+N2mNDjpMrTGEhC+W8sPYy3lGxzXvdA==",
	},

	// Sectigo (formerly Comodo) logs
	{
		Name:     "Sectigo 'Sabre' CT log",
		URL:      "https://sabre.ct.comodo.com/",
		Operator: "Sectigo",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8m/SiQ8/xfiHHqtls9m7FyOMBg4" +
			"JVZY9CgiixXGz0akvKD6DEL8S0ERmFe9n4dA5Blz7P/d3cPTz8X7+LY/GdQ==",
	},
	{
		Name:     "Sectigo 'Mammoth' CT log",
		URL:      "https://mammoth.ct.comodo.com/",
		Operator: "Sectigo",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7+R9dC4VFbbpuyOL+yy14ceAmEf7Q" +
			"GVKGnfR5gJnJvHf7C0vBwuOH7Y2c4+n9VNr5nLH8IFHKieDLGZx6JMVtA==",
	},

	// Let's Encrypt logs
	{
		Name:     "Let's Encrypt 'Oak2024H1' log",
		URL:      "https://oak.ct.letsencrypt.org/2024h1/",
		Operator: "Let's Encrypt",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVkPXfnvUcre6qVG9NpO36bWSD+pet" +
			"5TfQM+rHe5/fQoSEVvZq/9JOQzCiAlD3/zPz8D4QOBeW2Q5htP+Dlfy4A==",
	},
	{
		Name:     "Let's Encrypt 'Oak2024H2' log",
		URL:      "https://oak.ct.letsencrypt.org/2024h2/",
		Operator: "Let's Encrypt",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE13PWU0fp88nzuBvG4ee2qqVa92cCn" +
			"L1gJ4CuqrSsHmDe7i2e/h10mLKAQ/l4Pjey0B7Yr4QQ4T1kPTBqiF4ldA==",
	},
	{
		Name:     "Let's Encrypt 'Oak2025h1' log",
		URL:      "https://oak.ct.letsencrypt.org/2025h1/",
		Operator: "Let's Encrypt",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKeBpU9ejnCaIZeX39EsdF5vDvf8Ef" +
			"lC8mDVzAKaYNgNuLumaibMs0KFg0o7lnVb4dL5gQ6x2Jl7RbP7DPHkx3w==",
	},
	{
		Name:     "Let's Encrypt 'Oak2025h2' log",
		URL:      "https://oak.ct.letsencrypt.org/2025h2/",
		Operator: "Let's Encrypt",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtXYwB63GyNLkS9L1vqKNnP10+jrW+" +
			"lldthxg0lPw4H5Y8Kbwx8roZ3qReLTiOyLLCWBb0Xfpu3sYLAj9Mr3dZA==",
	},

	// Trust Asia logs
	{
		Name:     "Trust Asia Log2024-2",
		URL:      "https://ct2024.trustasia.com/log2024/",
		Operator: "TrustAsia",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp4TcLnmPuO/6QVDjj/K0m6o54dz" +
			"VQz0v1sLIXCiS48q9g7TPXEF75W7l7P4JKFzlmXEJJpEPLkTXF0ueGdVc5w==",
	},

	// Apple logs
	{
		Name:     "Apple CT Log - Test 2024 H1",
		URL:      "https://ct.apple.com/log/test2024h1/",
		Operator: "Apple",
		PublicKeyB64: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXK4PxGdNh+2R5PY1fG69lTlD3FU" +
			"6hq1UwHXd7+QEvpBBFQdK1/VU5M2lIBNxoEOl0qFbDR1nlPbf8noXBzxlcA==",
	},
}

// parseLogKey parses a base64-encoded SubjectPublicKeyInfo and returns
// the public key and the SHA-256 hash (log ID)
func parseLogKey(b64Key string) (crypto.PublicKey, [32]byte, error) {
	var logID [32]byte

	// Decode base64
	derBytes, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, logID, err
	}

	// Compute log ID (SHA-256 of SubjectPublicKeyInfo)
	logID = sha256.Sum256(derBytes)

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		// Try parsing as raw EC point (some logs use this format)
		pubKey, err = parseECPublicKey(derBytes)
		if err != nil {
			return nil, logID, err
		}
	}

	return pubKey, logID, nil
}

// parseECPublicKey attempts to parse an EC public key from various formats
func parseECPublicKey(data []byte) (crypto.PublicKey, error) {
	// First try standard PKIX format
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err == nil {
		return pubKey, nil
	}

	// Try PEM format
	block, _ := pem.Decode(data)
	if block != nil {
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			return pubKey, nil
		}
	}

	// Try raw EC point format (64 bytes for P-256, 96 for P-384)
	// This is unlikely for CT logs but included for completeness
	if len(data) == 65 && data[0] == 0x04 { // Uncompressed P-256 point
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, nil
	}

	return nil, err
}

// CTLogRegistry provides a thread-safe registry of CT logs that can be
// updated at runtime. This is useful for:
// - Adding custom/private CT logs
// - Updating logs from Google's log list at runtime
// - Removing retired logs
type CTLogRegistry struct {
	mu   sync.RWMutex
	logs map[[32]byte]*CTLogInfo
}

// NewCTLogRegistry creates a new registry initialized with the default logs
func NewCTLogRegistry() *CTLogRegistry {
	r := &CTLogRegistry{
		logs: make(map[[32]byte]*CTLogInfo),
	}

	// Copy default logs
	for id, log := range DefaultCTLogs {
		logCopy := *log
		r.logs[id] = &logCopy
	}

	return r
}

// Get returns the CT log info for the given log ID
func (r *CTLogRegistry) Get(logID [32]byte) (*CTLogInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	log, ok := r.logs[logID]
	return log, ok
}

// Add adds a new CT log to the registry
func (r *CTLogRegistry) Add(log *CTLogInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs[log.LogID] = log
}

// Remove removes a CT log from the registry
func (r *CTLogRegistry) Remove(logID [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.logs, logID)
}

// All returns a copy of all logs in the registry
func (r *CTLogRegistry) All() map[[32]byte]*CTLogInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	logs := make(map[[32]byte]*CTLogInfo, len(r.logs))
	for id, log := range r.logs {
		logCopy := *log
		logs[id] = &logCopy
	}
	return logs
}

// AddFromBase64 adds a log from its base64-encoded public key
func (r *CTLogRegistry) AddFromBase64(name, url, operator, publicKeyB64 string) error {
	pubKey, logID, err := parseLogKey(publicKeyB64)
	if err != nil {
		return err
	}

	r.Add(&CTLogInfo{
		LogID:     logID,
		PublicKey: pubKey,
		Name:      name,
		URL:       url,
		Operator:  operator,
	})

	return nil
}

// ComputeLogID computes the log ID (SHA-256 of SubjectPublicKeyInfo) for a public key
func ComputeLogID(pubKey crypto.PublicKey) ([32]byte, error) {
	var logID [32]byte

	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return logID, err
	}

	logID = sha256.Sum256(derBytes)
	return logID, nil
}
