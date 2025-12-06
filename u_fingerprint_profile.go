// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"time"
)

// FingerprintProfile defines a complete TLS fingerprint profile for browser impersonation.
// It encapsulates all parameters that contribute to TLS fingerprinting including
// ClientHello structure, expected fingerprints, server response expectations,
// record layer behavior, and session management.
type FingerprintProfile struct {
	// Identity
	ID          string // Unique identifier: "chrome_142_windows_11"
	Browser     string // Browser family: "chrome", "firefox", "safari", "edge"
	Version     int    // Browser version: 142
	Platform    string // OS family: "windows", "macos", "linux", "ios", "android"
	OSVersion   string // OS version: "11", "14", "22.04"
	Description string // Human-readable description

	// ClientHello configuration (controls JA3/JA4)
	ClientHello ClientHelloConfig

	// Expected fingerprints (for validation)
	Expected ExpectedFingerprints

	// Server response expectations
	ServerExpectations ServerExpectations

	// Record layer behavior
	RecordLayer RecordLayerConfig

	// Session behavior
	Session SessionBehaviorConfig

	// HTTP/2 correlation (for multi-layer consistency)
	HTTP2 HTTP2FingerprintConfig
}

// ClientHelloConfig defines all ClientHello fingerprint parameters.
// These parameters directly control the JA3 and JA4 fingerprints.
type ClientHelloConfig struct {
	// TLS Version
	LegacyVersion     uint16   // Version field in ClientHello (usually 0x0303 for TLS 1.2)
	SupportedVersions []uint16 // Versions in supported_versions extension

	// Cipher Suites (ORDER MATTERS for fingerprinting)
	CipherSuites []uint16

	// Extensions (ORDER MATTERS for non-shuffling browsers)
	Extensions        []ExtensionEntry
	ShuffleExtensions bool  // Chrome shuffles, Firefox doesn't
	ShuffleSeed       int64 // Seed for deterministic shuffle (0 = random)

	// Supported Groups / Curves
	SupportedGroups []CurveID

	// Signature Algorithms
	SignatureAlgorithms []SignatureScheme

	// EC Point Formats
	ECPointFormats []uint8

	// ALPN protocols
	ALPNProtocols []string

	// GREASE Configuration
	GREASE GREASEConfig

	// Key Shares (TLS 1.3)
	KeyShareGroups []CurveID // Which groups to send key shares for

	// SNI Behavior
	SNIBehavior SNIBehavior

	// Session ID
	SessionIDLength int // 0 or 32 typically

	// Compression (legacy, always null in modern TLS)
	CompressionMethods []uint8

	// Padding
	PaddingStyle  PaddingStyle
	PaddingTarget int // Target padded length (517 for Chrome)

	// PSK Modes (TLS 1.3)
	PSKModes []uint8

	// Certificate Compression Algorithms
	CertCompressionAlgos []CertCompressionAlgo

	// Delegated Credentials (Firefox)
	DelegatedCredentials bool

	// Application Settings (ALPS - Chrome)
	ApplicationSettings bool

	// Record Size Limit (Firefox)
	RecordSizeLimit uint16

	// ECH (Encrypted Client Hello)
	ECHEnabled bool
	ECHConfig  []byte

	// ExtensionOrder specifies the extension types to include and their order.
	// Use this instead of Extensions when you only need to specify order without
	// extension-specific configuration data. This is useful for built-in profiles
	// where extension order matters for fingerprinting but extension data is
	// generated from other fields (SupportedGroups, ALPNProtocols, etc.).
	// If both Extensions and ExtensionOrder are set, Extensions takes precedence.
	ExtensionOrder []uint16
}

// ExtensionEntry defines a single extension's configuration.
type ExtensionEntry struct {
	Type     uint16
	Critical bool        // If true, validation fails if missing
	Data     interface{} // Extension-specific configuration
}

// deepCopyExtensionData creates a deep copy of ExtensionEntry.Data.
// Handles known mutable types to prevent shared state between cloned profiles.
func deepCopyExtensionData(data interface{}) interface{} {
	if data == nil {
		return nil
	}
	switch v := data.(type) {
	case []byte:
		if v == nil {
			return nil
		}
		cp := make([]byte, len(v))
		copy(cp, v)
		return cp
	case []uint16:
		if v == nil {
			return nil
		}
		cp := make([]uint16, len(v))
		copy(cp, v)
		return cp
	case []string:
		if v == nil {
			return nil
		}
		cp := make([]string, len(v))
		copy(cp, v)
		return cp
	case map[string]string:
		if v == nil {
			return nil
		}
		cp := make(map[string]string, len(v))
		for k, val := range v {
			cp[k] = val
		}
		return cp
	default:
		// For primitive types (int, string, bool, etc.) and unknown types,
		// return as-is. Primitive types are copied by value.
		// WARNING: Unknown pointer/slice/map types will be shared!
		return data
	}
}

// SNIBehavior controls when SNI extension is included.
type SNIBehavior int

const (
	SNIAlways     SNIBehavior = iota // Always include SNI
	SNIDomainOnly                    // Include only for domain names, not IPs
	SNINever                         // Never include SNI
)

// PaddingStyle defines how ClientHello padding is applied.
type PaddingStyle int

const (
	PaddingNone    PaddingStyle = iota // No padding
	PaddingChrome                      // Chrome-style (target 517)
	PaddingFirefox                     // Firefox-style
	PaddingCustom                      // Custom padding function
)

// GREASEConfig controls GREASE value generation and placement.
type GREASEConfig struct {
	Enabled bool

	// Which fields get GREASE
	CipherSuites      bool
	Extensions        bool
	SupportedGroups   bool
	SupportedVersions bool
	KeyShare          bool
	SignatureAlgos    bool
	PSKModes          bool

	// Extension positions (indices where GREASE extensions appear)
	// For Chrome: typically [0, -2] (first and second-to-last)
	ExtensionPositions []int
}

// ExpectedFingerprints holds expected fingerprint values for validation.
type ExpectedFingerprints struct {
	JA3   string // Expected JA3 hash
	JA3r  string // Expected JA3 raw string
	JA4   string // Expected JA4 (sorted, hashed)
	JA4r  string // Expected JA4 raw
	JA4o  string // Expected JA4 original order
	JA4ro string // Expected JA4 original raw
}

// ServerExpectations defines what server responses should look like.
type ServerExpectations struct {
	// Acceptable JA4S patterns (can be regex or exact match)
	AcceptableJA4S []string

	// Acceptable cipher selections
	AcceptableCiphers []uint16

	// Certificate expectations
	Certificate CertificateExpectations
}

// CertificateExpectations defines expected certificate properties.
type CertificateExpectations struct {
	// Acceptable JA4X patterns
	AcceptableJA4X []string

	// Validation behavior
	ValidateChain bool
	ValidateSCT   bool
	RequireOCSP   bool
}

// RecordLayerConfig defines record-level fingerprint behavior.
type RecordLayerConfig struct {
	// Record sizes
	MaxRecordSize     int // Maximum TLS record size (16384 typical)
	InitialRecordSize int // Size of first records

	// Padding (TLS 1.3)
	PaddingEnabled bool
	PaddingMode    RecordPaddingMode
	PaddingLambda  float64 // For exponential mode
	PaddingMax     int     // Maximum padding bytes

	// Fragmentation
	AllowFragmentation bool
	FragmentPattern    []int // Typical fragment sizes
}

// RecordPaddingMode defines TLS 1.3 record padding strategy.
type RecordPaddingMode int

const (
	RecordPaddingNone        RecordPaddingMode = iota // No padding
	RecordPaddingRandom                               // Random padding
	RecordPaddingBlock                                // Block-aligned padding
	RecordPaddingExponential                          // Exponential distribution (Chrome-like)
	RecordPaddingChrome                               // Exactly Chrome behavior
	RecordPaddingFirefox                              // Exactly Firefox behavior
)

// SessionBehaviorConfig defines session management behavior.
type SessionBehaviorConfig struct {
	// Resumption
	ResumptionEnabled bool

	// Session ticket handling
	AcceptTickets  bool
	TicketLifetime time.Duration

	// Early data (0-RTT)
	EarlyDataEnabled bool
	MaxEarlyData     uint32

	// PSK
	// Deprecated: Use ClientHelloConfig.PSKModes instead. This field is kept for
	// backwards compatibility but is not used. PSK modes in the ClientHello
	// are controlled by ClientHelloConfig.PSKModes.
	PSKModes []uint8
}

// HTTP2FingerprintConfig defines HTTP/2 settings for fingerprint correlation.
// These settings can be used to validate that HTTP/2 fingerprints match TLS.
type HTTP2FingerprintConfig struct {
	// SETTINGS frame values
	HeaderTableSize      uint32
	EnablePush           bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32

	// Connection-level flow control
	ConnectionWindowSize uint32

	// Priority
	PriorityEnabled bool
}

// Clone creates a deep copy of the FingerprintProfile.
// Returns empty profile if receiver is nil (never returns nil).
func (p *FingerprintProfile) Clone() *FingerprintProfile {
	if p == nil {
		return &FingerprintProfile{}
	}

	clone := &FingerprintProfile{
		ID:          p.ID,
		Browser:     p.Browser,
		Version:     p.Version,
		Platform:    p.Platform,
		OSVersion:   p.OSVersion,
		Description: p.Description,
		Expected:    p.Expected,
		RecordLayer: p.RecordLayer,
		Session:     p.Session,
		HTTP2:       p.HTTP2,
	}

	// Deep copy RecordLayer.FragmentPattern slice
	if p.RecordLayer.FragmentPattern != nil {
		clone.RecordLayer.FragmentPattern = make([]int, len(p.RecordLayer.FragmentPattern))
		copy(clone.RecordLayer.FragmentPattern, p.RecordLayer.FragmentPattern)
	}

	// Deep copy Session.PSKModes slice (CRITICAL: was missing, caused shared state bug)
	if p.Session.PSKModes != nil {
		clone.Session.PSKModes = make([]uint8, len(p.Session.PSKModes))
		copy(clone.Session.PSKModes, p.Session.PSKModes)
	}

	// Deep copy ClientHello config
	clone.ClientHello = p.ClientHello.Clone()

	// Deep copy ServerExpectations
	clone.ServerExpectations = p.ServerExpectations.Clone()

	return clone
}

// Clone creates a deep copy of ClientHelloConfig.
func (c ClientHelloConfig) Clone() ClientHelloConfig {
	clone := c

	// Deep copy slices
	if c.SupportedVersions != nil {
		clone.SupportedVersions = make([]uint16, len(c.SupportedVersions))
		copy(clone.SupportedVersions, c.SupportedVersions)
	}

	if c.CipherSuites != nil {
		clone.CipherSuites = make([]uint16, len(c.CipherSuites))
		copy(clone.CipherSuites, c.CipherSuites)
	}

	if c.Extensions != nil {
		clone.Extensions = make([]ExtensionEntry, len(c.Extensions))
		for i, ext := range c.Extensions {
			clone.Extensions[i] = ExtensionEntry{
				Type:     ext.Type,
				Critical: ext.Critical,
				Data:     deepCopyExtensionData(ext.Data),
			}
		}
	}

	if c.SupportedGroups != nil {
		clone.SupportedGroups = make([]CurveID, len(c.SupportedGroups))
		copy(clone.SupportedGroups, c.SupportedGroups)
	}

	if c.SignatureAlgorithms != nil {
		clone.SignatureAlgorithms = make([]SignatureScheme, len(c.SignatureAlgorithms))
		copy(clone.SignatureAlgorithms, c.SignatureAlgorithms)
	}

	if c.ECPointFormats != nil {
		clone.ECPointFormats = make([]uint8, len(c.ECPointFormats))
		copy(clone.ECPointFormats, c.ECPointFormats)
	}

	if c.ALPNProtocols != nil {
		clone.ALPNProtocols = make([]string, len(c.ALPNProtocols))
		copy(clone.ALPNProtocols, c.ALPNProtocols)
	}

	if c.KeyShareGroups != nil {
		clone.KeyShareGroups = make([]CurveID, len(c.KeyShareGroups))
		copy(clone.KeyShareGroups, c.KeyShareGroups)
	}

	if c.CompressionMethods != nil {
		clone.CompressionMethods = make([]uint8, len(c.CompressionMethods))
		copy(clone.CompressionMethods, c.CompressionMethods)
	}

	if c.PSKModes != nil {
		clone.PSKModes = make([]uint8, len(c.PSKModes))
		copy(clone.PSKModes, c.PSKModes)
	}

	if c.CertCompressionAlgos != nil {
		clone.CertCompressionAlgos = make([]CertCompressionAlgo, len(c.CertCompressionAlgos))
		copy(clone.CertCompressionAlgos, c.CertCompressionAlgos)
	}

	if c.GREASE.ExtensionPositions != nil {
		clone.GREASE.ExtensionPositions = make([]int, len(c.GREASE.ExtensionPositions))
		copy(clone.GREASE.ExtensionPositions, c.GREASE.ExtensionPositions)
	}

	if c.ECHConfig != nil {
		clone.ECHConfig = make([]byte, len(c.ECHConfig))
		copy(clone.ECHConfig, c.ECHConfig)
	}

	if c.ExtensionOrder != nil {
		clone.ExtensionOrder = make([]uint16, len(c.ExtensionOrder))
		copy(clone.ExtensionOrder, c.ExtensionOrder)
	}

	return clone
}

// Clone creates a deep copy of ServerExpectations.
func (s ServerExpectations) Clone() ServerExpectations {
	clone := s

	if s.AcceptableJA4S != nil {
		clone.AcceptableJA4S = make([]string, len(s.AcceptableJA4S))
		copy(clone.AcceptableJA4S, s.AcceptableJA4S)
	}

	if s.AcceptableCiphers != nil {
		clone.AcceptableCiphers = make([]uint16, len(s.AcceptableCiphers))
		copy(clone.AcceptableCiphers, s.AcceptableCiphers)
	}

	if s.Certificate.AcceptableJA4X != nil {
		clone.Certificate.AcceptableJA4X = make([]string, len(s.Certificate.AcceptableJA4X))
		copy(clone.Certificate.AcceptableJA4X, s.Certificate.AcceptableJA4X)
	}

	return clone
}

// ToClientHelloSpec converts the profile to the legacy ClientHelloSpec format.
// This provides backwards compatibility with existing utls code.
func (p *FingerprintProfile) ToClientHelloSpec() ClientHelloSpec {
	spec := ClientHelloSpec{
		CipherSuites:       make([]uint16, len(p.ClientHello.CipherSuites)),
		CompressionMethods: make([]uint8, len(p.ClientHello.CompressionMethods)),
		TLSVersMin:         VersionTLS10,
		TLSVersMax:         VersionTLS13,
	}

	copy(spec.CipherSuites, p.ClientHello.CipherSuites)
	copy(spec.CompressionMethods, p.ClientHello.CompressionMethods)

	// Determine version range from supported versions
	if len(p.ClientHello.SupportedVersions) > 0 {
		spec.TLSVersMax = p.ClientHello.SupportedVersions[0]
		spec.TLSVersMin = p.ClientHello.SupportedVersions[len(p.ClientHello.SupportedVersions)-1]
		for _, v := range p.ClientHello.SupportedVersions {
			if v > spec.TLSVersMax {
				spec.TLSVersMax = v
			}
			if v < spec.TLSVersMin {
				spec.TLSVersMin = v
			}
		}
	}

	// Extensions need to be converted separately as they require TLSExtension interface
	// This is handled by the caller or by BuildExtensions method

	return spec
}

// Validate checks the profile for errors.
// Returns a list of validation errors, empty if the profile is valid.
// Note: Platform and Version are recommended but not strictly required for backward compatibility.
func (p *FingerprintProfile) Validate() []error {
	var errs []error

	// Required identity fields
	if p.ID == "" {
		errs = append(errs, &ProfileValidationError{Field: "ID", Message: "must not be empty"})
	}

	if p.Browser == "" {
		errs = append(errs, &ProfileValidationError{Field: "Browser", Message: "must not be empty"})
	}

	// Platform and Version are recommended but optional for backward compatibility
	// Production profiles should have these set

	// ClientHello required fields - only CipherSuites is truly required
	// Other fields are recommended for production profiles
	if len(p.ClientHello.CipherSuites) == 0 {
		errs = append(errs, &ProfileValidationError{Field: "CipherSuites", Message: "must have at least one cipher suite"})
	}

	// Validate SessionIDLength (must be 0 or 32)
	if p.ClientHello.SessionIDLength != 0 && p.ClientHello.SessionIDLength != 32 {
		errs = append(errs, &ProfileValidationError{Field: "SessionIDLength", Message: "must be 0 or 32"})
	}

	// Check for duplicate cipher suites
	cipherSeen := make(map[uint16]bool)
	for _, cs := range p.ClientHello.CipherSuites {
		if cipherSeen[cs] {
			errs = append(errs, &ProfileValidationError{
				Field:   "CipherSuites",
				Message: "contains duplicate cipher suite",
			})
			break
		}
		cipherSeen[cs] = true
	}

	// Note: Duplicate signature algorithms are allowed because real browsers
	// like Safari intentionally send duplicates (e.g., 0x0805, 0x0805).
	// This is valid TLS behavior even if unusual.

	// Validate GREASE configuration
	if p.ClientHello.GREASE.Enabled {
		// Firefox does not use GREASE
		if p.Browser == "firefox" {
			errs = append(errs, &ProfileValidationError{Field: "GREASE", Message: "Firefox does not use GREASE"})
		}

		// Validate ExtensionPositions if GREASE extensions are enabled
		if p.ClientHello.GREASE.Extensions && len(p.ClientHello.GREASE.ExtensionPositions) > 0 {
			extCount := len(p.ClientHello.ExtensionOrder)
			if extCount == 0 {
				extCount = len(p.ClientHello.Extensions)
			}
			for _, pos := range p.ClientHello.GREASE.ExtensionPositions {
				// Positive indices must be less than extCount+1 (can append at end)
				// Negative indices must be >= -extCount
				if pos >= 0 && pos > extCount {
					errs = append(errs, &ProfileValidationError{
						Field:   "GREASE.ExtensionPositions",
						Message: "position out of bounds (use -1 for last position)",
					})
					break
				}
				if pos < 0 && -pos > extCount {
					errs = append(errs, &ProfileValidationError{
						Field:   "GREASE.ExtensionPositions",
						Message: "negative position out of bounds",
					})
					break
				}
			}
		}
	}

	// Validate shuffle consistency
	if p.ClientHello.ShuffleExtensions {
		if p.Browser == "firefox" {
			errs = append(errs, &ProfileValidationError{Field: "ShuffleExtensions", Message: "Firefox does not shuffle extensions"})
		}
	}

	// Validate KeyShareGroups are subset of SupportedGroups
	if len(p.ClientHello.KeyShareGroups) > 0 && len(p.ClientHello.SupportedGroups) > 0 {
		supportedSet := make(map[CurveID]bool)
		for _, g := range p.ClientHello.SupportedGroups {
			supportedSet[g] = true
		}
		for _, ks := range p.ClientHello.KeyShareGroups {
			// Skip GREASE placeholders (0x?a?a pattern)
			if isGREASEValue(uint16(ks)) {
				continue
			}
			if !supportedSet[ks] {
				errs = append(errs, &ProfileValidationError{
					Field:   "KeyShareGroups",
					Message: "contains group not in SupportedGroups",
				})
				break
			}
		}
	}

	return errs
}

// isGREASEValue checks if a value is a GREASE placeholder (0x?a?a pattern).
func isGREASEValue(v uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// ProfileValidationError represents a validation error in a profile.
type ProfileValidationError struct {
	Field   string
	Message string
}

func (e *ProfileValidationError) Error() string {
	return "profile validation: " + e.Field + ": " + e.Message
}
