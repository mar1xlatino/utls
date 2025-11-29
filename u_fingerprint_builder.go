// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"time"
)

// ProfileBuilder creates custom profiles from a base profile.
type ProfileBuilder struct {
	profile *FingerprintProfile
	errors  []error
}

// NewProfileBuilder creates a builder starting from a registered profile.
func NewProfileBuilder(baseID string) (*ProfileBuilder, error) {
	profile, err := DefaultRegistry.Get(baseID)
	if err != nil {
		return nil, err
	}

	return &ProfileBuilder{
		profile: profile,
	}, nil
}

// NewProfileBuilderFrom creates a builder from an existing profile.
// If base is nil, returns a builder with an empty profile (same as NewEmptyProfileBuilder).
func NewProfileBuilderFrom(base *FingerprintProfile) *ProfileBuilder {
	if base == nil {
		return NewEmptyProfileBuilder()
	}
	return &ProfileBuilder{
		profile: base.Clone(),
	}
}

// NewEmptyProfileBuilder creates a builder with no base (for fully custom profiles).
func NewEmptyProfileBuilder() *ProfileBuilder {
	return &ProfileBuilder{
		profile: &FingerprintProfile{
			ClientHello: ClientHelloConfig{
				CompressionMethods: []uint8{0}, // compressionNone
				SessionIDLength:    32,
			},
		},
	}
}

// WithID sets the profile ID.
func (b *ProfileBuilder) WithID(id string) *ProfileBuilder {
	b.profile.ID = id
	return b
}

// WithBrowser sets the browser name.
func (b *ProfileBuilder) WithBrowser(browser string) *ProfileBuilder {
	b.profile.Browser = browser
	return b
}

// WithVersion sets the browser version.
func (b *ProfileBuilder) WithVersion(version int) *ProfileBuilder {
	b.profile.Version = version
	return b
}

// WithPlatform sets the platform.
func (b *ProfileBuilder) WithPlatform(platform string) *ProfileBuilder {
	b.profile.Platform = platform
	return b
}

// WithOSVersion sets the OS version.
func (b *ProfileBuilder) WithOSVersion(osVersion string) *ProfileBuilder {
	b.profile.OSVersion = osVersion
	return b
}

// WithDescription sets the description.
func (b *ProfileBuilder) WithDescription(desc string) *ProfileBuilder {
	b.profile.Description = desc
	return b
}

// WithCipherSuites replaces the cipher suite list.
func (b *ProfileBuilder) WithCipherSuites(ciphers []uint16) *ProfileBuilder {
	b.profile.ClientHello.CipherSuites = make([]uint16, len(ciphers))
	copy(b.profile.ClientHello.CipherSuites, ciphers)
	return b
}

// AddCipherSuite appends a cipher suite.
func (b *ProfileBuilder) AddCipherSuite(cipher uint16) *ProfileBuilder {
	b.profile.ClientHello.CipherSuites = append(b.profile.ClientHello.CipherSuites, cipher)
	return b
}

// AddCipherSuiteAt inserts a cipher suite at a specific position.
func (b *ProfileBuilder) AddCipherSuiteAt(cipher uint16, position int) *ProfileBuilder {
	ciphers := b.profile.ClientHello.CipherSuites
	if position < 0 {
		position = len(ciphers) + position + 1
	}
	if position < 0 || position > len(ciphers) {
		b.errors = append(b.errors, fmt.Errorf("invalid cipher suite position: %d", position))
		return b
	}

	// Insert at position
	ciphers = append(ciphers[:position], append([]uint16{cipher}, ciphers[position:]...)...)
	b.profile.ClientHello.CipherSuites = ciphers
	return b
}

// RemoveCipherSuite removes a cipher suite.
func (b *ProfileBuilder) RemoveCipherSuite(cipher uint16) *ProfileBuilder {
	ciphers := b.profile.ClientHello.CipherSuites
	for i, c := range ciphers {
		if c == cipher {
			b.profile.ClientHello.CipherSuites = append(ciphers[:i], ciphers[i+1:]...)
			return b
		}
	}
	return b
}

// ReorderCipherSuites reorders cipher suites to match the given order.
func (b *ProfileBuilder) ReorderCipherSuites(order []uint16) *ProfileBuilder {
	// Keep only ciphers that exist in both lists, in the new order
	existing := make(map[uint16]bool)
	for _, c := range b.profile.ClientHello.CipherSuites {
		existing[c] = true
	}

	var newOrder []uint16
	for _, c := range order {
		if existing[c] {
			newOrder = append(newOrder, c)
		}
	}

	b.profile.ClientHello.CipherSuites = newOrder
	return b
}

// WithExtensions replaces the extension list.
func (b *ProfileBuilder) WithExtensions(exts []uint16) *ProfileBuilder {
	b.profile.ClientHello.Extensions = make([]ExtensionEntry, len(exts))
	for i, ext := range exts {
		b.profile.ClientHello.Extensions[i] = ExtensionEntry{Type: ext}
	}
	return b
}

// AddExtension appends an extension.
func (b *ProfileBuilder) AddExtension(ext uint16) *ProfileBuilder {
	b.profile.ClientHello.Extensions = append(b.profile.ClientHello.Extensions, ExtensionEntry{Type: ext})
	return b
}

// AddExtensionAt inserts an extension at a specific position.
func (b *ProfileBuilder) AddExtensionAt(ext uint16, position int) *ProfileBuilder {
	exts := b.profile.ClientHello.Extensions
	if position < 0 {
		position = len(exts) + position + 1
	}
	if position < 0 || position > len(exts) {
		b.errors = append(b.errors, fmt.Errorf("invalid extension position: %d", position))
		return b
	}

	entry := ExtensionEntry{Type: ext}
	exts = append(exts[:position], append([]ExtensionEntry{entry}, exts[position:]...)...)
	b.profile.ClientHello.Extensions = exts
	return b
}

// RemoveExtension removes an extension.
func (b *ProfileBuilder) RemoveExtension(ext uint16) *ProfileBuilder {
	exts := b.profile.ClientHello.Extensions
	for i, e := range exts {
		if e.Type == ext {
			b.profile.ClientHello.Extensions = append(exts[:i], exts[i+1:]...)
			return b
		}
	}
	return b
}

// WithExtensionOrder reorders extensions to match the given order.
func (b *ProfileBuilder) WithExtensionOrder(order []uint16) *ProfileBuilder {
	existing := make(map[uint16]ExtensionEntry)
	for _, e := range b.profile.ClientHello.Extensions {
		existing[e.Type] = e
	}

	var newOrder []ExtensionEntry
	for _, t := range order {
		if entry, ok := existing[t]; ok {
			newOrder = append(newOrder, entry)
		}
	}

	b.profile.ClientHello.Extensions = newOrder
	return b
}

// WithShuffleExtensions sets whether to shuffle extensions.
func (b *ProfileBuilder) WithShuffleExtensions(shuffle bool) *ProfileBuilder {
	b.profile.ClientHello.ShuffleExtensions = shuffle
	return b
}

// WithGREASE enables or disables GREASE.
func (b *ProfileBuilder) WithGREASE(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.GREASE.Enabled = enabled
	return b
}

// WithGREASECipherSuites enables or disables GREASE in cipher suites.
func (b *ProfileBuilder) WithGREASECipherSuites(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.GREASE.CipherSuites = enabled
	return b
}

// WithGREASEExtensions enables or disables GREASE extensions.
func (b *ProfileBuilder) WithGREASEExtensions(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.GREASE.Extensions = enabled
	return b
}

// WithGREASEGroups enables or disables GREASE in supported groups.
func (b *ProfileBuilder) WithGREASEGroups(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.GREASE.SupportedGroups = enabled
	return b
}

// WithGREASEVersions enables or disables GREASE in supported versions.
func (b *ProfileBuilder) WithGREASEVersions(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.GREASE.SupportedVersions = enabled
	return b
}

// WithGREASEKeyShare enables or disables GREASE in key shares.
func (b *ProfileBuilder) WithGREASEKeyShare(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.GREASE.KeyShare = enabled
	return b
}

// WithGREASEPositions sets the positions for GREASE extensions.
func (b *ProfileBuilder) WithGREASEPositions(positions []int) *ProfileBuilder {
	b.profile.ClientHello.GREASE.ExtensionPositions = make([]int, len(positions))
	copy(b.profile.ClientHello.GREASE.ExtensionPositions, positions)
	return b
}

// WithSupportedGroups sets the supported groups.
func (b *ProfileBuilder) WithSupportedGroups(groups []CurveID) *ProfileBuilder {
	b.profile.ClientHello.SupportedGroups = make([]CurveID, len(groups))
	copy(b.profile.ClientHello.SupportedGroups, groups)
	return b
}

// WithSignatureAlgorithms sets the signature algorithms.
func (b *ProfileBuilder) WithSignatureAlgorithms(algs []SignatureScheme) *ProfileBuilder {
	b.profile.ClientHello.SignatureAlgorithms = make([]SignatureScheme, len(algs))
	copy(b.profile.ClientHello.SignatureAlgorithms, algs)
	return b
}

// WithALPN sets the ALPN protocols.
func (b *ProfileBuilder) WithALPN(protocols []string) *ProfileBuilder {
	b.profile.ClientHello.ALPNProtocols = make([]string, len(protocols))
	copy(b.profile.ClientHello.ALPNProtocols, protocols)
	return b
}

// WithKeyShareGroups sets the key share groups.
func (b *ProfileBuilder) WithKeyShareGroups(groups []CurveID) *ProfileBuilder {
	b.profile.ClientHello.KeyShareGroups = make([]CurveID, len(groups))
	copy(b.profile.ClientHello.KeyShareGroups, groups)
	return b
}

// WithPadding sets the padding style and target.
func (b *ProfileBuilder) WithPadding(style PaddingStyle, target int) *ProfileBuilder {
	b.profile.ClientHello.PaddingStyle = style
	b.profile.ClientHello.PaddingTarget = target
	return b
}

// WithSessionIDLength sets the session ID length.
func (b *ProfileBuilder) WithSessionIDLength(length int) *ProfileBuilder {
	if length != 0 && length != 32 {
		b.errors = append(b.errors, fmt.Errorf("session ID length must be 0 or 32, got %d", length))
		return b
	}
	b.profile.ClientHello.SessionIDLength = length
	return b
}

// WithSNIBehavior sets the SNI behavior.
func (b *ProfileBuilder) WithSNIBehavior(behavior SNIBehavior) *ProfileBuilder {
	b.profile.ClientHello.SNIBehavior = behavior
	return b
}

// WithPSKModes sets the PSK modes.
func (b *ProfileBuilder) WithPSKModes(modes []uint8) *ProfileBuilder {
	b.profile.ClientHello.PSKModes = make([]uint8, len(modes))
	copy(b.profile.ClientHello.PSKModes, modes)
	return b
}

// WithExpectedJA3 sets the expected JA3 fingerprint.
func (b *ProfileBuilder) WithExpectedJA3(ja3 string) *ProfileBuilder {
	b.profile.Expected.JA3 = ja3
	return b
}

// WithExpectedJA4 sets the expected JA4 fingerprint.
func (b *ProfileBuilder) WithExpectedJA4(ja4 string) *ProfileBuilder {
	b.profile.Expected.JA4 = ja4
	return b
}

// ExpectJA4S adds acceptable JA4S patterns.
func (b *ProfileBuilder) ExpectJA4S(patterns ...string) *ProfileBuilder {
	b.profile.ServerExpectations.AcceptableJA4S = append(
		b.profile.ServerExpectations.AcceptableJA4S, patterns...)
	return b
}

// ExpectCiphers adds acceptable cipher selections.
func (b *ProfileBuilder) ExpectCiphers(ciphers ...uint16) *ProfileBuilder {
	b.profile.ServerExpectations.AcceptableCiphers = append(
		b.profile.ServerExpectations.AcceptableCiphers, ciphers...)
	return b
}

// ExpectJA4X adds acceptable JA4X patterns.
func (b *ProfileBuilder) ExpectJA4X(patterns ...string) *ProfileBuilder {
	b.profile.ServerExpectations.Certificate.AcceptableJA4X = append(
		b.profile.ServerExpectations.Certificate.AcceptableJA4X, patterns...)
	return b
}

// WithRecordPadding enables or disables record padding.
func (b *ProfileBuilder) WithRecordPadding(enabled bool) *ProfileBuilder {
	b.profile.RecordLayer.PaddingEnabled = enabled
	return b
}

// WithRecordPaddingMode sets the record padding mode.
func (b *ProfileBuilder) WithRecordPaddingMode(mode RecordPaddingMode) *ProfileBuilder {
	b.profile.RecordLayer.PaddingMode = mode
	return b
}

// WithPaddingLambda sets the lambda for exponential padding.
func (b *ProfileBuilder) WithPaddingLambda(lambda float64) *ProfileBuilder {
	b.profile.RecordLayer.PaddingLambda = lambda
	return b
}

// WithMaxRecordSize sets the maximum record size.
func (b *ProfileBuilder) WithMaxRecordSize(size int) *ProfileBuilder {
	b.profile.RecordLayer.MaxRecordSize = size
	return b
}

// WithResumption enables or disables session resumption.
func (b *ProfileBuilder) WithResumption(enabled bool) *ProfileBuilder {
	b.profile.Session.ResumptionEnabled = enabled
	return b
}

// WithEarlyData enables or disables early data (0-RTT).
func (b *ProfileBuilder) WithEarlyData(enabled bool) *ProfileBuilder {
	b.profile.Session.EarlyDataEnabled = enabled
	return b
}

// WithTicketLifetime sets the session ticket lifetime.
func (b *ProfileBuilder) WithTicketLifetime(duration time.Duration) *ProfileBuilder {
	b.profile.Session.TicketLifetime = duration
	return b
}

// WithHTTP2Settings sets the HTTP/2 fingerprint settings.
func (b *ProfileBuilder) WithHTTP2Settings(settings HTTP2FingerprintConfig) *ProfileBuilder {
	b.profile.HTTP2 = settings
	return b
}

// WithHTTP2WindowSize sets the HTTP/2 initial window size.
func (b *ProfileBuilder) WithHTTP2WindowSize(size uint32) *ProfileBuilder {
	b.profile.HTTP2.InitialWindowSize = size
	return b
}

// WithHTTP2MaxStreams sets the HTTP/2 max concurrent streams.
func (b *ProfileBuilder) WithHTTP2MaxStreams(max uint32) *ProfileBuilder {
	b.profile.HTTP2.MaxConcurrentStreams = max
	return b
}

// WithSupportedVersions sets the supported TLS versions.
func (b *ProfileBuilder) WithSupportedVersions(versions []uint16) *ProfileBuilder {
	b.profile.ClientHello.SupportedVersions = make([]uint16, len(versions))
	copy(b.profile.ClientHello.SupportedVersions, versions)
	return b
}

// WithLegacyVersion sets the legacy version field.
func (b *ProfileBuilder) WithLegacyVersion(version uint16) *ProfileBuilder {
	b.profile.ClientHello.LegacyVersion = version
	return b
}

// WithCertCompression sets the certificate compression algorithms.
func (b *ProfileBuilder) WithCertCompression(algos []CertCompressionAlgo) *ProfileBuilder {
	b.profile.ClientHello.CertCompressionAlgos = make([]CertCompressionAlgo, len(algos))
	copy(b.profile.ClientHello.CertCompressionAlgos, algos)
	return b
}

// WithApplicationSettings enables or disables ALPS.
func (b *ProfileBuilder) WithApplicationSettings(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.ApplicationSettings = enabled
	return b
}

// WithDelegatedCredentials enables or disables delegated credentials.
func (b *ProfileBuilder) WithDelegatedCredentials(enabled bool) *ProfileBuilder {
	b.profile.ClientHello.DelegatedCredentials = enabled
	return b
}

// Build creates the final profile, returns error if invalid.
func (b *ProfileBuilder) Build() (*FingerprintProfile, error) {
	if len(b.errors) > 0 {
		return nil, b.errors[0]
	}

	// Validate the profile
	if errs := b.profile.Validate(); len(errs) > 0 {
		return nil, errs[0]
	}

	return b.profile.Clone(), nil
}

// MustBuild creates the final profile, panics if invalid.
func (b *ProfileBuilder) MustBuild() *FingerprintProfile {
	profile, err := b.Build()
	if err != nil {
		panic(err)
	}
	return profile
}

// Validate checks for errors without building.
func (b *ProfileBuilder) Validate() []error {
	if len(b.errors) > 0 {
		return b.errors
	}
	return b.profile.Validate()
}

// Errors returns accumulated errors.
func (b *ProfileBuilder) Errors() []error {
	return b.errors
}

// Clone creates a copy of the builder.
func (b *ProfileBuilder) Clone() *ProfileBuilder {
	return &ProfileBuilder{
		profile: b.profile.Clone(),
		errors:  append([]error{}, b.errors...),
	}
}

// Profile returns the current profile (without building/validating).
func (b *ProfileBuilder) Profile() *FingerprintProfile {
	return b.profile
}

// QuickProfile creates a simple profile with minimal configuration.
func QuickProfile(id, browser, platform string, version int) *ProfileBuilder {
	return NewEmptyProfileBuilder().
		WithID(id).
		WithBrowser(browser).
		WithPlatform(platform).
		WithVersion(version)
}

// ChromeProfile creates a Chrome-like profile builder.
func ChromeProfile(version int, platform string) *ProfileBuilder {
	builder, err := NewProfileBuilder("chrome_133_windows_11")
	if err != nil {
		// Fallback to building from scratch
		builder = NewEmptyProfileBuilder()
	}

	return builder.
		WithID(fmt.Sprintf("chrome_%d_%s", version, platform)).
		WithBrowser("chrome").
		WithVersion(version).
		WithPlatform(platform).
		WithGREASE(true).
		WithShuffleExtensions(true).
		WithPadding(PaddingChrome, 517)
}

// FirefoxProfile creates a Firefox-like profile builder.
func FirefoxProfile(version int, platform string) *ProfileBuilder {
	builder, err := NewProfileBuilder("firefox_145_windows_11")
	if err != nil {
		builder = NewEmptyProfileBuilder()
	}

	return builder.
		WithID(fmt.Sprintf("firefox_%d_%s", version, platform)).
		WithBrowser("firefox").
		WithVersion(version).
		WithPlatform(platform).
		WithGREASE(false).
		WithShuffleExtensions(false)
}

// SafariProfile creates a Safari-like profile builder.
func SafariProfile(version int, platform string) *ProfileBuilder {
	builder, err := NewProfileBuilder("safari_18_macos_14")
	if err != nil {
		builder = NewEmptyProfileBuilder()
	}

	return builder.
		WithID(fmt.Sprintf("safari_%d_%s", version, platform)).
		WithBrowser("safari").
		WithVersion(version).
		WithPlatform(platform)
}

// ErrInvalidProfile is returned when a profile fails validation.
var ErrInvalidProfile = errors.New("tls: invalid fingerprint profile")
