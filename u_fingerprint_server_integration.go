// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
)

// ServerFingerprintController orchestrates server-side TLS fingerprint control.
// It analyzes incoming ClientHello messages and controls ServerHello responses
// to produce specific JA4S/JA4X fingerprints.
//
// Usage:
//
//	ctrl := tls.NewServerFingerprintController("cloudflare")
//	config := &tls.Config{
//	    GetConfigForClient: ctrl.GetConfigForClient,
//	    Certificates: []tls.Certificate{cert},
//	}
//	listener, _ := tls.Listen("tcp", ":443", config)
type ServerFingerprintController struct {
	// Profile is the server fingerprint profile being applied
	profile *ServerProfile

	// Hooks for extensibility and monitoring
	hooks *HookChain

	// Options
	opts ServerFingerprintControllerOptions

	// Statistics
	stats serverFingerprintStats

	mu sync.RWMutex
}

// serverFingerprintStats tracks server fingerprint statistics.
// Note: Thread safety is provided by ServerFingerprintController.mu, not per-stats mutex.
type serverFingerprintStats struct {
	ClientHellosReceived int64
	ServerHellosSent     int64
	CertsGenerated       int64
}

// ServerFingerprintControllerOptions configures the server fingerprint controller.
type ServerFingerprintControllerOptions struct {
	// LogClientFingerprints enables logging of client fingerprints
	LogClientFingerprints bool

	// GenerateCertificates enables dynamic certificate generation
	GenerateCertificates bool

	// CertificateHostname is the hostname to use in generated certificates
	CertificateHostname string

	// FallbackCertificate is used when certificate generation is disabled
	FallbackCertificate *Certificate

	// ValidateClientFingerprint enables validation of client fingerprints
	ValidateClientFingerprint bool

	// AllowedClientFingerprints is a list of allowed JA4 patterns (if validation enabled)
	AllowedClientFingerprints []string
}

// DefaultServerFingerprintControllerOptions returns sensible defaults.
func DefaultServerFingerprintControllerOptions() ServerFingerprintControllerOptions {
	return ServerFingerprintControllerOptions{
		LogClientFingerprints:     false,
		GenerateCertificates:      false,
		ValidateClientFingerprint: false,
	}
}

// NewServerFingerprintController creates a new server fingerprint controller.
func NewServerFingerprintController(profileID string) (*ServerFingerprintController, error) {
	return NewServerFingerprintControllerWithOptions(profileID, DefaultServerFingerprintControllerOptions())
}

// NewServerFingerprintControllerWithOptions creates a controller with custom options.
func NewServerFingerprintControllerWithOptions(profileID string, opts ServerFingerprintControllerOptions) (*ServerFingerprintController, error) {
	profile, ok := DefaultServerProfileRegistry.Get(profileID)
	if !ok {
		return nil, fmt.Errorf("tls: unknown server profile: %s", profileID)
	}

	return &ServerFingerprintController{
		profile: profile.Clone(),
		hooks:   NewHookChain(),
		opts:    opts,
	}, nil
}

// NewServerFingerprintControllerFromProfile creates a controller from a profile directly.
// Returns nil if profile is nil - callers must check the return value.
func NewServerFingerprintControllerFromProfile(profile *ServerProfile, opts ServerFingerprintControllerOptions) *ServerFingerprintController {
	if profile == nil {
		return nil
	}
	return &ServerFingerprintController{
		profile: profile.Clone(),
		hooks:   NewHookChain(),
		opts:    opts,
	}
}

// GetConfigForClient returns a Config callback for per-client configuration.
// This is the main integration point with standard Go TLS server.
//
// Usage:
//
//	ctrl, _ := tls.NewServerFingerprintController("cloudflare")
//	config := &tls.Config{
//	    GetConfigForClient: ctrl.GetConfigForClient,
//	}
func (sfc *ServerFingerprintController) GetConfigForClient(chi *ClientHelloInfo) (*Config, error) {
	sfc.mu.Lock()
	sfc.stats.ClientHellosReceived++
	sfc.mu.Unlock()

	// Analyze client fingerprint
	clientFP, err := sfc.AnalyzeClientHello(chi)
	if err != nil {
		// Non-fatal: log but continue
		_ = err
	}

	// Validate client fingerprint if enabled
	if sfc.opts.ValidateClientFingerprint && clientFP != nil {
		if !sfc.validateClientFingerprint(clientFP) {
			return nil, errors.New("tls: client fingerprint not allowed")
		}
	}

	// Call hook to notify listeners of server profile being used.
	// Note: ServerProfile is different from FingerprintProfile (which is client-side).
	// We create a minimal FingerprintProfile to pass to the hook for compatibility.
	// Future improvement: Add a dedicated OnServerProfileSelected hook.
	fpProfile := &FingerprintProfile{
		ID:          sfc.profile.ID,
		Description: sfc.profile.Description,
	}
	if err := sfc.hooks.CallProfileSelected(fpProfile); err != nil {
		return nil, err
	}

	// Build config with controlled parameters
	config := sfc.buildConfig(chi)

	return config, nil
}

// AnalyzeClientHello computes fingerprints from ClientHelloInfo.
func (sfc *ServerFingerprintController) AnalyzeClientHello(chi *ClientHelloInfo) (*TLSFingerprint, error) {
	if chi == nil {
		return nil, errors.New("tls: nil ClientHelloInfo")
	}

	// Unfortunately ClientHelloInfo doesn't give us raw bytes
	// We can only compute partial fingerprint from available fields
	fp := &TLSFingerprint{}

	// Build approximate JA4 from available info
	// Format: t{version}{ciphers}{extensions}{sni}{alpn}
	var versionStr string
	for _, v := range chi.SupportedVersions {
		if v == VersionTLS13 {
			versionStr = "13"
			break
		}
		if v == VersionTLS12 {
			versionStr = "12"
		}
	}
	if versionStr == "" {
		versionStr = "00"
	}

	// SNI indicator
	sniChar := "d" // domain
	if chi.ServerName == "" {
		sniChar = "i" // IP or missing
	}

	// ALPN indicator
	alpnChar := "00"
	for _, proto := range chi.SupportedProtos {
		if proto == "h2" {
			alpnChar = "h2"
			break
		}
		if proto == "http/1.1" {
			alpnChar = "h1"
		}
	}

	// Cipher count
	cipherCount := len(chi.CipherSuites)
	if cipherCount > 99 {
		cipherCount = 99
	}

	// Extension count (approximate)
	extCount := 0
	if len(chi.SupportedVersions) > 0 {
		extCount++
	}
	if len(chi.SupportedCurves) > 0 {
		extCount++
	}
	if len(chi.SignatureSchemes) > 0 {
		extCount++
	}
	if len(chi.SupportedProtos) > 0 {
		extCount++
	}
	if chi.ServerName != "" {
		extCount++
	}

	// Build simplified JA4-like fingerprint
	fp.JA4 = fmt.Sprintf("t%s%s%02d%02d%s", versionStr, sniChar, cipherCount, extCount, alpnChar)

	return fp, nil
}

// validateClientFingerprint checks if client fingerprint is allowed.
func (sfc *ServerFingerprintController) validateClientFingerprint(fp *TLSFingerprint) bool {
	if len(sfc.opts.AllowedClientFingerprints) == 0 {
		return true // No restrictions
	}

	for _, allowed := range sfc.opts.AllowedClientFingerprints {
		if matchFingerprintPattern(fp.JA4, allowed) {
			return true
		}
	}

	return false
}

// matchFingerprintPattern matches a fingerprint against a pattern.
// Supports '*' as wildcard for any character sequence at any position.
// Examples:
//   - "*" matches everything
//   - "t13d*" matches anything starting with "t13d"
//   - "*h2" matches anything ending with "h2"
//   - "t13*h2" matches "t13d03h2", "t13d10h2", etc.
func matchFingerprintPattern(fingerprint, pattern string) bool {
	return matchWildcard(fingerprint, pattern)
}

// matchWildcard implements glob-style wildcard matching with '*' support.
// Uses dynamic programming for efficiency with multiple wildcards.
func matchWildcard(s, pattern string) bool {
	// Edge cases
	if pattern == "*" {
		return true
	}
	if pattern == "" {
		return s == ""
	}

	// dp[i][j] = true if s[:i] matches pattern[:j]
	m, n := len(s), len(pattern)
	dp := make([][]bool, m+1)
	for i := range dp {
		dp[i] = make([]bool, n+1)
	}

	// Empty pattern matches empty string
	dp[0][0] = true

	// Handle patterns starting with *
	for j := 1; j <= n; j++ {
		if pattern[j-1] == '*' {
			dp[0][j] = dp[0][j-1]
		}
	}

	// Fill the DP table
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if pattern[j-1] == '*' {
				// '*' can match zero characters (dp[i][j-1]) or more characters (dp[i-1][j])
				dp[i][j] = dp[i][j-1] || dp[i-1][j]
			} else if pattern[j-1] == '?' || s[i-1] == pattern[j-1] {
				// '?' matches any single character, or exact character match
				dp[i][j] = dp[i-1][j-1]
			}
		}
	}

	return dp[m][n]
}

// buildConfig creates a Config with controlled parameters.
// It merges the controller's settings with the base config's certificates.
func (sfc *ServerFingerprintController) buildConfig(chi *ClientHelloInfo) *Config {
	config := &Config{}

	// Set cipher suite preference based on profile
	if sfc.profile.ServerHello.CipherSelectionMode == "server" {
		config.CipherSuites = sfc.profile.ServerHello.CipherPreference
		config.PreferServerCipherSuites = true
	}

	// Set ALPN preference
	if len(sfc.profile.ServerHello.ALPNPreference) > 0 {
		config.NextProtos = sfc.profile.ServerHello.ALPNPreference
	}

	// Handle certificates:
	// 1. If GenerateCertificates is enabled, generate a certificate
	// 2. Otherwise, use FallbackCertificate if provided
	// 3. Otherwise, copy certificates from base config
	// 4. If no certificates available at all, return nil to use base config
	if sfc.opts.GenerateCertificates {
		hostname := chi.ServerName
		if hostname == "" {
			hostname = sfc.opts.CertificateHostname
		}
		if hostname != "" {
			cert, err := sfc.generateCertificate(hostname)
			if err == nil {
				config.Certificates = []Certificate{*cert}
			}
		}
	} else if sfc.opts.FallbackCertificate != nil {
		config.Certificates = []Certificate{*sfc.opts.FallbackCertificate}
	} else if chi.config != nil {
		// Copy certificates from base config
		if len(chi.config.Certificates) > 0 {
			config.Certificates = chi.config.Certificates
		}
		// Also copy GetCertificate if set
		if chi.config.GetCertificate != nil {
			config.GetCertificate = chi.config.GetCertificate
		}
	}

	// If we still have no certificates and no way to get them, return nil
	// to let the base config handle it
	if len(config.Certificates) == 0 && config.GetCertificate == nil {
		return nil
	}

	return config
}

// generateCertificate generates a certificate matching the profile.
func (sfc *ServerFingerprintController) generateCertificate(hostname string) (*Certificate, error) {
	sfc.mu.Lock()
	sfc.stats.CertsGenerated++
	sfc.mu.Unlock()

	x509Cert, privKey, err := GenerateCertificate(&sfc.profile.Certificate, hostname)
	if err != nil {
		return nil, err
	}

	return &Certificate{
		Certificate: [][]byte{x509Cert.Raw},
		PrivateKey:  privKey,
		Leaf:        x509Cert,
	}, nil
}

// BuildServerHello creates a ServerHello message with controlled fingerprint.
// This can be used for custom server implementations.
func (sfc *ServerFingerprintController) BuildServerHello(clientHello *clientHelloMsg) (*serverHelloMsg, error) {
	builder := NewServerHelloBuilder(sfc.profile).
		ForClientHello(clientHello)

	hello, err := builder.Build()
	if err != nil {
		return nil, err
	}

	// Call hook
	if err := sfc.hooks.CallBeforeSendServerHello(hello); err != nil {
		return nil, err
	}

	sfc.mu.Lock()
	sfc.stats.ServerHellosSent++
	sfc.mu.Unlock()

	return hello, nil
}

// SelectCipher selects a cipher suite based on profile and client preferences.
func (sfc *ServerFingerprintController) SelectCipher(clientCiphers []uint16) uint16 {
	return SelectCipher(sfc.profile, clientCiphers)
}

// SelectALPN selects an ALPN protocol based on profile and client preferences.
func (sfc *ServerFingerprintController) SelectALPN(clientProtocols []string) string {
	return SelectALPN(sfc.profile, clientProtocols)
}

// Profile returns the current server profile.
func (sfc *ServerFingerprintController) Profile() *ServerProfile {
	sfc.mu.RLock()
	defer sfc.mu.RUnlock()
	return sfc.profile
}

// Hooks returns the hook chain for adding custom hooks.
func (sfc *ServerFingerprintController) Hooks() *HookChain {
	return sfc.hooks
}

// AddHook adds a fingerprint hook to the controller.
func (sfc *ServerFingerprintController) AddHook(hook *FingerprintHooks) {
	sfc.hooks.Add(hook)
}

// Stats returns server fingerprint statistics.
func (sfc *ServerFingerprintController) Stats() ServerFingerprintStats {
	sfc.mu.RLock()
	defer sfc.mu.RUnlock()

	return ServerFingerprintStats{
		ClientHellosReceived: sfc.stats.ClientHellosReceived,
		ServerHellosSent:     sfc.stats.ServerHellosSent,
		CertsGenerated:       sfc.stats.CertsGenerated,
	}
}

// ServerFingerprintStats contains server fingerprint statistics.
type ServerFingerprintStats struct {
	ClientHellosReceived int64
	ServerHellosSent     int64
	CertsGenerated       int64
}

// ExpectedJA4S returns the expected JA4S fingerprint for the profile.
func (sfc *ServerFingerprintController) ExpectedJA4S() string {
	sfc.mu.RLock()
	defer sfc.mu.RUnlock()

	if sfc.profile == nil {
		return ""
	}
	return sfc.profile.ExpectedJA4S
}

// GenerateCertificateChain generates a certificate chain for the given hostname.
// If the profile has a custom Issuer configured (different from Subject), it generates
// a 2-cert chain (CA + leaf) to properly control the JA4X issuer hash component.
// Otherwise, it generates a single self-signed certificate.
func (sfc *ServerFingerprintController) GenerateCertificateChain(hostname string) ([]*x509.Certificate, crypto.PrivateKey, error) {
	// Determine chain length based on whether custom issuer is configured
	chainLength := 1
	if len(sfc.profile.Certificate.Issuer.Fields) > 0 {
		// Custom issuer configured - need CA chain to properly set issuer field
		chainLength = 2
	}
	return GenerateCertificateChain(&sfc.profile.Certificate, hostname, chainLength)
}

// FingerprintedListener wraps a net.Listener with fingerprint control.
type FingerprintedListener struct {
	inner      *listener
	controller *ServerFingerprintController
	baseConfig *Config
}

// NewFingerprintedListener creates a TLS listener with fingerprint control.
// The inner listener's config is augmented with fingerprint control via GetConfigForClient.
func NewFingerprintedListener(inner *listener, profileID string) (*FingerprintedListener, error) {
	ctrl, err := NewServerFingerprintController(profileID)
	if err != nil {
		return nil, err
	}

	// Store original config and inject our GetConfigForClient
	baseConfig := inner.config.Clone()

	// Chain the GetConfigForClient callbacks
	originalGetConfig := baseConfig.GetConfigForClient
	baseConfig.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		// First apply fingerprint control
		fpConfig, err := ctrl.GetConfigForClient(chi)
		if err != nil {
			return nil, err
		}

		// Then call original if it exists
		if originalGetConfig != nil {
			origConfig, err := originalGetConfig(chi)
			if err != nil {
				return nil, err
			}
			// Merge: fingerprint config takes precedence for fingerprint-related fields
			if origConfig != nil && fpConfig != nil {
				// Keep certificates from original if fingerprint config doesn't have them
				if len(fpConfig.Certificates) == 0 && len(origConfig.Certificates) > 0 {
					fpConfig.Certificates = origConfig.Certificates
				}
				if fpConfig.GetCertificate == nil && origConfig.GetCertificate != nil {
					fpConfig.GetCertificate = origConfig.GetCertificate
				}
			}
		}

		return fpConfig, nil
	}

	// Update the inner listener's config
	inner.config = baseConfig

	return &FingerprintedListener{
		inner:      inner,
		controller: ctrl,
		baseConfig: baseConfig,
	}, nil
}

// Accept waits for and returns the next connection with fingerprint control applied.
func (fl *FingerprintedListener) Accept() (*Conn, error) {
	// The inner listener now has GetConfigForClient set, so fingerprint control
	// is applied automatically during the TLS handshake
	conn, err := fl.inner.Accept()
	if err != nil {
		return nil, err
	}

	tlsConn, ok := conn.(*Conn)
	if !ok {
		// This should not happen with a properly configured TLS listener
		return nil, errors.New("tls: expected *Conn from listener")
	}

	return tlsConn, nil
}

// Close closes the listener.
func (fl *FingerprintedListener) Close() error {
	return fl.inner.Close()
}

// Controller returns the fingerprint controller.
func (fl *FingerprintedListener) Controller() *ServerFingerprintController {
	return fl.controller
}

// QuickServerConfig creates a Config with fingerprint control for the given profile.
// This is a convenience function for simple setups.
// Returns only the config - use QuickServerConfigWithController if you need access to the controller.
func QuickServerConfig(profileID string, cert Certificate) (*Config, error) {
	config, _, err := QuickServerConfigWithController(profileID, cert)
	return config, err
}

// QuickServerConfigWithController creates a Config with fingerprint control and returns both
// the config and the controller. Use this when you need access to controller methods like
// Stats(), AddHook(), etc.
func QuickServerConfigWithController(profileID string, cert Certificate) (*Config, *ServerFingerprintController, error) {
	ctrl, err := NewServerFingerprintController(profileID)
	if err != nil {
		return nil, nil, err
	}

	config := &Config{
		GetConfigForClient: ctrl.GetConfigForClient,
		Certificates:       []Certificate{cert},
	}

	// Apply profile preferences
	if ctrl.profile.ServerHello.CipherSelectionMode == "server" {
		config.CipherSuites = ctrl.profile.ServerHello.CipherPreference
		config.PreferServerCipherSuites = true
	}
	if len(ctrl.profile.ServerHello.ALPNPreference) > 0 {
		config.NextProtos = ctrl.profile.ServerHello.ALPNPreference
	}

	return config, ctrl, nil
}
