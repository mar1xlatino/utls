// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// FingerprintController orchestrates TLS fingerprint control for a connection.
// It manages the fingerprint profile, session state, hooks, and record layer controller.
//
// Usage:
//
//	uconn := tls.UClient(conn, config, tls.HelloCustom)
//	ctrl := tls.NewFingerprintController()
//	if err := ctrl.ApplyProfile(uconn, "chrome_142_windows_11"); err != nil {
//	    return err
//	}
//	// Connection now uses Chrome 142 fingerprint with frozen GREASE values
type FingerprintController struct {
	// Profile is the fingerprint profile being applied
	profile *FingerprintProfile

	// SessionState holds frozen values (GREASE, extension order) for session consistency
	sessionState *SessionFingerprintState

	// Hooks for extensibility and monitoring
	hooks *HookChain

	// RecordController for record-level fingerprinting (TLS 1.3 padding)
	recordController *RecordLayerController

	// TimingController for inter-record timing control (application-level delays)
	// Note: Timing is NOT automatically applied in conn.Write() because blocking I/O
	// would affect performance. Use GetRecordDelay() to get suggested delays and
	// apply them in your application code before writes.
	timingController *RecordTimingController

	// Validator for runtime fingerprint verification
	validator *FingerprintValidator

	// Options
	opts FingerprintControllerOptions

	mu sync.RWMutex
}

// FingerprintControllerOptions configures the fingerprint controller behavior.
type FingerprintControllerOptions struct {
	// ValidateOnBuild validates the ClientHello fingerprint after building
	ValidateOnBuild bool

	// StrictValidation fails the handshake if fingerprint validation fails
	StrictValidation bool

	// FreezeSessionOnFirstUse freezes the session state after first use
	FreezeSessionOnFirstUse bool

	// UseSessionCache uses the global session cache for session state
	UseSessionCache bool

	// SessionCacheKey overrides the default session cache key (origin)
	SessionCacheKey string
}

// DefaultFingerprintControllerOptions returns sensible defaults.
func DefaultFingerprintControllerOptions() FingerprintControllerOptions {
	return FingerprintControllerOptions{
		ValidateOnBuild:         false,
		StrictValidation:        false,
		FreezeSessionOnFirstUse: true,
		UseSessionCache:         true,
	}
}

// NewFingerprintController creates a new fingerprint controller with default options.
func NewFingerprintController() *FingerprintController {
	return NewFingerprintControllerWithOptions(DefaultFingerprintControllerOptions())
}

// NewFingerprintControllerWithOptions creates a controller with custom options.
func NewFingerprintControllerWithOptions(opts FingerprintControllerOptions) *FingerprintController {
	return &FingerprintController{
		hooks: NewHookChain(),
		opts:  opts,
	}
}

// ApplyProfile applies a fingerprint profile to a UConn by profile ID.
// This must be called before BuildHandshakeState() or Handshake().
func (fc *FingerprintController) ApplyProfile(uconn *UConn, profileID string) error {
	if uconn == nil {
		return errors.New("tls: cannot apply profile to nil UConn")
	}

	profile, err := DefaultRegistry.Get(profileID)
	if err != nil {
		return fmt.Errorf("tls: unknown fingerprint profile %s: %w", profileID, err)
	}

	return fc.ApplyFingerprintProfile(uconn, profile)
}

// ApplyFingerprintProfile applies a FingerprintProfile to a UConn.
func (fc *FingerprintController) ApplyFingerprintProfile(uconn *UConn, profile *FingerprintProfile) error {
	if uconn == nil {
		return errors.New("tls: cannot apply profile to nil UConn")
	}
	if profile == nil {
		return errors.New("tls: cannot apply nil profile")
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Clone the profile to avoid mutations affecting other connections
	fc.profile = profile.Clone()

	// Call hook: profile selected
	if err := fc.hooks.CallProfileSelected(fc.profile); err != nil {
		return fmt.Errorf("tls: profile selection hook failed: %w", err)
	}

	// Get or create session state for consistent GREASE/extension order
	origin := fc.getOrigin(uconn)
	if fc.opts.UseSessionCache && origin != "" {
		fc.sessionState = DefaultSessionCache.GetOrCreate(origin, fc.profile)
	} else {
		fc.sessionState = NewSessionFingerprintState(fc.profile, origin)
	}

	// Call hook: session state created/restored
	if fc.sessionState.ConnectionCount() == 1 {
		if err := fc.hooks.CallSessionStateCreated(fc.sessionState); err != nil {
			return fmt.Errorf("tls: session state creation hook failed: %w", err)
		}
	} else {
		if err := fc.hooks.CallSessionStateRestored(fc.sessionState); err != nil {
			return fmt.Errorf("tls: session state restoration hook failed: %w", err)
		}
	}

	// Build ClientHelloSpec from profile
	spec, err := fc.buildClientHelloSpec()
	if err != nil {
		return fmt.Errorf("tls: failed to build ClientHelloSpec: %w", err)
	}

	// Apply the spec to UConn
	// NOTE: ApplyPreset regenerates GREASE values, so we must apply frozen GREASE AFTER
	if err := uconn.ApplyPreset(spec); err != nil {
		return fmt.Errorf("tls: failed to apply preset: %w", err)
	}

	// Apply frozen GREASE values to UConn's greaseSeed AFTER ApplyPreset
	// (ApplyPreset regenerates random GREASE, we override with frozen values)
	fc.applyFrozenGREASE(uconn)

	// Set up record layer controller if padding is enabled
	if fc.profile.RecordLayer.PaddingEnabled {
		fc.recordController = NewRecordLayerController(&fc.profile.RecordLayer)

		// Wire to Config.RecordPadding - this is what actually applies padding in conn.writeRecordLocked()
		uconn.config.RecordPadding = convertRecordLayerToRecordPadding(&fc.profile.RecordLayer)
	}

	// Set up timing controller (for application-level timing control)
	fc.timingController = NewRecordTimingController()

	// Set up validator
	fc.validator = NewValidator(fc.profile)

	// Freeze session state if configured
	if fc.opts.FreezeSessionOnFirstUse {
		fc.sessionState.Freeze()
	}

	return nil
}

// getOrigin extracts the origin (host:port) from UConn config.
func (fc *FingerprintController) getOrigin(uconn *UConn) string {
	if fc.opts.SessionCacheKey != "" {
		return fc.opts.SessionCacheKey
	}
	if uconn.config != nil && uconn.config.ServerName != "" {
		return uconn.config.ServerName + ":443"
	}
	return ""
}

// applyFrozenGREASE applies frozen GREASE values from session state to UConn.
// This must be called AFTER ApplyPreset() since ApplyPreset regenerates GREASE.
// We also need to re-apply GREASE to hello fields since ApplyPreset already
// replaced placeholders with random GREASE values.
//
// IMPORTANT: SetTLSVers() overwrites Hello.SupportedVersions using makeSupportedVersions()
// which does NOT include GREASE. We must prepend our frozen GREASE value if the profile
// specifies GREASE should be in supported_versions.
func (fc *FingerprintController) applyFrozenGREASE(uconn *UConn) {
	if fc.sessionState == nil || fc.profile == nil || !fc.profile.ClientHello.GREASE.Enabled {
		return
	}

	grease := fc.sessionState.FrozenGREASE
	ch := &fc.profile.ClientHello

	// Set greaseSeed to our frozen values
	// Note: greaseSeed stores values that GetBoringGREASEValue transforms
	// GetBoringGREASEValue takes (seed & 0xf0) | 0x0a and duplicates it
	// So we store the seed such that transformation gives our frozen GREASE value
	// For frozen value 0xXaXa, we need seed high nibble = X
	uconn.greaseSeed[ssl_grease_cipher] = grease.CipherSuite >> 8     // High byte becomes nibble
	uconn.greaseSeed[ssl_grease_group] = grease.SupportedGroup >> 8   // High byte becomes nibble
	uconn.greaseSeed[ssl_grease_extension1] = grease.Extension1 >> 8  // High byte becomes nibble
	uconn.greaseSeed[ssl_grease_extension2] = grease.Extension2 >> 8  // High byte becomes nibble
	uconn.greaseSeed[ssl_grease_version] = grease.SupportedVersion >> 8

	// Now re-apply GREASE to hello fields that ApplyPreset already processed
	hello := uconn.HandshakeState.Hello

	// Fix cipher suites - replace any GREASE with our frozen value, or prepend if missing
	hasGREASECipher := false
	for i := range hello.CipherSuites {
		if isGREASEUint16(hello.CipherSuites[i]) {
			hello.CipherSuites[i] = grease.CipherSuite
			hasGREASECipher = true
		}
	}
	if !hasGREASECipher && ch.GREASE.CipherSuites {
		// Prepend GREASE cipher suite
		hello.CipherSuites = append([]uint16{grease.CipherSuite}, hello.CipherSuites...)
	}

	// Fix supported versions - SetTLSVers() uses makeSupportedVersions() which REMOVES GREASE
	// We must check if profile wants GREASE in supported_versions and prepend it
	hasGREASEVersion := false
	for i := range hello.SupportedVersions {
		if isGREASEUint16(hello.SupportedVersions[i]) {
			hello.SupportedVersions[i] = grease.SupportedVersion
			hasGREASEVersion = true
		}
	}
	if !hasGREASEVersion && ch.GREASE.SupportedVersions {
		// Prepend frozen GREASE to SupportedVersions
		hello.SupportedVersions = append([]uint16{grease.SupportedVersion}, hello.SupportedVersions...)
	}

	// ALWAYS fix SupportedVersionsExtension - writeToUConn will overwrite hello.SupportedVersions
	for _, ext := range uconn.Extensions {
		if sve, ok := ext.(*SupportedVersionsExtension); ok {
			// Check if it already has GREASE
			hasGrease := false
			for i := range sve.Versions {
				if isGREASEUint16(sve.Versions[i]) {
					sve.Versions[i] = grease.SupportedVersion
					hasGrease = true
				}
			}
			if !hasGrease && ch.GREASE.SupportedVersions {
				sve.Versions = append([]uint16{grease.SupportedVersion}, sve.Versions...)
			}
			break
		}
	}

	// Fix supported curves/groups in hello AND in extension
	// CRITICAL: Must fix the extension too, otherwise writeToUConn overwrites hello
	hasGREASEGroup := false
	for i := range hello.SupportedCurves {
		if isGREASEUint16(uint16(hello.SupportedCurves[i])) {
			hello.SupportedCurves[i] = CurveID(grease.SupportedGroup)
			hasGREASEGroup = true
		}
	}
	if !hasGREASEGroup && ch.GREASE.SupportedGroups {
		// Prepend GREASE group
		hello.SupportedCurves = append([]CurveID{CurveID(grease.SupportedGroup)}, hello.SupportedCurves...)
	}

	// Also fix SupportedCurvesExtension - writeToUConn will overwrite hello.SupportedCurves
	for _, ext := range uconn.Extensions {
		if sce, ok := ext.(*SupportedCurvesExtension); ok {
			hasGrease := false
			for i := range sce.Curves {
				if isGREASEUint16(uint16(sce.Curves[i])) {
					sce.Curves[i] = CurveID(grease.SupportedGroup)
					hasGrease = true
				}
			}
			if !hasGrease && ch.GREASE.SupportedGroups {
				sce.Curves = append([]CurveID{CurveID(grease.SupportedGroup)}, sce.Curves...)
			}
			break
		}
	}

	// Fix key shares in hello AND in extension
	hasGREASEKeyShare := false
	for i := range hello.KeyShares {
		if isGREASEUint16(uint16(hello.KeyShares[i].Group)) {
			hello.KeyShares[i].Group = CurveID(grease.KeyShare)
			hasGREASEKeyShare = true
		}
	}
	if !hasGREASEKeyShare && ch.GREASE.KeyShare {
		// Prepend GREASE key share with single byte (empty data is invalid per RFC 8446)
		hello.KeyShares = append([]KeyShare{{Group: CurveID(grease.KeyShare), Data: []byte{0}}}, hello.KeyShares...)
	}

	// Also fix KeyShareExtension - writeToUConn will overwrite hello.KeyShares
	for _, ext := range uconn.Extensions {
		if kse, ok := ext.(*KeyShareExtension); ok {
			hasGrease := false
			for i := range kse.KeyShares {
				if isGREASEUint16(uint16(kse.KeyShares[i].Group)) {
					kse.KeyShares[i].Group = CurveID(grease.KeyShare)
					hasGrease = true
				}
			}
			if !hasGrease && ch.GREASE.KeyShare {
				kse.KeyShares = append([]KeyShare{{Group: CurveID(grease.KeyShare), Data: []byte{0}}}, kse.KeyShares...)
			}
			break
		}
	}

	// Fix GREASE extensions themselves
	// Extensions built from GREASE markers already have correct Value set.
	// Extensions built from raw GREASE types (0x?a?a) need Value assigned here.
	// We track seen values to handle the edge case of mixed marker/raw GREASE.
	ext1Used := false
	ext2Used := false
	for _, ext := range uconn.Extensions {
		if ge, ok := ext.(*UtlsGREASEExtension); ok {
			if ge.Value == 0 {
				// No value set yet (built from raw GREASE type) - assign based on order
				if !ext1Used {
					ge.Value = grease.Extension1
					ext1Used = true
				} else if !ext2Used {
					ge.Value = grease.Extension2
					ge.Body = []byte{0} // Second GREASE extension has body
					ext2Used = true
				}
			} else {
				// Value already set (from marker) - mark as used
				if ge.Value == grease.Extension1 {
					ext1Used = true
				} else if ge.Value == grease.Extension2 {
					ext2Used = true
				}
			}
		}
	}
}

// buildClientHelloSpec builds a ClientHelloSpec from the profile.
func (fc *FingerprintController) buildClientHelloSpec() (*ClientHelloSpec, error) {
	if fc.profile == nil {
		return nil, errors.New("tls: no profile set")
	}

	ch := &fc.profile.ClientHello

	// Derive min/max version from SupportedVersions
	// Skip GREASE values when determining version range
	var minVers, maxVers uint16
	for _, v := range ch.SupportedVersions {
		if isGREASEUint16(v) {
			continue // Skip GREASE placeholders
		}
		if minVers == 0 || v < minVers {
			minVers = v
		}
		if maxVers == 0 || v > maxVers {
			maxVers = v
		}
	}
	// Default to TLS 1.2 if no valid versions found
	if minVers == 0 {
		minVers = VersionTLS12
	}
	if maxVers == 0 {
		maxVers = VersionTLS12
	}

	spec := &ClientHelloSpec{
		TLSVersMin: minVers,
		TLSVersMax: maxVers,
	}

	// Copy cipher suites
	spec.CipherSuites = make([]uint16, len(ch.CipherSuites))
	copy(spec.CipherSuites, ch.CipherSuites)

	// Build extensions
	extensions, err := fc.buildExtensions()
	if err != nil {
		return nil, err
	}
	spec.Extensions = extensions

	// Set compression methods (always null compression for TLS 1.3)
	spec.CompressionMethods = []uint8{0}

	return spec, nil
}

// buildExtensions builds TLS extensions from the profile.
func (fc *FingerprintController) buildExtensions() ([]TLSExtension, error) {
	ch := &fc.profile.ClientHello

	// Priority:
	// 1. If profile has explicit Extensions (with data), use those
	// 2. If profile has ExtensionOrder (types only), build extensions in that order
	// 3. Otherwise, generate default extensions

	if len(ch.Extensions) > 0 {
		return fc.buildExtensionsFromProfile()
	}

	if len(ch.ExtensionOrder) > 0 {
		return fc.buildExtensionsFromOrder()
	}

	// Fallback to default extension set
	return fc.generateDefaultExtensions()
}

// buildExtensionsFromOrder builds extensions from ExtensionOrder (types only).
// This is used when profile specifies extension ORDER but not explicit extension data.
// Extension data is generated from profile fields (SupportedGroups, ALPNProtocols, etc.)
func (fc *FingerprintController) buildExtensionsFromOrder() ([]TLSExtension, error) {
	if fc.profile == nil {
		return nil, errors.New("tls: profile not set")
	}
	ch := &fc.profile.ClientHello
	var extensions []TLSExtension

	// Use frozen extension order if available (for shuffle consistency)
	// Otherwise use the profile's ExtensionOrder directly
	var extOrder []uint16
	if fc.sessionState != nil && len(fc.sessionState.FrozenExtensionOrder) > 0 {
		extOrder = fc.sessionState.FrozenExtensionOrder
	} else {
		extOrder = ch.ExtensionOrder
	}

	// Validate: empty extension order is likely a configuration error
	if len(extOrder) == 0 {
		return nil, errors.New("tls: ExtensionOrder is empty - profile must specify extension order or use Extensions field")
	}

	// Track seen extension types to detect duplicates (except GREASE which can appear multiple times)
	seenExtensions := make(map[uint16]bool)

	// Build each extension in order
	for i, extType := range extOrder {
		// Allow multiple GREASE extensions and GREASE markers, but not duplicates of other types
		if !isGREASEUint16(extType) && !IsGreaseExtMarker(extType) {
			if seenExtensions[extType] {
				return nil, fmt.Errorf("tls: duplicate extension type %d (0x%04x) at position %d", extType, extType, i)
			}
			seenExtensions[extType] = true
		}

		tlsExt, err := fc.buildExtensionByType(extType)
		if err != nil {
			return nil, fmt.Errorf("tls: failed to build extension %d (0x%04x): %w", extType, extType, err)
		}
		if tlsExt != nil {
			extensions = append(extensions, tlsExt)
		}
	}

	return extensions, nil
}

// buildExtensionByType builds a TLS extension by its type ID.
// Uses profile configuration fields to populate extension data.
//
// GREASE handling: This function handles both raw GREASE types (0x?a?a) and
// GREASE markers (GreaseExtMarker1, GreaseExtMarker2). Markers are used when
// extensions have been shuffled to preserve which GREASE was originally first.
func (fc *FingerprintController) buildExtensionByType(extType uint16) (TLSExtension, error) {
	ch := &fc.profile.ClientHello

	// Check for GREASE markers first (used after shuffle to preserve original order)
	// The marker tells us which frozen GREASE value to use
	if extType == GreaseExtMarker1 {
		return &UtlsGREASEExtension{
			Value: fc.sessionState.FrozenGREASE.Extension1,
		}, nil
	}
	if extType == GreaseExtMarker2 {
		return &UtlsGREASEExtension{
			Value: fc.sessionState.FrozenGREASE.Extension2,
			Body:  []byte{0}, // Second GREASE extension has body per Chrome behavior
		}, nil
	}

	// Check for raw GREASE types (for profiles that don't use shuffle)
	if isGREASEUint16(extType) {
		return &UtlsGREASEExtension{}, nil
	}

	switch extType {
	case extensionServerName: // 0
		return &SNIExtension{}, nil

	case extensionStatusRequest: // 5
		return &StatusRequestExtension{}, nil

	case extensionSupportedCurves: // 10
		if len(ch.SupportedGroups) > 0 {
			groups := make([]CurveID, len(ch.SupportedGroups))
			copy(groups, ch.SupportedGroups)
			return &SupportedCurvesExtension{Curves: groups}, nil
		}
		return &SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256, CurveP384}}, nil

	case extensionSupportedPoints: // 11
		return &SupportedPointsExtension{SupportedPoints: []uint8{0}}, nil

	case extensionSignatureAlgorithms: // 13
		if len(ch.SignatureAlgorithms) > 0 {
			algs := make([]SignatureScheme, len(ch.SignatureAlgorithms))
			copy(algs, ch.SignatureAlgorithms)
			return &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: algs}, nil
		}
		return nil, nil

	case extensionALPN: // 16
		if len(ch.ALPNProtocols) > 0 {
			return &ALPNExtension{AlpnProtocols: ch.ALPNProtocols}, nil
		}
		return nil, nil

	case extensionSCT: // 18
		return &SCTExtension{}, nil

	case extensionExtendedMasterSecret: // 23
		return &ExtendedMasterSecretExtension{}, nil

	case extensionSessionTicket: // 35
		return &SessionTicketExtension{}, nil

	case extensionSupportedVersions: // 43
		if len(ch.SupportedVersions) > 0 {
			versions := make([]uint16, len(ch.SupportedVersions))
			copy(versions, ch.SupportedVersions)
			return &SupportedVersionsExtension{Versions: versions}, nil
		}
		return nil, nil

	case extensionPSKModes: // 45
		if len(ch.PSKModes) > 0 {
			modes := make([]uint8, len(ch.PSKModes))
			copy(modes, ch.PSKModes)
			return &PSKKeyExchangeModesExtension{Modes: modes}, nil
		}
		return &PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}}, nil

	case extensionKeyShare: // 51
		// Use KeyShareGroups from profile, find first non-GREASE
		var keyShareGroup CurveID = X25519 // default
		if len(ch.KeyShareGroups) > 0 {
			for _, g := range ch.KeyShareGroups {
				if !isGREASEUint16(uint16(g)) {
					keyShareGroup = g
					break
				}
			}
		}
		return &KeyShareExtension{KeyShares: []KeyShare{{Group: keyShareGroup}}}, nil

	case extensionRenegotiationInfo: // 65281 (0xff01)
		return &RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}, nil

	case utlsExtensionCompressCertificate: // 27 (0x001b)
		if len(ch.CertCompressionAlgos) > 0 {
			algos := make([]CertCompressionAlgo, len(ch.CertCompressionAlgos))
			copy(algos, ch.CertCompressionAlgos)
			return &UtlsCompressCertExtension{Algorithms: algos}, nil
		}
		return &UtlsCompressCertExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}}, nil

	case utlsExtensionApplicationSettings: // 17513 (0x4469)
		if len(ch.ALPNProtocols) > 0 {
			return &ApplicationSettingsExtension{SupportedProtocols: ch.ALPNProtocols}, nil
		}
		return nil, nil

	case utlsExtensionApplicationSettingsNew: // 17613 (0x44cd) - Chrome 140+ uses this
		if len(ch.ALPNProtocols) > 0 {
			return &ApplicationSettingsExtensionNew{SupportedProtocols: ch.ALPNProtocols}, nil
		}
		return nil, nil

	case fakeExtensionDelegatedCredentials: // 34 (0x0022) - Firefox
		return &FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: ch.SignatureAlgorithms,
		}, nil

	case fakeRecordSizeLimit: // 28 (0x001c) - Firefox
		limit := ch.RecordSizeLimit
		if limit == 0 {
			limit = 16385 // Default Firefox record size limit
		}
		return &FakeRecordSizeLimitExtension{Limit: limit}, nil

	case extensionPreSharedKey: // 41 (0x0029) - Firefox for session resumption
		// PSK extension is only added during session resumption when there's actual PSK data.
		// Without session data, return nil to omit it from the handshake.
		// The extension type in ExtensionOrder indicates Firefox supports PSK, but it's not
		// included in the ClientHello unless there's a session to resume.
		return nil, nil

	case utlsExtensionPadding: // 21
		return &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, nil

	case utlsExtensionECH: // 65037 (0xfe0d) - Encrypted Client Hello
		// ECH GREASE extension - uses default cipher suite
		return &GREASEEncryptedClientHelloExtension{
			CandidatePayloadLens: []uint16{128, 160, 192, 224},
		}, nil

	default:
		// Unknown extension type - skip it
		return nil, nil
	}
}

// buildExtensionsFromProfile builds extensions from explicit profile configuration.
func (fc *FingerprintController) buildExtensionsFromProfile() ([]TLSExtension, error) {
	ch := &fc.profile.ClientHello
	var extensions []TLSExtension

	// Get extension order - use frozen order if available, otherwise profile order
	var extOrder []uint16
	if len(fc.sessionState.FrozenExtensionOrder) > 0 {
		extOrder = fc.sessionState.FrozenExtensionOrder
	} else {
		extOrder = make([]uint16, len(ch.Extensions))
		for i, ext := range ch.Extensions {
			extOrder[i] = ext.Type
		}
	}

	// Build extension map for lookup
	extMap := make(map[uint16]ExtensionEntry)
	for _, ext := range ch.Extensions {
		extMap[ext.Type] = ext
	}

	// Build extensions in the specified order
	for _, extType := range extOrder {
		ext, ok := extMap[extType]
		if !ok {
			// Extension in order but not in profile - skip (may be GREASE placeholder)
			if isGREASEUint16(extType) {
				extensions = append(extensions, &UtlsGREASEExtension{})
			}
			continue
		}

		tlsExt, err := fc.buildExtension(ext)
		if err != nil {
			return nil, fmt.Errorf("tls: failed to build extension %d: %w", extType, err)
		}
		if tlsExt != nil {
			extensions = append(extensions, tlsExt)
		}
	}

	return extensions, nil
}

// generateDefaultExtensions generates a sensible default set of extensions
// based on the profile's other configuration (cipher suites, groups, etc.)
func (fc *FingerprintController) generateDefaultExtensions() ([]TLSExtension, error) {
	ch := &fc.profile.ClientHello
	var extensions []TLSExtension

	// Add GREASE extension at start if enabled
	if ch.GREASE.Enabled && ch.GREASE.Extensions {
		extensions = append(extensions, &UtlsGREASEExtension{})
	}

	// SNI extension
	extensions = append(extensions, &SNIExtension{})

	// Extended Master Secret
	extensions = append(extensions, &ExtendedMasterSecretExtension{})

	// Renegotiation Info
	extensions = append(extensions, &RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient})

	// Supported Groups
	if len(ch.SupportedGroups) > 0 {
		extensions = append(extensions, &SupportedCurvesExtension{Curves: ch.SupportedGroups})
	}

	// EC Point Formats
	extensions = append(extensions, &SupportedPointsExtension{SupportedPoints: []uint8{0}})

	// Session Ticket
	extensions = append(extensions, &SessionTicketExtension{})

	// ALPN
	if len(ch.ALPNProtocols) > 0 {
		extensions = append(extensions, &ALPNExtension{AlpnProtocols: ch.ALPNProtocols})
	}

	// Status Request (OCSP)
	extensions = append(extensions, &StatusRequestExtension{})

	// Signature Algorithms
	if len(ch.SignatureAlgorithms) > 0 {
		extensions = append(extensions, &SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: ch.SignatureAlgorithms,
		})
	}

	// SCT
	extensions = append(extensions, &SCTExtension{})

	// Key Share (TLS 1.3)
	if hasVersion(ch.SupportedVersions, VersionTLS13) {
		var keyShareGroup CurveID = X25519
		for _, g := range ch.KeyShareGroups {
			if !isGREASEUint16(uint16(g)) {
				keyShareGroup = g
				break
			}
		}
		extensions = append(extensions, &KeyShareExtension{
			KeyShares: []KeyShare{{Group: keyShareGroup}},
		})
	}

	// PSK Key Exchange Modes (TLS 1.3)
	if hasVersion(ch.SupportedVersions, VersionTLS13) {
		extensions = append(extensions, &PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}})
	}

	// Supported Versions
	if len(ch.SupportedVersions) > 0 {
		extensions = append(extensions, &SupportedVersionsExtension{Versions: ch.SupportedVersions})
	}

	// Compress Certificate (if enabled)
	if len(ch.CertCompressionAlgos) > 0 {
		extensions = append(extensions, &UtlsCompressCertExtension{
			Algorithms: ch.CertCompressionAlgos,
		})
	}

	// Application Settings (ALPS) if enabled
	if ch.ApplicationSettings && len(ch.ALPNProtocols) > 0 {
		extensions = append(extensions, &ApplicationSettingsExtension{
			SupportedProtocols: ch.ALPNProtocols,
		})
	}

	// Second GREASE extension near end if enabled
	if ch.GREASE.Enabled && ch.GREASE.Extensions {
		extensions = append(extensions, &UtlsGREASEExtension{})
	}

	// Padding extension (should be last or near-last for Chrome-like behavior)
	if ch.PaddingStyle == PaddingChrome {
		extensions = append(extensions, &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle})
	}

	return extensions, nil
}

// hasVersion checks if a version is in the list (ignoring GREASE)
func hasVersion(versions []uint16, target uint16) bool {
	for _, v := range versions {
		if v == target {
			return true
		}
	}
	return false
}

// buildExtension builds a single TLS extension from ExtensionEntry.
func (fc *FingerprintController) buildExtension(entry ExtensionEntry) (TLSExtension, error) {
	ch := &fc.profile.ClientHello

	switch entry.Type {
	case extensionServerName:
		return &SNIExtension{}, nil

	case extensionStatusRequest:
		return &StatusRequestExtension{}, nil

	case extensionSupportedCurves:
		groups := make([]CurveID, len(ch.SupportedGroups))
		copy(groups, ch.SupportedGroups)
		return &SupportedCurvesExtension{Curves: groups}, nil

	case extensionSupportedPoints:
		return &SupportedPointsExtension{SupportedPoints: []uint8{0}}, nil

	case extensionSignatureAlgorithms:
		algs := make([]SignatureScheme, len(ch.SignatureAlgorithms))
		copy(algs, ch.SignatureAlgorithms)
		return &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: algs}, nil

	case extensionALPN:
		return &ALPNExtension{AlpnProtocols: ch.ALPNProtocols}, nil

	case extensionSCT:
		return &SCTExtension{}, nil

	case utlsExtensionPadding:
		return &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, nil

	case extensionExtendedMasterSecret:
		return &ExtendedMasterSecretExtension{}, nil

	case extensionSessionTicket:
		return &SessionTicketExtension{}, nil

	case extensionSupportedVersions:
		versions := make([]uint16, len(ch.SupportedVersions))
		copy(versions, ch.SupportedVersions)
		return &SupportedVersionsExtension{Versions: versions}, nil

	case extensionPSKModes:
		return &PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}}, nil

	case extensionKeyShare:
		// Find first non-GREASE key share group
		var keyShareGroup CurveID = X25519 // default
		for _, g := range ch.KeyShareGroups {
			if !isGREASEUint16(uint16(g)) {
				keyShareGroup = g
				break
			}
		}
		return &KeyShareExtension{KeyShares: []KeyShare{{Group: keyShareGroup}}}, nil

	case utlsExtensionCompressCertificate:
		return &UtlsCompressCertExtension{
			Algorithms: []CertCompressionAlgo{CertCompressionBrotli},
		}, nil

	case utlsExtensionApplicationSettings:
		return &ApplicationSettingsExtension{SupportedProtocols: ch.ALPNProtocols}, nil

	case utlsExtensionApplicationSettingsNew: // 17613 (0x44cd) - Chrome 140+
		return &ApplicationSettingsExtensionNew{SupportedProtocols: ch.ALPNProtocols}, nil

	case fakeExtensionDelegatedCredentials: // 34 (0x0022) - Firefox
		return &FakeDelegatedCredentialsExtension{
			SupportedSignatureAlgorithms: ch.SignatureAlgorithms,
		}, nil

	case fakeRecordSizeLimit: // 28 (0x001c) - Firefox
		limit := ch.RecordSizeLimit
		if limit == 0 {
			limit = 16385 // Default Firefox record size limit
		}
		return &FakeRecordSizeLimitExtension{Limit: limit}, nil

	case extensionPreSharedKey: // 41 (0x0029) - Firefox session resumption
		// PSK extension requires session data - omit when no session to resume
		return nil, nil

	case extensionRenegotiationInfo:
		return &RenegotiationInfoExtension{Renegotiation: RenegotiateOnceAsClient}, nil

	default:
		// Check if GREASE
		if isGREASEUint16(entry.Type) {
			return &UtlsGREASEExtension{}, nil
		}

		// Unknown extension - use generic extension if data is available
		if entry.Data != nil {
			if data, ok := entry.Data.([]byte); ok {
				return &GenericExtension{Id: entry.Type, Data: data}, nil
			}
		}

		// Return nil for unknown extensions without data
		return nil, nil
	}
}

// Profile returns the current fingerprint profile.
func (fc *FingerprintController) Profile() *FingerprintProfile {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.profile
}

// SessionState returns the current session state.
func (fc *FingerprintController) SessionState() *SessionFingerprintState {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.sessionState
}

// Hooks returns the hook chain for adding custom hooks.
func (fc *FingerprintController) Hooks() *HookChain {
	return fc.hooks
}

// RecordController returns the record layer controller.
func (fc *FingerprintController) RecordController() *RecordLayerController {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.recordController
}

// TimingController returns the record timing controller.
// Use this to configure inter-record timing delays.
//
// Example:
//
//	ctrl.TimingController().SetDelay(10 * time.Millisecond)
//	ctrl.TimingController().SetJitter(5 * time.Millisecond)
//	ctrl.TimingController().SetBurstSize(3) // Send 3 records, then delay
func (fc *FingerprintController) TimingController() *RecordTimingController {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.timingController
}

// GetRecordDelay returns the suggested delay before sending the next record.
// This is for application-level timing control - call this before each Write()
// and apply the delay yourself if desired.
//
// Example:
//
//	delay := ctrl.GetRecordDelay()
//	if delay > 0 {
//	    time.Sleep(delay)
//	}
//	conn.Write(data)
func (fc *FingerprintController) GetRecordDelay() time.Duration {
	fc.mu.RLock()
	tc := fc.timingController
	fc.mu.RUnlock()

	if tc == nil {
		return 0
	}
	return tc.GetDelay()
}

// Validator returns the fingerprint validator.
func (fc *FingerprintController) Validator() *FingerprintValidator {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.validator
}

// AddHook adds a fingerprint hook to the controller.
// Returns error if hook chain is at capacity.
func (fc *FingerprintController) AddHook(hook *FingerprintHooks) error {
	return fc.hooks.Add(hook)
}

// ValidateClientHello validates a ClientHello against the expected fingerprint.
func (fc *FingerprintController) ValidateClientHello(hello *clientHelloMsg) (*ValidationResult, error) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	if fc.validator == nil {
		return nil, errors.New("tls: validator not initialized")
	}

	// Calculate actual fingerprints
	raw, err := hello.marshal()
	if err != nil {
		return nil, fmt.Errorf("tls: failed to marshal ClientHello: %w", err)
	}

	fp, err := CalculateFingerprints(raw)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to calculate fingerprints: %w", err)
	}

	// Validate
	result := fc.validator.ValidateJA4(fp.JA4)

	// Call validation hook
	if err := fc.hooks.CallClientHelloValidation(result); err != nil {
		return result, err
	}

	return result, nil
}

// GetExpectedJA4 returns the expected JA4 fingerprint.
func (fc *FingerprintController) GetExpectedJA4() string {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	if fc.profile == nil {
		return ""
	}
	return fc.profile.Expected.JA4
}

// GetExpectedJA3 returns the expected JA3 fingerprint.
func (fc *FingerprintController) GetExpectedJA3() string {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	if fc.profile == nil {
		return ""
	}
	return fc.profile.Expected.JA3
}

// FingerprintControllerInterface defines the interface for fingerprint control.
// This allows conn.go to check for fingerprint capability without type assertion to UConn.
type FingerprintControllerInterface interface {
	// GetFingerprintController returns the fingerprint controller if available.
	GetFingerprintController() *FingerprintController
}

// Ensure UConn can implement FingerprintControllerInterface when extended
var _ FingerprintControllerInterface = (*fingerprintedConn)(nil)

// fingerprintedConn wraps UConn with fingerprint control capability.
// This is used internally to provide the FingerprintControllerInterface.
type fingerprintedConn struct {
	*UConn
	controller *FingerprintController
}

// GetFingerprintController returns the fingerprint controller.
func (fpc *fingerprintedConn) GetFingerprintController() *FingerprintController {
	return fpc.controller
}

// NewFingerprintedConn creates a UConn with fingerprint control.
// This is a convenience function that combines UClient and FingerprintController.
func NewFingerprintedConn(conn net.Conn, config *Config, profileID string) (*UConn, *FingerprintController, error) {
	// Create UConn with custom ClientHelloID
	uconn := UClient(conn, config, HelloCustom)

	// Create and apply fingerprint controller
	controller := NewFingerprintController()
	if err := controller.ApplyProfile(uconn, profileID); err != nil {
		return nil, nil, err
	}

	return uconn, controller, nil
}

// QuickFingerprintedConn creates a fingerprinted connection with minimal setup.
// This is the simplest way to create a connection with a specific browser fingerprint.
func QuickFingerprintedConn(conn net.Conn, serverName string, profileID string) (*UConn, error) {
	config := &Config{ServerName: serverName}
	uconn := UClient(conn, config, HelloCustom)

	controller := NewFingerprintController()
	if err := controller.ApplyProfile(uconn, profileID); err != nil {
		return nil, err
	}

	return uconn, nil
}

// convertRecordLayerToRecordPadding converts a RecordLayerConfig (from fingerprint profile)
// to a RecordPaddingConfig (used by conn.writeRecordLocked).
// This bridges the fingerprint system with the core TLS record layer padding.
func convertRecordLayerToRecordPadding(cfg *RecordLayerConfig) *RecordPaddingConfig {
	if cfg == nil || !cfg.PaddingEnabled {
		return nil
	}

	// Map PaddingMode to Distribution string
	var distribution string
	switch cfg.PaddingMode {
	case RecordPaddingNone:
		return nil // No padding
	case RecordPaddingRandom:
		distribution = "uniform"
	case RecordPaddingBlock:
		distribution = "uniform" // Block-aligned uses uniform within blocks
	case RecordPaddingExponential:
		distribution = "exponential"
	case RecordPaddingChrome:
		distribution = "chrome"
	case RecordPaddingFirefox:
		// Firefox uses no padding
		return nil
	default:
		distribution = "chrome" // Default to Chrome-like
	}

	// Determine max padding
	maxPad := cfg.PaddingMax
	if maxPad <= 0 {
		maxPad = 255 // RFC 8446 maximum
	}
	if maxPad > 255 {
		maxPad = 255
	}

	// Get lambda for exponential distributions
	lambda := cfg.PaddingLambda
	if lambda <= 0 {
		lambda = 3.0 // Chrome default
	}

	return &RecordPaddingConfig{
		Enabled:      true,
		MinPadding:   0,
		MaxPadding:   maxPad,
		Distribution: distribution,
		Lambda:       lambda,
	}
}
