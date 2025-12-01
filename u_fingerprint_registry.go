// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ProfileRegistry manages all available fingerprint profiles.
type ProfileRegistry struct {
	profiles map[string]*FingerprintProfile
	mu       sync.RWMutex
}

// NewProfileRegistry creates a new empty registry.
func NewProfileRegistry() *ProfileRegistry {
	return &ProfileRegistry{
		profiles: make(map[string]*FingerprintProfile),
	}
}

// Get retrieves a profile by ID.
func (r *ProfileRegistry) Get(id string) (*FingerprintProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	profile, ok := r.profiles[id]
	if !ok {
		return nil, fmt.Errorf("tls: profile %q not found", id)
	}

	return profile.Clone(), nil
}

// Register adds a new profile to the registry.
func (r *ProfileRegistry) Register(profile *FingerprintProfile) error {
	if profile == nil {
		return errors.New("tls: cannot register nil profile")
	}

	if profile.ID == "" {
		return errors.New("tls: profile ID must not be empty")
	}

	// Validate the profile
	if errs := profile.Validate(); len(errs) > 0 {
		return fmt.Errorf("tls: profile validation failed: %v", errs[0])
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.profiles[profile.ID]; exists {
		return fmt.Errorf("tls: profile %q already registered", profile.ID)
	}

	r.profiles[profile.ID] = profile.Clone()
	return nil
}

// RegisterOrUpdate adds or updates a profile in the registry.
// Unlike Register, this allows overwriting existing profiles.
func (r *ProfileRegistry) RegisterOrUpdate(profile *FingerprintProfile) error {
	if profile == nil {
		return errors.New("tls: cannot register nil profile")
	}

	if profile.ID == "" {
		return errors.New("tls: profile ID must not be empty")
	}

	// Validate the profile (same as Register)
	if errs := profile.Validate(); len(errs) > 0 {
		return fmt.Errorf("tls: profile validation failed: %v", errs[0])
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.profiles[profile.ID] = profile.Clone()
	return nil
}

// Unregister removes a profile from the registry.
func (r *ProfileRegistry) Unregister(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.profiles[id]; !exists {
		return fmt.Errorf("tls: profile %q not found", id)
	}

	delete(r.profiles, id)
	return nil
}

// Exists checks if a profile exists.
func (r *ProfileRegistry) Exists(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.profiles[id]
	return exists
}

// List returns all profile IDs.
func (r *ProfileRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.profiles))
	for id := range r.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ListByBrowser returns profile IDs for a specific browser.
func (r *ProfileRegistry) ListByBrowser(browser string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var ids []string
	for id, profile := range r.profiles {
		if profile.Browser == browser {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ListByPlatform returns profile IDs for a specific platform.
func (r *ProfileRegistry) ListByPlatform(platform string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var ids []string
	for id, profile := range r.profiles {
		if profile.Platform == platform {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ListByBrowserAndPlatform returns profile IDs matching both criteria.
func (r *ProfileRegistry) ListByBrowserAndPlatform(browser, platform string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var ids []string
	for id, profile := range r.profiles {
		if profile.Browser == browser && profile.Platform == platform {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ProfileCriteria for matching profiles.
type ProfileCriteria struct {
	Browser    string
	MinVersion int
	MaxVersion int
	Platform   string
	OSVersion  string
}

// Match finds a profile matching criteria.
func (r *ProfileRegistry) Match(criteria ProfileCriteria) (*FingerprintProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, profile := range r.profiles {
		if criteria.Browser != "" && profile.Browser != criteria.Browser {
			continue
		}
		if criteria.Platform != "" && profile.Platform != criteria.Platform {
			continue
		}
		if criteria.OSVersion != "" && profile.OSVersion != criteria.OSVersion {
			continue
		}
		if criteria.MinVersion > 0 && profile.Version < criteria.MinVersion {
			continue
		}
		if criteria.MaxVersion > 0 && profile.Version > criteria.MaxVersion {
			continue
		}

		return profile.Clone(), nil
	}

	return nil, errors.New("tls: no profile matches criteria")
}

// Latest returns the latest version of a browser/platform combination.
func (r *ProfileRegistry) Latest(browser, platform string) (*FingerprintProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var latest *FingerprintProfile
	for _, profile := range r.profiles {
		if profile.Browser != browser {
			continue
		}
		if platform != "" && profile.Platform != platform {
			continue
		}
		if latest == nil || profile.Version > latest.Version {
			latest = profile
		}
	}

	if latest == nil {
		return nil, fmt.Errorf("tls: no profile found for browser %q platform %q", browser, platform)
	}

	return latest.Clone(), nil
}

// ProfileFilter for random selection.
type ProfileFilter struct {
	Browsers  []string // Empty = any
	Platforms []string // Empty = any
}

// Random returns a random profile (optionally filtered).
func (r *ProfileRegistry) Random(filter *ProfileFilter) (*FingerprintProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var candidates []*FingerprintProfile

	for _, profile := range r.profiles {
		if filter != nil {
			if len(filter.Browsers) > 0 && !containsString(filter.Browsers, profile.Browser) {
				continue
			}
			if len(filter.Platforms) > 0 && !containsString(filter.Platforms, profile.Platform) {
				continue
			}
		}
		candidates = append(candidates, profile)
	}

	if len(candidates) == 0 {
		return nil, errors.New("tls: no profiles match filter")
	}

	// Select random profile using rejection sampling to avoid modulo bias
	n := uint32(len(candidates))
	// Calculate threshold to reject values that would cause bias
	// threshold = 2^32 - (2^32 % n) = largest multiple of n <= 2^32
	// Using: threshold = -n % n when n is non-zero (works due to unsigned wraparound)
	threshold := -n % n
	if threshold == 0 {
		threshold = 0 // n is a power of 2 or 0, no rejection needed
	}

	var idx uint32
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			// Fallback to simple modulo if rand fails
			idx = 0
			break
		}
		v := binary.BigEndian.Uint32(b[:])
		// Only accept values that won't cause modulo bias
		if v >= threshold {
			idx = v % n
			break
		}
	}

	return candidates[idx].Clone(), nil
}

// containsString checks if a slice contains a string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// Export exports a profile to JSON.
func (r *ProfileRegistry) Export(id string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	profile, ok := r.profiles[id]
	if !ok {
		return nil, fmt.Errorf("tls: profile %q not found", id)
	}

	return json.MarshalIndent(profile, "", "  ")
}

// ExportAll exports all profiles to JSON.
func (r *ProfileRegistry) ExportAll() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return json.MarshalIndent(r.profiles, "", "  ")
}

// Import imports a profile from JSON.
func (r *ProfileRegistry) Import(data []byte) error {
	var profile FingerprintProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("tls: failed to unmarshal profile: %w", err)
	}

	return r.Register(&profile)
}

// ImportAll imports multiple profiles from JSON.
func (r *ProfileRegistry) ImportAll(data []byte) error {
	var profiles map[string]*FingerprintProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return fmt.Errorf("tls: failed to unmarshal profiles: %w", err)
	}

	for _, profile := range profiles {
		if err := r.Register(profile); err != nil {
			return err
		}
	}

	return nil
}

// ValidateAll validates all registered profiles.
func (r *ProfileRegistry) ValidateAll() map[string][]error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make(map[string][]error)
	for id, profile := range r.profiles {
		if errs := profile.Validate(); len(errs) > 0 {
			results[id] = errs
		}
	}

	return results
}

// Count returns the number of registered profiles.
func (r *ProfileRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.profiles)
}

// Clear removes all profiles from the registry.
func (r *ProfileRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles = make(map[string]*FingerprintProfile)
}

// DefaultRegistry is the global profile registry.
var DefaultRegistry = NewProfileRegistry()

// GetProfile retrieves a profile from the default registry.
func GetProfile(id string) (*FingerprintProfile, error) {
	return DefaultRegistry.Get(id)
}

// RegisterProfile adds a profile to the default registry.
func RegisterProfile(profile *FingerprintProfile) error {
	return DefaultRegistry.Register(profile)
}

// ListProfiles returns all profile IDs from the default registry.
func ListProfiles() []string {
	return DefaultRegistry.List()
}

// LatestProfile returns the latest version of a browser/platform from the default registry.
func LatestProfile(browser, platform string) (*FingerprintProfile, error) {
	return DefaultRegistry.Latest(browser, platform)
}

// RandomProfile returns a random profile from the default registry.
func RandomProfile(filter *ProfileFilter) (*FingerprintProfile, error) {
	return DefaultRegistry.Random(filter)
}

// init registers built-in profiles.
func init() {
	// Register built-in profiles
	// These are defined in separate files (chrome.go, firefox.go, etc.)
	// and registered here or via their own init functions
	registerBuiltinProfiles()
}

// registerBuiltinProfiles registers the default browser profiles.
// This is called from init() and can be extended.
//
// Note: Built-in profiles do not include Expected fingerprints (JA3, JA4, etc.)
// because exact fingerprints depend on per-session random values:
//   - GREASE values are randomly generated each session
//   - Extension order is shuffled (Chrome)
//   - Some extensions have random padding
//
// To get the expected fingerprints for validation, capture a real ClientHello
// from the profile using the capture tool in cmd/capture_profiles/.
func registerBuiltinProfiles() {
	// Chrome 133 Windows 11
	_ = DefaultRegistry.RegisterOrUpdate(&FingerprintProfile{
		ID:          "chrome_133_windows_11",
		Browser:     "chrome",
		Version:     133,
		Platform:    "windows",
		OSVersion:   "11",
		Description: "Google Chrome 133 on Windows 11",
		ClientHello: ClientHelloConfig{
			LegacyVersion: VersionTLS12,
			SupportedVersions: []uint16{
				0x0a0a, // GREASE placeholder
				VersionTLS13,
				VersionTLS12,
			},
			CipherSuites: []uint16{
				0x0a0a, // GREASE placeholder
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			SupportedGroups: []CurveID{
				0x0a0a, // GREASE placeholder
				X25519MLKEM768,
				X25519,
				CurveP256,
				CurveP384,
			},
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
				PKCS1WithSHA256,
				ECDSAWithP384AndSHA384,
				PSSWithSHA384,
				PKCS1WithSHA384,
				PSSWithSHA512,
				PKCS1WithSHA512,
			},
			ECPointFormats:    []uint8{0}, // uncompressed
			ALPNProtocols:     []string{"h2", "http/1.1"},
			ShuffleExtensions: true,
			// Chrome extension order (pre-shuffle) - will be frozen per session
			ExtensionOrder: []uint16{
				0x0000, // server_name (SNI)
				0x0017, // extended_master_secret
				0xff01, // renegotiation_info
				0x000a, // supported_groups
				0x000b, // ec_point_formats
				0x0023, // session_ticket
				0x000d, // signature_algorithms
				0x0010, // ALPN
				0x0005, // status_request
				0x0012, // signed_certificate_timestamp
				0x002b, // supported_versions
				0x002d, // psk_key_exchange_modes
				0x0033, // key_share
				0x001b, // compress_certificate
				0x44cd, // application_settings (ALPS)
				0x0015, // padding
			},
			GREASE: GREASEConfig{
				Enabled:            true,
				CipherSuites:       true,
				Extensions:         true,
				SupportedGroups:    true,
				SupportedVersions:  true,
				KeyShare:           true,
				ExtensionPositions: []int{0, -2},
			},
			KeyShareGroups:       []CurveID{0x0a0a, X25519MLKEM768, X25519},
			PaddingStyle:         PaddingChrome,
			PaddingTarget:        517,
			SessionIDLength:      32,
			CompressionMethods:   []uint8{0},
			PSKModes:             []uint8{1}, // psk_dhe_ke
			CertCompressionAlgos: []CertCompressionAlgo{CertCompressionBrotli},
			ApplicationSettings:  true,
		},
		RecordLayer: RecordLayerConfig{
			MaxRecordSize:  16384,
			PaddingEnabled: true,
			PaddingMode:    RecordPaddingExponential,
			PaddingLambda:  3.0,
		},
		Session: SessionBehaviorConfig{
			ResumptionEnabled: true,
			AcceptTickets:     true,
			EarlyDataEnabled:  true,
			PSKModes:          []uint8{1},
		},
		HTTP2: HTTP2FingerprintConfig{
			HeaderTableSize:      65536,
			EnablePush:           false,
			MaxConcurrentStreams: 1000,
			InitialWindowSize:    6291456,
			MaxFrameSize:         16384,
			MaxHeaderListSize:    262144,
			ConnectionWindowSize: 15663105,
		},
	})

	// Firefox 145 Windows 11
	_ = DefaultRegistry.RegisterOrUpdate(&FingerprintProfile{
		ID:          "firefox_145_windows_11",
		Browser:     "firefox",
		Version:     145,
		Platform:    "windows",
		OSVersion:   "11",
		Description: "Mozilla Firefox 145 on Windows 11",
		ClientHello: ClientHelloConfig{
			LegacyVersion: VersionTLS12,
			SupportedVersions: []uint16{
				VersionTLS13,
				VersionTLS12,
			},
			// Firefox cipher order: ChaCha20 before AES-256
			CipherSuites: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			SupportedGroups: []CurveID{
				X25519,
				CurveP256,
				CurveP384,
				CurveP521,
			},
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				ECDSAWithP384AndSHA384,
				ECDSAWithP521AndSHA512,
				PSSWithSHA256,
				PSSWithSHA384,
				PSSWithSHA512,
				PKCS1WithSHA256,
				PKCS1WithSHA384,
				PKCS1WithSHA512,
				ECDSAWithSHA1,
				PKCS1WithSHA1,
			},
			ECPointFormats:       []uint8{0},
			ALPNProtocols:        []string{"h2", "http/1.1"},
			ShuffleExtensions:    false, // Firefox doesn't shuffle!
			GREASE:               GREASEConfig{Enabled: false},
			KeyShareGroups:       []CurveID{X25519, CurveP256},
			PaddingStyle:         PaddingFirefox,
			SessionIDLength:      32,
			CompressionMethods:   []uint8{0},
			DelegatedCredentials: true,
			RecordSizeLimit:      16385,
		},
		Session: SessionBehaviorConfig{
			ResumptionEnabled: true,
			AcceptTickets:     true,
			PSKModes:          []uint8{1},
		},
	})

	// Safari 18 macOS 14
	_ = DefaultRegistry.RegisterOrUpdate(&FingerprintProfile{
		ID:          "safari_18_macos_14",
		Browser:     "safari",
		Version:     18,
		Platform:    "macos",
		OSVersion:   "14",
		Description: "Apple Safari 18 on macOS 14",
		ClientHello: ClientHelloConfig{
			LegacyVersion: VersionTLS12,
			SupportedVersions: []uint16{
				0x0a0a, // GREASE
				VersionTLS13,
				VersionTLS12,
			},
			CipherSuites: []uint16{
				0x0a0a, // GREASE
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				TLS_RSA_WITH_AES_256_GCM_SHA384,
				TLS_RSA_WITH_AES_128_GCM_SHA256,
				TLS_RSA_WITH_AES_256_CBC_SHA,
				TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			SupportedGroups: []CurveID{
				0x0a0a, // GREASE
				X25519,
				CurveP256,
				CurveP384,
				CurveP521,
			},
			SignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				PSSWithSHA256,
				PKCS1WithSHA256,
				ECDSAWithP384AndSHA384,
				ECDSAWithSHA1,
				PSSWithSHA384,
				PKCS1WithSHA384,
				PSSWithSHA512,
				PKCS1WithSHA512,
				PKCS1WithSHA1,
			},
			ECPointFormats:    []uint8{0},
			ALPNProtocols:     []string{"h2", "http/1.1"},
			ShuffleExtensions: false,
			GREASE: GREASEConfig{
				Enabled:            true,
				CipherSuites:       true,
				Extensions:         true,
				SupportedGroups:    true,
				SupportedVersions:  true,
				ExtensionPositions: []int{0},
			},
			KeyShareGroups:     []CurveID{0x0a0a, X25519},
			PaddingStyle:       PaddingNone, // Safari uses different padding
			SessionIDLength:    32,
			CompressionMethods: []uint8{0},
		},
		Session: SessionBehaviorConfig{
			ResumptionEnabled: true,
			AcceptTickets:     true,
		},
	})
}
