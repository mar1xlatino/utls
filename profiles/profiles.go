// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package profiles contains captured real-world browser TLS fingerprint profiles.
//
// Import this package to automatically register all profiles with the default registry:
//
//	import _ "github.com/refraction-networking/utls/profiles"
//
// Or register manually:
//
//	import "github.com/refraction-networking/utls/profiles"
//	profiles.RegisterAll(tls.DefaultRegistry)
//
// Available profiles:
//   - Chrome: 115, 138, 140, 141, 142 (Android, Linux, macOS, Windows)
//   - Firefox: 132, 141, 145 (Android, Linux, macOS, Windows)
//   - Safari: 17, 18 (macOS, iOS)
//   - Edge: 141 (Windows)
//   - Opera: 93, 124 (Android, macOS, Windows)
//   - Samsung Internet: 29 (Android, Linux)
//   - UC Browser: 15 (Android)
//   - Yandex: 25 (Android)
package profiles

import tls "github.com/refraction-networking/utls"

// init automatically registers all captured profiles when this package is imported.
func init() {
	// Use RegisterOrUpdate to allow overwriting built-in profiles with real captured ones
	for _, p := range All() {
		_ = tls.DefaultRegistry.RegisterOrUpdate(p)
	}
}

// All returns all captured profiles.
func All() []*tls.FingerprintProfile {
	return []*tls.FingerprintProfile{
		Chrome115Android,
		Chrome138Android,
		Chrome138Linux,
		Chrome140Android,
		Chrome140Linux,
		Chrome141Windows11,
		Chrome142Android,
		Chrome142Linux,
		Chrome142Macos,
		Chrome142Windows11,
		Edge141Windows11,
		Firefox132Windows11,
		Firefox141Linux,
		Firefox145Android,
		Firefox145Linux,
		Firefox145Macos,
		Firefox145Windows11,
		Opera93Android,
		Opera124Macos,
		Opera124Windows11,
		Safari17Macos,
		Safari18Ios,
		SamsungInternet29Android,
		SamsungInternet29Linux,
		UCBrowser15Android,
		Yandex25Android,
	}
}

// Chrome profiles
func Chrome() []*tls.FingerprintProfile {
	return []*tls.FingerprintProfile{
		Chrome115Android,
		Chrome138Android,
		Chrome138Linux,
		Chrome140Android,
		Chrome140Linux,
		Chrome141Windows11,
		Chrome142Android,
		Chrome142Linux,
		Chrome142Macos,
		Chrome142Windows11,
	}
}

// Firefox profiles
func Firefox() []*tls.FingerprintProfile {
	return []*tls.FingerprintProfile{
		Firefox132Windows11,
		Firefox141Linux,
		Firefox145Android,
		Firefox145Linux,
		Firefox145Macos,
		Firefox145Windows11,
	}
}

// Safari profiles
func Safari() []*tls.FingerprintProfile {
	return []*tls.FingerprintProfile{
		Safari17Macos,
		Safari18Ios,
	}
}

// Edge profiles
func Edge() []*tls.FingerprintProfile {
	return []*tls.FingerprintProfile{
		Edge141Windows11,
	}
}

// Opera profiles
func Opera() []*tls.FingerprintProfile {
	return []*tls.FingerprintProfile{
		Opera93Android,
		Opera124Macos,
		Opera124Windows11,
	}
}

// SamsungInternet profiles
func SamsungInternet() []*tls.FingerprintProfile {
	return []*tls.FingerprintProfile{
		SamsungInternet29Android,
		SamsungInternet29Linux,
	}
}

// Android returns all profiles for Android platform
func Android() []*tls.FingerprintProfile {
	var profiles []*tls.FingerprintProfile
	for _, p := range All() {
		if p.Platform == "android" {
			profiles = append(profiles, p)
		}
	}
	return profiles
}

// IDs returns all profile IDs
func IDs() []string {
	all := All()
	ids := make([]string, len(all))
	for i, p := range all {
		ids[i] = p.ID
	}
	return ids
}

// RegisterAll registers all captured profiles with the given registry.
func RegisterAll(registry *tls.ProfileRegistry) error {
	for _, p := range All() {
		if err := registry.Register(p); err != nil {
			return err
		}
	}
	return nil
}
