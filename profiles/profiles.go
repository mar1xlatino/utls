// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package profiles contains captured real-world browser TLS fingerprint profiles.
package profiles

import tls "github.com/refraction-networking/utls"

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

// RegisterAll registers all captured profiles with the given registry.
func RegisterAll(registry *tls.ProfileRegistry) error {
	for _, p := range All() {
		if err := registry.Register(p); err != nil {
			return err
		}
	}
	return nil
}
