// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profiles

import tls "github.com/refraction-networking/utls"

// Chrome138Android captured from real Chrome 138 on Android
// JA3: b4da7f95e46bf2cf5285fd609cf726e4
// JA4: t13d181300_e8a523a41297_43ade6aba3df
// JA4o: t13d181300_a9e16911e61f_e7108d209163 (original order)
var Chrome138Android = &tls.FingerprintProfile{
	ID:          "chrome_138_android",
	Browser:     "chrome",
	Version:     138,
	Platform:    "android",
	Description: "Captured from real Chrome 138",

	ClientHello: tls.ClientHelloConfig{
		LegacyVersion: 0x0303,

		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c,
			0xc030, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f,
			0x0035, 0x000a,
		},

		ExtensionOrder: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0005, 0x000d,
			0x0012, 0x0033, 0x002d, 0x002b, 0x0015,
		},

		SupportedGroups: []tls.CurveID{
			0x001d, 0x0017, 0x0018,
		},

		SignatureAlgorithms: []tls.SignatureScheme{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
			0x0201,
		},

		ALPNProtocols: []string{},

		SupportedVersions: []uint16{0x0304, 0x0303, 0x0302, 0x0301},

		KeyShareGroups: []tls.CurveID{0x001d},

		PSKModes: []uint8{0x01},

		CertCompressionAlgos: []tls.CertCompressionAlgo{},

		CompressionMethods: []uint8{0x00},

		SessionIDLength: 32,

		ShuffleExtensions: true,

		GREASE: tls.GREASEConfig{
			Enabled:            true,
			CipherSuites:       true,
			Extensions:         true,
			SupportedGroups:    true,
			SupportedVersions:  true,
			KeyShare:           true,
			ExtensionPositions: []int{0, 13},
		},
	},

	Expected: tls.ExpectedFingerprints{
		JA3:  "b4da7f95e46bf2cf5285fd609cf726e4",
		JA4:  "t13d181300_e8a523a41297_43ade6aba3df",
		JA4o: "t13d181300_a9e16911e61f_e7108d209163",
	},
}
