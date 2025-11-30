// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profiles

import tls "github.com/refraction-networking/utls"

// Yandex25Android captured from real Yandex 25 on Android
// JA3: ef031fdda09ca6458e8f6795a876f36d
// JA4: t13d1516h2_8daaf6152771_02713d6af862
// JA4o: t13d1516h2_acb858a92679_ca63666b52d6 (original order)
var Yandex25Android = &tls.FingerprintProfile{
	ID:          "yandex_25_android",
	Browser:     "yandex",
	Version:     25,
	Platform:    "android",
	Description: "Captured from real Yandex 25",

	ClientHello: tls.ClientHelloConfig{
		LegacyVersion: 0x0303,

		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
			0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
		},

		ExtensionOrder: []uint16{
			0x000d, 0xff01, 0x0012, 0x000a, 0x000b, 0x001b, 0x0023, 0x4469,
			0x0010, 0x002b, 0x0000, 0x0033, 0x002d, 0x0005, 0xfe0d, 0x0017,
		},

		SupportedGroups: []tls.CurveID{
			0x11ec, 0x001d, 0x0017, 0x0018,
		},

		SignatureAlgorithms: []tls.SignatureScheme{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
		},

		ALPNProtocols: []string{"h2", "http/1.1"},

		SupportedVersions: []uint16{0x0304, 0x0303},

		KeyShareGroups: []tls.CurveID{0x11ec, 0x001d},

		PSKModes: []uint8{0x01},

		CertCompressionAlgos: []tls.CertCompressionAlgo{0x0002},

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
			ExtensionPositions: []int{0, 17},
		},
	},

	Expected: tls.ExpectedFingerprints{
		JA3:  "ef031fdda09ca6458e8f6795a876f36d",
		JA4:  "t13d1516h2_8daaf6152771_02713d6af862",
		JA4o: "t13d1516h2_acb858a92679_ca63666b52d6",
	},
}
