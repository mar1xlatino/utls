// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profiles

import tls "github.com/refraction-networking/utls"

// Safari17Macos captured from real Safari 17 on macOS
// JA3: 773906b0efdefa24a7f2b8eb6985bf37
// JA4: t13d2014h1_a09f3c656075_14788d8d241b
// JA4o: t13d2014h1_de3eb69493ac_78169b6d3873 (original order)
var Safari17Macos = &tls.FingerprintProfile{
	ID:          "safari_17_macos",
	Browser:     "safari",
	Version:     17,
	Platform:    "macos",
	Description: "Captured from real Safari 17",

	ClientHello: tls.ClientHelloConfig{
		LegacyVersion: 0x0303,

		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f,
			0xcca8, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x0035,
			0x002f, 0xc008, 0xc012, 0x000a,
		},

		ExtensionOrder: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d,
			0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015,
		},

		SupportedGroups: []tls.CurveID{
			0x001d, 0x0017, 0x0018, 0x0019,
		},

		SignatureAlgorithms: []tls.SignatureScheme{
			0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501,
			0x0806, 0x0601, 0x0201,
		},

		ALPNProtocols: []string{"http/1.1"},

		SupportedVersions: []uint16{0x0304, 0x0303, 0x0302, 0x0301},

		KeyShareGroups: []tls.CurveID{0x001d},

		PSKModes: []uint8{0x01},

		CertCompressionAlgos: []tls.CertCompressionAlgo{0x0001},

		CompressionMethods: []uint8{0x00},

		SessionIDLength: 32,

		GREASE: tls.GREASEConfig{
			Enabled:            true,
			CipherSuites:       true,
			Extensions:         true,
			SupportedGroups:    true,
			SupportedVersions:  true,
			KeyShare:           true,
			ExtensionPositions: []int{0, -1},
		},
	},

	Expected: tls.ExpectedFingerprints{
		JA3:  "773906b0efdefa24a7f2b8eb6985bf37",
		JA4:  "t13d2014h1_a09f3c656075_14788d8d241b",
		JA4o: "t13d2014h1_de3eb69493ac_78169b6d3873",
	},
}
