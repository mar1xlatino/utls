// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package profiles

import tls "github.com/refraction-networking/utls"

// Firefox145Windows11 captured from real Firefox 145 on Windows 11
// JA3: 6f7889b9fb1a62a9577e685c1fcfa919
// JA4: t13d1717h2_5b57614c22b0_3cbfd9057e0d
// JA4o: t13d1717h2_5b234860e130_02b2423fdb95 (original order)
var Firefox145Windows11 = &tls.FingerprintProfile{
	ID:          "firefox_145_windows_11",
	Browser:     "firefox",
	Version:     145,
	Platform:    "windows_11",
	Description: "Captured from real Firefox 145",

	ClientHello: tls.ClientHelloConfig{
		LegacyVersion: 0x0303,

		CipherSuites: []uint16{
			0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c,
			0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
			0x0035,
		},

		ExtensionOrder: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005,
			0x0022, 0x0012, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x001b,
			0xfe0d,
		},

		SupportedGroups: []tls.CurveID{
			0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101,
		},

		SignatureAlgorithms: []tls.SignatureScheme{
			0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
			0x0601, 0x0203, 0x0201,
		},

		ALPNProtocols: []string{"h2", "http/1.1"},

		SupportedVersions: []uint16{
			0x0304, 0x0303,
		},

		KeyShareGroups: []tls.CurveID{
			0x11ec, 0x001d, 0x0017,
		},

		PSKModes: []uint8{0x01},

		CertCompressionAlgos: []tls.CertCompressionAlgo{
			0x0001, 0x0002, 0x0003,
		},

		CompressionMethods: []uint8{0x00},

		SessionIDLength: 32,

		GREASE: tls.GREASEConfig{
			Enabled:            false,
			CipherSuites:       false,
			Extensions:         false,
			SupportedGroups:    false,
			SupportedVersions:  false,
			KeyShare:           false,
			ExtensionPositions: []int{},
		},
	},

	Expected: tls.ExpectedFingerprints{
		JA3:  "6f7889b9fb1a62a9577e685c1fcfa919",
		JA4:  "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
		JA4o: "t13d1717h2_5b234860e130_02b2423fdb95",
	},
}
