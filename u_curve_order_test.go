// Copyright 2025 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"testing"
)

func TestCurveOrderVariationStatic(t *testing.T) {
	// Test that static strategy doesn't change order
	spec := &ClientHelloSpec{
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{Curves: []CurveID{
				GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384,
			}},
		},
		CurveOrder: CurveOrderStatic,
	}

	config := &Config{InsecureSkipVerify: true}
	uconn := uClient(nil, config, HelloCustom)
	uconn.Extensions = make([]TLSExtension, len(spec.Extensions))
	for i, ext := range spec.Extensions {
		uconn.Extensions[i] = cloneExtension(ext)
	}

	err := uconn.applyCurveOrderVariation(spec.CurveOrder)
	if err != nil {
		t.Fatalf("applyCurveOrderVariation failed: %v", err)
	}

	curveOrder := getCurveOrderFromExtensionsForTest(uconn.Extensions)
	if curveOrder != "P256,P384" {
		t.Errorf("Static strategy changed order: expected P256,P384, got %s", curveOrder)
	}
}

func TestCurveOrderVariationEmpty(t *testing.T) {
	// Test that empty strategy (default) doesn't change order
	spec := &ClientHelloSpec{
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{Curves: []CurveID{
				X25519, CurveP256, CurveP384,
			}},
		},
		CurveOrder: "", // Empty = static behavior
	}

	config := &Config{InsecureSkipVerify: true}
	uconn := uClient(nil, config, HelloCustom)
	uconn.Extensions = make([]TLSExtension, len(spec.Extensions))
	for i, ext := range spec.Extensions {
		uconn.Extensions[i] = cloneExtension(ext)
	}

	err := uconn.applyCurveOrderVariation(spec.CurveOrder)
	if err != nil {
		t.Fatalf("applyCurveOrderVariation failed: %v", err)
	}

	curveOrder := getCurveOrderFromExtensionsForTest(uconn.Extensions)
	if curveOrder != "P256,P384" {
		t.Errorf("Empty strategy changed order: expected P256,P384, got %s", curveOrder)
	}
}

func TestCurveOrderVariationP384First(t *testing.T) {
	// Test that P384First strategy always puts P384 before P256
	for i := 0; i < 10; i++ {
		spec := &ClientHelloSpec{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []byte{0x00},
			Extensions: []TLSExtension{
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384,
				}},
			},
			CurveOrder: CurveOrderP384First,
		}

		config := &Config{InsecureSkipVerify: true}
		uconn := uClient(nil, config, HelloCustom)
		uconn.Extensions = make([]TLSExtension, len(spec.Extensions))
		for j, ext := range spec.Extensions {
			uconn.Extensions[j] = cloneExtension(ext)
		}

		err := uconn.applyCurveOrderVariation(spec.CurveOrder)
		if err != nil {
			t.Fatalf("applyCurveOrderVariation failed: %v", err)
		}

		curveOrder := getCurveOrderFromExtensionsForTest(uconn.Extensions)
		if curveOrder != "P384,P256" {
			t.Errorf("Iteration %d: P384First should result in P384,P256, got %s", i, curveOrder)
		}
	}
}

func TestCurveOrderVariationP256First(t *testing.T) {
	// Test that P256First strategy keeps P256 before P384
	for i := 0; i < 10; i++ {
		spec := &ClientHelloSpec{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []byte{0x00},
			Extensions: []TLSExtension{
				&SupportedCurvesExtension{Curves: []CurveID{
					X25519, CurveP256, CurveP384,
				}},
			},
			CurveOrder: CurveOrderP256First,
		}

		config := &Config{InsecureSkipVerify: true}
		uconn := uClient(nil, config, HelloCustom)
		uconn.Extensions = make([]TLSExtension, len(spec.Extensions))
		for j, ext := range spec.Extensions {
			uconn.Extensions[j] = cloneExtension(ext)
		}

		err := uconn.applyCurveOrderVariation(spec.CurveOrder)
		if err != nil {
			t.Fatalf("applyCurveOrderVariation failed: %v", err)
		}

		curveOrder := getCurveOrderFromExtensionsForTest(uconn.Extensions)
		if curveOrder != "P256,P384" {
			t.Errorf("Iteration %d: P256First should result in P256,P384, got %s", i, curveOrder)
		}
	}
}

func TestCurveOrderVariationAutoVariation(t *testing.T) {
	// Test that auto variation produces ~20% swaps
	iterations := 100
	swapCount := 0

	for i := 0; i < iterations; i++ {
		spec := &ClientHelloSpec{
			CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
			CompressionMethods: []byte{0x00},
			Extensions: []TLSExtension{
				&SupportedCurvesExtension{Curves: []CurveID{
					GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384,
				}},
			},
			CurveOrder: CurveOrderAutoVariation,
		}

		config := &Config{InsecureSkipVerify: true}
		uconn := uClient(nil, config, HelloCustom)
		uconn.Extensions = make([]TLSExtension, len(spec.Extensions))
		for j, ext := range spec.Extensions {
			uconn.Extensions[j] = cloneExtension(ext)
		}

		err := uconn.applyCurveOrderVariation(spec.CurveOrder)
		if err != nil {
			t.Fatalf("applyCurveOrderVariation failed: %v", err)
		}

		curveOrder := getCurveOrderFromExtensionsForTest(uconn.Extensions)
		if curveOrder == "P384,P256" {
			swapCount++
		}
	}

	swapPct := float64(swapCount) / float64(iterations) * 100
	t.Logf("Auto variation swapped %d/%d times (%.1f%%)", swapCount, iterations, swapPct)

	// Allow 5-40% range for random variation (20% target with variance)
	if swapPct < 5 || swapPct > 40 {
		t.Errorf("Swap rate %.1f%% is outside expected range (5-40%%)", swapPct)
	}
}

func TestCurveOrderVariationKeyShareConsistency(t *testing.T) {
	// Test that key_share extension matches supported_groups order when both have P256/P384
	spec := &ClientHelloSpec{
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{Curves: []CurveID{
				X25519, CurveP256, CurveP384,
			}},
			&KeyShareExtension{KeyShares: []KeyShare{
				{Group: X25519},
				{Group: CurveP256},
				{Group: CurveP384},
			}},
		},
		CurveOrder: CurveOrderP384First,
	}

	config := &Config{InsecureSkipVerify: true}
	uconn := uClient(nil, config, HelloCustom)
	uconn.Extensions = make([]TLSExtension, len(spec.Extensions))
	for i, ext := range spec.Extensions {
		uconn.Extensions[i] = cloneExtension(ext)
	}

	err := uconn.applyCurveOrderVariation(spec.CurveOrder)
	if err != nil {
		t.Fatalf("applyCurveOrderVariation failed: %v", err)
	}

	curveOrder := getCurveOrderFromExtensionsForTest(uconn.Extensions)
	keyShareOrder := getKeyShareOrderFromExtensionsForTest(uconn.Extensions)

	if curveOrder != keyShareOrder {
		t.Errorf("Curve order (%s) doesn't match key_share order (%s)", curveOrder, keyShareOrder)
	}
	if curveOrder != "P384,P256" {
		t.Errorf("Expected P384,P256 order, got %s", curveOrder)
	}
}

func TestCurveOrderVariationIdempotent(t *testing.T) {
	// Test that calling P384First multiple times produces consistent result
	spec := &ClientHelloSpec{
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []byte{0x00},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{Curves: []CurveID{
				X25519, CurveP256, CurveP384,
			}},
		},
		CurveOrder: CurveOrderP384First,
	}

	config := &Config{InsecureSkipVerify: true}
	uconn := uClient(nil, config, HelloCustom)
	uconn.Extensions = make([]TLSExtension, len(spec.Extensions))
	for i, ext := range spec.Extensions {
		uconn.Extensions[i] = cloneExtension(ext)
	}

	// Apply twice
	uconn.applyCurveOrderVariation(spec.CurveOrder)
	uconn.applyCurveOrderVariation(spec.CurveOrder)

	curveOrder := getCurveOrderFromExtensionsForTest(uconn.Extensions)
	if curveOrder != "P384,P256" {
		t.Errorf("Idempotent test failed: expected P384,P256, got %s", curveOrder)
	}
}

func getCurveOrderFromExtensionsForTest(extensions []TLSExtension) string {
	for _, ext := range extensions {
		if curves, ok := ext.(*SupportedCurvesExtension); ok {
			p256Idx, p384Idx := -1, -1
			for i, c := range curves.Curves {
				if c == CurveP256 {
					p256Idx = i
				} else if c == CurveP384 {
					p384Idx = i
				}
			}
			if p256Idx < 0 || p384Idx < 0 {
				return "incomplete"
			}
			if p256Idx < p384Idx {
				return "P256,P384"
			}
			return "P384,P256"
		}
	}
	return "not found"
}

func getKeyShareOrderFromExtensionsForTest(extensions []TLSExtension) string {
	for _, ext := range extensions {
		if ks, ok := ext.(*KeyShareExtension); ok {
			p256Idx, p384Idx := -1, -1
			for i, share := range ks.KeyShares {
				if share.Group == CurveP256 {
					p256Idx = i
				} else if share.Group == CurveP384 {
					p384Idx = i
				}
			}
			if p256Idx < 0 || p384Idx < 0 {
				return "incomplete"
			}
			if p256Idx < p384Idx {
				return "P256,P384"
			}
			return "P384,P256"
		}
	}
	return "not found"
}
