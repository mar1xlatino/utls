// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// TestEarlyDataExtensionLen verifies the extension returns correct length.
func TestEarlyDataExtensionLen(t *testing.T) {
	ext := &EarlyDataExtension{}
	if got := ext.Len(); got != 4 {
		t.Errorf("EarlyDataExtension.Len() = %d, want 4", got)
	}
}

// TestEarlyDataExtensionRead verifies the extension serializes correctly.
func TestEarlyDataExtensionRead(t *testing.T) {
	ext := &EarlyDataExtension{}

	// Test with sufficient buffer
	buf := make([]byte, 4)
	n, err := ext.Read(buf)
	if err != io.EOF {
		t.Errorf("EarlyDataExtension.Read() error = %v, want io.EOF", err)
	}
	if n != 4 {
		t.Errorf("EarlyDataExtension.Read() n = %d, want 4", n)
	}

	// Verify extension type is 42 (early_data)
	expectedType := uint16(42)
	gotType := uint16(buf[0])<<8 | uint16(buf[1])
	if gotType != expectedType {
		t.Errorf("EarlyDataExtension type = %d, want %d", gotType, expectedType)
	}

	// Verify length is 0 (empty data in ClientHello)
	gotLen := uint16(buf[2])<<8 | uint16(buf[3])
	if gotLen != 0 {
		t.Errorf("EarlyDataExtension data length = %d, want 0", gotLen)
	}

	// Expected bytes: [0x00, 0x2a, 0x00, 0x00] (type=42, length=0)
	expected := []byte{0x00, 0x2a, 0x00, 0x00}
	if !bytes.Equal(buf, expected) {
		t.Errorf("EarlyDataExtension.Read() = %v, want %v", buf, expected)
	}
}

// TestEarlyDataExtensionReadShortBuffer verifies error on short buffer.
func TestEarlyDataExtensionReadShortBuffer(t *testing.T) {
	ext := &EarlyDataExtension{}

	// Test with short buffer (less than 4 bytes)
	shortBuf := make([]byte, 3)
	_, err := ext.Read(shortBuf)
	if err != io.ErrShortBuffer {
		t.Errorf("EarlyDataExtension.Read() with short buffer error = %v, want io.ErrShortBuffer", err)
	}
}

// TestEarlyDataExtensionWrite verifies the extension parses correctly.
func TestEarlyDataExtensionWrite(t *testing.T) {
	ext := &EarlyDataExtension{}

	// Test with empty data (valid for ClientHello)
	n, err := ext.Write([]byte{})
	if err != nil {
		t.Errorf("EarlyDataExtension.Write([]) error = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("EarlyDataExtension.Write([]) n = %d, want 0", n)
	}

	// Test with non-empty data (invalid for ClientHello)
	_, err = ext.Write([]byte{0x01, 0x02})
	if err == nil {
		t.Error("EarlyDataExtension.Write() with non-empty data should return error")
	}
}

// TestEarlyDataExtensionWriteToUConn verifies the extension sets Hello.EarlyData.
func TestEarlyDataExtensionWriteToUConn(t *testing.T) {
	uconn, err := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err != nil {
		t.Fatalf("UClient error: %v", err)
	}

	// Initialize handshake state with a basic spec
	spec := ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_CHACHA20_POLY1305_SHA256,
		},
		Extensions: []TLSExtension{
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []uint8{pointFormatUncompressed}},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
			&EarlyDataExtension{},
		},
	}

	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("ApplyPreset error: %v", err)
	}

	// BuildHandshakeState calls ApplyConfig which calls writeToUConn on all extensions
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatalf("BuildHandshakeState error: %v", err)
	}

	// Verify EarlyData flag is set
	if !uconn.HandshakeState.Hello.EarlyData {
		t.Error("EarlyDataExtension.writeToUConn() did not set Hello.EarlyData to true")
	}
}

// TestExtensionFromIDEarlyData verifies ExtensionFromID returns EarlyDataExtension for id 42.
func TestExtensionFromIDEarlyData(t *testing.T) {
	ext := ExtensionFromID(extensionEarlyData)
	if ext == nil {
		t.Fatal("ExtensionFromID(42) returned nil")
	}

	_, ok := ext.(*EarlyDataExtension)
	if !ok {
		t.Errorf("ExtensionFromID(42) returned %T, want *EarlyDataExtension", ext)
	}
}

// TestEarlyDataExtensionUnmarshalJSON verifies JSON unmarshaling is a no-op.
func TestEarlyDataExtensionUnmarshalJSON(t *testing.T) {
	ext := &EarlyDataExtension{}
	err := ext.UnmarshalJSON([]byte(`{}`))
	if err != nil {
		t.Errorf("EarlyDataExtension.UnmarshalJSON() error = %v, want nil", err)
	}
}

// TestEarlyDataExtensionRoundTrip verifies Read/Write consistency.
func TestEarlyDataExtensionRoundTrip(t *testing.T) {
	ext1 := &EarlyDataExtension{}

	// Read the extension
	buf := make([]byte, ext1.Len())
	n, err := ext1.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read error: %v", err)
	}
	if n != 4 {
		t.Fatalf("Read n = %d, want 4", n)
	}

	// Write back (parse) - note: Write expects only extension_data, not type+length
	ext2 := &EarlyDataExtension{}
	// The data portion is empty (bytes 4 onwards, which is nothing)
	_, err = ext2.Write(buf[4:])
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
}
