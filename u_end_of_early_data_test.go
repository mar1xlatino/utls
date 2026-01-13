// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"testing"
)

// TestEndOfEarlyDataMsgMarshal verifies that the EndOfEarlyData message
// marshals correctly to a 4-byte header with type 5 and zero-length content.
// RFC 8446 Section 4.5: struct {} EndOfEarlyData;
func TestEndOfEarlyDataMsgMarshal(t *testing.T) {
	msg := &endOfEarlyDataMsg{}
	data, err := msg.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// EndOfEarlyData message should be exactly 4 bytes:
	// - 1 byte: handshake type (5 = typeEndOfEarlyData)
	// - 3 bytes: length (0, because there's no content)
	if len(data) != 4 {
		t.Errorf("expected 4 bytes, got %d", len(data))
	}

	// Verify handshake type
	if data[0] != typeEndOfEarlyData {
		t.Errorf("expected type %d, got %d", typeEndOfEarlyData, data[0])
	}

	// Verify length is zero
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if length != 0 {
		t.Errorf("expected length 0, got %d", length)
	}
}

// TestEndOfEarlyDataMsgUnmarshal verifies that the EndOfEarlyData message
// unmarshals correctly from a 4-byte input.
func TestEndOfEarlyDataMsgUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantOK  bool
	}{
		{
			name:   "valid EndOfEarlyData",
			data:   []byte{typeEndOfEarlyData, 0, 0, 0},
			wantOK: true,
		},
		{
			name:   "too short",
			data:   []byte{typeEndOfEarlyData, 0, 0},
			wantOK: false,
		},
		{
			name:   "too long",
			data:   []byte{typeEndOfEarlyData, 0, 0, 0, 0},
			wantOK: false,
		},
		{
			name:   "empty",
			data:   []byte{},
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := &endOfEarlyDataMsg{}
			ok := msg.unmarshal(tc.data)
			if ok != tc.wantOK {
				t.Errorf("unmarshal returned %v, want %v", ok, tc.wantOK)
			}
		})
	}
}

// TestEndOfEarlyDataMsgRoundTrip verifies that marshal/unmarshal roundtrip works.
func TestEndOfEarlyDataMsgRoundTrip(t *testing.T) {
	original := &endOfEarlyDataMsg{}
	data, err := original.marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored := &endOfEarlyDataMsg{}
	if !restored.unmarshal(data) {
		t.Fatal("unmarshal failed")
	}

	// Re-marshal and compare
	data2, err := restored.marshal()
	if err != nil {
		t.Fatalf("second marshal failed: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Errorf("roundtrip mismatch: got %x, want %x", data2, data)
	}
}

// TestSendEndOfEarlyDataSkipsQUIC verifies that sendEndOfEarlyData returns
// nil without sending anything when c.quic is not nil.
// RFC 9001 Section 8.3: The TLS EndOfEarlyData message is not used with QUIC.
func TestSendEndOfEarlyDataSkipsQUIC(t *testing.T) {
	// Create a minimal handshake state with QUIC connection
	c := &Conn{
		quic: &quicState{}, // Non-nil quic means QUIC connection
	}
	hs := &clientHandshakeStateTLS13{
		c:                 c,
		earlyDataAccepted: true, // Even with early data accepted, should skip for QUIC
	}

	err := hs.sendEndOfEarlyData()
	if err != nil {
		t.Errorf("sendEndOfEarlyData returned error for QUIC: %v", err)
	}
}

// TestSendEndOfEarlyDataSkipsWhenNotAccepted verifies that sendEndOfEarlyData
// returns nil without sending anything when earlyDataAccepted is false.
func TestSendEndOfEarlyDataSkipsWhenNotAccepted(t *testing.T) {
	// Create a minimal handshake state without early data acceptance
	c := &Conn{
		quic: nil, // Non-QUIC connection
	}
	hs := &clientHandshakeStateTLS13{
		c:                 c,
		earlyDataAccepted: false, // Early data not accepted
	}

	err := hs.sendEndOfEarlyData()
	if err != nil {
		t.Errorf("sendEndOfEarlyData returned error when early data not accepted: %v", err)
	}
}
