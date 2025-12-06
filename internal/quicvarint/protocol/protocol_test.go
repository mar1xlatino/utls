// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package protocol

import (
	"strings"
	"testing"
	"time"
)

// Test PacketType constants and String method
func TestPacketTypeString(t *testing.T) {
	tests := []struct {
		pt       PacketType
		expected string
	}{
		{PacketTypeInitial, "Initial"},
		{PacketTypeRetry, "Retry"},
		{PacketTypeHandshake, "Handshake"},
		{PacketType0RTT, "0-RTT Protected"},
		{PacketType(0), "unknown packet type: 0"},
		{PacketType(99), "unknown packet type: 99"},
	}

	for _, tt := range tests {
		result := tt.pt.String()
		if result != tt.expected {
			t.Errorf("PacketType(%d).String() = %q, want %q", tt.pt, result, tt.expected)
		}
	}
}

// Test PacketType values are sequential
func TestPacketTypeValues(t *testing.T) {
	if PacketTypeInitial != 1 {
		t.Errorf("PacketTypeInitial = %d, want 1", PacketTypeInitial)
	}
	if PacketTypeRetry != 2 {
		t.Errorf("PacketTypeRetry = %d, want 2", PacketTypeRetry)
	}
	if PacketTypeHandshake != 3 {
		t.Errorf("PacketTypeHandshake = %d, want 3", PacketTypeHandshake)
	}
	if PacketType0RTT != 4 {
		t.Errorf("PacketType0RTT = %d, want 4", PacketType0RTT)
	}
}

// Test ECN constants
func TestECNConstants(t *testing.T) {
	if ECNUnsupported != 0 {
		t.Errorf("ECNUnsupported = %d, want 0", ECNUnsupported)
	}
	if ECNNon != 1 {
		t.Errorf("ECNNon = %d, want 1", ECNNon)
	}
	if ECT1 != 2 {
		t.Errorf("ECT1 = %d, want 2", ECT1)
	}
	if ECT0 != 3 {
		t.Errorf("ECT0 = %d, want 3", ECT0)
	}
	if ECNCE != 4 {
		t.Errorf("ECNCE = %d, want 4", ECNCE)
	}
}

// Test ParseECNHeaderBits
func TestParseECNHeaderBits(t *testing.T) {
	tests := []struct {
		bits     byte
		expected ECN
	}{
		{0b00000000, ECNNon},
		{0b00000001, ECT1},
		{0b00000010, ECT0},
		{0b00000011, ECNCE},
	}

	for _, tt := range tests {
		result := ParseECNHeaderBits(tt.bits)
		if result != tt.expected {
			t.Errorf("ParseECNHeaderBits(%#02x) = %v, want %v", tt.bits, result, tt.expected)
		}
	}
}

// Test ParseECNHeaderBits panics on invalid input
func TestParseECNHeaderBitsPanic(t *testing.T) {
	// Test with a value > 3 (only bits 0-3 are valid combinations)
	// Actually, looking at the code, it only handles 0, 1, 2, 3 - anything else panics
	// But the lower 2 bits of any byte can only be 0, 1, 2, or 3
	// So we need to pass a byte value that isn't 0, 1, 2, or 3
	invalidBytes := []byte{4, 5, 6, 7, 8, 100, 255}

	for _, b := range invalidBytes {
		t.Run(string(rune(b)), func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("ParseECNHeaderBits(%#02x) should panic", b)
				}
			}()
			_ = ParseECNHeaderBits(b)
		})
	}
}

// Test ECN.ToHeaderBits
func TestECNToHeaderBits(t *testing.T) {
	tests := []struct {
		ecn      ECN
		expected byte
	}{
		{ECNNon, 0b00000000},
		{ECT1, 0b00000001},
		{ECT0, 0b00000010},
		{ECNCE, 0b00000011},
	}

	for _, tt := range tests {
		result := tt.ecn.ToHeaderBits()
		if result != tt.expected {
			t.Errorf("ECN(%v).ToHeaderBits() = %#02x, want %#02x", tt.ecn, result, tt.expected)
		}
	}
}

// Test ECN.ToHeaderBits panics on ECNUnsupported
func TestECNToHeaderBitsPanicUnsupported(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("ECNUnsupported.ToHeaderBits() should panic")
		}
	}()
	_ = ECNUnsupported.ToHeaderBits()
}

// Test ECN.ToHeaderBits panics on invalid ECN value
func TestECNToHeaderBitsPanicInvalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("invalid ECN.ToHeaderBits() should panic")
		}
	}()
	_ = ECN(99).ToHeaderBits()
}

// Test ECN.String
func TestECNString(t *testing.T) {
	tests := []struct {
		ecn      ECN
		expected string
	}{
		{ECNUnsupported, "ECN unsupported"},
		{ECNNon, "Not-ECT"},
		{ECT1, "ECT(1)"},
		{ECT0, "ECT(0)"},
		{ECNCE, "CE"},
		{ECN(99), "invalid ECN value: 99"},
	}

	for _, tt := range tests {
		result := tt.ecn.String()
		if result != tt.expected {
			t.Errorf("ECN(%d).String() = %q, want %q", tt.ecn, result, tt.expected)
		}
	}
}

// Test round-trip: ParseECNHeaderBits -> ToHeaderBits
func TestECNRoundTrip(t *testing.T) {
	for bits := byte(0); bits <= 3; bits++ {
		ecn := ParseECNHeaderBits(bits)
		result := ecn.ToHeaderBits()
		if result != bits {
			t.Errorf("Round-trip failed: %#02x -> %v -> %#02x", bits, ecn, result)
		}
	}
}

// Test ByteCount type and constants
func TestByteCountConstants(t *testing.T) {
	// MaxByteCount = 2^62 - 1
	expectedMax := ByteCount(1<<62 - 1)
	if MaxByteCount != expectedMax {
		t.Errorf("MaxByteCount = %d, want %d", MaxByteCount, expectedMax)
	}

	if InvalidByteCount != -1 {
		t.Errorf("InvalidByteCount = %d, want -1", InvalidByteCount)
	}
}

// Test StatelessResetToken size
func TestStatelessResetTokenSize(t *testing.T) {
	var token StatelessResetToken
	if len(token) != 16 {
		t.Errorf("StatelessResetToken size = %d, want 16", len(token))
	}
}

// Test packet size constants
func TestPacketSizeConstants(t *testing.T) {
	if MaxPacketBufferSize != 1452 {
		t.Errorf("MaxPacketBufferSize = %d, want 1452", MaxPacketBufferSize)
	}

	if MaxLargePacketBufferSize != 20*1024 {
		t.Errorf("MaxLargePacketBufferSize = %d, want %d", MaxLargePacketBufferSize, 20*1024)
	}

	if MinInitialPacketSize != 1200 {
		t.Errorf("MinInitialPacketSize = %d, want 1200", MinInitialPacketSize)
	}

	if MinUnknownVersionPacketSize != MinInitialPacketSize {
		t.Errorf("MinUnknownVersionPacketSize = %d, want %d", MinUnknownVersionPacketSize, MinInitialPacketSize)
	}
}

// Test connection constants
func TestConnectionConstants(t *testing.T) {
	if MinConnectionIDLenInitial != 8 {
		t.Errorf("MinConnectionIDLenInitial = %d, want 8", MinConnectionIDLenInitial)
	}

	if MaxConnIDLen != 20 {
		t.Errorf("MaxConnIDLen = %d, want 20", MaxConnIDLen)
	}

	if DefaultActiveConnectionIDLimit != 2 {
		t.Errorf("DefaultActiveConnectionIDLimit = %d, want 2", DefaultActiveConnectionIDLimit)
	}
}

// Test ACK delay constants
func TestAckDelayConstants(t *testing.T) {
	if DefaultAckDelayExponent != 3 {
		t.Errorf("DefaultAckDelayExponent = %d, want 3", DefaultAckDelayExponent)
	}

	if MaxAckDelayExponent != 20 {
		t.Errorf("MaxAckDelayExponent = %d, want 20", MaxAckDelayExponent)
	}

	expectedDefaultMaxDelay := 25 * time.Millisecond
	if DefaultMaxAckDelay != expectedDefaultMaxDelay {
		t.Errorf("DefaultMaxAckDelay = %v, want %v", DefaultMaxAckDelay, expectedDefaultMaxDelay)
	}

	expectedMaxMaxDelay := (1<<14 - 1) * time.Millisecond
	if MaxMaxAckDelay != expectedMaxMaxDelay {
		t.Errorf("MaxMaxAckDelay = %v, want %v", MaxMaxAckDelay, expectedMaxMaxDelay)
	}
}

// Test invalid packet limits
func TestInvalidPacketLimits(t *testing.T) {
	// AES limit = 2^52
	expectedAESLimit := uint64(1 << 52)
	if InvalidPacketLimitAES != expectedAESLimit {
		t.Errorf("InvalidPacketLimitAES = %d, want %d", InvalidPacketLimitAES, expectedAESLimit)
	}

	// ChaCha limit = 2^36
	expectedChaChaLimit := uint64(1 << 36)
	if InvalidPacketLimitChaCha != expectedChaChaLimit {
		t.Errorf("InvalidPacketLimitChaCha = %d, want %d", InvalidPacketLimitChaCha, expectedChaChaLimit)
	}
}

// Test MinStatelessResetSize calculation
func TestMinStatelessResetSize(t *testing.T) {
	// 1 (first byte) + 20 (max conn ID) + 4 (max pkt num) + 1 (min payload) + 16 (token)
	expected := 1 + 20 + 4 + 1 + 16
	if MinStatelessResetSize != expected {
		t.Errorf("MinStatelessResetSize = %d, want %d", MinStatelessResetSize, expected)
	}
}

// Test PacketType.String doesn't contain implementation details
func TestPacketTypeStringFormat(t *testing.T) {
	// Ensure unknown packet types have a reasonable format
	unknown := PacketType(255)
	str := unknown.String()
	if !strings.HasPrefix(str, "unknown packet type:") {
		t.Errorf("Unknown PacketType.String() = %q, should start with 'unknown packet type:'", str)
	}
}

// Benchmark tests
func BenchmarkParseECNHeaderBits(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ParseECNHeaderBits(byte(i % 4))
	}
}

func BenchmarkECNToHeaderBits(b *testing.B) {
	ecns := []ECN{ECNNon, ECT0, ECT1, ECNCE}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ecns[i%4].ToHeaderBits()
	}
}

func BenchmarkPacketTypeString(b *testing.B) {
	types := []PacketType{PacketTypeInitial, PacketTypeRetry, PacketTypeHandshake, PacketType0RTT}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = types[i%4].String()
	}
}
