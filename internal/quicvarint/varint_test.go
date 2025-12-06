// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package quicvarint

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/refraction-networking/utls/internal/quicvarint/protocol"
)

// Test constants match expected values
func TestConstants(t *testing.T) {
	if Min != 0 {
		t.Errorf("Min = %d, want 0", Min)
	}
	if Max != 4611686018427387903 {
		t.Errorf("Max = %d, want 4611686018427387903", Max)
	}
}

// Test IsValidVarint
func TestIsValidVarint(t *testing.T) {
	tests := []struct {
		value uint64
		valid bool
	}{
		{0, true},
		{1, true},
		{63, true},
		{64, true},
		{16383, true},
		{16384, true},
		{1073741823, true},
		{1073741824, true},
		{Max, true},
		{Max + 1, false},
		{^uint64(0), false}, // max uint64
	}

	for _, tt := range tests {
		result := IsValidVarint(tt.value)
		if result != tt.valid {
			t.Errorf("IsValidVarint(%d) = %v, want %v", tt.value, result, tt.valid)
		}
	}
}

// Test Len returns correct byte count
func TestLen(t *testing.T) {
	tests := []struct {
		value    uint64
		expected protocol.ByteCount
		hasErr   bool
	}{
		{0, 1, false},
		{1, 1, false},
		{63, 1, false},       // maxVarInt1
		{64, 2, false},       // min for 2-byte
		{16383, 2, false},    // maxVarInt2
		{16384, 4, false},    // min for 4-byte
		{1073741823, 4, false}, // maxVarInt4
		{1073741824, 8, false}, // min for 8-byte
		{Max, 8, false},      // maxVarInt8
		{Max + 1, 0, true},   // too large
	}

	for _, tt := range tests {
		length, err := Len(tt.value)
		if tt.hasErr {
			if err == nil {
				t.Errorf("Len(%d) expected error, got nil", tt.value)
			}
			if !errors.Is(err, ErrValueTooLarge) {
				t.Errorf("Len(%d) error = %v, want ErrValueTooLarge", tt.value, err)
			}
		} else {
			if err != nil {
				t.Errorf("Len(%d) unexpected error: %v", tt.value, err)
			}
			if length != tt.expected {
				t.Errorf("Len(%d) = %d, want %d", tt.value, length, tt.expected)
			}
		}
	}
}

// Test Append encoding
func TestAppend(t *testing.T) {
	tests := []struct {
		value    uint64
		expected []byte
		hasErr   bool
	}{
		// 1-byte encodings (0x00 - 0x3f)
		{0, []byte{0x00}, false},
		{1, []byte{0x01}, false},
		{37, []byte{0x25}, false}, // RFC 9000 Section 16, Example C.1
		{63, []byte{0x3f}, false},

		// 2-byte encodings (0x40xx)
		{64, []byte{0x40, 0x40}, false},
		{100, []byte{0x40, 0x64}, false},
		{494, []byte{0x41, 0xee}, false},
		{15293, []byte{0x7b, 0xbd}, false},                                            // RFC 9000 Section 16, Example C.2
		{16383, []byte{0x7f, 0xff}, false},

		// 4-byte encodings (0x80xxxxxx)
		{16384, []byte{0x80, 0x00, 0x40, 0x00}, false},
		{494878333, []byte{0x9d, 0x7f, 0x3e, 0x7d}, false},                             // RFC 9000 Section 16, Example C.3
		{1073741823, []byte{0xbf, 0xff, 0xff, 0xff}, false},

		// 8-byte encodings (0xc0xxxxxxxxxxxx)
		{1073741824, []byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}, false},
		{151288809941952652, []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, false}, // RFC 9000 Section 16, Example C.4
		{Max, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false},

		// Too large
		{Max + 1, nil, true},
	}

	for _, tt := range tests {
		result, err := Append(nil, tt.value)
		if tt.hasErr {
			if err == nil {
				t.Errorf("Append(%d) expected error, got nil", tt.value)
			}
		} else {
			if err != nil {
				t.Errorf("Append(%d) unexpected error: %v", tt.value, err)
			}
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Append(%d) = %x, want %x", tt.value, result, tt.expected)
			}
		}
	}
}

// Test Read decoding
func TestRead(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
		hasErr   bool
		errType  error
	}{
		// 1-byte encodings
		{"zero", []byte{0x00}, 0, false, nil},
		{"one", []byte{0x01}, 1, false, nil},
		{"RFC9000 C.1 (37)", []byte{0x25}, 37, false, nil},
		{"63", []byte{0x3f}, 63, false, nil},

		// 2-byte encodings
		{"64", []byte{0x40, 0x40}, 64, false, nil},
		{"100", []byte{0x40, 0x64}, 100, false, nil},
		{"RFC9000 C.2 (15293)", []byte{0x7b, 0xbd}, 15293, false, nil},
		{"16383", []byte{0x7f, 0xff}, 16383, false, nil},

		// 4-byte encodings
		{"16384", []byte{0x80, 0x00, 0x40, 0x00}, 16384, false, nil},
		{"RFC9000 C.3 (494878333)", []byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333, false, nil},
		{"1073741823", []byte{0xbf, 0xff, 0xff, 0xff}, 1073741823, false, nil},

		// 8-byte encodings
		{"1073741824", []byte{0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}, 1073741824, false, nil},
		{"RFC9000 C.4 (151288809941952652)", []byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652, false, nil},
		{"Max", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, Max, false, nil},

		// Non-minimal encodings (should be rejected by Read)
		{"non-minimal 0 in 2-byte", []byte{0x40, 0x00}, 0, true, ErrNonMinimalEncoding},
		{"non-minimal 63 in 2-byte", []byte{0x40, 0x3f}, 0, true, ErrNonMinimalEncoding},
		{"non-minimal 64 in 4-byte", []byte{0x80, 0x00, 0x00, 0x40}, 0, true, ErrNonMinimalEncoding},
		{"non-minimal 16383 in 4-byte", []byte{0x80, 0x00, 0x3f, 0xff}, 0, true, ErrNonMinimalEncoding},
		{"non-minimal 0 in 8-byte", []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, true, ErrNonMinimalEncoding},
		{"non-minimal 1073741823 in 8-byte", []byte{0xc0, 0x00, 0x00, 0x00, 0x3f, 0xff, 0xff, 0xff}, 0, true, ErrNonMinimalEncoding},

		// Truncated input
		{"truncated 2-byte", []byte{0x40}, 0, true, io.EOF},
		{"truncated 4-byte", []byte{0x80, 0x00, 0x40}, 0, true, io.EOF},
		{"truncated 8-byte", []byte{0xc0, 0x00, 0x00, 0x00, 0x40}, 0, true, io.EOF},

		// Empty input
		{"empty", []byte{}, 0, true, io.EOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.input)
			result, err := Read(reader)

			if tt.hasErr {
				if err == nil {
					t.Errorf("Read expected error, got nil")
				} else if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("Read error = %v, want %v", err, tt.errType)
				}
			} else {
				if err != nil {
					t.Errorf("Read unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("Read = %d, want %d", result, tt.expected)
				}
			}
		})
	}
}

// Test ReadLenient accepts non-minimal encodings
func TestReadLenient(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint64
	}{
		// Standard encodings
		{"zero", []byte{0x00}, 0},
		{"64", []byte{0x40, 0x40}, 64},

		// Non-minimal encodings (should be accepted by ReadLenient)
		{"non-minimal 0 in 2-byte", []byte{0x40, 0x00}, 0},
		{"non-minimal 63 in 2-byte", []byte{0x40, 0x3f}, 63},
		{"non-minimal 0 in 4-byte", []byte{0x80, 0x00, 0x00, 0x00}, 0},
		{"non-minimal 0 in 8-byte", []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.input)
			result, err := ReadLenient(reader)
			if err != nil {
				t.Errorf("ReadLenient unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("ReadLenient = %d, want %d", result, tt.expected)
			}
		})
	}
}

// Test round-trip encoding/decoding
func TestRoundTrip(t *testing.T) {
	testValues := []uint64{
		0, 1, 2, 10, 50, 63,           // 1-byte boundary
		64, 65, 100, 1000, 16383,      // 2-byte boundary
		16384, 16385, 100000, 1073741823, // 4-byte boundary
		1073741824, 1073741825, Max,   // 8-byte boundary
	}

	for _, val := range testValues {
		encoded, err := Append(nil, val)
		if err != nil {
			t.Errorf("Append(%d) error: %v", val, err)
			continue
		}

		reader := bytes.NewReader(encoded)
		decoded, err := Read(reader)
		if err != nil {
			t.Errorf("Read after Append(%d) error: %v", val, err)
			continue
		}

		if decoded != val {
			t.Errorf("Round-trip failed: Append(%d) -> Read() = %d", val, decoded)
		}
	}
}

// Test AppendWithLen
func TestAppendWithLen(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		length   protocol.ByteCount
		hasErr   bool
		errType  error
	}{
		// Valid cases
		{"0 in 1 byte", 0, 1, false, nil},
		{"63 in 1 byte", 63, 1, false, nil},
		{"0 in 2 bytes", 0, 2, false, nil},
		{"64 in 2 bytes", 64, 2, false, nil},
		{"0 in 4 bytes", 0, 4, false, nil},
		{"16384 in 4 bytes", 16384, 4, false, nil},
		{"0 in 8 bytes", 0, 8, false, nil},
		{"1073741824 in 8 bytes", 1073741824, 8, false, nil},

		// Value too large for specified length
		{"64 in 1 byte", 64, 1, true, ErrValueTooLargeForLength},
		{"16384 in 2 bytes", 16384, 2, true, ErrValueTooLargeForLength},
		{"1073741824 in 4 bytes", 1073741824, 4, true, ErrValueTooLargeForLength},

		// Invalid lengths
		{"0 in 3 bytes", 0, 3, true, ErrInvalidLength},
		{"0 in 5 bytes", 0, 5, true, ErrInvalidLength},
		{"0 in 6 bytes", 0, 6, true, ErrInvalidLength},
		{"0 in 7 bytes", 0, 7, true, ErrInvalidLength},

		// Value too large overall
		{"Max+1", Max + 1, 8, true, ErrValueTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := AppendWithLen(nil, tt.value, tt.length)
			if tt.hasErr {
				if err == nil {
					t.Errorf("AppendWithLen expected error, got nil")
				} else if tt.errType != nil && !errors.Is(err, tt.errType) {
					t.Errorf("AppendWithLen error = %v, want %v", err, tt.errType)
				}
			} else {
				if err != nil {
					t.Errorf("AppendWithLen unexpected error: %v", err)
					return
				}
				if protocol.ByteCount(len(result)) != tt.length {
					t.Errorf("AppendWithLen length = %d, want %d", len(result), tt.length)
				}

				// Verify can be decoded (lenient mode for padded values)
				reader := bytes.NewReader(result)
				decoded, err := ReadLenient(reader)
				if err != nil {
					t.Errorf("ReadLenient error: %v", err)
					return
				}
				if decoded != tt.value {
					t.Errorf("AppendWithLen/ReadLenient: got %d, want %d", decoded, tt.value)
				}
			}
		})
	}
}

// TestAppendWithLenExactEncoding verifies that AppendWithLen produces the exact
// expected byte sequences for padded encodings (non-minimal but valid).
func TestAppendWithLenExactEncoding(t *testing.T) {
	tests := []struct {
		name     string
		value    uint64
		length   protocol.ByteCount
		expected []byte
	}{
		// 2-byte padded encodings
		{"0 padded to 2 bytes", 0, 2, []byte{0x40, 0x00}},
		{"42 padded to 2 bytes", 42, 2, []byte{0x40, 0x2a}},
		{"63 padded to 2 bytes", 63, 2, []byte{0x40, 0x3f}},

		// 4-byte padded encodings
		{"0 padded to 4 bytes", 0, 4, []byte{0x80, 0x00, 0x00, 0x00}},
		{"42 padded to 4 bytes", 42, 4, []byte{0x80, 0x00, 0x00, 0x2a}},
		{"63 padded to 4 bytes", 63, 4, []byte{0x80, 0x00, 0x00, 0x3f}},
		{"64 padded to 4 bytes", 64, 4, []byte{0x80, 0x00, 0x00, 0x40}},
		{"16383 padded to 4 bytes", 16383, 4, []byte{0x80, 0x00, 0x3f, 0xff}},

		// 8-byte padded encodings
		{"0 padded to 8 bytes", 0, 8, []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"42 padded to 8 bytes", 42, 8, []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a}},
		{"63 padded to 8 bytes", 63, 8, []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f}},
		{"64 padded to 8 bytes", 64, 8, []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40}},
		{"16383 padded to 8 bytes", 16383, 8, []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0xff}},
		{"16384 padded to 8 bytes", 16384, 8, []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00}},
		{"1073741823 padded to 8 bytes", 1073741823, 8, []byte{0xc0, 0x00, 0x00, 0x00, 0x3f, 0xff, 0xff, 0xff}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := AppendWithLen(nil, tc.value, tc.length)
			if err != nil {
				t.Fatalf("AppendWithLen(%d, %d) error: %v", tc.value, tc.length, err)
			}
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("AppendWithLen(%d, %d) = %x, want %x", tc.value, tc.length, result, tc.expected)
			}

			// Also verify the value can be read back correctly with lenient reader
			reader := bytes.NewReader(result)
			decoded, err := ReadLenient(reader)
			if err != nil {
				t.Fatalf("ReadLenient error: %v", err)
			}
			if decoded != tc.value {
				t.Errorf("ReadLenient decoded %d, want %d", decoded, tc.value)
			}
		})
	}
}

// Test Append preserves existing buffer content
func TestAppendPreservesBuffer(t *testing.T) {
	prefix := []byte{0xde, 0xad, 0xbe, 0xef}
	result, err := Append(prefix, 42)
	if err != nil {
		t.Fatalf("Append error: %v", err)
	}

	if !bytes.HasPrefix(result, prefix) {
		t.Errorf("Append did not preserve prefix: got %x, want prefix %x", result, prefix)
	}

	// Verify the value is correctly appended
	reader := bytes.NewReader(result[len(prefix):])
	decoded, err := Read(reader)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if decoded != 42 {
		t.Errorf("Decoded value = %d, want 42", decoded)
	}
}

// Test multiple values in sequence
func TestMultipleValues(t *testing.T) {
	values := []uint64{0, 63, 64, 16383, 16384, 1073741823, 1073741824, Max}

	var buf []byte
	for _, v := range values {
		var err error
		buf, err = Append(buf, v)
		if err != nil {
			t.Fatalf("Append(%d) error: %v", v, err)
		}
	}

	reader := bytes.NewReader(buf)
	for i, expected := range values {
		decoded, err := Read(reader)
		if err != nil {
			t.Fatalf("Read value %d error: %v", i, err)
		}
		if decoded != expected {
			t.Errorf("Value %d: got %d, want %d", i, decoded, expected)
		}
	}
}

// Benchmark tests
func BenchmarkAppend1Byte(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Append(nil, 42)
	}
}

func BenchmarkAppend2Bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Append(nil, 1000)
	}
}

func BenchmarkAppend4Bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Append(nil, 100000)
	}
}

func BenchmarkAppend8Bytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Append(nil, Max)
	}
}

func BenchmarkRead1Byte(b *testing.B) {
	encoded, _ := Append(nil, 42)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encoded)
		_, _ = Read(reader)
	}
}

func BenchmarkRead8Bytes(b *testing.B) {
	encoded, _ := Append(nil, Max)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encoded)
		_, _ = Read(reader)
	}
}

func BenchmarkLen(b *testing.B) {
	values := []uint64{0, 63, 64, 16383, 16384, 1073741823, 1073741824, Max}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, v := range values {
			_, _ = Len(v)
		}
	}
}
