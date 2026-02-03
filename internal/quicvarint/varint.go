// Copyright 2024 The quic-go Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file of
// the quic-go repository.

package quicvarint

import (
	"io"

	utlserrors "github.com/refraction-networking/utls/errors"
	"github.com/refraction-networking/utls/internal/quicvarint/protocol"
)

// ErrNonMinimalEncoding is returned when a varint is encoded using more bytes
// than necessary, violating RFC 9000 Section 16 which requires minimal encoding.
var ErrNonMinimalEncoding = utlserrors.New("quic: varint uses non-minimal encoding").AtError()

// ErrValueTooLarge is returned when a value exceeds the maximum QUIC varint (2^62-1).
var ErrValueTooLarge = utlserrors.New("quic: value exceeds maximum varint (2^62-1)").AtError()

// ErrInvalidLength is returned when an invalid length is specified for AppendWithLen.
var ErrInvalidLength = utlserrors.New("quic: invalid varint length (must be 1, 2, 4, or 8)").AtError()

// ErrValueTooLargeForLength is returned when a value cannot fit in the specified length.
var ErrValueTooLargeForLength = utlserrors.New("quic: value too large for specified length").AtError()

// taken from the QUIC draft
const (
	// Min is the minimum value allowed for a QUIC varint.
	Min = 0

	// Max is the maximum allowed value for a QUIC varint (2^62-1).
	Max = maxVarInt8

	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// IsValidVarint returns true if i can be encoded as a QUIC variable-length integer.
// Valid values are in the range [0, 2^62-1].
func IsValidVarint(i uint64) bool {
	return i <= maxVarInt8
}

// Read reads a number in the QUIC varint format from r.
// Returns ErrNonMinimalEncoding if the value uses more bytes than necessary,
// as required by RFC 9000 Section 16.
func Read(r io.ByteReader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	numBytes := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if numBytes == 1 {
		return uint64(b1), nil
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if numBytes == 2 {
		val := uint64(b2) + uint64(b1)<<8
		// RFC 9000 Section 16: 2-byte encoding requires val >= 64
		if val < 64 {
			return 0, ErrNonMinimalEncoding
		}
		return val, nil
	}
	b3, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if numBytes == 4 {
		val := uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24
		// RFC 9000 Section 16: 4-byte encoding requires val >= 16384
		if val < 16384 {
			return 0, ErrNonMinimalEncoding
		}
		return val, nil
	}
	b5, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	val := uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56
	// RFC 9000 Section 16: 8-byte encoding requires val >= 1073741824
	if val < 1073741824 {
		return 0, ErrNonMinimalEncoding
	}
	return val, nil
}

// ReadLenient reads a number in the QUIC varint format from r.
// Unlike Read, this function accepts non-minimal encodings for compatibility
// with implementations that may not strictly follow RFC 9000 Section 16.
func ReadLenient(r io.ByteReader) (uint64, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	// the first two bits of the first byte encode the length
	numBytes := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if numBytes == 1 {
		return uint64(b1), nil
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if numBytes == 2 {
		return uint64(b2) + uint64(b1)<<8, nil
	}
	b3, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b4, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if numBytes == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, nil
	}
	b5, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b6, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b7, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	b8, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, nil
}

// Append appends i in the QUIC varint format.
// Returns ErrValueTooLarge if i > 2^62-1 (Max, the maximum QUIC varint value).
func Append(b []byte, i uint64) ([]byte, error) {
	if i <= maxVarInt1 {
		return append(b, uint8(i)), nil
	}
	if i <= maxVarInt2 {
		return append(b, []byte{uint8(i>>8) | 0x40, uint8(i)}...), nil
	}
	if i <= maxVarInt4 {
		return append(b, []byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)}...), nil
	}
	if i <= maxVarInt8 {
		return append(b, []byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		}...), nil
	}
	return nil, ErrValueTooLarge
}

// AppendWithLen appends i in the QUIC varint format with the desired length.
// Returns:
//   - ErrInvalidLength if length is not 1, 2, 4, or 8
//   - ErrValueTooLargeForLength if i cannot be encoded in the specified length
//   - ErrValueTooLarge if i > 2^62-1
func AppendWithLen(b []byte, i uint64, length protocol.ByteCount) ([]byte, error) {
	if length != 1 && length != 2 && length != 4 && length != 8 {
		return nil, ErrInvalidLength
	}
	l, err := Len(i)
	if err != nil {
		return nil, err
	}
	if l == length {
		return Append(b, i)
	}
	if l > length {
		return nil, ErrValueTooLargeForLength
	}
	if length == 2 {
		b = append(b, 0b01000000)
	} else if length == 4 {
		b = append(b, 0b10000000)
	} else if length == 8 {
		b = append(b, 0b11000000)
	}
	for j := protocol.ByteCount(1); j < length-l; j++ {
		b = append(b, 0)
	}
	for j := protocol.ByteCount(0); j < l; j++ {
		b = append(b, uint8(i>>(8*(l-1-j))))
	}
	return b, nil
}

// Len determines the number of bytes that will be needed to write the number i.
// Returns ErrValueTooLarge if i > 2^62-1 (Max, the maximum QUIC varint value).
func Len(i uint64) (protocol.ByteCount, error) {
	if i <= maxVarInt1 {
		return 1, nil
	}
	if i <= maxVarInt2 {
		return 2, nil
	}
	if i <= maxVarInt4 {
		return 4, nil
	}
	if i <= maxVarInt8 {
		return 8, nil
	}
	return 0, ErrValueTooLarge
}
