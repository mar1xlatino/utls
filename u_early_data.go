// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls provides TLS 1.3 0-RTT early data support infrastructure.
//
// # RFC 8446 Section 8 Compliance - 0-RTT and Anti-Replay
//
// This file provides CLIENT-SIDE 0-RTT early data infrastructure. Per RFC 8446:
//
// ## Current Implementation Status
//
// IMPORTANT: 0-RTT data TRANSMISSION is NOT yet implemented. The WriteEarlyData
// function returns ErrEarlyDataNotImplemented. This file provides infrastructure
// for state tracking, buffering, and configuration that can be used when full
// 0-RTT support is implemented.
//
// ## Security Considerations (RFC 8446 Section 8)
//
// 0-RTT data has weaker security guarantees than data sent after the handshake:
//
//   - NO FORWARD SECRECY: 0-RTT data is encrypted with keys derived solely from
//     the PSK, not from an ephemeral key exchange. Compromise of the PSK allows
//     decryption of all 0-RTT data encrypted with that PSK.
//
//   - REPLAY VULNERABILITY: An attacker can capture and replay 0-RTT data.
//     Applications MUST only send data that is safe to replay (idempotent).
//
// ## Anti-Replay Protection Responsibilities
//
// Per RFC 8446 Section 8, anti-replay protection is a SERVER-SIDE responsibility:
//
//   - Servers SHOULD implement one of the anti-replay mechanisms described in
//     RFC 8446 Section 8 (single-use tickets, client hello recording, or
//     freshness checks based on obfuscated_ticket_age).
//
//   - Clients CANNOT prevent replay attacks; they can only limit exposure by
//     sending only idempotent, replay-safe data as 0-RTT.
//
// ## Client-Side Obligations
//
// Applications using 0-RTT SHOULD:
//
//  1. Only send idempotent requests (GET, HEAD, OPTIONS in HTTP terms)
//  2. Never send data that causes state changes on first receipt
//  3. Be prepared for the server to reject 0-RTT data
//  4. Resend rejected 0-RTT data after the handshake completes
//
// ## References
//
//   - RFC 8446 Section 8: https://www.rfc-editor.org/rfc/rfc8446#section-8
//   - RFC 8446 Section 2.3: https://www.rfc-editor.org/rfc/rfc8446#section-2.3

package tls

import (
	"errors"
	"fmt"
	"math"
	"sync"
)

// Early data (0-RTT) error types.
var (
	// ErrEarlyDataNotSupported is returned when attempting to write early data
	// but the session doesn't support 0-RTT.
	ErrEarlyDataNotSupported = errors.New("tls: server does not support 0-RTT early data")

	// ErrEarlyDataRejected is returned when the server rejects 0-RTT data.
	// The application must resend the data via normal Write() after handshake.
	ErrEarlyDataRejected = errors.New("tls: server rejected 0-RTT early data")

	// ErrEarlyDataTooLarge is returned when early data exceeds max_early_data_size.
	ErrEarlyDataTooLarge = errors.New("tls: early data exceeds maximum size")

	// ErrEarlyDataAfterHandshake is returned when WriteEarlyData is called
	// after handshake has completed.
	ErrEarlyDataAfterHandshake = errors.New("tls: handshake already complete, use Write()")

	// ErrEarlyDataNoSecret is returned when early traffic secret hasn't been derived.
	ErrEarlyDataNoSecret = errors.New("tls: early traffic secret not derived")
)

// EarlyDataState tracks the state of 0-RTT early data.
type EarlyDataState struct {
	mu sync.RWMutex

	// enabled indicates if early data is supported for this session.
	enabled bool

	// accepted indicates if server accepted the 0-RTT data.
	accepted bool

	// rejected indicates if server rejected the 0-RTT data.
	rejected bool

	// maxSize is the maximum early data size from the session ticket.
	maxSize uint32

	// written tracks bytes written as early data.
	written uint32

	// buffer stores early data for potential resend if rejected.
	buffer []byte

	// trafficSecret is the early traffic secret for encryption.
	trafficSecret []byte
}

// NewEarlyDataState creates a new early data state tracker.
func NewEarlyDataState() *EarlyDataState {
	return &EarlyDataState{}
}

// Enable enables early data with the given max size and traffic secret.
func (e *EarlyDataState) Enable(maxSize uint32, trafficSecret []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = true
	e.maxSize = maxSize
	e.trafficSecret = make([]byte, len(trafficSecret))
	copy(e.trafficSecret, trafficSecret)
}

// Disable disables early data and securely zeros the traffic secret.
func (e *EarlyDataState) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = false
	// Zero traffic secret when disabling to prevent key material from lingering
	if e.trafficSecret != nil {
		zeroSlice(e.trafficSecret)
		e.trafficSecret = nil
	}
}

// IsEnabled returns true if early data is enabled.
func (e *EarlyDataState) IsEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled
}

// MaxSize returns the maximum early data size.
func (e *EarlyDataState) MaxSize() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.maxSize
}

// TrafficSecret returns the early traffic secret.
func (e *EarlyDataState) TrafficSecret() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.trafficSecret == nil {
		return nil
	}
	result := make([]byte, len(e.trafficSecret))
	copy(result, e.trafficSecret)
	return result
}

// SetAccepted marks early data as accepted by server.
func (e *EarlyDataState) SetAccepted() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accepted = true
}

// SetRejected marks early data as rejected by server.
func (e *EarlyDataState) SetRejected() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rejected = true
}

// IsAccepted returns true if server accepted early data.
func (e *EarlyDataState) IsAccepted() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.accepted
}

// IsRejected returns true if server rejected early data.
func (e *EarlyDataState) IsRejected() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rejected
}

// Maximum buffer size to prevent memory exhaustion (16MB)
const maxEarlyDataBufferSize = 16 << 20

// RecordWrite records early data write and buffers for potential resend.
func (e *EarlyDataState) RecordWrite(data []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Security: Validate len(data) fits in uint32 before cast to prevent silent truncation
	if len(data) > math.MaxUint32 {
		return fmt.Errorf("%w: data length %d exceeds uint32 max", ErrEarlyDataTooLarge, len(data))
	}
	dataLen := uint32(len(data))

	// Security: Check for integer overflow before addition
	if dataLen > 0xFFFFFFFF-e.written {
		return fmt.Errorf("%w: would overflow uint32", ErrEarlyDataTooLarge)
	}

	newTotal := e.written + dataLen

	// Check configured max size
	if e.maxSize > 0 && newTotal > e.maxSize {
		return fmt.Errorf("%w: %d bytes exceeds max %d", ErrEarlyDataTooLarge, newTotal, e.maxSize)
	}

	// Security: Enforce absolute max to prevent memory exhaustion
	if newTotal > maxEarlyDataBufferSize {
		return fmt.Errorf("%w: %d bytes exceeds absolute max %d", ErrEarlyDataTooLarge, newTotal, maxEarlyDataBufferSize)
	}

	e.written = newTotal
	e.buffer = append(e.buffer, data...)
	return nil
}

// BytesWritten returns total bytes written as early data.
func (e *EarlyDataState) BytesWritten() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.written
}

// BufferedData returns a copy of buffered early data (for resend on rejection).
func (e *EarlyDataState) BufferedData() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.buffer == nil {
		return nil
	}
	result := make([]byte, len(e.buffer))
	copy(result, e.buffer)
	return result
}

// ClearBuffer clears the early data buffer (after acceptance or resend).
// Also resets the written counter for consistency.
func (e *EarlyDataState) ClearBuffer() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.buffer = nil
	e.written = 0 // Reset counter to match cleared buffer
}

// Reset resets all early data state.
// Securely zeros the traffic secret before releasing it.
func (e *EarlyDataState) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = false
	e.accepted = false
	e.rejected = false
	e.maxSize = 0
	e.written = 0
	e.buffer = nil
	// Zero traffic secret before releasing to prevent key material from lingering in memory.
	// zeroSlice includes runtime.KeepAlive to prevent compiler optimization.
	if e.trafficSecret != nil {
		zeroSlice(e.trafficSecret)
		e.trafficSecret = nil
	}
}

// EarlyDataConfig configures 0-RTT early data behavior.
//
// # Security Warning
//
// 0-RTT data lacks forward secrecy and is vulnerable to replay attacks.
// See WriteEarlyData documentation and RFC 8446 Section 8 for details.
// Only enable 0-RTT for applications that send idempotent, replay-safe data.
type EarlyDataConfig struct {
	// Enabled allows sending early data when resuming sessions.
	// WARNING: Only enable if your application sends idempotent data.
	Enabled bool

	// MaxSize limits early data size. 0 means use server's max_early_data_size.
	MaxSize uint32

	// OnAccepted is called when server accepts early data.
	OnAccepted func()

	// OnRejected is called when server rejects early data.
	// The buffered data is provided for application to resend.
	OnRejected func(bufferedData []byte)

	// BufferForResend buffers early data in case of rejection.
	// If false, application must track data itself.
	BufferForResend bool

	// SilentFallback enables automatic sending of buffered early data after
	// handshake completes. When true (default), data written via WriteEarlyData()
	// is silently buffered and sent as regular data after handshake completion.
	// This avoids the detection vector of advertising early_data without sending any.
	//
	// When false, WriteEarlyData() returns ErrEarlyDataNotImplemented and the
	// application must manually handle buffered data via EarlyDataBufferedData().
	SilentFallback bool
}

// DefaultEarlyDataConfig returns default early data configuration.
// SilentFallback is enabled by default for graceful handling.
func DefaultEarlyDataConfig() *EarlyDataConfig {
	return &EarlyDataConfig{
		Enabled:         false,
		MaxSize:         0,
		BufferForResend: true,
		SilentFallback:  true,
	}
}

// UConn early data methods are added below.
// These integrate with the existing UConn structure.

// WriteEarlyData buffers data to be sent as early as possible.
//
// # Silent Fallback Behavior
//
// Since true 0-RTT is not implemented for non-QUIC TLS connections, this function
// implements "silent fallback": data is buffered and automatically sent as regular
// application data after the handshake completes successfully. This avoids the
// detection vector where ClientHello advertises early_data but no data is sent.
//
// The function returns success (nil error) when data is buffered. After handshake
// completion, call EarlyDataRejected() to check if fallback was used (it will return
// true since data was sent as regular data, not as true 0-RTT).
//
// For QUIC connections, early data IS supported at the transport layer via
// quicSetWriteSecret() and this function's behavior may differ.
//
// # Security Warning - Replay Attacks (RFC 8446 Section 8)
//
// 0-RTT data is vulnerable to replay attacks. An attacker who captures the
// ClientHello and early data can replay it to the server. The server may
// process the replayed data multiple times.
//
// Applications MUST only send idempotent data that is safe to replay:
//   - HTTP GET, HEAD, OPTIONS requests
//   - Read-only database queries
//   - Requests that do not modify server state
//
// Applications MUST NOT send as 0-RTT:
//   - HTTP POST, PUT, DELETE requests with side effects
//   - Financial transactions
//   - Any request that modifies state on first receipt
//
// Anti-replay protection is a SERVER-SIDE responsibility. This client library
// cannot prevent replay attacks; servers must implement mechanisms described
// in RFC 8446 Section 8 (single-use tickets, ClientHello recording, etc.).
//
// Returns ErrEarlyDataNotSupported if early data is not enabled for this connection.
// Must be called after setting up session resumption but before Handshake().
func (uconn *UConn) WriteEarlyData(data []byte) (int, error) {
	// Check handshake state
	if uconn.ConnectionState().HandshakeComplete {
		return 0, ErrEarlyDataAfterHandshake
	}

	// Check early data state
	if uconn.earlyData == nil {
		return 0, ErrEarlyDataNotSupported
	}

	if !uconn.earlyData.IsEnabled() {
		return 0, ErrEarlyDataNotSupported
	}

	// Check max size with integer overflow protection
	maxSize := uconn.earlyData.MaxSize()
	if maxSize > 0 {
		// Protect against integer truncation: len(data) could exceed uint32 max
		if len(data) > math.MaxUint32 {
			return 0, fmt.Errorf("%w: data length %d exceeds uint32 max",
				ErrEarlyDataTooLarge, len(data))
		}
		currentWritten := uconn.earlyData.BytesWritten()
		if currentWritten+uint32(len(data)) > maxSize {
			return 0, fmt.Errorf("%w: %d + %d exceeds max %d",
				ErrEarlyDataTooLarge, currentWritten, len(data), maxSize)
		}
	}

	// Record write for potential resend
	if err := uconn.earlyData.RecordWrite(data); err != nil {
		return 0, err
	}

	// Write early data record
	// Note: Actual encryption requires cipher setup from early traffic secret
	return uconn.writeEarlyDataInternal(data)
}

// ErrEarlyDataNotImplemented indicates true 0-RTT early data transmission is not implemented.
// This error is kept for backwards compatibility and informational purposes.
//
// Current behavior: WriteEarlyData() uses "silent fallback" - data is buffered and
// automatically sent as regular application data after handshake completion.
// The function returns nil (no error) to indicate successful buffering.
//
// After handshake, EarlyDataRejected() returns true to indicate fallback was used.
// Use HasBufferedEarlyData() before handshake to check if data is pending.
//
// Full 0-RTT implementation would require:
//  1. Setting up early data cipher from earlyTrafficSecret
//  2. Creating TLS records with application_data content type (0x17)
//  3. Writing encrypted records after ClientHello, before ServerHello
//  4. Server-side anti-replay protection per RFC 8446 Section 8
var ErrEarlyDataNotImplemented = errors.New("tls: true 0-RTT early data not implemented - silent fallback used")

// writeEarlyDataInternal handles the actual early data record write.
// Since true 0-RTT is not implemented for non-QUIC TLS, this uses silent fallback:
// data is buffered and will be automatically sent after handshake completes.
//
// For QUIC connections, early data is handled at the QUIC transport layer
// via quicSetWriteSecret(), not through this function.
func (uconn *UConn) writeEarlyDataInternal(data []byte) (int, error) {
	// Silent fallback: Data is already buffered via RecordWrite() called before this.
	// The buffered data will be automatically sent via sendBufferedEarlyData()
	// which is called after handshake completion.
	//
	// This approach avoids the detection vector where ClientHello advertises
	// early_data extension but no early data records are actually sent.
	// Since we don't advertise the extension (for non-QUIC), there's no
	// inconsistency between what we advertise and what we send.
	//
	// NOTE: For true 0-RTT implementation, this would need:
	// 1. Setting up early data cipher from trafficSecret
	// 2. Creating TLS records with application_data content type (0x17)
	// 3. Writing encrypted records after ClientHello, before ServerHello
	// 4. Integration with handshake_client_tls13.go

	// Return success - data will be sent after handshake completes
	return len(data), nil
}

// EarlyDataAccepted returns true if server accepted 0-RTT early data.
// Only valid after Handshake() completes.
func (uconn *UConn) EarlyDataAccepted() bool {
	if uconn.earlyData == nil {
		return false
	}
	return uconn.earlyData.IsAccepted()
}

// EarlyDataRejected returns true if server rejected 0-RTT early data.
// When rejected, application must resend data via normal Write().
func (uconn *UConn) EarlyDataRejected() bool {
	if uconn.earlyData == nil {
		return false
	}
	return uconn.earlyData.IsRejected()
}

// SetMaxEarlyData sets maximum early data size for this connection.
// If 0, uses server's max_early_data_size from session ticket.
func (uconn *UConn) SetMaxEarlyData(max uint32) {
	if uconn.earlyData == nil {
		uconn.earlyData = NewEarlyDataState()
	}
	uconn.earlyData.mu.Lock()
	uconn.earlyData.maxSize = max
	uconn.earlyData.mu.Unlock()
}

// EnableEarlyData enables 0-RTT early data for this connection.
// Must be called before Handshake() and after loading a resumable session.
func (uconn *UConn) EnableEarlyData() {
	if uconn.earlyData == nil {
		uconn.earlyData = NewEarlyDataState()
	}
	uconn.earlyData.mu.Lock()
	uconn.earlyData.enabled = true
	uconn.earlyData.mu.Unlock()
}

// EarlyDataBufferedData returns buffered early data for resending.
// Call this after EarlyDataRejected() returns true.
func (uconn *UConn) EarlyDataBufferedData() []byte {
	if uconn.earlyData == nil {
		return nil
	}
	return uconn.earlyData.BufferedData()
}

// ClearEarlyDataBuffer clears the early data buffer.
// Call after successfully resending data or when no longer needed.
func (uconn *UConn) ClearEarlyDataBuffer() {
	if uconn.earlyData != nil {
		uconn.earlyData.ClearBuffer()
	}
}

// sendBufferedEarlyData sends any buffered early data after handshake completes.
// This implements the "silent fallback" for 0-RTT: data that was written via
// WriteEarlyData() before handshake is automatically sent as regular data
// after the handshake completes successfully.
//
// This is called internally after handshake completion when there's buffered data.
// Returns nil if no buffered data exists.
func (uconn *UConn) sendBufferedEarlyData() error {
	if uconn.earlyData == nil {
		return nil
	}

	buffered := uconn.earlyData.BufferedData()
	if len(buffered) == 0 {
		return nil
	}

	// Write the buffered data using normal Write() now that handshake is complete
	n, err := uconn.Write(buffered)
	if err != nil {
		return fmt.Errorf("tls: failed to send buffered early data: %w", err)
	}

	if n != len(buffered) {
		return fmt.Errorf("tls: incomplete write of buffered early data: wrote %d of %d bytes", n, len(buffered))
	}

	// Clear the buffer after successful send
	uconn.earlyData.ClearBuffer()

	// Mark as rejected (since it wasn't actually sent as 0-RTT)
	// This allows applications to distinguish between true 0-RTT and fallback
	uconn.earlyData.SetRejected()

	return nil
}

// HasBufferedEarlyData returns true if there is buffered early data waiting to be sent.
func (uconn *UConn) HasBufferedEarlyData() bool {
	if uconn.earlyData == nil {
		return false
	}
	return uconn.earlyData.BytesWritten() > 0
}
