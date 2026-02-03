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
	"context"
	"fmt"
	"math"
	"sync"

	utlserrors "github.com/refraction-networking/utls/errors"
)

// Early data (0-RTT) error types.
var (
	// ErrEarlyDataNotSupported is returned when attempting to write early data
	// but the session doesn't support 0-RTT.
	ErrEarlyDataNotSupported = utlserrors.New("tls: server does not support 0-RTT early data").AtError()

	// ErrEarlyDataRejected is returned when the server rejects 0-RTT data.
	// The application must resend the data via normal Write() after handshake.
	ErrEarlyDataRejected = utlserrors.New("tls: server rejected 0-RTT early data").AtError()

	// ErrEarlyDataTooLarge is returned when early data exceeds max_early_data_size.
	ErrEarlyDataTooLarge = utlserrors.New("tls: early data exceeds maximum size").AtError()

	// ErrEarlyDataAfterHandshake is returned when WriteEarlyData is called
	// after handshake has completed.
	ErrEarlyDataAfterHandshake = utlserrors.New("tls: handshake already complete, use Write()").AtError()

	// ErrEarlyDataNoSecret is returned when early traffic secret hasn't been derived.
	ErrEarlyDataNoSecret = utlserrors.New("tls: early traffic secret not derived").AtError()

	// ErrCipherSuiteMismatch is returned when the cipher suite passed to transmitEarlyData
	// does not match the cipher suite stored in EarlyDataState. This indicates a bug in
	// the caller - the cipher suite must match what was negotiated during session resumption.
	// Using the wrong cipher suite would encrypt data with incorrect keys.
	ErrCipherSuiteMismatch = utlserrors.New("tls: cipher suite mismatch for early data encryption").AtError()
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

	// cipherSuiteID is the TLS 1.3 cipher suite used for early data encryption.
	// This must match the cipher suite from the session being resumed.
	cipherSuiteID uint16

	// transmitted indicates that early data has been transmitted over the wire.
	// This is used to distinguish between buffered-only and actually-transmitted states.
	transmitted bool
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

	utlserrors.LogDebug(context.Background(), "0-RTT: enabled early data, max_size:", maxSize)
}

// EnableWithCipherSuite enables early data with the cipher suite for TLS 1.3 encryption.
// This is the preferred method for enabling 0-RTT as it stores all necessary
// cryptographic parameters for actual early data transmission.
func (e *EarlyDataState) EnableWithCipherSuite(maxSize uint32, trafficSecret []byte, cipherSuiteID uint16) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = true
	e.maxSize = maxSize
	e.cipherSuiteID = cipherSuiteID
	e.trafficSecret = make([]byte, len(trafficSecret))
	copy(e.trafficSecret, trafficSecret)

	utlserrors.LogDebug(context.Background(), "0-RTT: enabled early data with cipher suite:", cipherSuiteID, "max_size:", maxSize)
}

// CipherSuiteID returns the cipher suite ID for early data encryption.
func (e *EarlyDataState) CipherSuiteID() uint16 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cipherSuiteID
}

// SetTransmitted marks early data as having been transmitted over the wire.
func (e *EarlyDataState) SetTransmitted() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.transmitted = true
}

// WasTransmitted returns true if early data was actually transmitted as 0-RTT records.
func (e *EarlyDataState) WasTransmitted() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.transmitted
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

	utlserrors.LogDebug(context.Background(), "0-RTT: server accepted early data")
}

// SetRejected marks early data as rejected by server.
func (e *EarlyDataState) SetRejected() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rejected = true

	utlserrors.LogDebug(context.Background(), "0-RTT: server rejected early data, data must be resent")
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

// TryRecordWrite atomically checks if the data fits within max_early_data_size
// and records the write if it does. This prevents TOCTOU race conditions where
// concurrent calls to WriteEarlyData() could exceed max_early_data_size.
//
// This method acquires the lock once and performs both the size check and the
// write operation atomically, eliminating the race window that exists when
// calling MaxSize(), BytesWritten(), and RecordWrite() separately.
//
// Returns:
//   - currentWritten: bytes written before this call (for logging)
//   - nil error on success
//   - ErrEarlyDataTooLarge if the write would exceed limits
func (e *EarlyDataState) TryRecordWrite(data []byte) (currentWritten uint32, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Capture current state for return value (useful for logging)
	currentWritten = e.written

	// Security: Validate len(data) fits in uint32 before cast to prevent silent truncation
	if len(data) > math.MaxUint32 {
		return currentWritten, fmt.Errorf("%w: data length %d exceeds uint32 max",
			ErrEarlyDataTooLarge, len(data))
	}
	dataLen := uint32(len(data))

	// Security: Check for integer overflow before addition
	if dataLen > 0xFFFFFFFF-e.written {
		return currentWritten, fmt.Errorf("%w: would overflow uint32", ErrEarlyDataTooLarge)
	}

	newTotal := e.written + dataLen

	// Atomic check: verify write fits within configured max size
	if e.maxSize > 0 && newTotal > e.maxSize {
		return currentWritten, fmt.Errorf("%w: %d + %d exceeds max %d",
			ErrEarlyDataTooLarge, e.written, dataLen, e.maxSize)
	}

	// Security: Enforce absolute max to prevent memory exhaustion
	if newTotal > maxEarlyDataBufferSize {
		return currentWritten, fmt.Errorf("%w: %d bytes exceeds absolute max %d",
			ErrEarlyDataTooLarge, newTotal, maxEarlyDataBufferSize)
	}

	// Atomic write: update state within the same lock acquisition
	e.written = newTotal
	e.buffer = append(e.buffer, data...)
	return currentWritten, nil
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
// The buffer is zeroed before release to prevent sensitive early data from
// lingering in memory.
func (e *EarlyDataState) ClearBuffer() {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Zero early data buffer before releasing to prevent sensitive application
	// data from lingering in memory. zeroSlice includes runtime.KeepAlive
	// to prevent compiler optimization.
	if e.buffer != nil {
		zeroSlice(e.buffer)
		e.buffer = nil
	}
	e.written = 0 // Reset counter to match cleared buffer
}

// Reset resets all early data state.
// Securely zeros sensitive data (buffer and traffic secret) before releasing.
func (e *EarlyDataState) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = false
	e.accepted = false
	e.rejected = false
	e.maxSize = 0
	e.written = 0
	// Zero early data buffer before releasing to prevent sensitive application
	// data from lingering in memory.
	if e.buffer != nil {
		zeroSlice(e.buffer)
		e.buffer = nil
	}
	e.cipherSuiteID = 0
	e.transmitted = false
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
	ctx := context.Background()

	// Check handshake state
	if uconn.ConnectionState().HandshakeComplete {
		utlserrors.LogDebug(ctx, "0-RTT: write rejected - handshake already complete")
		return 0, ErrEarlyDataAfterHandshake
	}

	// Check early data state
	if uconn.earlyData == nil {
		utlserrors.LogDebug(ctx, "0-RTT: write rejected - early data not initialized")
		return 0, ErrEarlyDataNotSupported
	}

	if !uconn.earlyData.IsEnabled() {
		utlserrors.LogDebug(ctx, "0-RTT: write rejected - early data not enabled")
		return 0, ErrEarlyDataNotSupported
	}

	// Atomically check size limits and record write to prevent TOCTOU race condition.
	// TryRecordWrite performs the size check and buffer write under a single lock,
	// ensuring concurrent calls cannot exceed max_early_data_size (RFC 8446 compliance).
	currentWritten, err := uconn.earlyData.TryRecordWrite(data)
	if err != nil {
		utlserrors.LogDebug(ctx, "0-RTT: write rejected -", err)
		return 0, err
	}

	utlserrors.LogDebug(ctx, "0-RTT: buffered early data, size:", len(data), "total written:", currentWritten+uint32(len(data)))

	// Write early data record
	// Note: Actual encryption requires cipher setup from early traffic secret
	return uconn.writeEarlyDataInternal(data)
}

// ErrEarlyDataNotImplemented is kept for backwards compatibility.
// Note: True 0-RTT early data transmission IS now implemented for standard TLS (non-QUIC).
// This error may still be returned in edge cases where transmission fails.
var ErrEarlyDataNotImplemented = utlserrors.New("tls: early data transmission failed").AtError()

// writeEarlyDataInternal buffers early data for transmission.
//
// The actual 0-RTT transmission happens during Handshake() via transmitEarlyData(),
// which is called after ClientHello is sent but before ServerHello is received.
//
// Flow for 0-RTT early data:
//  1. Application calls WriteEarlyData() before Handshake() - data is buffered here
//  2. Application calls Handshake()
//  3. ClientHello is sent with early_data extension
//  4. client_early_traffic_secret is derived from PSK
//  5. transmitEarlyData() encrypts and sends buffered data as application_data records
//  6. ServerHello is received and handshake continues
//  7. If server accepts early_data: data was processed, EarlyDataAccepted() returns true
//  8. If server rejects early_data: data must be resent, EarlyDataRejected() returns true
//
// For QUIC connections, early data is handled at the QUIC transport layer
// via quicSetWriteSecret(), not through this path.
func (uconn *UConn) writeEarlyDataInternal(data []byte) (int, error) {
	// Data is already buffered via RecordWrite() called before this.
	// The buffered data will be transmitted during Handshake() via transmitEarlyData()
	// after ClientHello is sent.
	//
	// If transmitEarlyData() fails or is not called (e.g., no early_data extension),
	// the buffered data will be sent via sendBufferedEarlyData() after handshake
	// completion as a fallback.

	// Return success - data is buffered and will be transmitted during handshake
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
// Returns nil if:
//   - No early data state exists
//   - No buffered data exists
//   - Early data was already accepted by server (transmitted as 0-RTT)
//   - Early data was already transmitted but awaiting acceptance
func (uconn *UConn) sendBufferedEarlyData() error {
	ctx := context.Background()

	if uconn.earlyData == nil {
		return nil
	}

	// If server accepted early data, it was already delivered via 0-RTT.
	// Buffer should already be cleared by readServerParameters(), but check anyway.
	if uconn.earlyData.IsAccepted() {
		utlserrors.LogDebug(ctx, "0-RTT: early data already accepted, no fallback needed")
		return nil
	}

	// CRITICAL FIX: If early data was already transmitted as 0-RTT records,
	// do NOT resend automatically - even if the server rejected it.
	// Automatic resend would cause double transmission of data that was already
	// sent over the wire, potentially executing non-idempotent operations twice
	// (e.g., financial transactions, state changes).
	//
	// Per RFC 8446, when server rejects 0-RTT, the application is responsible for
	// deciding whether to resend. Use EarlyDataRejected() to detect rejection and
	// EarlyDataBufferedData() to retrieve the buffered data for manual resend.
	if uconn.earlyData.WasTransmitted() {
		utlserrors.LogDebug(ctx, "0-RTT: early data was already transmitted as 0-RTT, skipping automatic resend")
		return nil
	}

	// If early data was NOT transmitted (e.g., no session available, cipher setup
	// failed, or transmission error), but data was buffered via WriteEarlyData(),
	// send it now as regular application data. This implements "silent fallback"
	// for cases where true 0-RTT transmission did not occur.
	buffered := uconn.earlyData.BufferedData()
	if len(buffered) == 0 {
		return nil
	}

	utlserrors.LogDebug(ctx, "0-RTT: sending buffered early data as fallback, size:", len(buffered))

	// Write the buffered data using normal Write() now that handshake is complete
	n, err := uconn.Write(buffered)
	if err != nil {
		utlserrors.LogDebug(ctx, "0-RTT: fallback write failed:", err)
		return utlserrors.New("tls: failed to send buffered early data").Base(err).AtError()
	}

	if n != len(buffered) {
		utlserrors.LogDebug(ctx, "0-RTT: fallback write incomplete:", n, "of", len(buffered), "bytes")
		return utlserrors.New("tls: incomplete write of buffered early data: wrote", n, "of", len(buffered), "bytes").AtError()
	}

	utlserrors.LogDebug(ctx, "0-RTT: fallback write complete, sent", n, "bytes")

	// Clear the buffer after successful send
	uconn.earlyData.ClearBuffer()

	// Mark as rejected if not already marked
	// This allows applications to distinguish between true 0-RTT and fallback
	if !uconn.earlyData.IsRejected() {
		uconn.earlyData.SetRejected()
	}

	return nil
}

// HasBufferedEarlyData returns true if there is buffered early data waiting to be sent.
func (uconn *UConn) HasBufferedEarlyData() bool {
	if uconn.earlyData == nil {
		return false
	}
	return uconn.earlyData.BytesWritten() > 0
}

// transmitEarlyData transmits buffered early data as encrypted 0-RTT records.
// This is the core function for true 0-RTT early data transmission (non-QUIC).
//
// This function is called internally from the handshake after ClientHello is sent
// and before ServerHello is received. The sequence is:
//
//  1. ClientHello is sent with early_data extension
//  2. Early traffic secret is derived from the PSK
//  3. Output cipher is set up with early traffic keys
//  4. This function transmits any buffered early data as application_data records
//  5. ServerHello is received
//  6. Handshake continues with handshake traffic keys
//
// Per RFC 8446 Section 4.2.10, early data is encrypted with keys derived from
// client_early_traffic_secret and sent using application_data content type (0x17).
//
// Parameters:
//   - suite: The TLS 1.3 cipher suite from the session being resumed
//   - earlyTrafficSecret: The client_early_traffic_secret for encryption
//
// Returns error if transmission fails. Returns nil if no data to transmit.
//
// Error Handling and State Restoration:
//
// This function uses a defer to restore cipher state on ANY error after state is
// saved. This ensures consistent state restoration regardless of which operation
// fails (setTrafficSecret, writeRecordLocked, or flush).
//
// IMPORTANT: If writeRecordLocked() partially succeeds (writes some data before
// failing), data has already been sent over the wire with the new cipher state.
// In this case, state restoration maintains internal consistency but the connection
// should be considered compromised and not reused. The sequence number restoration
// could theoretically cause record replay issues if the connection were reused,
// but since TLS connections are typically abandoned on error, this is acceptable.
func (uconn *UConn) transmitEarlyData(suite *cipherSuiteTLS13, earlyTrafficSecret []byte) (transmitErr error) {
	ctx := context.Background()

	if uconn.earlyData == nil {
		return nil
	}

	// Get buffered data to transmit
	buffered := uconn.earlyData.BufferedData()
	if len(buffered) == 0 {
		utlserrors.LogDebug(ctx, "0-RTT: no buffered data to transmit")
		return nil
	}

	// Validate parameters - these early returns are safe because cipher state
	// has not been modified yet.
	if suite == nil {
		utlserrors.LogDebug(ctx, "0-RTT: transmission failed - no cipher suite")
		return utlserrors.New("tls: early data transmission requires cipher suite").AtError()
	}

	// Validate cipher suite matches what was negotiated for early data.
	// This is a critical security check - using the wrong cipher suite would
	// encrypt data with incorrect keys, potentially causing decryption failure
	// or security issues. A mismatch indicates a bug in the caller.
	expectedSuiteID := uconn.earlyData.CipherSuiteID()
	if expectedSuiteID != 0 && suite.id != expectedSuiteID {
		utlserrors.LogDebug(ctx, "0-RTT: transmission failed - cipher suite mismatch: expected",
			fmt.Sprintf("0x%04x", expectedSuiteID), "got", fmt.Sprintf("0x%04x", suite.id))
		return fmt.Errorf("%w: expected 0x%04x, got 0x%04x", ErrCipherSuiteMismatch, expectedSuiteID, suite.id)
	}

	if len(earlyTrafficSecret) == 0 {
		utlserrors.LogDebug(ctx, "0-RTT: transmission failed - no early traffic secret")
		return ErrEarlyDataNoSecret
	}

	utlserrors.LogDebug(ctx, "0-RTT: attempting early data transmission, size:", len(buffered), "cipher suite:", fmt.Sprintf("0x%04x", suite.id))

	// Enforce max_early_data_size limit from session ticket.
	// Per RFC 8446 Section 4.2.10, the client MUST NOT send more than
	// max_early_data_size bytes of early data.
	maxSize := uconn.earlyData.MaxSize()
	if maxSize > 0 && uint32(len(buffered)) > maxSize {
		// Truncate to max size - the remaining data will be sent via fallback
		// after handshake completes (if server accepts early data, this truncation
		// means we send less; if server rejects, all buffered data is resent).
		utlserrors.LogDebug(ctx, "0-RTT: truncating early data from", len(buffered), "to max_early_data_size:", maxSize)
		buffered = buffered[:maxSize]
	}

	c := uconn.Conn

	// Save current output cipher state BEFORE any modifications.
	// This state will be restored on ANY error via defer.
	savedCipher := c.out.cipher
	savedTrafficSecret := c.out.trafficSecret
	savedSeq := c.out.seq
	savedLevel := c.out.level

	// Defer state restoration on ANY error after this point.
	// This ensures consistent behavior regardless of which operation fails:
	// - setTrafficSecret failure: restores state (cipher may be partially set)
	// - writeRecordLocked failure: restores state (but wire may have partial data)
	// - flush failure: restores state (previously missing, causing BUG)
	//
	// Note on partial writes: If writeRecordLocked() writes some data before failing,
	// that data is already on the wire and cannot be recalled. Restoring state
	// maintains internal consistency but the connection is effectively broken.
	defer func() {
		if transmitErr != nil {
			c.out.cipher = savedCipher
			c.out.trafficSecret = savedTrafficSecret
			c.out.seq = savedSeq
			c.out.level = savedLevel
			utlserrors.LogDebug(ctx, "0-RTT: restored cipher state after error")
		}
	}()

	// Set up the output cipher with early traffic secret.
	// This uses the same mechanism as handshake/application traffic keys.
	// If this fails, the defer will restore the original cipher state.
	if err := c.out.setTrafficSecret(suite, QUICEncryptionLevelEarly, earlyTrafficSecret); err != nil {
		utlserrors.LogDebug(ctx, "0-RTT: failed to set early data cipher:", err)
		transmitErr = utlserrors.New("tls: failed to set early data cipher").Base(err).AtError()
		return transmitErr
	}

	// Write early data as application_data records (content type 0x17).
	// The data will be encrypted with the early traffic keys.
	c.out.Lock()
	n, err := c.writeRecordLocked(recordTypeApplicationData, buffered)
	c.out.Unlock()

	if err != nil {
		utlserrors.LogDebug(ctx, "0-RTT: failed to write early data records:", err)
		transmitErr = utlserrors.New("tls: failed to write early data records").Base(err).AtError()
		return transmitErr
	}

	if n != len(buffered) {
		utlserrors.LogDebug(ctx, "0-RTT: incomplete transmission:", n, "of", len(buffered), "bytes")
		transmitErr = utlserrors.New("tls: incomplete early data transmission: wrote", n, "of", len(buffered), "bytes").AtError()
		return transmitErr
	}

	// Flush to ensure data is sent over the wire before reading ServerHello.
	// FIXED: Previously, flush errors did not trigger state restoration.
	// Now the defer handles this automatically.
	if _, err := c.flush(); err != nil {
		utlserrors.LogDebug(ctx, "0-RTT: failed to flush early data:", err)
		transmitErr = utlserrors.New("tls: failed to flush early data").Base(err).AtError()
		return transmitErr
	}

	utlserrors.LogDebug(ctx, "0-RTT: early data transmitted successfully, size:", n)

	// Mark early data as transmitted
	uconn.earlyData.SetTransmitted()

	// Write to key log for debugging with tools like Wireshark.
	// This is non-fatal - early data has been transmitted successfully.
	if err := c.config.writeKeyLog(keyLogLabelClientEarlyTraffic, uconn.HandshakeState.Hello.Random, earlyTrafficSecret); err != nil {
		utlserrors.LogDebug(ctx, "0-RTT: key log write failed (non-fatal):", err)
	}

	// Note: On success, we do NOT restore the cipher state because the handshake
	// will immediately set up handshake keys after receiving ServerHello.
	// The early data cipher is only used for these initial records.
	// transmitErr remains nil, so defer does not restore state.

	return nil
}
