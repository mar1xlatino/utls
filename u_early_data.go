// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
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

// Disable disables early data.
func (e *EarlyDataState) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = false
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
func (e *EarlyDataState) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.enabled = false
	e.accepted = false
	e.rejected = false
	e.maxSize = 0
	e.written = 0
	e.buffer = nil
	e.trafficSecret = nil
}

// EarlyDataConfig configures 0-RTT early data behavior.
type EarlyDataConfig struct {
	// Enabled allows sending early data when resuming sessions.
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
}

// DefaultEarlyDataConfig returns default early data configuration.
func DefaultEarlyDataConfig() *EarlyDataConfig {
	return &EarlyDataConfig{
		Enabled:         false,
		MaxSize:         0,
		BufferForResend: true,
	}
}

// UConn early data methods are added below.
// These integrate with the existing UConn structure.

// WriteEarlyData sends 0-RTT early data before handshake completes.
// Returns ErrEarlyDataNotSupported if server doesn't support 0-RTT.
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

	// Check max size
	maxSize := uconn.earlyData.MaxSize()
	if maxSize > 0 {
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

// ErrEarlyDataNotImplemented indicates early data transmission is not yet implemented.
var ErrEarlyDataNotImplemented = errors.New("tls: early data transmission not yet implemented - data buffered for manual handling")

// writeEarlyDataInternal handles the actual early data record write.
// Currently returns an error as full implementation requires handshake integration.
// The data is buffered and can be retrieved via EarlyDataBufferedData() for manual handling.
func (uconn *UConn) writeEarlyDataInternal(data []byte) (int, error) {
	// NOTE: Full implementation requires:
	// 1. Setting up early data cipher from trafficSecret
	// 2. Creating proper TLS record with early data content type (0x17)
	// 3. Writing encrypted record to connection after ClientHello
	// 4. Integration with handshake_client_tls13.go
	//
	// For now, data is buffered in earlyData.buffer and callers should:
	// 1. Check EarlyDataBufferedData() after handshake
	// 2. If EarlyDataRejected(), resend via normal Write()
	// 3. If EarlyDataAccepted(), data was handled (when fully implemented)

	// Return error to make it clear this is not silently working
	// The data IS buffered via RecordWrite() called before this
	return len(data), ErrEarlyDataNotImplemented
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

// setEarlyDataAccepted is called internally when server accepts early data.
func (uconn *UConn) setEarlyDataAccepted() {
	if uconn.earlyData != nil {
		uconn.earlyData.SetAccepted()
	}
	// Note: Hook integration can be added via external FingerprintController
	// if the application needs to be notified of early data acceptance.
}

// setEarlyDataRejected is called internally when server rejects early data.
func (uconn *UConn) setEarlyDataRejected() {
	if uconn.earlyData != nil {
		uconn.earlyData.SetRejected()
	}
	// Note: Hook integration can be added via external FingerprintController
	// if the application needs to be notified of early data rejection.
}

// initEarlyDataFromSession initializes early data state from session.
func (uconn *UConn) initEarlyDataFromSession(session *SessionState) {
	if session == nil || !session.EarlyData {
		return
	}

	if uconn.earlyData == nil {
		uconn.earlyData = NewEarlyDataState()
	}

	// The max early data size comes from the session ticket
	// TrafficSecret will be derived during handshake from EarlySecret
	uconn.earlyData.mu.Lock()
	uconn.earlyData.enabled = true
	uconn.earlyData.mu.Unlock()
}

// setEarlyTrafficSecret sets the early traffic secret for encryption.
func (uconn *UConn) setEarlyTrafficSecret(secret []byte) {
	if uconn.earlyData == nil {
		uconn.earlyData = NewEarlyDataState()
	}

	uconn.earlyData.mu.Lock()
	uconn.earlyData.trafficSecret = make([]byte, len(secret))
	copy(uconn.earlyData.trafficSecret, secret)
	uconn.earlyData.mu.Unlock()
}
