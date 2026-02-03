// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// HandshakePhase identifies a specific phase of the TLS handshake.
// These phases correspond to distinct I/O operations during the handshake
// and can have individual timeout configurations.
type HandshakePhase int

const (
	// PhaseClientHello is the phase where the client sends ClientHello.
	PhaseClientHello HandshakePhase = iota
	// PhaseServerHello is the phase waiting for ServerHello response.
	PhaseServerHello
	// PhaseCertificate is the phase for certificate exchange.
	PhaseCertificate
	// PhaseKeyExchange is the phase for key exchange operations.
	PhaseKeyExchange
	// PhaseFinished is the phase for Finished message exchange.
	PhaseFinished
	// PhaseComplete indicates handshake is complete.
	PhaseComplete
)

// String returns a human-readable name for the handshake phase.
func (p HandshakePhase) String() string {
	switch p {
	case PhaseClientHello:
		return "ClientHello"
	case PhaseServerHello:
		return "ServerHello"
	case PhaseCertificate:
		return "Certificate"
	case PhaseKeyExchange:
		return "KeyExchange"
	case PhaseFinished:
		return "Finished"
	case PhaseComplete:
		return "Complete"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}

// HandshakeTimeouts configures per-phase timeouts for the TLS handshake.
// Each phase can have its own timeout, allowing fine-grained control over
// handshake timing. A zero value for any timeout means use the overall
// handshake timeout for that phase.
type HandshakeTimeouts struct {
	// Overall is the total handshake timeout. This is the maximum time
	// allowed for the entire handshake to complete. If zero, no overall
	// timeout is applied (relies on context deadline or per-phase timeouts).
	Overall time.Duration

	// ClientHello is the timeout for sending the ClientHello message.
	// This includes the time to serialize and write the message.
	ClientHello time.Duration

	// ServerResponse is the timeout for receiving the ServerHello message.
	// This is typically the longest wait as it includes network round-trip.
	ServerResponse time.Duration

	// Certificate is the timeout for certificate exchange phase.
	// This includes receiving server certificates and sending client
	// certificate if requested.
	Certificate time.Duration

	// KeyExchange is the timeout for key exchange operations.
	// This covers ServerKeyExchange and ClientKeyExchange messages.
	KeyExchange time.Duration

	// Finished is the timeout for Finished message exchange.
	// This is the final phase of the handshake.
	Finished time.Duration

	// AlertSendTimeout is the timeout for sending an alert before closing
	// on timeout. If zero, defaults to 500ms. Set to -1 to skip alert sending.
	AlertSendTimeout time.Duration
}

// DefaultHandshakeTimeouts returns sensible default timeout values for a
// TLS handshake. These values are tuned for typical internet conditions:
//   - Overall: 30s (generous for high-latency connections)
//   - ClientHello: 5s (local operation, should be fast)
//   - ServerResponse: 15s (includes network round-trip)
//   - Certificate: 10s (certificate chains can be large)
//   - KeyExchange: 5s (cryptographic operations)
//   - Finished: 5s (final round-trip)
func DefaultHandshakeTimeouts() *HandshakeTimeouts {
	return &HandshakeTimeouts{
		Overall:          30 * time.Second,
		ClientHello:      5 * time.Second,
		ServerResponse:   15 * time.Second,
		Certificate:      10 * time.Second,
		KeyExchange:      5 * time.Second,
		Finished:         5 * time.Second,
		AlertSendTimeout: 500 * time.Millisecond,
	}
}

// FastHandshakeTimeouts returns aggressive timeout values suitable for
// low-latency networks or when fast failure is preferred.
func FastHandshakeTimeouts() *HandshakeTimeouts {
	return &HandshakeTimeouts{
		Overall:          10 * time.Second,
		ClientHello:      2 * time.Second,
		ServerResponse:   5 * time.Second,
		Certificate:      3 * time.Second,
		KeyExchange:      2 * time.Second,
		Finished:         2 * time.Second,
		AlertSendTimeout: 200 * time.Millisecond,
	}
}

// Clone returns a deep copy of the HandshakeTimeouts.
func (t *HandshakeTimeouts) Clone() *HandshakeTimeouts {
	if t == nil {
		return nil
	}
	return &HandshakeTimeouts{
		Overall:          t.Overall,
		ClientHello:      t.ClientHello,
		ServerResponse:   t.ServerResponse,
		Certificate:      t.Certificate,
		KeyExchange:      t.KeyExchange,
		Finished:         t.Finished,
		AlertSendTimeout: t.AlertSendTimeout,
	}
}

// getPhaseTimeout returns the timeout for a specific phase.
// If the phase-specific timeout is zero, returns the overall timeout.
func (t *HandshakeTimeouts) getPhaseTimeout(phase HandshakePhase) time.Duration {
	if t == nil {
		return 0
	}
	var phaseTimeout time.Duration
	switch phase {
	case PhaseClientHello:
		phaseTimeout = t.ClientHello
	case PhaseServerHello:
		phaseTimeout = t.ServerResponse
	case PhaseCertificate:
		phaseTimeout = t.Certificate
	case PhaseKeyExchange:
		phaseTimeout = t.KeyExchange
	case PhaseFinished:
		phaseTimeout = t.Finished
	default:
		phaseTimeout = 0
	}
	if phaseTimeout > 0 {
		return phaseTimeout
	}
	return t.Overall
}

// getAlertSendTimeout returns the timeout for sending alerts.
// Defaults to 500ms if not set. Returns 0 if set to -1 (disabled).
func (t *HandshakeTimeouts) getAlertSendTimeout() time.Duration {
	if t == nil {
		return 500 * time.Millisecond
	}
	if t.AlertSendTimeout < 0 {
		return 0 // Disabled
	}
	if t.AlertSendTimeout == 0 {
		return 500 * time.Millisecond
	}
	return t.AlertSendTimeout
}

// HandshakeTimeoutError is returned when a handshake phase times out.
// It provides detailed information about which phase timed out and the
// configured timeout value.
type HandshakeTimeoutError struct {
	// Phase indicates which handshake phase timed out.
	Phase HandshakePhase

	// ConfiguredTimeout is the configured timeout value that was exceeded.
	ConfiguredTimeout time.Duration

	// Elapsed is the actual time spent before timeout.
	Elapsed time.Duration

	// AlertSent indicates whether a timeout alert was successfully sent
	// to the peer before closing the connection.
	AlertSent bool

	// Cause is the underlying error (typically context.DeadlineExceeded).
	Cause error
}

// Error implements the error interface.
func (e *HandshakeTimeoutError) Error() string {
	alertStatus := ""
	if e.AlertSent {
		alertStatus = ", alert sent"
	}
	return fmt.Sprintf("tls: handshake timeout in %s phase after %v (timeout: %v%s)",
		e.Phase, e.Elapsed.Round(time.Millisecond), e.ConfiguredTimeout, alertStatus)
}

// Unwrap returns the underlying cause for errors.Is/As support.
func (e *HandshakeTimeoutError) Unwrap() error {
	return e.Cause
}

// IsTimeout returns true, implementing the net.Error interface.
func (e *HandshakeTimeoutError) Timeout() bool {
	return true
}

// Temporary returns false; timeout errors should be retried with
// a new connection.
func (e *HandshakeTimeoutError) Temporary() bool {
	return false
}

// HandshakeProgressCallback is called to report handshake progress.
// It can be used to implement progress indicators or logging for
// long handshakes.
type HandshakeProgressCallback func(phase HandshakePhase, elapsed time.Duration)

// handshakeTimeoutController manages per-phase timeouts and progress
// reporting during a TLS handshake. It is created for each handshake
// and coordinates timeout enforcement with graceful error handling.
type handshakeTimeoutController struct {
	// Configuration
	timeouts         *HandshakeTimeouts
	progressCallback HandshakeProgressCallback
	baseCtx          context.Context

	// State (protected by mu)
	mu           sync.Mutex
	currentPhase HandshakePhase
	phaseStart   time.Time
	handshakeStart time.Time
	phaseCancel  context.CancelFunc
	phaseDone    chan struct{}

	// Error state (atomic for lock-free reads)
	timedOut atomic.Bool

	// Connection reference for alert sending
	conn *Conn
}

// newHandshakeTimeoutController creates a new timeout controller.
func newHandshakeTimeoutController(ctx context.Context, timeouts *HandshakeTimeouts, conn *Conn) *handshakeTimeoutController {
	return &handshakeTimeoutController{
		timeouts:       timeouts,
		baseCtx:        ctx,
		currentPhase:   PhaseClientHello,
		handshakeStart: time.Now(),
		phaseStart:     time.Now(),
		conn:           conn,
	}
}

// setProgressCallback sets the callback for progress reporting.
func (c *handshakeTimeoutController) setProgressCallback(cb HandshakeProgressCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.progressCallback = cb
}

// enterPhase transitions to a new handshake phase with its timeout.
// Returns a context that will be canceled when the phase times out.
func (c *handshakeTimeoutController) enterPhase(phase HandshakePhase) (context.Context, error) {
	c.mu.Lock()

	// Cancel previous phase timer if any
	if c.phaseCancel != nil {
		c.phaseCancel()
		c.phaseCancel = nil
	}

	// Check if base context is already canceled
	select {
	case <-c.baseCtx.Done():
		c.mu.Unlock()
		return nil, c.baseCtx.Err()
	default:
	}

	// Capture callback and handshake start time before releasing lock.
	// This prevents deadlock if the callback calls methods that acquire c.mu.
	callback := c.progressCallback
	handshakeStart := c.handshakeStart

	// Release lock before calling user-provided callback to prevent deadlock
	c.mu.Unlock()

	// Record phase transition time and call progress callback outside of lock
	now := time.Now()
	if callback != nil {
		elapsed := now.Sub(handshakeStart)
		callback(phase, elapsed)
	}

	// Re-acquire lock for state updates
	c.mu.Lock()
	defer c.mu.Unlock()

	c.currentPhase = phase
	c.phaseStart = now

	// Get timeout for this phase
	timeout := c.timeouts.getPhaseTimeout(phase)
	if timeout <= 0 {
		// No timeout for this phase, use base context
		return c.baseCtx, nil
	}

	// Create phase-specific context with timeout
	phaseCtx, cancel := context.WithTimeout(c.baseCtx, timeout)
	c.phaseCancel = cancel
	c.phaseDone = make(chan struct{})

	return phaseCtx, nil
}

// checkPhaseTimeout checks if the current phase has timed out.
// If so, it attempts to send an alert and returns a HandshakeTimeoutError.
func (c *handshakeTimeoutController) checkPhaseTimeout(err error) error {
	if err == nil {
		return nil
	}

	// Check if this is a timeout error
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return err
	}

	c.mu.Lock()
	phase := c.currentPhase
	phaseStart := c.phaseStart
	timeout := c.timeouts.getPhaseTimeout(phase)
	alertTimeout := c.timeouts.getAlertSendTimeout()
	conn := c.conn
	c.mu.Unlock()

	elapsed := time.Since(phaseStart)

	// Mark as timed out
	c.timedOut.Store(true)

	// Try to send alert before closing
	alertSent := false
	if alertTimeout > 0 && conn != nil {
		alertSent = c.trySendAlert(conn, alertTimeout)
	}

	// Call observability hook for timeout error
	remoteAddr := ""
	if conn != nil && conn.conn != nil {
		if addr := conn.conn.RemoteAddr(); addr != nil {
			remoteAddr = addr.String()
		}
	}
	callOnTimeoutError(remoteAddr)

	return &HandshakeTimeoutError{
		Phase:             phase,
		ConfiguredTimeout: timeout,
		Elapsed:           elapsed,
		AlertSent:         alertSent,
		Cause:             err,
	}
}

// trySendAlert attempts to send a user_canceled alert to the peer.
// Returns true if the alert was successfully sent.
func (c *handshakeTimeoutController) trySendAlert(conn *Conn, timeout time.Duration) bool {
	// Create a short timeout context for sending the alert
	alertCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Set deadline on the underlying connection if possible.
	// This deadline is what actually interrupts the sendAlert call.
	if conn.conn != nil {
		deadline := time.Now().Add(timeout)
		_ = conn.conn.SetWriteDeadline(deadline)
	}

	// Channel to signal completion - buffered to prevent goroutine leak
	done := make(chan bool, 1)

	go func() {
		// Try to send user_canceled alert (0x5A = 90)
		// This is the appropriate alert for timeout/cancellation scenarios.
		// The write deadline on the connection ensures this won't block forever.
		err := conn.sendAlert(alertUserCanceled)
		done <- (err == nil)
	}()

	// Wait for either completion or timeout
	var success bool
	select {
	case success = <-done:
		// Goroutine completed normally
	case <-alertCtx.Done():
		// Context timed out - the goroutine will still complete because
		// the write deadline on the connection will cause sendAlert to fail.
		// Wait for the goroutine to finish to prevent leak.
		success = <-done
	}

	// Clear the write deadline only after the goroutine has completed
	if conn.conn != nil {
		_ = conn.conn.SetWriteDeadline(time.Time{})
	}

	return success
}

// elapsed returns the total time elapsed since handshake started.
func (c *handshakeTimeoutController) elapsed() time.Duration {
	c.mu.Lock()
	start := c.handshakeStart
	c.mu.Unlock()
	return time.Since(start)
}

// cleanup releases resources held by the controller.
func (c *handshakeTimeoutController) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.phaseCancel != nil {
		c.phaseCancel()
		c.phaseCancel = nil
	}
}

// IsHandshakeTimeoutError returns true if err is a HandshakeTimeoutError.
func IsHandshakeTimeoutError(err error) bool {
	var hte *HandshakeTimeoutError
	return errors.As(err, &hte)
}

// GetHandshakeTimeoutPhase returns the phase that timed out, or -1 if
// the error is not a HandshakeTimeoutError.
func GetHandshakeTimeoutPhase(err error) HandshakePhase {
	var hte *HandshakeTimeoutError
	if errors.As(err, &hte) {
		return hte.Phase
	}
	return -1
}

// phaseContextKey is a context key for storing phase information.
type phaseContextKey struct{}

// withPhase adds phase information to a context.
func withPhase(ctx context.Context, phase HandshakePhase) context.Context {
	return context.WithValue(ctx, phaseContextKey{}, phase)
}

// getPhase extracts phase information from a context.
func getPhase(ctx context.Context) (HandshakePhase, bool) {
	phase, ok := ctx.Value(phaseContextKey{}).(HandshakePhase)
	return phase, ok
}
