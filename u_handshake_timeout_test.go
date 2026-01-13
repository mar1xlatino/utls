// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"testing"
	"time"
)

// =============================================================================
// HandshakeTimeouts Tests
// =============================================================================

func TestDefaultHandshakeTimeouts(t *testing.T) {
	timeouts := DefaultHandshakeTimeouts()
	if timeouts == nil {
		t.Fatal("DefaultHandshakeTimeouts() returned nil")
	}

	// Verify expected default values
	if timeouts.Overall != 30*time.Second {
		t.Errorf("Overall timeout = %v, want %v", timeouts.Overall, 30*time.Second)
	}
	if timeouts.ClientHello != 5*time.Second {
		t.Errorf("ClientHello timeout = %v, want %v", timeouts.ClientHello, 5*time.Second)
	}
	if timeouts.ServerResponse != 15*time.Second {
		t.Errorf("ServerResponse timeout = %v, want %v", timeouts.ServerResponse, 15*time.Second)
	}
	if timeouts.Certificate != 10*time.Second {
		t.Errorf("Certificate timeout = %v, want %v", timeouts.Certificate, 10*time.Second)
	}
	if timeouts.KeyExchange != 5*time.Second {
		t.Errorf("KeyExchange timeout = %v, want %v", timeouts.KeyExchange, 5*time.Second)
	}
	if timeouts.Finished != 5*time.Second {
		t.Errorf("Finished timeout = %v, want %v", timeouts.Finished, 5*time.Second)
	}
	if timeouts.AlertSendTimeout != 500*time.Millisecond {
		t.Errorf("AlertSendTimeout = %v, want %v", timeouts.AlertSendTimeout, 500*time.Millisecond)
	}
}

func TestFastHandshakeTimeouts(t *testing.T) {
	timeouts := FastHandshakeTimeouts()
	if timeouts == nil {
		t.Fatal("FastHandshakeTimeouts() returned nil")
	}

	// Verify fast defaults are shorter than regular defaults
	defaultTimeouts := DefaultHandshakeTimeouts()
	if timeouts.Overall >= defaultTimeouts.Overall {
		t.Errorf("Fast Overall timeout should be less than default")
	}
	if timeouts.ServerResponse >= defaultTimeouts.ServerResponse {
		t.Errorf("Fast ServerResponse timeout should be less than default")
	}
}

func TestHandshakeTimeoutsClone(t *testing.T) {
	original := &HandshakeTimeouts{
		Overall:          10 * time.Second,
		ClientHello:      2 * time.Second,
		ServerResponse:   5 * time.Second,
		Certificate:      3 * time.Second,
		KeyExchange:      2 * time.Second,
		Finished:         2 * time.Second,
		AlertSendTimeout: 200 * time.Millisecond,
	}

	clone := original.Clone()
	if clone == nil {
		t.Fatal("Clone() returned nil")
	}

	// Verify clone has same values
	if clone.Overall != original.Overall {
		t.Errorf("Clone Overall = %v, want %v", clone.Overall, original.Overall)
	}
	if clone.ServerResponse != original.ServerResponse {
		t.Errorf("Clone ServerResponse = %v, want %v", clone.ServerResponse, original.ServerResponse)
	}

	// Verify clone is a separate copy
	clone.Overall = 100 * time.Second
	if original.Overall == clone.Overall {
		t.Error("Clone should be a separate copy")
	}
}

func TestHandshakeTimeoutsCloneNil(t *testing.T) {
	var timeouts *HandshakeTimeouts
	clone := timeouts.Clone()
	if clone != nil {
		t.Error("Clone of nil should return nil")
	}
}

func TestGetPhaseTimeout(t *testing.T) {
	timeouts := &HandshakeTimeouts{
		Overall:        30 * time.Second,
		ClientHello:    5 * time.Second,
		ServerResponse: 15 * time.Second,
		Certificate:    10 * time.Second,
		KeyExchange:    0, // Should fall back to Overall
		Finished:       5 * time.Second,
	}

	tests := []struct {
		phase    HandshakePhase
		expected time.Duration
	}{
		{PhaseClientHello, 5 * time.Second},
		{PhaseServerHello, 15 * time.Second},
		{PhaseCertificate, 10 * time.Second},
		{PhaseKeyExchange, 30 * time.Second}, // Falls back to Overall
		{PhaseFinished, 5 * time.Second},
		{PhaseComplete, 30 * time.Second}, // Unknown phase falls back to Overall
	}

	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			got := timeouts.getPhaseTimeout(tt.phase)
			if got != tt.expected {
				t.Errorf("getPhaseTimeout(%v) = %v, want %v", tt.phase, got, tt.expected)
			}
		})
	}
}

func TestGetAlertSendTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeout  *HandshakeTimeouts
		expected time.Duration
	}{
		{
			name:     "nil_timeouts",
			timeout:  nil,
			expected: 500 * time.Millisecond,
		},
		{
			name:     "zero_value",
			timeout:  &HandshakeTimeouts{},
			expected: 500 * time.Millisecond,
		},
		{
			name:     "custom_value",
			timeout:  &HandshakeTimeouts{AlertSendTimeout: 200 * time.Millisecond},
			expected: 200 * time.Millisecond,
		},
		{
			name:     "disabled",
			timeout:  &HandshakeTimeouts{AlertSendTimeout: -1},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.timeout.getAlertSendTimeout()
			if got != tt.expected {
				t.Errorf("getAlertSendTimeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// HandshakePhase Tests
// =============================================================================

func TestHandshakePhaseString(t *testing.T) {
	tests := []struct {
		phase    HandshakePhase
		expected string
	}{
		{PhaseClientHello, "ClientHello"},
		{PhaseServerHello, "ServerHello"},
		{PhaseCertificate, "Certificate"},
		{PhaseKeyExchange, "KeyExchange"},
		{PhaseFinished, "Finished"},
		{PhaseComplete, "Complete"},
		{HandshakePhase(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.phase.String()
			if got != tt.expected {
				t.Errorf("String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// HandshakeTimeoutError Tests
// =============================================================================

func TestHandshakeTimeoutError(t *testing.T) {
	cause := context.DeadlineExceeded
	err := &HandshakeTimeoutError{
		Phase:             PhaseServerHello,
		ConfiguredTimeout: 15 * time.Second,
		Elapsed:           16500 * time.Millisecond,
		AlertSent:         true,
		Cause:             cause,
	}

	// Test error message
	msg := err.Error()
	if msg == "" {
		t.Error("Error() returned empty string")
	}
	if !containsSubstring(msg, "ServerHello") {
		t.Error("Error message should contain phase name")
	}
	if !containsSubstring(msg, "alert sent") {
		t.Error("Error message should indicate alert was sent")
	}

	// Test Unwrap
	if !errors.Is(err, cause) {
		t.Error("errors.Is should find cause through Unwrap")
	}

	// Test Timeout method
	if !err.Timeout() {
		t.Error("Timeout() should return true")
	}

	// Test Temporary method
	if err.Temporary() {
		t.Error("Temporary() should return false")
	}
}

func TestHandshakeTimeoutErrorNoAlert(t *testing.T) {
	err := &HandshakeTimeoutError{
		Phase:             PhaseClientHello,
		ConfiguredTimeout: 5 * time.Second,
		Elapsed:           5500 * time.Millisecond,
		AlertSent:         false,
		Cause:             context.DeadlineExceeded,
	}

	msg := err.Error()
	if containsSubstring(msg, "alert sent") {
		t.Error("Error message should not contain 'alert sent' when AlertSent is false")
	}
}

// =============================================================================
// IsHandshakeTimeoutError Tests
// =============================================================================

func TestIsHandshakeTimeoutError(t *testing.T) {
	timeoutErr := &HandshakeTimeoutError{
		Phase:             PhaseServerHello,
		ConfiguredTimeout: 15 * time.Second,
		Elapsed:           16 * time.Second,
		Cause:             context.DeadlineExceeded,
	}

	if !IsHandshakeTimeoutError(timeoutErr) {
		t.Error("IsHandshakeTimeoutError should return true for HandshakeTimeoutError")
	}

	if IsHandshakeTimeoutError(errors.New("not a timeout error")) {
		t.Error("IsHandshakeTimeoutError should return false for non-timeout errors")
	}

	if IsHandshakeTimeoutError(nil) {
		t.Error("IsHandshakeTimeoutError should return false for nil")
	}
}

func TestGetHandshakeTimeoutPhase(t *testing.T) {
	timeoutErr := &HandshakeTimeoutError{
		Phase:             PhaseServerHello,
		ConfiguredTimeout: 15 * time.Second,
		Elapsed:           16 * time.Second,
		Cause:             context.DeadlineExceeded,
	}

	if GetHandshakeTimeoutPhase(timeoutErr) != PhaseServerHello {
		t.Error("GetHandshakeTimeoutPhase should return the phase from the error")
	}

	if GetHandshakeTimeoutPhase(errors.New("not a timeout error")) != -1 {
		t.Error("GetHandshakeTimeoutPhase should return -1 for non-timeout errors")
	}
}

// =============================================================================
// handshakeTimeoutController Tests
// =============================================================================

func TestHandshakeTimeoutControllerCreation(t *testing.T) {
	ctx := context.Background()
	timeouts := DefaultHandshakeTimeouts()

	ctrl := newHandshakeTimeoutController(ctx, timeouts, nil)
	if ctrl == nil {
		t.Fatal("newHandshakeTimeoutController returned nil")
	}

	if ctrl.currentPhase != PhaseClientHello {
		t.Errorf("Initial phase = %v, want %v", ctrl.currentPhase, PhaseClientHello)
	}

	ctrl.cleanup()
}

func TestHandshakeTimeoutControllerEnterPhase(t *testing.T) {
	ctx := context.Background()
	timeouts := &HandshakeTimeouts{
		Overall:        30 * time.Second,
		ServerResponse: 5 * time.Second,
	}

	ctrl := newHandshakeTimeoutController(ctx, timeouts, nil)
	defer ctrl.cleanup()

	// Enter ServerHello phase
	phaseCtx, err := ctrl.enterPhase(PhaseServerHello)
	if err != nil {
		t.Fatalf("enterPhase failed: %v", err)
	}
	if phaseCtx == nil {
		t.Fatal("enterPhase returned nil context")
	}

	// Verify current phase is updated
	ctrl.mu.Lock()
	currentPhase := ctrl.currentPhase
	ctrl.mu.Unlock()

	if currentPhase != PhaseServerHello {
		t.Errorf("currentPhase = %v, want %v", currentPhase, PhaseServerHello)
	}
}

func TestHandshakeTimeoutControllerProgressCallback(t *testing.T) {
	ctx := context.Background()
	timeouts := DefaultHandshakeTimeouts()

	var callbackCalls []HandshakePhase
	callback := func(phase HandshakePhase, elapsed time.Duration) {
		callbackCalls = append(callbackCalls, phase)
	}

	ctrl := newHandshakeTimeoutController(ctx, timeouts, nil)
	ctrl.setProgressCallback(callback)
	defer ctrl.cleanup()

	// Enter phases
	_, _ = ctrl.enterPhase(PhaseServerHello)
	_, _ = ctrl.enterPhase(PhaseCertificate)
	_, _ = ctrl.enterPhase(PhaseFinished)

	// Verify callback was called
	if len(callbackCalls) != 3 {
		t.Errorf("Callback called %d times, want 3", len(callbackCalls))
	}

	expectedPhases := []HandshakePhase{PhaseServerHello, PhaseCertificate, PhaseFinished}
	for i, expected := range expectedPhases {
		if i < len(callbackCalls) && callbackCalls[i] != expected {
			t.Errorf("Callback phase %d = %v, want %v", i, callbackCalls[i], expected)
		}
	}
}

func TestHandshakeTimeoutControllerElapsed(t *testing.T) {
	ctx := context.Background()
	timeouts := DefaultHandshakeTimeouts()

	ctrl := newHandshakeTimeoutController(ctx, timeouts, nil)
	defer ctrl.cleanup()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	elapsed := ctrl.elapsed()
	if elapsed < 10*time.Millisecond {
		t.Errorf("elapsed() = %v, want >= 10ms", elapsed)
	}
}

func TestHandshakeTimeoutControllerCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	timeouts := DefaultHandshakeTimeouts()
	ctrl := newHandshakeTimeoutController(ctx, timeouts, nil)
	defer ctrl.cleanup()

	// Entering phase with canceled context should return error
	_, err := ctrl.enterPhase(PhaseServerHello)
	if err == nil {
		t.Error("enterPhase with canceled context should return error")
	}
}

func TestHandshakeTimeoutControllerCheckTimeout(t *testing.T) {
	ctx := context.Background()
	timeouts := &HandshakeTimeouts{
		Overall:        30 * time.Second,
		ServerResponse: 5 * time.Second,
	}

	ctrl := newHandshakeTimeoutController(ctx, timeouts, nil)
	defer ctrl.cleanup()

	// Enter a phase
	_, _ = ctrl.enterPhase(PhaseServerHello)

	// Check non-timeout error - should pass through unchanged
	normalErr := errors.New("some error")
	result := ctrl.checkPhaseTimeout(normalErr)
	if result != normalErr {
		t.Error("Non-timeout error should pass through unchanged")
	}

	// Check nil error - should return nil
	result = ctrl.checkPhaseTimeout(nil)
	if result != nil {
		t.Error("nil error should return nil")
	}

	// Check deadline exceeded - should return HandshakeTimeoutError
	result = ctrl.checkPhaseTimeout(context.DeadlineExceeded)
	var hte *HandshakeTimeoutError
	if !errors.As(result, &hte) {
		t.Fatal("Deadline exceeded should be wrapped in HandshakeTimeoutError")
	}
	if hte.Phase != PhaseServerHello {
		t.Errorf("Error phase = %v, want %v", hte.Phase, PhaseServerHello)
	}
}

// =============================================================================
// UConn Methods Tests
// =============================================================================

func TestUConnSetHandshakeTimeouts(t *testing.T) {
	// Create a UConn with mock connection
	uconn := &UConn{
		Conn: &Conn{},
	}

	// Set timeouts
	timeouts := DefaultHandshakeTimeouts()
	uconn.SetHandshakeTimeouts(timeouts)

	// Verify timeouts are set
	got := uconn.HandshakeTimeouts()
	if got == nil {
		t.Fatal("HandshakeTimeouts() returned nil")
	}
	if got.Overall != timeouts.Overall {
		t.Errorf("Overall = %v, want %v", got.Overall, timeouts.Overall)
	}

	// Verify it's a clone
	got.Overall = 100 * time.Second
	stored := uconn.handshakeTimeouts
	if stored.Overall == got.Overall {
		t.Error("HandshakeTimeouts() should return a clone")
	}
}

func TestUConnSetHandshakeTimeoutsNil(t *testing.T) {
	uconn := &UConn{
		Conn: &Conn{},
	}

	// Set to non-nil first
	uconn.SetHandshakeTimeouts(DefaultHandshakeTimeouts())

	// Set to nil
	uconn.SetHandshakeTimeouts(nil)

	got := uconn.HandshakeTimeouts()
	if got != nil {
		t.Error("Setting nil should clear timeouts")
	}
}

func TestUConnSetHandshakeProgressCallback(t *testing.T) {
	uconn := &UConn{
		Conn: &Conn{},
	}

	// Set callback
	called := false
	cb := func(phase HandshakePhase, elapsed time.Duration) {
		called = true
	}
	uconn.SetHandshakeProgressCallback(cb)

	// Verify callback is set
	got := uconn.HandshakeProgressCallback()
	if got == nil {
		t.Fatal("HandshakeProgressCallback() returned nil")
	}

	// Call it to verify it works
	got(PhaseServerHello, time.Second)
	if !called {
		t.Error("Callback was not invoked")
	}
}

func TestUConnEnterHandshakePhaseNoController(t *testing.T) {
	uconn := &UConn{
		Conn: &Conn{},
	}

	// Without timeout controller, should return background context
	ctx, err := uconn.enterHandshakePhase(PhaseServerHello)
	if err != nil {
		t.Fatalf("enterHandshakePhase failed: %v", err)
	}
	if ctx == nil {
		t.Fatal("enterHandshakePhase returned nil context")
	}
}

func TestUConnCheckHandshakePhaseTimeoutNoController(t *testing.T) {
	uconn := &UConn{
		Conn: &Conn{},
	}

	// Without timeout controller, errors pass through unchanged
	testErr := errors.New("test error")
	result := uconn.checkHandshakePhaseTimeout(testErr)
	if result != testErr {
		t.Error("Error should pass through unchanged without controller")
	}

	// nil should return nil
	result = uconn.checkHandshakePhaseTimeout(nil)
	if result != nil {
		t.Error("nil should return nil")
	}
}

func TestUConnHandshakeElapsedNoController(t *testing.T) {
	uconn := &UConn{
		Conn: &Conn{},
	}

	// Without timeout controller, should return 0
	elapsed := uconn.handshakeElapsed()
	if elapsed != 0 {
		t.Errorf("handshakeElapsed() = %v, want 0", elapsed)
	}
}

// =============================================================================
// Context Phase Helpers Tests
// =============================================================================

func TestWithPhaseAndGetPhase(t *testing.T) {
	ctx := context.Background()

	// Add phase to context
	ctxWithPhase := withPhase(ctx, PhaseServerHello)

	// Get phase back
	phase, ok := getPhase(ctxWithPhase)
	if !ok {
		t.Error("getPhase should return true for context with phase")
	}
	if phase != PhaseServerHello {
		t.Errorf("phase = %v, want %v", phase, PhaseServerHello)
	}
}

func TestGetPhaseNoPhase(t *testing.T) {
	ctx := context.Background()

	// Get phase from context without phase
	phase, ok := getPhase(ctx)
	if ok {
		t.Error("getPhase should return false for context without phase")
	}
	if phase != 0 {
		t.Errorf("phase should be zero value, got %v", phase)
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
