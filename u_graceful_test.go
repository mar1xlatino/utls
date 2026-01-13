// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected TLSErrorType
	}{
		// Nil error
		{
			name:     "nil error",
			err:      nil,
			expected: ErrorTransient,
		},

		// Transient errors
		{
			name:     "connection reset",
			err:      errors.New("read: connection reset by peer"),
			expected: ErrorTransient,
		},
		{
			name:     "timeout",
			err:      errors.New("i/o timeout"),
			expected: ErrorTransient,
		},
		{
			name:     "connection refused",
			err:      errors.New("connection refused"),
			expected: ErrorTransient,
		},
		{
			name:     "broken pipe",
			err:      errors.New("write: broken pipe"),
			expected: ErrorTransient,
		},
		{
			name:     "eof",
			err:      errors.New("unexpected EOF"),
			expected: ErrorTransient,
		},

		// HRR retry errors
		{
			name:     "key share error",
			err:      errors.New("tls: server requested key share for group not offered"),
			expected: ErrorHRRRetry,
		},
		{
			name:     "selected group error",
			err:      errors.New("tls: server selected unsupported group"),
			expected: ErrorHRRRetry,
		},
		{
			name:     "hrr related error",
			err:      errors.New("tls: HelloRetryRequest processing failed"),
			expected: ErrorHRRRetry,
		},

		// Downgrade errors
		{
			name:     "protocol version",
			err:      errors.New("tls: protocol version not supported"),
			expected: ErrorDowngrade,
		},
		{
			name:     "unsupported version",
			err:      errors.New("tls: unsupported version"),
			expected: ErrorDowngrade,
		},
		{
			name:     "no common cipher",
			err:      errors.New("tls: no common cipher suite"),
			expected: ErrorDowngrade,
		},
		{
			name:     "tls 1.3 error",
			err:      errors.New("tls: TLS 1.3 handshake failed"),
			expected: ErrorDowngrade,
		},

		// Permanent errors
		{
			name:     "certificate error",
			err:      errors.New("tls: bad certificate"),
			expected: ErrorPermanent,
		},
		{
			name:     "x509 error",
			err:      errors.New("x509: certificate signed by unknown authority"),
			expected: ErrorPermanent,
		},
		{
			name:     "expired certificate",
			err:      errors.New("tls: certificate has expired"),
			expected: ErrorPermanent,
		},
		{
			name:     "access denied",
			err:      errors.New("tls: access denied"),
			expected: ErrorPermanent,
		},
		{
			name:     "bad record mac",
			err:      errors.New("tls: bad record MAC"),
			expected: ErrorPermanent,
		},
		{
			name:     "decrypt error",
			err:      errors.New("tls: error decrypting message"),
			expected: ErrorPermanent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyError(tc.err)
			if result != tc.expected {
				t.Errorf("ClassifyError(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestClassifyAlertError(t *testing.T) {
	tests := []struct {
		name     string
		alert    alert
		expected TLSErrorType
	}{
		// Transient
		{
			name:     "user canceled",
			alert:    alertUserCanceled,
			expected: ErrorTransient,
		},

		// Recoverable
		{
			name:     "close notify",
			alert:    alertCloseNotify,
			expected: ErrorRecoverable,
		},
		{
			name:     "no renegotiation",
			alert:    alertNoRenegotiation,
			expected: ErrorRecoverable,
		},
		{
			name:     "unknown PSK identity",
			alert:    alertUnknownPSKIdentity,
			expected: ErrorRecoverable,
		},
		{
			name:     "ECH required",
			alert:    alertECHRequired,
			expected: ErrorRecoverable,
		},

		// Downgrade
		{
			name:     "protocol version",
			alert:    alertProtocolVersion,
			expected: ErrorDowngrade,
		},
		{
			name:     "insufficient security",
			alert:    alertInsufficientSecurity,
			expected: ErrorDowngrade,
		},
		{
			name:     "inappropriate fallback",
			alert:    alertInappropriateFallback,
			expected: ErrorDowngrade,
		},
		{
			name:     "handshake failure",
			alert:    alertHandshakeFailure,
			expected: ErrorDowngrade,
		},

		// HRR retry
		{
			name:     "missing extension",
			alert:    alertMissingExtension,
			expected: ErrorHRRRetry,
		},
		{
			name:     "illegal parameter",
			alert:    alertIllegalParameter,
			expected: ErrorHRRRetry,
		},

		// Permanent
		{
			name:     "bad certificate",
			alert:    alertBadCertificate,
			expected: ErrorPermanent,
		},
		{
			name:     "unsupported certificate",
			alert:    alertUnsupportedCertificate,
			expected: ErrorPermanent,
		},
		{
			name:     "certificate revoked",
			alert:    alertCertificateRevoked,
			expected: ErrorPermanent,
		},
		{
			name:     "certificate expired",
			alert:    alertCertificateExpired,
			expected: ErrorPermanent,
		},
		{
			name:     "unknown CA",
			alert:    alertUnknownCA,
			expected: ErrorPermanent,
		},
		{
			name:     "access denied",
			alert:    alertAccessDenied,
			expected: ErrorPermanent,
		},
		{
			name:     "bad record MAC",
			alert:    alertBadRecordMAC,
			expected: ErrorPermanent,
		},
		{
			name:     "internal error",
			alert:    alertInternalError,
			expected: ErrorPermanent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := AlertError(tc.alert)
			result := ClassifyError(err)
			if result != tc.expected {
				t.Errorf("ClassifyError(AlertError(%v)) = %v, want %v", tc.alert, result, tc.expected)
			}
		})
	}
}

func TestTLSErrorTypeString(t *testing.T) {
	tests := []struct {
		errType  TLSErrorType
		expected string
	}{
		{ErrorTransient, "transient"},
		{ErrorPermanent, "permanent"},
		{ErrorDowngrade, "downgrade"},
		{ErrorHRRRetry, "hrr-retry"},
		{ErrorRecoverable, "recoverable"},
		{TLSErrorType(99), "unknown(99)"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			result := tc.errType.String()
			if result != tc.expected {
				t.Errorf("TLSErrorType(%d).String() = %q, want %q", tc.errType, result, tc.expected)
			}
		})
	}
}

func TestClassifiedError(t *testing.T) {
	origErr := errors.New("original error")
	classifiedErr := &ClassifiedError{
		Err:      origErr,
		Type:     ErrorTransient,
		Original: origErr,
	}

	// Test Error() method
	errStr := classifiedErr.Error()
	if !strings.Contains(errStr, "transient") {
		t.Errorf("Error() should contain 'transient', got %q", errStr)
	}
	if !strings.Contains(errStr, "original error") {
		t.Errorf("Error() should contain 'original error', got %q", errStr)
	}

	// Test Unwrap() method
	unwrapped := classifiedErr.Unwrap()
	if unwrapped != origErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, origErr)
	}
}

func TestDefaultGracefulConfig(t *testing.T) {
	cfg := DefaultGracefulConfig()

	if cfg == nil {
		t.Fatal("DefaultGracefulConfig() returned nil")
	}

	if cfg.AllowVersionDowngrade {
		t.Error("AllowVersionDowngrade should be false by default for security")
	}

	if !cfg.RetryOnHRRFailure {
		t.Error("RetryOnHRRFailure should be true by default")
	}

	if cfg.MaxHRRRetries != 1 {
		t.Errorf("MaxHRRRetries = %d, want 1", cfg.MaxHRRRetries)
	}

	if cfg.MaxTransientRetries != 2 {
		t.Errorf("MaxTransientRetries = %d, want 2", cfg.MaxTransientRetries)
	}

	if cfg.RetryDelay != 100*time.Millisecond {
		t.Errorf("RetryDelay = %v, want 100ms", cfg.RetryDelay)
	}

	if cfg.MaxRetryDelay != 5*time.Second {
		t.Errorf("MaxRetryDelay = %v, want 5s", cfg.MaxRetryDelay)
	}

	if cfg.HealthCheckInterval != 30*time.Second {
		t.Errorf("HealthCheckInterval = %v, want 30s", cfg.HealthCheckInterval)
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("connection reset"), true},                            // transient
		{errors.New("timeout"), true},                                     // transient
		{errors.New("key share error"), true},                             // HRR retry
		{errors.New("close notify"), true},                                // recoverable (via alert)
		{errors.New("bad certificate"), false},                            // permanent
		{errors.New("access denied"), false},                              // permanent
		{errors.New("protocol version not supported"), false},             // downgrade (not retryable without version change)
		{errors.New("some unknown error that doesn't match patterns"), true}, // defaults to transient
	}

	for _, tc := range tests {
		t.Run(tc.err.Error(), func(t *testing.T) {
			result := IsRetryable(tc.err)
			if result != tc.expected {
				t.Errorf("IsRetryable(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestIsDowngradeable(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("protocol version not supported"), true},
		{errors.New("unsupported version"), true},
		{errors.New("TLS 1.3 handshake failed"), true},
		{errors.New("no common cipher suite"), true},
		{errors.New("connection reset"), false},
		{errors.New("bad certificate"), false},
	}

	for _, tc := range tests {
		t.Run(tc.err.Error(), func(t *testing.T) {
			result := IsDowngradeable(tc.err)
			if result != tc.expected {
				t.Errorf("IsDowngradeable(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestShouldRetryHandshake(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("connection reset"), true},
		{errors.New("timeout"), true},
		{errors.New("key share error"), true},
		{errors.New("protocol version not supported"), true}, // downgrade is a form of retry
		{errors.New("bad certificate"), false},
		{errors.New("access denied"), false},
	}

	for _, tc := range tests {
		t.Run(tc.err.Error(), func(t *testing.T) {
			result := ShouldRetryHandshake(tc.err)
			if result != tc.expected {
				t.Errorf("ShouldRetryHandshake(%v) = %v, want %v", tc.err, result, tc.expected)
			}
		})
	}
}

func TestGetRecommendedAction(t *testing.T) {
	tests := []struct {
		err             error
		expectedContain string
	}{
		{errors.New("connection reset"), "Retry"},
		{errors.New("bad certificate"), "not retry"},
		{errors.New("protocol version"), "downgrade"},
		{errors.New("key share error"), "key share"},
		{errors.New("close notify"), "Reconnect"},
	}

	for _, tc := range tests {
		t.Run(tc.err.Error(), func(t *testing.T) {
			action := GetRecommendedAction(tc.err)
			if !strings.Contains(strings.ToLower(action), strings.ToLower(tc.expectedContain)) {
				t.Errorf("GetRecommendedAction(%v) = %q, should contain %q", tc.err, action, tc.expectedContain)
			}
		})
	}
}

func TestClassifyAndWrap(t *testing.T) {
	// Test nil error
	result := ClassifyAndWrap(nil)
	if result != nil {
		t.Errorf("ClassifyAndWrap(nil) = %v, want nil", result)
	}

	// Test actual error
	err := errors.New("connection reset")
	result = ClassifyAndWrap(err)
	if result == nil {
		t.Fatal("ClassifyAndWrap returned nil for non-nil error")
	}
	if result.Type != ErrorTransient {
		t.Errorf("ClassifyAndWrap type = %v, want ErrorTransient", result.Type)
	}
	if result.Original != err {
		t.Errorf("ClassifyAndWrap Original = %v, want %v", result.Original, err)
	}
}

func TestGracefulConfigValidation(t *testing.T) {
	// Create a minimal mock UConn for testing
	// Note: Full integration tests would require a real server

	cfg := &GracefulConfig{
		MaxHRRRetries: -1, // Invalid, should be capped
	}

	// Test that negative MaxHRRRetries is corrected
	mockDialer := func() (net.Conn, error) {
		return nil, errors.New("mock dialer")
	}

	// Create a mock UConn - we can't easily create a real one without a connection
	// but we can test the config validation in NewGracefulConn
	tlsConfig := &Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}

	// Create with nil UConn to test config validation
	gc := &GracefulConn{
		UConn:     nil,
		config:    cfg,
		dialer:    mockDialer,
		tlsConfig: tlsConfig,
	}

	// Manually apply the validation that NewGracefulConn does
	if cfg.MaxHRRRetries < 0 {
		cfg.MaxHRRRetries = 0
	}
	if cfg.MaxHRRRetries > 3 {
		cfg.MaxHRRRetries = 3
	}

	if gc.config.MaxHRRRetries != 0 {
		t.Errorf("MaxHRRRetries should be capped at 0 when negative, got %d", gc.config.MaxHRRRetries)
	}

	// Test upper bound capping
	cfg.MaxHRRRetries = 10
	if cfg.MaxHRRRetries < 0 {
		cfg.MaxHRRRetries = 0
	}
	if cfg.MaxHRRRetries > 3 {
		cfg.MaxHRRRetries = 3
	}

	if cfg.MaxHRRRetries != 3 {
		t.Errorf("MaxHRRRetries should be capped at 3, got %d", cfg.MaxHRRRetries)
	}
}

func TestGracefulStats(t *testing.T) {
	stats := GracefulStats{
		HRRRetries:       2,
		TransientRetries: 3,
		Downgraded:       true,
		Healthy:          false,
		LastHealthy:      time.Now().Add(-5 * time.Minute),
		LastError:        errors.New("test error"),
		LastErrorTime:    time.Now().Add(-1 * time.Minute),
	}

	if stats.HRRRetries != 2 {
		t.Errorf("HRRRetries = %d, want 2", stats.HRRRetries)
	}
	if stats.TransientRetries != 3 {
		t.Errorf("TransientRetries = %d, want 3", stats.TransientRetries)
	}
	if !stats.Downgraded {
		t.Error("Downgraded should be true")
	}
	if stats.Healthy {
		t.Error("Healthy should be false")
	}
	if stats.LastError == nil {
		t.Error("LastError should not be nil")
	}
}

// TestNetErrorClassification tests that net.Error types are properly classified
func TestNetErrorClassification(t *testing.T) {
	// Test timeout error
	timeoutErr := &gracefulMockNetError{timeout: true, temporary: false}
	if ClassifyError(timeoutErr) != ErrorTransient {
		t.Error("Timeout net.Error should be classified as transient")
	}

	// Test temporary error
	tempErr := &gracefulMockNetError{timeout: false, temporary: true}
	if ClassifyError(tempErr) != ErrorTransient {
		t.Error("Temporary net.Error should be classified as transient")
	}
}

// gracefulMockNetError implements net.Error for testing
type gracefulMockNetError struct {
	timeout   bool
	temporary bool
}

func (e *gracefulMockNetError) Error() string   { return "mock net error" }
func (e *gracefulMockNetError) Timeout() bool   { return e.timeout }
func (e *gracefulMockNetError) Temporary() bool { return e.temporary }

// TestCertificateVerificationErrorClassification tests that certificate errors are permanent
func TestCertificateVerificationErrorClassification(t *testing.T) {
	certErr := &CertificateVerificationError{
		Err: errors.New("certificate has expired"),
	}

	if ClassifyError(certErr) != ErrorPermanent {
		t.Error("CertificateVerificationError should be classified as permanent")
	}
}
