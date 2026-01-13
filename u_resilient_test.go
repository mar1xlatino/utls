// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

// =============================================================================
// Error Classification Tests
// =============================================================================

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "context canceled (not transient)",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "connection reset",
			err:      syscall.ECONNRESET,
			expected: true,
		},
		{
			name:     "connection refused",
			err:      syscall.ECONNREFUSED,
			expected: true,
		},
		{
			name:     "connection timed out",
			err:      syscall.ETIMEDOUT,
			expected: true,
		},
		{
			name:     "network unreachable",
			err:      syscall.ENETUNREACH,
			expected: true,
		},
		{
			name:     "host unreachable",
			err:      syscall.EHOSTUNREACH,
			expected: true,
		},
		{
			name:     "EOF (transient - premature close)",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "unexpected EOF",
			err:      io.ErrUnexpectedEOF,
			expected: true,
		},
		{
			name:     "wrapped connection reset",
			err:      errors.New("read: connection reset by peer"),
			expected: true,
		},
		{
			name:     "wrapped timeout",
			err:      errors.New("dial: i/o timeout"),
			expected: true,
		},
		{
			name:     "random error (not transient)",
			err:      errors.New("some random error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTransientError(tt.err)
			if result != tt.expected {
				t.Errorf("IsTransientError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "certificate invalid error",
			err:      &x509.CertificateInvalidError{Reason: x509.Expired},
			expected: true,
		},
		{
			name:     "hostname error",
			err:      x509.HostnameError{Certificate: nil, Host: "example.com"},
			expected: true,
		},
		{
			name:     "unknown authority error",
			err:      x509.UnknownAuthorityError{},
			expected: true,
		},
		{
			name:     "alert certificate expired",
			err:      AlertError(45),
			expected: true,
		},
		{
			name:     "alert certificate revoked",
			err:      AlertError(44),
			expected: true,
		},
		{
			name:     "alert bad certificate",
			err:      AlertError(42),
			expected: true,
		},
		{
			name:     "alert unknown CA",
			err:      AlertError(48),
			expected: true,
		},
		{
			name:     "wrapped certificate error",
			err:      errors.New("x509: certificate has expired"),
			expected: true,
		},
		{
			name:     "transient error (not permanent)",
			err:      syscall.ECONNRESET,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPermanentError(tt.err)
			if result != tt.expected {
				t.Errorf("IsPermanentError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestIsProfileSpecificError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "alert protocol version",
			err:      AlertError(70),
			expected: true,
		},
		{
			name:     "alert handshake failure",
			err:      AlertError(40),
			expected: true,
		},
		{
			name:     "alert insufficient security",
			err:      AlertError(71),
			expected: true,
		},
		{
			name:     "alert illegal parameter",
			err:      AlertError(47),
			expected: true,
		},
		{
			name:     "alert decode error",
			err:      AlertError(50),
			expected: true,
		},
		{
			name:     "wrapped protocol version error",
			err:      errors.New("tls: protocol version not supported"),
			expected: true,
		},
		{
			name:     "wrapped cipher suite error",
			err:      errors.New("tls: no common cipher suite"),
			expected: true,
		},
		{
			name:     "certificate error (not profile specific)",
			err:      AlertError(42), // bad certificate
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsProfileSpecificError(tt.err)
			if result != tt.expected {
				t.Errorf("IsProfileSpecificError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Backoff Calculation Tests
// =============================================================================

func TestCalculateBackoff(t *testing.T) {
	d := &ResilientDialer{
		BaseBackoff:       100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
		BackoffJitter:     0.0, // No jitter for deterministic testing
	}

	// Test exponential growth
	expected := []time.Duration{
		100 * time.Millisecond,  // attempt 0: 100ms * 2^0 = 100ms
		200 * time.Millisecond,  // attempt 1: 100ms * 2^1 = 200ms
		400 * time.Millisecond,  // attempt 2: 100ms * 2^2 = 400ms
		800 * time.Millisecond,  // attempt 3: 100ms * 2^3 = 800ms
		1600 * time.Millisecond, // attempt 4: 100ms * 2^4 = 1600ms
	}

	for i, want := range expected {
		got := d.calculateBackoff(i)
		if got != want {
			t.Errorf("calculateBackoff(%d) = %v, want %v", i, got, want)
		}
	}

	// Test max backoff cap
	// attempt 10: 100ms * 2^10 = 102.4s, should be capped at 5s
	got := d.calculateBackoff(10)
	if got != 5*time.Second {
		t.Errorf("calculateBackoff(10) = %v, want 5s (capped)", got)
	}
}

func TestCalculateBackoffWithJitter(t *testing.T) {
	d := &ResilientDialer{
		BaseBackoff:       100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
		BackoffJitter:     0.5, // 50% jitter
	}

	// With 50% jitter, attempt 0 backoff should be in range [50ms, 150ms]
	// (100ms * [1-0.5, 1+0.5])
	minBackoff := 50 * time.Millisecond
	maxBackoff := 150 * time.Millisecond

	// Run multiple times to verify jitter variation
	var sawVariation bool
	var lastBackoff time.Duration
	for i := 0; i < 100; i++ {
		backoff := d.calculateBackoff(0)
		if backoff < minBackoff || backoff > maxBackoff {
			t.Errorf("calculateBackoff(0) with jitter = %v, want in range [%v, %v]",
				backoff, minBackoff, maxBackoff)
		}
		if lastBackoff > 0 && backoff != lastBackoff {
			sawVariation = true
		}
		lastBackoff = backoff
	}

	if !sawVariation {
		t.Error("calculateBackoff with jitter should produce varying values")
	}
}

// =============================================================================
// ResilientDialer Configuration Tests
// =============================================================================

func TestDefaultResilientDialer(t *testing.T) {
	config := &Config{ServerName: "example.com"}
	d := DefaultResilientDialer(config)

	if len(d.Profiles) != 3 {
		t.Errorf("DefaultResilientDialer should have 3 profiles, got %d", len(d.Profiles))
	}

	if d.MaxRetries != 3 {
		t.Errorf("DefaultResilientDialer MaxRetries = %d, want 3", d.MaxRetries)
	}

	if d.BaseBackoff != 100*time.Millisecond {
		t.Errorf("DefaultResilientDialer BaseBackoff = %v, want 100ms", d.BaseBackoff)
	}

	if d.MaxBackoff != 5*time.Second {
		t.Errorf("DefaultResilientDialer MaxBackoff = %v, want 5s", d.MaxBackoff)
	}

	if d.BackoffMultiplier != 2.0 {
		t.Errorf("DefaultResilientDialer BackoffMultiplier = %v, want 2.0", d.BackoffMultiplier)
	}

	if d.DialTimeout != 10*time.Second {
		t.Errorf("DefaultResilientDialer DialTimeout = %v, want 10s", d.DialTimeout)
	}
}

func TestNewResilientDialer(t *testing.T) {
	config := &Config{ServerName: "example.com"}

	// Test with no profiles (should default to Chrome)
	d := NewResilientDialer(config)
	if len(d.Profiles) != 1 {
		t.Errorf("NewResilientDialer with no profiles should default to 1, got %d", len(d.Profiles))
	}

	// Test with custom profiles
	d = NewResilientDialer(config, HelloFirefox_Auto, HelloSafari_Auto)
	if len(d.Profiles) != 2 {
		t.Errorf("NewResilientDialer with 2 profiles got %d", len(d.Profiles))
	}
}

func TestEffectiveProfiles(t *testing.T) {
	// Empty profiles should default to Chrome
	d := &ResilientDialer{}
	profiles := d.effectiveProfiles()
	if len(profiles) != 1 {
		t.Errorf("effectiveProfiles with empty Profiles should return 1, got %d", len(profiles))
	}
	if profiles[0] != HelloChrome_Auto {
		t.Errorf("effectiveProfiles default should be HelloChrome_Auto, got %v", profiles[0])
	}

	// Set profiles should be returned as-is
	d.Profiles = []ClientHelloID{HelloFirefox_Auto, HelloSafari_Auto}
	profiles = d.effectiveProfiles()
	if len(profiles) != 2 {
		t.Errorf("effectiveProfiles with set Profiles should return 2, got %d", len(profiles))
	}
}

func TestEffectiveMaxRetries(t *testing.T) {
	d := &ResilientDialer{}

	// Default (0) should return 3
	if d.effectiveMaxRetries() != 3 {
		t.Errorf("effectiveMaxRetries with default should return 3, got %d", d.effectiveMaxRetries())
	}

	// Negative should return 0
	d.MaxRetries = -1
	if d.effectiveMaxRetries() != 0 {
		t.Errorf("effectiveMaxRetries with -1 should return 0, got %d", d.effectiveMaxRetries())
	}

	// Positive value should be returned as-is
	d.MaxRetries = 5
	if d.effectiveMaxRetries() != 5 {
		t.Errorf("effectiveMaxRetries with 5 should return 5, got %d", d.effectiveMaxRetries())
	}
}

// =============================================================================
// DialResult Tests
// =============================================================================

func TestDialResultError(t *testing.T) {
	// Test with last error
	result := &DialResult{
		TotalAttempts: 5,
		LastError:     errors.New("connection failed"),
	}
	errStr := result.Error()
	if errStr == "" {
		t.Error("DialResult.Error() should return non-empty string when LastError is set")
	}

	// Test without last error
	result = &DialResult{}
	if result.Error() != "" {
		t.Error("DialResult.Error() should return empty string when LastError is nil")
	}
}

func TestDialResultUnwrap(t *testing.T) {
	originalErr := errors.New("original error")
	result := &DialResult{LastError: originalErr}

	if !errors.Is(result, originalErr) {
		t.Error("errors.Is should find original error through Unwrap")
	}
}

// =============================================================================
// Mock Network Error for Testing
// =============================================================================

// resilientMockNetError implements net.Error for resilience tests
// Named differently to avoid conflict with mockNetError in u_graceful_test.go
type resilientMockNetError struct {
	msg       string
	timeout   bool
	temporary bool
}

func (e *resilientMockNetError) Error() string   { return e.msg }
func (e *resilientMockNetError) Timeout() bool   { return e.timeout }
func (e *resilientMockNetError) Temporary() bool { return e.temporary }

func TestIsTransientErrorWithNetError(t *testing.T) {
	// Test timeout network error
	timeoutErr := &resilientMockNetError{
		msg:     "timeout",
		timeout: true,
	}
	if !IsTransientError(timeoutErr) {
		t.Error("IsTransientError should return true for timeout network error")
	}

	// Test non-transient network error (Temporary() is deprecated and no longer checked)
	permErr := &resilientMockNetError{
		msg:       "permanent",
		timeout:   false,
		temporary: false,
	}
	if IsTransientError(permErr) {
		t.Error("IsTransientError should return false for permanent network error")
	}
}

// =============================================================================
// Logger Interface Tests
// =============================================================================

type testLogger struct {
	messages []string
}

func (l *testLogger) Printf(format string, args ...interface{}) {
	l.messages = append(l.messages, format)
}

func TestResilientDialerLogging(t *testing.T) {
	logger := &testLogger{}
	d := &ResilientDialer{
		Logger: logger,
	}

	d.logf("test message %d", 1)

	if len(logger.messages) != 1 {
		t.Errorf("Expected 1 log message, got %d", len(logger.messages))
	}

	// Test without logger (should not panic)
	d.Logger = nil
	d.logf("should not panic")
}

// =============================================================================
// Integration-like Tests (without actual network)
// =============================================================================

func TestDialResultProfileAttempts(t *testing.T) {
	result := &DialResult{
		ProfileAttempts: make(map[string]int),
	}

	// Simulate attempts
	result.ProfileAttempts["Chrome-Auto"] = 3
	result.ProfileAttempts["Firefox-Auto"] = 2

	if result.ProfileAttempts["Chrome-Auto"] != 3 {
		t.Errorf("Expected 3 Chrome attempts, got %d", result.ProfileAttempts["Chrome-Auto"])
	}

	if result.ProfileAttempts["Firefox-Auto"] != 2 {
		t.Errorf("Expected 2 Firefox attempts, got %d", result.ProfileAttempts["Firefox-Auto"])
	}
}

func TestDialAttemptError(t *testing.T) {
	attemptErr := DialAttemptError{
		Profile:   HelloChrome_Auto,
		Attempt:   1,
		Error:     errors.New("connection refused"),
		Transient: true,
		Duration:  100 * time.Millisecond,
	}

	if !attemptErr.Transient {
		t.Error("DialAttemptError should be marked as transient")
	}

	if attemptErr.Attempt != 1 {
		t.Errorf("Expected attempt 1, got %d", attemptErr.Attempt)
	}
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

func TestDialWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	d := &ResilientDialer{
		Profiles: []ClientHelloID{HelloChrome_Auto},
		Config:   &Config{ServerName: "example.com"},
	}

	// This should fail quickly with context canceled
	_, err := d.Dial(ctx, "tcp", "example.com:443")
	if err == nil {
		t.Error("Dial with canceled context should return error")
	}

	// Check that context error is in the error chain
	var result *DialResult
	if errors.As(err, &result) && result.LastError != nil {
		if !errors.Is(result.LastError, context.Canceled) {
			t.Errorf("Expected context.Canceled in error chain, got %v", result.LastError)
		}
	}
}

func TestDialWithDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Wait for deadline to pass
	time.Sleep(1 * time.Millisecond)

	d := &ResilientDialer{
		Profiles: []ClientHelloID{HelloChrome_Auto},
		Config:   &Config{ServerName: "example.com"},
	}

	_, err := d.Dial(ctx, "tcp", "example.com:443")
	if err == nil {
		t.Error("Dial with exceeded deadline should return error")
	}
}

// =============================================================================
// ServerName Extraction Tests
// =============================================================================

func TestServerNameExtraction(t *testing.T) {
	tests := []struct {
		addr     string
		expected string
	}{
		{"example.com:443", "example.com"},
		{"sub.example.com:8443", "sub.example.com"},
		{"192.168.1.1:443", "192.168.1.1"},
		{"[::1]:443", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			host, _, err := net.SplitHostPort(tt.addr)
			if err != nil {
				t.Fatalf("SplitHostPort(%q) failed: %v", tt.addr, err)
			}
			if host != tt.expected {
				t.Errorf("SplitHostPort(%q) = %q, want %q", tt.addr, host, tt.expected)
			}
		})
	}
}
