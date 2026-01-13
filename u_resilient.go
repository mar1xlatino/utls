// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ResilientDialer provides TLS connection establishment with retry logic,
// exponential backoff, and profile fallback mechanisms for resilient connections.
//
// It wraps UClient with automatic retry handling for transient errors and
// profile fallback when certain profiles fail to connect.
//
// Example usage:
//
//	dialer := tls.DefaultResilientDialer(&tls.Config{
//	    ServerName: "example.com",
//	})
//	conn, err := dialer.DialWithFallback(ctx, "tcp", "example.com:443")
type ResilientDialer struct {
	// Profiles is the ordered list of ClientHelloIDs to try.
	// Each profile is tried in sequence if previous ones fail.
	// If empty, defaults to [HelloChrome_Auto].
	Profiles []ClientHelloID

	// MaxRetries is the maximum number of retries per profile for transient errors.
	// Set to 0 for no retries. Defaults to 3 if not set.
	MaxRetries int

	// BaseBackoff is the initial backoff duration before the first retry.
	// Defaults to 100ms if not set.
	BaseBackoff time.Duration

	// MaxBackoff is the maximum backoff duration between retries.
	// Backoff is capped at this value. Defaults to 5s if not set.
	MaxBackoff time.Duration

	// BackoffMultiplier is the factor by which backoff increases after each retry.
	// Defaults to 2.0 if not set.
	BackoffMultiplier float64

	// BackoffJitter adds randomness to backoff to prevent thundering herd.
	// Value between 0.0 (no jitter) and 1.0 (full jitter). Defaults to 0.2.
	BackoffJitter float64

	// Config is the TLS configuration template used for connections.
	// ServerName must be set or provided via the address parameter.
	Config *Config

	// DialTimeout is the timeout for each individual dial attempt.
	// If zero, uses the context deadline. Defaults to 10s if context has no deadline.
	DialTimeout time.Duration

	// Dialer is the underlying network dialer. If nil, net.Dialer{} is used.
	Dialer *net.Dialer

	// Logger receives diagnostic messages about connection attempts.
	// If nil, no logging is performed.
	Logger ResilientDialerLogger

	// OnProfileSuccess is called when a profile successfully connects.
	// This can be used to track which profiles work best.
	OnProfileSuccess func(profile ClientHelloID, attempt int, duration time.Duration)

	// OnRetry is called before each retry attempt.
	// Return false to abort retrying.
	OnRetry func(profile ClientHelloID, attempt int, err error, nextBackoff time.Duration) bool

	// mu protects internal state
	mu sync.RWMutex

	// rng for backoff jitter, lazily initialized
	rng *rand.Rand
}

// ResilientDialerLogger defines the logging interface for ResilientDialer.
type ResilientDialerLogger interface {
	// Printf logs a formatted message.
	Printf(format string, args ...interface{})
}

// DialResult contains detailed information about a connection attempt.
type DialResult struct {
	// Conn is the established connection, or nil if all attempts failed.
	Conn *UConn

	// UsedProfile is the ClientHelloID that successfully connected.
	UsedProfile ClientHelloID

	// TotalAttempts is the total number of connection attempts made.
	TotalAttempts int

	// ProfileAttempts maps each tried profile to the number of attempts.
	ProfileAttempts map[string]int

	// LastError is the last error encountered, if any.
	LastError error

	// Duration is the total time spent attempting to connect.
	Duration time.Duration

	// Errors contains all errors encountered during attempts.
	Errors []DialAttemptError
}

// DialAttemptError records an individual attempt failure.
type DialAttemptError struct {
	Profile   ClientHelloID
	Attempt   int
	Error     error
	Transient bool
	Duration  time.Duration
}

// Error implements the error interface for DialResult.
func (r *DialResult) Error() string {
	if r.LastError != nil {
		return fmt.Sprintf("tls: all %d connection attempts failed: %v", r.TotalAttempts, r.LastError)
	}
	return ""
}

// Unwrap returns the underlying error for errors.Is/As compatibility.
func (r *DialResult) Unwrap() error {
	return r.LastError
}

// DefaultResilientDialer creates a ResilientDialer with sensible defaults.
// It configures:
//   - Profiles: Chrome Auto, Firefox Auto, Safari Auto
//   - MaxRetries: 3
//   - BaseBackoff: 100ms
//   - MaxBackoff: 5s
//   - BackoffMultiplier: 2.0
//   - BackoffJitter: 0.2
//   - DialTimeout: 10s
func DefaultResilientDialer(config *Config) *ResilientDialer {
	return &ResilientDialer{
		Profiles: []ClientHelloID{
			HelloChrome_Auto,
			HelloFirefox_Auto,
			HelloSafari_Auto,
		},
		MaxRetries:        3,
		BaseBackoff:       100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
		BackoffJitter:     0.2,
		Config:            config,
		DialTimeout:       10 * time.Second,
	}
}

// NewResilientDialer creates a ResilientDialer with the specified profiles.
// Other settings use sensible defaults.
func NewResilientDialer(config *Config, profiles ...ClientHelloID) *ResilientDialer {
	if len(profiles) == 0 {
		profiles = []ClientHelloID{HelloChrome_Auto}
	}
	return &ResilientDialer{
		Profiles:          profiles,
		MaxRetries:        3,
		BaseBackoff:       100 * time.Millisecond,
		MaxBackoff:        5 * time.Second,
		BackoffMultiplier: 2.0,
		BackoffJitter:     0.2,
		Config:            config,
		DialTimeout:       10 * time.Second,
	}
}

// Dial establishes a TLS connection using the first profile with retry logic.
// It returns the connection on success or an error after all retries are exhausted.
//
// This method only uses the first profile in the Profiles list. For profile
// fallback, use DialWithFallback instead.
func (d *ResilientDialer) Dial(ctx context.Context, network, addr string) (*UConn, error) {
	result := d.dial(ctx, network, addr, false)
	if result.Conn != nil {
		return result.Conn, nil
	}
	return nil, result
}

// DialWithFallback establishes a TLS connection, trying multiple profiles.
// If the first profile fails with errors that suggest profile incompatibility,
// it falls back to subsequent profiles in the Profiles list.
//
// Transient errors (timeouts, connection resets) are retried within each profile.
// Permanent errors (certificate validation) cause immediate failure without fallback.
func (d *ResilientDialer) DialWithFallback(ctx context.Context, network, addr string) (*UConn, error) {
	result := d.dial(ctx, network, addr, true)
	if result.Conn != nil {
		return result.Conn, nil
	}
	return nil, result
}

// DialWithResult provides detailed information about the connection attempt.
// Use this when you need diagnostic information about which profile worked
// and how many attempts were made.
func (d *ResilientDialer) DialWithResult(ctx context.Context, network, addr string, fallback bool) *DialResult {
	return d.dial(ctx, network, addr, fallback)
}

// dial is the internal implementation of connection establishment.
func (d *ResilientDialer) dial(ctx context.Context, network, addr string, fallback bool) *DialResult {
	startTime := time.Now()
	result := &DialResult{
		ProfileAttempts: make(map[string]int),
		Errors:          make([]DialAttemptError, 0),
	}

	profiles := d.effectiveProfiles()
	if !fallback {
		// Only use first profile when not in fallback mode
		profiles = profiles[:1]
	}

	for _, profile := range profiles {
		profileKey := profile.Str()
		maxRetries := d.effectiveMaxRetries()

		for attempt := 0; attempt <= maxRetries; attempt++ {
			result.TotalAttempts++
			result.ProfileAttempts[profileKey]++

			// Check context cancellation before attempting
			if err := ctx.Err(); err != nil {
				result.LastError = err
				result.Duration = time.Since(startTime)
				return result
			}

			attemptStart := time.Now()
			conn, err := d.attemptDial(ctx, network, addr, profile)
			attemptDuration := time.Since(attemptStart)

			if err == nil {
				// Success
				result.Conn = conn
				result.UsedProfile = profile
				result.Duration = time.Since(startTime)

				d.logf("connected with profile %s on attempt %d", profileKey, attempt+1)

				if d.OnProfileSuccess != nil {
					d.OnProfileSuccess(profile, attempt+1, attemptDuration)
				}

				return result
			}

			// Record the error
			isTransient := IsTransientError(err)
			result.Errors = append(result.Errors, DialAttemptError{
				Profile:   profile,
				Attempt:   attempt + 1,
				Error:     err,
				Transient: isTransient,
				Duration:  attemptDuration,
			})
			result.LastError = err

			d.logf("attempt %d with profile %s failed: %v (transient=%v)",
				attempt+1, profileKey, err, isTransient)

			// Check if we should retry or move to next profile
			if !isTransient {
				// Permanent error - check if it's profile-specific
				if IsProfileSpecificError(err) && fallback {
					d.logf("profile-specific error, trying next profile")
					break // Try next profile
				}
				// Other permanent errors (like cert validation) should fail immediately
				if IsPermanentError(err) {
					result.Duration = time.Since(startTime)
					return result
				}
				// Unknown error type, try fallback if available
				if fallback {
					break
				}
			}

			// Should we retry?
			if attempt < maxRetries {
				backoff := d.calculateBackoff(attempt)

				// Check if OnRetry callback wants to abort
				if d.OnRetry != nil && !d.OnRetry(profile, attempt+1, err, backoff) {
					d.logf("retry aborted by callback")
					result.Duration = time.Since(startTime)
					return result
				}

				d.logf("retrying in %v", backoff)

				// Wait with context cancellation support
				select {
				case <-ctx.Done():
					result.LastError = ctx.Err()
					result.Duration = time.Since(startTime)
					return result
				case <-time.After(backoff):
					// Continue to retry
				}
			}
		}
	}

	result.Duration = time.Since(startTime)
	return result
}

// attemptDial makes a single connection attempt with the given profile.
func (d *ResilientDialer) attemptDial(ctx context.Context, network, addr string, profile ClientHelloID) (*UConn, error) {
	// Create context with dial timeout
	dialCtx := ctx
	if d.DialTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, d.DialTimeout)
		defer cancel()
	}

	// Get dialer
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	// Dial TCP connection
	tcpConn, err := dialer.DialContext(dialCtx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	// Prepare TLS config
	config := d.Config
	if config == nil {
		config = &Config{}
	}
	// Clone to avoid modifying original
	config = config.Clone()

	// Extract server name from address if not set
	if config.ServerName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			// addr might be just a hostname without port
			host = addr
		}
		config.ServerName = host
	}

	// Create UConn
	uconn, err := UClient(tcpConn, config, profile)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("UClient creation failed: %w", err)
	}

	// Perform handshake
	if err := uconn.HandshakeContext(dialCtx); err != nil {
		uconn.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	return uconn, nil
}

// calculateBackoff computes the backoff duration for a given attempt number.
func (d *ResilientDialer) calculateBackoff(attempt int) time.Duration {
	base := d.BaseBackoff
	if base == 0 {
		base = 100 * time.Millisecond
	}

	multiplier := d.BackoffMultiplier
	if multiplier == 0 {
		multiplier = 2.0
	}

	maxBackoff := d.MaxBackoff
	if maxBackoff == 0 {
		maxBackoff = 5 * time.Second
	}

	// Calculate exponential backoff
	backoff := float64(base) * math.Pow(multiplier, float64(attempt))

	// Apply jitter
	jitter := d.BackoffJitter
	if jitter > 0 {
		d.mu.Lock()
		if d.rng == nil {
			d.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
		}
		// Jitter: backoff * (1 - jitter + rand*2*jitter)
		// This gives a range of [backoff*(1-jitter), backoff*(1+jitter)]
		jitterFactor := 1.0 - jitter + d.rng.Float64()*2*jitter
		backoff *= jitterFactor
		d.mu.Unlock()
	}

	// Cap at max backoff
	if backoff > float64(maxBackoff) {
		backoff = float64(maxBackoff)
	}

	return time.Duration(backoff)
}

// effectiveProfiles returns the profiles to use, with defaults if empty.
func (d *ResilientDialer) effectiveProfiles() []ClientHelloID {
	if len(d.Profiles) == 0 {
		return []ClientHelloID{HelloChrome_Auto}
	}
	return d.Profiles
}

// effectiveMaxRetries returns the max retries, with default if not set.
func (d *ResilientDialer) effectiveMaxRetries() int {
	if d.MaxRetries < 0 {
		return 0
	}
	if d.MaxRetries == 0 {
		return 3 // Default
	}
	return d.MaxRetries
}

// logf logs a message if a logger is configured.
func (d *ResilientDialer) logf(format string, args ...interface{}) {
	if d.Logger != nil {
		d.Logger.Printf("[ResilientDialer] "+format, args...)
	}
}

// =============================================================================
// Error Classification
// =============================================================================

// IsTransientError determines if an error is transient and worth retrying.
// Transient errors include:
//   - Network timeouts
//   - Connection resets
//   - Temporary network failures
//   - DNS resolution timeouts
//   - TLS handshake timeouts
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context errors
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Context canceled is not transient (user-initiated)
	if errors.Is(err, context.Canceled) {
		return false
	}

	// Check for network errors with Timeout() or Temporary()
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	// Check for specific syscall errors that are transient
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		switch syscallErr {
		case syscall.ECONNRESET, // Connection reset by peer
			syscall.ECONNREFUSED, // Connection refused (server may be starting)
			syscall.ETIMEDOUT,    // Connection timed out
			syscall.ENETUNREACH,  // Network unreachable
			syscall.EHOSTUNREACH, // Host unreachable
			syscall.ECONNABORTED, // Connection aborted
			syscall.ENETRESET,    // Network dropped connection on reset
			syscall.EPIPE:        // Broken pipe
			return true
		}
	}

	// Check error message for common transient patterns
	errStr := strings.ToLower(err.Error())
	transientPatterns := []string{
		"connection reset",
		"connection refused",
		"connection timed out",
		"network is unreachable",
		"host is unreachable",
		"no route to host",
		"broken pipe",
		"connection aborted",
		"i/o timeout",
		"temporary failure",
		"try again",
		"server busy",
		"too many connections",
	}

	for _, pattern := range transientPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	// Check for EOF which can be transient (server closed connection prematurely)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	return false
}

// IsPermanentError determines if an error is permanent and should not be retried.
// Permanent errors include:
//   - Certificate validation failures
//   - Protocol version mismatch
//   - No common cipher suites
//   - Authentication failures
func IsPermanentError(err error) bool {
	if err == nil {
		return false
	}

	// Certificate errors are permanent
	var certErr *x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		return true
	}

	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return true
	}

	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return true
	}

	// Check for TLS alert errors that are permanent
	var alertErr AlertError
	if errors.As(err, &alertErr) {
		// Convert to uint8 to compare with internal alert constants
		alertVal := uint8(alertErr)
		switch alertVal {
		case 45, // alertCertificateExpired
			44,  // alertCertificateRevoked
			46,  // alertCertificateUnknown
			49,  // alertAccessDenied
			42,  // alertBadCertificate
			113, // alertBadCertificateStatusResponse
			48:  // alertUnknownCA
			return true
		}
	}

	// Check error messages for permanent failure patterns
	errStr := strings.ToLower(err.Error())
	permanentPatterns := []string{
		"certificate",
		"x509",
		"verify",
		"expired",
		"revoked",
		"untrusted",
		"invalid certificate",
		"unknown authority",
		"authentication failed",
		"access denied",
	}

	for _, pattern := range permanentPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// IsProfileSpecificError determines if an error is likely due to profile incompatibility.
// These errors suggest trying a different TLS fingerprint might succeed.
// Profile-specific errors include:
//   - Protocol version negotiation failures
//   - Cipher suite negotiation failures
//   - Extension negotiation failures
//   - HelloRetryRequest loops
func IsProfileSpecificError(err error) bool {
	if err == nil {
		return false
	}

	// Check for TLS alert errors that suggest profile issues
	var alertErr AlertError
	if errors.As(err, &alertErr) {
		// Convert to uint8 to compare with internal alert constants
		alertVal := uint8(alertErr)
		switch alertVal {
		case 70, // alertProtocolVersion
			40, // alertHandshakeFailure
			71, // alertInsufficientSecurity
			80, // alertInternalError
			47, // alertIllegalParameter
			50: // alertDecodeError
			return true
		}
	}

	// Check error messages for profile-related patterns
	errStr := strings.ToLower(err.Error())
	profilePatterns := []string{
		"protocol version",
		"cipher suite",
		"no common",
		"handshake failure",
		"insufficient security",
		"illegal parameter",
		"decode error",
		"hello retry",
		"unsupported",
		"incompatible",
		"extension",
	}

	for _, pattern := range profilePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}
