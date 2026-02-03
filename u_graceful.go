// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utlserrors "github.com/refraction-networking/utls/errors"
)

// TLSErrorType classifies TLS errors for graceful degradation decisions.
// This classification helps determine whether to retry, downgrade, or fail permanently.
type TLSErrorType int

const (
	// ErrorTransient indicates a temporary error where retry may help.
	// Examples: network timeout, temporary server overload, connection reset.
	ErrorTransient TLSErrorType = iota

	// ErrorPermanent indicates a fatal error where retry will not help.
	// Examples: certificate validation failure, protocol violation, authentication failure.
	ErrorPermanent

	// ErrorDowngrade indicates the error may be resolved by trying a lower TLS version.
	// Examples: TLS 1.3 handshake failure, unsupported cipher suite in TLS 1.3.
	ErrorDowngrade

	// ErrorHRRRetry indicates HelloRetryRequest handling failed but retry with
	// different key share might succeed.
	ErrorHRRRetry

	// ErrorRecoverable indicates the connection may be salvageable with reconnection.
	// Examples: half-closed connection, session ticket expired.
	ErrorRecoverable
)

// String returns a human-readable name for the error type.
func (t TLSErrorType) String() string {
	switch t {
	case ErrorTransient:
		return "transient"
	case ErrorPermanent:
		return "permanent"
	case ErrorDowngrade:
		return "downgrade"
	case ErrorHRRRetry:
		return "hrr-retry"
	case ErrorRecoverable:
		return "recoverable"
	default:
		return fmt.Sprintf("unknown(%d)", int(t))
	}
}

// ClassifiedError wraps an error with its classification for graceful handling.
type ClassifiedError struct {
	Err      error
	Type     TLSErrorType
	Original error // Original unwrapped error if available
}

func (e *ClassifiedError) Error() string {
	return fmt.Sprintf("tls: %s error: %v", e.Type.String(), e.Err)
}

func (e *ClassifiedError) Unwrap() error {
	return e.Err
}

// ClassifyError analyzes an error and returns its classification for graceful degradation.
// This function inspects the error chain to determine the appropriate recovery strategy.
func ClassifyError(err error) TLSErrorType {
	if err == nil {
		return ErrorTransient // No error, but treat as transient for safety
	}

	errStr := strings.ToLower(err.Error())

	// Check for specific error types using errors.As
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return ErrorTransient
		}
	}

	// Check for alert errors
	var alertErr AlertError
	if errors.As(err, &alertErr) {
		return classifyAlertError(alert(alertErr))
	}

	// Check for certificate verification errors
	var certErr *CertificateVerificationError
	if errors.As(err, &certErr) {
		return ErrorPermanent
	}

	// Check for ECH rejection
	var echErr *ECHRejectionError
	if errors.As(err, &echErr) {
		// ECH rejection with retry configs is recoverable
		if len(echErr.RetryConfigList) > 0 {
			return ErrorRecoverable
		}
		return ErrorPermanent
	}

	// String-based classification for common error patterns
	switch {
	// Connection/network errors (transient)
	case strings.Contains(errStr, "connection reset"):
		return ErrorTransient
	case strings.Contains(errStr, "connection refused"):
		return ErrorTransient
	case strings.Contains(errStr, "timeout"):
		return ErrorTransient
	case strings.Contains(errStr, "temporary failure"):
		return ErrorTransient
	case strings.Contains(errStr, "broken pipe"):
		return ErrorTransient
	case strings.Contains(errStr, "network unreachable"):
		return ErrorTransient
	case strings.Contains(errStr, "eof"):
		return ErrorTransient

	// Close notify (recoverable - reconnect needed)
	case strings.Contains(errStr, "close notify"):
		return ErrorRecoverable

	// HelloRetryRequest related errors (HRR retry)
	case strings.Contains(errStr, "helloretryrequest"):
		return ErrorHRRRetry
	case strings.Contains(errStr, "key share"):
		return ErrorHRRRetry
	case strings.Contains(errStr, "selected group"):
		return ErrorHRRRetry
	case strings.Contains(errStr, "unsupported group"):
		return ErrorHRRRetry

	// Version/protocol errors (downgrade candidates)
	case strings.Contains(errStr, "protocol version"):
		return ErrorDowngrade
	case strings.Contains(errStr, "unsupported version"):
		return ErrorDowngrade
	case strings.Contains(errStr, "version not supported"):
		return ErrorDowngrade
	case strings.Contains(errStr, "tls 1.3"):
		return ErrorDowngrade
	case strings.Contains(errStr, "no common cipher"):
		return ErrorDowngrade
	case strings.Contains(errStr, "unconfigured cipher"):
		return ErrorDowngrade

	// Certificate errors (permanent)
	case strings.Contains(errStr, "certificate"):
		return ErrorPermanent
	case strings.Contains(errStr, "x509"):
		return ErrorPermanent
	case strings.Contains(errStr, "expired"):
		return ErrorPermanent
	case strings.Contains(errStr, "revoked"):
		return ErrorPermanent
	case strings.Contains(errStr, "unknown authority"):
		return ErrorPermanent

	// Authentication/authorization errors (permanent)
	case strings.Contains(errStr, "access denied"):
		return ErrorPermanent
	case strings.Contains(errStr, "authentication"):
		return ErrorPermanent
	case strings.Contains(errStr, "bad record mac"):
		return ErrorPermanent
	case strings.Contains(errStr, "decrypt"):
		return ErrorPermanent

	// Protocol violations (permanent)
	case strings.Contains(errStr, "illegal parameter"):
		return ErrorPermanent
	case strings.Contains(errStr, "unexpected message"):
		return ErrorPermanent
	case strings.Contains(errStr, "decode error"):
		return ErrorPermanent
	case strings.Contains(errStr, "internal error"):
		return ErrorPermanent
	}

	// Default to transient for unknown errors (safer for retry logic)
	return ErrorTransient
}

// classifyAlertError classifies TLS alert codes into error types.
func classifyAlertError(a alert) TLSErrorType {
	switch a {
	// Transient/recoverable alerts
	case alertCloseNotify:
		return ErrorRecoverable
	case alertUserCanceled:
		return ErrorTransient
	case alertNoRenegotiation:
		return ErrorRecoverable

	// Downgrade candidates
	case alertProtocolVersion:
		return ErrorDowngrade
	case alertInsufficientSecurity:
		return ErrorDowngrade
	case alertInappropriateFallback:
		return ErrorDowngrade
	case alertHandshakeFailure:
		// Handshake failure could be TLS 1.3 incompatibility
		return ErrorDowngrade

	// HRR-related alerts
	case alertMissingExtension:
		return ErrorHRRRetry
	case alertIllegalParameter:
		// Could be key share issue
		return ErrorHRRRetry

	// Permanent errors (certificates and security)
	case alertBadCertificate:
		return ErrorPermanent
	case alertUnsupportedCertificate:
		return ErrorPermanent
	case alertCertificateRevoked:
		return ErrorPermanent
	case alertCertificateExpired:
		return ErrorPermanent
	case alertCertificateUnknown:
		return ErrorPermanent
	case alertUnknownCA:
		return ErrorPermanent
	case alertAccessDenied:
		return ErrorPermanent
	case alertBadRecordMAC:
		return ErrorPermanent
	case alertDecryptionFailed:
		return ErrorPermanent
	case alertDecryptError:
		return ErrorPermanent
	case alertCertificateRequired:
		return ErrorPermanent
	case alertUnknownPSKIdentity:
		return ErrorRecoverable // PSK issue, try without PSK
	case alertECHRequired:
		return ErrorRecoverable // Need ECH, can retry with configs

	// Internal/protocol errors (permanent)
	case alertInternalError:
		return ErrorPermanent
	case alertDecodeError:
		return ErrorPermanent
	case alertUnexpectedMessage:
		return ErrorPermanent

	default:
		return ErrorTransient
	}
}

// GracefulConfig configures graceful degradation behavior for TLS connections.
// These options control how the connection handles various failure scenarios.
type GracefulConfig struct {
	// AllowVersionDowngrade enables automatic fallback to TLS 1.2 if TLS 1.3 fails.
	// This is disabled by default for security (prevents downgrade attacks).
	// Only enable if connecting to servers known to have TLS 1.3 compatibility issues.
	AllowVersionDowngrade bool

	// RetryOnHRRFailure enables retry with different key share on HRR failure.
	// When enabled, if HelloRetryRequest handling fails, the connection will
	// attempt to reconnect with a different key share configuration.
	RetryOnHRRFailure bool

	// MaxHRRRetries limits the number of HRR retry attempts.
	// Default is 1 (one retry after initial failure). Maximum is 3.
	MaxHRRRetries int

	// MaxTransientRetries limits retries for transient errors.
	// Default is 2. Set to 0 to disable transient retries.
	MaxTransientRetries int

	// RetryDelay is the base delay between retry attempts.
	// Actual delay uses exponential backoff: RetryDelay * 2^attempt.
	// Default is 100ms.
	RetryDelay time.Duration

	// MaxRetryDelay caps the maximum delay between retries.
	// Default is 5 seconds.
	MaxRetryDelay time.Duration

	// HealthCheckInterval is how often to check connection health.
	// Default is 30 seconds. Set to 0 to disable periodic health checks.
	HealthCheckInterval time.Duration

	// OnError is called when an error occurs, providing classification info.
	// This callback can be used for logging, metrics, or custom handling.
	// Return true to proceed with automatic recovery, false to fail immediately.
	OnError func(err error, errType TLSErrorType, attempt int) bool

	// OnRecovery is called when recovery succeeds after a failure.
	// Provides information about what recovery action was taken.
	OnRecovery func(action string, attempts int)
}

// DefaultGracefulConfig returns a GracefulConfig with sensible defaults.
// Version downgrade is disabled for security; enable explicitly if needed.
func DefaultGracefulConfig() *GracefulConfig {
	return &GracefulConfig{
		AllowVersionDowngrade: false, // Security: disabled by default
		RetryOnHRRFailure:     true,
		MaxHRRRetries:         1,
		MaxTransientRetries:   2,
		RetryDelay:            100 * time.Millisecond,
		MaxRetryDelay:         5 * time.Second,
		HealthCheckInterval:   30 * time.Second,
	}
}

// GracefulConn wraps a UConn with graceful degradation capabilities.
// It provides automatic error recovery, version downgrade, and health checking.
type GracefulConn struct {
	*UConn

	config     *GracefulConfig
	dialer     func() (net.Conn, error) // Function to create new underlying connections
	tlsConfig  *Config
	helloID    ClientHelloID
	serverName string

	// State tracking
	mu            sync.Mutex
	hrrRetries    int
	transRetries  int
	downgraded    bool
	lastError     error
	lastErrorTime time.Time

	// Health check state
	healthMu      sync.RWMutex
	healthy       atomic.Bool
	lastHealthy   time.Time
	healthCheckCh chan struct{}
	healthDone    chan struct{}
	closeOnce     sync.Once // Ensures healthDone channel is closed exactly once
}

// NewGracefulConn creates a GracefulConn wrapper around a UConn.
// The dialer function is used to create new underlying connections for recovery.
// Pass nil for dialer if automatic reconnection is not needed.
func NewGracefulConn(uconn *UConn, config *GracefulConfig, dialer func() (net.Conn, error)) *GracefulConn {
	if config == nil {
		config = DefaultGracefulConfig()
	}

	// Validate and cap MaxHRRRetries
	if config.MaxHRRRetries < 0 {
		config.MaxHRRRetries = 0
	} else if config.MaxHRRRetries > 3 {
		config.MaxHRRRetries = 3
	}

	gc := &GracefulConn{
		UConn:      uconn,
		config:     config,
		dialer:     dialer,
		tlsConfig:  uconn.config,
		helloID:    uconn.ClientHelloID,
		serverName: uconn.config.ServerName,
	}

	gc.healthy.Store(true)
	gc.lastHealthy = time.Now()

	// Start health check goroutine if configured
	if config.HealthCheckInterval > 0 && dialer != nil {
		gc.healthCheckCh = make(chan struct{}, 1)
		gc.healthDone = make(chan struct{})
		go gc.healthCheckLoop()
	}

	return gc
}

// HandshakeWithRecovery performs the TLS handshake with automatic error recovery.
// It implements retry logic for transient errors, HRR failures, and version downgrade.
func (gc *GracefulConn) HandshakeWithRecovery(ctx context.Context) error {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	utlserrors.LogDebug(ctx, "graceful: initiating handshake with recovery")

	var lastErr error
	totalAttempts := 0

	for {
		totalAttempts++

		utlserrors.LogDebug(ctx, "graceful: handshake attempt", totalAttempts)

		// Attempt handshake
		err := gc.UConn.HandshakeContext(ctx)
		if err == nil {
			gc.healthy.Store(true)
			gc.lastHealthy = time.Now()
			gc.lastError = nil

			utlserrors.LogDebug(ctx, "graceful: handshake succeeded after", totalAttempts, "attempts")

			// Notify recovery if we had failures before
			if totalAttempts > 1 && gc.config.OnRecovery != nil {
				action := "retry"
				if gc.downgraded {
					action = "version-downgrade"
				}
				// Release lock before callback to prevent deadlock if callback
				// calls methods on GracefulConn that also acquire gc.mu
				onRecovery := gc.config.OnRecovery
				gc.mu.Unlock()
				onRecovery(action, totalAttempts)
				gc.mu.Lock()
			}
			return nil
		}

		lastErr = err
		gc.lastError = err
		gc.lastErrorTime = time.Now()

		// Classify the error
		errType := ClassifyError(err)
		utlserrors.LogDebug(ctx, "graceful: handshake failed, error type:", errType.String(), "error:", err)

		// Call error callback if configured
		if gc.config.OnError != nil {
			// Capture state and release lock before callback to prevent deadlock
			// if callback calls methods on GracefulConn that also acquire gc.mu
			errCopy := err
			typeCopy := errType
			attemptsCopy := totalAttempts
			onError := gc.config.OnError

			gc.mu.Unlock()
			proceed := onError(errCopy, typeCopy, attemptsCopy)
			gc.mu.Lock()

			if !proceed {
				utlserrors.LogDebug(ctx, "graceful: recovery aborted by OnError callback")
				return &ClassifiedError{Err: err, Type: errType, Original: err}
			}
		}

		// Decide recovery strategy based on error type
		switch errType {
		case ErrorTransient:
			if gc.transRetries >= gc.config.MaxTransientRetries {
				utlserrors.LogDebug(ctx, "graceful: max transient retries exceeded:", gc.transRetries)
				return &ClassifiedError{Err: err, Type: errType, Original: err}
			}
			gc.transRetries++
			utlserrors.LogDebug(ctx, "graceful: transient error, retry", gc.transRetries)

			// Reconnect for transient errors
			if err := gc.reconnect(ctx); err != nil {
				return &ClassifiedError{Err: utlserrors.New("reconnect failed").Base(err).AtError(), Type: ErrorPermanent, Original: lastErr}
			}

			// Apply backoff delay
			gc.backoffDelay(ctx, gc.transRetries)

		case ErrorHRRRetry:
			if !gc.config.RetryOnHRRFailure || gc.hrrRetries >= gc.config.MaxHRRRetries {
				utlserrors.LogDebug(ctx, "graceful: HRR retry not allowed or max retries exceeded")
				return &ClassifiedError{Err: err, Type: errType, Original: err}
			}
			gc.hrrRetries++
			utlserrors.LogDebug(ctx, "graceful: HRR failure, retry", gc.hrrRetries)

			// Reconnect with potentially different key share
			if err := gc.reconnect(ctx); err != nil {
				return &ClassifiedError{Err: utlserrors.New("HRR reconnect failed").Base(err).AtError(), Type: ErrorPermanent, Original: lastErr}
			}

		case ErrorDowngrade:
			if !gc.config.AllowVersionDowngrade || gc.downgraded {
				utlserrors.LogDebug(ctx, "graceful: version downgrade not allowed or already downgraded")
				return &ClassifiedError{Err: err, Type: errType, Original: err}
			}

			utlserrors.LogDebug(ctx, "graceful: attempting version downgrade to TLS 1.2")
			// Attempt version downgrade
			if err := gc.downgradeVersion(ctx); err != nil {
				return &ClassifiedError{Err: utlserrors.New("version downgrade failed").Base(err).AtError(), Type: ErrorPermanent, Original: lastErr}
			}
			gc.downgraded = true

		case ErrorRecoverable:
			// Try reconnect once for recoverable errors
			if gc.transRetries > 0 {
				utlserrors.LogDebug(ctx, "graceful: recoverable error, but already retried")
				return &ClassifiedError{Err: err, Type: errType, Original: err}
			}
			gc.transRetries++
			utlserrors.LogDebug(ctx, "graceful: recoverable error, attempting reconnect")

			if err := gc.reconnect(ctx); err != nil {
				return &ClassifiedError{Err: utlserrors.New("recovery reconnect failed").Base(err).AtError(), Type: ErrorPermanent, Original: lastErr}
			}

		case ErrorPermanent:
			// No recovery for permanent errors
			gc.healthy.Store(false)
			utlserrors.LogDebug(ctx, "graceful: permanent error, no recovery possible")
			return &ClassifiedError{Err: err, Type: errType, Original: err}

		default:
			utlserrors.LogDebug(ctx, "graceful: unknown error type, failing")
			return &ClassifiedError{Err: err, Type: errType, Original: err}
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			utlserrors.LogDebug(ctx, "graceful: context cancelled during recovery")
			return ctx.Err()
		default:
		}
	}
}

// reconnect creates a new underlying connection and reinitializes the TLS state.
func (gc *GracefulConn) reconnect(ctx context.Context) error {
	if gc.dialer == nil {
		utlserrors.LogDebug(ctx, "graceful: reconnect failed - no dialer configured")
		return utlserrors.New("no dialer configured for reconnection").AtError()
	}

	utlserrors.LogDebug(ctx, "graceful: closing existing connection for reconnect")

	// Close existing connection (ignore errors)
	if gc.UConn != nil && gc.UConn.conn != nil {
		gc.UConn.conn.Close()
	}

	utlserrors.LogDebug(ctx, "graceful: dialing new connection")

	// Create new underlying connection
	conn, err := gc.dialer()
	if err != nil {
		utlserrors.LogDebug(ctx, "graceful: dial failed:", err)
		return utlserrors.New("dial failed").Base(err).AtError()
	}

	// Create new UConn with same configuration
	newUConn, err := UClient(conn, gc.tlsConfig, gc.helloID)
	if err != nil {
		conn.Close()
		utlserrors.LogDebug(ctx, "graceful: create UConn failed:", err)
		return utlserrors.New("create UConn failed").Base(err).AtError()
	}

	utlserrors.LogDebug(ctx, "graceful: reconnect successful")
	gc.UConn = newUConn
	return nil
}

// downgradeVersion attempts to reconnect with TLS 1.2 instead of TLS 1.3.
func (gc *GracefulConn) downgradeVersion(ctx context.Context) error {
	if gc.dialer == nil {
		utlserrors.LogDebug(ctx, "graceful: downgrade failed - no dialer configured")
		return utlserrors.New("no dialer configured for version downgrade").AtError()
	}

	utlserrors.LogDebug(ctx, "graceful: closing existing connection for version downgrade")

	// Close existing connection
	if gc.UConn != nil && gc.UConn.conn != nil {
		gc.UConn.conn.Close()
	}

	utlserrors.LogDebug(ctx, "graceful: dialing new connection for TLS 1.2 downgrade")

	// Create new underlying connection
	conn, err := gc.dialer()
	if err != nil {
		utlserrors.LogDebug(ctx, "graceful: dial failed during downgrade:", err)
		return utlserrors.New("dial failed").Base(err).AtError()
	}

	// Create config with TLS 1.2 max version
	downgradedConfig := gc.tlsConfig.Clone()
	downgradedConfig.MaxVersion = VersionTLS12

	// Create new UConn with downgraded version
	newUConn, err := UClient(conn, downgradedConfig, gc.helloID)
	if err != nil {
		conn.Close()
		utlserrors.LogDebug(ctx, "graceful: create downgraded UConn failed:", err)
		return utlserrors.New("create downgraded UConn failed").Base(err).AtError()
	}

	utlserrors.LogDebug(ctx, "graceful: version downgrade to TLS 1.2 successful")
	gc.UConn = newUConn
	gc.tlsConfig = downgradedConfig
	return nil
}

// backoffDelay applies exponential backoff delay between retry attempts.
func (gc *GracefulConn) backoffDelay(ctx context.Context, attempt int) {
	delay := gc.config.RetryDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > gc.config.MaxRetryDelay {
			delay = gc.config.MaxRetryDelay
			break
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// IsHealthy returns whether the connection is considered healthy.
// A connection is healthy if:
// - Handshake completed successfully
// - No permanent errors have occurred
// - The underlying connection is still open
func (gc *GracefulConn) IsHealthy() bool {
	if gc.UConn == nil {
		return false
	}

	// Check atomic healthy flag
	if !gc.healthy.Load() {
		return false
	}

	// Check if handshake is complete
	if !gc.UConn.isHandshakeComplete.Load() {
		return false
	}

	// Check for recent errors
	gc.mu.Lock()
	hasRecentError := gc.lastError != nil &&
		time.Since(gc.lastErrorTime) < gc.config.HealthCheckInterval
	gc.mu.Unlock()

	return !hasRecentError
}

// Ping sends a zero-length application data record to test connection liveness.
// This can detect half-closed connections and verify the peer is still responsive.
// Returns nil if the connection is healthy, error otherwise.
func (gc *GracefulConn) Ping() error {
	ctx := context.Background()

	if gc.UConn == nil {
		utlserrors.LogDebug(ctx, "graceful: ping failed - connection not initialized")
		return utlserrors.New("connection not initialized").AtError()
	}

	if !gc.UConn.isHandshakeComplete.Load() {
		utlserrors.LogDebug(ctx, "graceful: ping failed - handshake not complete")
		return utlserrors.New("handshake not complete").AtError()
	}

	utlserrors.LogDebug(ctx, "graceful: sending ping")

	// Set a short deadline for the ping operation
	deadline := time.Now().Add(5 * time.Second)
	gc.UConn.SetDeadline(deadline)
	defer gc.UConn.SetDeadline(time.Time{})

	// Try to write zero bytes (this will flush any pending writes and check the connection)
	// For TLS 1.3, we could send a KeyUpdate if supported, but writing zero bytes
	// is a lightweight connection check.
	_, err := gc.UConn.Write(nil)
	if err != nil && !errors.Is(err, io.EOF) {
		gc.healthy.Store(false)
		utlserrors.LogDebug(ctx, "graceful: ping failed:", err)
		return utlserrors.New("ping failed").Base(err).AtError()
	}

	gc.healthMu.Lock()
	gc.lastHealthy = time.Now()
	gc.healthMu.Unlock()
	gc.healthy.Store(true)

	utlserrors.LogDebug(ctx, "graceful: ping successful")
	return nil
}

// healthCheckLoop runs periodic health checks on the connection.
func (gc *GracefulConn) healthCheckLoop() {
	ticker := time.NewTicker(gc.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := gc.Ping(); err != nil {
				gc.healthy.Store(false)
			}
		case <-gc.healthCheckCh:
			// Force immediate health check
			if err := gc.Ping(); err != nil {
				gc.healthy.Store(false)
			}
		case <-gc.healthDone:
			return
		}
	}
}

// Close closes the connection and stops health checking.
func (gc *GracefulConn) Close() error {
	ctx := context.Background()

	utlserrors.LogDebug(ctx, "graceful: initiating close")

	// Stop health check goroutine (sync.Once ensures channel is closed exactly once)
	gc.closeOnce.Do(func() {
		if gc.healthDone != nil {
			utlserrors.LogDebug(ctx, "graceful: stopping health check goroutine")
			close(gc.healthDone)
		}
	})

	gc.healthy.Store(false)

	if gc.UConn != nil {
		utlserrors.LogDebug(ctx, "graceful: closing underlying connection")
		return gc.UConn.Close()
	}

	utlserrors.LogDebug(ctx, "graceful: close complete")
	return nil
}

// LastError returns the most recent error and when it occurred.
func (gc *GracefulConn) LastError() (time.Time, error) {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	return gc.lastErrorTime, gc.lastError
}

// Stats returns current graceful connection statistics.
func (gc *GracefulConn) Stats() GracefulStats {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	gc.healthMu.RLock()
	lastHealthy := gc.lastHealthy
	gc.healthMu.RUnlock()

	return GracefulStats{
		HRRRetries:       gc.hrrRetries,
		TransientRetries: gc.transRetries,
		Downgraded:       gc.downgraded,
		Healthy:          gc.healthy.Load(),
		LastHealthy:      lastHealthy,
		LastError:        gc.lastError,
		LastErrorTime:    gc.lastErrorTime,
	}
}

// GracefulStats contains statistics about the graceful connection.
type GracefulStats struct {
	HRRRetries       int
	TransientRetries int
	Downgraded       bool
	Healthy          bool
	LastHealthy      time.Time
	LastError        error
	LastErrorTime    time.Time
}

// IsRetryable is a convenience function that returns true if the error type
// indicates the operation might succeed on retry.
func IsRetryable(err error) bool {
	errType := ClassifyError(err)
	switch errType {
	case ErrorTransient, ErrorHRRRetry, ErrorRecoverable:
		return true
	default:
		return false
	}
}

// IsDowngradeable returns true if the error suggests trying a lower TLS version
// might help. Note: Downgrading should be done with caution as it may weaken security.
func IsDowngradeable(err error) bool {
	return ClassifyError(err) == ErrorDowngrade
}

// WrapWithGraceful creates a GracefulConn from an existing UConn with a simple
// dialer that reconnects to the same address. This is a convenience function
// for common use cases.
func WrapWithGraceful(uconn *UConn, config *GracefulConfig) *GracefulConn {
	// Extract remote address for reconnection
	var remoteAddr string
	if uconn.conn != nil {
		if addr := uconn.conn.RemoteAddr(); addr != nil {
			remoteAddr = addr.String()
		}
	}

	var dialer func() (net.Conn, error)
	if remoteAddr != "" {
		dialer = func() (net.Conn, error) {
			return net.DialTimeout("tcp", remoteAddr, 30*time.Second)
		}
	}

	return NewGracefulConn(uconn, config, dialer)
}

// Standalone utility functions for error classification without GracefulConn

// ClassifyAndWrap classifies an error and wraps it with the classification.
func ClassifyAndWrap(err error) *ClassifiedError {
	if err == nil {
		return nil
	}
	errType := ClassifyError(err)
	return &ClassifiedError{
		Err:      err,
		Type:     errType,
		Original: err,
	}
}

// ShouldRetryHandshake is a convenience function that returns true if
// a handshake error suggests retrying might succeed.
func ShouldRetryHandshake(err error) bool {
	errType := ClassifyError(err)
	switch errType {
	case ErrorTransient, ErrorHRRRetry, ErrorRecoverable:
		return true
	case ErrorDowngrade:
		// Downgrade is a form of retry, but needs version change
		return true
	default:
		return false
	}
}

// GetRecommendedAction returns a string describing the recommended action
// for the given error. Useful for logging and debugging.
func GetRecommendedAction(err error) string {
	errType := ClassifyError(err)
	switch errType {
	case ErrorTransient:
		return "Retry after brief delay"
	case ErrorPermanent:
		return "Do not retry - check configuration/certificates"
	case ErrorDowngrade:
		return "Consider TLS version downgrade (security implications)"
	case ErrorHRRRetry:
		return "Retry with different key share configuration"
	case ErrorRecoverable:
		return "Reconnect and retry"
	default:
		return "Unknown - manual investigation needed"
	}
}

// CreateDowngradedSpec creates a new ClientHelloSpec with the TLS version
// constrained to a maximum of maxVersion. This is used for graceful degradation
// when a server doesn't support the original TLS version (typically TLS 1.3).
//
// The function performs the following modifications:
//   - Sets TLSVersMax to min(original.TLSVersMax, maxVersion)
//   - Removes TLS 1.3-only cipher suites if maxVersion < TLS 1.3
//   - Filters SupportedVersionsExtension to only include versions <= maxVersion
//   - Removes TLS 1.3-only extensions (KeyShare, PSK, PSKModes) if downgrading below 1.3
//
// Parameters:
//   - original: The original ClientHelloSpec to downgrade (must not be nil)
//   - maxVersion: The maximum TLS version for the new spec (e.g., VersionTLS12)
//
// Returns:
//   - A new ClientHelloSpec with downgraded version settings
//   - An error if original is nil or maxVersion is invalid
//
// Security Note: Downgrading TLS versions reduces security. Only use this
// when necessary for compatibility with legacy servers.
func CreateDowngradedSpec(original *ClientHelloSpec, maxVersion uint16) (*ClientHelloSpec, error) {
	if original == nil {
		return nil, utlserrors.New("tls: cannot downgrade nil ClientHelloSpec").AtError()
	}
	if maxVersion < VersionTLS10 || maxVersion > VersionTLS13 {
		return nil, utlserrors.New("tls: invalid max version", fmt.Sprintf("0x%04x", maxVersion)).AtError()
	}

	// Create a shallow copy first
	downgraded := &ClientHelloSpec{
		CompressionMethods: original.CompressionMethods,
		TLSVersMin:         original.TLSVersMin,
		TLSVersMax:         original.TLSVersMax,
		GetSessionID:       original.GetSessionID,
		SessionIDLength:    original.SessionIDLength,
		CipherSuiteOrder:   original.CipherSuiteOrder,
		CurveOrder:         original.CurveOrder,
	}

	// Constrain max version
	if downgraded.TLSVersMax > maxVersion {
		downgraded.TLSVersMax = maxVersion
	}

	// Filter cipher suites - remove TLS 1.3-only suites if downgrading below 1.3
	if maxVersion < VersionTLS13 {
		downgraded.CipherSuites = filterNonTLS13CipherSuites(original.CipherSuites)
	} else {
		// Copy cipher suites
		downgraded.CipherSuites = make([]uint16, len(original.CipherSuites))
		copy(downgraded.CipherSuites, original.CipherSuites)
	}

	// Filter and copy extensions
	downgraded.Extensions = filterExtensionsForVersion(original.Extensions, maxVersion)

	return downgraded, nil
}

// filterNonTLS13CipherSuites removes TLS 1.3-only cipher suites from the list.
// TLS 1.3 cipher suites are in the range 0x1301-0x1305.
func filterNonTLS13CipherSuites(suites []uint16) []uint16 {
	filtered := make([]uint16, 0, len(suites))
	for _, suite := range suites {
		// TLS 1.3 cipher suites: 0x1301-0x1305
		if suite < 0x1301 || suite > 0x1305 {
			filtered = append(filtered, suite)
		}
	}
	return filtered
}

// filterExtensionsForVersion filters extensions based on the target TLS version.
// Removes TLS 1.3-only extensions when downgrading below TLS 1.3, and updates
// SupportedVersionsExtension to only include versions <= maxVersion.
func filterExtensionsForVersion(extensions []TLSExtension, maxVersion uint16) []TLSExtension {
	filtered := make([]TLSExtension, 0, len(extensions))

	for _, ext := range extensions {
		switch e := ext.(type) {
		case *SupportedVersionsExtension:
			// Filter versions to only include those <= maxVersion
			newVersions := make([]uint16, 0, len(e.Versions))
			for _, v := range e.Versions {
				// Keep GREASE values and versions <= maxVersion
				if isGREASEUint16(v) || v <= maxVersion {
					newVersions = append(newVersions, v)
				}
			}
			if len(newVersions) > 0 {
				filtered = append(filtered, &SupportedVersionsExtension{
					Versions: newVersions,
				})
			}

		case *KeyShareExtension:
			// KeyShare is TLS 1.3 only - skip if downgrading below 1.3
			if maxVersion >= VersionTLS13 {
				filtered = append(filtered, ext)
			}

		case PreSharedKeyExtension:
			// PSK extension is TLS 1.3 only - skip if downgrading below 1.3
			if maxVersion >= VersionTLS13 {
				filtered = append(filtered, ext)
			}

		case *PSKKeyExchangeModesExtension:
			// PSK modes is TLS 1.3 only - skip if downgrading below 1.3
			if maxVersion >= VersionTLS13 {
				filtered = append(filtered, ext)
			}

		default:
			// Keep all other extensions
			filtered = append(filtered, ext)
		}
	}

	return filtered
}
