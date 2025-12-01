// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// ErrHookPanic wraps a panic that occurred in a hook callback.
type ErrHookPanic struct {
	Hook  string
	Panic interface{}
}

func (e *ErrHookPanic) Error() string {
	return fmt.Sprintf("tls: hook %s panicked: %v", e.Hook, e.Panic)
}

// SessionTicketData represents modifiable session ticket parameters.
// Used by OnBeforeSessionTicketSend hook to customize ticket fields.
type SessionTicketData struct {
	// Lifetime is the ticket lifetime in seconds (default: 7 days).
	Lifetime uint32
	// AgeAdd is the obfuscated age addition value.
	AgeAdd uint32
	// Nonce is the ticket nonce (typically increments 0, 1 for 2 tickets).
	Nonce []byte
	// Label is the ticket label (encrypted ticket data).
	Label []byte
	// MaxEarlyData is the maximum early data size (0 to disable).
	MaxEarlyData uint32
}

// FingerprintHooks allows external code to hook into fingerprint operations.
// These hooks enable integrators to monitor, validate, and customize
// fingerprint behavior at various points in the TLS handshake.
type FingerprintHooks struct {
	// Profile Hooks

	// OnProfileSelected is called when a profile is selected for a connection.
	// Return an error to abort the connection.
	OnProfileSelected func(profile *FingerprintProfile) error

	// OnSessionStateCreated is called when new session state is created.
	OnSessionStateCreated func(state *SessionFingerprintState) error

	// OnSessionStateRestored is called when session state is restored from cache.
	OnSessionStateRestored func(state *SessionFingerprintState) error

	// ClientHello Hooks

	// OnBeforeBuildClientHello is called before ClientHello is built.
	// The profile can be modified in this hook.
	OnBeforeBuildClientHello func(profile *FingerprintProfile) error

	// OnAfterBuildClientHello is called after ClientHello is built.
	// Receives the built message and raw bytes.
	OnAfterBuildClientHello func(hello *clientHelloMsg, raw []byte) error

	// OnClientHelloBuilt is called with computed fingerprints.
	OnClientHelloBuilt func(hello *clientHelloMsg, fp *TLSFingerprint) error

	// OnClientHelloValidation is called after fingerprint validation.
	// Return an error to abort if validation failed.
	OnClientHelloValidation func(result *ValidationResult) error

	// ServerHello Hooks

	// OnServerHelloReceived is called when ServerHello is received.
	OnServerHelloReceived func(hello *serverHelloMsg, raw []byte, fp *ServerHelloFingerprint) error

	// OnBeforeSendServerHello is called before sending ServerHello (server-side).
	OnBeforeSendServerHello func(hello *serverHelloMsg) error

	// OnAfterSendServerHello is called after sending ServerHello (server-side).
	OnAfterSendServerHello func(hello *serverHelloMsg, raw []byte) error

	// Certificate Hooks

	// OnCertificatesReceived is called when certificates are received.
	OnCertificatesReceived func(certs []*x509.Certificate, fps []*CertificateFingerprint) error

	// OnCertificateValidation is called after certificate fingerprint validation.
	OnCertificateValidation func(result *ValidationResult) error

	// Record Layer Hooks

	// OnBeforeWriteRecord is called before writing a record.
	// Returns modified data and padding to add.
	OnBeforeWriteRecord func(recordType recordType, data []byte) ([]byte, int, error)

	// OnAfterReadRecord is called after reading a record.
	OnAfterReadRecord func(recordType recordType, data []byte) error

	// Session Hooks

	// OnSessionTicketReceived is called when a session ticket is received.
	OnSessionTicketReceived func(ticket []byte) error

	// OnResumptionAttempt is called when attempting session resumption.
	OnResumptionAttempt func(state *SessionFingerprintState) error

	// Handshake Hooks

	// OnHandshakeStart is called when handshake begins.
	OnHandshakeStart func() error

	// OnHandshakeComplete is called when handshake completes successfully.
	OnHandshakeComplete func(state ConnectionState, fp *TLSConnectionFingerprint) error

	// OnHandshakeError is called when handshake fails.
	OnHandshakeError func(err error) error

	// Monitoring Hooks

	// OnFingerprintComputed is called whenever a fingerprint is computed.
	OnFingerprintComputed func(fpType string, fingerprint string) error

	// OnValidationFailure is called when any validation fails.
	OnValidationFailure func(what string, result *ValidationResult) error

	// === SESSION ID HOOKS ===

	// OnBeforeSessionIDGeneration is called before session ID is generated.
	// Return non-nil []byte to use custom session ID (must be 32 bytes for TLS 1.3).
	// Return nil to use default random generation.
	OnBeforeSessionIDGeneration func(config *Config) []byte

	// OnSessionIDGenerated is called after session ID is set.
	OnSessionIDGenerated func(sessionID []byte)

	// === CERTIFICATE GENERATION HOOKS ===

	// OnBeforeCertificateGeneration is called before ephemeral cert creation.
	// Modify template in-place to customize certificate fields.
	OnBeforeCertificateGeneration func(template *x509.Certificate, hostname string)

	// OnAfterCertificateGeneration is called after cert is created but before use.
	// Return error to reject certificate and fail handshake.
	OnAfterCertificateGeneration func(cert *x509.Certificate, privateKey crypto.PrivateKey) error

	// OnBeforeCertificateSign is called before certificate is signed.
	// Return custom signature bytes to override default signing.
	// Return nil to use default signing.
	OnBeforeCertificateSign func(cert *x509.Certificate, signatureAlgorithm x509.SignatureAlgorithm) []byte

	// === SERVERHELLO BUILDER HOOKS ===

	// OnBeforeServerHelloBuild is called before ServerHello is constructed.
	// Modify builder in-place to customize ServerHello fields.
	OnBeforeServerHelloBuild func(builder *ServerHelloBuilder, clientHello *ClientHelloInfo)

	// OnServerHelloBuilt is called after ServerHello is built but before sending.
	// Return modified bytes to replace ServerHello, or nil to use default.
	OnServerHelloBuilt func(serverHello []byte) []byte

	// OnBeforeServerHelloSend is called just before ServerHello is written.
	// Last chance to inspect/log the exact bytes being sent.
	OnBeforeServerHelloSend func(serverHello []byte)

	// === EXTENSION HOOKS ===

	// OnBeforeExtensionsBuild is called before extensions are marshaled.
	// Modify extensions slice in-place to add/remove/reorder extensions.
	OnBeforeExtensionsBuild func(extensions *[]TLSExtension, isClientHello bool)

	// OnExtensionData allows injecting custom data into specific extension.
	// Return nil to use default extension data.
	OnExtensionData func(extType uint16, isClientHello bool) []byte

	// === ALPN HOOKS ===

	// OnBeforeALPNNegotiation is called before ALPN selection.
	// Return selected protocol to override, or empty string for default.
	OnBeforeALPNNegotiation func(clientProtocols []string, serverProtocols []string) string

	// OnALPNNegotiated is called after ALPN is selected.
	OnALPNNegotiated func(selectedProtocol string)

	// === KEY GENERATION HOOKS ===

	// OnBeforeKeyGeneration is called before ephemeral key generation.
	// Return custom key pair to override, or nil for default generation.
	OnBeforeKeyGeneration func(group CurveID) (publicKey, privateKey []byte)

	// OnKeyGenerated is called after ephemeral key is generated.
	OnKeyGenerated func(group CurveID, publicKey []byte)

	// === HELLO RETRY REQUEST HOOKS ===

	// OnBeforeHelloRetryRequest is called before HRR is sent.
	// Modify fields to customize HRR. Return false to skip HRR.
	OnBeforeHelloRetryRequest func(selectedGroup CurveID, cookie []byte) bool

	// OnHelloRetryRequestSent is called after HRR is sent.
	OnHelloRetryRequestSent func(hrrBytes []byte)

	// OnClientHelloAfterHRR is called when second ClientHello is received.
	OnClientHelloAfterHRR func(clientHello *ClientHelloInfo)

	// === SESSION TICKET HOOKS ===

	// OnBeforeSessionTicketSend is called before each session ticket is sent.
	// Modify ticket data in-place. Return false to skip this ticket.
	OnBeforeSessionTicketSend func(ticketNum int, ticketData *SessionTicketData) bool

	// OnSessionTicketCount allows customizing number of tickets to send.
	// Return -1 for default (usually 2 for browser mimicry).
	OnSessionTicketCount func() int

	// === AUTHENTICATION HOOKS ===

	// OnAuthenticationData is called to get authentication data.
	// Return auth data to embed in session ID or certificate.
	OnAuthenticationData func(config *Config) []byte

	// OnAuthenticationVerify is called to verify client authentication.
	// Return nil error if authentication succeeds.
	OnAuthenticationVerify func(authData []byte, expected []byte) error

	// OnAuthenticationSuccess is called when authentication succeeds.
	OnAuthenticationSuccess func(remoteAddr string, authData []byte)

	// OnAuthenticationFailure is called when authentication fails.
	OnAuthenticationFailure func(remoteAddr string, reason string)

	// === EARLY DATA (0-RTT) HOOKS ===

	// OnEarlyDataWrite is called before early data is encrypted.
	// Return modified data or nil to use original.
	OnEarlyDataWrite func(data []byte) []byte

	// OnEarlyDataAccepted is called when server accepts 0-RTT.
	OnEarlyDataAccepted func()

	// OnEarlyDataRejected is called when server rejects 0-RTT.
	// The buffered data that needs resending is provided.
	OnEarlyDataRejected func(bufferedData []byte)
}

// DefaultHooks returns an empty hooks structure with no callbacks.
func DefaultHooks() *FingerprintHooks {
	return &FingerprintHooks{}
}

// Clone creates a shallow copy of the hooks structure.
// Returns empty hooks if receiver is nil (never returns nil).
// Note: Function callbacks are copied by reference, not cloned. If your
// callbacks capture mutable state via closures, the clone and original
// will share that state. This is intentional - function values cannot
// be deep-copied in Go.
func (h *FingerprintHooks) Clone() *FingerprintHooks {
	if h == nil {
		return &FingerprintHooks{}
	}
	clone := *h
	return &clone
}

// Merge combines two hook structures, with other taking precedence.
func (h *FingerprintHooks) Merge(other *FingerprintHooks) *FingerprintHooks {
	if h == nil {
		return other.Clone()
	}
	if other == nil {
		return h.Clone()
	}

	merged := h.Clone()

	if other.OnProfileSelected != nil {
		merged.OnProfileSelected = other.OnProfileSelected
	}
	if other.OnSessionStateCreated != nil {
		merged.OnSessionStateCreated = other.OnSessionStateCreated
	}
	if other.OnSessionStateRestored != nil {
		merged.OnSessionStateRestored = other.OnSessionStateRestored
	}
	if other.OnBeforeBuildClientHello != nil {
		merged.OnBeforeBuildClientHello = other.OnBeforeBuildClientHello
	}
	if other.OnAfterBuildClientHello != nil {
		merged.OnAfterBuildClientHello = other.OnAfterBuildClientHello
	}
	if other.OnClientHelloBuilt != nil {
		merged.OnClientHelloBuilt = other.OnClientHelloBuilt
	}
	if other.OnClientHelloValidation != nil {
		merged.OnClientHelloValidation = other.OnClientHelloValidation
	}
	if other.OnServerHelloReceived != nil {
		merged.OnServerHelloReceived = other.OnServerHelloReceived
	}
	if other.OnBeforeSendServerHello != nil {
		merged.OnBeforeSendServerHello = other.OnBeforeSendServerHello
	}
	if other.OnAfterSendServerHello != nil {
		merged.OnAfterSendServerHello = other.OnAfterSendServerHello
	}
	if other.OnCertificatesReceived != nil {
		merged.OnCertificatesReceived = other.OnCertificatesReceived
	}
	if other.OnCertificateValidation != nil {
		merged.OnCertificateValidation = other.OnCertificateValidation
	}
	if other.OnBeforeWriteRecord != nil {
		merged.OnBeforeWriteRecord = other.OnBeforeWriteRecord
	}
	if other.OnAfterReadRecord != nil {
		merged.OnAfterReadRecord = other.OnAfterReadRecord
	}
	if other.OnSessionTicketReceived != nil {
		merged.OnSessionTicketReceived = other.OnSessionTicketReceived
	}
	if other.OnResumptionAttempt != nil {
		merged.OnResumptionAttempt = other.OnResumptionAttempt
	}
	if other.OnHandshakeStart != nil {
		merged.OnHandshakeStart = other.OnHandshakeStart
	}
	if other.OnHandshakeComplete != nil {
		merged.OnHandshakeComplete = other.OnHandshakeComplete
	}
	if other.OnHandshakeError != nil {
		merged.OnHandshakeError = other.OnHandshakeError
	}
	if other.OnFingerprintComputed != nil {
		merged.OnFingerprintComputed = other.OnFingerprintComputed
	}
	if other.OnValidationFailure != nil {
		merged.OnValidationFailure = other.OnValidationFailure
	}

	// Session ID hooks
	if other.OnBeforeSessionIDGeneration != nil {
		merged.OnBeforeSessionIDGeneration = other.OnBeforeSessionIDGeneration
	}
	if other.OnSessionIDGenerated != nil {
		merged.OnSessionIDGenerated = other.OnSessionIDGenerated
	}

	// Certificate generation hooks
	if other.OnBeforeCertificateGeneration != nil {
		merged.OnBeforeCertificateGeneration = other.OnBeforeCertificateGeneration
	}
	if other.OnAfterCertificateGeneration != nil {
		merged.OnAfterCertificateGeneration = other.OnAfterCertificateGeneration
	}
	if other.OnBeforeCertificateSign != nil {
		merged.OnBeforeCertificateSign = other.OnBeforeCertificateSign
	}

	// ServerHello builder hooks
	if other.OnBeforeServerHelloBuild != nil {
		merged.OnBeforeServerHelloBuild = other.OnBeforeServerHelloBuild
	}
	if other.OnServerHelloBuilt != nil {
		merged.OnServerHelloBuilt = other.OnServerHelloBuilt
	}
	if other.OnBeforeServerHelloSend != nil {
		merged.OnBeforeServerHelloSend = other.OnBeforeServerHelloSend
	}

	// Extension hooks
	if other.OnBeforeExtensionsBuild != nil {
		merged.OnBeforeExtensionsBuild = other.OnBeforeExtensionsBuild
	}
	if other.OnExtensionData != nil {
		merged.OnExtensionData = other.OnExtensionData
	}

	// ALPN hooks
	if other.OnBeforeALPNNegotiation != nil {
		merged.OnBeforeALPNNegotiation = other.OnBeforeALPNNegotiation
	}
	if other.OnALPNNegotiated != nil {
		merged.OnALPNNegotiated = other.OnALPNNegotiated
	}

	// Key generation hooks
	if other.OnBeforeKeyGeneration != nil {
		merged.OnBeforeKeyGeneration = other.OnBeforeKeyGeneration
	}
	if other.OnKeyGenerated != nil {
		merged.OnKeyGenerated = other.OnKeyGenerated
	}

	// HRR hooks
	if other.OnBeforeHelloRetryRequest != nil {
		merged.OnBeforeHelloRetryRequest = other.OnBeforeHelloRetryRequest
	}
	if other.OnHelloRetryRequestSent != nil {
		merged.OnHelloRetryRequestSent = other.OnHelloRetryRequestSent
	}
	if other.OnClientHelloAfterHRR != nil {
		merged.OnClientHelloAfterHRR = other.OnClientHelloAfterHRR
	}

	// Session ticket hooks
	if other.OnBeforeSessionTicketSend != nil {
		merged.OnBeforeSessionTicketSend = other.OnBeforeSessionTicketSend
	}
	if other.OnSessionTicketCount != nil {
		merged.OnSessionTicketCount = other.OnSessionTicketCount
	}

	// Authentication hooks
	if other.OnAuthenticationData != nil {
		merged.OnAuthenticationData = other.OnAuthenticationData
	}
	if other.OnAuthenticationVerify != nil {
		merged.OnAuthenticationVerify = other.OnAuthenticationVerify
	}
	if other.OnAuthenticationSuccess != nil {
		merged.OnAuthenticationSuccess = other.OnAuthenticationSuccess
	}
	if other.OnAuthenticationFailure != nil {
		merged.OnAuthenticationFailure = other.OnAuthenticationFailure
	}

	// Early data hooks
	if other.OnEarlyDataWrite != nil {
		merged.OnEarlyDataWrite = other.OnEarlyDataWrite
	}
	if other.OnEarlyDataAccepted != nil {
		merged.OnEarlyDataAccepted = other.OnEarlyDataAccepted
	}
	if other.OnEarlyDataRejected != nil {
		merged.OnEarlyDataRejected = other.OnEarlyDataRejected
	}

	return merged
}

// Chain chains multiple hooks together for a single callback.
// The chained function calls each hook in order, stopping on error.
// HookChain is thread-safe for concurrent Add and Call operations.
type HookChain struct {
	hooks    []*FingerprintHooks
	mu       sync.RWMutex
	maxHooks int // Maximum hooks allowed (0 = default 100)
}

// MaxHooksDefault is the default maximum number of hooks in a chain.
const MaxHooksDefault = 100

// ErrHookChainFull is returned when adding to a full hook chain.
var ErrHookChainFull = fmt.Errorf("tls: hook chain capacity exceeded")

// NewHookChain creates a new hook chain.
// Nil hooks in the input are filtered out for consistency with Add().
func NewHookChain(hooks ...*FingerprintHooks) *HookChain {
	// Filter nil hooks to be consistent with Add() behavior
	filtered := make([]*FingerprintHooks, 0, len(hooks))
	for _, h := range hooks {
		if h != nil {
			filtered = append(filtered, h)
		}
	}
	return &HookChain{hooks: filtered}
}

// Add adds a hook to the chain.
// Nil hooks are ignored. Safe to call on nil receiver.
// Returns error if chain is at capacity.
func (c *HookChain) Add(hook *FingerprintHooks) error {
	if c == nil || hook == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce capacity limit to prevent memory exhaustion
	maxHooks := c.maxHooks
	if maxHooks <= 0 {
		maxHooks = MaxHooksDefault
	}
	if len(c.hooks) >= maxHooks {
		return ErrHookChainFull
	}

	c.hooks = append(c.hooks, hook)
	return nil
}

// SetMaxHooks sets the maximum number of hooks allowed.
// Zero uses the default (100). Negative values are treated as unlimited.
func (c *HookChain) SetMaxHooks(max int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxHooks = max
}

// Remove removes a hook from the chain by pointer comparison.
// Returns true if the hook was found and removed.
// Order is preserved to maintain correct hook execution sequence.
// Safe to call on nil receiver.
func (c *HookChain) Remove(hook *FingerprintHooks) bool {
	if c == nil || hook == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, h := range c.hooks {
		if h == hook {
			// Preserve order: shift elements left instead of swap
			// Clear the last element for garbage collection
			copy(c.hooks[i:], c.hooks[i+1:])
			c.hooks[len(c.hooks)-1] = nil // Clear reference for GC
			c.hooks = c.hooks[:len(c.hooks)-1]
			return true
		}
	}
	return false
}

// Clear removes all hooks from the chain.
// Safe to call on nil receiver.
func (c *HookChain) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Clear all references for garbage collection
	for i := range c.hooks {
		c.hooks[i] = nil
	}
	c.hooks = nil
}

// Len returns the number of hooks in the chain.
// Safe to call on nil receiver (returns 0).
func (c *HookChain) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.hooks)
}

// getHooks returns a snapshot of hooks for safe iteration.
// Safe to call on nil receiver (returns nil).
func (c *HookChain) getHooks() []*FingerprintHooks {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*FingerprintHooks, len(c.hooks))
	copy(result, c.hooks)
	return result
}

// CallProfileSelected calls OnProfileSelected on all hooks.
// Recovers from panics in hook callbacks and returns them as errors.
func (c *HookChain) CallProfileSelected(profile *FingerprintProfile) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &ErrHookPanic{Hook: "OnProfileSelected", Panic: r}
		}
	}()
	for _, h := range c.getHooks() {
		if h != nil && h.OnProfileSelected != nil {
			if err := h.OnProfileSelected(profile); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallSessionStateCreated calls OnSessionStateCreated on all hooks.
func (c *HookChain) CallSessionStateCreated(state *SessionFingerprintState) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnSessionStateCreated != nil {
			if err := h.OnSessionStateCreated(state); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallSessionStateRestored calls OnSessionStateRestored on all hooks.
func (c *HookChain) CallSessionStateRestored(state *SessionFingerprintState) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnSessionStateRestored != nil {
			if err := h.OnSessionStateRestored(state); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallBeforeBuildClientHello calls OnBeforeBuildClientHello on all hooks.
func (c *HookChain) CallBeforeBuildClientHello(profile *FingerprintProfile) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeBuildClientHello != nil {
			if err := h.OnBeforeBuildClientHello(profile); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallAfterBuildClientHello calls OnAfterBuildClientHello on all hooks.
func (c *HookChain) CallAfterBuildClientHello(hello *clientHelloMsg, raw []byte) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAfterBuildClientHello != nil {
			if err := h.OnAfterBuildClientHello(hello, raw); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallClientHelloBuilt calls OnClientHelloBuilt on all hooks.
func (c *HookChain) CallClientHelloBuilt(hello *clientHelloMsg, fp *TLSFingerprint) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnClientHelloBuilt != nil {
			if err := h.OnClientHelloBuilt(hello, fp); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallClientHelloValidation calls OnClientHelloValidation on all hooks.
func (c *HookChain) CallClientHelloValidation(result *ValidationResult) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnClientHelloValidation != nil {
			if err := h.OnClientHelloValidation(result); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallServerHelloReceived calls OnServerHelloReceived on all hooks.
func (c *HookChain) CallServerHelloReceived(hello *serverHelloMsg, raw []byte, fp *ServerHelloFingerprint) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnServerHelloReceived != nil {
			if err := h.OnServerHelloReceived(hello, raw, fp); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallBeforeSendServerHello calls OnBeforeSendServerHello on all hooks.
func (c *HookChain) CallBeforeSendServerHello(hello *serverHelloMsg) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeSendServerHello != nil {
			if err := h.OnBeforeSendServerHello(hello); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallAfterSendServerHello calls OnAfterSendServerHello on all hooks.
func (c *HookChain) CallAfterSendServerHello(hello *serverHelloMsg, raw []byte) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAfterSendServerHello != nil {
			if err := h.OnAfterSendServerHello(hello, raw); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallCertificatesReceived calls OnCertificatesReceived on all hooks.
func (c *HookChain) CallCertificatesReceived(certs []*x509.Certificate, fps []*CertificateFingerprint) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnCertificatesReceived != nil {
			if err := h.OnCertificatesReceived(certs, fps); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallCertificateValidation calls OnCertificateValidation on all hooks.
func (c *HookChain) CallCertificateValidation(result *ValidationResult) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnCertificateValidation != nil {
			if err := h.OnCertificateValidation(result); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallBeforeWriteRecord calls OnBeforeWriteRecord on all hooks.
// Returns the possibly modified data, padding amount, and any error.
// The first hook that returns modified data, non-zero padding, or an error stops the chain.
// Recovers from panics in hook callbacks and returns them as errors.
func (c *HookChain) CallBeforeWriteRecord(rt recordType, data []byte) (modData []byte, padding int, err error) {
	defer func() {
		if r := recover(); r != nil {
			modData, padding, err = nil, 0, &ErrHookPanic{Hook: "OnBeforeWriteRecord", Panic: r}
		}
	}()
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeWriteRecord != nil {
			md, p, e := h.OnBeforeWriteRecord(rt, data)
			if e != nil {
				return nil, 0, e
			}
			// Return if data modified OR padding requested (fix: don't lose padding)
			if md != nil || p > 0 {
				if md == nil {
					md = data // Use original data with requested padding
				}
				return md, p, nil
			}
		}
	}
	return data, 0, nil
}

// CallAfterReadRecord calls OnAfterReadRecord on all hooks.
func (c *HookChain) CallAfterReadRecord(rt recordType, data []byte) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAfterReadRecord != nil {
			if err := h.OnAfterReadRecord(rt, data); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallSessionTicketReceived calls OnSessionTicketReceived on all hooks.
func (c *HookChain) CallSessionTicketReceived(ticket []byte) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnSessionTicketReceived != nil {
			if err := h.OnSessionTicketReceived(ticket); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallResumptionAttempt calls OnResumptionAttempt on all hooks.
func (c *HookChain) CallResumptionAttempt(state *SessionFingerprintState) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnResumptionAttempt != nil {
			if err := h.OnResumptionAttempt(state); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallHandshakeStart calls OnHandshakeStart on all hooks.
func (c *HookChain) CallHandshakeStart() error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnHandshakeStart != nil {
			if err := h.OnHandshakeStart(); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallHandshakeComplete calls OnHandshakeComplete on all hooks.
func (c *HookChain) CallHandshakeComplete(state ConnectionState, fp *TLSConnectionFingerprint) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnHandshakeComplete != nil {
			if err := h.OnHandshakeComplete(state, fp); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallHandshakeError calls OnHandshakeError on all hooks.
func (c *HookChain) CallHandshakeError(err error) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnHandshakeError != nil {
			if herr := h.OnHandshakeError(err); herr != nil {
				return herr
			}
		}
	}
	return nil
}

// CallFingerprintComputed calls OnFingerprintComputed on all hooks.
func (c *HookChain) CallFingerprintComputed(fpType, fingerprint string) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnFingerprintComputed != nil {
			if err := h.OnFingerprintComputed(fpType, fingerprint); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallValidationFailure calls OnValidationFailure on all hooks.
func (c *HookChain) CallValidationFailure(what string, result *ValidationResult) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnValidationFailure != nil {
			if err := h.OnValidationFailure(what, result); err != nil {
				return err
			}
		}
	}
	return nil
}

// === SESSION ID HOOKS ===

// CallBeforeSessionIDGeneration calls OnBeforeSessionIDGeneration on all hooks.
// Returns the first non-nil custom session ID, or nil for default.
func (c *HookChain) CallBeforeSessionIDGeneration(config *Config) []byte {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeSessionIDGeneration != nil {
			if id := h.OnBeforeSessionIDGeneration(config); id != nil {
				return id
			}
		}
	}
	return nil
}

// CallSessionIDGenerated calls OnSessionIDGenerated on all hooks.
func (c *HookChain) CallSessionIDGenerated(sessionID []byte) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnSessionIDGenerated != nil {
			h.OnSessionIDGenerated(sessionID)
		}
	}
}

// === CERTIFICATE GENERATION HOOKS ===

// CallBeforeCertificateGeneration calls OnBeforeCertificateGeneration on all hooks.
func (c *HookChain) CallBeforeCertificateGeneration(template *x509.Certificate, hostname string) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeCertificateGeneration != nil {
			h.OnBeforeCertificateGeneration(template, hostname)
		}
	}
}

// CallAfterCertificateGeneration calls OnAfterCertificateGeneration on all hooks.
func (c *HookChain) CallAfterCertificateGeneration(cert *x509.Certificate, privateKey crypto.PrivateKey) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAfterCertificateGeneration != nil {
			if err := h.OnAfterCertificateGeneration(cert, privateKey); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallBeforeCertificateSign calls OnBeforeCertificateSign on all hooks.
// Returns the first non-nil custom signature, or nil for default signing.
func (c *HookChain) CallBeforeCertificateSign(cert *x509.Certificate, sigAlgo x509.SignatureAlgorithm) []byte {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeCertificateSign != nil {
			if sig := h.OnBeforeCertificateSign(cert, sigAlgo); sig != nil {
				return sig
			}
		}
	}
	return nil
}

// === SERVERHELLO BUILDER HOOKS ===

// CallBeforeServerHelloBuild calls OnBeforeServerHelloBuild on all hooks.
func (c *HookChain) CallBeforeServerHelloBuild(builder *ServerHelloBuilder, clientHello *ClientHelloInfo) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeServerHelloBuild != nil {
			h.OnBeforeServerHelloBuild(builder, clientHello)
		}
	}
}

// CallServerHelloBuilt calls OnServerHelloBuilt on all hooks.
// Returns the first non-nil modified bytes, or nil to use default.
func (c *HookChain) CallServerHelloBuilt(serverHello []byte) []byte {
	for _, h := range c.getHooks() {
		if h != nil && h.OnServerHelloBuilt != nil {
			if modified := h.OnServerHelloBuilt(serverHello); modified != nil {
				return modified
			}
		}
	}
	return nil
}

// CallBeforeServerHelloSend calls OnBeforeServerHelloSend on all hooks.
func (c *HookChain) CallBeforeServerHelloSend(serverHello []byte) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeServerHelloSend != nil {
			h.OnBeforeServerHelloSend(serverHello)
		}
	}
}

// === EXTENSION HOOKS ===

// CallBeforeExtensionsBuild calls OnBeforeExtensionsBuild on all hooks.
func (c *HookChain) CallBeforeExtensionsBuild(extensions *[]TLSExtension, isClientHello bool) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeExtensionsBuild != nil {
			h.OnBeforeExtensionsBuild(extensions, isClientHello)
		}
	}
}

// CallExtensionData calls OnExtensionData on all hooks.
// Returns the first non-nil custom data, or nil for default.
func (c *HookChain) CallExtensionData(extType uint16, isClientHello bool) []byte {
	for _, h := range c.getHooks() {
		if h != nil && h.OnExtensionData != nil {
			if data := h.OnExtensionData(extType, isClientHello); data != nil {
				return data
			}
		}
	}
	return nil
}

// === ALPN HOOKS ===

// CallBeforeALPNNegotiation calls OnBeforeALPNNegotiation on all hooks.
// Returns the first non-empty protocol override, or empty string for default.
func (c *HookChain) CallBeforeALPNNegotiation(clientProtocols, serverProtocols []string) string {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeALPNNegotiation != nil {
			if proto := h.OnBeforeALPNNegotiation(clientProtocols, serverProtocols); proto != "" {
				return proto
			}
		}
	}
	return ""
}

// CallALPNNegotiated calls OnALPNNegotiated on all hooks.
func (c *HookChain) CallALPNNegotiated(selectedProtocol string) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnALPNNegotiated != nil {
			h.OnALPNNegotiated(selectedProtocol)
		}
	}
}

// === KEY GENERATION HOOKS ===

// CallBeforeKeyGeneration calls OnBeforeKeyGeneration on all hooks.
// Returns the first valid key pair (both non-nil), or (nil, nil) for default generation.
// Security: Both public AND private key must be non-nil to be accepted.
// Recovers from panics and returns (nil, nil) to allow default key generation.
func (c *HookChain) CallBeforeKeyGeneration(group CurveID) (publicKey, privateKey []byte) {
	defer func() {
		if r := recover(); r != nil {
			// On panic, return nil to use default key generation
			publicKey, privateKey = nil, nil
		}
	}()
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeKeyGeneration != nil {
			pub, priv := h.OnBeforeKeyGeneration(group)
			// Security: Require BOTH keys to be non-nil to prevent crypto failures
			if pub != nil && priv != nil {
				return pub, priv
			}
		}
	}
	return nil, nil
}

// CallKeyGenerated calls OnKeyGenerated on all hooks.
func (c *HookChain) CallKeyGenerated(group CurveID, publicKey []byte) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnKeyGenerated != nil {
			h.OnKeyGenerated(group, publicKey)
		}
	}
}

// === HRR HOOKS ===

// CallBeforeHelloRetryRequest calls OnBeforeHelloRetryRequest on all hooks.
// Returns false if any hook returns false (to skip HRR).
func (c *HookChain) CallBeforeHelloRetryRequest(selectedGroup CurveID, cookie []byte) bool {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeHelloRetryRequest != nil {
			if !h.OnBeforeHelloRetryRequest(selectedGroup, cookie) {
				return false
			}
		}
	}
	return true
}

// CallHelloRetryRequestSent calls OnHelloRetryRequestSent on all hooks.
func (c *HookChain) CallHelloRetryRequestSent(hrrBytes []byte) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnHelloRetryRequestSent != nil {
			h.OnHelloRetryRequestSent(hrrBytes)
		}
	}
}

// CallClientHelloAfterHRR calls OnClientHelloAfterHRR on all hooks.
func (c *HookChain) CallClientHelloAfterHRR(clientHello *ClientHelloInfo) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnClientHelloAfterHRR != nil {
			h.OnClientHelloAfterHRR(clientHello)
		}
	}
}

// === SESSION TICKET HOOKS ===

// CallBeforeSessionTicketSend calls OnBeforeSessionTicketSend on all hooks.
// Returns false if any hook returns false (to skip this ticket).
func (c *HookChain) CallBeforeSessionTicketSend(ticketNum int, ticketData *SessionTicketData) bool {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeSessionTicketSend != nil {
			if !h.OnBeforeSessionTicketSend(ticketNum, ticketData) {
				return false
			}
		}
	}
	return true
}

// CallSessionTicketCount calls OnSessionTicketCount on all hooks.
// Returns the first non-negative count, or -1 for default.
func (c *HookChain) CallSessionTicketCount() int {
	for _, h := range c.getHooks() {
		if h != nil && h.OnSessionTicketCount != nil {
			if count := h.OnSessionTicketCount(); count >= 0 {
				return count
			}
		}
	}
	return -1
}

// === AUTHENTICATION HOOKS ===

// CallAuthenticationData calls OnAuthenticationData on all hooks.
// Returns the first non-nil auth data, or nil.
func (c *HookChain) CallAuthenticationData(config *Config) []byte {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAuthenticationData != nil {
			if data := h.OnAuthenticationData(config); data != nil {
				return data
			}
		}
	}
	return nil
}

// CallAuthenticationVerify calls OnAuthenticationVerify on all hooks.
func (c *HookChain) CallAuthenticationVerify(authData, expected []byte) error {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAuthenticationVerify != nil {
			if err := h.OnAuthenticationVerify(authData, expected); err != nil {
				return err
			}
		}
	}
	return nil
}

// CallAuthenticationSuccess calls OnAuthenticationSuccess on all hooks.
func (c *HookChain) CallAuthenticationSuccess(remoteAddr string, authData []byte) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAuthenticationSuccess != nil {
			h.OnAuthenticationSuccess(remoteAddr, authData)
		}
	}
}

// CallAuthenticationFailure calls OnAuthenticationFailure on all hooks.
func (c *HookChain) CallAuthenticationFailure(remoteAddr string, reason string) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnAuthenticationFailure != nil {
			h.OnAuthenticationFailure(remoteAddr, reason)
		}
	}
}

// === EARLY DATA HOOKS ===

// CallEarlyDataWrite calls OnEarlyDataWrite on all hooks.
// Returns the first non-nil modified data, or nil to use original.
func (c *HookChain) CallEarlyDataWrite(data []byte) []byte {
	for _, h := range c.getHooks() {
		if h != nil && h.OnEarlyDataWrite != nil {
			if modified := h.OnEarlyDataWrite(data); modified != nil {
				return modified
			}
		}
	}
	return nil
}

// CallEarlyDataAccepted calls OnEarlyDataAccepted on all hooks.
func (c *HookChain) CallEarlyDataAccepted() {
	for _, h := range c.getHooks() {
		if h != nil && h.OnEarlyDataAccepted != nil {
			h.OnEarlyDataAccepted()
		}
	}
}

// CallEarlyDataRejected calls OnEarlyDataRejected on all hooks.
func (c *HookChain) CallEarlyDataRejected(bufferedData []byte) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnEarlyDataRejected != nil {
			h.OnEarlyDataRejected(bufferedData)
		}
	}
}

// FingerprintEventType represents different fingerprint events.
type FingerprintEventType int

const (
	EventProfileSelected FingerprintEventType = iota
	EventSessionCreated
	EventSessionRestored
	EventClientHelloBuilt
	EventServerHelloReceived
	EventCertificatesReceived
	EventHandshakeComplete
	EventHandshakeError
	EventValidationFailed
)

// FingerprintEvent represents a fingerprint-related event.
type FingerprintEvent struct {
	Type      FingerprintEventType
	Timestamp int64
	Data      interface{}
}

// FingerprintEventListener is a callback for fingerprint events.
type FingerprintEventListener func(event FingerprintEvent)

// FingerprintMonitor collects fingerprint events for analysis.
// FingerprintMonitor is thread-safe for concurrent operations.
type FingerprintMonitor struct {
	listeners []FingerprintEventListener
	events    []FingerprintEvent
	maxEvents int
	mu        sync.RWMutex
}

// NewFingerprintMonitor creates a new monitor.
func NewFingerprintMonitor(maxEvents int) *FingerprintMonitor {
	if maxEvents <= 0 {
		maxEvents = 1000
	}
	return &FingerprintMonitor{
		maxEvents: maxEvents,
	}
}

// AddListener adds an event listener.
// Nil listeners and nil receivers are ignored.
func (m *FingerprintMonitor) AddListener(listener FingerprintEventListener) {
	if m == nil || listener == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// Emit emits an event. Nil receiver is ignored.
func (m *FingerprintMonitor) Emit(eventType FingerprintEventType, data interface{}) {
	if m == nil {
		return
	}
	event := FingerprintEvent{
		Type:      eventType,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}

	m.mu.Lock()
	// Store event with proper memory management
	if len(m.events) >= m.maxEvents {
		// Create new slice to avoid memory leak from reslicing
		// Reslicing (m.events[1:]) keeps old backing array alive
		newEvents := make([]FingerprintEvent, len(m.events)-1, m.maxEvents)
		copy(newEvents, m.events[1:])
		m.events = newEvents
	}
	m.events = append(m.events, event)

	// Copy listeners for notification outside lock
	listeners := make([]FingerprintEventListener, len(m.listeners))
	copy(listeners, m.listeners)
	m.mu.Unlock()

	// Notify listeners outside lock to prevent deadlocks
	for _, listener := range listeners {
		if listener != nil {
			listener(event)
		}
	}
}

// Events returns collected events. Returns nil for nil receiver.
func (m *FingerprintMonitor) Events() []FingerprintEvent {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]FingerprintEvent, len(m.events))
	copy(result, m.events)
	return result
}

// Clear clears collected events. Nil receiver is ignored.
func (m *FingerprintMonitor) Clear() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}

// ToHooks converts the monitor to FingerprintHooks.
// All generated hooks handle nil inputs gracefully.
// Returns empty hooks for nil receiver.
func (m *FingerprintMonitor) ToHooks() *FingerprintHooks {
	if m == nil {
		return &FingerprintHooks{}
	}
	return &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			var id string
			if profile != nil {
				id = profile.ID
			}
			m.Emit(EventProfileSelected, id)
			return nil
		},
		OnSessionStateCreated: func(state *SessionFingerprintState) error {
			var id string
			if state != nil {
				id = state.ID
			}
			m.Emit(EventSessionCreated, id)
			return nil
		},
		OnSessionStateRestored: func(state *SessionFingerprintState) error {
			var id string
			if state != nil {
				id = state.ID
			}
			m.Emit(EventSessionRestored, id)
			return nil
		},
		OnClientHelloBuilt: func(hello *clientHelloMsg, fp *TLSFingerprint) error {
			m.Emit(EventClientHelloBuilt, fp)
			return nil
		},
		OnServerHelloReceived: func(hello *serverHelloMsg, raw []byte, fp *ServerHelloFingerprint) error {
			m.Emit(EventServerHelloReceived, fp)
			return nil
		},
		OnCertificatesReceived: func(certs []*x509.Certificate, fps []*CertificateFingerprint) error {
			m.Emit(EventCertificatesReceived, fps)
			return nil
		},
		OnHandshakeComplete: func(state ConnectionState, fp *TLSConnectionFingerprint) error {
			m.Emit(EventHandshakeComplete, fp)
			return nil
		},
		OnHandshakeError: func(err error) error {
			m.Emit(EventHandshakeError, err)
			return nil
		},
		OnValidationFailure: func(what string, result *ValidationResult) error {
			m.Emit(EventValidationFailed, map[string]interface{}{
				"what":   what,
				"result": result,
			})
			return nil
		},
	}
}

// LoggingHooks returns hooks that log all events.
// All hooks handle nil inputs gracefully.
// Returns empty hooks if logFunc is nil.
func LoggingHooks(logFunc func(format string, args ...interface{})) *FingerprintHooks {
	if logFunc == nil {
		return &FingerprintHooks{}
	}
	return &FingerprintHooks{
		OnProfileSelected: func(profile *FingerprintProfile) error {
			if profile == nil {
				logFunc("profile selected: <nil>")
			} else {
				logFunc("profile selected: %s", profile.ID)
			}
			return nil
		},
		OnSessionStateCreated: func(state *SessionFingerprintState) error {
			if state == nil {
				logFunc("session state created: <nil>")
			} else {
				logFunc("session state created: %s for %s", state.ID, state.Origin)
			}
			return nil
		},
		OnClientHelloBuilt: func(hello *clientHelloMsg, fp *TLSFingerprint) error {
			if fp == nil {
				logFunc("ClientHello built: JA4=<nil>")
			} else {
				logFunc("ClientHello built: JA4=%s", fp.JA4)
			}
			return nil
		},
		OnServerHelloReceived: func(hello *serverHelloMsg, raw []byte, fp *ServerHelloFingerprint) error {
			if fp == nil {
				logFunc("ServerHello received: JA4S=<nil>")
			} else {
				logFunc("ServerHello received: JA4S=%s", fp.JA4S)
			}
			return nil
		},
		OnHandshakeComplete: func(state ConnectionState, fp *TLSConnectionFingerprint) error {
			logFunc("handshake complete: version=%s cipher=%04x", VersionName(state.Version), state.CipherSuite)
			return nil
		},
		OnHandshakeError: func(err error) error {
			logFunc("handshake error: %v", err)
			return nil
		},
	}
}
