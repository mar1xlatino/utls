// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/x509"
	"sync"
	"time"
)

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
}

// DefaultHooks returns an empty hooks structure with no callbacks.
func DefaultHooks() *FingerprintHooks {
	return &FingerprintHooks{}
}

// Clone creates a shallow copy of the hooks structure.
// Note: Function callbacks are copied by reference, not cloned. If your
// callbacks capture mutable state via closures, the clone and original
// will share that state. This is intentional - function values cannot
// be deep-copied in Go.
func (h *FingerprintHooks) Clone() *FingerprintHooks {
	if h == nil {
		return nil
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

	return merged
}

// Chain chains multiple hooks together for a single callback.
// The chained function calls each hook in order, stopping on error.
// HookChain is thread-safe for concurrent Add and Call operations.
type HookChain struct {
	hooks []*FingerprintHooks
	mu    sync.RWMutex
}

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
func (c *HookChain) Add(hook *FingerprintHooks) {
	if c == nil || hook == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hooks = append(c.hooks, hook)
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
func (c *HookChain) CallProfileSelected(profile *FingerprintProfile) error {
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
// The first hook that returns modified data or an error stops the chain.
func (c *HookChain) CallBeforeWriteRecord(rt recordType, data []byte) ([]byte, int, error) {
	for _, h := range c.getHooks() {
		if h != nil && h.OnBeforeWriteRecord != nil {
			modData, padding, err := h.OnBeforeWriteRecord(rt, data)
			if err != nil {
				return nil, 0, err
			}
			if modData != nil {
				return modData, padding, nil
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
// Nil listeners are ignored.
func (m *FingerprintMonitor) AddListener(listener FingerprintEventListener) {
	if listener == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, listener)
}

// Emit emits an event.
func (m *FingerprintMonitor) Emit(eventType FingerprintEventType, data interface{}) {
	event := FingerprintEvent{
		Type:      eventType,
		Timestamp: time.Now().UnixNano(),
		Data:      data,
	}

	m.mu.Lock()
	// Store event
	if len(m.events) >= m.maxEvents {
		m.events = m.events[1:]
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

// Events returns collected events.
func (m *FingerprintMonitor) Events() []FingerprintEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]FingerprintEvent, len(m.events))
	copy(result, m.events)
	return result
}

// Clear clears collected events.
func (m *FingerprintMonitor) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}

// ToHooks converts the monitor to FingerprintHooks.
// All generated hooks handle nil inputs gracefully.
func (m *FingerprintMonitor) ToHooks() *FingerprintHooks {
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
func LoggingHooks(logFunc func(format string, args ...interface{})) *FingerprintHooks {
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
