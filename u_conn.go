// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/utls/memcontrol"
)

// ClientHelloBuildStatus tracks whether and how the ClientHello has been built.
// This is used internally to prevent double-building and to track the building method.
type ClientHelloBuildStatus int

const (
	// NotBuilt indicates the ClientHello has not yet been built.
	NotBuilt ClientHelloBuildStatus = 0
	// BuildByUtls indicates the ClientHello was built using uTLS extension mechanism.
	BuildByUtls ClientHelloBuildStatus = 1
	// BuildByGoTLS indicates the ClientHello was built using standard Go TLS.
	BuildByGoTLS ClientHelloBuildStatus = 2
)

// ErrExtensionsLocked is returned when attempting to modify Extensions after
// BuildHandshakeState() has been called. This prevents race conditions between
// user code modifying Extensions and the handshake goroutine iterating over it.
var ErrExtensionsLocked = errors.New("tls: cannot modify extensions after BuildHandshakeState() has been called")

// UConn is the main uTLS connection type, embedding the standard crypto/tls Conn
// with additional fingerprinting capabilities. It allows mimicking the TLS fingerprint
// of various browsers and clients.
//
// Create a UConn using UClient() for regular TCP connections or UQUICClient() for QUIC.
// Configure the fingerprint by selecting a ClientHelloID (e.g., HelloChrome_120,
// HelloFirefox_145) or by manually configuring Extensions for HelloCustom.
//
// Example:
//
//	conn, _ := net.Dial("tcp", "example.com:443")
//	uconn, err := tls.UClient(conn, &tls.Config{ServerName: "example.com"}, tls.HelloChrome_120)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if err := uconn.Handshake(); err != nil {
//	    log.Fatal(err)
//	}
type UConn struct {
	*Conn

	// Extensions contains the TLS extensions to be sent in the ClientHello.
	// WARNING: Do not modify Extensions after BuildHandshakeState() or Handshake()
	// has been called. Doing so will result in ErrExtensionsLocked being returned
	// from methods like SetSNI(). Use ExtensionsLocked() to check if modifications
	// are still allowed.
	Extensions        []TLSExtension
	ClientHelloID     ClientHelloID
	sessionController *sessionController

	clientHelloBuildStatus ClientHelloBuildStatus
	clientHelloSpec        *ClientHelloSpec

	HandshakeState PubClientHandshakeState

	greaseSeed [ssl_grease_last_index]uint16

	omitSNIExtension bool

	// skipResumptionOnNilExtension is copied from `Config.PreferSkipResumptionOnNilExtension`.
	//
	// By default, if ClientHelloSpec is predefined or utls-generated (as opposed to HelloCustom), this flag will be updated to true.
	skipResumptionOnNilExtension bool

	// certCompressionAlgs represents the set of advertised certificate compression
	// algorithms, as specified in the ClientHello. This is only relevant client-side, for the
	// server certificate. All other forms of certificate compression are unsupported.
	certCompressionAlgs []CertCompressionAlgo

	// ech extension is a shortcut to the ECH extension in the Extensions slice if there is one.
	ech ECHExtension

	// stateMu protects rawServerHello from concurrent access.
	// This field is written during handshake and read after handshake completes.
	// Using RWMutex allows concurrent reads while ensuring exclusive writes.
	stateMu sync.RWMutex

	// echCtx is the echContext returned by makeClientHello()
	// Protected by atomic.Pointer for lock-free thread-safe access.
	// Use echCtx.Load() to read and echCtx.Store() to write.
	echCtx atomic.Pointer[echClientContext]

	// rawServerHello stores the raw ServerHello bytes for JA4S calculation.
	// Captured during handshake when serverHello is received.
	// Protected by stateMu - use setRawServerHello/getRawServerHello for access.
	rawServerHello []byte

	// earlyData tracks 0-RTT early data state for this connection.
	earlyData *EarlyDataState

	// extensionsLocked prevents modification of Extensions after BuildHandshakeState()
	// has been called. This prevents race conditions between user code modifying
	// Extensions and the handshake goroutine iterating over it.
	// Protected by extensionsMu for thread-safe access.
	extensionsLocked bool
	extensionsMu     sync.RWMutex

	// handshakeTimingConfig controls timing jitter during handshakes to resist
	// timing-based fingerprinting. When nil, no timing jitter is applied.
	// See HandshakeTimingConfig for configuration options.
	handshakeTimingConfig *HandshakeTimingConfig

	// handshakeTimeouts configures per-phase timeouts for the TLS handshake.
	// When nil, no per-phase timeouts are applied (relies on context deadline).
	// See HandshakeTimeouts for configuration options.
	handshakeTimeouts *HandshakeTimeouts

	// handshakeProgressCallback is called during handshake to report progress.
	// Can be used for progress indicators or logging.
	handshakeProgressCallback HandshakeProgressCallback

	// handshakeTimeoutCtrl is the timeout controller for the current handshake.
	// Protected by handshakeMutex (only accessed during handshake).
	handshakeTimeoutCtrl *handshakeTimeoutController
}

// UClient returns a new uTLS client, with behavior depending on clientHelloID.
//
// The conn parameter must be non-nil for regular TLS usage. Passing nil will
// return an error. For QUIC usage where the connection is managed by the QUIC
// layer, use UQUICClient() instead.
//
// Config can be nil but then ServerName must be set before handshake, or
// InsecureSkipVerify must be true. If config is provided with empty ServerName
// and InsecureSkipVerify=false, an error is returned immediately.
//
// Returns an error if:
//   - conn is nil (for non-QUIC usage)
//   - config has empty ServerName and InsecureSkipVerify is false
func UClient(conn net.Conn, config *Config, clientHelloID ClientHelloID) (*UConn, error) {
	if conn == nil {
		return nil, errors.New("tls: UClient requires non-nil connection for non-QUIC usage; for QUIC, use UQUICClient instead")
	}
	// Validate config requirements early to provide clear error messages.
	// Either ServerName must be set for hostname verification, or InsecureSkipVerify
	// must be true to skip verification entirely. InsecureServerNameToVerify is also
	// accepted as an alternative for advanced use cases (e.g., fingerprint spoofing).
	// Note: nil config is allowed and will be initialized later, with validation
	// occurring during handshake when ServerName could be set via SetSNI().
	if config != nil && len(config.ServerName) == 0 && !config.InsecureSkipVerify && len(config.InsecureServerNameToVerify) == 0 {
		return nil, errors.New("tls: either Config.ServerName must be set or Config.InsecureSkipVerify must be true")
	}
	return uClient(conn, config, clientHelloID), nil
}

// uClient is the internal constructor that allows nil conn for QUIC usage.
// This is used by UQUICClient where the connection is managed by the QUIC layer.
func uClient(conn net.Conn, config *Config, clientHelloID ClientHelloID) *UConn {
	if config == nil {
		config = &Config{}
	}

	// [uTLS] Enable TLS 1.3 record padding by default for fingerprint resistance.
	// Real browsers add 0-255 bytes of random padding per record (RFC 8446 Section 5.4).
	// This matches Chrome-like exponential distribution (~70% 0-72 bytes, ~25% 72-150, ~5% 150-255).
	// Users can disable with: config.RecordPadding = DisabledRecordPaddingConfig()
	if config.RecordPadding == nil {
		config.RecordPadding = DefaultRecordPaddingConfig()
	}

	// Optionally wrap connection with memcontrol for memory-aware tracking
	if config.EnableMemoryTracking && conn != nil {
		conn = memcontrol.WrapOrPassthrough(conn, "utls-client")
	}

	tlsConn := Conn{conn: conn, config: config, isClient: true}
	handshakeState := PubClientHandshakeState{C: &tlsConn, Hello: &PubClientHelloMsg{}}
	uconn := UConn{Conn: &tlsConn, ClientHelloID: clientHelloID, HandshakeState: handshakeState}
	uconn.HandshakeState.uconn = &uconn
	uconn.handshakeFn = uconn.clientHandshake
	uconn.sessionController = newSessionController(&uconn)
	uconn.utls.sessionController = uconn.sessionController
	uconn.skipResumptionOnNilExtension = config.PreferSkipResumptionOnNilExtension || clientHelloID.Client != helloCustom

	// [uTLS] Enable timing jitter by default for browser profiles to resist timing-based fingerprinting.
	// Real browsers have 1-20ms+ variance from CPU work, crypto operations, etc.
	// Users can disable with: uconn.SetHandshakeTimingConfig(nil)
	if uconn.handshakeTimingConfig == nil {
		uconn.handshakeTimingConfig = TimingConfigForClientHelloID(clientHelloID)
	}

	return &uconn
}

// lockExtensions marks the Extensions slice as locked, preventing further
// modifications. This is called automatically by BuildHandshakeState().
// Internal use only.
func (uconn *UConn) lockExtensions() {
	uconn.extensionsMu.Lock()
	uconn.extensionsLocked = true
	uconn.extensionsMu.Unlock()
}

// ExtensionsLocked returns true if the Extensions slice has been locked
// by BuildHandshakeState(). Once locked, methods that modify Extensions
// (like SetSNI) will return ErrExtensionsLocked.
// Thread-safe.
func (uconn *UConn) ExtensionsLocked() bool {
	uconn.extensionsMu.RLock()
	locked := uconn.extensionsLocked
	uconn.extensionsMu.RUnlock()
	return locked
}

// BuildHandshakeState behavior varies based on ClientHelloID and
// whether it was already called before.
// If HelloGolang:
//
//	[only once] make default ClientHello and overwrite existing state
//
// If any other mimicking ClientHelloID is used:
//
//	[only once] make ClientHello based on ID and overwrite existing state
//	[each call] apply uconn.Extensions config to internal crypto/tls structures
//	[each call] marshal ClientHello.
//
// BuildHandshakeState is automatically called before uTLS performs handshake,
// and should only be called explicitly to inspect/change fields of
// default/mimicked ClientHello.
// With the excpetion of session ticket and psk extensions, which cannot be changed
// after calling BuildHandshakeState, all other fields can be modified.
func (uconn *UConn) BuildHandshakeState() error {
	return uconn.buildHandshakeState(true)
}

// BuildHandshakeStateWithoutSession is the same as BuildHandshakeState, but does not
// set the session. This is only useful when you want to inspect the ClientHello before
// setting the session manually through SetSessionTicketExtension or SetPSKExtension.
// BuildHandshakeState is automatically called before uTLS performs handshake.
func (uconn *UConn) BuildHandshakeStateWithoutSession() error {
	return uconn.buildHandshakeState(false)
}

func (uconn *UConn) buildHandshakeState(loadSession bool) error {
	// Lock extensions to prevent race conditions with user code modifying Extensions
	// while we iterate over it during handshake.
	uconn.lockExtensions()

	if uconn.ClientHelloID == HelloGolang {
		if uconn.clientHelloBuildStatus == BuildByGoTLS {
			return nil
		}
		if uconn.clientHelloBuildStatus != NotBuilt {
			return errors.New("BuildHandshakeState failed: invalid call, client hello has already been built previously")
		}

		// use default Golang ClientHello.
		hello, keySharePrivate, ech, err := uconn.makeClientHello()
		if err != nil {
			return err
		}

		uconn.HandshakeState.Hello = hello.getPublicPtr()
		uconn.HandshakeState.State13.KeyShareKeys = keySharePrivate.ToPublic()
		uconn.HandshakeState.C = uconn.Conn
		uconn.echCtx.Store(ech)
		uconn.clientHelloBuildStatus = BuildByGoTLS
	} else {
		if !(uconn.clientHelloBuildStatus == BuildByUtls || uconn.clientHelloBuildStatus == NotBuilt) {
			return errors.New("BuildHandshakeState failed: invalid call, client hello has already been built by go-tls")
		}
		if uconn.clientHelloBuildStatus == NotBuilt {
			err := uconn.applyPresetByID(uconn.ClientHelloID)
			if err != nil {
				return err
			}
			if uconn.omitSNIExtension {
				uconn.removeSNIExtension()
			}
		}

		err := uconn.ApplyConfig()
		if err != nil {
			return err
		}

		if loadSession {
			err = uconn.uLoadSession()
			if err != nil {
				return err
			}
		}

		err = uconn.MarshalClientHello()
		if err != nil {
			return err
		}

		if loadSession {
			if err := uconn.uApplyPatch(); err != nil {
				return err
			}
			if err := uconn.sessionController.finalCheck(); err != nil {
				return err
			}
			uconn.clientHelloBuildStatus = BuildByUtls
		}

	}
	return nil
}

func (uconn *UConn) uLoadSession() error {
	if cfg := uconn.config; cfg.SessionTicketsDisabled || cfg.ClientSessionCache == nil {
		return nil
	}
	switch uconn.sessionController.shouldLoadSession() {
	case shouldReturn:
	case shouldSetTicket:
		if err := uconn.sessionController.setSessionTicketToUConn(); err != nil {
			return err
		}
	case shouldSetPsk:
		if err := uconn.sessionController.setPskToUConn(); err != nil {
			return err
		}
	case shouldLoad:
		hello := uconn.HandshakeState.Hello.getPrivatePtr()
		if hello == nil {
			return errors.New("tls: cannot load session - ClientHello is nil")
		}
		if err := uconn.sessionController.utlsAboutToLoadSession(); err != nil {
			return err
		}
		session, earlySecret, binderKey, err := uconn.loadSession(hello)
		if session == nil || err != nil {
			return err
		}
		if session.version == VersionTLS12 {
			// We use the session ticket extension for tls 1.2 session resumption
			if err := uconn.sessionController.initSessionTicketExt(session, hello.sessionTicket); err != nil {
				return err
			}
			if err := uconn.sessionController.setSessionTicketToUConn(); err != nil {
				return err
			}
		} else {
			if err := uconn.sessionController.initPskExt(session, earlySecret, binderKey, hello.pskIdentities); err != nil {
				return err
			}
		}
	}

	return nil
}

func (uconn *UConn) uApplyPatch() error {
	helloLen := len(uconn.HandshakeState.Hello.Raw)
	if uconn.sessionController.shouldUpdateBinders() {
		if err := uconn.sessionController.updateBinders(); err != nil {
			return err
		}
		if err := uconn.sessionController.setPskToUConn(); err != nil {
			return err
		}
	}
	if helloLen != len(uconn.HandshakeState.Hello.Raw) {
		return errors.New("tls: uApplyPatch Failed: the patch should never change the length of the marshaled clientHello")
	}
	return nil
}

// DidTls12Resume reports whether the connection was established using TLS 1.2
// session resumption. This returns true if a session ticket was successfully
// used to resume a previous session, avoiding a full handshake.
//
// Note: For TLS 1.3 connections, check ConnectionState().DidResume instead,
// as TLS 1.3 uses PSK-based resumption which is tracked differently.
func (uconn *UConn) DidTls12Resume() bool {
	return uconn.didResume
}

// SetSessionState sets the session ticket, which may be preshared or fake.
// If session is nil, the body of session ticket extension will be unset,
// but the extension itself still MAY be present for mimicking purposes.
// Session tickets to be reused - use same cache on following connections.
//
// Deprecated: This method is deprecated in favor of SetSessionTicketExtension,
// as it only handles session override of TLS 1.2
func (uconn *UConn) SetSessionState(session *ClientSessionState) error {
	sessionTicketExt := &SessionTicketExtension{Initialized: true}
	if session != nil {
		sessionTicketExt.Ticket = session.session.ticket
		sessionTicketExt.Session = session.session
	}
	return uconn.SetSessionTicketExtension(sessionTicketExt)
}

// SetSessionTicket sets the session ticket extension.
// If extension is nil, this will be a no-op.
func (uconn *UConn) SetSessionTicketExtension(sessionTicketExt ISessionTicketExtension) error {
	if uconn.config.SessionTicketsDisabled || uconn.config.ClientSessionCache == nil {
		return fmt.Errorf("tls: SetSessionTicketExtension failed: session is disabled")
	}
	if sessionTicketExt == nil {
		return nil
	}
	return uconn.sessionController.overrideSessionTicketExt(sessionTicketExt)
}

// SetPskExtension sets the psk extension for tls 1.3 resumption. This is a no-op if the psk is nil.
func (uconn *UConn) SetPskExtension(pskExt PreSharedKeyExtension) error {
	if uconn.config.SessionTicketsDisabled || uconn.config.ClientSessionCache == nil {
		return fmt.Errorf("tls: SetPskExtension failed: session is disabled")
	}
	if pskExt == nil {
		return nil
	}

	uconn.HandshakeState.Hello.TicketSupported = true
	return uconn.sessionController.overridePskExt(pskExt)
}

// If you want session tickets to be reused - use same cache on following connections
func (uconn *UConn) SetSessionCache(cache ClientSessionCache) {
	uconn.config.ClientSessionCache = cache
	uconn.HandshakeState.Hello.TicketSupported = true
}

// SetClientRandom sets client random explicitly.
// BuildHandshakeFirst() must be called before SetClientRandom.
// r must to be 32 bytes long.
func (uconn *UConn) SetClientRandom(r []byte) error {
	if len(r) != 32 {
		return errors.New("tls: invalid client random length")
	} else {
		uconn.HandshakeState.Hello.Random = make([]byte, 32)
		copy(uconn.HandshakeState.Hello.Random, r)
		return nil
	}
}

// applyCurveOrderVariation applies curve order variation based on the CurveOrderStrategy.
// This modifies supported_groups and key_share extensions to match the specified strategy.
// Called during ApplyPreset before key share generation to ensure consistency.
//
// Detection Vector Addressed:
// Report Section 1.1.8 identifies that Chrome profiles hardcode exact curve order:
// GREASE, X25519, P256, P384. Real Chrome varies order based on hardware curve support.
// Identical curve order across all connections is detectable by DPI systems.
func (uconn *UConn) applyCurveOrderVariation(strategy CurveOrderStrategy) error {
	// Skip if strategy is empty (legacy behavior) or explicitly static
	if strategy == "" || strategy == CurveOrderStatic {
		return nil
	}

	// Find SupportedCurvesExtension and KeyShareExtension
	var supportedCurves *SupportedCurvesExtension
	var keyShare *KeyShareExtension
	for _, ext := range uconn.Extensions {
		switch e := ext.(type) {
		case *SupportedCurvesExtension:
			supportedCurves = e
		case *KeyShareExtension:
			keyShare = e
		}
	}

	// If no supported curves extension, nothing to vary
	if supportedCurves == nil {
		return nil
	}

	// Determine whether to swap P256/P384
	swapP256P384 := false
	switch strategy {
	case CurveOrderAutoVariation:
		// Random swap with ~20% probability (like real Chrome hardware variation)
		var randomByte [1]byte
		if _, err := uconn.config.rand().Read(randomByte[:]); err != nil {
			return err
		}
		// 20% chance: values 0-50 out of 0-255 (approximately 20%)
		swapP256P384 = randomByte[0] < 51
	case CurveOrderP384First:
		swapP256P384 = true
	case CurveOrderP256First:
		swapP256P384 = false
	default:
		// Unknown strategy, use static behavior
		return nil
	}

	// If no swap needed, return early
	if !swapP256P384 {
		return nil
	}

	// Find and swap P256/P384 in supported curves
	p256Idx := -1
	p384Idx := -1
	for i, curve := range supportedCurves.Curves {
		if curve == CurveP256 {
			p256Idx = i
		} else if curve == CurveP384 {
			p384Idx = i
		}
	}

	// Only swap if both P256 and P384 are present and P256 comes before P384
	if p256Idx >= 0 && p384Idx >= 0 && p256Idx < p384Idx {
		supportedCurves.Curves[p256Idx], supportedCurves.Curves[p384Idx] =
			supportedCurves.Curves[p384Idx], supportedCurves.Curves[p256Idx]
	}

	// Ensure KeyShare extension matches the new curve order
	if keyShare != nil {
		p256KsIdx := -1
		p384KsIdx := -1
		for i, ks := range keyShare.KeyShares {
			if ks.Group == CurveP256 {
				p256KsIdx = i
			} else if ks.Group == CurveP384 {
				p384KsIdx = i
			}
		}

		// Only swap in key_shares if both are present and P256 comes before P384
		if p256KsIdx >= 0 && p384KsIdx >= 0 && p256KsIdx < p384KsIdx {
			keyShare.KeyShares[p256KsIdx], keyShare.KeyShares[p384KsIdx] =
				keyShare.KeyShares[p384KsIdx], keyShare.KeyShares[p256KsIdx]
		}
	}

	return nil
}

// SetSNI sets the Server Name Indication extension to the specified hostname.
// This must be called before BuildHandshakeState() or Handshake().
// Returns ErrExtensionsLocked if called after BuildHandshakeState().
//
// Thread-safe: Uses extensionsMu to prevent TOCTOU race conditions between
// the lock check and modification. The mutex is held for the entire operation
// to ensure atomicity with respect to lockExtensions() calls from handshake.
//
// Note: This method does not validate the hostname format. For browser-compliant
// validation, use SetSNIWithValidation instead.
func (uconn *UConn) SetSNI(sni string) error {
	// Hold lock for entire operation to prevent TOCTOU race:
	// Without this, another goroutine could call lockExtensions() between
	// our check and modification, allowing us to modify Extensions while
	// the handshake iterates over it.
	uconn.extensionsMu.Lock()
	defer uconn.extensionsMu.Unlock()

	if uconn.extensionsLocked {
		return ErrExtensionsLocked
	}
	hname := hostnameInSNI(sni)
	uconn.config.ServerName = hname
	for _, ext := range uconn.Extensions {
		sniExt, ok := ext.(*SNIExtension)
		if ok {
			sniExt.ServerName = hname
		}
	}
	return nil
}

// SetSNIWithValidation sets the SNI after validating and normalizing the hostname.
// This matches browser behavior for hostname validation, which helps prevent
// DPI detection via malformed SNI probing.
//
// Validation includes:
//   - Maximum 253 characters total
//   - Maximum 63 characters per label
//   - Valid characters: a-z, A-Z, 0-9, hyphen
//   - No hyphen at start/end of labels
//   - No trailing dot (stripped automatically)
//   - IP addresses rejected
//   - IDN domains converted to Punycode
//
// Thread-safe: Uses extensionsMu to prevent TOCTOU race conditions between
// the lock check and modification. The mutex is held for the entire modification
// operation to ensure atomicity with respect to lockExtensions() calls from handshake.
//
// Returns ErrExtensionsLocked if called after BuildHandshakeState().
// Returns SNIValidationError if the hostname is invalid.
func (uconn *UConn) SetSNIWithValidation(sni string) error {
	// Validate and normalize the hostname BEFORE acquiring lock
	// (validation doesn't access Extensions, so no need to hold lock)
	normalized, err := ValidateAndNormalizeSNI(sni)
	if err != nil {
		return err
	}

	// Use hostnameInSNI for final processing (handles IP check, trailing dots)
	hname := hostnameInSNI(normalized)
	if len(hname) == 0 {
		return &SNIValidationError{Hostname: sni, Reason: "hostname resolved to empty after processing"}
	}

	// Hold lock for check and modification to prevent TOCTOU race:
	// Without this, another goroutine could call lockExtensions() between
	// our check and modification, allowing us to modify Extensions while
	// the handshake iterates over it.
	uconn.extensionsMu.Lock()
	defer uconn.extensionsMu.Unlock()

	if uconn.extensionsLocked {
		return ErrExtensionsLocked
	}

	uconn.config.ServerName = hname
	for _, ext := range uconn.Extensions {
		sniExt, ok := ext.(*SNIExtension)
		if ok {
			sniExt.ServerName = hname
		}
	}
	return nil
}

// RemoveSNIExtension removes SNI from the list of extensions sent in ClientHello
// It returns an error when used with HelloGolang ClientHelloID
func (uconn *UConn) RemoveSNIExtension() error {
	if uconn.ClientHelloID == HelloGolang {
		return fmt.Errorf("cannot call RemoveSNIExtension on a UConn with a HelloGolang ClientHelloID")
	}
	uconn.omitSNIExtension = true
	return nil
}

func (uconn *UConn) removeSNIExtension() {
	filteredExts := make([]TLSExtension, 0, len(uconn.Extensions))
	for _, e := range uconn.Extensions {
		if _, ok := e.(*SNIExtension); !ok {
			filteredExts = append(filteredExts, e)
		}
	}
	uconn.Extensions = filteredExts
}

// Handshake runs the client handshake using given clientHandshakeState
// Requires hs.hello, and, optionally, hs.session to be set.
func (c *UConn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the client or server handshake
// protocol if it has not yet been run.
//
// The provided Context must be non-nil. If the context is canceled before
// the handshake is complete, the handshake is interrupted and an error is returned.
// Once the handshake has completed, cancellation of the context will not affect the
// connection.
func (c *UConn) HandshakeContext(ctx context.Context) error {
	// Delegate to unexported method for named return
	// without confusing documented signature.
	return c.handshakeContext(ctx)
}

func (c *UConn) handshakeContext(ctx context.Context) (ret error) {
	// Fast sync/atomic-based exit if there is no handshake in flight and the
	// last one succeeded without an error. Avoids the expensive context setup
	// and mutex for most Read and Write calls.
	if c.isHandshakeComplete.Load() {
		return nil
	}

	// [uTLS section begins]
	// Apply overall handshake timeout if configured
	baseCtx := ctx
	var overallCancel context.CancelFunc
	if c.handshakeTimeouts != nil && c.handshakeTimeouts.Overall > 0 {
		baseCtx, overallCancel = context.WithTimeout(ctx, c.handshakeTimeouts.Overall)
		defer overallCancel()
	}
	// [uTLS section ends]

	handshakeCtx, cancel := context.WithCancel(baseCtx)
	// Note: defer this before starting the "interrupter" goroutine
	// so that we can tell the difference between the input being canceled and
	// this cancellation. In the former case, we need to close the connection.
	defer cancel()

	// Start the "interrupter" goroutine, if this context might be canceled.
	// (The background context cannot).
	//
	// The interrupter goroutine waits for the input context to be done and
	// closes the connection if this happens before the function returns.
	if c.quic != nil {
		c.quic.cancelc = handshakeCtx.Done()
		c.quic.cancel = cancel
	} else if handshakeCtx.Done() != nil {
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-handshakeCtx.Done():
				// Close the connection, discarding the error
				_ = c.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.isHandshakeComplete.Load() {
		return nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	// [uTLS section begins]
	// Initialize timeout controller if per-phase timeouts are configured
	if c.handshakeTimeouts != nil {
		c.handshakeTimeoutCtrl = newHandshakeTimeoutController(handshakeCtx, c.handshakeTimeouts, c.Conn)
		if c.handshakeProgressCallback != nil {
			c.handshakeTimeoutCtrl.setProgressCallback(c.handshakeProgressCallback)
		}
		defer func() {
			c.handshakeTimeoutCtrl.cleanup()
			c.handshakeTimeoutCtrl = nil
		}()
	}

	if c.isClient {
		err := c.BuildHandshakeState()
		if err != nil {
			return err
		}
	}
	// [uTLS section ends]
	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		c.handshakes++

		// [uTLS section begins]
		// Send any buffered early data after successful handshake.
		// This implements "silent fallback" for 0-RTT: data written via WriteEarlyData()
		// before handshake is automatically sent as regular data after handshake.
		// Skip for QUIC connections as they handle early data at the transport layer.
		if c.quic == nil {
			if err := c.sendBufferedEarlyData(); err != nil {
				c.handshakeErr = err
			}
		}
		// [uTLS section ends]
	} else {
		// If an error occurred during the hadshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
		// Internal inconsistency - reset completion flag and preserve the error
		c.isHandshakeComplete.Store(false)
	}

	if c.quic != nil {
		if c.handshakeErr == nil {
			c.quicHandshakeComplete()
			// Provide the 1-RTT read secret now that the handshake is complete.
			// The QUIC layer MUST NOT decrypt 1-RTT packets prior to completing
			// the handshake (RFC 9001, Section 5.7).
			c.quicSetReadSecret(QUICEncryptionLevelApplication, c.cipherSuite, c.in.trafficSecret)
		} else {
			var a alert
			c.out.Lock()
			if !errors.As(c.out.err, &a) {
				a = alertInternalError
			}
			c.out.Unlock()
			// Return an error which wraps both the handshake error and
			// any alert error we may have sent, or alertInternalError
			// if we didn't send an alert.
			// Truncate the text of the alert to 0 characters.
			c.handshakeErr = fmt.Errorf("%w%.0w", c.handshakeErr, AlertError(a))
		}
		close(c.quic.blockedc)
		close(c.quic.signalc)
	}

	return c.handshakeErr
}

// Copy-pasted from tls.Conn in its entirety. But c.Handshake() is now utls' one, not tls.
// Write writes data to the connection.
func (c *UConn) Write(b []byte) (int, error) {
	// interlock with Close below
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			defer c.activeCall.Add(-2)
			break
		}
	}

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.isHandshakeComplete.Load() {
		return 0, alertInternalError
	}

	if c.closeNotifySent {
		return 0, errShutdown
	}

	// SSL 3.0 and TLS 1.0 are susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// https://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// https://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && c.vers <= VersionTLS10 {
		if _, ok := c.out.cipher.(cipher.BlockMode); ok {
			n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
			if err != nil {
				return n, c.out.setErrorLocked(err)
			}
			m, b = 1, b[1:]
		}
	}

	n, err := c.writeRecordLocked(recordTypeApplicationData, b)
	return n + m, c.out.setErrorLocked(err)
}

// ApplyConfig writes the configuration from each TLS extension in uconn.Extensions
// to the internal UConn state. This is called automatically during BuildHandshakeState()
// and generally should not be called directly by user code.
//
// Each extension's writeToUConn method is invoked to transfer its settings
// (such as SNI hostname, supported curves, ALPN protocols, etc.) to the connection.
//
// Thread-safe: Protected by extensionsMu RLock to prevent race conditions with
// concurrent modification of Extensions slice. The lock is held for the entire
// iteration to ensure consistency.
//
// Returns an error if any extension fails to apply its configuration.
func (uconn *UConn) ApplyConfig() error {
	uconn.extensionsMu.RLock()
	defer uconn.extensionsMu.RUnlock()
	for _, ext := range uconn.Extensions {
		err := ext.writeToUConn(uconn)
		if err != nil {
			return err
		}
	}
	return nil
}

// SetRecordPadding configures TLS 1.3 record padding for fingerprint control.
// This method sets the padding configuration that will be applied in writeRecordLocked().
// Use nil to disable padding, or DefaultRecordPaddingConfig() for Chrome-like behavior.
//
// Example:
//
//	uconn.SetRecordPadding(tls.DefaultRecordPaddingConfig())  // Chrome-like
//	uconn.SetRecordPadding(nil)                               // Disable padding
//	uconn.SetRecordPadding(&tls.RecordPaddingConfig{         // Custom
//	    Enabled:      true,
//	    Distribution: "exponential",
//	    Lambda:       3.0,
//	    MaxPadding:   128,
//	})
func (uconn *UConn) SetRecordPadding(cfg *RecordPaddingConfig) {
	if uconn.config == nil {
		return
	}
	uconn.config.RecordPadding = cfg
}

// SetRecordPaddingMode is a convenience method to configure padding mode.
// Valid modes:
//   - "chrome" (default when nil): Chrome-like exponential distribution
//   - "exponential": Standard exponential distribution
//   - "uniform": Uniform random distribution
//   - "none": Explicitly disable padding (NOT RECOMMENDED - breaks fingerprint)
//   - "" (empty): Use default (Chrome-like padding)
//
// Note: Padding is ENABLED BY DEFAULT for TLS 1.3 fingerprint resistance.
// Only use "none" if you have specific requirements.
func (uconn *UConn) SetRecordPaddingMode(mode string) {
	if uconn.config == nil {
		return
	}
	switch mode {
	case "none":
		// Explicitly disable padding (user's explicit choice)
		uconn.config.RecordPadding = DisabledRecordPaddingConfig()
	case "", "chrome":
		// Empty or "chrome" uses the default Chrome-like distribution
		uconn.config.RecordPadding = DefaultRecordPaddingConfig()
	case "exponential":
		uconn.config.RecordPadding = &RecordPaddingConfig{
			Enabled:      true,
			Distribution: "exponential",
			Lambda:       3.0,
			MaxPadding:   255,
		}
	case "uniform":
		uconn.config.RecordPadding = &RecordPaddingConfig{
			Enabled:      true,
			Distribution: "uniform",
			MaxPadding:   255,
		}
	default:
		// Unknown mode, use Chrome as default
		uconn.config.RecordPadding = DefaultRecordPaddingConfig()
	}
}

// SetHandshakeTiming configures handshake timing jitter for fingerprint resistance.
// When enabled, introduces realistic delays between handshake messages to simulate
// real browser behavior (certificate validation, key computation, etc.).
//
// Use nil to disable timing jitter, or DefaultHandshakeTimingConfig() for recommended settings.
//
// Example:
//
//	uconn.SetHandshakeTiming(tls.DefaultHandshakeTimingConfig())  // Enable with defaults
//	uconn.SetHandshakeTiming(nil)                                  // Disable timing jitter
//	uconn.SetHandshakeTiming(tls.ChromeHandshakeTimingConfig())   // Chrome-like timing
func (uconn *UConn) SetHandshakeTiming(cfg *HandshakeTimingConfig) {
	uconn.handshakeTimingConfig = cfg
}

// HandshakeTimingConfig returns the current handshake timing configuration.
// Returns nil if timing jitter is disabled.
func (uconn *UConn) HandshakeTimingConfig() *HandshakeTimingConfig {
	return uconn.handshakeTimingConfig
}

// getHandshakeTimingController creates a timing controller for the current handshake.
// Returns nil if timing is not configured.
func (uconn *UConn) getHandshakeTimingController() *handshakeTimingController {
	if uconn.handshakeTimingConfig == nil {
		return nil
	}
	return newHandshakeTimingController(uconn.handshakeTimingConfig)
}

// SetCloseNotifyJitter configures close_notify timing jitter for fingerprint resistance.
// When enabled, introduces realistic timing variability in sending close_notify alerts,
// mimicking real browser connection shutdown behavior.
//
// Use nil to disable jitter (default), or DefaultCloseNotifyConfig() for browser-like behavior.
//
// Example:
//
//	uconn.SetCloseNotifyJitter(tls.DefaultCloseNotifyConfig())  // Enable with defaults
//	uconn.SetCloseNotifyJitter(tls.ChromeCloseNotifyConfig())   // Chrome-like
//	uconn.SetCloseNotifyJitter(tls.FirefoxCloseNotifyConfig())  // Firefox-like
//	uconn.SetCloseNotifyJitter(nil)                              // Disable (default)
func (uconn *UConn) SetCloseNotifyJitter(cfg *CloseNotifyConfig) {
	if uconn.config == nil {
		return
	}
	uconn.config.CloseNotifyJitter = cfg
}

// CloseNotifyJitter returns the current close_notify jitter configuration.
// Returns nil if jitter is disabled (default).
func (uconn *UConn) CloseNotifyJitter() *CloseNotifyConfig {
	if uconn.config == nil {
		return nil
	}
	return uconn.config.CloseNotifyJitter
}

// SetHandshakeTimeouts configures per-phase timeouts for the TLS handshake.
// This allows fine-grained control over timing during different handshake phases,
// and enables graceful timeout handling with alert sending.
//
// When set, timeouts are enforced for each handshake phase:
//   - ClientHello: Time to send the ClientHello message
//   - ServerResponse: Time to receive ServerHello
//   - Certificate: Time for certificate exchange
//   - KeyExchange: Time for key exchange operations
//   - Finished: Time for Finished message exchange
//
// On timeout, the connection attempts to send a user_canceled alert before
// closing, and returns a HandshakeTimeoutError with detailed phase information.
//
// Use nil to disable per-phase timeouts (relies on context deadline only).
// Use DefaultHandshakeTimeouts() for sensible defaults.
//
// Example:
//
//	uconn.SetHandshakeTimeouts(tls.DefaultHandshakeTimeouts())  // Enable defaults
//	uconn.SetHandshakeTimeouts(tls.FastHandshakeTimeouts())     // Aggressive timeouts
//	uconn.SetHandshakeTimeouts(nil)                              // Disable (context only)
//	uconn.SetHandshakeTimeouts(&tls.HandshakeTimeouts{          // Custom
//	    Overall:        10 * time.Second,
//	    ServerResponse: 5 * time.Second,
//	})
func (uconn *UConn) SetHandshakeTimeouts(t *HandshakeTimeouts) {
	uconn.handshakeTimeouts = t.Clone()
}

// HandshakeTimeouts returns the current handshake timeout configuration.
// Returns nil if per-phase timeouts are disabled.
func (uconn *UConn) HandshakeTimeouts() *HandshakeTimeouts {
	return uconn.handshakeTimeouts.Clone()
}

// SetHandshakeProgressCallback sets a callback that is invoked during handshake
// to report progress through handshake phases. This is useful for:
//   - Progress indicators for long handshakes
//   - Debugging/logging handshake timing
//   - Monitoring handshake performance
//
// The callback receives the current phase and elapsed time since handshake start.
// It is called from the handshake goroutine, so it should be fast and non-blocking.
//
// Use nil to disable progress callbacks.
//
// Example:
//
//	uconn.SetHandshakeProgressCallback(func(phase tls.HandshakePhase, elapsed time.Duration) {
//	    log.Printf("Handshake phase %s at %v", phase, elapsed)
//	})
func (uconn *UConn) SetHandshakeProgressCallback(cb HandshakeProgressCallback) {
	uconn.handshakeProgressCallback = cb
}

// HandshakeProgressCallback returns the current progress callback, or nil if none set.
func (uconn *UConn) HandshakeProgressCallback() HandshakeProgressCallback {
	return uconn.handshakeProgressCallback
}

// enterHandshakePhase transitions to a new handshake phase and returns a
// context with the phase-specific timeout. Returns the base context if
// no timeout controller is configured.
// This is called internally during handshake.
func (uconn *UConn) enterHandshakePhase(phase HandshakePhase) (context.Context, error) {
	if uconn.handshakeTimeoutCtrl == nil {
		return context.Background(), nil
	}
	return uconn.handshakeTimeoutCtrl.enterPhase(phase)
}

// checkHandshakePhaseTimeout wraps an error with phase timeout information
// if the error is a context timeout/cancellation error.
// This is called internally during handshake to enhance error reporting.
func (uconn *UConn) checkHandshakePhaseTimeout(err error) error {
	if uconn.handshakeTimeoutCtrl == nil {
		return err
	}
	return uconn.handshakeTimeoutCtrl.checkPhaseTimeout(err)
}

// handshakeElapsed returns the elapsed time since handshake started.
// Returns 0 if no timeout controller is active.
func (uconn *UConn) handshakeElapsed() time.Duration {
	if uconn.handshakeTimeoutCtrl == nil {
		return 0
	}
	return uconn.handshakeTimeoutCtrl.elapsed()
}

// GreaseSeed returns a copy of the GREASE seed array.
// Used for frozen GREASE restoration in session consistency.
// The array indices correspond to ssl_grease_cipher (0), ssl_grease_group (1),
// ssl_grease_extension1 (2), ssl_grease_extension2 (3), ssl_grease_version (4).
// Note: Array size is 5 elements (indices 0-4).
func (uconn *UConn) GreaseSeed() [ssl_grease_last_index]uint16 {
	return uconn.greaseSeed
}

// SetGreaseSeedAt sets a specific GREASE seed value by index.
// Valid indices: ssl_grease_cipher (0), ssl_grease_group (1),
// ssl_grease_extension1 (2), ssl_grease_extension2 (3),
// ssl_grease_version (4).
// Note: ssl_grease_ticket_extension (5) is NOT a valid index - the array
// has only 5 elements (indices 0-4). Returns error if index is out of bounds.
func (uconn *UConn) SetGreaseSeedAt(index int, value uint16) error {
	if index < 0 || index >= ssl_grease_last_index {
		return fmt.Errorf("tls: invalid seed index: %d", index)
	}
	uconn.greaseSeed[index] = value
	return nil
}

// SetGreaseSeedFromFrozen applies frozen GREASE values for session consistency.
// This ensures that GREASE values remain consistent across multiple connections
// within the same session, which is critical for fingerprint stability.
// The high byte of each frozen value is used as the seed, which is then
// transformed by GetBoringGREASEValue to produce the actual GREASE value.
func (uconn *UConn) SetGreaseSeedFromFrozen(frozen *FrozenGREASEValues) {
	if frozen == nil {
		return
	}
	// Extract high byte from each frozen value to use as seed
	// GetBoringGREASEValue will transform: seed & 0xf0 | 0x0a, then duplicate
	uconn.greaseSeed[ssl_grease_cipher] = frozen.CipherSuite >> 8
	uconn.greaseSeed[ssl_grease_group] = frozen.SupportedGroup >> 8
	uconn.greaseSeed[ssl_grease_extension1] = frozen.Extension1 >> 8
	uconn.greaseSeed[ssl_grease_extension2] = frozen.Extension2 >> 8
	uconn.greaseSeed[ssl_grease_version] = frozen.SupportedVersion >> 8
	// Note: KeyShare uses same value as SupportedGroup per Chrome behavior
	// SignatureAlgo and PSKMode are not in standard greaseSeed array
}

// RawServerHello returns captured ServerHello bytes for JA4S calculation.
// Returns nil if ServerHello hasn't been received yet.
// The returned slice is a copy to prevent modification of internal state.
// Thread-safe: Protected by stateMu RWMutex.
func (uconn *UConn) RawServerHello() []byte {
	uconn.stateMu.RLock()
	raw := uconn.rawServerHello
	uconn.stateMu.RUnlock()

	if raw == nil {
		return nil
	}
	// Return copy to prevent modification
	result := make([]byte, len(raw))
	copy(result, raw)
	return result
}

// SetRawServerHello stores raw ServerHello bytes.
// This is primarily used for testing and ServerHello replay scenarios.
// Thread-safe: Protected by stateMu RWMutex.
func (uconn *UConn) SetRawServerHello(raw []byte) {
	uconn.stateMu.Lock()
	defer uconn.stateMu.Unlock()

	if raw == nil {
		uconn.rawServerHello = nil
		return
	}
	uconn.rawServerHello = make([]byte, len(raw))
	copy(uconn.rawServerHello, raw)
}

// Note: ClearRawServerHello is defined in u_fingerprint.go

// ExtensionTypes returns ordered list of extension type IDs from current Extensions.
// This is the public accessor for extensionsList(), used for fingerprint calculation
// and ECH outer extension compression.
func (uconn *UConn) ExtensionTypes() []uint16 {
	return uconn.extensionsList()
}

// CertCompressionAlgs returns the advertised certificate compression algorithms.
// Returns nil if no compression algorithms were advertised.
// The returned slice is a copy to prevent modification of internal state.
func (uconn *UConn) CertCompressionAlgs() []CertCompressionAlgo {
	if uconn.certCompressionAlgs == nil {
		return nil
	}
	result := make([]CertCompressionAlgo, len(uconn.certCompressionAlgs))
	copy(result, uconn.certCompressionAlgs)
	return result
}

// SetCertCompressionAlgs sets the certificate compression algorithms to advertise.
func (uconn *UConn) SetCertCompressionAlgs(algs []CertCompressionAlgo) {
	if algs == nil {
		uconn.certCompressionAlgs = nil
		return
	}
	uconn.certCompressionAlgs = make([]CertCompressionAlgo, len(algs))
	copy(uconn.certCompressionAlgs, algs)
}

// NegotiatedRecordSizeLimit returns the negotiated record size limit (RFC 8449).
// Returns 0 if the extension was not negotiated.
// This is the maximum plaintext record size we can send to the server.
// In TLS 1.3, the limit includes the content type byte, so actual data capacity is limit-1.
func (uconn *UConn) NegotiatedRecordSizeLimit() uint16 {
	return uconn.Conn.utls.negotiatedRecordSizeLimit
}

// EchContextInfo provides read-only access to ECH context state.
type EchContextInfo struct {
	Enabled         bool   // Whether ECH is configured
	ConfigID        uint8  // ECH config ID
	KdfID           uint16 // KDF algorithm ID
	AeadID          uint16 // AEAD algorithm ID
	Rejected        bool   // Whether ECH was rejected by server
	HasRetryConfigs bool   // Whether retry configs are available
}

// EchContext returns information about the ECH (Encrypted Client Hello) context.
// Returns nil if ECH is not configured for this connection.
// Thread-safe: Uses atomic.Pointer for lock-free access.
func (uconn *UConn) EchContext() *EchContextInfo {
	echCtx := uconn.echCtx.Load()
	if echCtx == nil {
		return nil
	}
	// echCtx fields are set during handshake and immutable after,
	// so safe to read without holding the lock
	info := &EchContextInfo{
		Enabled:  true,
		KdfID:    echCtx.kdfID,
		AeadID:   echCtx.aeadID,
		Rejected: echCtx.echRejected,
	}
	config := echCtx.config
	if config != nil {
		info.ConfigID = config.ConfigID
	}
	info.HasRetryConfigs = len(echCtx.retryConfigs) > 0
	return info
}

// EchRetryConfigs returns the ECH retry configs provided by the server.
// Returns nil if ECH was not rejected or no retry configs were provided.
// Thread-safe: Uses atomic.Pointer for lock-free access.
func (uconn *UConn) EchRetryConfigs() []byte {
	echCtx := uconn.echCtx.Load()
	if echCtx == nil {
		return nil
	}
	// echCtx fields are set during handshake and immutable after,
	// so safe to read without holding the lock
	retryConfigs := echCtx.retryConfigs
	if len(retryConfigs) == 0 {
		return nil
	}
	result := make([]byte, len(retryConfigs))
	copy(result, retryConfigs)
	return result
}

// extensionsList returns the list of extension type IDs from the current Extensions.
// This is used for ECH outer extensions compression.
//
// Thread-safe: Protected by extensionsMu RLock.
func (uconn *UConn) extensionsList() []uint16 {
	uconn.extensionsMu.RLock()
	defer uconn.extensionsMu.RUnlock()
	outerExts := make([]uint16, 0, len(uconn.Extensions))
	for _, ext := range uconn.Extensions {
		// Allocate buffer for extension data
		extLen := ext.Len()
		if extLen < 2 {
			// Extension too short to contain type ID, skip
			continue
		}
		buffer := make([]byte, extLen)
		n, err := ext.Read(buffer)
		if err != nil && err != io.EOF {
			// Skip extensions that fail to serialize
			continue
		}
		if n < 2 {
			// Not enough data read to extract extension type
			continue
		}
		// Parse extension type from first 2 bytes (big-endian)
		extType := uint16(buffer[0])<<8 | uint16(buffer[1])
		outerExts = append(outerExts, extType)
	}
	return outerExts
}

func (uconn *UConn) computeAndUpdateOuterECHExtension(inner *clientHelloMsg, ech *echClientContext, useKey bool) error {
	// This function is mostly copied from
	// https://github.com/refraction-networking/utls/blob/e430876b1d82fdf582efc57f3992d448e7ab3d8a/ech.go#L408
	if ech == nil {
		return errors.New("tls: ech context is nil in computeAndUpdateOuterECHExtension")
	}
	var encapKey []byte
	if useKey {
		encapKey = ech.encapsulatedKey
	}

	encodedInner, err := encodeInnerClientHelloReorderOuterExts(inner, int(ech.config.MaxNameLength), uconn.extensionsList())
	if err != nil {
		return err
	}

	encryptedLen := len(encodedInner) + ech.hpkeContext.Overhead()
	outerECHExt, err := generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, make([]byte, encryptedLen))
	if err != nil {
		return err
	}

	echExtIdx := slices.IndexFunc(uconn.Extensions, func(ext TLSExtension) bool {
		_, ok := ext.(EncryptedClientHelloExtension)
		return ok
	})
	if echExtIdx < 0 {
		return fmt.Errorf("extension satisfying EncryptedClientHelloExtension not present")
	}
	oldExt := uconn.Extensions[echExtIdx]

	uconn.Extensions[echExtIdx] = &GenericExtension{
		Id:   extensionEncryptedClientHello,
		Data: outerECHExt,
	}

	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	serializedOuter := uconn.HandshakeState.Hello.Raw
	serializedOuter = serializedOuter[4:]
	encryptedInner, err := ech.hpkeContext.Seal(serializedOuter, encodedInner)
	if err != nil {
		return err
	}
	outerECHExt, err = generateOuterECHExt(ech.config.ConfigID, ech.kdfID, ech.aeadID, encapKey, encryptedInner)
	if err != nil {
		return err
	}
	uconn.Extensions[echExtIdx] = &GenericExtension{
		Id:   extensionEncryptedClientHello,
		Data: outerECHExt,
	}

	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	uconn.Extensions[echExtIdx] = oldExt
	return nil

}

// MarshalClientHello serializes the ClientHello message into the Raw field
// of HandshakeState.Hello. If ECH (Encrypted Client Hello) is configured,
// this method also computes and includes the ECH extension.
//
// This is called automatically during BuildHandshakeState() and typically
// should not be called directly unless you need to re-marshal after modifying
// extensions.
//
// For ECH connections, this method:
//   - Creates the inner ClientHello
//   - Computes the encrypted ECH extension
//   - Stores the ECH context for later use during handshake
//
// Returns an error if marshaling or ECH computation fails.
func (uconn *UConn) MarshalClientHello() error {
	if len(uconn.config.EncryptedClientHelloConfigList) > 0 {
		inner, _, ech, err := uconn.makeClientHello()
		if err != nil {
			return err
		}

		// copy compressed extensions to the ClientHelloInner
		inner.keyShares = KeyShares(uconn.HandshakeState.Hello.KeyShares).ToPrivate()
		inner.supportedSignatureAlgorithms = uconn.HandshakeState.Hello.SupportedSignatureAlgorithms
		inner.sessionId = uconn.HandshakeState.Hello.SessionId
		inner.supportedCurves = uconn.HandshakeState.Hello.SupportedCurves

		ech.innerHello = inner

		if err := uconn.computeAndUpdateOuterECHExtension(inner, ech, true); err != nil {
			return fmt.Errorf("tls: failed to compute ECH extension: %w", err)
		}

		uconn.echCtx.Store(ech)
		return nil
	}

	if err := uconn.MarshalClientHelloNoECH(); err != nil {
		return err
	}

	return nil

}

// MarshalClientHelloNoECH marshals ClientHello as if there was no
// ECH extension present.
func (uconn *UConn) MarshalClientHelloNoECH() error {
	hello := uconn.HandshakeState.Hello
	headerLength := 2 + 32 + 1 + len(hello.SessionId) +
		2 + len(hello.CipherSuites)*2 +
		1 + len(hello.CompressionMethods)

	extensionsLen := 0
	var paddingExt *UtlsPaddingExtension // reference to padding extension, if present

	// Check for duplicate extension types (RFC 8446 forbids duplicates)
	seenExts := make(map[uint16]bool)
	// Initialize with minimal capacity to avoid nil slice panic when resizing
	// Most extensions are small (< 64 bytes), buffer grows as needed
	extBuf := make([]byte, 0, 64)

	for _, ext := range uconn.Extensions {
		if pe, ok := ext.(*UtlsPaddingExtension); !ok {
			extLen := ext.Len()
			// Check for duplicate extension types
			// Extensions with Len() >= 4 have at least type (2 bytes) + length (2 bytes)
			if extLen >= 4 {
				// Ensure buffer is large enough for this extension
				if cap(extBuf) < extLen {
					extBuf = make([]byte, extLen)
				} else {
					extBuf = extBuf[:extLen]
				}
				// Read extension to get its type from first 2 bytes
				// Read() is idempotent - safe to call multiple times
				if n, err := ext.Read(extBuf); n >= 2 && (err == nil || err == io.EOF) {
					extType := uint16(extBuf[0])<<8 | uint16(extBuf[1])
					// Allow multiple GREASE extensions (real browsers have ~6.25% collision rate)
					// RFC 8701 allows GREASE values to appear multiple times
					if seenExts[extType] && !isGREASEUint16(extType) {
						return fmt.Errorf("tls: duplicate extension type %d", extType)
					}
					seenExts[extType] = true
				}
			}
			// Add length of extension to total length
			extensionsLen += extLen
		} else {
			// If padding - process it later
			if paddingExt == nil {
				paddingExt = pe
			} else {
				return errors.New("multiple padding extensions")
			}
		}
	}

	if paddingExt != nil {
		// determine padding extension presence and length
		paddingExt.Update(headerLength + 4 + extensionsLen + 2)
		extensionsLen += paddingExt.Len()
	}

	helloLen := headerLength
	if len(uconn.Extensions) > 0 {
		helloLen += 2 + extensionsLen // 2 bytes for extensions' length
	}

	helloBuffer := bytes.Buffer{}
	bufferedWriter := bufio.NewWriterSize(&helloBuffer, helloLen+4) // 1 byte for tls record type, 3 for length
	// We use buffered Writer to avoid checking write errors after every Write(): whenever first error happens
	// Write() will become noop, and error will be accessible via Flush(), which is called once in the end

	binary.Write(bufferedWriter, binary.BigEndian, typeClientHello)
	helloLenBytes := []byte{byte(helloLen >> 16), byte(helloLen >> 8), byte(helloLen)} // poor man's uint24
	binary.Write(bufferedWriter, binary.BigEndian, helloLenBytes)
	binary.Write(bufferedWriter, binary.BigEndian, hello.Vers)

	binary.Write(bufferedWriter, binary.BigEndian, hello.Random)

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.SessionId)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.SessionId)

	binary.Write(bufferedWriter, binary.BigEndian, uint16(len(hello.CipherSuites)<<1))
	for _, suite := range hello.CipherSuites {
		binary.Write(bufferedWriter, binary.BigEndian, suite)
	}

	binary.Write(bufferedWriter, binary.BigEndian, uint8(len(hello.CompressionMethods)))
	binary.Write(bufferedWriter, binary.BigEndian, hello.CompressionMethods)

	if len(uconn.Extensions) > 0 {
		// Validate PSK extension is last if present (RFC 8446 Section 4.2.11)
		pskIndex := -1
		for i, ext := range uconn.Extensions {
			if _, ok := ext.(PreSharedKeyExtension); ok {
				pskIndex = i
			}
		}
		if pskIndex != -1 && pskIndex != len(uconn.Extensions)-1 {
			return errors.New("tls: pre_shared_key extension must be last")
		}

		binary.Write(bufferedWriter, binary.BigEndian, uint16(extensionsLen))
		for _, ext := range uconn.Extensions {
			if _, err := bufferedWriter.ReadFrom(ext); err != nil {
				return err
			}
		}
	}

	err := bufferedWriter.Flush()
	if err != nil {
		return err
	}

	if helloBuffer.Len() != 4+helloLen {
		return errors.New("tls: invalid ClientHello length")
	}

	hello.Raw = helloBuffer.Bytes()
	return nil
}

// get current state of cipher and encrypt zeros to get keystream
func (uconn *UConn) GetOutKeystream(length int) ([]byte, error) {
	zeros := make([]byte, length)

	if outCipher, ok := uconn.out.cipher.(cipher.AEAD); ok {
		// AEAD.Seal() does not mutate internal state, other ciphers might
		return outCipher.Seal(nil, uconn.out.seq[:], zeros, nil), nil
	}
	return nil, errors.New("could not convert OutCipher to cipher.AEAD")
}

// SetTLSVers sets min and max TLS version in all appropriate places.
// Function will use first non-zero version parsed in following order:
//  1. Provided minTLSVers, maxTLSVers
//  2. specExtensions may have SupportedVersionsExtension
//  3. [default] min = TLS 1.0, max = TLS 1.2
//
// Error is only returned if things are in clearly undesirable state
// to help user fix them.
func (uconn *UConn) SetTLSVers(minTLSVers, maxTLSVers uint16, specExtensions []TLSExtension) error {
	if minTLSVers == 0 && maxTLSVers == 0 {
		// if version is not set explicitly in the ClientHelloSpec, check the SupportedVersions extension
		supportedVersionsExtensionsPresent := 0
		for _, e := range specExtensions {
			switch ext := e.(type) {
			case *SupportedVersionsExtension:
				findVersionsInSupportedVersionsExtensions := func(versions []uint16) (uint16, uint16) {
					// returns (minVers, maxVers)
					minVers := uint16(0)
					maxVers := uint16(0)
					for _, vers := range versions {
						if isGREASEUint16(vers) {
							continue
						}
						if maxVers < vers || maxVers == 0 {
							maxVers = vers
						}
						if minVers > vers || minVers == 0 {
							minVers = vers
						}
					}
					return minVers, maxVers
				}

				supportedVersionsExtensionsPresent += 1
				minTLSVers, maxTLSVers = findVersionsInSupportedVersionsExtensions(ext.Versions)
				if minTLSVers == 0 && maxTLSVers == 0 {
					return fmt.Errorf("SupportedVersions extension has invalid Versions field")
				} // else: proceed
			}
		}
		switch supportedVersionsExtensionsPresent {
		case 0:
			// if mandatory for TLS 1.3 extension is not present, just default to 1.2
			minTLSVers = VersionTLS10
			maxTLSVers = VersionTLS12
		case 1:
		default:
			return fmt.Errorf("tls: duplicate supported_versions extension")
		}
	}

	if minTLSVers < VersionTLS10 || minTLSVers > VersionTLS13 {
		return fmt.Errorf("tls: unsupported protocol version 0x%X", minTLSVers)
	}

	if maxTLSVers < VersionTLS10 || maxTLSVers > VersionTLS13 {
		return fmt.Errorf("tls: unsupported protocol version 0x%X", maxTLSVers)
	}

	uconn.HandshakeState.Hello.SupportedVersions = makeSupportedVersions(minTLSVers, maxTLSVers)
	if uconn.config.EncryptedClientHelloConfigList == nil {
		uconn.config.MinVersion = minTLSVers
		uconn.config.MaxVersion = maxTLSVers
	}

	return nil
}

// SetUnderlyingConn replaces the underlying network connection.
// This can be used to swap the connection after initial setup,
// for example when wrapping with a proxy connection.
//
// WARNING: This should only be called before the handshake begins.
// Replacing the connection during or after handshake will cause
// undefined behavior and likely connection failures.
func (uconn *UConn) SetUnderlyingConn(c net.Conn) {
	uconn.Conn.conn = c
}

// GetUnderlyingConn returns the underlying network connection.
// This can be used to access the raw TCP connection for operations
// like setting deadlines or reading connection metadata.
func (uconn *UConn) GetUnderlyingConn() net.Conn {
	return uconn.Conn.conn
}

// isClosed returns true if Close() has been called on this connection.
// This checks the low bit of the activeCall atomic field which is set by Close().
// Thread-safe: uses atomic operations internally.
func (uconn *UConn) isClosed() bool {
	if uconn == nil || uconn.Conn == nil {
		return true
	}
	return uconn.Conn.activeCall.Load()&1 != 0
}

// IsHealthy returns true if the connection appears usable for TLS operations.
// A connection is considered healthy if:
//   - The UConn and underlying Conn are not nil
//   - The TLS handshake has completed successfully
//   - Close() has not been called on the connection
//
// This is a lightweight check and does not perform any I/O operations.
// For active connection health verification, use GracefulConn.Ping() instead.
//
// Thread-safe: uses atomic operations for all checks.
func (uconn *UConn) IsHealthy() bool {
	if uconn == nil || uconn.Conn == nil {
		return false
	}
	// Check if handshake completed
	if !uconn.isHandshakeComplete.Load() {
		return false
	}
	// Check if connection is closed
	if uconn.isClosed() {
		return false
	}
	return true
}

// MakeConnWithCompleteHandshake allows to forge both server and client side TLS connections.
// Major Hack Alert.
func MakeConnWithCompleteHandshake(tcpConn net.Conn, version uint16, cipherSuite uint16, masterSecret []byte, clientRandom []byte, serverRandom []byte, isClient bool) *Conn {
	tlsConn := &Conn{conn: tcpConn, config: &Config{}, isClient: isClient}
	cs := cipherSuiteByID(cipherSuite)
	if cs != nil {
		// This is mostly borrowed from establishKeys()
		clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
			keysFromMasterSecret(version, cs, masterSecret, clientRandom, serverRandom,
				cs.macLen, cs.keyLen, cs.ivLen)

		var clientCipher, serverCipher interface{}
		var clientHash, serverHash hash.Hash
		if cs.cipher != nil {
			clientCipher = cs.cipher(clientKey, clientIV, true /* for reading */)
			if clientCipher == nil {
				// Cipher creation failed (invalid key length)
				return nil
			}
			clientHash = cs.mac(clientMAC)
			serverCipher = cs.cipher(serverKey, serverIV, false /* not for reading */)
			if serverCipher == nil {
				// Cipher creation failed (invalid key length)
				return nil
			}
			serverHash = cs.mac(serverMAC)
		} else {
			var err error
			clientCipher, err = cs.aead(clientKey, clientIV)
			if err != nil {
				// AEAD creation failed (invalid key length)
				return nil
			}
			serverCipher, err = cs.aead(serverKey, serverIV)
			if err != nil {
				// AEAD creation failed (invalid key length)
				return nil
			}
		}

		if isClient {
			tlsConn.in.prepareCipherSpec(version, serverCipher, serverHash)
			tlsConn.out.prepareCipherSpec(version, clientCipher, clientHash)
		} else {
			tlsConn.in.prepareCipherSpec(version, clientCipher, clientHash)
			tlsConn.out.prepareCipherSpec(version, serverCipher, serverHash)
		}

		// skip the handshake states
		tlsConn.isHandshakeComplete.Store(true)
		tlsConn.cipherSuite = cipherSuite
		tlsConn.haveVers = true
		tlsConn.vers = version

		// Update to the new cipher specs
		// and consume the finished messages
		tlsConn.in.changeCipherSpec()
		tlsConn.out.changeCipherSpec()

		// Increment sequence numbers - errors are effectively impossible here
		// since we just initialized (seq starts at 0), but handle gracefully.
		if err := tlsConn.in.incSeq(); err != nil {
			return nil
		}
		if err := tlsConn.out.incSeq(); err != nil {
			return nil
		}

		return tlsConn
	} else {
		// TODO: Support TLS 1.3 Cipher Suites
		return nil
	}
}

func makeSupportedVersions(minVers, maxVers uint16) []uint16 {
	a := make([]uint16, maxVers-minVers+1)
	for i := range a {
		a[i] = maxVers - uint16(i)
	}
	return a
}

// Extending (*Conn).readHandshake() to support more customized handshake messages.
func (c *Conn) utlsHandshakeMessageType(msgType byte) (handshakeMessage, error) {
	switch msgType {
	case utlsTypeCompressedCertificate:
		return new(utlsCompressedCertificateMsg), nil
	case utlsTypeEncryptedExtensions:
		if c.isClient {
			return new(encryptedExtensionsMsg), nil
		} else {
			return new(utlsClientEncryptedExtensionsMsg), nil
		}
	default:
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}
}

// Extending (*Conn).connectionStateLocked()
func (c *Conn) utlsConnectionStateLocked(state *ConnectionState) {
	state.PeerApplicationSettings = c.utls.peerApplicationSettings
}

type utlsConnExtraFields struct {
	// Application Settings (ALPS)
	peerApplicationSettings      []byte
	localApplicationSettings     []byte
	applicationSettingsCodepoint uint16

	sessionController *sessionController

	// negotiatedRecordSizeLimit stores the record size limit negotiated via
	// the record_size_limit extension (RFC 8449). When non-zero, this limits
	// the maximum plaintext size of TLS records sent to the peer.
	// This is stored in Conn (not UConn) so maxPayloadSizeForWrite can access it.
	negotiatedRecordSizeLimit uint16

	// advertisedRecordSizeLimit stores the record size limit WE advertised to
	// the peer (what we told them we can receive). Per RFC 8449 Section 4:
	// "A TLS endpoint that receives a record larger than its advertised limit
	// MUST generate a fatal 'record_overflow' alert."
	// This is used for receiver-side enforcement of RFC 8449.
	advertisedRecordSizeLimit uint16
}

// Read reads data from the connection.
//
// As Read calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both Read and [Conn.Write] before Read is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *UConn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	c.in.Lock()
	defer c.in.Unlock()

	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
		for c.hand.Len() > 0 {
			if err := c.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	n, _ := c.input.Read(b)

	// If a close-notify alert is waiting, read it so that we can return (n,
	// EOF) instead of (n, nil), to signal to the HTTP response reading
	// goroutine that the connection is now closed. This eliminates a race
	// where the HTTP response reading goroutine would otherwise not observe
	// the EOF until its next read, by which time a client goroutine might
	// have already tried to reuse the HTTP connection for a new request.
	// See https://golang.org/cl/76400046 and https://golang.org/issue/3514
	if n != 0 && c.input.Len() == 0 && c.rawInput.Len() > 0 &&
		recordType(c.rawInput.Bytes()[0]) == recordTypeAlert {
		if err := c.readRecord(); err != nil {
			return n, err // will be io.EOF on closeNotify
		}
	}

	return n, nil
}

// handleRenegotiation processes a HelloRequest handshake message.
func (c *UConn) handleRenegotiation() error {
	if c.vers == VersionTLS13 {
		return errors.New("tls: internal error: unexpected renegotiation")
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}

	if !c.isClient {
		return c.sendAlert(alertNoRenegotiation)
	}

	switch c.config.Renegotiation {
	case RenegotiateNever:
		return c.sendAlert(alertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			return c.sendAlert(alertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
		// Ok.
	default:
		c.sendAlert(alertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	c.isHandshakeComplete.Store(false)

	// [uTLS section begins]
	if err = c.BuildHandshakeState(); err != nil {
		return err
	}
	// [uTLS section ends]
	if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
		c.handshakes++
	}
	return c.handshakeErr
}

// handlePostHandshakeMessage processes a handshake message arrived after the
// handshake is complete. Up to TLS 1.2, it indicates the start of a renegotiation.
func (c *UConn) handlePostHandshakeMessage() error {
	if c.vers != VersionTLS13 {
		return c.handleRenegotiation()
	}

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: too many non-advancing records"))
	}

	switch msg := msg.(type) {
	case *newSessionTicketMsgTLS13:
		return c.handleNewSessionTicket(msg)
	case *keyUpdateMsg:
		return c.handleKeyUpdate(msg)
	}
	// The QUIC layer is supposed to treat an unexpected post-handshake CertificateRequest
	// as a QUIC-level PROTOCOL_VIOLATION error (RFC 9001, Section 4.4). Returning an
	// unexpected_message alert here doesn't provide it with enough information to distinguish
	// this condition from other unexpected messages. This is probably fine.
	c.sendAlert(alertUnexpectedMessage)
	return fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
}
