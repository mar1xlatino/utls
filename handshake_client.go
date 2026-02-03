// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"slices"
	"strings"
	"time"

	utlserrors "github.com/refraction-networking/utls/errors"
	"github.com/refraction-networking/utls/internal/byteorder"
	"github.com/refraction-networking/utls/internal/fips140tls"
	"github.com/refraction-networking/utls/internal/hpke"
	"github.com/refraction-networking/utls/internal/tls13"
	"golang.org/x/net/idna"
)

// classifyAndCallErrorHook examines the error type and calls the appropriate
// error-specific observability hook. This provides fine-grained error tracking
// for timeout, network, and cryptographic errors during TLS handshakes.
func classifyAndCallErrorHook(remoteAddr string, err error) {
	if err == nil {
		return
	}

	// Check for context-related errors (timeout/cancellation)
	if err == context.DeadlineExceeded || err == context.Canceled {
		callOnTimeoutError(remoteAddr)
		return
	}

	// Check if error wraps a context error
	var ctxErr error
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		if unwrapped == context.DeadlineExceeded || unwrapped == context.Canceled {
			callOnTimeoutError(remoteAddr)
			return
		}
		ctxErr = unwrapped
	}
	_ = ctxErr // Silence unused variable warning

	// Check for network errors (implements net.Error interface)
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			callOnTimeoutError(remoteAddr)
		} else {
			callOnNetworkError(remoteAddr, err)
		}
		return
	}

	// All TLS/crypto-related errors (errors starting with "tls:" or alert errors)
	errStr := err.Error()
	if strings.HasPrefix(errStr, "tls:") || strings.Contains(errStr, "alert") ||
		strings.Contains(errStr, "certificate") || strings.Contains(errStr, "cipher") ||
		strings.Contains(errStr, "handshake") || strings.Contains(errStr, "decrypt") ||
		strings.Contains(errStr, "signature") || strings.Contains(errStr, "verify") {
		callOnCryptoError(remoteAddr, err)
		return
	}

	// For any other error, treat as network error (conservative default)
	callOnNetworkError(remoteAddr, err)
}

type clientHandshakeState struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *SessionState // the session being resumed
	ticket       []byte        // a fresh ticket received during this handshake

	uconn *UConn // [uTLS]
}

var testingOnlyForceClientHelloSignatureAlgorithms []SignatureScheme

func (c *Conn) makeClientHello() (*clientHelloMsg, *keySharePrivateKeys, *echClientContext, error) {
	ctx := context.Background()
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(ctx, "makeClientHello: starting ClientHello construction")
	}
	config := c.config

	// [UTLS SECTION START]
	// Validate that the config has enough information for certificate verification.
	// Either ServerName must be set for hostname verification, or InsecureSkipVerify
	// must be true to skip verification entirely. InsecureServerNameToVerify is also
	// accepted as an alternative for advanced use cases (e.g., fingerprint spoofing).
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify && len(config.InsecureServerNameToVerify) == 0 {
		utlserrors.LogDebug(ctx, "makeClientHello: missing ServerName configuration")
		return nil, nil, nil, utlserrors.New("tls: either Config.ServerName must be set or Config.InsecureSkipVerify must be true").AtError()
	}
	// [UTLS SECTION END]

	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, nil, nil, utlserrors.New("tls: invalid NextProtos value").AtError()
		} else {
			nextProtosLength += 1 + l
		}
	}
	if nextProtosLength > 0xffff {
		return nil, nil, nil, utlserrors.New("tls: NextProtos values too large").AtError()
	}

	supportedVersions := config.supportedVersions(roleClient)
	if len(supportedVersions) == 0 {
		return nil, nil, nil, utlserrors.New("tls: no supported versions satisfy MinVersion and MaxVersion").AtError()
	}
	maxVersion := config.maxSupportedVersion(roleClient)

	hello := &clientHelloMsg{
		vers:                         maxVersion,
		compressionMethods:           []uint8{compressionNone},
		random:                       make([]byte, 32),
		extendedMasterSecret:         true,
		ocspStapling:                 true,
		scts:                         true,
		serverName:                   hostnameInSNI(config.ServerName),
		supportedCurves:              config.curvePreferences(maxVersion),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		alpnProtocols:                config.NextProtos,
		supportedVersions:            supportedVersions,
	}

	// The version at the beginning of the ClientHello was capped at TLS 1.2
	// for compatibility reasons. The supported_versions extension is used
	// to negotiate versions now. See RFC 8446, Section 4.2.1.
	if hello.vers > VersionTLS12 {
		hello.vers = VersionTLS12
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		// Don't advertise TLS 1.2-only cipher suites unless
		// we're attempting TLS 1.2.
		if maxVersion < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, nil, utlserrors.New("tls: short read from Rand").Base(err).AtError()
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if c.quic == nil {
		hello.sessionId = make([]byte, 32)
		if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
			return nil, nil, nil, utlserrors.New("tls: short read from Rand for session ID").Base(err).AtError()
		}
	}

	if maxVersion >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
	}
	if testingOnlyForceClientHelloSignatureAlgorithms != nil {
		hello.supportedSignatureAlgorithms = testingOnlyForceClientHelloSignatureAlgorithms
	}

	var keyShareKeys *keySharePrivateKeys
	if len(hello.supportedVersions) > 0 && hello.supportedVersions[0] == VersionTLS13 {
		// Reset the list of ciphers when the client only supports TLS 1.3.
		if len(hello.supportedVersions) == 1 {
			hello.cipherSuites = nil
		}
		if fips140tls.Required() {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13FIPS...)
		} else if hasAESGCMHardwareSupport {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13...)
		} else {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13NoAES...)
		}

		if len(hello.supportedCurves) == 0 {
			return nil, nil, nil, utlserrors.New("tls: no supported elliptic curves for ECDHE").AtError()
		}
		curveID := hello.supportedCurves[0]
		keyShareKeys = &keySharePrivateKeys{curveID: curveID}
		// Note that if X25519MLKEM768 is supported, it will be first because
		// the preference order is fixed.
		if curveID == X25519MLKEM768 {
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), X25519)
			if err != nil {
				return nil, nil, nil, err
			}
			seed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(config.rand(), seed); err != nil {
				return nil, nil, nil, err
			}
			keyShareKeys.mlkem, err = mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, nil, nil, err
			}
			mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
			x25519EphemeralKey := keyShareKeys.ecdhe.PublicKey().Bytes()
			hello.keyShares = []keyShare{
				{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)},
			}
			// If both X25519MLKEM768 and X25519 are supported, we send both key
			// shares (as a fallback) and we reuse the same X25519 ephemeral
			// key, as allowed by draft-ietf-tls-hybrid-design-09, Section 3.2.
			if slices.Contains(hello.supportedCurves, X25519) {
				hello.keyShares = append(hello.keyShares, keyShare{group: X25519, data: x25519EphemeralKey})
			}
		} else if curveID == SecP256r1MLKEM768 {
			// SecP256r1MLKEM768: P-256 + ML-KEM-768 hybrid (draft-ietf-tls-ecdhe-mlkem-03)
			// Client key share format: P-256 public key (65 bytes) || ML-KEM-768 encapsulation key (1184 bytes)
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), CurveP256)
			if err != nil {
				return nil, nil, nil, err
			}
			seed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(config.rand(), seed); err != nil {
				return nil, nil, nil, err
			}
			keyShareKeys.mlkem, err = mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, nil, nil, err
			}
			p256PublicKey := keyShareKeys.ecdhe.PublicKey().Bytes()
			mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
			// Format: ECDH public key first, then ML-KEM encapsulation key (per draft-ietf-tls-ecdhe-mlkem-03)
			hello.keyShares = []keyShare{
				{group: SecP256r1MLKEM768, data: append(p256PublicKey, mlkemEncapsulationKey...)},
			}
			// If P-256 is also in supported curves, add it as a fallback
			if slices.Contains(hello.supportedCurves, CurveP256) {
				hello.keyShares = append(hello.keyShares, keyShare{group: CurveP256, data: p256PublicKey})
			}
		} else if curveID == SecP384r1MLKEM1024 {
			// SecP384r1MLKEM1024: P-384 + ML-KEM-1024 hybrid (draft-ietf-tls-ecdhe-mlkem-03)
			// Client key share format: P-384 public key (97 bytes) || ML-KEM-1024 encapsulation key (1568 bytes)
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), CurveP384)
			if err != nil {
				return nil, nil, nil, err
			}
			seed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(config.rand(), seed); err != nil {
				return nil, nil, nil, err
			}
			keyShareKeys.mlkem1024, err = mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, nil, nil, err
			}
			p384PublicKey := keyShareKeys.ecdhe.PublicKey().Bytes()
			mlkemEncapsulationKey := keyShareKeys.mlkem1024.EncapsulationKey().Bytes()
			// Format: ECDH public key first, then ML-KEM encapsulation key
			hello.keyShares = []keyShare{
				{group: SecP384r1MLKEM1024, data: append(p384PublicKey, mlkemEncapsulationKey...)},
			}
			// If P-384 is also in supported curves, add it as a fallback
			if slices.Contains(hello.supportedCurves, CurveP384) {
				hello.keyShares = append(hello.keyShares, keyShare{group: CurveP384, data: p384PublicKey})
			}
		} else {
			if _, ok := curveForCurveID(curveID); !ok {
				return nil, nil, nil, utlserrors.New("tls: CurvePreferences includes unsupported curve").AtError()
			}
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), curveID)
			if err != nil {
				return nil, nil, nil, err
			}
			hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe.PublicKey().Bytes()}}
		}
	}

	if c.quic != nil {
		p, err := c.quicGetTransportParameters()
		if err != nil {
			return nil, nil, nil, err
		}
		if p == nil {
			p = []byte{}
		}
		hello.quicTransportParameters = p
	}

	var ech *echClientContext
	if c.config.EncryptedClientHelloConfigList != nil {
		if c.config.MinVersion != 0 && c.config.MinVersion < VersionTLS13 {
			return nil, nil, nil, utlserrors.New("tls: MinVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated").AtError()
		}
		if c.config.MaxVersion != 0 && c.config.MaxVersion <= VersionTLS12 {
			return nil, nil, nil, utlserrors.New("tls: MaxVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated").AtError()
		}
		echConfigs, err := parseECHConfigList(c.config.EncryptedClientHelloConfigList)
		if err != nil {
			return nil, nil, nil, err
		}
		echConfig := pickECHConfig(echConfigs)
		if echConfig == nil {
			return nil, nil, nil, utlserrors.New("tls: EncryptedClientHelloConfigList contains no valid configs").AtError()
		}
		ech = &echClientContext{config: echConfig}
		hello.encryptedClientHello = []byte{1} // indicate inner hello

		// ECH spec Section 5.1: Inner ClientHello "MUST NOT offer to negotiate
		// TLS 1.2 or below". We must strip all TLS 1.2-specific elements.

		// We need to explicitly set these 1.2 fields to nil, as we do not
		// marshal them when encoding the inner hello, otherwise transcripts
		// will later mismatch.
		hello.supportedPoints = nil
		hello.ticketSupported = false
		hello.secureRenegotiationSupported = false
		hello.extendedMasterSecret = false

		// ECH spec Section 5.1: Filter supportedVersions to only include TLS 1.3+.
		// The inner ClientHello must not offer to negotiate TLS 1.2 or below.
		var tls13Versions []uint16
		for _, v := range hello.supportedVersions {
			if v >= VersionTLS13 {
				tls13Versions = append(tls13Versions, v)
			}
		}
		if len(tls13Versions) == 0 {
			return nil, nil, nil, utlserrors.New("tls: ECH requires TLS 1.3, but no TLS 1.3+ versions configured").AtError()
		}
		hello.supportedVersions = tls13Versions

		// ECH spec Section 5.1: Filter cipher suites to only include TLS 1.3 suites.
		// TLS 1.2 cipher suites must not be offered in the inner ClientHello.
		var tls13Suites []uint16
		for _, suite := range hello.cipherSuites {
			if cipherSuiteTLS13ByID(suite) != nil {
				tls13Suites = append(tls13Suites, suite)
			}
		}
		if len(tls13Suites) == 0 {
			return nil, nil, nil, utlserrors.New("tls: ECH requires TLS 1.3 cipher suites, but none configured").AtError()
		}
		hello.cipherSuites = tls13Suites

		// ECH spec Section 5.1: Clear TLS 1.2 session ticket.
		// Session resumption via session tickets is a TLS 1.2 mechanism.
		// TLS 1.3 uses PSK identities instead.
		hello.sessionTicket = nil

		echPK, err := hpke.ParseHPKEPublicKey(ech.config.KemID, ech.config.PublicKey)
		if err != nil {
			return nil, nil, nil, err
		}
		suite, err := pickECHCipherSuite(ech.config.SymmetricCipherSuite)
		if err != nil {
			return nil, nil, nil, err
		}
		ech.kdfID, ech.aeadID = suite.KDFID, suite.AEADID
		info := append([]byte("tls ech\x00"), ech.config.raw...)
		ech.encapsulatedKey, ech.hpkeContext, err = hpke.SetupSender(ech.config.KemID, suite.KDFID, suite.AEADID, echPK, info)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return hello, keyShareKeys, ech, nil
}

type echClientContext struct {
	config          *echConfig
	hpkeContext     *hpke.Sender
	encapsulatedKey []byte
	innerHello      *clientHelloMsg
	innerTranscript hash.Hash
	kdfID           uint16
	aeadID          uint16
	echRejected     bool
	retryConfigs    []byte
}

func (c *Conn) clientHandshake(ctx context.Context) (err error) {
	// Wire up observability hooks for handshake lifecycle monitoring.
	// Get remote address early - it may not be available if connection fails.
	var remoteAddr string
	if c.conn != nil {
		if addr := c.conn.RemoteAddr(); addr != nil {
			remoteAddr = addr.String()
		}
	}
	if remoteAddr == "" {
		remoteAddr = "unknown"
	}

	// Signal handshake start and track timing for duration measurement.
	callOnHandshakeStart(remoteAddr)
	startTime := time.Now()

	// Defer hook calls for success/failure based on outcome.
	// Also includes panic recovery to prevent crashes and report via observability.
	defer func() {
		// Panic recovery: catch any panics, report via observability, then re-panic
		if r := recover(); r != nil {
			callOnPanicRecovered("clientHandshake", r)
			// Convert panic to error for proper cleanup
			err = fmt.Errorf("tls: panic in clientHandshake: %v", r)
			callOnHandshakeFailure(remoteAddr, err.Error())
			// Re-panic to preserve stack trace for debugging
			panic(r)
		}

		if err != nil {
			callOnHandshakeFailure(remoteAddr, err.Error())
			// Classify error and call appropriate error-specific hooks
			classifyAndCallErrorHook(remoteAddr, err)
		} else {
			callOnHandshakeSuccess(remoteAddr, time.Since(startTime))
		}
	}()

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(ctx, "clientHandshake: starting handshake for ", c.config.ServerName)
	}
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	hello, keyShareKeys, ech, err := c.makeClientHello()
	if err != nil {
		utlserrors.LogDebug(ctx, "clientHandshake: makeClientHello failed")
		return err
	}

	session, earlySecret, binderKey, err := c.loadSession(hello)
	if err != nil {
		utlserrors.LogDebug(ctx, "clientHandshake: loadSession failed")
		return err
	}
	if session != nil {
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
					c.config.ClientSessionCache.Put(cacheKey, nil)
				}
			}
		}()
	}

	if ech != nil {
		// Split hello into inner and outer
		ech.innerHello = hello.clone()

		// Clear PSK from outer hello to prevent privacy leak.
		// PSK/session tickets in outer hello would be visible to network observers
		// and could be used to correlate connections across sessions, defeating
		// ECH's privacy goals. See draft-ietf-tls-esni-18 Section 6.1.4.
		hello.pskIdentities = nil
		hello.pskBinders = nil

		// Overwrite the server name in the outer hello with the public facing
		// name.
		hello.serverName = string(ech.config.PublicName)
		// Generate a new random for the outer hello.
		hello.random = make([]byte, 32)
		_, err = io.ReadFull(c.config.rand(), hello.random)
		if err != nil {
			return utlserrors.New("tls: short read from Rand for ECH outer hello").Base(err).AtError()
		}

		// NOTE: we don't do PSK GREASE, in line with boringssl, it's meant to
		// work around _possibly_ broken middleboxes, but there is little-to-no
		// evidence that this is actually a problem.

		if err := computeAndUpdateOuterECHExtension(hello, ech.innerHello, ech, true); err != nil {
			return err
		}
	}

	c.serverName = hello.serverName

	if _, err := c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	if hello.earlyData {
		// Safety check: session must be non-nil when earlyData is set.
		// Invariant: loadSession sets hello.earlyData=true only after accessing
		// session.EarlyData, guaranteeing session is non-nil. This explicit check
		// satisfies static analyzers and guards against future code changes.
		if session == nil {
			c.sendAlert(alertInternalError)
			return utlserrors.New("tls: internal error: earlyData set but session is nil").AtError()
		}
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		// Safety check: cipher suite must be valid for TLS 1.3 early data.
		// Invariant: loadSession validates cipherSuiteTLS13ByID(session.cipherSuite)
		// at lines 525-528 before enabling earlyData. This explicit check satisfies
		// static analyzers and provides clear error if invariant is violated.
		if suite == nil {
			c.sendAlert(alertInternalError)
			return utlserrors.New("tls: internal error: invalid cipher suite for early data").AtError()
		}
		transcript := suite.hash.New()
		if err := transcriptMsg(hello, transcript); err != nil {
			return err
		}
		earlyTrafficSecret, err := earlySecret.ClientEarlyTrafficSecret(transcript)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		c.quicSetWriteSecret(QUICEncryptionLevelEarly, suite.id, earlyTrafficSecret)
	}

	// serverHelloMsg is not included in the transcript
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return err
	}

	// If we are negotiating a protocol version that's lower than what we
	// support, check for the server downgrade canaries.
	// See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion(roleClient)
	tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
	tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
	if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
		maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox").AtError()
	}

	if c.vers == VersionTLS13 {
		hs := &clientHandshakeStateTLS13{
			c:            c,
			ctx:          ctx,
			serverHello:  serverHello,
			hello:        hello,
			keyShareKeys: keyShareKeys,
			session:      session,
			earlySecret:  earlySecret,
			binderKey:    binderKey,
			echContext:   ech,
		}
		return hs.handshake()
	}

	hs := &clientHandshakeState{
		c:           c,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}
	return hs.handshake()
}

func (c *Conn) loadSession(hello *clientHelloMsg) (
	session *SessionState, earlySecret *tls13.EarlySecret, binderKey []byte, err error) {
	// [UTLS SECTION START]
	if c.utls.sessionController != nil {
		if err = c.utls.sessionController.onEnterLoadSessionCheck(); err != nil {
			return nil, nil, nil, err
		}
		defer func() {
			if returnErr := c.utls.sessionController.onLoadSessionReturn(); returnErr != nil && err == nil {
				err = returnErr
			}
		}()
	}
	// [UTLS SECTION END]
	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil, nil, nil, nil
	}

	echInner := bytes.Equal(hello.encryptedClientHello, []byte{1})

	// ticketSupported is a TLS 1.2 extension (as TLS 1.3 replaced tickets with PSK
	// identities) and ECH requires and forces TLS 1.3.
	hello.ticketSupported = true && !echInner

	if hello.supportedVersions[0] == VersionTLS13 {
		// Require DHE on resumption as it guarantees forward secrecy against
		// compromise of the session ticket key. See RFC 8446, Section 4.2.9.
		hello.pskModes = []uint8{pskModeDHE}
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	if c.handshakes != 0 {
		return nil, nil, nil, nil
	}

	// Try to resume a previously negotiated TLS session, if available.
	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil, nil, nil, nil
	}
	cs, ok := c.config.ClientSessionCache.Get(cacheKey)
	if !ok || cs == nil {
		return nil, nil, nil, nil
	}
	session = cs.session

	// Check that version used for the previous session is still valid.
	versOk := false
	for _, v := range hello.supportedVersions {
		if v == session.version {
			versOk = true
			break
		}
	}
	if !versOk {
		return nil, nil, nil, nil
	}

	// Check that the cached server certificate is not expired, and that it's
	// valid for the ServerName. This should be ensured by the cache key, but
	// protect the application from a faulty ClientSessionCache implementation.
	// [UTLS SECTION START]
	if !c.config.InsecureSkipTimeVerify {
		if len(session.peerCertificates) > 0 && c.config.time().After(session.peerCertificates[0].NotAfter) {
			// Expired certificate, delete the entry.
			c.config.ClientSessionCache.Put(cacheKey, nil)
			return nil, nil, nil, nil
		}
	}
	// [UTLS SECTION END]
	if !c.config.InsecureSkipVerify {
		if len(session.verifiedChains) == 0 {
			// The original connection had InsecureSkipVerify, while this doesn't.
			return nil, nil, nil, nil
		}
		// [UTLS SECTION START]
		var dnsName string
		if len(c.config.InsecureServerNameToVerify) == 0 {
			dnsName = c.config.ServerName
		} else if c.config.InsecureServerNameToVerify != "*" {
			dnsName = c.config.InsecureServerNameToVerify
		}
		// Guard against empty peerCertificates slice before accessing [0]
		if len(dnsName) > 0 && len(session.peerCertificates) > 0 {
			if err := session.peerCertificates[0].VerifyHostname(dnsName); err != nil {
				return nil, nil, nil, nil
			}
		}
		// [UTLS SECTION END]
	}

	if session.version != VersionTLS13 {
		// In TLS 1.2 the cipher suite must match the resumed session. Ensure we
		// are still offering it.
		if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
			return nil, nil, nil, nil
		}

		hello.sessionTicket = session.ticket
		return
	}

	// Check that the session ticket is not expired.
	if c.config.time().After(time.Unix(int64(session.useBy), 0)) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return nil, nil, nil, nil
	}

	// In TLS 1.3 the KDF hash must match the resumed session. Ensure we
	// offer at least one cipher suite with that hash.
	cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
	if cipherSuite == nil {
		return nil, nil, nil, nil
	}
	cipherSuiteOk := false
	for _, offeredID := range hello.cipherSuites {
		offeredSuite := cipherSuiteTLS13ByID(offeredID)
		if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return nil, nil, nil, nil
	}

	if c.quic != nil {
		if c.quic.enableSessionEvents {
			c.quicResumeSession(session)
		}

		// For 0-RTT, the cipher suite has to match exactly, and we need to be
		// offering the same ALPN.
		if session.EarlyData && mutualCipherSuiteTLS13(hello.cipherSuites, session.cipherSuite) != nil {
			for _, alpn := range hello.alpnProtocols {
				if alpn == session.alpnProtocol {
					hello.earlyData = true
					break
				}
			}
		}
	}

	// Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
	ticketAge := c.config.time().Sub(time.Unix(int64(session.createdAt), 0))

	// Prevent integer overflow when converting ticketAge to uint32 milliseconds.
	// If the ticket is older than ~49.7 days (math.MaxUint32 milliseconds),
	// the conversion would wrap around, making old tickets appear young.
	// Skip resumption in this case as the ticket is too old anyway.
	ticketAgeMs := int64(ticketAge / time.Millisecond)
	if ticketAgeMs < 0 || ticketAgeMs > math.MaxUint32 {
		return nil, nil, nil, nil
	}

	// [uTLS] Use jittered ticket age computation to resist DPI correlation.
	// The jitter simulates natural clock drift between client and server.
	identity := pskIdentity{
		label:               session.ticket,
		obfuscatedTicketAge: computeTicketAgeWithJitter(ticketAge, session.ageAdd, c.config),
	}
	hello.pskIdentities = []pskIdentity{identity}
	hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}

	// Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
	earlySecret, err = tls13.NewEarlySecret(cipherSuite.hash.New, session.secret)
	if err != nil {
		return nil, nil, nil, err
	}
	binderKey, err = earlySecret.ResumptionBinderKey()
	if err != nil {
		return nil, nil, nil, err
	}
	// [UTLS SECTION START]
	if c.utls.sessionController != nil {
		shouldWrite, writeErr := c.utls.sessionController.shouldLoadSessionWriteBinders()
		if writeErr != nil {
			return nil, nil, nil, writeErr
		}
		if !shouldWrite {
			return
		}
	}
	// [UTLS SECTION END]
	transcript := cipherSuite.hash.New()
	// [uTLS] Use constant-time binder computation when configured to prevent timing side-channel attacks.
	// This is controlled by Config.PSKBinderConstantTime (defaults to true for security).
	finishedHashFunc := cipherSuite.finishedHash
	if c.config.PSKBinderConstantTime {
		finishedHashFunc = cipherSuite.finishedHashConstantTime
	}
	if err := computeAndUpdatePSK(hello, binderKey, transcript, finishedHashFunc); err != nil {
		return nil, nil, nil, err
	}

	return
}

func (c *Conn) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVersion := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVersion = serverHello.supportedVersion
	}

	vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return utlserrors.New("tls: server selected unsupported protocol version ", fmt.Sprintf("%x", peerVersion)).AtError()
	}

	c.vers = vers
	c.haveVers = true
	c.in.version = vers
	c.out.version = vers

	return nil
}

// Does the handshake, either a full one or resumes old session. Requires hs.c,
// hs.hello, hs.serverHello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	// [uTLS SECTION START]
	// Initialize handshake timing controller for fingerprint resistance.
	// Timing jitter simulates real browser behavior during handshakes.
	var timingCtrl *handshakeTimingController
	if hs.uconn != nil {
		timingCtrl = hs.uconn.getHandshakeTimingController()
	}
	// [uTLS SECTION END]

	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	// [uTLS SECTION START]
	// Apply ServerHello timing delay to simulate parsing and processing time.
	// Real browsers take measurable time to parse extensions and validate parameters.
	if timingCtrl != nil {
		timingCtrl.ApplyServerHelloDelay()
	}
	// [uTLS SECTION END]

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	if err := transcriptMsg(hs.hello, &hs.finishedHash); err != nil {
		return err
	}
	if err := transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil {
		return err
	}

	c.buffering = true
	c.didResume = isResume
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		// [uTLS SECTION START]
		// Apply Finished timing delay to simulate key derivation computation.
		// Real browsers take time for final key schedule operations.
		// Note: No certificate delay for resumed sessions as certs are not reverified.
		if timingCtrl != nil {
			timingCtrl.ApplyFinishedDelay()
		}
		// [uTLS SECTION END]
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		// [uTLS SECTION START]
		// Apply certificate timing delay to simulate chain verification.
		// Real browsers spend significant time validating certificate chains,
		// checking OCSP responses, and verifying signatures.
		if timingCtrl != nil {
			timingCtrl.ApplyCertificateDelay()
		}
		// [uTLS SECTION END]
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// [uTLS SECTION START]
		// Apply Finished timing delay to simulate key derivation computation.
		// Real browsers take time for final key schedule operations.
		if timingCtrl != nil {
			timingCtrl.ApplyFinishedDelay()
		}
		// [uTLS SECTION END]
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}
	if err := hs.saveSessionTicket(); err != nil {
		return err
	}

	if hs.suite == nil {
		c.sendAlert(alertInternalError)
		return utlserrors.New("tls: internal error: cipher suite not set after handshake").AtError()
	}
	c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random)
	c.isHandshakeComplete.Store(true)

	return nil
}

func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return utlserrors.New("tls: server chose an unconfigured cipher suite").AtError()
	}

	// [UTLS SECTION START]
	// if hs.c.config.CipherSuites == nil && !fips140tls.Required() && rsaKexCiphers[hs.suite.id] {
	// 	tlsrsakex.Value() // ensure godebug is initialized
	// 	tlsrsakex.IncNonDefault()
	// }
	// if hs.c.config.CipherSuites == nil && !fips140tls.Required() && tdesCiphers[hs.suite.id] {
	// 	tls3des.Value() // ensure godebug is initialized
	// 	tls3des.IncNonDefault()
	// }
	// [UTLS SECTION END]

	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}

	msg, err = c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(alertUnexpectedMessage)
			return utlserrors.New("tls: received unexpected CertificateStatus message").AtError()
		}

		c.ocspResponse = cs.response

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	if c.handshakes == 0 {
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		if err := c.verifyServerCertificate(certMsg.certificates); err != nil {
			return err
		}
	} else {
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return utlserrors.New("tls: server's identity changed during renegotiation").AtError()
		}
	}

	keyAgreement := hs.suite.ka(c.vers)
	// Ensure key material is zeroed even on error paths
	defer keyAgreement.cleanup()

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return err
		}
		if len(skx.key) >= 3 && skx.key[0] == 3 /* named curve */ {
			c.curveID = CurveID(byteorder.BEUint16(skx.key[1:]))
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	if ok {
		certRequested = true

		cri := certificateRequestInfoFromMsg(hs.ctx, c.vers, certReq)
		if chainToSend, err = c.getClientCertificate(cri); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		msg, err = c.readHandshake(&hs.finishedHash)
		if err != nil {
			return err
		}
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	if certRequested {
		certMsg = new(certificateMsg)
		if chainToSend != nil {
			certMsg.certificates = chainToSend.Certificate
		}
		if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
			return err
		}
	}

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		if _, err := hs.c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
			return err
		}
	}

	if hs.serverHello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret,
			hs.hello.random, hs.serverHello.random)
	}
	// Zero the pre-master secret immediately after deriving the master secret
	// to minimize the window where it could be extracted from memory.
	zeroSlice(preMasterSecret)

	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return utlserrors.New("tls: failed to write to key log").Base(err).AtError()
	}

	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{}

		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return utlserrors.New("tls: client certificate private key of type ", fmt.Sprintf("%T", chainToSend.PrivateKey), " does not implement crypto.Signer").AtError()
		}

		var sigType uint8
		var sigHash crypto.Hash
		if c.vers >= VersionTLS12 {
			signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
			sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
			if err != nil {
				return c.sendAlert(alertInternalError)
			}
			certVerify.hasSignatureAlgorithm = true
			certVerify.signatureAlgorithm = signatureAlgorithm
		} else {
			sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return err
			}
		}

		signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash)
		signOpts := crypto.SignerOpts(sigHash)
		if sigType == signatureRSAPSS {
			signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
		}
		certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		if _, err := hs.c.writeHandshakeRecord(certVerify, &hs.finishedHash); err != nil {
			return err
		}
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		if clientCipher == nil {
			return utlserrors.New("tls: failed to create client cipher").AtError()
		}
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		if serverCipher == nil {
			return utlserrors.New("tls: failed to create server cipher").AtError()
		}
		serverHash = hs.suite.mac(serverMAC)
	} else {
		var err error
		clientCipher, err = hs.suite.aead(clientKey, clientIV)
		if err != nil {
			return utlserrors.New("tls: failed to create client AEAD cipher").Base(err).AtError()
		}
		serverCipher, err = hs.suite.aead(serverKey, serverIV)
		if err != nil {
			return utlserrors.New("tls: failed to create server AEAD cipher").Base(err).AtError()
		}
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return false, err
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, utlserrors.New("tls: server selected unsupported compression format").AtError()
	}

	// RFC 8449 Section 5: max_fragment_length and record_size_limit are mutually exclusive.
	// A client MUST treat receipt of both extensions as a fatal error and generate
	// an "illegal_parameter" alert.
	if hs.serverHello.hasMaxFragmentLength && hs.serverHello.recordSizeLimit > 0 {
		c.sendAlert(alertIllegalParameter)
		return false, utlserrors.New("tls: server sent both max_fragment_length and record_size_limit extensions").AtError()
	}

	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, utlserrors.New("tls: initial handshake had non-empty renegotiation extension").AtError()
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if subtle.ConstantTimeCompare(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) != 1 {
			c.sendAlert(alertHandshakeFailure)
			return false, utlserrors.New("tls: incorrect renegotiation extension contents").AtError()
		}
	}

	if err := checkALPN(hs.hello.alpnProtocols, hs.serverHello.alpnProtocol, false); err != nil {
		c.sendAlert(alertUnsupportedExtension)
		return false, err
	}
	c.clientProtocol = hs.serverHello.alpnProtocol

	c.scts = hs.serverHello.scts

	if !hs.serverResumedSession() {
		return false, nil
	}

	if hs.session.version != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, utlserrors.New("tls: server resumed a session with a different version").AtError()
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, utlserrors.New("tls: server resumed a session with a different cipher suite").AtError()
	}

	// RFC 7627, Section 5.3
	if hs.session.extMasterSecret != hs.serverHello.extendedMasterSecret {
		c.sendAlert(alertHandshakeFailure)
		return false, utlserrors.New("tls: server resumed a session with a different EMS extension").AtError()
	}

	// Restore master secret and certificates from previous state
	hs.masterSecret = hs.session.secret
	c.extMasterSecret = hs.session.extMasterSecret
	c.peerCertificates = hs.session.peerCertificates
	c.activeCertHandles = hs.c.activeCertHandles
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	// Let the ServerHello SCTs override the session SCTs from the original
	// connection, if any are provided
	if len(c.scts) == 0 && len(hs.session.scts) != 0 {
		c.scts = hs.session.scts
	}

	return true, nil
}

// checkALPN ensure that the server's choice of ALPN protocol is compatible with
// the protocols that we advertised in the ClientHello.
func checkALPN(clientProtos []string, serverProto string, quic bool) error {
	if serverProto == "" {
		if quic && len(clientProtos) > 0 {
			// RFC 9001, Section 8.1
			return utlserrors.New("tls: server did not select an ALPN protocol").AtError()
		}
		return nil
	}
	if len(clientProtos) == 0 {
		return utlserrors.New("tls: server advertised unrequested ALPN extension").AtError()
	}
	for _, proto := range clientProtos {
		if proto == serverProto {
			return nil
		}
	}
	return utlserrors.New("tls: server selected unadvertised ALPN protocol").AtError()
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return utlserrors.New("tls: server's Finished message was incorrect").AtError()
	}

	if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}
	c := hs.c

	if !hs.hello.ticketSupported {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: server sent unrequested session ticket").AtError()
	}

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}

	hs.ticket = sessionTicketMsg.ticket
	return nil
}

func (hs *clientHandshakeState) saveSessionTicket() error {
	if hs.ticket == nil {
		return nil
	}
	c := hs.c

	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil
	}

	session := c.sessionState()
	session.secret = hs.masterSecret
	session.ticket = hs.ticket

	cs := &ClientSessionState{session: session}
	// [UTLS BEGIN]
	if c.config.ClientSessionCache != nil { // skip saving session if cache is nil
		c.config.ClientSessionCache.Put(cacheKey, cs)
	}
	// [UTLS END]
	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// defaultMaxRSAKeySize is the maximum RSA key size in bits that we are willing
// to verify the signatures of during a TLS handshake.
const defaultMaxRSAKeySize = 8192

// var tlsmaxrsasize = godebug.New("tlsmaxrsasize") // [uTLS] unused

func checkKeySize(n int) (max int, ok bool) {
	// [uTLS SECTION START]
	// Disable the unsupported godebug package
	// if v := tlsmaxrsasize.Value(); v != "" {
	// 	if max, err := strconv.Atoi(v); err == nil {
	// 		if (n <= max) != (n <= defaultMaxRSAKeySize) {
	// 			tlsmaxrsasize.IncNonDefault()
	// 		}
	// 		return max, n <= max
	// 	}
	// }
	// [uTLS SECTION END]
	return defaultMaxRSAKeySize, n <= defaultMaxRSAKeySize
}

// verifyServerCertificate parses and verifies the provided chain, setting
// c.verifiedChains and c.peerCertificates or sending the appropriate alert.
func (c *Conn) verifyServerCertificate(certificates [][]byte) error {
	ctx := context.Background()
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(ctx, "verifyServerCertificate: verifying ", len(certificates), " certificates")
	}
	activeHandles := make([]*activeCert, len(certificates))
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := globalCertCache.newCert(asn1Data)
		if err != nil {
			utlserrors.LogDebug(ctx, "verifyServerCertificate: failed to parse certificate ", i)
			c.sendAlert(alertBadCertificate)
			return utlserrors.New("tls: failed to parse certificate from server").Base(err).AtError()
		}
		if cert.cert.PublicKeyAlgorithm == x509.RSA {
			rsaKey, ok := cert.cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				c.sendAlert(alertBadCertificate)
				return utlserrors.New("tls: certificate public key type mismatch for RSA algorithm").AtError()
			}
			n := rsaKey.N.BitLen()
			if max, ok := checkKeySize(n); !ok {
				c.sendAlert(alertBadCertificate)
				return utlserrors.New("tls: server sent certificate containing RSA key larger than ", max, " bits").AtError()
			}
		}
		activeHandles[i] = cert
		certs[i] = cert.cert
	}

	echRejected := c.config.EncryptedClientHelloConfigList != nil && !c.echAccepted
	if echRejected {
		if c.config.EncryptedClientHelloRejectionVerify != nil {
			if err := c.config.EncryptedClientHelloRejectionVerify(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		} else {
			opts := x509.VerifyOptions{
				Roots:       c.config.RootCAs,
				CurrentTime: c.config.time(),
				// DNSName:       c.serverName, // [uTLS]
				Intermediates: x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}

			// [UTLS SECTION START]
			if c.config.InsecureSkipTimeVerify {
				// Check if certificate is within acceptable expired age limit
				maxAge := c.config.InsecureMaxExpiredAge
				if maxAge == 0 {
					maxAge = 30 * 24 * time.Hour // Default: 30 days max expired
				}
				now := time.Now()
				if maxAge > 0 && now.After(certs[0].NotAfter) {
					expiredDuration := now.Sub(certs[0].NotAfter)
					if expiredDuration > maxAge {
						utlserrors.LogError(context.Background(),
							"SECURITY: Certificate expired ", expiredDuration.String(), " ago, exceeds maximum allowed age of ", maxAge.String(), " - rejecting despite InsecureSkipTimeVerify")
						c.sendAlert(alertCertificateExpired)
						return &CertificateVerificationError{
							UnverifiedCertificates: certs,
							Err:                    utlserrors.New("tls: certificate expired more than maximum allowed age").AtError(),
						}
					}
					utlserrors.LogWarning(context.Background(),
						"InsecureSkipTimeVerify accepting certificate expired ", expiredDuration.String(), " ago")
				}
				opts.CurrentTime = certs[0].NotAfter
			}

			if len(c.config.InsecureServerNameToVerify) == 0 {
				opts.DNSName = c.config.ServerName
			} else if c.config.InsecureServerNameToVerify != "*" {
				opts.DNSName = c.config.InsecureServerNameToVerify
			} else {
				// SECURITY WARNING: "*" disables ALL hostname verification, making the
				// connection vulnerable to man-in-the-middle attacks. Any valid certificate
				// from any domain will be accepted. Only use this for testing purposes.
				utlserrors.LogWarning(context.Background(),
					"SECURITY RISK: InsecureServerNameToVerify='*' disables hostname verification - vulnerable to MITM attacks")
			}
			// [UTLS SECTION END]

			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
			chains, err := certs[0].Verify(opts)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
			}

			c.verifiedChains, err = fipsAllowedChains(chains)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
			}
		}
	} else if !c.config.InsecureSkipVerify {
		// [UTLS SECTION START]
		opts := x509.VerifyOptions{
			Roots:       c.config.RootCAs,
			CurrentTime: c.config.time(),
			// DNSName:       c.serverName, // [uTLS]
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}

		if c.config.InsecureSkipTimeVerify {
			// Check if certificate is within acceptable expired age limit
			maxAge := c.config.InsecureMaxExpiredAge
			if maxAge == 0 {
				maxAge = 30 * 24 * time.Hour // Default: 30 days max expired
			}
			now := time.Now()
			if maxAge > 0 && now.After(certs[0].NotAfter) {
				expiredDuration := now.Sub(certs[0].NotAfter)
				if expiredDuration > maxAge {
					utlserrors.LogError(context.Background(),
						"SECURITY: Certificate expired ", expiredDuration.String(), " ago, exceeds maximum allowed age of ", maxAge.String(), " - rejecting despite InsecureSkipTimeVerify")
					c.sendAlert(alertCertificateExpired)
					return &CertificateVerificationError{
						UnverifiedCertificates: certs,
						Err:                    utlserrors.New("tls: certificate expired more than maximum allowed age").AtError(),
					}
				}
				utlserrors.LogWarning(context.Background(),
					"InsecureSkipTimeVerify accepting certificate expired ", expiredDuration.String(), " ago")
			}
			opts.CurrentTime = certs[0].NotAfter
		}

		if len(c.config.InsecureServerNameToVerify) == 0 {
			opts.DNSName = c.config.ServerName
		} else if c.config.InsecureServerNameToVerify != "*" {
			opts.DNSName = c.config.InsecureServerNameToVerify
		} else {
			// SECURITY WARNING: "*" disables ALL hostname verification, making the
			// connection vulnerable to man-in-the-middle attacks. Any valid certificate
			// from any domain will be accepted. Only use this for testing purposes.
			utlserrors.LogWarning(context.Background(),
				"SECURITY RISK: InsecureServerNameToVerify='*' disables hostname verification - vulnerable to MITM attacks")
		}
		// [UTLS SECTION END]

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		chains, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}

		c.verifiedChains, err = fipsAllowedChains(chains)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return utlserrors.New("tls: server's certificate contains an unsupported type of public key: ", fmt.Sprintf("%T", certs[0].PublicKey)).AtError()
	}

	c.activeCertHandles = activeHandles
	c.peerCertificates = certs

	// [uTLS] Certificate Transparency validation per RFC 6962
	// Validate SCTs if RequireCT is enabled. SCTs may come from:
	// 1. TLS extension (c.scts, set in processServerHello or readServerCertificate)
	// 2. X.509v3 certificate extension (embedded in leaf certificate)
	// The validation happens after certificate chain verification to ensure we
	// have verified certificates before trusting SCT signatures.
	if c.config.RequireCT && !echRejected {
		// Collect SCTs from all sources
		allSCTs := make([][]byte, 0, len(c.scts)+8)

		// Add SCTs from TLS extension (already stored in c.scts)
		allSCTs = append(allSCTs, c.scts...)

		// Extract SCTs from certificate extension if present
		if certSCTs, err := ExtractSCTsFromCertificate(certs[0]); err == nil && len(certSCTs) > 0 {
			allSCTs = append(allSCTs, certSCTs...)
		}

		// Validate all collected SCTs
		if err := ValidateSCTs(certs[0], certs, allSCTs, c.config.CTLogs); err != nil {
			c.sendAlert(alertBadCertificate)
			return &CertificateVerificationError{
				UnverifiedCertificates: certs,
				Err:                    utlserrors.New("certificate transparency validation failed").Base(err).AtError(),
			}
		}
	}

	if c.config.VerifyPeerCertificate != nil && !echRejected {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil && !echRejected {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	return nil
}

// certificateRequestInfoFromMsg generates a CertificateRequestInfo from a TLS
// <= 1.2 CertificateRequest, making an effort to fill in missing information.
func certificateRequestInfoFromMsg(ctx context.Context, vers uint16, certReq *certificateRequestMsg) *CertificateRequestInfo {
	cri := &CertificateRequestInfo{
		AcceptableCAs: certReq.certificateAuthorities,
		Version:       vers,
		ctx:           ctx,
	}

	var rsaAvail, ecAvail bool
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecAvail = true
		}
	}

	if !certReq.hasSignatureAlgorithm {
		// Prior to TLS 1.2, signature schemes did not exist. In this case we
		// make up a list based on the acceptable certificate types, to help
		// GetClientCertificate and SupportsCertificate select the right certificate.
		// The hash part of the SignatureScheme is a lie here, because
		// TLS 1.0 and 1.1 always use MD5+SHA1 for RSA and SHA1 for ECDSA.
		switch {
		case rsaAvail && ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case rsaAvail:
			cri.SignatureSchemes = []SignatureScheme{
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1,
			}
		case ecAvail:
			cri.SignatureSchemes = []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
			}
		}
		return cri
	}

	// Filter the signature schemes based on the certificate types.
	// See RFC 5246, Section 7.4.4 (where it calls this "somewhat complicated").
	cri.SignatureSchemes = make([]SignatureScheme, 0, len(certReq.supportedSignatureAlgorithms))
	for _, sigScheme := range certReq.supportedSignatureAlgorithms {
		sigType, _, err := typeAndHashFromSignatureScheme(sigScheme)
		if err != nil {
			continue
		}
		switch sigType {
		case signatureECDSA, signatureEd25519:
			if ecAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		case signatureRSAPSS, signaturePKCS1v15:
			if rsaAvail {
				cri.SignatureSchemes = append(cri.SignatureSchemes, sigScheme)
			}
		}
	}

	return cri
}

func (c *Conn) getClientCertificate(cri *CertificateRequestInfo) (*Certificate, error) {
	if c.config.GetClientCertificate != nil {
		return c.config.GetClientCertificate(cri)
	}

	for _, chain := range c.config.Certificates {
		if err := cri.SupportsCertificate(&chain); err != nil {
			continue
		}
		return &chain, nil
	}

	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
func (c *Conn) clientSessionCacheKey() string {
	if len(c.config.ServerName) > 0 {
		return c.config.ServerName
	}
	if c.conn != nil {
		if addr := c.conn.RemoteAddr(); addr != nil {
			return addr.String()
		}
	}
	return ""
}

// hostnameInSNI converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// Internationalized Domain Names (IDN) are converted to Punycode (ASCII form).
// See RFC 6066, Section 3 and RFC 5891 (IDNA 2008).
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	// Convert IDN (Internationalized Domain Name) to Punycode (ASCII) form.
	// SNI extension requires ASCII-compatible encoding per RFC 6066.
	// idna.Lookup implements the IDNA 2008 Lookup protocol which:
	// - Converts Unicode to Punycode (e.g., "xn--nxasmq5b" for Greek letters)
	// - Validates the domain according to IDNA rules
	// - Returns the original string if it's already ASCII
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		// If IDN conversion fails, return the original name.
		// This maintains backward compatibility - the connection may still
		// succeed if the server accepts the non-ASCII name, or fail with
		// a more informative error during handshake.
		return name
	}
	return ascii
}

func computeAndUpdatePSK(m *clientHelloMsg, binderKey []byte, transcript hash.Hash, finishedHash func([]byte, hash.Hash) ([]byte, error)) error {
	helloBytes, err := m.marshalWithoutBinders()
	if err != nil {
		return err
	}
	transcript.Write(helloBytes)
	binder, err := finishedHash(binderKey, transcript)
	if err != nil {
		return err
	}
	pskBinders := [][]byte{binder}
	return m.updateBinders(pskBinders)
}
