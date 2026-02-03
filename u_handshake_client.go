// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utlserrors "github.com/refraction-networking/utls/errors"
	"github.com/refraction-networking/utls/internal/fips140tls"
	"github.com/refraction-networking/utls/internal/hpke"
	"github.com/refraction-networking/utls/internal/tls13"
)

// uconnClassifyAndCallErrorHook examines the error type and calls the appropriate
// error-specific observability hook. This provides fine-grained error tracking
// for timeout, network, and cryptographic errors during UConn TLS handshakes.
func uconnClassifyAndCallErrorHook(remoteAddr string, err error) {
	if err == nil {
		return
	}

	// Check for context-related errors (timeout/cancellation)
	if err == context.DeadlineExceeded || err == context.Canceled {
		callOnTimeoutError(remoteAddr)
		return
	}

	// Check if error wraps a context error
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		if unwrapped == context.DeadlineExceeded || unwrapped == context.Canceled {
			callOnTimeoutError(remoteAddr)
			return
		}
	}

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

// This function is called by (*clientHandshakeStateTLS13).readServerCertificate()
// to retrieve the certificate out of a message read by (*Conn).readHandshake()
func (hs *clientHandshakeStateTLS13) utlsReadServerCertificate(msg any) (processedMsg any, err error) {
	for _, ext := range hs.uconn.Extensions {
		switch ext.(type) {
		case *UtlsCompressCertExtension:
			// Included Compressed Certificate extension
			if len(hs.uconn.certCompressionAlgs) > 0 {
				compressedCertMsg, ok := msg.(*utlsCompressedCertificateMsg)
				if ok {
					if err = transcriptMsg(compressedCertMsg, hs.transcript); err != nil {
						return nil, err
					}
					msg, err = hs.decompressCert(*compressedCertMsg)
					if err != nil {
						return nil, utlserrors.New("tls: failed to decompress certificate message").Base(err).AtError()
					} else {
						return msg, nil
					}
				}
			}
		default:
			continue
		}
	}
	return nil, nil
}

// called by (*clientHandshakeStateTLS13).utlsReadServerCertificate() when UtlsCompressCertExtension is used
func (hs *clientHandshakeStateTLS13) decompressCert(m utlsCompressedCertificateMsg) (*certificateMsgTLS13, error) {
	var (
		decompressed io.Reader
		compressed   = bytes.NewReader(m.compressedCertificateMessage)
		c            = hs.c
	)

	// Check to see if the peer responded with an algorithm we advertised.
	supportedAlg := false
	for _, alg := range hs.uconn.certCompressionAlgs {
		if m.algorithm == uint16(alg) {
			supportedAlg = true
		}
	}
	if !supportedAlg {
		c.sendAlert(alertBadCertificate)
		return nil, utlserrors.New("tls: server used unadvertised compression algorithm: ", m.algorithm).AtError()
	}

	switch CertCompressionAlgo(m.algorithm) {
	case CertCompressionBrotli:
		decompressed = brotli.NewReader(compressed)

	case CertCompressionZlib:
		rc, err := zlib.NewReader(compressed)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, utlserrors.New("tls: failed to open zlib reader").Base(err).AtError()
		}
		defer rc.Close()
		decompressed = rc

	case CertCompressionZstd:
		rc, err := zstd.NewReader(compressed)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, utlserrors.New("tls: failed to open zstd reader").Base(err).AtError()
		}
		defer rc.Close()
		decompressed = rc

	default:
		c.sendAlert(alertBadCertificate)
		return nil, utlserrors.New("tls: unsupported compression algorithm: ", m.algorithm).AtError()
	}

	// RFC 8879: uncompressed_length is uint24, max 16MB. We use a reasonable limit to prevent DoS.
	// Most certificate chains are under 100KB; 16MB is extremely generous.
	const maxDecompressedCertSize = 1 << 24 // 16MB per RFC 8879
	if m.uncompressedLength > maxDecompressedCertSize {
		c.sendAlert(alertBadCertificate)
		return nil, utlserrors.New("tls: compressed certificate uncompressed length ", m.uncompressedLength, " exceeds maximum ", maxDecompressedCertSize).AtError()
	}
	if m.uncompressedLength == 0 {
		c.sendAlert(alertBadCertificate)
		return nil, utlserrors.New("tls: compressed certificate has zero uncompressed length").AtError()
	}

	rawMsg := make([]byte, m.uncompressedLength+4) // +4 for message type and uint24 length field
	rawMsg[0] = typeCertificate
	rawMsg[1] = uint8(m.uncompressedLength >> 16)
	rawMsg[2] = uint8(m.uncompressedLength >> 8)
	rawMsg[3] = uint8(m.uncompressedLength)

	// Use io.ReadFull to ensure we read the exact number of bytes.
	// A single Read() call is not guaranteed to return all data at once.
	n, err := io.ReadFull(decompressed, rawMsg[4:])
	if err != nil {
		c.sendAlert(alertBadCertificate)
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			// If, after decompression, the specified length does not match the actual length,
			// the party receiving the invalid message MUST abort the connection with the
			// "bad_certificate" alert. https://datatracker.ietf.org/doc/html/rfc8879#section-4
			return nil, utlserrors.New("tls: decompressed len ", n, " does not match specified len ", m.uncompressedLength).AtError()
		}
		return nil, err
	}

	// RFC 8879 Section 5: Implementations MUST limit the size of the resulting
	// decompressed chain to the specified uncompressed length, and they MUST abort
	// the connection if the size of the output of the decompression function exceeds
	// that limit. Verify no excess data remains after reading the declared length.
	extraByte := make([]byte, 1)
	if extraN, _ := decompressed.Read(extraByte); extraN > 0 {
		c.sendAlert(alertBadCertificate)
		return nil, utlserrors.New("tls: decompressed certificate data exceeds declared uncompressed_length").AtError()
	}

	certMsg := new(certificateMsgTLS13)
	if !certMsg.unmarshal(rawMsg) {
		return nil, c.sendAlert(alertUnexpectedMessage)
	}
	return certMsg, nil
}

// to be called in (*clientHandshakeStateTLS13).handshake(),
// after hs.readServerFinished() and before hs.sendClientCertificate()
func (hs *clientHandshakeStateTLS13) serverFinishedReceived() error {
	if err := hs.sendClientEncryptedExtensions(); err != nil {
		return err
	}
	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientEncryptedExtensions() error {
	c := hs.c
	clientEncryptedExtensions := new(utlsClientEncryptedExtensionsMsg)
	if c.utls.applicationSettingsCodepoint != 0 {
		clientEncryptedExtensions.applicationSettingsCodepoint = c.utls.applicationSettingsCodepoint
		clientEncryptedExtensions.applicationSettings = c.utls.localApplicationSettings
		if _, err := c.writeHandshakeRecord(clientEncryptedExtensions, hs.transcript); err != nil {
			return err
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) utlsReadServerParameters(encryptedExtensions *encryptedExtensionsMsg) error {
	hs.c.utls.peerApplicationSettings = encryptedExtensions.utls.applicationSettings
	hs.c.utls.applicationSettingsCodepoint = encryptedExtensions.utls.applicationSettingsCodepoint

	if hs.c.utls.applicationSettingsCodepoint != 0 {
		if hs.uconn.vers < VersionTLS13 {
			return utlserrors.New("tls: server sent application settings at invalid version").AtError()
		}
		if len(hs.uconn.clientProtocol) == 0 {
			return utlserrors.New("tls: server sent application settings without ALPN").AtError()
		}

		// Check if the ALPN selected by the server exists in the client's list.
		if alps, ok := hs.uconn.config.ApplicationSettings[hs.serverHello.alpnProtocol]; ok {
			hs.c.utls.localApplicationSettings = alps
		} else {
			// return errors.New("tls: server selected ALPN doesn't match a client ALPS")
			return nil // ignore if client doesn't have ALPS in use.
			// TODO: is this a issue or not?
		}
	}

	// RFC 8449 Section 5: max_fragment_length and record_size_limit are mutually exclusive.
	// A client MUST treat receipt of both extensions as a fatal error and generate
	// an "illegal_parameter" alert.
	if encryptedExtensions.utls.hasMaxFragmentLength && encryptedExtensions.utls.recordSizeLimit > 0 {
		hs.c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: server sent both max_fragment_length and record_size_limit extensions").AtError()
	}

	// RFC 8449: Process record_size_limit from server's EncryptedExtensions.
	// The server's limit tells us the maximum plaintext size we can SEND to the server.
	// We only honor this if we advertised record_size_limit in our ClientHello.
	if encryptedExtensions.utls.recordSizeLimit > 0 {
		// RFC 8449 Section 4: Version-specific maximum limits.
		// TLS 1.2 and earlier: max is 2^14 (16384)
		// TLS 1.3: max is 2^14+1 (16385) to account for content type byte
		maxLimit := uint16(16385)
		if hs.c.vers < VersionTLS13 {
			maxLimit = 16384
		}
		serverLimit := encryptedExtensions.utls.recordSizeLimit
		if serverLimit > maxLimit {
			hs.c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: server record_size_limit ", serverLimit, " exceeds maximum ", maxLimit, " for negotiated version").AtError()
		}

		// Verify we actually advertised record_size_limit extension
		advertisedLimit := uint16(0)
		for _, ext := range hs.uconn.Extensions {
			if rsl, ok := ext.(*RecordSizeLimitExtension); ok {
				advertisedLimit = rsl.Limit
				break
			}
		}
		if advertisedLimit > 0 {
			// Server responded with its limit - this is what we must respect when sending.
			// Per RFC 8449 Section 4: The server MUST NOT send a value larger than
			// the value the client offered. If it does, we should use our advertised value.
			if serverLimit > advertisedLimit {
				// Server violated RFC 8449 by sending larger limit than we offered.
				// Use our advertised limit as a safety measure.
				serverLimit = advertisedLimit
			}
			// Store in Conn.utls so maxPayloadSizeForWrite can access it
			hs.c.utls.negotiatedRecordSizeLimit = serverLimit
		}
	}

	return nil
}

func (c *Conn) makeClientHelloForApplyPreset() (*clientHelloMsg, *keySharePrivateKeys, *echClientContext, error) {
	config := c.config

	// [UTLS SECTION START]
	// Validate that the config has enough information for certificate verification.
	// Either ServerName must be set for hostname verification, or InsecureSkipVerify
	// must be true to skip verification entirely. InsecureServerNameToVerify is also
	// accepted as an alternative for advanced use cases (e.g., fingerprint spoofing).
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify && len(config.InsecureServerNameToVerify) == 0 {
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
	if hello.supportedVersions[0] == VersionTLS13 {
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
		// curveID := hello.supportedCurves[0]
		// keyShareKeys = &keySharePrivateKeys{curveID: curveID}
		// // Note that if X25519MLKEM768 is supported, it will be first because
		// // the preference order is fixed.
		// if curveID == X25519MLKEM768 {
		// 	keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), X25519)
		// 	if err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	seed := make([]byte, mlkem.SeedSize)
		// 	if _, err := io.ReadFull(config.rand(), seed); err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	keyShareKeys.mlkem, err = mlkem.NewDecapsulationKey768(seed)
		// 	if err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
		// 	x25519EphemeralKey := keyShareKeys.ecdhe.PublicKey().Bytes()
		// 	hello.keyShares = []keyShare{
		// 		{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)},
		// 	}
		// 	// If both X25519MLKEM768 and X25519 are supported, we send both key
		// 	// shares (as a fallback) and we reuse the same X25519 ephemeral
		// 	// key, as allowed by draft-ietf-tls-hybrid-design-09, Section 3.2.
		// 	if slices.Contains(hello.supportedCurves, X25519) {
		// 		hello.keyShares = append(hello.keyShares, keyShare{group: X25519, data: x25519EphemeralKey})
		// 	}
		// } else {
		// 	if _, ok := curveForCurveID(curveID); !ok {
		// 		return nil, nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
		// 	}
		// 	keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), curveID)
		// 	if err != nil {
		// 		return nil, nil, nil, err
		// 	}
		// 	hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe.PublicKey().Bytes()}}
		// }
	}

	// [UTLS] We don't need this, since it is not ready yet
	// if c.quic != nil {
	// 	p, err := c.quicGetTransportParameters()
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}
	// 	if p == nil {
	// 		p = []byte{}
	// 	}
	// 	hello.quicTransportParameters = p
	// }

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
		// We need to explicitly set these 1.2 fields to nil, as we do not
		// marshal them when encoding the inner hello, otherwise transcripts
		// will later mismatch.
		hello.supportedPoints = nil
		hello.ticketSupported = false
		hello.secureRenegotiationSupported = false
		hello.extendedMasterSecret = false

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

// clientHandshakeWithOneState checks that exactly one expected state is set (1.2 or 1.3)
// and performs client TLS handshake with that state
func (c *UConn) clientHandshake(ctx context.Context) (err error) {
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
	defer func() {
		if err != nil {
			callOnHandshakeFailure(remoteAddr, err.Error())
			// Classify error and call appropriate error-specific hooks
			uconnClassifyAndCallErrorHook(remoteAddr, err)
		} else {
			callOnHandshakeSuccess(remoteAddr, time.Since(startTime))
		}
	}()

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(ctx, "UConn clientHandshake: starting uTLS handshake for ", c.config.ServerName)
	}

	// [uTLS section begins]
	hello := c.HandshakeState.Hello.getPrivatePtr()
	ech := c.echCtx.Load()
	defer func() { c.HandshakeState.Hello = hello.getPublicPtr() }()

	sessionIsLocked := c.utls.sessionController.isSessionLocked()

	// after this point exactly 1 out of 2 HandshakeState pointers is non-nil,
	// useTLS13 variable tells which pointer
	// [uTLS section ends]

	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	// [uTLS section begins]
	// don't make new ClientHello, use hs.hello
	// preserve the checks from beginning and end of makeClientHello()
	// Validate that the config has enough information for certificate verification.
	// Either ServerName must be set for hostname verification, or InsecureSkipVerify
	// must be true to skip verification entirely. InsecureServerNameToVerify is also
	// accepted as an alternative for advanced use cases (e.g., fingerprint spoofing).
	if len(c.config.ServerName) == 0 && !c.config.InsecureSkipVerify && len(c.config.InsecureServerNameToVerify) == 0 {
		return utlserrors.New("tls: either Config.ServerName must be set or Config.InsecureSkipVerify must be true").AtError()
	}

	nextProtosLength := 0
	for _, proto := range c.config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return utlserrors.New("tls: invalid NextProtos value").AtError()
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return utlserrors.New("tls: NextProtos values too large").AtError()
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	var (
		session     *SessionState
		earlySecret *tls13.EarlySecret
		binderKey   []byte
	)
	if !sessionIsLocked {
		// [uTLS section ends]

		session, earlySecret, binderKey, err = c.loadSession(hello)

		// [uTLS section start]
	} else {
		session = c.HandshakeState.Session

		if c.HandshakeState.State13.EarlySecret != nil && session != nil {
			cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
			if cipherSuite == nil {
				return utlserrors.New("tls: unknown cipher suite for session resumption").AtError()
			}
			var esErr error
			earlySecret, esErr = tls13.NewEarlySecretFromSecret(cipherSuite.hash.New, c.HandshakeState.State13.EarlySecret)
			if esErr != nil {
				return esErr
			}
		}

		binderKey = c.HandshakeState.State13.BinderKey
	}
	// [uTLS section ends]
	if err != nil {
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

	if ech != nil && c.clientHelloBuildStatus != BuildByUtls {
		// Split hello into inner and outer
		ech.innerHello = hello.clone()

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

	// [uTLS] Early data (0-RTT) transmission block.
	// Per RFC 8446 Section 4.2.10, early data requires:
	// 1. A valid TLS 1.3 session with EarlyData support
	// 2. Matching cipher suite
	// 3. Matching ALPN protocol (if used)
	// 4. Derived early traffic secret
	//
	// Validation is critical because EarlyDataExtension.writeToUConn() sets
	// hello.earlyData=true unconditionally, but session may be nil or invalid.
	canSendEarlyData := hello.earlyData &&
		session != nil &&
		session.EarlyData &&
		earlySecret != nil

	// Additional validation: verify cipher suite and ALPN match
	if canSendEarlyData {
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
		if suite == nil {
			canSendEarlyData = false
		} else if session.alpnProtocol != "" {
			// If session has ALPN, verify client is offering the same protocol
			alpnMatch := false
			for _, alpn := range hello.alpnProtocols {
				if alpn == session.alpnProtocol {
					alpnMatch = true
					break
				}
			}
			if !alpnMatch {
				canSendEarlyData = false
			}
		}
	}

	if canSendEarlyData {
		suite := cipherSuiteTLS13ByID(session.cipherSuite)
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

		// [uTLS] For non-QUIC connections, transmit any buffered early data as 0-RTT records.
		// This happens after ClientHello is sent but before we read ServerHello.
		// Per RFC 8446 Section 4.2.10, early data is encrypted with client_early_traffic_secret
		// and sent using application_data content type (0x17).
		//
		// For QUIC connections, early data is handled at the transport layer via
		// quicSetWriteSecret() above, not through this path.
		if c.quic == nil {
			// Initialize early data state with session limits if not already set
			if c.earlyData == nil {
				c.earlyData = NewEarlyDataState()
			}
			// Enable with the session's max_early_data_size limit
			c.earlyData.EnableWithCipherSuite(session.maxEarlyDataSize, earlyTrafficSecret, suite.id)

			if err := c.transmitEarlyData(suite, earlyTrafficSecret); err != nil {
				// Log the error but don't fail the handshake - early data is optional
				// and the server may reject it anyway. The data is still buffered
				// for potential fallback transmission after handshake.
				if c.config.KeyLogWriter != nil {
					// Only log if key logging is enabled (indicates debug mode)
					c.config.writeKeyLog("EARLY_DATA_ERROR", hello.random, []byte(err.Error()))
				}
			}
		}
	} else if hello.earlyData {
		// hello.earlyData was set (EarlyDataExtension present) but we cannot send early data.
		// This is not an error - the server will see early_data extension but no early data,
		// which is allowed per RFC 8446 (server may reject or accept empty early data).
		// Log for debugging if key logging is enabled.
		if c.config.KeyLogWriter != nil && c.quic == nil {
			reason := "unknown"
			if session == nil {
				reason = "no_session"
			} else if !session.EarlyData {
				reason = "session_no_early_data"
			} else if earlySecret == nil {
				reason = "no_early_secret"
			}
			c.config.writeKeyLog("EARLY_DATA_SKIPPED", hello.random, []byte(reason))
		}
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

	// [uTLS] Capture raw ServerHello for JA4S calculation
	if serverHello.original != nil {
		c.stateMu.Lock()
		c.rawServerHello = make([]byte, len(serverHello.original))
		copy(c.rawServerHello, serverHello.original)
		c.stateMu.Unlock()
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

	// uTLS: do not create new handshakeState, use existing one
	c.HandshakeState.ServerHello = serverHello.getPublicPtr()
	if c.vers == VersionTLS13 {
		hs13 := c.HandshakeState.toPrivate13()
		hs13.serverHello = serverHello
		hs13.hello = hello
		hs13.echContext = ech
		if c.HandshakeState.State13.EarlySecret != nil && session.cipherSuite != 0 {
			suite := cipherSuiteTLS13ByID(session.cipherSuite)
			if suite == nil {
				return utlserrors.New("tls: unknown cipher suite for early secret session resumption").AtError()
			}
			var esErr error
			hs13.earlySecret, esErr = tls13.NewEarlySecretFromSecret(suite.hash.New, c.HandshakeState.State13.EarlySecret)
			if esErr != nil {
				return esErr
			}
		}
		if c.HandshakeState.MasterSecret != nil && session.cipherSuite != 0 {
			suite := cipherSuiteTLS13ByID(session.cipherSuite)
			if suite == nil {
				return utlserrors.New("tls: unknown cipher suite for master secret session resumption").AtError()
			}
			var msErr error
			hs13.masterSecret, msErr = tls13.NewMasterSecretFromSecret(suite.hash.New, c.HandshakeState.MasterSecret)
			if msErr != nil {
				return msErr
			}
		}
		if !sessionIsLocked {
			hs13.earlySecret = earlySecret
			hs13.binderKey = binderKey
			hs13.session = session
		}
		hs13.ctx = ctx
		// In TLS 1.3, session tickets are delivered after the handshake.
		err = hs13.handshake()
		if handshakeState := hs13.toPublic13(); handshakeState != nil {
			c.HandshakeState = *handshakeState
		}
		return err
	}

	hs12 := c.HandshakeState.toPrivate12()
	hs12.serverHello = serverHello
	hs12.hello = hello
	hs12.ctx = ctx
	hs12.session = session
	err = hs12.handshake()
	if handshakeState := hs12.toPublic12(); handshakeState != nil {
		c.HandshakeState = *handshakeState
	}
	if err != nil {
		return err
	}
	return nil
}

func (c *UConn) echTranscriptMsg(outer *clientHelloMsg, echCtx *echClientContext) (err error) {
	// Recreate the inner ClientHello from its compressed form using server's decodeInnerClientHello function.
	// See https://github.com/refraction-networking/utls/blob/e430876b1d82fdf582efc57f3992d448e7ab3d8a/ech.go#L276-L283
	encodedInner, err := encodeInnerClientHelloReorderOuterExts(echCtx.innerHello, int(echCtx.config.MaxNameLength), c.extensionsList())
	if err != nil {
		return err
	}

	decodedInner, err := decodeInnerClientHello(outer, encodedInner)
	if err != nil {
		return err
	}

	if err := transcriptMsg(decodedInner, echCtx.innerTranscript); err != nil {
		return err
	}

	return nil
}
