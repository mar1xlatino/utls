// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	utlserrors "github.com/refraction-networking/utls/errors"
	"github.com/refraction-networking/utls/internal/byteorder"
	"github.com/refraction-networking/utls/internal/fips140tls"
	"github.com/refraction-networking/utls/internal/hkdf"
	"github.com/refraction-networking/utls/internal/hpke"
	"github.com/refraction-networking/utls/internal/tls13"
)

// maxClientPSKIdentities is the number of client PSK identities the server will
// attempt to validate. It will ignore the rest not to let cheap ClientHello
// messages cause too much work in session ticket decryption attempts.
const maxClientPSKIdentities = 5

type echServerContext struct {
	hpkeContext *hpke.Recipient
	configID    uint8
	ciphersuite echCipher
	// inner indicates that the initial client_hello we recieved contained an
	// encrypted_client_hello extension that indicated it was an "inner" hello.
	// We don't do any additional processing of the hello in this case, so all
	// fields above are unset.
	inner bool
}

type serverHandshakeStateTLS13 struct {
	c               *Conn
	ctx             context.Context
	clientHello     *clientHelloMsg
	hello           *serverHelloMsg
	sentDummyCCS    bool
	usingPSK        bool
	earlyData       bool
	suite           *cipherSuiteTLS13
	cert            *Certificate
	sigAlg          SignatureScheme
	earlySecret     *tls13.EarlySecret
	sharedKey       []byte
	handshakeSecret *tls13.HandshakeSecret
	masterSecret    *tls13.MasterSecret
	trafficSecret   []byte // client_application_traffic_secret_0
	transcript      hash.Hash
	clientFinished  []byte
	echContext      *echServerContext
}

func (hs *serverHandshakeStateTLS13) handshake() error {
	c := hs.c

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 handshake starting")
	}

	// For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
	if err := hs.processClientHello(); err != nil {
		return err
	}
	if err := hs.checkForResumption(); err != nil {
		return err
	}
	if err := hs.pickCertificate(); err != nil {
		return err
	}
	c.buffering = true
	if err := hs.sendServerParameters(); err != nil {
		return err
	}
	if err := hs.sendServerCertificate(); err != nil {
		return err
	}
	if err := hs.sendServerFinished(); err != nil {
		return err
	}
	// Note that at this point we could start sending application data without
	// waiting for the client's second flight, but the application might not
	// expect the lack of replay protection of the ClientHello parameters.
	if _, err := c.flush(); err != nil {
		return err
	}
	if err := hs.readClientCertificate(); err != nil {
		return err
	}
	if err := hs.readClientFinished(); err != nil {
		return err
	}

	c.isHandshakeComplete.Store(true)

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 handshake completed successfully")
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) processClientHello() error {
	c := hs.c

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 processing ClientHello, SNI:", hs.clientHello.serverName)
	}

	hs.hello = new(serverHelloMsg)

	// TLS 1.3 froze the ServerHello.legacy_version field, and uses
	// supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
	hs.hello.vers = VersionTLS12
	hs.hello.supportedVersion = c.vers

	if len(hs.clientHello.supportedVersions) == 0 {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: client used the legacy version field to negotiate TLS 1.3").AtError()
	}

	// Abort if the client is doing a fallback and landing lower than what we
	// support. See RFC 7507, which however does not specify the interaction
	// with supported_versions. The only difference is that with
	// supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
	// handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
	// it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
	// TLS 1.2, because a TLS 1.3 server would abort here. The situation before
	// supported_versions was not better because there was just no way to do a
	// TLS 1.4 handshake without risking the server selecting TLS 1.3.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// Use c.vers instead of max(supported_versions) because an attacker
			// could defeat this by adding an arbitrary high version otherwise.
			if c.vers < c.config.maxSupportedVersion(roleServer) {
				c.sendAlert(alertInappropriateFallback)
				return utlserrors.New("tls: client using inappropriate protocol fallback").AtError()
			}
			break
		}
	}

	if len(hs.clientHello.compressionMethods) != 1 ||
		hs.clientHello.compressionMethods[0] != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: TLS 1.3 client supports illegal compression methods").AtError()
	}

	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	// RFC 5746 Section 3.4: In an initial handshake, the renegotiated_connection
	// field must be empty. Section 3.6: For TLS, reject with handshake_failure.
	// RFC 8446 Section 4.1.2: TLS 1.3 does not support renegotiation.
	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		if c.handshakes > 0 {
			// Client is attempting renegotiation, which is not allowed in TLS 1.3
			return utlserrors.New("tls: renegotiation not supported in TLS 1.3").AtError()
		}
		return utlserrors.New("tls: initial handshake had non-empty renegotiation extension").AtError()
	}

	if hs.clientHello.earlyData && c.quic != nil {
		if len(hs.clientHello.pskIdentities) == 0 {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: early_data without pre_shared_key").AtError()
		}
	} else if hs.clientHello.earlyData && c.config.ServerMaxEarlyData > 0 {
		// [uTLS] Non-QUIC 0-RTT support: allow early_data when ServerMaxEarlyData is configured
		if len(hs.clientHello.pskIdentities) == 0 {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: early_data without pre_shared_key").AtError()
		}
	} else if hs.clientHello.earlyData {
		// See RFC 8446, Section 4.2.10 for the complicated behavior required
		// here. The scenario is that a different server at our address offered
		// to accept early data in the past, which we can't handle. For now, all
		// 0-RTT enabled session tickets need to expire before a Go server can
		// replace a server or join a pool. That's the same requirement that
		// applies to mixing or replacing with any TLS 1.2 server.
		c.sendAlert(alertUnsupportedExtension)
		return utlserrors.New("tls: client sent unexpected early data").AtError()
	}

	// RFC 9001 Section 8.4: A client MUST NOT request the use of the TLS 1.3
	// compatibility mode. A server SHOULD treat the receipt of a TLS ClientHello
	// with a non-empty legacy_session_id field as a connection error.
	if c.quic != nil && len(hs.clientHello.sessionId) > 0 {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: QUIC client sent non-empty legacy_session_id").AtError()
	}

	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.compressionMethod = compressionNone

	preferenceList := defaultCipherSuitesTLS13
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(hs.clientHello.cipherSuites) {
		preferenceList = defaultCipherSuitesTLS13NoAES
	}
	if fips140tls.Required() {
		preferenceList = defaultCipherSuitesTLS13FIPS
	}
	for _, suiteID := range preferenceList {
		hs.suite = mutualCipherSuiteTLS13(hs.clientHello.cipherSuites, suiteID)
		if hs.suite != nil {
			break
		}
	}
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return utlserrors.New("tls: no cipher suite supported by both client and server").AtError()
	}
	c.cipherSuite = hs.suite.id
	hs.hello.cipherSuite = hs.suite.id
	hs.transcript = hs.suite.hash.New()

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 selected cipher suite", fmt.Sprintf("0x%04x", hs.suite.id))
	}

	// First, if a post-quantum key exchange is available, use one. See
	// draft-ietf-tls-key-share-prediction-01, Section 4 for why this must be
	// first.
	//
	// Second, if the client sent a key share for a group we support, use that,
	// to avoid a HelloRetryRequest round-trip.
	//
	// Finally, pick in our fixed preference order.
	preferredGroups := c.config.curvePreferences(c.vers)
	preferredGroups = slices.DeleteFunc(preferredGroups, func(group CurveID) bool {
		return !slices.Contains(hs.clientHello.supportedCurves, group)
	})
	if len(preferredGroups) == 0 {
		c.sendAlert(alertHandshakeFailure)
		return utlserrors.New("tls: no key exchanges supported by both client and server").AtError()
	}
	hasKeyShare := func(group CurveID) bool {
		for _, ks := range hs.clientHello.keyShares {
			if ks.group == group {
				return true
			}
		}
		return false
	}
	sort.SliceStable(preferredGroups, func(i, j int) bool {
		return hasKeyShare(preferredGroups[i]) && !hasKeyShare(preferredGroups[j])
	})
	sort.SliceStable(preferredGroups, func(i, j int) bool {
		return isPQKeyExchange(preferredGroups[i]) && !isPQKeyExchange(preferredGroups[j])
	})
	selectedGroup := preferredGroups[0]

	var clientKeyShare *keyShare
	for _, ks := range hs.clientHello.keyShares {
		if ks.group == selectedGroup {
			clientKeyShare = &ks
			break
		}
	}
	if clientKeyShare == nil {
		ks, err := hs.doHelloRetryRequest(selectedGroup)
		if err != nil {
			return err
		}
		clientKeyShare = ks
	}
	c.curveID = selectedGroup

	ecdhGroup := selectedGroup
	ecdhData := clientKeyShare.data
	if selectedGroup == X25519MLKEM768 {
		ecdhGroup = X25519
		if len(ecdhData) != mlkem.EncapsulationKeySize768+x25519PublicKeySize {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: invalid X25519MLKEM768 client key share").AtError()
		}
		ecdhData = ecdhData[mlkem.EncapsulationKeySize768:]
	}
	if selectedGroup == SecP256r1MLKEM768 {
		// SecP256r1MLKEM768: P-256 point (65 bytes) || ML-KEM encapsulation key (1184 bytes)
		ecdhGroup = CurveP256
		if len(ecdhData) != p256PublicKeySize+mlkem.EncapsulationKeySize768 {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: invalid SecP256r1MLKEM768 client key share").AtError()
		}
		ecdhData = ecdhData[:p256PublicKeySize]
	}
	if selectedGroup == SecP384r1MLKEM1024 {
		// SecP384r1MLKEM1024: P-384 point (97 bytes) || ML-KEM-1024 encapsulation key (1568 bytes) = 1665 bytes
		ecdhGroup = CurveP384
		if len(ecdhData) != p384PublicKeySize+mlkem1024EncapsulationKeySize {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: invalid SecP384r1MLKEM1024 client key share").AtError()
		}
		ecdhData = ecdhData[:p384PublicKeySize]
	}
	if _, ok := curveForCurveID(ecdhGroup); !ok {
		// RFC 8446 Section 6.2: illegal_parameter - A field in the handshake
		// was incorrect or inconsistent with other fields. This applies when
		// the negotiated curve cannot be used.
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: CurvePreferences includes unsupported curve").AtError()
	}
	key, err := generateECDHEKey(c.config.rand(), ecdhGroup)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}
	peerKey, err := key.Curve().NewPublicKey(ecdhData)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: invalid client key share").AtError()
	}
	hs.sharedKey, err = key.ECDH(peerKey)
	if err != nil {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: invalid client key share").AtError()
	}
	if selectedGroup == X25519MLKEM768 {
		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[:mlkem.EncapsulationKeySize768])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: invalid X25519MLKEM768 client key share").AtError()
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		// draft-ietf-tls-ecdhe-mlkem-03, Section 3.1.3: "For
		// X25519MLKEM768, the shared secret is the concatenation of the ML-KEM
		// shared secret and the X25519 shared secret. The shared secret is 64
		// bytes (32 bytes for each part)."
		//
		// FIX: Explicit allocation to prevent append aliasing.
		// Encapsulate() returns cap=64 for a 32-byte secret (SHA-512 internal buffer),
		// so append(mlkemSharedSecret, ecdhKey...) reuses the same backing array.
		// If anyone later adds zeroSlice(mlkemSharedSecret), it would silently
		// destroy the first 32 bytes of the combined shared key.
		combined := make([]byte, len(mlkemSharedSecret)+len(hs.sharedKey))
		copy(combined, mlkemSharedSecret)
		copy(combined[len(mlkemSharedSecret):], hs.sharedKey)
		hs.sharedKey = combined
		// draft-ietf-tls-ecdhe-mlkem-03, Section 3.1.2: "When the
		// X25519MLKEM768 group is negotiated, the server's key exchange value
		// is the concatenation of an ML-KEM ciphertext returned from
		// encapsulation to the client's encapsulation key, and the server's
		// ephemeral X25519 share."
		hs.hello.serverShare.data = append(ciphertext, hs.hello.serverShare.data...)
	}
	if selectedGroup == SecP256r1MLKEM768 {
		// SecP256r1MLKEM768: ML-KEM encapsulation key is at offset p256PublicKeySize
		k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[p256PublicKeySize:])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: invalid SecP256r1MLKEM768 client key share").AtError()
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		// draft-ietf-tls-ecdhe-mlkem-03, Section 4.3: "For SecP256r1MLKEM768,
		// the shared secret is the concatenation of the ECDHE and ML-KEM shared
		// secret. The size of the shared secret is 64 bytes (32 bytes for each part)."
		hs.sharedKey = append(hs.sharedKey, mlkemSharedSecret...)
		// draft-ietf-tls-ecdhe-mlkem-03, Section 4.2: "When the SecP256r1MLKEM768
		// group is negotiated, the server's key exchange value is the concatenation
		// of the server's ephemeral secp256r1 share and an ML-KEM ciphertext."
		hs.hello.serverShare.data = append(hs.hello.serverShare.data, ciphertext...)
	}
	if selectedGroup == SecP384r1MLKEM1024 {
		// SecP384r1MLKEM1024: ML-KEM-1024 encapsulation key is at offset p384PublicKeySize
		k, err := mlkem.NewEncapsulationKey1024(clientKeyShare.data[p384PublicKeySize:])
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: invalid SecP384r1MLKEM1024 client key share").AtError()
		}
		mlkemSharedSecret, ciphertext := k.Encapsulate()
		// draft-ietf-tls-ecdhe-mlkem-03, Section 4.3: "For SecP384r1MLKEM1024,
		// the shared secret is the concatenation of the ECDHE and ML-KEM shared
		// secret. The size of the shared secret is 80 bytes (48 bytes for ECDH
		// part and 32 bytes for the ML-KEM part)."
		hs.sharedKey = append(hs.sharedKey, mlkemSharedSecret...)
		// draft-ietf-tls-ecdhe-mlkem-03, Section 4.2: "When the SecP384r1MLKEM1024
		// group is negotiated, the server's key exchange value is the concatenation
		// of the server's ephemeral secp384r1 share and an ML-KEM ciphertext."
		hs.hello.serverShare.data = append(hs.hello.serverShare.data, ciphertext...)
	}

	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols, c.quic != nil)
	if err != nil {
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	c.clientProtocol = selectedProto

	if c.quic != nil {
		// RFC 9001 Section 4.2: Clients MUST NOT offer TLS versions older than 1.3.
		for _, v := range hs.clientHello.supportedVersions {
			if v < VersionTLS13 {
				c.sendAlert(alertProtocolVersion)
				return utlserrors.New("tls: client offered TLS version older than TLS 1.3").AtError()
			}
		}
		// RFC 9001 Section 8.2.
		if hs.clientHello.quicTransportParameters == nil {
			c.sendAlert(alertMissingExtension)
			return utlserrors.New("tls: client did not send a quic_transport_parameters extension").AtError()
		}
		c.quicSetTransportParameters(hs.clientHello.quicTransportParameters)
	} else {
		if hs.clientHello.quicTransportParameters != nil {
			c.sendAlert(alertUnsupportedExtension)
			return utlserrors.New("tls: client sent an unexpected quic_transport_parameters extension").AtError()
		}
	}

	c.serverName = hs.clientHello.serverName
	return nil
}

func (hs *serverHandshakeStateTLS13) checkForResumption() error {
	c := hs.c

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 checking for session resumption")
	}

	if c.config.SessionTicketsDisabled {
		if utlserrors.DebugLoggingEnabled {
			utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 session tickets disabled")
		}
		return nil
	}

	modeOK := false
	for _, mode := range hs.clientHello.pskModes {
		if mode == pskModeDHE {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return nil
	}

	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		c.sendAlert(alertIllegalParameter)
		return utlserrors.New("tls: invalid or missing PSK binders").AtError()
	}
	if len(hs.clientHello.pskIdentities) == 0 {
		return nil
	}

	// RFC 8446 Section 4.2.11.2: All binders must be verified in constant time
	// relative to each other to prevent timing attacks revealing which PSK was accepted.
	//
	// Strategy: First validate all PSK identities and compute expected binders,
	// then verify ALL binders before making a selection decision.

	numIdentities := len(hs.clientHello.pskIdentities)
	if numIdentities > maxClientPSKIdentities {
		numIdentities = maxClientPSKIdentities
	}

	// pskCandidate holds pre-validated PSK information for constant-time selection
	type pskCandidate struct {
		valid             bool
		sessionState      *SessionState
		earlySecret       *tls13.EarlySecret
		pskBinder         []byte // computed expected binder
		ticketAgeMismatch bool   // RFC 8446 Section 4.2.10: age validation failed
	}

	candidates := make([]pskCandidate, numIdentities)

	// Phase 1: Validate all PSK identities and compute expected binders.
	// This phase may have variable timing per identity, but the binder
	// verification in Phase 2 will be constant-time across all identities.
	for i := 0; i < numIdentities; i++ {
		identity := hs.clientHello.pskIdentities[i]

		var sessionState *SessionState
		if c.config.UnwrapSession != nil {
			var err error
			sessionState, err = c.config.UnwrapSession(identity.label, c.connectionStateLocked())
			if err != nil {
				return err
			}
			if sessionState == nil {
				continue
			}
		} else {
			plaintext := c.config.decryptTicket(identity.label, c.ticketKeys)
			if plaintext == nil {
				continue
			}
			var err error
			sessionState, err = ParseSessionState(plaintext)
			if err != nil {
				continue
			}
		}

		if sessionState.version != VersionTLS13 {
			continue
		}

		createdAt := time.Unix(int64(sessionState.createdAt), 0)
		ticketAge := c.config.time().Sub(createdAt)
		if ticketAge > maxSessionTicketLifetime {
			continue
		}

		// RFC 8446 Section 4.2.10: Validate ticket age freshness.
		// The client sends obfuscated_ticket_age = (ticket_age_ms + ageAdd) mod 2^32.
		// We verify this matches the actual ticket age within a tolerance.
		// This is a SHOULD requirement - mismatch rejects 0-RTT but allows handshake.
		var ticketAgeMismatch bool
		if ticketAge >= 0 {
			// Compute claimed age: obfuscated_ticket_age - ageAdd (mod 2^32)
			claimedAgeMs := identity.obfuscatedTicketAge - sessionState.ageAdd
			actualAgeMs := uint32(ticketAge.Milliseconds())

			// Allow 10-second tolerance for clock drift per RFC 8446 Section 8.3
			const ticketAgeTolerance = 10000 // milliseconds
			var ageDiff int64
			if actualAgeMs >= claimedAgeMs {
				ageDiff = int64(actualAgeMs - claimedAgeMs)
			} else {
				ageDiff = int64(claimedAgeMs - actualAgeMs)
			}
			if ageDiff > int64(ticketAgeTolerance) {
				ticketAgeMismatch = true
			}
		}

		pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
		if pskSuite == nil || pskSuite.hash != hs.suite.hash {
			continue
		}

		// PSK connections don't re-establish client certificates, but carry
		// them over in the session ticket. Ensure the presence of client certs
		// in the ticket is consistent with the configured requirements.
		sessionHasClientCerts := len(sessionState.peerCertificates) != 0
		needClientCerts := requiresClientCert(c.config.ClientAuth)
		if needClientCerts && !sessionHasClientCerts {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
			continue
		}
		if sessionHasClientCerts && c.config.time().After(sessionState.peerCertificates[0].NotAfter) {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth >= VerifyClientCertIfGiven &&
			len(sessionState.verifiedChains) == 0 {
			continue
		}

		// Compute the expected binder for this PSK
		earlySecret, err := tls13.NewEarlySecret(hs.suite.hash.New, sessionState.secret)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		binderKey, err := earlySecret.ResumptionBinderKey()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		// Clone the transcript in case a HelloRetryRequest was recorded.
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			c.sendAlert(alertInternalError)
			return utlserrors.New("tls: internal error: failed to clone hash").AtError()
		}
		clientHelloBytes, err := hs.clientHello.marshalWithoutBinders()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		transcript.Write(clientHelloBytes)
		pskBinder, err := hs.suite.finishedHash(binderKey, transcript)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		candidates[i] = pskCandidate{
			valid:             true,
			sessionState:      sessionState,
			earlySecret:       earlySecret,
			pskBinder:         pskBinder,
			ticketAgeMismatch: ticketAgeMismatch,
		}
	}

	// Phase 2: Verify ALL binders in constant time.
	// We must verify every binder for every valid candidate to prevent timing attacks.
	// Use subtle.ConstantTimeCompare which returns 1 for match, 0 for mismatch.
	binderMatches := make([]int, numIdentities)
	for i := 0; i < numIdentities; i++ {
		if candidates[i].valid {
			// Compare the provided binder with the expected one
			binderMatches[i] = subtle.ConstantTimeCompare(
				hs.clientHello.pskBinders[i],
				candidates[i].pskBinder,
			)
		}
		// For invalid candidates, binderMatches[i] remains 0
	}

	// Phase 3: Check for any valid sessions with invalid binders.
	// RFC 8446: If a session is valid but the binder is wrong, this indicates
	// a forged or corrupted binder and must result in a decrypt_error alert.
	// We must check ALL valid candidates before deciding to prevent timing leaks.
	hasValidCandidate := false
	hasValidWithBadBinder := false
	selectedIndex := -1
	for i := 0; i < numIdentities; i++ {
		if candidates[i].valid {
			hasValidCandidate = true
			if binderMatches[i] == 1 {
				// Valid session with matching binder - select first one
				if selectedIndex == -1 {
					selectedIndex = i
				}
			} else {
				// Valid session but binder doesn't match - this is an error
				hasValidWithBadBinder = true
			}
		}
	}

	// If any valid session had an invalid binder, reject the handshake.
	// This prevents attackers from using corrupted binders.
	if hasValidWithBadBinder && selectedIndex == -1 {
		// All valid sessions had bad binders - this is an attack
		c.sendAlert(alertDecryptError)
		return utlserrors.New("tls: invalid PSK binder").AtError()
	}

	// No valid PSK found - this is not an error, just no resumption
	if !hasValidCandidate || selectedIndex == -1 {
		return nil
	}

	selected := candidates[selectedIndex]

	// Set the early secret from the selected candidate
	hs.earlySecret = selected.earlySecret

	// Handle QUIC session events
	if c.quic != nil && c.quic.enableSessionEvents {
		if err := c.quicResumeSession(selected.sessionState); err != nil {
			return err
		}
	}

	// Handle early data (0-RTT) for QUIC - only allowed for the first PSK identity
	// RFC 8446 Section 4.2.10: Reject 0-RTT if ticket age mismatch detected
	if c.quic != nil && hs.clientHello.earlyData && selectedIndex == 0 &&
		selected.sessionState.EarlyData && selected.sessionState.cipherSuite == hs.suite.id &&
		selected.sessionState.alpnProtocol == c.clientProtocol &&
		!selected.ticketAgeMismatch {
		hs.earlyData = true

		transcript := hs.suite.hash.New()
		if err := transcriptMsg(hs.clientHello, transcript); err != nil {
			return err
		}
		earlyTrafficSecret, err := hs.earlySecret.ClientEarlyTrafficSecret(transcript)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		c.quicSetReadSecret(QUICEncryptionLevelEarly, hs.suite.id, earlyTrafficSecret)
	}

	// [uTLS] Handle early data (0-RTT) for non-QUIC when ServerMaxEarlyData is configured
	// RFC 8446 Section 4.2.10: Reject 0-RTT if ticket age mismatch detected
	if c.quic == nil && c.config.ServerMaxEarlyData > 0 && hs.clientHello.earlyData && selectedIndex == 0 &&
		selected.sessionState.EarlyData && selected.sessionState.cipherSuite == hs.suite.id &&
		selected.sessionState.alpnProtocol == c.clientProtocol &&
		!selected.ticketAgeMismatch {
		hs.earlyData = true
		// Note: For non-QUIC, the early data traffic secret is derived but the actual
		// early data reading requires additional implementation in conn.go.
		// Setting hs.earlyData = true causes the server to send early_data extension
		// in EncryptedExtensions, signaling acceptance to the client.
	}

	c.didResume = true
	c.peerCertificates = selected.sessionState.peerCertificates
	c.ocspResponse = selected.sessionState.ocspResponse
	c.scts = selected.sessionState.scts
	c.verifiedChains = selected.sessionState.verifiedChains

	hs.hello.selectedIdentityPresent = true
	hs.hello.selectedIdentity = uint16(selectedIndex)
	hs.usingPSK = true
	return nil
}

// cloneHash uses the encoding.BinaryMarshaler and encoding.BinaryUnmarshaler
// interfaces implemented by standard library hashes to clone the state of in
// to a new instance of h. It returns nil if the operation fails.
func cloneHash(in hash.Hash, h crypto.Hash) hash.Hash {
	// Recreate the interface to avoid importing encoding.
	type binaryMarshaler interface {
		MarshalBinary() (data []byte, err error)
		UnmarshalBinary(data []byte) error
	}
	marshaler, ok := in.(binaryMarshaler)
	if !ok {
		return nil
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil
	}
	out := h.New()
	unmarshaler, ok := out.(binaryMarshaler)
	if !ok {
		return nil
	}
	if err := unmarshaler.UnmarshalBinary(state); err != nil {
		return nil
	}
	return out
}

func (hs *serverHandshakeStateTLS13) pickCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		if utlserrors.DebugLoggingEnabled {
			utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 using PSK, skipping certificate selection")
		}
		return nil
	}

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 selecting certificate")
	}

	// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
	if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
		return c.sendAlert(alertMissingExtension)
	}

	certificate, err := c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			c.sendAlert(alertUnrecognizedName)
		} else {
			c.sendAlert(alertInternalError)
		}
		return err
	}
	hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
	if err != nil {
		// getCertificate returned a certificate that is unsupported or
		// incompatible with the client's signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	hs.cert = certificate

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.c.quic != nil {
		return nil
	}
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	return hs.c.writeChangeCipherRecord()
}

func (hs *serverHandshakeStateTLS13) doHelloRetryRequest(selectedGroup CurveID) (*keyShare, error) {
	c := hs.c

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return nil, err
	}
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)

	helloRetryRequest := &serverHelloMsg{
		vers:              hs.hello.vers,
		random:            helloRetryRequestRandom,
		sessionId:         hs.hello.sessionId,
		cipherSuite:       hs.hello.cipherSuite,
		compressionMethod: hs.hello.compressionMethod,
		supportedVersion:  hs.hello.supportedVersion,
		selectedGroup:     selectedGroup,
	}

	if hs.echContext != nil {
		// Compute the acceptance message.
		helloRetryRequest.encryptedClientHello = make([]byte, 8)
		confTranscript := cloneHash(hs.transcript, hs.suite.hash)
		if confTranscript == nil {
			c.sendAlert(alertInternalError)
			return nil, utlserrors.New("tls: internal error: failed to clone transcript hash for ECH").AtError()
		}
		if err := transcriptMsg(helloRetryRequest, confTranscript); err != nil {
			return nil, err
		}
		hrrEchSecret, err := hkdf.Extract(hs.suite.hash.New, hs.clientHello.random, nil)
		if err != nil {
			return nil, err
		}
		acceptConfirmation, err := tls13.ExpandLabel(hs.suite.hash.New,
			hrrEchSecret,
			"hrr ech accept confirmation",
			confTranscript.Sum(nil),
			8,
		)
		if err != nil {
			return nil, err
		}
		helloRetryRequest.encryptedClientHello = acceptConfirmation
	}

	if _, err := hs.c.writeHandshakeRecord(helloRetryRequest, hs.transcript); err != nil {
		return nil, err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return nil, err
	}

	// clientHelloMsg is not included in the transcript.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, err
	}

	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}

	if hs.echContext != nil {
		if len(clientHello.encryptedClientHello) == 0 {
			c.sendAlert(alertMissingExtension)
			return nil, utlserrors.New("tls: second client hello missing encrypted client hello extension").AtError()
		}

		echType, echCiphersuite, configID, encap, payload, err := parseECHExt(clientHello.encryptedClientHello)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return nil, utlserrors.New("tls: client sent invalid encrypted client hello extension").AtError()
		}

		if echType == outerECHExt && hs.echContext.inner || echType == innerECHExt && !hs.echContext.inner {
			c.sendAlert(alertDecodeError)
			return nil, utlserrors.New("tls: unexpected switch in encrypted client hello extension type").AtError()
		}

		if echType == outerECHExt {
			if echCiphersuite != hs.echContext.ciphersuite || configID != hs.echContext.configID || len(encap) != 0 {
				c.sendAlert(alertIllegalParameter)
				return nil, utlserrors.New("tls: second client hello encrypted client hello extension does not match").AtError()
			}

			encodedInner, err := decryptECHPayload(hs.echContext.hpkeContext, clientHello.original, payload)
			if err != nil {
				c.sendAlert(alertDecryptError)
				return nil, utlserrors.New("tls: failed to decrypt second client hello encrypted client hello extension payload").AtError()
			}

			echInner, err := decodeInnerClientHello(clientHello, encodedInner)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return nil, utlserrors.New("tls: client sent invalid encrypted client hello extension").AtError()
			}

			clientHello = echInner
		}
	}

	if len(clientHello.keyShares) != 1 {
		c.sendAlert(alertIllegalParameter)
		return nil, utlserrors.New("tls: client didn't send one key share in second ClientHello").AtError()
	}
	ks := &clientHello.keyShares[0]

	if ks.group != selectedGroup {
		c.sendAlert(alertIllegalParameter)
		return nil, utlserrors.New("tls: client sent unexpected key share in second ClientHello").AtError()
	}

	if clientHello.earlyData {
		c.sendAlert(alertIllegalParameter)
		return nil, utlserrors.New("tls: client indicated early data in second ClientHello").AtError()
	}

	if illegalClientHelloChange(clientHello, hs.clientHello) {
		c.sendAlert(alertIllegalParameter)
		return nil, utlserrors.New("tls: client illegally modified second ClientHello").AtError()
	}

	c.didHRR = true
	hs.clientHello = clientHello
	return ks, nil
}

// illegalClientHelloChange reports whether the two ClientHello messages are
// different, with the exception of the changes allowed before and after a
// HelloRetryRequest. See RFC 8446, Section 4.1.2.
func illegalClientHelloChange(ch, ch1 *clientHelloMsg) bool {
	if len(ch.supportedVersions) != len(ch1.supportedVersions) ||
		len(ch.cipherSuites) != len(ch1.cipherSuites) ||
		len(ch.supportedCurves) != len(ch1.supportedCurves) ||
		len(ch.supportedSignatureAlgorithms) != len(ch1.supportedSignatureAlgorithms) ||
		len(ch.supportedSignatureAlgorithmsCert) != len(ch1.supportedSignatureAlgorithmsCert) ||
		len(ch.alpnProtocols) != len(ch1.alpnProtocols) {
		return true
	}
	for i := range ch.supportedVersions {
		if ch.supportedVersions[i] != ch1.supportedVersions[i] {
			return true
		}
	}
	for i := range ch.cipherSuites {
		if ch.cipherSuites[i] != ch1.cipherSuites[i] {
			return true
		}
	}
	for i := range ch.supportedCurves {
		if ch.supportedCurves[i] != ch1.supportedCurves[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithms {
		if ch.supportedSignatureAlgorithms[i] != ch1.supportedSignatureAlgorithms[i] {
			return true
		}
	}
	for i := range ch.supportedSignatureAlgorithmsCert {
		if ch.supportedSignatureAlgorithmsCert[i] != ch1.supportedSignatureAlgorithmsCert[i] {
			return true
		}
	}
	for i := range ch.alpnProtocols {
		if ch.alpnProtocols[i] != ch1.alpnProtocols[i] {
			return true
		}
	}
	return ch.vers != ch1.vers ||
		!bytes.Equal(ch.random, ch1.random) ||
		!bytes.Equal(ch.sessionId, ch1.sessionId) ||
		!bytes.Equal(ch.compressionMethods, ch1.compressionMethods) ||
		ch.serverName != ch1.serverName ||
		ch.ocspStapling != ch1.ocspStapling ||
		!bytes.Equal(ch.supportedPoints, ch1.supportedPoints) ||
		ch.ticketSupported != ch1.ticketSupported ||
		!bytes.Equal(ch.sessionTicket, ch1.sessionTicket) ||
		ch.secureRenegotiationSupported != ch1.secureRenegotiationSupported ||
		!bytes.Equal(ch.secureRenegotiation, ch1.secureRenegotiation) ||
		ch.scts != ch1.scts ||
		!bytes.Equal(ch.cookie, ch1.cookie) ||
		!bytes.Equal(ch.pskModes, ch1.pskModes) ||
		// RFC 9001 Section 8.1: QUIC transport parameters must not change after HRR
		!bytes.Equal(ch.quicTransportParameters, ch1.quicTransportParameters)
}

func (hs *serverHandshakeStateTLS13) sendServerParameters() error {
	c := hs.c

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 sending server parameters")
	}

	if hs.echContext != nil {
		copy(hs.hello.random[32-8:], make([]byte, 8))
		echTranscript := cloneHash(hs.transcript, hs.suite.hash)
		if echTranscript == nil {
			c.sendAlert(alertInternalError)
			return utlserrors.New("tls: internal error: failed to clone transcript hash for ECH confirmation").AtError()
		}
		echTranscript.Write(hs.clientHello.original)
		if err := transcriptMsg(hs.hello, echTranscript); err != nil {
			return err
		}
		// compute the acceptance message
		echSecret, err := hkdf.Extract(hs.suite.hash.New, hs.clientHello.random, nil)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		acceptConfirmation, err := tls13.ExpandLabel(hs.suite.hash.New,
			echSecret,
			"ech accept confirmation",
			echTranscript.Sum(nil),
			8,
		)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		copy(hs.hello.random[32-8:], acceptConfirmation)
	}

	if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil {
		return err
	}

	if _, err := hs.c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil {
		return err
	}

	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		var err error
		earlySecret, err = tls13.NewEarlySecret(hs.suite.hash.New, nil)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}
	handshakeSecret, err := earlySecret.HandshakeSecret(hs.sharedKey)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	hs.handshakeSecret = handshakeSecret
	// Zero the shared key immediately after deriving the handshake secret
	// to minimize the window where it could be extracted from memory.
	zeroSlice(hs.sharedKey)
	hs.sharedKey = nil

	clientSecret, err := hs.handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if err := c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	serverSecret, err := hs.handshakeSecret.ServerHandshakeTrafficSecret(hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if err := c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelHandshake, hs.suite.id, serverSecret)
		c.quicSetReadSecret(QUICEncryptionLevelHandshake, hs.suite.id, clientSecret)
	}

	err = c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	encryptedExtensions := new(encryptedExtensionsMsg)
	encryptedExtensions.alpnProtocol = c.clientProtocol

	// [uTLS] Check if client sent ALPS and server has application settings for the negotiated ALPN
	if hs.clientHello.alpsCodepoint != 0 && len(c.clientProtocol) > 0 {
		if alps, ok := c.config.ApplicationSettings[c.clientProtocol]; ok {
			encryptedExtensions.utls.applicationSettingsCodepoint = hs.clientHello.alpsCodepoint
			encryptedExtensions.utls.applicationSettings = alps
		}
	}

	if c.quic != nil {
		p, err := c.quicGetTransportParameters()
		if err != nil {
			return err
		}
		encryptedExtensions.quicTransportParameters = p
		encryptedExtensions.earlyData = hs.earlyData
	}

	// If client sent ECH extension, but we didn't accept it,
	// send retry configs, if available.
	if len(hs.c.config.EncryptedClientHelloKeys) > 0 && len(hs.clientHello.encryptedClientHello) > 0 && hs.echContext == nil {
		encryptedExtensions.echRetryConfigs, err = buildRetryConfigList(hs.c.config.EncryptedClientHelloKeys)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	if _, err := hs.c.writeHandshakeRecord(encryptedExtensions, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) requestClientCert() bool {
	return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
}

func (hs *serverHandshakeStateTLS13) sendServerCertificate() error {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil
	}

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 sending server certificate")
	}

	if hs.requestClientCert() {
		// Request a client certificate
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
		if c.config.ClientCAs != nil {
			// Note: Subjects() is deprecated for system cert pools because it
			// won't include system roots. However, ClientCAs is user-configured
			// and not the system pool, so this usage is correct and safe.
			//lint:ignore SA1019 ClientCAs is user-configured, not a system cert pool
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}

		if _, err := hs.c.writeHandshakeRecord(certReq, hs.transcript); err != nil {
			return err
		}
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0

	// [uTLS] Check if we should compress the certificate (RFC 8879)
	compressionAlg := hs.negotiateCertCompression()
	if compressionAlg != 0 {
		// Send CompressedCertificate instead of Certificate
		compressedMsg, err := hs.compressCertificate(certMsg, compressionAlg)
		if err != nil || compressedMsg == nil {
			// Fall back to uncompressed on error or when compression is not beneficial
			// (RFC 8879 Section 4.2.1: compression SHOULD NOT be applied if result >= original)
			if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil {
				return err
			}
		} else {
			if _, err := hs.c.writeHandshakeRecord(compressedMsg, hs.transcript); err != nil {
				return err
			}
		}
	} else {
		if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil {
			return err
		}
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	certVerifyMsg.signatureAlgorithm = hs.sigAlg

	sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	signer, ok := hs.cert.PrivateKey.(crypto.Signer)
	if !ok {
		c.sendAlert(alertInternalError)
		return utlserrors.New("tls: server certificate private key does not implement crypto.Signer").AtError()
	}
	sig, err := signer.Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		public := signer.Public()
		if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
			rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
			c.sendAlert(alertHandshakeFailure)
		} else {
			c.sendAlert(alertInternalError)
		}
		return utlserrors.New("tls: failed to sign handshake").Base(err).AtError()
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) sendServerFinished() error {
	c := hs.c

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 sending server Finished")
	}

	verifyData, err := hs.suite.finishedHash(c.out.trafficSecret, hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	finished := &finishedMsg{
		verifyData: verifyData,
	}

	if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil {
		return err
	}

	// Derive secrets that take context through the server Finished.

	hs.masterSecret, err = hs.handshakeSecret.MasterSecret()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	hs.trafficSecret, err = hs.masterSecret.ClientApplicationTrafficSecret(hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	serverSecret, err := hs.masterSecret.ServerApplicationTrafficSecret(hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if err := c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if c.quic != nil {
		if c.hand.Len() != 0 {
			// TODO: Handle this in setTrafficSecret?
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelApplication, hs.suite.id, serverSecret)
	}

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	// If we did not request client certificates, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() {
		if err := hs.sendSessionTickets(); err != nil {
			return err
		}
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) shouldSendSessionTickets() bool {
	if hs.c.config.SessionTicketsDisabled {
		return false
	}

	// QUIC tickets are sent by QUICConn.SendSessionTicket, not automatically.
	if hs.c.quic != nil {
		return false
	}

	// Don't send tickets the client wouldn't use. See RFC 8446, Section 4.2.9.
	for _, pskMode := range hs.clientHello.pskModes {
		if pskMode == pskModeDHE {
			return true
		}
	}
	return false
}

func (hs *serverHandshakeStateTLS13) sendSessionTickets() error {
	c := hs.c

	var err error
	hs.clientFinished, err = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	if err := transcriptMsg(finishedMsg, hs.transcript); err != nil {
		return err
	}

	c.resumptionSecret, err = hs.masterSecret.ResumptionMasterSecret(hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if !hs.shouldSendSessionTickets() {
		return nil
	}
	return c.sendSessionTicket(false, nil)
}

func (c *Conn) sendSessionTicket(earlyData bool, extra [][]byte) error {
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	if suite == nil {
		return utlserrors.New("tls: internal error: unknown cipher suite").AtError()
	}
	// ticket_nonce, which must be unique per connection, is always left at
	// zero because we only ever send one ticket per connection.
	psk, err := tls13.ExpandLabel(suite.hash.New, c.resumptionSecret, "resumption",
		nil, suite.hash.Size())
	if err != nil {
		return err
	}

	m := new(newSessionTicketMsgTLS13)

	// ticket_age_add is a random 32-bit value. See RFC 8446, section 4.6.1.
	// CRITICAL: Generate ageAdd BEFORE creating the session state so it's
	// included in the encrypted ticket. This is required for 0-RTT ticket
	// age validation per RFC 8446 Section 4.2.10.
	ageAdd := make([]byte, 4)
	if _, err := c.config.rand().Read(ageAdd); err != nil {
		return err
	}
	m.ageAdd = byteorder.LEUint32(ageAdd)
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)

	state := c.sessionState()
	state.secret = psk
	state.EarlyData = earlyData
	state.Extra = extra
	state.ageAdd = m.ageAdd // Store ageAdd in session state for ticket age validation
	if c.config.WrapSession != nil {
		var err error
		m.label, err = c.config.WrapSession(c.connectionStateLocked(), state)
		if err != nil {
			return err
		}
	} else {
		stateBytes, err := state.Bytes()
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		m.label, err = c.config.encryptTicket(stateBytes, c.ticketKeys)
		if err != nil {
			return err
		}
	}

	if earlyData {
		// RFC 9001, Section 4.6.1
		m.maxEarlyData = 0xffffffff
	} else if c.config.ServerMaxEarlyData > 0 {
		// [uTLS] Non-QUIC 0-RTT support: advertise maxEarlyData in session tickets
		m.maxEarlyData = c.config.ServerMaxEarlyData
		state.EarlyData = true
		state.maxEarlyDataSize = c.config.ServerMaxEarlyData
	}

	if _, err := c.writeHandshakeRecord(m, nil); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientCertificate() error {
	c := hs.c

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 reading client certificate")
	}

	if !hs.requestClientCert() {
		// Make sure the connection is still being verified whether or not
		// the server requested a client certificate.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	// If we requested a client certificate, then the client must send a
	// certificate message. If it's empty, no CertificateVerify is sent.

	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}

	if err := c.processCertsFromClient(certMsg.certificate); err != nil {
		return err
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if len(certMsg.certificate.Certificate) != 0 {
		// certificateVerifyMsg is included in the transcript, but not until
		// after we verify the handshake signature, since the state before
		// this message was sent is used.
		msg, err = c.readHandshake(nil)
		if err != nil {
			return err
		}

		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		// See RFC 8446, Section 4.4.3.
		if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms()) {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: client certificate used with invalid signature algorithm").AtError()
		}
		sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
		if err != nil {
			return c.sendAlert(alertInternalError)
		}
		if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
			c.sendAlert(alertIllegalParameter)
			return utlserrors.New("tls: client certificate used with invalid signature algorithm").AtError()
		}
		signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
		if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
			sigHash, signed, certVerify.signature); err != nil {
			c.sendAlert(alertDecryptError)
			return utlserrors.New("tls: invalid signature by the client certificate").Base(err).AtError()
		}

		if err := transcriptMsg(certVerify, hs.transcript); err != nil {
			return err
		}
	}

	// If we waited until the client certificates to send session tickets, we
	// are ready to do it now.
	if err := hs.sendSessionTickets(); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeStateTLS13) readClientFinished() error {
	c := hs.c

	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(hs.ctx, "server: TLS 1.3 reading client Finished")
	}

	// finishedMsg is not included in the transcript.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	if !hmac.Equal(hs.clientFinished, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return utlserrors.New("tls: invalid client finished hash").AtError()
	}

	c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, hs.trafficSecret)

	return nil
}

// [uTLS] negotiateCertCompression finds the first mutually supported certificate
// compression algorithm between server config and client's compress_certificate extension.
// Returns 0 if no compression should be used.
func (hs *serverHandshakeStateTLS13) negotiateCertCompression() uint16 {
	serverAlgs := hs.c.config.ServerCertCompressionAlgorithms
	if len(serverAlgs) == 0 {
		return 0
	}
	clientAlgs := hs.clientHello.certCompressionAlgorithms
	if len(clientAlgs) == 0 {
		return 0
	}

	// Server preference order: use first server algorithm that client supports
	for _, serverAlg := range serverAlgs {
		for _, clientAlg := range clientAlgs {
			if uint16(serverAlg) == clientAlg {
				return uint16(serverAlg)
			}
		}
	}
	return 0
}

// [uTLS] compressCertificate compresses a certificate message using the specified algorithm.
// Returns a CompressedCertificate message ready to be sent, or nil if compression is not beneficial.
// RFC 8879 Section 4.2.1: If the length of the resulting compressed data is equal to
// or larger than the original, compression SHOULD NOT be applied.
func (hs *serverHandshakeStateTLS13) compressCertificate(certMsg *certificateMsgTLS13, algorithm uint16) (*utlsCompressedCertificateMsg, error) {
	// Marshal the certificate message (without the 4-byte header)
	certBytes, err := certMsg.marshal()
	if err != nil {
		return nil, err
	}
	// Skip the 4-byte header (message type + uint24 length)
	if len(certBytes) < 4 {
		return nil, utlserrors.New("tls: certificate message too short").AtError()
	}
	uncompressedPayload := certBytes[4:]

	var compressedPayload []byte

	switch CertCompressionAlgo(algorithm) {
	case CertCompressionBrotli:
		compressedPayload = compressBrotli(uncompressedPayload)
	case CertCompressionZlib:
		compressedPayload = compressZlib(uncompressedPayload)
	case CertCompressionZstd:
		compressedPayload = compressZstd(uncompressedPayload)
	default:
		return nil, utlserrors.New("tls: unsupported compression algorithm").AtError()
	}

	// RFC 8879 Section 4.2.1: If the length of the resulting compressed data
	// is equal to or larger than the original, compression SHOULD NOT be applied.
	// Return nil to signal that the caller should send uncompressed certificate.
	if len(compressedPayload) >= len(uncompressedPayload) {
		return nil, nil
	}

	return &utlsCompressedCertificateMsg{
		algorithm:                    algorithm,
		uncompressedLength:           uint32(len(uncompressedPayload)),
		compressedCertificateMessage: compressedPayload,
	}, nil
}

// [uTLS] compressBrotli compresses data using Brotli algorithm.
func compressBrotli(data []byte) []byte {
	var buf bytes.Buffer
	writer := brotli.NewWriterLevel(&buf, brotli.BestCompression)
	writer.Write(data)
	writer.Close()
	return buf.Bytes()
}

// [uTLS] compressZlib compresses data using zlib/DEFLATE algorithm.
func compressZlib(data []byte) []byte {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	writer.Write(data)
	writer.Close()
	return buf.Bytes()
}

// [uTLS] compressZstd compresses data using Zstandard algorithm.
func compressZstd(data []byte) []byte {
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	if err != nil {
		return nil
	}
	return encoder.EncodeAll(data, nil)
}
