// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"slices"
	"time"

	"github.com/refraction-networking/utls/internal/hkdf"
	"github.com/refraction-networking/utls/internal/tls13"
)

type clientHandshakeStateTLS13 struct {
	c            *Conn
	ctx          context.Context
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	keyShareKeys *keySharePrivateKeys

	session     *SessionState
	earlySecret *tls13.EarlySecret
	binderKey   []byte

	certReq       *certificateRequestMsgTLS13
	usingPSK      bool
	sentDummyCCS  bool
	suite         *cipherSuiteTLS13
	transcript    hash.Hash
	masterSecret  *tls13.MasterSecret
	trafficSecret []byte // client_application_traffic_secret_0

	echContext *echClientContext

	// hrrCount tracks the number of HelloRetryRequest messages received.
	// RFC 8446 Section 4.1.4: A client MUST abort the handshake with an
	// "unexpected_message" alert if it receives a second HelloRetryRequest.
	hrrCount int

	// peerDC holds the parsed and verified delegated credential from the server,
	// if one was received and accepted. When set, its public key is used for
	// CertificateVerify instead of the certificate's public key.
	// See RFC 9345 for delegated credentials specification.
	peerDC *DelegatedCredential // [uTLS]

	uconn *UConn // [uTLS]
}

// handshake requires hs.c, hs.hello, hs.serverHello, hs.keyShareKeys, and,
// optionally, hs.session, hs.earlySecret and hs.binderKey to be set.
func (hs *clientHandshakeStateTLS13) handshake() error {
	c := hs.c

	// The server must not select TLS 1.3 in a renegotiation. See RFC 8446,
	// sections 4.1.2 and 4.1.3.
	if c.handshakes > 0 {
		c.sendAlert(alertProtocolVersion)
		return errors.New("tls: server selected TLS 1.3 in a renegotiation")
	}

	// Consistency check on the presence of a keyShare and its parameters.
	if hs.keyShareKeys == nil || hs.keyShareKeys.ecdhe == nil || len(hs.hello.keyShares) == 0 {
		return c.sendAlert(alertInternalError)
	}

	// [uTLS SECTION START]
	// Initialize handshake timing controller for fingerprint resistance.
	// Timing jitter simulates real browser behavior during handshakes.
	var timingCtrl *handshakeTimingController
	if hs.uconn != nil {
		timingCtrl = hs.uconn.getHandshakeTimingController()
	}
	// [uTLS SECTION END]

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	hs.transcript = hs.suite.hash.New()

	if err := transcriptMsg(hs.hello, hs.transcript); err != nil {
		return err
	}

	if hs.echContext != nil {
		hs.echContext.innerTranscript = hs.suite.hash.New()
		// [uTLS SECTION BEGIN]
		if hs.uconn != nil && hs.uconn.clientHelloBuildStatus == BuildByUtls {
			if err := hs.uconn.echTranscriptMsg(hs.hello, hs.echContext); err != nil {
				return err
			}
		} else {
			if err := transcriptMsg(hs.echContext.innerHello, hs.echContext.innerTranscript); err != nil {
				return err
			}
		}
		// [uTLS SECTION END]
	}

	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		if err := hs.sendDummyChangeCipherSpec(); err != nil {
			return err
		}
		if err := hs.processHelloRetryRequest(); err != nil {
			return err
		}
	}

	if hs.echContext != nil {
		if len(hs.serverHello.original) < 38 {
			return errors.New("tls: serverHello too short for ECH confirmation")
		}
		confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
		confTranscript.Write(hs.serverHello.original[:30])
		confTranscript.Write(make([]byte, 8))
		confTranscript.Write(hs.serverHello.original[38:])
		echSecret, err := hkdf.Extract(hs.suite.hash.New, hs.echContext.innerHello.random, nil)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		acceptConfirmation, err := tls13.ExpandLabel(hs.suite.hash.New,
			echSecret,
			"ech accept confirmation",
			confTranscript.Sum(nil),
			8,
		)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.random[len(hs.serverHello.random)-8:]) == 1 {
			hs.hello = hs.echContext.innerHello
			c.serverName = c.config.ServerName
			hs.transcript = hs.echContext.innerTranscript
			c.echAccepted = true

			if hs.serverHello.encryptedClientHello != nil {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: unexpected encrypted client hello extension in server hello despite ECH being accepted")
			}

			if hs.hello.serverName == "" && hs.serverHello.serverNameAck {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: unexpected server_name extension in server hello")
			}
		} else {
			hs.echContext.echRejected = true
		}
	}

	if err := transcriptMsg(hs.serverHello, hs.transcript); err != nil {
		return err
	}

	c.buffering = true
	if err := hs.processServerHello(); err != nil {
		return err
	}
	// [uTLS SECTION START]
	// Apply ServerHello timing delay to simulate parsing and processing time.
	// Real browsers take measurable time to parse extensions and validate parameters.
	if timingCtrl != nil {
		timingCtrl.ApplyServerHelloDelay()
	}
	// [uTLS SECTION END]
	if err := hs.sendDummyChangeCipherSpec(); err != nil {
		return err
	}
	if err := hs.establishHandshakeKeys(); err != nil {
		return err
	}
	if err := hs.readServerParameters(); err != nil {
		return err
	}
	if err := hs.readServerCertificate(); err != nil {
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
	if err := hs.readServerFinished(); err != nil {
		return err
	}
	// [UTLS SECTION START]
	if err := hs.serverFinishedReceived(); err != nil {
		return err
	}
	// [UTLS SECTION END]
	if err := hs.sendClientCertificate(); err != nil {
		return err
	}
	// [uTLS SECTION START]
	// Apply Finished timing delay to simulate key derivation computation.
	// Real browsers take time for final key schedule operations.
	if timingCtrl != nil {
		timingCtrl.ApplyFinishedDelay()
	}
	// [uTLS SECTION END]
	if err := hs.sendClientFinished(); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		c.sendAlert(alertECHRequired)
		return &ECHRejectionError{hs.echContext.retryConfigs}
	}

	c.isHandshakeComplete.Store(true)

	return nil
}

// checkServerHelloOrHRR does validity checks that apply to both ServerHello and
// HelloRetryRequest messages. It sets hs.suite.
func (hs *clientHandshakeStateTLS13) checkServerHelloOrHRR() error {
	c := hs.c

	if hs.serverHello.supportedVersion == 0 {
		c.sendAlert(alertMissingExtension)
		return errors.New("tls: server selected TLS 1.3 using the legacy version field")
	}

	if hs.serverHello.supportedVersion != VersionTLS13 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid version after a HelloRetryRequest")
	}

	if hs.serverHello.vers != VersionTLS12 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an incorrect legacy version")
	}

	if hs.serverHello.ocspStapling ||
		hs.serverHello.ticketSupported ||
		hs.serverHello.extendedMasterSecret ||
		hs.serverHello.secureRenegotiationSupported ||
		len(hs.serverHello.secureRenegotiation) != 0 ||
		len(hs.serverHello.alpnProtocol) != 0 ||
		len(hs.serverHello.scts) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a ServerHello extension forbidden in TLS 1.3")
	}

	if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not echo the legacy session ID")
	}

	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported compression format")
	}

	selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
	if hs.suite != nil && selectedSuite != hs.suite {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server changed cipher suite after a HelloRetryRequest")
	}
	if selectedSuite == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}
	hs.suite = selectedSuite
	c.cipherSuite = hs.suite.id

	return nil
}

// sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
// with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
// The timing of CCS relative to other handshake messages is a fingerprinting vector.
// When timing is enabled via HandshakeTimingConfig.CCSDelay, jitter is applied
// before and after sending CCS to simulate real browser behavior.
func (hs *clientHandshakeStateTLS13) sendDummyChangeCipherSpec() error {
	if hs.c.quic != nil {
		return nil
	}
	if hs.sentDummyCCS {
		return nil
	}
	hs.sentDummyCCS = true

	// [uTLS SECTION START]
	// Apply CCS timing jitter for fingerprint resistance.
	// Real browsers have variable timing around CCS:
	//   - Chrome: sends CCS quickly after ClientHello
	//   - Firefox: more variable timing
	var timingCtrl *handshakeTimingController
	if hs.uconn != nil {
		timingCtrl = hs.uconn.getHandshakeTimingController()
	}

	// Apply pre-CCS delay
	if timingCtrl != nil {
		timingCtrl.ApplyCCSPreDelay()
	}
	// [uTLS SECTION END]

	if err := hs.c.writeChangeCipherRecord(); err != nil {
		return err
	}

	// [uTLS SECTION START]
	// Apply post-CCS delay
	if timingCtrl != nil {
		timingCtrl.ApplyCCSPostDelay()
	}
	// [uTLS SECTION END]

	return nil
}

// findECHExtPositionInServerHello finds the byte offset of the ECH extension data
// within a ServerHello message. Returns the position relative to the start of
// the message (including header), or -1 if not found.
func findECHExtPositionInServerHello(msg []byte, echDataLen int) int {
	if len(msg) < 4+2+32+1 { // header + version + random + min session id len
		return -1
	}

	pos := 4  // skip header (type + length)
	pos += 2  // skip version
	pos += 32 // skip random

	// Session ID
	if pos >= len(msg) {
		return -1
	}
	sessionIDLen := int(msg[pos])
	// Bounds check: ensure session ID fits within message
	if pos+1+sessionIDLen > len(msg) {
		return -1
	}
	pos += 1 + sessionIDLen

	// Cipher suite (2 bytes) + compression method (1 byte)
	// Bounds check: ensure we have enough bytes for cipher suite and compression
	if pos+3 > len(msg) {
		return -1
	}
	pos += 3

	if pos+2 > len(msg) {
		return -1
	}

	// Extensions length
	extLen := int(msg[pos])<<8 | int(msg[pos+1])
	pos += 2

	// Parse extensions
	extEnd := pos + extLen
	if extEnd > len(msg) {
		return -1
	}

	for pos+4 <= extEnd {
		extType := uint16(msg[pos])<<8 | uint16(msg[pos+1])
		extDataLen := int(msg[pos+2])<<8 | int(msg[pos+3])
		pos += 4 // skip type and length

		// Bounds check: ensure extension data fits within extension block
		if pos+extDataLen > extEnd {
			return -1
		}

		if extType == extensionEncryptedClientHello {
			if extDataLen == echDataLen {
				return pos // position of the extension data
			}
			return -1 // length mismatch
		}

		pos += extDataLen
	}

	return -1
}

// processHelloRetryRequest handles the HRR in hs.serverHello, modifies and
// resends hs.hello, and reads the new ServerHello into hs.serverHello.
func (hs *clientHandshakeStateTLS13) processHelloRetryRequest() error {
	c := hs.c

	// RFC 8446 Section 4.1.4: Track HRR count and abort if we receive more than one.
	// This check provides defense-in-depth: even if code structure changes in the future
	// and this function is somehow called multiple times, we will detect and abort.
	hs.hrrCount++
	if hs.hrrCount > 1 {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: received multiple HelloRetryRequest messages")
	}

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. (The idea is that the server might offload transcript
	// storage to the client in the cookie.) See RFC 8446, Section 4.4.1.
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)
	if err := transcriptMsg(hs.serverHello, hs.transcript); err != nil {
		return err
	}

	var isInnerHello bool
	hello := hs.hello
	if hs.echContext != nil {
		chHash = hs.echContext.innerTranscript.Sum(nil)
		hs.echContext.innerTranscript.Reset()
		hs.echContext.innerTranscript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
		hs.echContext.innerTranscript.Write(chHash)

		if hs.serverHello.encryptedClientHello != nil {
			if len(hs.serverHello.encryptedClientHello) != 8 {
				hs.c.sendAlert(alertDecodeError)
				return errors.New("tls: malformed extension in server hello")
			}

			confTranscript := cloneHash(hs.echContext.innerTranscript, hs.suite.hash)
			hrrHello := make([]byte, len(hs.serverHello.original))
			copy(hrrHello, hs.serverHello.original)

			// Use position-based zeroing instead of bytes.Replace
			echPos := findECHExtPositionInServerHello(hrrHello, 8)
			if echPos >= 0 && echPos+8 <= len(hrrHello) {
				copy(hrrHello[echPos:], make([]byte, 8))
			} else {
				// Fallback to bytes.Replace if position-based fails
				hrrHello = bytes.Replace(hrrHello, hs.serverHello.encryptedClientHello, make([]byte, 8), 1)
			}
			confTranscript.Write(hrrHello)
			hrrEchSecret, err := hkdf.Extract(hs.suite.hash.New, hs.echContext.innerHello.random, nil)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			acceptConfirmation, err := tls13.ExpandLabel(hs.suite.hash.New,
				hrrEchSecret,
				"hrr ech accept confirmation",
				confTranscript.Sum(nil),
				8,
			)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			if subtle.ConstantTimeCompare(acceptConfirmation, hs.serverHello.encryptedClientHello) == 1 {
				hello = hs.echContext.innerHello
				c.serverName = c.config.ServerName
				isInnerHello = true
				c.echAccepted = true
			}
		}

		if err := transcriptMsg(hs.serverHello, hs.echContext.innerTranscript); err != nil {
			return err
		}
	} else if hs.serverHello.encryptedClientHello != nil {
		// Unsolicited extension should be rejected
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: unexpected extension in server hello")
	}

	// The only HelloRetryRequest extensions we support are key_share and
	// cookie, and clients must abort the handshake if the HRR would not result
	// in any change in the ClientHello.
	if hs.serverHello.selectedGroup == 0 && hs.serverHello.cookie == nil {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server sent an unnecessary HelloRetryRequest message")
	}

	if hs.serverHello.cookie != nil {
		hello.cookie = hs.serverHello.cookie
	}

	if hs.serverHello.serverShare.group != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received malformed key_share extension")
	}

	// If the server sent a key_share extension selecting a group, ensure it's
	// a group we advertised but did not send a key share for, and send a key
	// share for it this time.
	if curveID := hs.serverHello.selectedGroup; curveID != 0 {
		if !slices.Contains(hello.supportedCurves, curveID) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server selected unsupported group")
		}
		if slices.ContainsFunc(hs.hello.keyShares, func(ks keyShare) bool {
			return ks.group == curveID
		}) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server sent an unnecessary HelloRetryRequest key_share")
		}
		// [uTLS] Handle ML-KEM/post-quantum hybrid key exchange in HRR
		// This fixes the detection vector where server selects X25519MLKEM768/X25519Kyber768Draft00
		// via HelloRetryRequest and we couldn't generate the key share.
		if curveID == X25519MLKEM768 || curveID == X25519Kyber768Draft00 {
			// Generate X25519 ephemeral key for the hybrid
			ecdheKey, err := generateECDHEKey(c.config.rand(), X25519)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			// Generate ML-KEM-768 decapsulation key
			seed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(c.config.rand(), seed); err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			mlkemKey, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			// Set up key share keys for decapsulation later
			hs.keyShareKeys = &keySharePrivateKeys{
				curveID:    curveID,
				ecdhe:      ecdheKey,
				mlkem:      mlkemKey,
				mlkemEcdhe: ecdheKey, // Same key used for hybrid
			}
			// Create key share data: format depends on the specific hybrid
			var keyShareData []byte
			if curveID == X25519Kyber768Draft00 {
				// Draft format: X25519 (32 bytes) || ML-KEM encapsulation key (1184 bytes)
				keyShareData = append(ecdheKey.PublicKey().Bytes(), mlkemKey.EncapsulationKey().Bytes()...)
			} else {
				// Final X25519MLKEM768 format: ML-KEM encapsulation key (1184 bytes) || X25519 (32 bytes)
				keyShareData = append(mlkemKey.EncapsulationKey().Bytes(), ecdheKey.PublicKey().Bytes()...)
			}
			hello.keyShares = []keyShare{{group: curveID, data: keyShareData}}
		} else if IsFFDHEGroup(curveID) {
			// [uTLS] Handle FFDHE (Finite Field Diffie-Hellman Ephemeral) key exchange in HRR
			// RFC 7919 defines standardized FFDHE groups for TLS.
			ffdheKey, err := generateFFDHEKey(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			hs.keyShareKeys = &keySharePrivateKeys{curveID: curveID, ffdhe: ffdheKey}
			hello.keyShares = []keyShare{{group: curveID, data: ffdheKey.PublicKeyBytes()}}
		} else if _, ok := curveForCurveID(curveID); !ok {
			// RFC 8446 Section 6.2: illegal_parameter - The server requested
			// a curve that is not supported by this implementation.
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: CurvePreferences includes unsupported curve")
		} else {
			// Standard ECDHE key generation for non-hybrid curves
			key, err := generateECDHEKey(c.config.rand(), curveID)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			hs.keyShareKeys = &keySharePrivateKeys{curveID: curveID, ecdhe: key}
			hello.keyShares = []keyShare{{group: curveID, data: key.PublicKey().Bytes()}}
		}
	}

	if len(hello.pskIdentities) > 0 {
		pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
		if pskSuite == nil {
			return c.sendAlert(alertInternalError)
		}
		if pskSuite.hash == hs.suite.hash {
			// Update binders and obfuscated_ticket_age.
			// [uTLS] Use jittered ticket age computation to resist DPI correlation.
			ticketAge := c.config.time().Sub(time.Unix(int64(hs.session.createdAt), 0))
			hello.pskIdentities[0].obfuscatedTicketAge = computeTicketAgeWithJitter(ticketAge, hs.session.ageAdd, c.config)

			transcript := hs.suite.hash.New()
			transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
			transcript.Write(chHash)
			if err := transcriptMsg(hs.serverHello, transcript); err != nil {
				return err
			}

			// [uTLS] Use constant-time binder computation when configured to prevent timing side-channel attacks.
			// This is controlled by Config.PSKBinderConstantTime (defaults to true for security).
			finishedHashFunc := hs.suite.finishedHash
			if c.config.PSKBinderConstantTime {
				finishedHashFunc = hs.suite.finishedHashConstantTime
			}
			if err := computeAndUpdatePSK(hello, hs.binderKey, transcript, finishedHashFunc); err != nil {
				return err
			}
		} else {
			// Server selected a cipher suite incompatible with the PSK.
			hello.pskIdentities = nil
			hello.pskBinders = nil
		}
	}

	// [uTLS SECTION BEGINS]
	// crypto/tls code above this point had changed crypto/tls structures in accordance with HRR, and is about
	// to call default marshaller.
	// Instead, we fill uTLS-specific structs and call uTLS marshaller.
	// Only extensionCookie, extensionPreSharedKey, extensionKeyShare, extensionEarlyData, extensionSupportedVersions,
	// and utlsExtensionPadding are supposed to change
	if hs.uconn != nil {
		if hs.uconn.ClientHelloID != HelloGolang {
			// Sync PSK binders that were pre-computed with HRR transcript by the standard library code
			// RFC 8446 Section 4.2.11: PSK binders must be recalculated after HRR with the
			// transcript: MessageHash(CH1) + HRR. This was done above (lines 421-446).
			if len(hello.pskIdentities) > 0 {
				// The standard library code has already recalculated the PSK binders
				// with the proper transcript. Sync these pre-computed values to uTLS structures.
				pubIdentities := pskIdentities(hello.pskIdentities).ToPublic()

				// Update the public HandshakeState
				hs.uconn.HandshakeState.Hello.PskIdentities = pubIdentities
				hs.uconn.HandshakeState.Hello.PskBinders = hello.pskBinders

				// Find and update the PSK extension with the pre-computed binders
				// This sets hrrBindersPrecomputed=true to prevent PatchBuiltHello from
				// recalculating binders with an incorrect transcript.
				for _, ext := range hs.uconn.Extensions {
					if pskExt, ok := ext.(PreSharedKeyExtension); ok {
						pskExt.SetHRRPSKBinderState(pubIdentities, hello.pskBinders)
						break
					}
				}
			}

			keyShareExtFound := false
			for _, ext := range hs.uconn.Extensions {
				// new ks seems to be generated either way
				if ks, ok := ext.(*KeyShareExtension); ok {
					ks.KeyShares = keyShares(hs.hello.keyShares).ToPublic()
					keyShareExtFound = true
				}
			}
			if !keyShareExtFound {
				return errors.New("tls: received HelloRetryRequest but key share extension not found")
			}

			if len(hs.serverHello.cookie) > 0 {
				// serverHello specified a cookie, let's echo it
				cookieFound := false
				for _, ext := range hs.uconn.Extensions {
					if ks, ok := ext.(*CookieExtension); ok {
						ks.Cookie = hs.serverHello.cookie
						cookieFound = true
					}
				}

				if !cookieFound {
					// FINGERPRINT CONSIDERATION: Adding cookie extension changes CH2 structure.
					// Per RFC 8446 Section 4.1.2, adding a cookie extension is allowed after HRR.
					//
					// All standard browser profiles (Chrome, Firefox, Safari, Edge, iOS) now
					// include a CookieExtension{} placeholder at the browser-appropriate position:
					//   - Chrome/Edge: after PSKKeyExchangeModesExtension
					//   - Firefox: after SupportedVersionsExtension
					//   - Safari/iOS: after PSKKeyExchangeModesExtension
					//
					// The placeholder has Len()=0 when Cookie is empty, so it doesn't affect
					// the initial ClientHello. When HRR is received, the Cookie field is set
					// and the extension serializes normally, preserving extension order.
					//
					// This fallback insertion is for custom profiles that don't include the
					// placeholder. We insert after key_share to maintain some consistency,
					// but this is detectable by sophisticated fingerprinting.
					//
					// WARNING: If you're using a custom profile, add CookieExtension{}
					// at the browser-appropriate position for best fingerprint consistency.
					cookieExt := &CookieExtension{Cookie: hs.serverHello.cookie}

					// Find key_share extension index to insert cookie right after it
					insertIdx := -1
					for i, ext := range hs.uconn.Extensions {
						if _, ok := ext.(*KeyShareExtension); ok {
							insertIdx = i + 1
							break
						}
					}

					if insertIdx < 0 || insertIdx >= len(hs.uconn.Extensions) {
						// key_share not found or at end, insert at position 1 (after GREASE/SNI)
						// but before PSK which must be last
						if len(hs.uconn.Extensions) <= 1 {
							insertIdx = 0
						} else {
							insertIdx = 1
						}
					}

					// Ensure we don't insert at or after PSK (must be last)
					// Check if last extension is PSK
					if len(hs.uconn.Extensions) > 0 {
						if _, isPSK := hs.uconn.Extensions[len(hs.uconn.Extensions)-1].(PreSharedKeyExtension); isPSK {
							if insertIdx >= len(hs.uconn.Extensions)-1 {
								insertIdx = len(hs.uconn.Extensions) - 1
							}
						}
					}

					// Insert cookie extension at the determined position
					hs.uconn.Extensions = append(hs.uconn.Extensions[:insertIdx],
						append([]TLSExtension{cookieExt}, hs.uconn.Extensions[insertIdx:]...)...)
				}
			}
			if err := hs.uconn.MarshalClientHelloNoECH(); err != nil {
				return err
			}
			hs.hello.original = hs.uconn.HandshakeState.Hello.Raw
		}
	}
	// [uTLS SECTION ENDS]
	if hello.earlyData {
		hello.earlyData = false
		c.quicRejectedEarlyData()
	}

	if isInnerHello {
		// Any extensions which have changed in hello, but are mirrored in the
		// outer hello and compressed, need to be copied to the outer hello, so
		// they can be properly decompressed by the server. For now, the only
		// extension which may have changed is keyShares.
		hs.hello.keyShares = hello.keyShares
		hs.echContext.innerHello = hello
		if hs.uconn != nil && hs.uconn.clientHelloBuildStatus == BuildByUtls {
			if err := hs.uconn.computeAndUpdateOuterECHExtension(hs.echContext.innerHello, hs.echContext, false); err != nil {
				return err
			}

			hs.hello.original = hs.uconn.HandshakeState.Hello.Raw

			if err := hs.uconn.echTranscriptMsg(hs.hello, hs.echContext); err != nil {
				return err
			}

		} else {
			if err := transcriptMsg(hs.echContext.innerHello, hs.echContext.innerTranscript); err != nil {
				return err
			}

			if err := computeAndUpdateOuterECHExtension(hs.hello, hs.echContext.innerHello, hs.echContext, false); err != nil {
				return err
			}
		}
	} else {
		hs.hello = hello
	}

	if _, err := hs.c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil {
		return err
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
	hs.serverHello = serverHello

	// RFC 8446 Section 4.1.4: A client MUST abort the handshake with an
	// "unexpected_message" alert if it receives a HelloRetryRequest after
	// an initial HelloRetryRequest. Detect this immediately before proceeding.
	// Also increment hrrCount so state tracking remains consistent.
	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		hs.hrrCount++ // Track the second HRR for consistent state
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: server sent two HelloRetryRequest messages")
	}

	// [uTLS] Capture raw ServerHello for JA4S calculation
	if hs.uconn != nil && serverHello.original != nil {
		hs.uconn.stateMu.Lock()
		hs.uconn.rawServerHello = make([]byte, len(serverHello.original))
		copy(hs.uconn.rawServerHello, serverHello.original)
		hs.uconn.stateMu.Unlock()
	}

	if err := hs.checkServerHelloOrHRR(); err != nil {
		return err
	}

	c.didHRR = true
	return nil
}

func (hs *clientHandshakeStateTLS13) processServerHello() error {
	c := hs.c

	// RFC 8446 Section 4.1.4: Defense-in-depth check for HRR.
	// If we reach here with an HRR (either first or repeated), it indicates
	// a protocol error. The primary checks are in processHelloRetryRequest().
	if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
		hs.hrrCount++ // Track for consistent state even in error path
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: server sent two HelloRetryRequest messages")
	}

	if len(hs.serverHello.cookie) != 0 {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent a cookie in a normal ServerHello")
	}

	if hs.serverHello.selectedGroup != 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: malformed key_share extension")
	}

	if hs.serverHello.serverShare.group == 0 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server did not send a key share")
	}
	if !slices.ContainsFunc(hs.hello.keyShares, func(ks keyShare) bool {
		return ks.group == hs.serverHello.serverShare.group
	}) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected unsupported group")
	}

	if !hs.serverHello.selectedIdentityPresent {
		return nil
	}

	if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK")
	}

	if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
		return c.sendAlert(alertInternalError)
	}
	pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
	if pskSuite == nil {
		return c.sendAlert(alertInternalError)
	}
	if pskSuite.hash != hs.suite.hash {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: server selected an invalid PSK and cipher suite pair")
	}

	hs.usingPSK = true
	c.didResume = true
	c.peerCertificates = hs.session.peerCertificates
	c.activeCertHandles = hs.session.activeCertHandles
	c.verifiedChains = hs.session.verifiedChains
	c.ocspResponse = hs.session.ocspResponse
	c.scts = hs.session.scts
	return nil
}

// [uTLS] SECTION BEGIN
func getSharedKey(peerData []byte, key *ecdh.PrivateKey) ([]byte, error) {
	peerKey, err := key.Curve().NewPublicKey(peerData)
	if err != nil {
		return nil, errors.New("tls: invalid server key share")
	}
	sharedKey, err := key.ECDH(peerKey)
	if err != nil {
		return nil, errors.New("tls: invalid server key share")
	}

	return sharedKey, nil
}

// [uTLS] SECTION END

func (hs *clientHandshakeStateTLS13) establishHandshakeKeys() error {
	c := hs.c

	serverGroup := hs.serverHello.serverShare.group
	ecdhePeerData := hs.serverHello.serverShare.data

	// [uTLS] Handle FFDHE key exchange (RFC 7919)
	var sharedKey []byte
	var err error
	if IsFFDHEGroup(serverGroup) {
		if hs.keyShareKeys.ffdhe == nil {
			c.sendAlert(alertInternalError)
			return errors.New("tls: FFDHE key share selected but no FFDHE key available")
		}
		// Validate server key share length matches expected FFDHE group size
		expectedSize := expectedKeyShareSize(serverGroup)
		if len(ecdhePeerData) != expectedSize {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server FFDHE key share size")
		}
		// Compute shared secret using FFDHE
		sharedKey, err = hs.keyShareKeys.ffdhe.SharedSecret(ecdhePeerData)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server FFDHE key share")
		}
	} else {
		// Handle ECDHE and hybrid key exchanges
		if serverGroup == X25519MLKEM768 {
			if len(ecdhePeerData) != mlkem.CiphertextSize768+x25519PublicKeySize {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: invalid server X25519MLKEM768 key share")
			}
			ecdhePeerData = hs.serverHello.serverShare.data[mlkem.CiphertextSize768:]
		}
		// [uTLS] SECTION BEGIN
		if serverGroup == X25519Kyber768Draft00 {
			if len(ecdhePeerData) != x25519PublicKeySize+mlkem.CiphertextSize768 {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: invalid server X25519Kyber768Draft00 key share")
			}
			ecdhePeerData = hs.serverHello.serverShare.data[:x25519PublicKeySize]
		}
		sharedKey, err = getSharedKey(ecdhePeerData, hs.keyShareKeys.ecdhe)
		// [uTLS] SECTION END
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid server key share")
		}
	}
	if serverGroup == X25519MLKEM768 {
		if hs.keyShareKeys.mlkem == nil {
			return c.sendAlert(alertInternalError)
		}
		// [uTLS] SECTION BEGIN
		if hs.uconn != nil && hs.uconn.clientHelloBuildStatus == BuildByUtls {
			if sharedKey, err = getSharedKey(ecdhePeerData, hs.keyShareKeys.mlkemEcdhe); err != nil {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: invalid server key share")
			}
		}
		// [uTLS] SECTION END
		ciphertext := hs.serverHello.serverShare.data[:mlkem.CiphertextSize768]
		mlkemShared, err := hs.keyShareKeys.mlkem.Decapsulate(ciphertext)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid X25519MLKEM768 server key share")
		}
		sharedKey = append(mlkemShared, sharedKey...)
	}
	// [uTLS] SECTION BEGIN
	if serverGroup == X25519Kyber768Draft00 {
		if hs.keyShareKeys.mlkem == nil {
			return c.sendAlert(alertInternalError)
		}
		if hs.uconn != nil && hs.uconn.clientHelloBuildStatus == BuildByUtls {
			if sharedKey, err = getSharedKey(ecdhePeerData, hs.keyShareKeys.mlkemEcdhe); err != nil {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: invalid server key share")
			}
		}
		ciphertext := hs.serverHello.serverShare.data[x25519PublicKeySize:]
		kyberShared, err := kyberDecapsulate(hs.keyShareKeys.mlkem, ciphertext)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: invalid X25519Kyber768Draft00 server key share")
		}
		sharedKey = append(sharedKey, kyberShared...)
	}
	// [uTLS] SECTION END
	c.curveID = serverGroup

	earlySecret := hs.earlySecret
	if !hs.usingPSK {
		var err error
		earlySecret, err = tls13.NewEarlySecret(hs.suite.hash.New, nil)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	handshakeSecret, err := earlySecret.HandshakeSecret(sharedKey)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	// Zero the shared key immediately after deriving the handshake secret
	// to minimize the window where it could be extracted from memory.
	zeroSlice(sharedKey)

	clientSecret, err := handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if err := c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	serverSecret, err := handshakeSecret.ServerHandshakeTrafficSecret(hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if err := c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: unexpected data after ServerHello in QUIC")
		}
		c.quicSetWriteSecret(QUICEncryptionLevelHandshake, hs.suite.id, clientSecret)
		c.quicSetReadSecret(QUICEncryptionLevelHandshake, hs.suite.id, serverSecret)
	}

	err = c.config.writeKeyLog(keyLogLabelClientHandshake, hs.hello.random, clientSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	hs.masterSecret, err = handshakeSecret.MasterSecret()
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerParameters() error {
	c := hs.c

	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}

	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(encryptedExtensions, msg)
	}

	if err := checkALPN(hs.hello.alpnProtocols, encryptedExtensions.alpnProtocol, c.quic != nil); err != nil {
		// RFC 8446 specifies that no_application_protocol is sent by servers, but
		// does not specify how clients handle the selection of an incompatible protocol.
		// RFC 9001 Section 8.1 specifies that QUIC clients send no_application_protocol
		// in this case. Always sending no_application_protocol seems reasonable.
		c.sendAlert(alertNoApplicationProtocol)
		return err
	}
	c.clientProtocol = encryptedExtensions.alpnProtocol

	// [UTLS SECTION STARTS]
	if hs.uconn != nil {
		err = hs.utlsReadServerParameters(encryptedExtensions)
		if err != nil {
			c.sendAlert(alertUnsupportedExtension)
			return err
		}
	}
	// [UTLS SECTION ENDS]

	if c.quic != nil {
		if encryptedExtensions.quicTransportParameters == nil {
			// RFC 9001 Section 8.2.
			c.sendAlert(alertMissingExtension)
			return errors.New("tls: server did not send a quic_transport_parameters extension")
		}
		c.quicSetTransportParameters(encryptedExtensions.quicTransportParameters)
	} else {
		if encryptedExtensions.quicTransportParameters != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent an unexpected quic_transport_parameters extension")
		}
	}

	if !hs.hello.earlyData && encryptedExtensions.earlyData {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tls: server sent an unexpected early_data extension")
	}
	if hs.hello.earlyData && !encryptedExtensions.earlyData {
		c.quicRejectedEarlyData()
	}
	if encryptedExtensions.earlyData {
		if hs.session.cipherSuite != c.cipherSuite {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: server accepted 0-RTT with the wrong cipher suite")
		}
		if hs.session.alpnProtocol != c.clientProtocol {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tls: server accepted 0-RTT with the wrong ALPN")
		}
	}
	if hs.echContext != nil {
		if hs.echContext.echRejected {
			// Filter retry configs to only include those with supported algorithms.
			// This prevents wasted retry attempts with configs we cannot use.
			// filterUsableECHConfigs returns nil if no usable configs exist.
			hs.echContext.retryConfigs = filterUsableECHConfigs(encryptedExtensions.echRetryConfigs)
		} else if encryptedExtensions.echRetryConfigs != nil {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tls: server sent encrypted client hello retry configs after accepting encrypted client hello")
		}
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerCertificate() error {
	c := hs.c

	// Either a PSK or a certificate is always used, but not both.
	// See RFC 8446, Section 4.1.1.
	if hs.usingPSK {
		// Verify that cached certificates have not expired since session was established.
		// This prevents accepting expired/invalid certificates on session resumption.
		// Skip this check if InsecureSkipVerify is set, consistent with initial handshake behavior.
		// See Issue 31641 for context on why full re-verification is not performed.
		if !c.config.InsecureSkipVerify && len(hs.session.peerCertificates) > 0 {
			cert := hs.session.peerCertificates[0]
			now := c.config.time()
			if now.After(cert.NotAfter) {
				c.sendAlert(alertCertificateExpired)
				return errors.New("tls: server certificate has expired since session was established")
			}
			if now.Before(cert.NotBefore) {
				c.sendAlert(alertCertificateExpired)
				return errors.New("tls: server certificate is not yet valid")
			}
		}
		// Make sure the connection is still being verified whether or not this
		// is a resumption. Resumptions currently don't reverify certificates so
		// they don't call verifyServerCertificate. See Issue 31641.
		if c.config.VerifyConnection != nil {
			if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}
		return nil
	}

	// [UTLS SECTION BEGINS]
	// msg, err := c.readHandshake(hs.transcript)
	msg, err := c.readHandshake(nil) // hold writing to transcript until we know it is not compressed cert
	// [UTLS SECTION ENDS]
	if err != nil {
		return err
	}

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		hs.certReq = certReq
		transcriptMsg(certReq, hs.transcript) // [UTLS] if it is certReq (not compressedCert), write to transcript

		// msg, err = c.readHandshake(hs.transcript)
		msg, err = c.readHandshake(nil) // [UTLS] we don't write to transcript until make sure it is not compressed cert
		if err != nil {
			return err
		}
	}

	// [UTLS SECTION BEGINS]
	var skipWritingCertToTranscript bool = false
	if hs.uconn != nil {
		processedMsg, err := hs.utlsReadServerCertificate(msg)
		if err != nil {
			return err
		}
		if processedMsg != nil {
			skipWritingCertToTranscript = true
			msg = processedMsg // msg is now a processed-by-extension certificateMsg
		}
	}
	// [UTLS SECTION ENDS]

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	if len(certMsg.certificate.Certificate) == 0 {
		c.sendAlert(alertDecodeError)
		return errors.New("tls: received empty certificates message")
	}
	// [UTLS SECTION BEGINS]
	if !skipWritingCertToTranscript { // write to transcript only if it is not compressedCert (i.e. if not processed by extension)
		if err = transcriptMsg(certMsg, hs.transcript); err != nil {
			return err
		}
	}
	// [UTLS SECTION ENDS]

	c.scts = certMsg.certificate.SignedCertificateTimestamps
	c.ocspResponse = certMsg.certificate.OCSPStaple

	if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return err
	}

	// [uTLS] Process delegated credential if present and enabled.
	// This must happen after certificate verification but before CertificateVerify.
	if c.config.AcceptDelegatedCredentials && len(certMsg.delegatedCredential) > 0 {
		dc, err := parseDelegatedCredential(certMsg.delegatedCredential)
		if err != nil {
			c.sendAlert(alertDecodeError)
			return errors.New("tls: failed to parse delegated credential: " + err.Error())
		}

		// Verify the DC signature against the leaf certificate
		if err := dc.Verify(c.peerCertificates[0]); err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: delegated credential verification failed: " + err.Error())
		}

		// Check validity period
		if !dc.IsValid(c.peerCertificates[0].NotBefore, c.config.time()) {
			c.sendAlert(alertCertificateExpired)
			return errors.New("tls: delegated credential has expired or is not yet valid")
		}

		// Check TTL is within RFC 9345 limits (7 days max)
		if !dc.IsValidTTL() {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: delegated credential validity period exceeds maximum (7 days)")
		}

		// Verify the DC's public key type matches its expected signature algorithm
		if err := verifyDCCertVerifyAlgorithm(dc); err != nil {
			c.sendAlert(alertIllegalParameter)
			return err
		}

		hs.peerDC = dc
	}

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
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: certificate used with invalid signature algorithm")
	}

	// [uTLS] Determine which public key to use for CertificateVerify verification.
	// If a delegated credential was accepted, use the DC's public key.
	// Otherwise, use the certificate's public key as usual.
	var verifyKey crypto.PublicKey
	if hs.peerDC != nil {
		// RFC 9345: When using a delegated credential, the CertificateVerify
		// must be signed with the DC's public key using the algorithm
		// specified in the DC's dc_cert_verify_algorithm field.
		if certVerify.signatureAlgorithm != hs.peerDC.ExpectedCertVerifyAlgorithm {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: CertificateVerify algorithm does not match delegated credential's expected algorithm")
		}
		verifyKey = hs.peerDC.PublicKey()
	} else {
		verifyKey = c.peerCertificates[0].PublicKey
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	if err := verifyHandshakeSignature(sigType, verifyKey,
		sigHash, signed, certVerify.signature); err != nil {
		c.sendAlert(alertDecryptError)
		if hs.peerDC != nil {
			return errors.New("tls: invalid signature by the delegated credential: " + err.Error())
		}
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}

	if err := transcriptMsg(certVerify, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) readServerFinished() error {
	c := hs.c

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	finished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(finished, msg)
	}

	expectedMAC, err := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if !hmac.Equal(expectedMAC, finished.verifyData) {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: invalid server finished hash")
	}

	if err := transcriptMsg(finished, hs.transcript); err != nil {
		return err
	}

	// Derive secrets that take context through the server Finished.

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
	if err := c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientCertificate() error {
	c := hs.c

	if hs.certReq == nil {
		return nil
	}

	if hs.echContext != nil && hs.echContext.echRejected {
		if _, err := hs.c.writeHandshakeRecord(&certificateMsgTLS13{}, hs.transcript); err != nil {
			return err
		}
		return nil
	}

	cert, err := c.getClientCertificate(&CertificateRequestInfo{
		AcceptableCAs:    hs.certReq.certificateAuthorities,
		SignatureSchemes: hs.certReq.supportedSignatureAlgorithms,
		Version:          c.vers,
		ctx:              hs.ctx,
	})
	if err != nil {
		return err
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *cert
	certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0

	if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil {
		return err
	}

	// If we sent an empty certificate message, skip the CertificateVerify.
	if len(cert.Certificate) == 0 {
		return nil
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true

	certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert, hs.certReq.supportedSignatureAlgorithms)
	if err != nil {
		// getClientCertificate returned a certificate incompatible with the
		// CertificateRequestInfo supported signature algorithms.
		c.sendAlert(alertHandshakeFailure)
		return err
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		c.sendAlert(alertInternalError)
		return errors.New("tls: client certificate private key does not implement crypto.Signer")
	}
	sig, err := signer.Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to sign handshake: " + err.Error())
	}
	certVerifyMsg.signature = sig

	if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil {
		return err
	}

	return nil
}

func (hs *clientHandshakeStateTLS13) sendClientFinished() error {
	c := hs.c

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

	if err := c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, hs.trafficSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
		c.resumptionSecret, err = hs.masterSecret.ResumptionMasterSecret(hs.transcript)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}

	if c.quic != nil {
		if c.hand.Len() != 0 {
			c.sendAlert(alertUnexpectedMessage)
		}
		c.quicSetWriteSecret(QUICEncryptionLevelApplication, hs.suite.id, hs.trafficSecret)
	}

	return nil
}

func (c *Conn) handleNewSessionTicket(msg *newSessionTicketMsgTLS13) error {
	if !c.isClient {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tls: received new session ticket from a client")
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: received a session ticket with invalid lifetime")
	}

	// RFC 9001, Section 4.6.1
	if c.quic != nil && msg.maxEarlyData != 0 && msg.maxEarlyData != 0xffffffff {
		c.sendAlert(alertIllegalParameter)
		return errors.New("tls: invalid early data for QUIC connection")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		return c.sendAlert(alertInternalError)
	}

	psk, err := tls13.ExpandLabel(cipherSuite.hash.New, c.resumptionSecret, "resumption",
		msg.nonce, cipherSuite.hash.Size())
	if err != nil {
		return c.sendAlert(alertInternalError)
	}

	session := c.sessionState()
	session.secret = psk
	session.useBy = uint64(c.config.time().Add(lifetime).Unix())
	session.ageAdd = msg.ageAdd
	session.EarlyData = c.quic != nil && msg.maxEarlyData == 0xffffffff // RFC 9001, Section 4.6.1
	session.ticket = msg.label
	if c.quic != nil && c.quic.enableSessionEvents {
		c.quicStoreSession(session)
		return nil
	}
	cs := &ClientSessionState{session: session}
	if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
		c.config.ClientSessionCache.Put(cacheKey, cs)
	}

	return nil
}
