// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"io"

	utlserrors "github.com/refraction-networking/utls/errors"
	"golang.org/x/crypto/cryptobyte"
)

// Sentinel errors for session ticket decryption failures.
// These allow callers to distinguish between different failure modes.
var (
	// ErrTicketDecryptionFailed indicates the session ticket could not be decrypted.
	// This typically occurs when MAC verification fails due to:
	//   - Expired tickets encrypted with rotated-out keys
	//   - Forged or tampered tickets
	//   - Tickets from a different server or cluster
	// This error is not returned by DecryptTicket (which returns nil, nil for
	// backward compatibility) but can be used by custom UnwrapSession implementations.
	ErrTicketDecryptionFailed = utlserrors.New("tls: session ticket decryption failed").AtError()

	// ErrTicketTooShort indicates the session ticket is shorter than the minimum
	// required length (AES block size + HMAC-SHA256 size).
	ErrTicketTooShort = utlserrors.New("tls: session ticket too short").AtError()

	// ErrTicketParsingFailed indicates the session ticket was successfully decrypted
	// (MAC verification passed) but the decrypted payload could not be parsed.
	// This is a security-relevant condition: a cryptographically valid ticket with
	// corrupt contents may indicate data corruption, a bug, or a sophisticated attack.
	ErrTicketParsingFailed = utlserrors.New("tls: session ticket parsing failed after successful decryption").AtError()
)

// A SessionState is a resumable session.
type SessionState struct {
	// Encoded as a SessionState (in the language of RFC 8446, Section 3).
	//
	//   enum { server(1), client(2) } SessionStateType;
	//
	//   opaque Certificate<1..2^24-1>;
	//
	//   Certificate CertificateChain<0..2^24-1>;
	//
	//   opaque Extra<0..2^24-1>;
	//
	//   struct {
	//       uint16 version;
	//       SessionStateType type;
	//       uint16 cipher_suite;
	//       uint64 created_at;
	//       opaque secret<1..2^8-1>;
	//       Extra extra<0..2^24-1>;
	//       uint8 ext_master_secret = { 0, 1 };
	//       uint8 early_data = { 0, 1 };
	//       CertificateEntry certificate_list<0..2^24-1>;
	//       CertificateChain verified_chains<0..2^24-1>; /* excluding leaf */
	//       select (SessionState.early_data) {
	//           case 0: Empty;
	//           case 1: opaque alpn<1..2^8-1>;
	//       };
	//       select (SessionState.type) {
	//           case server: Empty;
	//           case client: struct {
	//               select (SessionState.version) {
	//                   case VersionTLS10..VersionTLS12: Empty;
	//                   case VersionTLS13: struct {
	//                       uint64 use_by;
	//                       uint32 age_add;
	//                   };
	//               };
	//           };
	//       };
	//   } SessionState;
	//

	// Extra is ignored by crypto/tls, but is encoded by [SessionState.Bytes]
	// and parsed by [ParseSessionState].
	//
	// This allows [Config.UnwrapSession]/[Config.WrapSession] and
	// [ClientSessionCache] implementations to store and retrieve additional
	// data alongside this session.
	//
	// To allow different layers in a protocol stack to share this field,
	// applications must only append to it, not replace it, and must use entries
	// that can be recognized even if out of order (for example, by starting
	// with an id and version prefix).
	Extra [][]byte

	// EarlyData indicates whether the ticket can be used for 0-RTT in a QUIC
	// connection. The application may set this to false if it is true to
	// decline to offer 0-RTT even if supported.
	EarlyData bool

	version     uint16
	isClient    bool
	cipherSuite uint16
	// createdAt is the generation time of the secret on the sever (which for
	// TLS 1.0–1.2 might be earlier than the current session) and the time at
	// which the ticket was received on the client.
	createdAt         uint64 // seconds since UNIX epoch
	secret            []byte // master secret for TLS 1.2, or the PSK for TLS 1.3
	extMasterSecret   bool
	peerCertificates  []*x509.Certificate
	activeCertHandles []*activeCert
	ocspResponse      []byte
	scts              [][]byte
	verifiedChains    [][]*x509.Certificate
	alpnProtocol      string // only set if EarlyData is true

	// Client-side TLS 1.3-only fields.
	useBy  uint64 // seconds since UNIX epoch
	ageAdd uint32
	ticket []byte

	// [uTLS] maxEarlyDataSize is the max_early_data_size from the NewSessionTicket.
	// Per RFC 8446 Section 4.6.1, this indicates the maximum amount of 0-RTT data
	// the server will accept. For QUIC (RFC 9001), this must be 0xffffffff.
	// For standard TLS, this is the byte limit for early data.
	// Zero means early data is not supported for this session.
	maxEarlyDataSize uint32
}

// Bytes encodes the session, including any private fields, so that it can be
// parsed by [ParseSessionState]. The encoding contains secret values critical
// to the security of future and possibly past sessions.
//
// The specific encoding should be considered opaque and may change incompatibly
// between Go versions.
func (s *SessionState) Bytes() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16(s.version)
	if s.isClient {
		b.AddUint8(2) // client
	} else {
		b.AddUint8(1) // server
	}
	b.AddUint16(s.cipherSuite)
	addUint64(&b, s.createdAt)
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(s.secret)
	})
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, extra := range s.Extra {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(extra)
			})
		}
	})
	if s.extMasterSecret {
		b.AddUint8(1)
	} else {
		b.AddUint8(0)
	}
	if s.EarlyData {
		b.AddUint8(1)
	} else {
		b.AddUint8(0)
	}
	marshalCertificate(&b, Certificate{
		Certificate:                 certificatesToBytesSlice(s.peerCertificates),
		OCSPStaple:                  s.ocspResponse,
		SignedCertificateTimestamps: s.scts,
	})
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, chain := range s.verifiedChains {
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				// We elide the first certificate because it's always the leaf.
				if len(chain) == 0 {
					b.SetError(utlserrors.New("tls: internal error: empty verified chain").AtError())
					return
				}
				for _, cert := range chain[1:] {
					b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddBytes(cert.Raw)
					})
				}
			})
		}
	})
	if s.EarlyData {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(s.alpnProtocol))
		})
	}
	if s.isClient {
		if s.version >= VersionTLS13 {
			addUint64(&b, s.useBy)
			b.AddUint32(s.ageAdd)
			// [uTLS] Serialize maxEarlyDataSize when EarlyData is enabled.
			// This is critical for 0-RTT session resumption - without it,
			// the client doesn't know how much early data the server accepts.
			if s.EarlyData {
				b.AddUint32(s.maxEarlyDataSize)
			}
		}
	} else {
		// Server-side TLS 1.3 session ticket: include ageAdd when EarlyData is enabled.
		// This is required for RFC 8446 Section 4.2.10 ticket age validation during 0-RTT.
		// Without ageAdd in the ticket, the server cannot verify the client's obfuscated_ticket_age.
		if s.version >= VersionTLS13 && s.EarlyData {
			b.AddUint32(s.ageAdd)
		}
	}
	return b.Bytes()
}

func certificatesToBytesSlice(certs []*x509.Certificate) [][]byte {
	s := make([][]byte, 0, len(certs))
	for _, c := range certs {
		s = append(s, c.Raw)
	}
	return s
}

// ParseSessionState parses a [SessionState] encoded by [SessionState.Bytes].
func ParseSessionState(data []byte) (*SessionState, error) {
	ss := &SessionState{}
	s := cryptobyte.String(data)
	var typ, extMasterSecret, earlyData uint8
	var cert Certificate
	var extra cryptobyte.String
	if !s.ReadUint16(&ss.version) ||
		!s.ReadUint8(&typ) ||
		(typ != 1 && typ != 2) ||
		!s.ReadUint16(&ss.cipherSuite) ||
		!readUint64(&s, &ss.createdAt) ||
		!readUint8LengthPrefixed(&s, &ss.secret) ||
		!s.ReadUint24LengthPrefixed(&extra) ||
		!s.ReadUint8(&extMasterSecret) ||
		!s.ReadUint8(&earlyData) ||
		len(ss.secret) == 0 ||
		!unmarshalCertificate(&s, &cert) {
		return nil, utlserrors.New("tls: invalid session encoding").AtError()
	}
	for !extra.Empty() {
		var e []byte
		if !readUint24LengthPrefixed(&extra, &e) {
			return nil, utlserrors.New("tls: invalid session encoding: malformed extra data").AtError()
		}
		ss.Extra = append(ss.Extra, e)
	}
	switch extMasterSecret {
	case 0:
		ss.extMasterSecret = false
	case 1:
		ss.extMasterSecret = true
	default:
		return nil, utlserrors.New("tls: invalid session encoding: invalid extMasterSecret value").AtError()
	}
	switch earlyData {
	case 0:
		ss.EarlyData = false
	case 1:
		ss.EarlyData = true
	default:
		return nil, utlserrors.New("tls: invalid session encoding: invalid earlyData value").AtError()
	}
	for _, cert := range cert.Certificate {
		c, err := globalCertCache.newCert(cert)
		if err != nil {
			return nil, err
		}
		ss.activeCertHandles = append(ss.activeCertHandles, c)
		ss.peerCertificates = append(ss.peerCertificates, c.cert)
	}
	ss.ocspResponse = cert.OCSPStaple
	ss.scts = cert.SignedCertificateTimestamps
	var chainList cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&chainList) {
		return nil, utlserrors.New("tls: invalid session encoding: missing chain list").AtError()
	}
	for !chainList.Empty() {
		var certList cryptobyte.String
		if !chainList.ReadUint24LengthPrefixed(&certList) {
			return nil, utlserrors.New("tls: invalid session encoding: malformed certificate chain").AtError()
		}
		var chain []*x509.Certificate
		if len(ss.peerCertificates) == 0 {
			return nil, utlserrors.New("tls: invalid session encoding: empty peer certificates").AtError()
		}
		chain = append(chain, ss.peerCertificates[0])
		for !certList.Empty() {
			var cert []byte
			if !readUint24LengthPrefixed(&certList, &cert) {
				return nil, utlserrors.New("tls: invalid session encoding: malformed certificate").AtError()
			}
			c, err := globalCertCache.newCert(cert)
			if err != nil {
				return nil, err
			}
			ss.activeCertHandles = append(ss.activeCertHandles, c)
			chain = append(chain, c.cert)
		}
		ss.verifiedChains = append(ss.verifiedChains, chain)
	}
	if ss.EarlyData {
		var alpn []byte
		if !readUint8LengthPrefixed(&s, &alpn) {
			return nil, utlserrors.New("tls: invalid session encoding: missing ALPN for early data").AtError()
		}
		ss.alpnProtocol = string(alpn)
	}
	if isClient := typ == 2; !isClient {
		// Server-side TLS 1.3 session ticket: read ageAdd when EarlyData is enabled.
		// This is required for RFC 8446 Section 4.2.10 ticket age validation during 0-RTT.
		if ss.version >= VersionTLS13 && ss.EarlyData {
			if !s.ReadUint32(&ss.ageAdd) {
				return nil, utlserrors.New("tls: invalid session encoding: missing ageAdd for server-side 0-RTT").AtError()
			}
		}
		if !s.Empty() {
			return nil, utlserrors.New("tls: invalid session encoding: trailing data in server session").AtError()
		}
		utlserrors.LogDebug(context.Background(), "session: parsed server-side session state, version=", ss.version, ", earlyData=", ss.EarlyData)
		return ss, nil
	}
	ss.isClient = true
	if len(ss.peerCertificates) == 0 {
		return nil, utlserrors.New("tls: no server certificates in client session").AtError()
	}
	if ss.version < VersionTLS13 {
		if !s.Empty() {
			return nil, utlserrors.New("tls: invalid session encoding: trailing data in TLS 1.2 client session").AtError()
		}
		utlserrors.LogDebug(context.Background(), "session: parsed TLS 1.2 client session state")
		return ss, nil
	}
	if !s.ReadUint64(&ss.useBy) || !s.ReadUint32(&ss.ageAdd) {
		return nil, utlserrors.New("tls: invalid session encoding: missing TLS 1.3 client fields").AtError()
	}
	// [uTLS] Parse maxEarlyDataSize when EarlyData is enabled.
	// This is critical for 0-RTT session resumption.
	if ss.EarlyData {
		if !s.ReadUint32(&ss.maxEarlyDataSize) {
			return nil, utlserrors.New("tls: invalid session encoding: missing maxEarlyDataSize for early data").AtError()
		}
	}
	if !s.Empty() {
		return nil, utlserrors.New("tls: invalid session encoding: trailing data in TLS 1.3 client session").AtError()
	}

	// RFC 8446 Section 4.6.1: "Servers MUST NOT use any value greater than
	// 604800 seconds (7 days)." Validate that the ticket lifetime does not
	// exceed this maximum to reject malformed or malicious session data.
	// maxSessionTicketLifetime is 7 * 24 * time.Hour = 604800 seconds.
	const maxLifetimeSeconds = uint64(7 * 24 * 60 * 60) // 604800 seconds
	if ss.useBy > ss.createdAt && (ss.useBy-ss.createdAt) > maxLifetimeSeconds {
		return nil, utlserrors.New("tls: session ticket lifetime exceeds maximum allowed by RFC 8446").AtError()
	}

	utlserrors.LogDebug(context.Background(), "session: parsed TLS 1.3 client session state, earlyData=", ss.EarlyData, ", maxEarlyDataSize=", ss.maxEarlyDataSize)
	return ss, nil
}

// sessionState returns a partially filled-out [SessionState] with information
// from the current connection.
func (c *Conn) sessionState() *SessionState {
	return &SessionState{
		version:           c.vers,
		cipherSuite:       c.cipherSuite,
		createdAt:         uint64(c.config.time().Unix()),
		alpnProtocol:      c.clientProtocol,
		peerCertificates:  c.peerCertificates,
		activeCertHandles: c.activeCertHandles,
		ocspResponse:      c.ocspResponse,
		scts:              c.scts,
		isClient:          c.isClient,
		extMasterSecret:   c.extMasterSecret,
		verifiedChains:    c.verifiedChains,
	}
}

// EncryptTicket encrypts a ticket with the [Config]'s configured (or default)
// session ticket keys. It can be used as a [Config.WrapSession] implementation.
func (c *Config) EncryptTicket(cs ConnectionState, ss *SessionState) ([]byte, error) {
	utlserrors.LogDebug(context.Background(), "session: encrypting ticket for cipher=", ss.cipherSuite, ", version=", ss.version)
	ticketKeys, err := c.ticketKeys(nil)
	if err != nil {
		return nil, utlserrors.New("tls: failed to get ticket keys").Base(err).AtError()
	}
	stateBytes, err := ss.Bytes()
	if err != nil {
		return nil, utlserrors.New("tls: failed to serialize session state").Base(err).AtError()
	}
	return c.encryptTicket(stateBytes, ticketKeys)
}

func (c *Config) encryptTicket(state []byte, ticketKeys []ticketKey) ([]byte, error) {
	if len(ticketKeys) == 0 {
		return nil, utlserrors.New("tls: internal error: session ticket keys unavailable").AtError()
	}

	utlserrors.LogDebug(context.Background(), "session ticket: encrypting, stateSize=", len(state))

	encrypted := make([]byte, aes.BlockSize+len(state)+sha256.Size)
	iv := encrypted[:aes.BlockSize]
	ciphertext := encrypted[aes.BlockSize : len(encrypted)-sha256.Size]
	authenticated := encrypted[:len(encrypted)-sha256.Size]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	if _, err := io.ReadFull(c.rand(), iv); err != nil {
		return nil, utlserrors.New("tls: failed to generate IV for session ticket").Base(err).AtError()
	}
	key := ticketKeys[0]
	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, utlserrors.New("tls: failed to create cipher while encrypting ticket").Base(err).AtError()
	}
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, state)

	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(authenticated)
	mac.Sum(macBytes[:0])

	utlserrors.LogDebug(context.Background(), "session ticket: encrypted successfully, size=", len(encrypted))
	return encrypted, nil
}

// DecryptTicket decrypts a ticket encrypted by [Config.EncryptTicket]. It can
// be used as a [Config.UnwrapSession] implementation.
//
// If the ticket can't be decrypted (MAC verification fails), DecryptTicket
// returns (nil, nil). This is expected behavior for expired, forged, or
// mismatched tickets.
//
// If the ticket is successfully decrypted but cannot be parsed, DecryptTicket
// returns (nil, ErrTicketParsingFailed) with the underlying error wrapped.
// This indicates a cryptographically valid ticket with corrupt contents,
// which may be a security concern.
func (c *Config) DecryptTicket(identity []byte, cs ConnectionState) (*SessionState, error) {
	utlserrors.LogDebug(context.Background(), "session: decrypting ticket, identitySize=", len(identity))
	ticketKeys, err := c.ticketKeys(nil)
	if err != nil {
		return nil, utlserrors.New("tls: failed to get ticket keys").Base(err).AtError()
	}
	stateBytes := c.decryptTicket(identity, ticketKeys)
	if stateBytes == nil {
		// Decryption failed (MAC mismatch, ticket too short, etc.)
		// This is expected for old/forged tickets - return nil to ignore
		utlserrors.LogDebug(context.Background(), "session: ticket decryption failed (MAC mismatch or invalid)")
		return nil, nil
	}
	s, err := ParseSessionState(stateBytes)
	if err != nil {
		// SECURITY: Ticket passed MAC verification but payload is corrupt.
		// This is unexpected and may indicate data corruption, a bug in
		// ticket generation, or a sophisticated attack. Return error so
		// callers can log/monitor this condition.
		return nil, utlserrors.New("tls: session ticket parsing failed after successful decryption").Base(err).AtError()
	}
	utlserrors.LogDebug(context.Background(), "session: ticket decrypted successfully, version=", s.version)
	return s, nil
}

func (c *Config) decryptTicket(encrypted []byte, ticketKeys []ticketKey) []byte {
	utlserrors.LogDebug(context.Background(), "session ticket: decrypting, size=", len(encrypted))

	if len(encrypted) < aes.BlockSize+sha256.Size {
		utlserrors.LogDebug(context.Background(), "session ticket: too short, minSize=", aes.BlockSize+sha256.Size)
		return nil
	}

	iv := encrypted[:aes.BlockSize]
	ciphertext := encrypted[aes.BlockSize : len(encrypted)-sha256.Size]
	authenticated := encrypted[:len(encrypted)-sha256.Size]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	// SECURITY: Fully constant-time implementation to prevent timing attacks
	// that could reveal which key in the rotation pool was used.
	//
	// Strategy: Decrypt with ALL keys, then use constant-time selection to
	// pick the result from the matching key. This ensures identical timing
	// regardless of which key (if any) matches.

	numKeys := len(ticketKeys)
	if numKeys == 0 {
		return nil
	}

	// Pre-allocate decryption results for all keys
	decrypted := make([][]byte, numKeys)
	matchResults := make([]int, numKeys)

	// Process ALL keys unconditionally - same operations for each
	for i, key := range ticketKeys {
		// Compute MAC
		mac := hmac.New(sha256.New, key.hmacKey[:])
		mac.Write(authenticated)
		expected := mac.Sum(nil)

		// Constant-time compare - result is 1 for match, 0 for mismatch
		matchResults[i] = subtle.ConstantTimeCompare(macBytes, expected)

		// ALWAYS decrypt for every key to ensure constant timing
		// This prevents timing leaks about which key matched
		block, err := aes.NewCipher(key.aesKey[:])
		if err != nil {
			// Create dummy plaintext on error to maintain constant timing
			decrypted[i] = make([]byte, len(ciphertext))
			matchResults[i] = 0 // Mark as non-match on cipher error
			continue
		}
		plaintext := make([]byte, len(ciphertext))
		cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)
		decrypted[i] = plaintext
	}

	// Constant-time selection: find the matching result
	// If multiple keys match (shouldn't happen), use the first one
	var result []byte
	foundMask := 0
	for i := 0; i < numKeys; i++ {
		// selectMask is all 1s if this key matched AND we haven't found one yet
		// subtle.ConstantTimeSelect needs int, so we use bit manipulation
		isMatch := matchResults[i]
		notYetFound := 1 - foundMask

		// shouldSelect is 1 only if isMatch==1 AND foundMask==0
		shouldSelect := isMatch & notYetFound

		// Update foundMask: once we find a match, foundMask stays 1
		foundMask |= isMatch

		// Constant-time conditional copy: if shouldSelect==1, copy this result
		if result == nil {
			result = make([]byte, len(ciphertext))
		}
		for j := 0; j < len(result); j++ {
			// For each byte: result[j] = shouldSelect ? decrypted[i][j] : result[j]
			result[j] = byte(subtle.ConstantTimeSelect(shouldSelect, int(decrypted[i][j]), int(result[j])))
		}
	}

	// Return nil if no key matched (foundMask == 0)
	// Use constant-time check to avoid branch timing leak
	if foundMask == 0 {
		utlserrors.LogDebug(context.Background(), "session ticket: decryption failed, no key matched")
		return nil
	}
	utlserrors.LogDebug(context.Background(), "session ticket: decrypted successfully, plaintextSize=", len(result))
	return result
}

// ClientSessionState contains the state needed by a client to
// resume a previous TLS session.
type ClientSessionState struct {
	session *SessionState
}

// ResumptionState returns the session ticket sent by the server (also known as
// the session's identity) and the state necessary to resume this session.
//
// It can be called by [ClientSessionCache.Put] to serialize (with
// [SessionState.Bytes]) and store the session.
func (cs *ClientSessionState) ResumptionState() (ticket []byte, state *SessionState, err error) {
	if cs == nil || cs.session == nil {
		return nil, nil, nil
	}
	return cs.session.ticket, cs.session, nil
}

// NewResumptionState returns a state value that can be returned by
// [ClientSessionCache.Get] to resume a previous session.
//
// state needs to be returned by [ParseSessionState], and the ticket and session
// state must have been returned by [ClientSessionState.ResumptionState].
func NewResumptionState(ticket []byte, state *SessionState) (*ClientSessionState, error) {
	state.ticket = ticket
	return &ClientSessionState{
		session: state,
	}, nil
}

// // DecryptTicketWith decrypts an encrypted session ticket
// // using a TicketKeys (ie []TicketKey) struct
// //
// // usedOldKey will be true if the key used for decryption is
// // not the first in the []TicketKey slice
// //
// // [uTLS] changed to be made public and take a TicketKeys and use a fake conn receiver
// func DecryptTicketWith(encrypted []byte, tks TicketKeys) (plaintext []byte, usedOldKey bool) {
// 	// create fake conn
// 	c := &Conn{
// 		ticketKeys: tks.ToPrivate(),
// 	}

// 	return c.decryptTicket(encrypted)
// }
