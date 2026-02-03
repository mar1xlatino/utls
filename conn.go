// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// TLS low level connection and record layer

package tls

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utlserrors "github.com/refraction-networking/utls/errors"
)

// A Conn represents a secured connection.
// It implements the net.Conn interface.
type Conn struct {
	// constant
	conn        net.Conn
	isClient    bool
	handshakeFn func(context.Context) error // (*Conn).clientHandshake or serverHandshake
	quic        *quicState                  // nil for non-QUIC connections

	// isHandshakeComplete is true if the connection is currently transferring
	// application data (i.e. is not currently processing a handshake).
	// isHandshakeComplete is true implies handshakeErr == nil.
	isHandshakeComplete atomic.Bool
	// constant after handshake; protected by handshakeMutex
	handshakeMutex sync.Mutex
	handshakeErr   error   // error resulting from handshake
	vers           uint16  // TLS version
	haveVers       bool    // version has been negotiated
	config         *Config // configuration passed to constructor
	// handshakes counts the number of handshakes performed on the
	// connection so far. If renegotiation is disabled then this is either
	// zero or one.
	handshakes       int
	extMasterSecret  bool
	didResume        bool // whether this connection was a session resumption
	didHRR           bool // whether a HelloRetryRequest was sent/received
	cipherSuite      uint16
	curveID          CurveID
	ocspResponse     []byte   // stapled OCSP response
	scts             [][]byte // signed certificate timestamps from server
	peerCertificates []*x509.Certificate
	// activeCertHandles contains the cache handles to certificates in
	// peerCertificates that are used to track active references.
	activeCertHandles []*activeCert
	// verifiedChains contains the certificate chains that we built, as
	// opposed to the ones presented by the server.
	verifiedChains [][]*x509.Certificate
	// serverName contains the server name indicated by the client, if any.
	serverName string
	// secureRenegotiation is true if the server echoed the secure
	// renegotiation extension. (This is meaningless as a server because
	// renegotiation is not supported in that case.)
	secureRenegotiation bool
	// ekm is a closure for exporting keying material.
	ekm func(label string, context []byte, length int) ([]byte, error)
	// resumptionSecret is the resumption_master_secret for handling
	// or sending NewSessionTicket messages.
	resumptionSecret []byte
	echAccepted      bool

	// ticketKeys is the set of active session ticket keys for this
	// connection. The first one is used to encrypt new tickets and
	// all are tried to decrypt tickets.
	ticketKeys []ticketKey

	// clientFinishedIsFirst is true if the client sent the first Finished
	// message during the most recent handshake. This is recorded because
	// the first transmitted Finished message is the tls-unique
	// channel-binding value.
	clientFinishedIsFirst bool

	// closeNotifyErr is any error from sending the alertCloseNotify record.
	closeNotifyErr error
	// closeNotifySent is true if the Conn attempted to send an
	// alertCloseNotify record.
	closeNotifySent bool
	// closeNotifySeq is a sequence counter that increments whenever closeNotify
	// state changes. Used to detect ABA race conditions when the lock is temporarily
	// released during closeNotify jitter delays. Protected by out.Mutex.
	closeNotifySeq uint64

	// fatalAlertSent prevents sending multiple fatal alerts on the same connection.
	// RFC 8446 Section 6: After sending or receiving a fatal alert, implementations
	// MUST NOT send any additional alerts. Once set, all subsequent alert sends
	// (including close_notify) are suppressed.
	fatalAlertSent atomic.Bool

	// clientFinished and serverFinished contain the Finished message sent
	// by the client or server in the most recent handshake. This is
	// retained to support the renegotiation extension and tls-unique
	// channel-binding.
	clientFinished [12]byte
	serverFinished [12]byte

	// clientProtocol is the negotiated ALPN protocol.
	clientProtocol string

	utls utlsConnExtraFields // [UTLS] used for extensive things such as ALPS, PSK, etc

	// input/output
	in, out   halfConn
	rawInput  bytes.Buffer // raw input, starting with a record header
	input     bytes.Reader // application data waiting to be read, from rawInput.Next
	hand      bytes.Buffer // handshake data waiting to be read
	buffering bool         // whether records are buffered in sendBuf
	sendBuf   []byte       // a buffer of records waiting to be sent

	// bytesSent counts the bytes of application data sent.
	// packetsSent counts packets.
	// These counters use atomic operations for thread-safe concurrent access.
	bytesSent   atomic.Int64
	packetsSent atomic.Int64

	// retryCount counts the number of consecutive non-advancing records
	// received by Conn.readRecord. That is, records that neither advance the
	// handshake, nor deliver application data. Protected by in.Mutex.
	retryCount int

	// activeCall indicates whether Close has been call in the low bit.
	// the rest of the bits are the number of goroutines in Conn.Write.
	activeCall atomic.Int32

	tmp [16]byte
}

// Access to net.Conn methods.
// Cannot just embed net.Conn because that would
// export the struct field too.

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means [Conn.Read] and [Conn.Write] will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means [Conn.Read] will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means [Conn.Write] will not time out.
// After a [Conn.Write] has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// NetConn returns the underlying connection that is wrapped by c.
// Note that writing to or reading from this connection directly will corrupt the
// TLS session.
func (c *Conn) NetConn() net.Conn {
	return c.conn
}

// ClientProtocol returns the negotiated ALPN protocol.
// Returns empty string if ALPN was not used or handshake is not complete.
// This is equivalent to ConnectionState().NegotiatedProtocol but can be
// called without copying the full connection state.
func (c *Conn) ClientProtocol() string {
	return c.clientProtocol
}

// safeRemoteAddr returns the remote address as a string, or "" if unavailable.
// This safely handles both nil connection and nil address cases.
func (c *Conn) safeRemoteAddr() string {
	if c.conn == nil {
		return ""
	}
	addr := c.conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

// A halfConn represents one direction of the record layer
// connection, either sending or receiving.
type halfConn struct {
	sync.Mutex

	err     error  // first permanent error
	version uint16 // protocol version
	cipher  any    // cipher algorithm
	mac     hash.Hash
	seq     [8]byte // 64-bit sequence number

	scratchBuf [13]byte // to avoid allocs; interface method args escape

	nextCipher any       // next encryption state
	nextMac    hash.Hash // next MAC algorithm

	level         QUICEncryptionLevel // current QUIC encryption level
	trafficSecret []byte              // current TLS 1.3 traffic secret
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }

func (hc *halfConn) setErrorLocked(err error) error {
	if e, ok := err.(net.Error); ok {
		hc.err = &permanentError{err: e}
	} else {
		hc.err = err
	}
	return hc.err
}

// prepareCipherSpec sets the encryption and MAC states
// that a subsequent changeCipherSpec will use.
func (hc *halfConn) prepareCipherSpec(version uint16, cipher any, mac hash.Hash) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

// changeCipherSpec changes the encryption and MAC states
// to the ones previously passed to prepareCipherSpec.
func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil || hc.version == VersionTLS13 {
		return alertInternalError
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

func (hc *halfConn) setTrafficSecret(suite *cipherSuiteTLS13, level QUICEncryptionLevel, secret []byte) error {
	// Zero the old traffic secret before replacing it to minimize
	// the window where it could be extracted from memory.
	if hc.trafficSecret != nil {
		zeroSlice(hc.trafficSecret)
	}
	hc.trafficSecret = secret
	hc.level = level
	key, iv, err := suite.trafficKey(secret)
	if err != nil {
		return err
	}
	aeadCipher, err := suite.aead(key, iv)
	if err != nil {
		// Zero key material before returning error.
		zeroSlice(key)
		zeroSlice(iv)
		return fmt.Errorf("tls: failed to create AEAD cipher: %w", err)
	}
	hc.cipher = aeadCipher
	// Zero the derived key and IV after AEAD construction.
	// Note: AEAD implementations typically copy these internally.
	zeroSlice(key)
	zeroSlice(iv)
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

// zeroSecrets zeros all secret material in the connection.
// Called on fatal errors per RFC 8446 Section 6: "Servers and clients MUST forget
// the secret values and keys established in failed connections."
//
// Uses explicit nil assignment after zeroing to help GC and prevent accidental reuse.
// The zeroing loop overwrites sensitive cryptographic material in memory before
// releasing the reference. Uses zeroSlice which includes runtime.KeepAlive to
// prevent compiler optimization from eliding the zeroing operation.
func (c *Conn) zeroSecrets() {
	// Zero input traffic secret
	if c.in.trafficSecret != nil {
		zeroSlice(c.in.trafficSecret)
		c.in.trafficSecret = nil
	}
	// Zero output traffic secret
	if c.out.trafficSecret != nil {
		zeroSlice(c.out.trafficSecret)
		c.out.trafficSecret = nil
	}
	// Zero resumption secret (TLS 1.3)
	if c.resumptionSecret != nil {
		zeroSlice(c.resumptionSecret)
		c.resumptionSecret = nil
	}
}

// errSequenceOverflow is returned when TLS sequence number would wrap around.
// This indicates the connection has processed 2^64 records and must be closed.
var errSequenceOverflow = utlserrors.New("tls: sequence number overflow").AtError()

// errUnknownCipherType is returned when an unrecognized cipher type is encountered.
// This typically indicates a programming error or corrupted state.
var errUnknownCipherType = utlserrors.New("tls: unknown cipher type").AtError()

// incSeq increments the sequence number.
// Returns an error if the sequence number would overflow.
//
// Per RFC 8446 Section 5.3: "If a TLS implementation would need to wrap a
// sequence number, it MUST either rekey (Section 4.6.3) or terminate the
// connection."
func (hc *halfConn) incSeq() error {
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return nil
		}
	}

	// Not allowed to let sequence number wrap.
	// Per RFC 8446, must rekey or terminate the connection.
	// Set permanent error to prevent any further use of this connection half,
	// ensuring the connection cannot continue in an undefined state even if
	// calling code ignores the returned error.
	hc.err = errSequenceOverflow
	return errSequenceOverflow
}

// explicitNonceLen returns the number of bytes of explicit nonce or IV included
// in each record. Explicit nonces are present only in CBC modes after TLS 1.0
// and in certain AEAD modes in TLS 1.2.
// Returns an error if an unknown cipher type is encountered.
func (hc *halfConn) explicitNonceLen() (int, error) {
	if hc.cipher == nil {
		return 0, nil
	}

	switch c := hc.cipher.(type) {
	case cipher.Stream:
		return 0, nil
	case aead:
		return c.explicitNonceLen(), nil
	case cbcMode:
		// TLS 1.1 introduced a per-record explicit IV to fix the BEAST attack.
		if hc.version >= VersionTLS11 {
			return c.BlockSize(), nil
		}
		return 0, nil
	default:
		return 0, errUnknownCipherType
	}
}

// extractPadding returns, in constant time, the length of the padding to remove
// from the end of payload. It also returns a byte which is equal to 255 if the
// padding was valid and 0 otherwise. See RFC 2246, Section 6.2.3.2.
func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good = byte(int32(^t) >> 31)

	// The maximum possible padding length plus the actual length field
	toCheck := 256
	// The length of the padded data is public, so we can use an if here
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	// Zero the padding length on error. This ensures any unchecked bytes
	// are included in the MAC. Otherwise, an attacker that could
	// distinguish MAC failures from padding failures could mount an attack
	// similar to POODLE in SSL 3.0: given a good ciphertext that uses a
	// full block's worth of padding, replace the final block with another
	// block. If the MAC check passed but the padding check failed, the
	// last byte of that block decrypted to the block size.
	//
	// See also macAndPaddingGood logic below.
	paddingLen &= good

	toRemove = int(paddingLen) + 1
	return
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

// cbcMode is an interface for block ciphers using cipher block chaining.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

// decrypt authenticates and decrypts the record if protection is active at
// this stage. The returned plaintext might overlap with the input.
func (hc *halfConn) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
	// decrypted. See RFC 8446, Appendix D.4.
	if hc.version == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	paddingGood := byte(255)
	paddingLen := 0

	explicitNonceLen, err := hc.explicitNonceLen()
	if err != nil {
		return nil, 0, alertInternalError
	}

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case aead:
			if len(payload) < explicitNonceLen {
				return nil, 0, alertBadRecordMAC
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				nonce = hc.seq[:]
			}
			payload = payload[explicitNonceLen:]

			var additionalData []byte
			if hc.version == VersionTLS13 {
				additionalData = record[:recordHeaderLen]
			} else {
				additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
				additionalData = append(additionalData, record[:3]...)
				n := len(payload) - c.Overhead()
				additionalData = append(additionalData, byte(n>>8), byte(n))
			}

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				return nil, 0, alertBadRecordMAC
			}
		case cbcMode:
			blockSize := c.BlockSize()
			minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
			if len(payload)%blockSize != 0 || len(payload) < minPayload {
				return nil, 0, alertBadRecordMAC
			}

			if explicitNonceLen > 0 {
				c.SetIV(payload[:explicitNonceLen])
				payload = payload[explicitNonceLen:]
			}
			c.CryptBlocks(payload, payload)

			// In a limited attempt to protect against CBC padding oracles like
			// Lucky13, the data past paddingLen (which is secret) is passed to
			// the MAC function as extra data, to be fed into the HMAC after
			// computing the digest. This makes the MAC roughly constant time as
			// long as the digest computation is constant time and does not
			// affect the subsequent write, modulo cache effects.
			paddingLen, paddingGood = extractPadding(payload)
		default:
			return nil, 0, alertInternalError
		}

		if hc.version == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			// TLS 1.3 always uses AEAD ciphers, so plaintext must be assigned above.
			// This check satisfies static analyzers and provides defense in depth.
			if plaintext == nil {
				return nil, 0, alertInternalError
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			// Remove padding and find the ContentType scanning from the end.
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	if hc.mac != nil {
		macSize := hc.mac.Size()
		if len(payload) < macSize {
			return nil, 0, alertBadRecordMAC
		}

		n := len(payload) - macSize - paddingLen
		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
		record[3] = byte(n >> 8)
		record[4] = byte(n)
		remoteMAC := payload[n : n+macSize]
		localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

		// This is equivalent to checking the MACs and paddingGood
		// separately, but in constant-time to prevent distinguishing
		// padding failures from MAC failures. Depending on what value
		// of paddingLen was returned on bad padding, distinguishing
		// bad MAC from bad padding can lead to an attack.
		//
		// See also the logic at the end of extractPadding.
		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		if macAndPaddingGood != 1 {
			return nil, 0, alertBadRecordMAC
		}

		plaintext = payload[:n]
	}

	if err := hc.incSeq(); err != nil {
		return nil, 0, alertInternalError
	}
	return plaintext, typ, nil
}

// sliceForAppend extends the input slice by n bytes. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	total := len(in) + n
	// Explicit nil check satisfies static analyzers. For nil slice with n > 0,
	// cap(in) is 0 so we'd allocate anyway, but nilaway cannot prove this.
	if in != nil && cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// encrypt encrypts payload, adding the appropriate nonce and/or MAC, and
// appends it to record, which must already contain the record header.
// For TLS 1.3, paddingLen specifies how many zero bytes to add after the ContentType.
func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader, paddingLen int) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	explicitNonceLen, err := hc.explicitNonceLen()
	if err != nil {
		return nil, err
	}
	if explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
			// The AES-GCM construction in TLS has an explicit nonce so that the
			// nonce can be random. However, the nonce is only 8 bytes which is
			// too small for a secure, random nonce. Therefore we use the
			// sequence number as the nonce. The 3DES-CBC construction also has
			// an 8 bytes nonce but its nonces must be unpredictable (see RFC
			// 5246, Appendix F.3), forcing us to use randomness. That's not
			// 3DES' biggest problem anyway because the birthday bound on block
			// collision is reached first due to its similarly small block size
			// (see the Sweet32 attack).
			copy(explicitNonce, hc.seq[:])
		} else {
			if _, err := io.ReadFull(rand, explicitNonce); err != nil {
				return nil, err
			}
		}
	}

	var dst []byte
	switch c := hc.cipher.(type) {
	case cipher.Stream:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		record, dst = sliceForAppend(record, len(payload)+len(mac))
		c.XORKeyStream(dst[:len(payload)], payload)
		c.XORKeyStream(dst[len(payload):], mac)
	case aead:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}

		if hc.version == VersionTLS13 {
			record = append(record, payload...)

			// Encrypt the actual ContentType and replace the plaintext one.
			record = append(record, record[0])
			record[0] = byte(recordTypeApplicationData)

			// [uTLS] Add TLS 1.3 record padding per RFC 8446 Section 5.4
			// Padding zeros are added after ContentType byte
			if paddingLen > 0 {
				// Clamp padding to not exceed record limits
				paddingLen = ClampPaddingToRecordLimit(len(payload), paddingLen)
				// Only allocate and append if clamping didn't reduce to zero
				if paddingLen > 0 {
					// Append padding zeros (make() initializes to zeros)
					padding := make([]byte, paddingLen)
					record = append(record, padding...)
				}
			}

			n := len(payload) + 1 + paddingLen + c.Overhead()
			record[3] = byte(n >> 8)
			record[4] = byte(n)

			record = c.Seal(record[:recordHeaderLen],
				nonce, record[recordHeaderLen:], record[:recordHeaderLen])
		} else {
			additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
			additionalData = append(additionalData, record[:recordHeaderLen]...)
			record = c.Seal(record, nonce, payload, additionalData)
		}
	case cbcMode:
		mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
		blockSize := c.BlockSize()
		plaintextLen := len(payload) + len(mac)
		paddingLen := blockSize - plaintextLen%blockSize
		record, dst = sliceForAppend(record, plaintextLen+paddingLen)
		copy(dst, payload)
		copy(dst[len(payload):], mac)
		for i := plaintextLen; i < len(dst); i++ {
			dst[i] = byte(paddingLen - 1)
		}
		if len(explicitNonce) > 0 {
			c.SetIV(explicitNonce)
		}
		c.CryptBlocks(dst, dst)
	default:
		return nil, errUnknownCipherType
	}

	// Update length to include nonce, MAC and any block padding needed.
	n := len(record) - recordHeaderLen
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	if err := hc.incSeq(); err != nil {
		return nil, err
	}

	return record, nil
}

// RecordHeaderError is returned when a TLS record header is invalid.
type RecordHeaderError struct {
	// Msg contains a human readable string that describes the error.
	Msg string
	// RecordHeader contains the five bytes of TLS record header that
	// triggered the error.
	RecordHeader [5]byte
	// Conn provides the underlying net.Conn in the case that a client
	// sent an initial handshake that didn't look like TLS.
	// It is nil if there's already been a handshake or a TLS alert has
	// been written to the connection.
	Conn net.Conn
}

func (e RecordHeaderError) Error() string { return "tls: " + e.Msg }

func (c *Conn) newRecordHeaderError(conn net.Conn, msg string) (err RecordHeaderError) {
	err.Msg = msg
	err.Conn = conn
	copy(err.RecordHeader[:], c.rawInput.Bytes())
	return err
}

func (c *Conn) readRecord() error {
	return c.readRecordOrCCS(false)
}

func (c *Conn) readChangeCipherSpec() error {
	return c.readRecordOrCCS(true)
}

// readRecordOrCCS reads one or more TLS records from the connection and
// updates the record layer state. Some invariants:
//   - c.in must be locked
//   - c.input must be empty
//
// During the handshake one and only one of the following will happen:
//   - c.hand grows
//   - c.in.changeCipherSpec is called
//   - an error is returned
//
// After the handshake one and only one of the following will happen:
//   - c.hand grows
//   - c.input is set
//   - an error is returned
func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {
	if c.in.err != nil {
		if utlserrors.DebugLoggingEnabled {
			utlserrors.LogDebug(context.Background(), "conn: readRecordOrCCS returning cached error: ", c.in.err)
		}
		return c.in.err
	}
	handshakeComplete := c.isHandshakeComplete.Load()

	// This function modifies c.rawInput, which owns the c.input memory.
	if c.input.Len() != 0 {
		return c.in.setErrorLocked(utlserrors.New("tls: internal error: attempted to read record with pending application data").AtError())
	}
	c.input.Reset(nil)

	if c.quic != nil {
		return c.in.setErrorLocked(utlserrors.New("tls: internal error: attempted to read record with QUIC transport").AtError())
	}

	// Read header, payload.
	if err := c.readFromUntil(c.conn, recordHeaderLen); err != nil {
		// RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
		// is an error, but popular web sites seem to do this, so we accept it
		// if and only if at the record boundary.
		if err == io.ErrUnexpectedEOF && c.rawInput.Len() == 0 {
			err = io.EOF
		}
		if utlserrors.DebugLoggingEnabled {
			utlserrors.LogDebug(context.Background(), "conn: readRecordOrCCS header read error: ", err)
		}
		// Note: net.Error.Temporary() is deprecated since Go 1.18.
		// Timeout errors can be checked via Timeout(), but "temporary" errors
		// are unreliable. Always set the error to ensure proper cleanup.

		// Call observability hook for network errors (not EOF)
		if err != io.EOF {
			remoteAddr := c.safeRemoteAddr()
			var netErr net.Error
			if errors.As(err, &netErr) {
				if netErr.Timeout() {
					callOnTimeoutError(remoteAddr)
				} else {
					callOnNetworkError(remoteAddr, err)
				}
			} else {
				callOnNetworkError(remoteAddr, err)
			}
		}

		c.in.setErrorLocked(err)
		return err
	}
	hdr := c.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(context.Background(), "conn: readRecordOrCCS type=", typ, " vers=", uint16(hdr[1])<<8|uint16(hdr[2]))
	}

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		c.sendAlert(alertProtocolVersion)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 handshake received"))
	}

	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	expectedVers := c.vers
	if expectedVers == VersionTLS13 {
		// All TLS 1.3 records are expected to have 0x0303 (1.2) after
		// the initial hello (RFC 8446 Section 5.1).
		expectedVers = VersionTLS12
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if c.haveVers && vers != expectedVers {
		c.sendAlert(alertProtocolVersion)
		msg := fmt.Sprintf("received record with version %x when expecting version %x", vers, expectedVers)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if !c.haveVers {
		// First message, be extra suspicious: this might not be a TLS
		// client. Bail out before reading a full 'body', if possible.
		// The current max version is 3.3 so if the version is >= 16.0,
		// it's probably not real.
		if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
			return c.in.setErrorLocked(c.newRecordHeaderError(c.conn, "first record does not look like a TLS handshake"))
		}
	}
	if c.vers == VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
		c.sendAlert(alertRecordOverflow)
		msg := fmt.Sprintf("oversized record received with length %d", n)
		return c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if err := c.readFromUntil(c.conn, recordHeaderLen+n); err != nil {
		// Note: net.Error.Temporary() is deprecated since Go 1.18.
		// Always set the error to ensure proper cleanup.

		// Call observability hook for network errors (not EOF)
		if err != io.EOF {
			remoteAddr := c.safeRemoteAddr()
			var netErr net.Error
			if errors.As(err, &netErr) {
				if netErr.Timeout() {
					callOnTimeoutError(remoteAddr)
				} else {
					callOnNetworkError(remoteAddr, err)
				}
			} else {
				callOnNetworkError(remoteAddr, err)
			}
		}

		c.in.setErrorLocked(err)
		return err
	}

	// Process message.
	record := c.rawInput.Next(recordHeaderLen + n)
	data, typ, err := c.in.decrypt(record)
	if err != nil {
		if utlserrors.DebugLoggingEnabled {
			utlserrors.LogDebug(context.Background(), "conn: decrypt failed: ", err)
		}
		// Call observability hook for crypto/decryption errors
		remoteAddr := c.safeRemoteAddr()
		callOnCryptoError(remoteAddr, err)
		return c.in.setErrorLocked(c.sendAlert(err.(alert)))
	}
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(context.Background(), "conn: decrypted record type=", typ, " len=", len(data))
	}
	if len(data) > maxPlaintext {
		return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
	}

	// [uTLS] RFC 8449: Enforce advertised record size limit.
	// Per RFC 8449 Section 4: "A TLS endpoint that receives a record larger
	// than its advertised limit MUST generate a fatal 'record_overflow' alert."
	// This check applies to the inner plaintext after decryption.
	// In TLS 1.3, the advertised limit includes the content type byte.
	if c.utls.advertisedRecordSizeLimit > 0 && len(data) > int(c.utls.advertisedRecordSizeLimit) {
		return c.in.setErrorLocked(c.sendAlert(alertRecordOverflow))
	}

	// Application Data messages are always protected.
	if c.in.cipher == nil && typ == recordTypeApplicationData {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
		// This is a state-advancing message: reset the retry count.
		c.retryCount = 0
	}

	// Handshake messages MUST NOT be interleaved with other record types in TLS 1.3.
	if c.vers == VersionTLS13 && typ != recordTypeHandshake && c.hand.Len() > 0 {
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	switch typ {
	default:
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))

	case recordTypeAlert:
		if c.quic != nil {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if len(data) != 2 {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if utlserrors.DebugLoggingEnabled {
			utlserrors.LogDebug(context.Background(), "alert: received", alert(data[1]).String())
		}
		if alert(data[1]) == alertCloseNotify {
			return c.in.setErrorLocked(io.EOF)
		}
		if c.vers == VersionTLS13 {
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		}
		switch data[0] {
		case alertLevelWarning:
			// Drop the record on the floor and retry.
			return c.retryReadRecord(expectChangeCipherSpec)
		case alertLevelError:
			return c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		default:
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}

	case recordTypeChangeCipherSpec:
		if len(data) != 1 || data[0] != 1 {
			return c.in.setErrorLocked(c.sendAlert(alertDecodeError))
		}
		// Handshake messages are not allowed to fragment across the CCS.
		if c.hand.Len() > 0 {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		// In TLS 1.3, change_cipher_spec records are ignored until the
		// Finished. See RFC 8446, Appendix D.4. Note that according to Section
		// 5, a server can send a ChangeCipherSpec before its ServerHello, when
		// c.vers is still unset. That's not useful though and suspicious if the
		// server then selects a lower protocol version, so don't allow that.
		if c.vers == VersionTLS13 && !handshakeComplete {
			return c.retryReadRecord(expectChangeCipherSpec)
		}
		if !expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		if err := c.in.changeCipherSpec(); err != nil {
			return c.in.setErrorLocked(c.sendAlert(err.(alert)))
		}

	case recordTypeApplicationData:
		if !handshakeComplete || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		// Some OpenSSL servers send empty records in order to randomize the
		// CBC IV. Ignore a limited number of empty records.
		if len(data) == 0 {
			return c.retryReadRecord(expectChangeCipherSpec)
		}
		// Note that data is owned by c.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because c.rawInput is
		// not read from or written to until c.input is drained.
		c.input.Reset(data)

	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		c.hand.Write(data)
	}

	return nil
}

// retryReadRecord recurs into readRecordOrCCS to drop a non-advancing record, like
// a warning alert, empty application_data, or a change_cipher_spec in TLS 1.3.
func (c *Conn) retryReadRecord(expectChangeCipherSpec bool) error {
	c.retryCount++
	if c.retryCount > maxUselessRecords {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(utlserrors.New("tls: too many ignored records").AtError())
	}
	return c.readRecordOrCCS(expectChangeCipherSpec)
}

// atLeastReader reads from R, stopping with EOF once at least N bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// readFromUntil reads from r into c.rawInput until c.rawInput contains
// at least n bytes or else returns an error.
func (c *Conn) readFromUntil(r io.Reader, n int) error {
	if c.rawInput.Len() >= n {
		return nil
	}
	needs := n - c.rawInput.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	c.rawInput.Grow(needs + bytes.MinRead)
	_, err := c.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

// sendAlertLocked sends a TLS alert message.
// For fatal alerts, it also zeros all secret material per RFC 8446 Section 6:
// "Servers and clients MUST forget the secret values and keys established
// in failed connections."
//
// Prevents sending multiple fatal alerts on the same connection per RFC 8446
// Section 6: "Upon transmission or receipt of a fatal alert message, both
// parties MUST immediately close the connection." Once a fatal alert is sent,
// all subsequent alerts (including close_notify) are suppressed.
func (c *Conn) sendAlertLocked(err alert) error {
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(context.Background(), "alert: sending", err.String())
	}
	if c.quic != nil {
		return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
	}

	// Determine if this is a fatal alert per RFC 8446 Section 6.
	// In TLS 1.3, only close_notify and user_canceled are warning-level;
	// all other alerts are fatal. alertNoRenegotiation is TLS 1.2 only
	// (renegotiation is forbidden in TLS 1.3) and uses warning level.
	isFatal := err != alertCloseNotify && err != alertUserCanceled && err != alertNoRenegotiation

	// RFC 8446 Section 6: Once a fatal alert has been sent, no further alerts
	// should be transmitted. This prevents sending close_notify after a fatal
	// alert (which would be an RFC violation) and prevents duplicate fatal alerts.
	if isFatal {
		if !c.fatalAlertSent.CompareAndSwap(false, true) {
			// Already sent a fatal alert - suppress this duplicate
			return nil
		}
	} else {
		// For non-fatal alerts (close_notify, user_canceled, no_renegotiation):
		// suppress if a fatal alert was already sent
		if c.fatalAlertSent.Load() {
			return nil
		}
	}

	// RFC 8446 Section 6: Zero all secret material on fatal alert.
	// This ensures traffic secrets and resumption secrets don't persist
	// in memory after a failed connection, preventing potential extraction
	// via memory inspection attacks.
	if isFatal {
		c.zeroSecrets()
	}

	switch err {
	case alertNoRenegotiation, alertCloseNotify, alertUserCanceled:
		// RFC 8446 Section 6.1: user_canceled "generally has AlertLevel=warning"
		c.tmp[0] = alertLevelWarning
	default:
		c.tmp[0] = alertLevelError
	}
	c.tmp[1] = byte(err)

	_, writeErr := c.writeRecordLocked(recordTypeAlert, c.tmp[0:2])
	if err == alertCloseNotify {
		// closeNotify is a special case in that it isn't an error.
		return writeErr
	}

	return c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
}

// sendAlert sends a TLS alert message.
func (c *Conn) sendAlert(err alert) error {
	c.out.Lock()
	defer c.out.Unlock()
	return c.sendAlertLocked(err)
}

const (
	// tcpMSSEstimate is a conservative estimate of the TCP maximum segment
	// size (MSS). A constant is used, rather than querying the kernel for
	// the actual MSS, to avoid complexity. The value here is the IPv6
	// minimum MTU (1280 bytes) minus the overhead of an IPv6 header (40
	// bytes) and a TCP header with timestamps (32 bytes).
	tcpMSSEstimate = 1208

	// recordSizeBoostThreshold is the number of bytes of application data
	// sent after which the TLS record size will be increased to the
	// maximum.
	recordSizeBoostThreshold = 128 * 1024
)

// maxPayloadSizeForWrite returns the maximum TLS payload size to use for the
// next application data record. There is the following trade-off:
//
//   - For latency-sensitive applications, such as web browsing, each TLS
//     record should fit in one TCP segment.
//   - For throughput-sensitive applications, such as large file transfers,
//     larger TLS records better amortize framing and encryption overheads.
//
// A simple heuristic that works well in practice is to use small records for
// the first 1MB of data, then use larger records for subsequent data, and
// reset back to smaller records after the connection becomes idle. See "High
// Performance Web Networking", Chapter 4, or:
// https://www.igvita.com/2013/10/24/optimizing-tls-record-size-and-buffering-latency/
//
// In the interests of simplicity and determinism, this code does not attempt
// to reset the record size once the connection is idle, however.
//
// [uTLS] This function also respects the negotiated record_size_limit (RFC 8449)
// when the extension was negotiated. The limit applies to the inner plaintext.
// Returns an error if an unknown cipher type is encountered.
func (c *Conn) maxPayloadSizeForWrite(typ recordType) (int, error) {
	// [uTLS] Determine the effective maximum plaintext based on record_size_limit.
	// RFC 8449 Section 4: The limit is for the inner plaintext, which in TLS 1.3
	// includes the content type byte. So for TLS 1.3, if limit is L, we can send
	// L-1 bytes of actual application data (1 byte reserved for content type).
	effectiveMax := maxPlaintext
	if c.utls.negotiatedRecordSizeLimit > 0 {
		// The negotiated limit is for inner plaintext (before encryption overhead).
		// In TLS 1.3, this includes the 1-byte content type, so actual data is limit-1.
		// In TLS 1.2, the limit applies directly to the plaintext.
		limit := int(c.utls.negotiatedRecordSizeLimit)
		if c.vers == VersionTLS13 {
			// RFC 8449 Section 4: For TLS 1.3, the limit includes content type byte
			effectiveMax = limit - 1
		} else {
			effectiveMax = limit
		}
		// Ensure we don't exceed the protocol maximum
		if effectiveMax > maxPlaintext {
			effectiveMax = maxPlaintext
		}
		// Ensure minimum reasonable size (RFC 8449 minimum is 64, minus content type = 63)
		if effectiveMax < 63 {
			effectiveMax = 63
		}
	}

	if c.config.DynamicRecordSizingDisabled || typ != recordTypeApplicationData {
		return effectiveMax, nil
	}

	if c.bytesSent.Load() >= recordSizeBoostThreshold {
		return effectiveMax, nil
	}

	// Subtract TLS overheads to get the maximum payload size.
	explicitNonceLen, err := c.out.explicitNonceLen()
	if err != nil {
		return 0, err
	}
	payloadBytes := tcpMSSEstimate - recordHeaderLen - explicitNonceLen
	if c.out.cipher != nil {
		switch ciph := c.out.cipher.(type) {
		case cipher.Stream:
			payloadBytes -= c.out.mac.Size()
		case cipher.AEAD:
			payloadBytes -= ciph.Overhead()
		case cbcMode:
			blockSize := ciph.BlockSize()
			// The payload must fit in a multiple of blockSize, with
			// room for at least one padding byte.
			payloadBytes = (payloadBytes & ^(blockSize - 1)) - 1
			// The MAC is appended before padding so affects the
			// payload size directly.
			payloadBytes -= c.out.mac.Size()
		default:
			return 0, errUnknownCipherType
		}
	}
	if c.vers == VersionTLS13 {
		payloadBytes-- // encrypted ContentType
	}

	// Allow packet growth in arithmetic progression up to max.
	// Atomically increment and get the previous value (Add returns new value).
	pkt := c.packetsSent.Add(1) - 1
	if pkt > 1000 {
		return effectiveMax, nil // avoid overflow in multiply below
	}

	n := payloadBytes * int(pkt+1)
	if n > effectiveMax {
		n = effectiveMax
	}
	return n, nil
}

func (c *Conn) write(data []byte) (int, error) {
	if c.buffering {
		c.sendBuf = append(c.sendBuf, data...)
		return len(data), nil
	}

	n, err := c.conn.Write(data)
	c.bytesSent.Add(int64(n))
	return n, err
}

func (c *Conn) flush() (int, error) {
	if len(c.sendBuf) == 0 {
		return 0, nil
	}

	n, err := c.conn.Write(c.sendBuf)
	c.bytesSent.Add(int64(n))
	c.sendBuf = nil
	c.buffering = false
	return n, err
}

// outBufPool pools the record-sized scratch buffers used by writeRecordLocked.
var outBufPool = sync.Pool{
	New: func() any {
		return new([]byte)
	},
}

// writeRecordLocked writes a TLS record with the given type and payload to the
// connection and updates the record layer state.
func (c *Conn) writeRecordLocked(typ recordType, data []byte) (int, error) {
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(context.Background(), "conn: writeRecordLocked type=", typ, " len=", len(data))
	}
	if c.quic != nil {
		if typ != recordTypeHandshake {
			return 0, utlserrors.New("tls: internal error: sending non-handshake message to QUIC transport").AtError()
		}
		c.quicWriteCryptoData(c.out.level, data)
		if !c.buffering {
			if _, err := c.flush(); err != nil {
				return 0, err
			}
		}
		return len(data), nil
	}

	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		// You might be tempted to simplify this by just passing &outBuf to Put,
		// but that would make the local copy of the outBuf slice header escape
		// to the heap, causing an allocation. Instead, we keep around the
		// pointer to the slice header returned by Get, which is already on the
		// heap, and overwrite and return that.
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()

	var n int
	for len(data) > 0 {
		m := len(data)
		maxPayload, err := c.maxPayloadSizeForWrite(typ)
		if err != nil {
			return n, err
		}
		if m > maxPayload {
			m = maxPayload
		}

		_, outBuf = sliceForAppend(outBuf[:0], recordHeaderLen)
		outBuf[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionTLS10
		} else if vers == VersionTLS13 {
			// TLS 1.3 froze the record layer version to 1.2.
			// See RFC 8446, Section 5.1.
			vers = VersionTLS12
		}
		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(m >> 8)
		outBuf[4] = byte(m)

		// [uTLS] Generate TLS 1.3 record padding for fingerprint resistance.
		// For UConn (uTLS), padding is ENABLED BY DEFAULT via uClient().
		// For standard Conn, padding is disabled unless explicitly configured.
		// Use config.RecordPadding = DisabledRecordPaddingConfig() to disable.
		paddingLen := 0
		if c.vers == VersionTLS13 && c.config.RecordPadding != nil {
			paddingLen = c.config.RecordPadding.GeneratePadding()
		}

		outBuf, err = c.out.encrypt(outBuf, data[:m], c.config.rand(), paddingLen)
		if err != nil {
			return n, err
		}
		if _, err := c.write(outBuf); err != nil {
			return n, err
		}
		n += m
		data = data[m:]
	}

	if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
		if err := c.out.changeCipherSpec(); err != nil {
			return n, c.sendAlertLocked(err.(alert))
		}
	}

	return n, nil
}

// writeHandshakeRecord writes a handshake message to the connection and updates
// the record layer state. If transcript is non-nil the marshaled message is
// written to it.
func (c *Conn) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	return c.writeRecordLocked(recordTypeHandshake, data)
}

// writeChangeCipherRecord writes a ChangeCipherSpec message to the connection and
// updates the record layer state.
func (c *Conn) writeChangeCipherRecord() error {
	c.out.Lock()
	defer c.out.Unlock()
	_, err := c.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1})
	return err
}

// readHandshakeBytes reads handshake data until c.hand contains at least n bytes.
func (c *Conn) readHandshakeBytes(n int) error {
	if c.quic != nil {
		return c.quicReadHandshakeBytes(n)
	}
	for c.hand.Len() < n {
		if err := c.readRecord(); err != nil {
			return err
		}
	}
	return nil
}

// readHandshake reads the next handshake message from
// the record layer. If transcript is non-nil, the message
// is written to the passed transcriptHash.
func (c *Conn) readHandshake(transcript transcriptHash) (any, error) {
	if err := c.readHandshakeBytes(4); err != nil {
		return nil, err
	}
	data := c.hand.Bytes()

	maxHandshakeSize := maxHandshake
	// hasVers indicates we're past the first message, forcing someone trying to
	// make us just allocate a large buffer to at least do the initial part of
	// the handshake first.
	if c.haveVers && data[0] == typeCertificate {
		// Since certificate messages are likely to be the only messages that
		// can be larger than maxHandshake, we use a special limit for just
		// those messages.
		maxHandshakeSize = maxHandshakeCertificateMsg
	}

	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshakeSize {
		c.sendAlertLocked(alertInternalError)
		return nil, c.in.setErrorLocked(fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshakeSize))
	}
	if err := c.readHandshakeBytes(4 + n); err != nil {
		return nil, err
	}
	data = c.hand.Next(4 + n)
	return c.unmarshalHandshakeMessage(data, transcript)
}

func (c *Conn) unmarshalHandshakeMessage(data []byte, transcript transcriptHash) (handshakeMessage, error) {
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		if c.vers == VersionTLS13 {
			m = new(newSessionTicketMsgTLS13)
		} else {
			m = new(newSessionTicketMsg)
		}
	case typeCertificate:
		if c.vers == VersionTLS13 {
			m = new(certificateMsgTLS13)
		} else {
			m = new(certificateMsg)
		}
	case typeCertificateRequest:
		if c.vers == VersionTLS13 {
			m = new(certificateRequestMsgTLS13)
		} else {
			m = &certificateRequestMsg{
				hasSignatureAlgorithm: c.vers >= VersionTLS12,
			}
		}
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: c.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	// [uTLS] Commented typeEncryptedExtensions to force
	// utlsHandshakeMessageType to handle it
	// case typeEncryptedExtensions:
	// 	m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		// RFC 9001 Section 8.3: The TLS EndOfEarlyData message is not used with QUIC.
		// A server MUST treat receipt of this message as a connection error.
		if c.quic != nil {
			return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
		}
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		// [UTLS SECTION BEGINS]
		var err error
		m, err = c.utlsHandshakeMessageType(data[0]) // see u_conn.go
		if err == nil {
			break
		}
		// [UTLS SECTION ENDS]
		return nil, c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		// RFC 8446 Section 6: decode_error - A message could not be decoded
		// because some field was out of the specified range or the length of
		// the message was incorrect. This includes duplicate extensions, invalid
		// lengths, and malformed data structures.
		return nil, c.in.setErrorLocked(c.sendAlert(alertDecodeError))
	}

	if transcript != nil {
		transcript.Write(data)
	}

	return m, nil
}

var (
	errShutdown = utlserrors.New("tls: protocol is shutdown").AtError()
)

// Write writes data to the connection.
//
// As Write calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both [Conn.Read] and Write before Write is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *Conn) Write(b []byte) (int, error) {
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(context.Background(), "conn: Write len=", len(b))
	}
	// interlock with Close below
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)

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

	// TLS 1.0 is susceptible to a chosen-plaintext
	// attack when using block mode ciphers due to predictable IVs.
	// This can be prevented by splitting each Application Data
	// record into two records, effectively randomizing the IV.
	//
	// https://www.openssl.org/~bodo/tls-cbc.txt
	// https://bugzilla.mozilla.org/show_bug.cgi?id=665814
	// https://www.imperialviolet.org/2012/01/15/beastfollowup.html

	var m int
	if len(b) > 1 && c.vers == VersionTLS10 {
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

// handleRenegotiation processes a HelloRequest handshake message.
func (c *Conn) handleRenegotiation() error {
	if c.vers == VersionTLS13 {
		return utlserrors.New("tls: internal error: unexpected renegotiation").AtError()
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
		return utlserrors.New("tls: unknown Renegotiation value").AtError()
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	c.isHandshakeComplete.Store(false)
	if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
		c.handshakes++
	}
	return c.handshakeErr
}

// handlePostHandshakeMessage processes a handshake message arrived after the
// handshake is complete. Up to TLS 1.2, it indicates the start of a renegotiation.
func (c *Conn) handlePostHandshakeMessage() error {
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
		return c.in.setErrorLocked(utlserrors.New("tls: too many non-advancing records").AtError())
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

func (c *Conn) handleKeyUpdate(keyUpdate *keyUpdateMsg) error {
	if c.quic != nil {
		// RFC 9001, Section 6: Key updates are not used in QUIC.
		// Return the alert error so callers can properly check for it.
		return c.in.setErrorLocked(c.sendAlert(alertUnexpectedMessage))
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil {
		return c.in.setErrorLocked(c.sendAlert(alertInternalError))
	}

	newSecret, err := cipherSuite.nextTrafficSecret(c.in.trafficSecret)
	if err != nil {
		return c.in.setErrorLocked(c.sendAlert(alertInternalError))
	}
	if err := c.in.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret); err != nil {
		return c.in.setErrorLocked(c.sendAlert(alertInternalError))
	}

	if keyUpdate.updateRequested {
		c.out.Lock()
		defer c.out.Unlock()

		msg := &keyUpdateMsg{}
		msgBytes, err := msg.marshal()
		if err != nil {
			return err
		}
		_, err = c.writeRecordLocked(recordTypeHandshake, msgBytes)
		if err != nil {
			// Surface the error at the next write and return it immediately.
			// RFC 8446 Section 4.6.3: KeyUpdate failures must be reported to caller.
			c.out.setErrorLocked(err)
			return err
		}

		newSecret, err := cipherSuite.nextTrafficSecret(c.out.trafficSecret)
		if err != nil {
			c.out.setErrorLocked(err)
			return err
		}
		if err := c.out.setTrafficSecret(cipherSuite, QUICEncryptionLevelInitial, newSecret); err != nil {
			c.out.setErrorLocked(err)
			return err
		}
	}

	return nil
}

// Read reads data from the connection.
//
// As Read calls [Conn.Handshake], in order to prevent indefinite blocking a deadline
// must be set for both Read and [Conn.Write] before Read is called when the handshake
// has not yet completed. See [Conn.SetDeadline], [Conn.SetReadDeadline], and
// [Conn.SetWriteDeadline].
func (c *Conn) Read(b []byte) (int, error) {
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(context.Background(), "conn: Read bufLen=", len(b))
	}
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
			if utlserrors.DebugLoggingEnabled {
				utlserrors.LogDebug(context.Background(), "conn: Read readRecord error: ", err)
			}
			return 0, err
		}
		for c.hand.Len() > 0 {
			if err := c.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	n, _ := c.input.Read(b)
	if utlserrors.DebugLoggingEnabled {
		utlserrors.LogDebug(context.Background(), "conn: Read returned n=", n)
	}

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

// Close closes the connection.
// Per RFC 8446 Section 6, all secret material is zeroed on close to prevent
// key material from persisting in memory after the connection ends.
func (c *Conn) Close() error {
	utlserrors.LogDebug(context.Background(), "conn: Close called")
	// Interlock with Conn.Write above.
	var x int32
	for {
		x = c.activeCall.Load()
		if x&1 != 0 {
			return net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x|1) {
			break
		}
	}
	if x != 0 {
		// io.Writer and io.Closer should not be used concurrently.
		// If Close is called while a Write is currently in-flight,
		// interpret that as a sign that this Close is really just
		// being used to break the Write and/or clean up resources and
		// avoid sending the alertCloseNotify, which may block
		// waiting on handshakeMutex or the c.out mutex.
		// Still zero secrets before closing for security.
		c.zeroSecrets()
		return c.conn.Close()
	}

	var alertErr error
	if c.isHandshakeComplete.Load() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("tls: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}

	// RFC 8446 Section 6: Zero all session-specific cryptographic material.
	// This zeros traffic secrets and resumption secret to prevent key material
	// from lingering in memory after the connection is closed.
	c.zeroSecrets()

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

var errEarlyCloseWrite = utlserrors.New("tls: CloseWrite called before handshake complete").AtError()

// CloseWrite shuts down the writing side of the connection. It should only be
// called once the handshake has completed and does not call CloseWrite on the
// underlying connection. Most callers should just use [Conn.Close].
func (c *Conn) CloseWrite() error {
	if !c.isHandshakeComplete.Load() {
		return errEarlyCloseWrite
	}

	return c.closeNotify()
}

func (c *Conn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()

	if !c.closeNotifySent {
		// [uTLS] Apply close_notify jitter for fingerprint resistance.
		// Real browsers have variable timing/behavior when closing connections.
		jitterCfg := c.config.CloseNotifyJitter
		if jitterCfg != nil && jitterCfg.Enabled {
			// Check if we should skip close_notify entirely (mimics browser abrupt close)
			if jitterCfg.ShouldSkip() {
				c.closeNotifySent = true
				c.closeNotifySeq++ // Increment sequence to signal state change
				// No error - skipping is intentional behavior
				c.closeNotifyErr = nil
				return nil
			}

			// Apply random delay before sending close_notify
			if delay := jitterCfg.GetDelay(); delay > 0 {
				// Capture sequence number before releasing lock to detect ABA race.
				// If another goroutine modifies closeNotify state while we sleep,
				// the sequence will change and we'll know state was modified.
				seqBefore := c.closeNotifySeq

				// Unlock while sleeping to avoid blocking other operations
				c.out.Unlock()
				time.Sleep(delay)
				c.out.Lock()

				// Check sequence number to detect if state changed during sleep.
				// This handles the ABA problem: even if closeNotifySent is still false,
				// a sequence change indicates concurrent activity occurred.
				if c.closeNotifySeq != seqBefore || c.closeNotifySent {
					// State changed while we were sleeping; return current state.
					// Another goroutine handled (or is handling) the close_notify.
					return c.closeNotifyErr
				}
			}
		}

		// Set a Write Deadline to prevent possibly blocking forever.
		// Use configurable timeout from Config, defaulting to 5 seconds. [uTLS]
		c.SetWriteDeadline(time.Now().Add(c.config.closeNotifyTimeout()))
		c.closeNotifyErr = c.sendAlertLocked(alertCloseNotify)
		c.closeNotifySent = true
		c.closeNotifySeq++ // Increment sequence to signal state change
		// Any subsequent writes will fail.
		c.SetWriteDeadline(time.Now())
	}
	return c.closeNotifyErr
}

// Handshake runs the client or server handshake
// protocol if it has not yet been run.
//
// Most uses of this package need not call Handshake explicitly: the
// first [Conn.Read] or [Conn.Write] will call it automatically.
//
// For control over canceling or setting a timeout on a handshake, use
// [Conn.HandshakeContext] or the [Dialer]'s DialContext method instead.
//
// In order to avoid denial of service attacks, the maximum RSA key size allowed
// in certificates sent by either the TLS server or client is limited to 8192
// bits. This limit can be overridden by setting tlsmaxrsasize in the GODEBUG
// environment variable (e.g. GODEBUG=tlsmaxrsasize=4096).
func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

// HandshakeContext runs the client or server handshake
// protocol if it has not yet been run.
//
// The provided Context must be non-nil. If the context is canceled before
// the handshake is complete, the handshake is interrupted and an error is returned.
// Once the handshake has completed, cancellation of the context will not affect the
// connection.
//
// Most uses of this package need not call HandshakeContext explicitly: the
// first [Conn.Read] or [Conn.Write] will call it automatically.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	// Delegate to unexported method for named return
	// without confusing documented signature.
	return c.handshakeContext(ctx)
}

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {
	// Fast sync/atomic-based exit if there is no handshake in flight and the
	// last one succeeded without an error. Avoids the expensive context setup
	// and mutex for most Read and Write calls.
	if c.isHandshakeComplete.Load() {
		return nil
	}
	utlserrors.LogDebug(ctx, "conn: handshakeContext starting")

	handshakeCtx, cancel := context.WithCancel(ctx)
	// Note: defer this before starting the "interrupter" goroutine
	// so that we can tell the difference between the input being canceled and
	// this cancellation. In the former case, we need to close the connection.
	defer cancel()

	if c.quic != nil {
		c.quic.cancelc = handshakeCtx.Done()
		c.quic.cancel = cancel
	} else if ctx.Done() != nil {
		// Start the "interrupter" goroutine, if this context might be canceled.
		// (The background context cannot).
		//
		// The interrupter goroutine waits for the input context to be done and
		// closes the connection if this happens before the function returns.
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

	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		c.handshakes++
		utlserrors.LogDebug(ctx, "conn: handshake complete, cipher=", c.cipherSuite, " vers=", c.vers)
	} else {
		utlserrors.LogDebug(ctx, "conn: handshake failed: ", c.handshakeErr)
		// If an error occurred during the handshake try to flush the
		// alert that might be left in the buffer.
		c.flush()
	}

	if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
		c.handshakeErr = utlserrors.New("tls: internal error: handshake should have had a result").AtError()
	}
	if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
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
		// Use thread-safe channel close to prevent "send on closed channel" panic.
		// The closeChannels method uses sync.Once to ensure channels are closed
		// exactly once, even if multiple goroutines attempt to close them.
		c.quic.closeChannels()
	}

	return c.handshakeErr
}

// ConnectionState returns basic TLS details about the connection.
func (c *Conn) ConnectionState() ConnectionState {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	return c.connectionStateLocked()
}

// var tlsunsafeekm = godebug.New("tlsunsafeekm") // [uTLS] unsupportted

func (c *Conn) connectionStateLocked() ConnectionState {
	var state ConnectionState
	state.HandshakeComplete = c.isHandshakeComplete.Load()
	state.Version = c.vers
	state.NegotiatedProtocol = c.clientProtocol
	state.DidResume = c.didResume
	state.testingOnlyDidHRR = c.didHRR
	// c.curveID is not set on TLS 1.0–1.2 resumptions. Fix that before exposing it.
	state.testingOnlyCurveID = c.curveID
	state.NegotiatedProtocolIsMutual = true
	state.ServerName = c.serverName
	state.CipherSuite = c.cipherSuite
	state.PeerCertificates = c.peerCertificates
	state.VerifiedChains = c.verifiedChains
	state.SignedCertificateTimestamps = c.scts
	state.OCSPResponse = c.ocspResponse
	if (!c.didResume || c.extMasterSecret) && c.vers != VersionTLS13 {
		if c.clientFinishedIsFirst {
			state.TLSUnique = c.clientFinished[:]
		} else {
			state.TLSUnique = c.serverFinished[:]
		}
	}
	if c.config.Renegotiation != RenegotiateNever {
		state.ekm = noEKMBecauseRenegotiation
	} else if c.vers != VersionTLS13 && !c.extMasterSecret {
		state.ekm = func(label string, context []byte, length int) ([]byte, error) {
			// [uTLS SECTION START]
			// Disabling unsupported godebug package
			// if tlsunsafeekm.Value() == "1" {
			// 	tlsunsafeekm.IncNonDefault()
			// 	return c.ekm(label, context, length)
			// }
			// [uTLS SECTION END]
			return noEKMBecauseNoEMS(label, context, length)
		}
	} else {
		state.ekm = c.ekm
	}
	state.ECHAccepted = c.echAccepted
	// [UTLS SECTION START]
	c.utlsConnectionStateLocked(&state)
	// [UTLS SECTION END]
	return state
}

// OCSPResponse returns the stapled OCSP response from the TLS server, if
// any. (Only valid for client connections.)
func (c *Conn) OCSPResponse() []byte {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	return c.ocspResponse
}

// VerifyHostname checks that the peer certificate chain is valid for
// connecting to host. If so, it returns nil; if not, it returns an error
// describing the problem.
func (c *Conn) VerifyHostname(host string) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if !c.isClient {
		return utlserrors.New("tls: VerifyHostname called on TLS server connection").AtError()
	}
	if !c.isHandshakeComplete.Load() {
		return utlserrors.New("tls: handshake has not yet been performed").AtError()
	}
	if len(c.verifiedChains) == 0 {
		return utlserrors.New("tls: handshake did not verify certificate chain").AtError()
	}
	if len(c.peerCertificates) == 0 {
		return utlserrors.New("tls: no peer certificates available").AtError()
	}
	return c.peerCertificates[0].VerifyHostname(host)
}
