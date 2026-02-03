// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"container/list"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"
	_ "unsafe" // for linkname

	utlserrors "github.com/refraction-networking/utls/errors"
	"github.com/refraction-networking/utls/internal/fips140tls"
)

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)

// VersionName returns the name for the provided TLS version number
// (e.g. "TLS 1.3"), or a fallback representation of the value if the
// version is not implemented by this package.
func VersionName(version uint16) string {
	switch version {
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

const (
	maxPlaintext               = 16384        // maximum plaintext payload length
	maxCiphertext              = 16384 + 2048 // maximum ciphertext payload length
	maxCiphertextTLS13         = 16384 + 256  // maximum ciphertext length in TLS 1.3
	recordHeaderLen            = 5            // record header length
	maxHandshake               = 65536        // maximum handshake we support (protocol max is 16 MB)
	maxHandshakeCertificateMsg = 262144       // maximum certificate message size (256 KiB)
	maxUselessRecords          = 32           // maximum number of consecutive non-advancing records
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
	typeMessageHash         uint8 = 254 // synthetic message
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionMaxFragmentLength       uint16 = 1  // RFC 6066
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionStatusRequestV2         uint16 = 17
	extensionSCT                     uint16 = 18
	extensionExtendedMasterSecret    uint16 = 23
	extensionCompressCertificate     uint16 = 27 // RFC 8879
	extensionRecordSizeLimit         uint16 = 28 // RFC 8449
	extensionDelegatedCredentials    uint16 = 34
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionQUICTransportParameters uint16 = 57
	extensionRenegotiationInfo       uint16 = 0xff01
	extensionECHOuterExtensions      uint16 = 0xfd00
	extensionEncryptedClientHello    uint16 = 0xfe0d
)

// TLS signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// CurveID is the type of a TLS identifier for a key exchange mechanism. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
//
// In TLS 1.2, this registry used to support only elliptic curves. In TLS 1.3,
// it was extended to other groups and renamed NamedGroup. See RFC 8446, Section
// 4.2.7. It was then also extended to other mechanisms, such as hybrid
// post-quantum KEMs.
type CurveID uint16

const (
	CurveP256      CurveID = 23
	CurveP384      CurveID = 24
	CurveP521      CurveID = 25
	X25519         CurveID = 29
	X25519MLKEM768 CurveID = 4588

	// Post-quantum hybrid key exchange mechanisms (TLS 1.3 only)
	// These combine classical ECDHE with post-quantum ML-KEM (Kyber) for hybrid security.
	// See IANA TLS Supported Groups registry and draft-ietf-tls-ecdhe-mlkem.
	SecP256r1MLKEM768  CurveID = 4587 // P-256 + ML-KEM-768 hybrid (draft-ietf-tls-ecdhe-mlkem-03)
	SecP384r1MLKEM1024 CurveID = 4589 // P-384 + ML-KEM-1024 hybrid (draft-ietf-tls-ecdhe-mlkem-03)
)

// isTLS13OnlyKeyExchange reports whether the curve/group is only supported in TLS 1.3.
// All post-quantum hybrid key exchanges are TLS 1.3 only.
func isTLS13OnlyKeyExchange(curve CurveID) bool {
	return isPQKeyExchange(curve)
}

// isPQKeyExchange reports whether the curve/group is a post-quantum hybrid key exchange.
// These mechanisms combine classical ECDHE with post-quantum algorithms (ML-KEM/Kyber)
// for security against both classical and quantum adversaries.
//
// Supported PQ key exchanges:
//   - X25519MLKEM768 (4588): X25519 + ML-KEM-768, IETF standard
//   - X25519Kyber768Draft00 (0x6399): X25519 + Kyber768, legacy draft (Chrome 115-130)
//   - SecP256r1MLKEM768 (4587): P-256 + ML-KEM-768, IETF standard (draft-ietf-tls-ecdhe-mlkem-03)
//   - SecP384r1MLKEM1024 (4589): P-384 + ML-KEM-1024, IETF standard (draft-ietf-tls-ecdhe-mlkem-03)
func isPQKeyExchange(curve CurveID) bool {
	switch curve {
	case X25519MLKEM768, X25519Kyber768Draft00, SecP256r1MLKEM768, SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group CurveID
	data  []byte
}

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
const (
	pskModePlain uint8 = 0
	pskModeDHE   uint8 = 1
)

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
type pskIdentity struct {
	label               []byte
	obfuscatedTicketAge uint32
}

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
const (
	pointFormatUncompressed uint8 = 0
)

// TLS CertificateStatusType (RFC 3546)
const (
	statusTypeOCSP   uint8 = 1
	statusV2TypeOCSP uint8 = 2
)

// Certificate types (for certificateRequestMsg)
const (
	certTypeRSASign   = 1
	certTypeECDSASign = 64 // ECDSA or EdDSA keys, see RFC 8422, Section 3.
)

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
const (
	signaturePKCS1v15 uint8 = iota + 225
	signatureRSAPSS
	signatureECDSA
	signatureEd25519
	signatureEdDilithium3
)

// directSigning is a standard Hash value that signals that no pre-hashing
// should be performed, and that the input should be signed directly. It is the
// hash function associated with the Ed25519 signature scheme.
var directSigning crypto.Hash = 0

// helloRetryRequestRandom is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
var helloRetryRequestRandom = []byte{ // See RFC 8446, Section 4.1.3.
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

const (
	// downgradeCanaryTLS12 or downgradeCanaryTLS11 is embedded in the server
	// random as a downgrade protection if the server would be capable of
	// negotiating a higher version. See RFC 8446, Section 4.1.3.
	downgradeCanaryTLS12 = "DOWNGRD\x01"
	downgradeCanaryTLS11 = "DOWNGRD\x00"
)

// testingOnlyForceDowngradeCanary is set in tests to force the server side to
// include downgrade canaries even if it's using its highers supported version.
var testingOnlyForceDowngradeCanary bool

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	// Version is the TLS version used by the connection (e.g. VersionTLS12).
	Version uint16

	// HandshakeComplete is true if the handshake has concluded.
	HandshakeComplete bool

	// DidResume is true if this connection was successfully resumed from a
	// previous session with a session ticket or similar mechanism.
	DidResume bool

	// CipherSuite is the cipher suite negotiated for the connection (e.g.
	// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_AES_128_GCM_SHA256).
	CipherSuite uint16

	// NegotiatedProtocol is the application protocol negotiated with ALPN.
	NegotiatedProtocol string

	// NegotiatedProtocolIsMutual used to indicate a mutual NPN negotiation.
	//
	// Deprecated: this value is always true.
	NegotiatedProtocolIsMutual bool

	// PeerApplicationSettings is the Application-Layer Protocol Settings (ALPS)
	// provided by peer.
	PeerApplicationSettings []byte // [uTLS]

	// ServerName is the value of the Server Name Indication extension sent by
	// the client. It's available both on the server and on the client side.
	ServerName string

	// PeerCertificates are the parsed certificates sent by the peer, in the
	// order in which they were sent. The first element is the leaf certificate
	// that the connection is verified against.
	//
	// On the client side, it can't be empty. On the server side, it can be
	// empty if Config.ClientAuth is not RequireAnyClientCert or
	// RequireAndVerifyClientCert.
	//
	// PeerCertificates and its contents should not be modified.
	PeerCertificates []*x509.Certificate

	// VerifiedChains is a list of one or more chains where the first element is
	// PeerCertificates[0] and the last element is from Config.RootCAs (on the
	// client side) or Config.ClientCAs (on the server side).
	//
	// On the client side, it's set if Config.InsecureSkipVerify is false. On
	// the server side, it's set if Config.ClientAuth is VerifyClientCertIfGiven
	// (and the peer provided a certificate) or RequireAndVerifyClientCert.
	//
	// VerifiedChains and its contents should not be modified.
	VerifiedChains [][]*x509.Certificate

	// SignedCertificateTimestamps is a list of SCTs provided by the peer
	// through the TLS handshake for the leaf certificate, if any.
	SignedCertificateTimestamps [][]byte

	// OCSPResponse is a stapled Online Certificate Status Protocol (OCSP)
	// response provided by the peer for the leaf certificate, if any.
	OCSPResponse []byte

	// TLSUnique contains the "tls-unique" channel binding value (see RFC 5929,
	// Section 3). This value will be nil for TLS 1.3 connections and for
	// resumed connections that don't support Extended Master Secret (RFC 7627).
	TLSUnique []byte

	// ECHAccepted indicates if Encrypted Client Hello was offered by the client
	// and accepted by the server. Currently, ECH is supported only on the
	// client side.
	ECHAccepted bool

	// ekm is a closure exposed via ExportKeyingMaterial.
	ekm func(label string, context []byte, length int) ([]byte, error)

	// testingOnlyDidHRR is true if a HelloRetryRequest was sent/received.
	testingOnlyDidHRR bool

	// testingOnlyCurveID is the selected CurveID, or zero if an RSA exchanges
	// is performed.
	testingOnlyCurveID CurveID
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice as defined in RFC 5705. If context is nil, it is not used as part of
// the seed. If the connection was set to allow renegotiation via
// Config.Renegotiation, or if the connections supports neither TLS 1.3 nor
// Extended Master Secret, this function will return an error.
//
// Exporting key material without Extended Master Secret or TLS 1.3 was disabled
// in Go 1.22 due to security issues (see the Security Considerations sections
// of RFC 5705 and RFC 7627), but can be re-enabled with the GODEBUG setting
// tlsunsafeekm=1.
func (cs *ConnectionState) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	return cs.ekm(label, context, length)
}

// ClientAuthType declares the policy the server will follow for
// TLS Client Authentication.
type ClientAuthType int

const (
	// NoClientCert indicates that no client certificate should be requested
	// during the handshake, and if any certificates are sent they will not
	// be verified.
	NoClientCert ClientAuthType = iota
	// RequestClientCert indicates that a client certificate should be requested
	// during the handshake, but does not require that the client send any
	// certificates.
	RequestClientCert
	// RequireAnyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one certificate is required to be
	// sent by the client, but that certificate is not required to be valid.
	RequireAnyClientCert
	// VerifyClientCertIfGiven indicates that a client certificate should be requested
	// during the handshake, but does not require that the client sends a
	// certificate. If the client does send a certificate it is required to be
	// valid.
	VerifyClientCertIfGiven
	// RequireAndVerifyClientCert indicates that a client certificate should be requested
	// during the handshake, and that at least one valid certificate is required
	// to be sent by the client.
	RequireAndVerifyClientCert
)

// requiresClientCert reports whether the ClientAuthType requires a client
// certificate to be provided.
func requiresClientCert(c ClientAuthType) bool {
	switch c {
	case RequireAnyClientCert, RequireAndVerifyClientCert:
		return true
	default:
		return false
	}
}

// ClientSessionCache is a cache of ClientSessionState objects that can be used
// by a client to resume a TLS session with a given server. ClientSessionCache
// implementations should expect to be called concurrently from different
// goroutines. Up to TLS 1.2, only ticket-based resumption is supported, not
// SessionID-based resumption. In TLS 1.3 they were merged into PSK modes, which
// are supported via this interface.
type ClientSessionCache interface {
	// Get searches for a ClientSessionState associated with the given key.
	// On return, ok is true if one was found.
	Get(sessionKey string) (session *ClientSessionState, ok bool)

	// Put adds the ClientSessionState to the cache with the given key. It might
	// get called multiple times in a connection if a TLS 1.3 server provides
	// more than one session ticket. If called with a nil *ClientSessionState,
	// it should remove the cache entry.
	Put(sessionKey string, cs *ClientSessionState)
}

//go:generate stringer -linecomment -type=SignatureScheme,CurveID,ClientAuthType -output=common_string.go

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
type SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms.
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	// EdDSA algorithms.
	Ed25519 SignatureScheme = 0x0807

	// Legacy signature and hash algorithms for TLS 1.2.
	PKCS1WithSHA1 SignatureScheme = 0x0201
	ECDSAWithSHA1 SignatureScheme = 0x0203
)

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate and GetConfigForClient callbacks.
type ClientHelloInfo struct {
	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []uint16

	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	// SupportedCurves lists the key exchange mechanisms supported by the
	// client. It was renamed to "supported groups" in TLS 1.3, see RFC 8446,
	// Section 4.2.7 and [CurveID].
	//
	// SupportedCurves may be nil in TLS 1.2 and lower if the Supported Elliptic
	// Curves Extension is not being used (see RFC 4492, Section 5.1.1).
	SupportedCurves []CurveID

	// SupportedPoints lists the point formats supported by the client.
	// SupportedPoints is set only if the Supported Point Formats Extension
	// is being used (see RFC 4492, Section 5.1.2).
	SupportedPoints []uint8

	// SignatureSchemes lists the signature and hash schemes that the client
	// is willing to verify. SignatureSchemes is set only if the Signature
	// Algorithms Extension is being used (see RFC 5246, Section 7.4.1.4.1).
	SignatureSchemes []SignatureScheme

	// SupportedProtos lists the application protocols supported by the client.
	// SupportedProtos is set only if the Application-Layer Protocol
	// Negotiation Extension is being used (see RFC 7301, Section 3.1).
	//
	// Servers can select a protocol by setting Config.NextProtos in a
	// GetConfigForClient return value.
	SupportedProtos []string

	// SupportedVersions lists the TLS versions supported by the client.
	// For TLS versions less than 1.3, this is extrapolated from the max
	// version advertised by the client, so values other than the greatest
	// might be rejected if used.
	SupportedVersions []uint16

	// Extensions lists the IDs of the extensions presented by the client
	// in the ClientHello.
	Extensions []uint16

	// Conn is the underlying net.Conn for the connection. Do not read
	// from, or write to, this connection; that will cause the TLS
	// connection to fail.
	Conn net.Conn

	// config is embedded by the GetCertificate or GetConfigForClient caller,
	// for use with SupportsCertificate.
	config *Config

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (c *ClientHelloInfo) Context() context.Context {
	return c.ctx
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte

	// SignatureSchemes lists the signature schemes that the server is
	// willing to verify.
	SignatureSchemes []SignatureScheme

	// Version is the TLS version that was negotiated for this connection.
	Version uint16

	// ctx is the context of the handshake that is in progress.
	ctx context.Context
}

// Context returns the context of the handshake that is in progress.
// This context is a child of the context passed to HandshakeContext,
// if any, and is canceled when the handshake concludes.
func (c *CertificateRequestInfo) Context() context.Context {
	return c.ctx
}

// RenegotiationSupport enumerates the different levels of support for TLS
// renegotiation. TLS renegotiation is the act of performing subsequent
// handshakes on a connection after the first. This significantly complicates
// the state machine and has been the source of numerous, subtle security
// issues. Initiating a renegotiation is not supported, but support for
// accepting renegotiation requests may be enabled.
//
// Even when enabled, the server may not change its identity between handshakes
// (i.e. the leaf certificate must be the same). Additionally, concurrent
// handshake and application data flow is not permitted so renegotiation can
// only be used with protocols that synchronise with the renegotiation, such as
// HTTPS.
//
// Renegotiation is not defined in TLS 1.3.
type RenegotiationSupport int

const (
	// RenegotiateNever disables renegotiation.
	RenegotiateNever RenegotiationSupport = iota

	// RenegotiateOnceAsClient allows a remote server to request
	// renegotiation once per connection.
	RenegotiateOnceAsClient

	// RenegotiateFreelyAsClient allows a remote server to repeatedly
	// request renegotiation.
	RenegotiateFreelyAsClient
)

// A Config structure is used to configure a TLS client or server.
// After one has been passed to a TLS function it must not be
// modified. A Config may be reused; the tls package will also not
// modify it.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	// The Reader must be safe for use by multiple goroutines.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// Certificates contains one or more certificate chains to present to the
	// other side of the connection. The first certificate compatible with the
	// peer's requirements is selected automatically.
	//
	// Server configurations must set one of Certificates, GetCertificate or
	// GetConfigForClient. Clients doing client-authentication may set either
	// Certificates or GetClientCertificate.
	//
	// Note: if there are multiple Certificates, and they don't have the
	// optional field Leaf set, certificate selection will incur a significant
	// per-handshake performance cost.
	Certificates []Certificate

	// NameToCertificate maps from a certificate name to an element of
	// Certificates. Note that a certificate name can be of the form
	// '*.example.com' and so doesn't have to be a domain name as such.
	//
	// Deprecated: NameToCertificate only allows associating a single
	// certificate with a given name. Leave this field nil to let the library
	// select the first compatible chain from Certificates.
	NameToCertificate map[string]*Certificate

	// GetCertificate returns a Certificate based on the given
	// ClientHelloInfo. It will only be called if the client supplies SNI
	// information or if Certificates is empty.
	//
	// If GetCertificate is nil or returns nil, then the certificate is
	// retrieved from NameToCertificate. If NameToCertificate is nil, the
	// best element of Certificates will be used.
	//
	// Once a Certificate is returned it should not be modified.
	GetCertificate func(*ClientHelloInfo) (*Certificate, error)

	// GetClientCertificate, if not nil, is called when a server requests a
	// certificate from a client. If set, the contents of Certificates will
	// be ignored.
	//
	// If GetClientCertificate returns an error, the handshake will be
	// aborted and that error will be returned. Otherwise
	// GetClientCertificate must return a non-nil Certificate. If
	// Certificate.Certificate is empty then no certificate will be sent to
	// the server. If this is unacceptable to the server then it may abort
	// the handshake.
	//
	// GetClientCertificate may be called multiple times for the same
	// connection if renegotiation occurs or if TLS 1.3 is in use.
	//
	// Once a Certificate is returned it should not be modified.
	GetClientCertificate func(*CertificateRequestInfo) (*Certificate, error)

	// GetConfigForClient, if not nil, is called after a ClientHello is
	// received from a client. It may return a non-nil Config in order to
	// change the Config that will be used to handle this connection. If
	// the returned Config is nil, the original Config will be used. The
	// Config returned by this callback may not be subsequently modified.
	//
	// If GetConfigForClient is nil, the Config passed to Server() will be
	// used for all connections.
	//
	// If SessionTicketKey was explicitly set on the returned Config, or if
	// SetSessionTicketKeys was called on the returned Config, those keys will
	// be used. Otherwise, the original Config keys will be used (and possibly
	// rotated if they are automatically managed).
	GetConfigForClient func(*ClientHelloInfo) (*Config, error)

	// VerifyPeerCertificate, if not nil, is called after normal
	// certificate verification by either a TLS client or server. It
	// receives the raw ASN.1 certificates provided by the peer and also
	// any verified chains that normal processing found. If it returns a
	// non-nil error, the handshake is aborted and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. If normal verification is disabled (on the
	// client when InsecureSkipVerify is set, or on a server when ClientAuth is
	// RequestClientCert or RequireAnyClientCert), then this callback will be
	// considered but the verifiedChains argument will always be nil. When
	// ClientAuth is NoClientCert, this callback is not called on the server.
	// rawCerts may be empty on the server if ClientAuth is RequestClientCert or
	// VerifyClientCertIfGiven.
	//
	// This callback is not invoked on resumed connections, as certificates are
	// not re-verified on resumption.
	//
	// verifiedChains and its contents should not be modified.
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

	// VerifyConnection, if not nil, is called after normal certificate
	// verification and after VerifyPeerCertificate by either a TLS client
	// or server. If it returns a non-nil error, the handshake is aborted
	// and that error results.
	//
	// If normal verification fails then the handshake will abort before
	// considering this callback. This callback will run for all connections,
	// including resumptions, regardless of InsecureSkipVerify or ClientAuth
	// settings.
	VerifyConnection func(ConnectionState) error

	// RootCAs defines the set of root certificate authorities
	// that clients use when verifying server certificates.
	// If RootCAs is nil, TLS uses the host's root CA set.
	RootCAs *x509.CertPool

	// NextProtos is a list of supported application level protocols, in
	// order of preference. If both peers support ALPN, the selected
	// protocol will be one from this list, and the connection will fail
	// if there is no mutually supported protocol. If NextProtos is empty
	// or the peer doesn't support ALPN, the connection will succeed and
	// ConnectionState.NegotiatedProtocol will be empty.
	NextProtos []string

	// ApplicationSettings is a set of application settings (ALPS) to use
	// with each application protocol (ALPN).
	ApplicationSettings map[string][]byte // [uTLS]

	// ServerName is used to verify the hostname on the returned
	// certificates unless InsecureSkipVerify is given. It is also included
	// in the client's handshake to support virtual hosting unless it is
	// an IP address.
	ServerName string

	// ClientAuth determines the server's policy for
	// TLS Client Authentication. The default is NoClientCert.
	ClientAuth ClientAuthType

	// ClientCAs defines the set of root certificate authorities
	// that servers use if required to verify a client certificate
	// by the policy in ClientAuth.
	ClientCAs *x509.CertPool

	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. If InsecureSkipVerify is true, crypto/tls
	// accepts any certificate presented by the server and any host name in that
	// certificate. In this mode, TLS is susceptible to machine-in-the-middle
	// attacks unless custom verification is used. This should be used only for
	// testing or in combination with VerifyConnection or VerifyPeerCertificate.
	InsecureSkipVerify bool

	// InsecureSkipTimeVerify controls whether a client verifies the server's
	// certificate chain against time. If InsecureSkipTimeVerify is true,
	// crypto/tls accepts the certificate even when it is expired.
	//
	// This field is ignored when InsecureSkipVerify is true.
	InsecureSkipTimeVerify bool // [uTLS]

	// InsecureMaxExpiredAge is the maximum time a certificate can be expired
	// when InsecureSkipTimeVerify is true. This prevents accepting certificates
	// that expired years ago, which could indicate a stolen or compromised certificate.
	//
	// Default value (0) means 30 days maximum expired age.
	// Set to a positive duration to specify a custom maximum age.
	// Set to a negative value (e.g., -1) for unlimited age (DANGEROUS: accepts
	// any expired certificate regardless of how long ago it expired).
	//
	// This field is only used when InsecureSkipTimeVerify is true.
	// [uTLS] Security hardening for InsecureSkipTimeVerify.
	InsecureMaxExpiredAge time.Duration // [uTLS]

	// AcceptDelegatedCredentials controls whether the client will accept and
	// verify Delegated Credentials (RFC 9345) from the server. When true, if
	// the server presents a delegated credential in the Certificate message,
	// the client will:
	//   1. Verify the DC signature using the certificate's public key
	//   2. Check that the certificate has the DelegationUsage extension
	//   3. Verify the DC is within its validity period
	//   4. Use the DC's public key for CertificateVerify verification
	//
	// This enables short-lived keys while maintaining compatibility with
	// long-lived certificates. Delegated credentials are useful for:
	//   - Limiting key exposure windows
	//   - Enabling key rotation without certificate reissuance
	//   - Supporting post-quantum migration strategies
	//
	// When false (default), delegated credentials are ignored even if sent
	// by the server, and the certificate's public key is used directly.
	// The FakeDelegatedCredentialsExtension can still be used in ClientHello
	// for fingerprint purposes without actually processing server DCs.
	//
	// [uTLS] This is a uTLS extension implementing RFC 9345.
	AcceptDelegatedCredentials bool // [uTLS]

	// ServerCertCompressionAlgorithms specifies which certificate compression
	// algorithms (RFC 8879) the server supports. When a client advertises
	// compress_certificate extension with one of these algorithms, the server
	// will compress its certificate chain using the first mutually supported algorithm.
	//
	// Supported algorithms:
	//   - CertCompressionZlib (1)   - zlib/DEFLATE compression
	//   - CertCompressionBrotli (2) - Brotli compression (preferred, best ratio)
	//   - CertCompressionZstd (3)   - Zstandard compression (fast)
	//
	// The order matters: the server will use the first algorithm from this list
	// that the client also supports. For best compatibility, use:
	//   []CertCompressionAlgo{CertCompressionBrotli, CertCompressionZlib, CertCompressionZstd}
	//
	// When nil or empty (default), the server does not compress certificates.
	// [uTLS] This is a uTLS extension implementing RFC 8879.
	ServerCertCompressionAlgorithms []CertCompressionAlgo // [uTLS]

	// ServerMaxEarlyData specifies the maximum amount of 0-RTT (early data)
	// the server will accept on non-QUIC connections. When non-zero, the server
	// will advertise this value in session tickets and accept early data from
	// clients using those tickets.
	//
	// For QUIC connections, this value is ignored and 0xffffffff is used per RFC 9001.
	//
	// When zero (default), 0-RTT is disabled for non-QUIC connections.
	// Typical values: 16384 (16KB) is a safe default that covers most use cases.
	//
	// Security considerations:
	//   - 0-RTT data is replayable by network attackers
	//   - Only non-mutating, idempotent requests should be sent as 0-RTT
	//   - Applications must implement replay protection for sensitive operations
	//
	// [uTLS] This is a uTLS extension for non-QUIC 0-RTT support.
	ServerMaxEarlyData uint32 // [uTLS]

	// OmitEmptyPsk determines whether utls will automatically conceal
	// the psk extension when it is empty. When the psk extension is empty, the
	// browser omits it from the client hello. Utls can mimic this behavior,
	// but it deviates from the provided client hello specification, rendering
	// it unsuitable as the default behavior. Users have the option to enable
	// this behavior at their own discretion.
	OmitEmptyPsk bool // [uTLS]

	// InsecureServerNameToVerify is used to verify the hostname on the returned
	// certificates. It is intended to use with spoofed ServerName.
	// If InsecureServerNameToVerify is "*", crypto/tls will do normal
	// certificate validation but ignore certificate's DNSName.
	//
	// SECURITY WARNING: Setting InsecureServerNameToVerify to "*" completely
	// disables hostname verification, accepting certificates from ANY domain.
	// This makes the connection vulnerable to man-in-the-middle (MITM) attacks
	// where an attacker with any valid certificate can intercept traffic.
	// Only use "*" for testing purposes, NEVER in production environments.
	//
	// This field is ignored when InsecureSkipVerify is true.
	InsecureServerNameToVerify string // [uTLS]

	// PreferSkipResumptionOnNilExtension controls the behavior when session resumption is enabled but the corresponding session extensions are nil.
	//
	// To successfully use session resumption, ensure that the following requirements are met:
	//  - SessionTicketsDisabled is set to false
	//  - ClientSessionCache is non-nil
	//  - For TLS 1.2, SessionTicketExtension is non-nil
	//  - For TLS 1.3, PreSharedKeyExtension is non-nil
	//
	// There may be cases where users enable session resumption (SessionTicketsDisabled: false && ClientSessionCache: non-nil), but they do not provide SessionTicketExtension or PreSharedKeyExtension in the ClientHelloSpec. This could be intentional or accidental.
	//
	// By default, utls throws an exception in such scenarios. Set this to true to skip the resumption and suppress the exception.
	PreferSkipResumptionOnNilExtension bool // [uTLS]

	// PSKBinderConstantTime controls whether PSK (Pre-Shared Key) binder computation
	// uses constant-time operations to prevent timing side-channel attacks.
	//
	// When true (default), PSK binder computation:
	//   - Uses a minimum computation time floor to normalize timing
	//   - Prevents DPI systems from fingerprinting based on binder computation timing
	//   - Adds approximately 100-200 microseconds to binder computation
	//
	// When false, binder computation timing may vary based on transcript size,
	// which could leak information to network observers analyzing handshake timing.
	//
	// Security note: This is a defense-in-depth measure. The HMAC computation itself
	// is already constant-time, but the overall operation timing (including transcript
	// hashing) can vary. This option ensures consistent observable timing.
	//
	// Defaults to true for security. Set to false only if you need minimal latency
	// and are not concerned about timing side-channel attacks from DPI systems.
	PSKBinderConstantTime bool // [uTLS]

	// CipherSuites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
	// the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
	//
	// If CipherSuites is nil, a safe default list is used. The default cipher
	// suites might change over time. In Go 1.22 RSA key exchange based cipher
	// suites were removed from the default list, but can be re-added with the
	// GODEBUG setting tlsrsakex=1. In Go 1.23 3DES cipher suites were removed
	// from the default list, but can be re-added with the GODEBUG setting
	// tls3des=1.
	CipherSuites []uint16

	// PreferServerCipherSuites is a legacy field and has no effect.
	//
	// It used to control whether the server would follow the client's or the
	// server's preference. Servers now select the best mutually supported
	// cipher suite based on logic that takes into account inferred client
	// hardware, server hardware, and security.
	//
	// Deprecated: PreferServerCipherSuites is ignored.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled may be set to true to disable session ticket and
	// PSK (resumption) support. Note that on clients, session ticket support is
	// also disabled if ClientSessionCache is nil.
	SessionTicketsDisabled bool

	// SessionTicketKey is used by TLS servers to provide session resumption.
	// See RFC 5077 and the PSK mode of RFC 8446. If zero, it will be filled
	// with random data before the first server handshake.
	//
	// Deprecated: if this field is left at zero, session ticket keys will be
	// automatically rotated every day and dropped after seven days. For
	// customizing the rotation schedule or synchronizing servers that are
	// terminating connections for the same host, use SetSessionTicketKeys.
	SessionTicketKey [32]byte

	// ClientSessionCache is a cache of ClientSessionState entries for TLS
	// session resumption. It is only used by clients.
	ClientSessionCache ClientSessionCache

	// TicketAgeJitter controls jitter applied to obfuscated_ticket_age in TLS 1.3
	// session resumption. This prevents DPI from correlating sessions by observing
	// deterministic ticket age patterns.
	//
	// When nil (default), no jitter is applied (deterministic behavior for backward
	// compatibility). To enable jitter with sensible defaults, use:
	//   config.TicketAgeJitter = DefaultTicketAgeJitterConfig()
	//
	// The jitter simulates natural clock drift between client and server, which
	// typically ranges from 50-500ms in real-world conditions. This makes traffic
	// analysis more difficult without affecting TLS functionality.
	//
	// [uTLS] This is a uTLS extension for fingerprint resistance.
	TicketAgeJitter *TicketAgeJitterConfig // [uTLS]

	// UnwrapSession is called on the server to turn a ticket/identity
	// previously produced by [WrapSession] into a usable session.
	//
	// UnwrapSession will usually either decrypt a session state in the ticket
	// (for example with [Config.EncryptTicket]), or use the ticket as a handle
	// to recover a previously stored state. It must use [ParseSessionState] to
	// deserialize the session state.
	//
	// If UnwrapSession returns an error, the connection is terminated. If it
	// returns (nil, nil), the session is ignored. crypto/tls may still choose
	// not to resume the returned session.
	UnwrapSession func(identity []byte, cs ConnectionState) (*SessionState, error)

	// WrapSession is called on the server to produce a session ticket/identity.
	//
	// WrapSession must serialize the session state with [SessionState.Bytes].
	// It may then encrypt the serialized state (for example with
	// [Config.DecryptTicket]) and use it as the ticket, or store the state and
	// return a handle for it.
	//
	// If WrapSession returns an error, the connection is terminated.
	//
	// Warning: the return value will be exposed on the wire and to clients in
	// plaintext. The application is in charge of encrypting and authenticating
	// it (and rotating keys) or returning high-entropy identifiers. Failing to
	// do so correctly can compromise current, previous, and future connections
	// depending on the protocol version.
	WrapSession func(ConnectionState, *SessionState) ([]byte, error)

	// MinVersion contains the minimum TLS version that is acceptable.
	//
	// By default, TLS 1.2 is currently used as the minimum. TLS 1.0 is the
	// minimum supported by this package.
	//
	// The server-side default can be reverted to TLS 1.0 by including the value
	// "tls10server=1" in the GODEBUG environment variable.
	MinVersion uint16

	// MaxVersion contains the maximum TLS version that is acceptable.
	//
	// By default, the maximum version supported by this package is used,
	// which is currently TLS 1.3.
	MaxVersion uint16

	// CurvePreferences contains a set of supported key exchange mechanisms.
	// The name refers to elliptic curves for legacy reasons, see [CurveID].
	// The order of the list is ignored, and key exchange mechanisms are chosen
	// from this list using an internal preference order. If empty, the default
	// will be used.
	//
	// From Go 1.24, the default includes the [X25519MLKEM768] hybrid
	// post-quantum key exchange. To disable it, set CurvePreferences explicitly
	// or use the GODEBUG=tlsmlkem=0 environment variable.
	CurvePreferences []CurveID

	// PQSignatureSchemesEnabled controls whether additional post-quantum
	// signature schemes are supported for peer certificates. For available
	// signature schemes, see tls_cf.go.
	PQSignatureSchemesEnabled bool // [UTLS] ported from cloudflare/go

	// DynamicRecordSizingDisabled disables adaptive sizing of TLS records.
	// When true, the largest possible TLS record size is always used. When
	// false, the size of TLS records may be adjusted in an attempt to
	// improve latency.
	DynamicRecordSizingDisabled bool

	// RecordPadding controls TLS 1.3 record padding per RFC 8446 Section 5.4.
	// Padding zeros are added to TLS 1.3 records to resist traffic analysis
	// attacks and match real browser behavior. Padding is only applied to
	// TLS 1.3 connections.
	//
	// ENABLED BY DEFAULT: If nil (default), Chrome-like padding is used with
	// exponential distribution (lambda ~3.0):
	//   - ~70% of records: 0-72 bytes padding
	//   - ~25% of records: 72-150 bytes padding
	//   - ~5% of records: 150-255 bytes padding
	//
	// To explicitly disable padding (NOT RECOMMENDED - breaks fingerprint):
	//   config.RecordPadding = DisabledRecordPaddingConfig()
	//
	// To customize padding behavior:
	//   config.RecordPadding = &RecordPaddingConfig{
	//       Enabled: true, MinPadding: 0, MaxPadding: 255,
	//       Distribution: "chrome", Lambda: 3.0,
	//   }
	RecordPadding *RecordPaddingConfig // [uTLS]

	// Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	Renegotiation RenegotiationSupport

	// KeyLogWriter optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of KeyLogWriter compromises security and should only be
	// used for debugging.
	KeyLogWriter io.Writer

	// EncryptedClientHelloConfigList is a serialized ECHConfigList. If
	// provided, clients will attempt to connect to servers using Encrypted
	// Client Hello (ECH) using one of the provided ECHConfigs.
	//
	// Servers do not use this field. In order to configure ECH for servers, see
	// the EncryptedClientHelloKeys field.
	//
	// If the list contains no valid ECH configs, the handshake will fail
	// and return an error.
	//
	// If EncryptedClientHelloConfigList is set, MinVersion, if set, must
	// be VersionTLS13.
	//
	// When EncryptedClientHelloConfigList is set, the handshake will only
	// succeed if ECH is successfully negotiated. If the server rejects ECH,
	// an ECHRejectionError error will be returned, which may contain a new
	// ECHConfigList that the server suggests using.
	//
	// How this field is parsed may change in future Go versions, if the
	// encoding described in the final Encrypted Client Hello RFC changes.
	EncryptedClientHelloConfigList []byte

	// EncryptedClientHelloRejectionVerify, if not nil, is called when ECH is
	// rejected by the remote server, in order to verify the ECH provider
	// certificate in the outer ClientHello. If it returns a non-nil error, the
	// handshake is aborted and that error results.
	//
	// On the server side this field is not used.
	//
	// Unlike VerifyPeerCertificate and VerifyConnection, normal certificate
	// verification will not be performed before calling
	// EncryptedClientHelloRejectionVerify.
	//
	// If EncryptedClientHelloRejectionVerify is nil and ECH is rejected, the
	// roots in RootCAs will be used to verify the ECH providers public
	// certificate. VerifyPeerCertificate and VerifyConnection are not called
	// when ECH is rejected, even if set, and InsecureSkipVerify is ignored.
	EncryptedClientHelloRejectionVerify func(ConnectionState) error

	// EncryptedClientHelloKeys are the ECH keys to use when a client
	// attempts ECH.
	//
	// If EncryptedClientHelloKeys is set, MinVersion, if set, must be
	// VersionTLS13.
	//
	// If a client attempts ECH, but it is rejected by the server, the server
	// will send a list of configs to retry based on the set of
	// EncryptedClientHelloKeys which have the SendAsRetry field set.
	//
	// On the client side, this field is ignored. In order to configure ECH for
	// clients, see the EncryptedClientHelloConfigList field.
	EncryptedClientHelloKeys []EncryptedClientHelloKey

	// CloseNotifyTimeout is the timeout for sending the close_notify alert
	// during connection shutdown. If zero, defaults to 5 seconds.
	// This prevents connections from blocking indefinitely on close when
	// the peer is unresponsive.
	CloseNotifyTimeout time.Duration // [uTLS]

	// CloseNotifyJitter controls timing jitter for close_notify alerts to resist
	// TLS fingerprinting based on connection shutdown timing patterns.
	//
	// Real browsers show variable timing in sending close_notify:
	//   - Chrome sometimes skips close_notify entirely on navigation
	//   - Firefox typically sends close_notify with 0-50ms delay
	//   - Safari has intermediate behavior
	//
	// When nil (default), no jitter is applied and close_notify is sent immediately.
	// Use DefaultCloseNotifyConfig() to enable browser-like behavior.
	//
	// Example:
	//   config.CloseNotifyJitter = DefaultCloseNotifyConfig()  // Enable jitter
	//   config.CloseNotifyJitter = ChromeCloseNotifyConfig()   // Chrome-like
	//   config.CloseNotifyJitter = nil                         // Disable (default)
	CloseNotifyJitter *CloseNotifyConfig // [uTLS]

	// EnableMemoryTracking enables memory-aware connection tracking via memcontrol.
	// When true, connections are wrapped with memcontrol.Conn for memory budget
	// tracking and automatic idle connection shedding under memory pressure.
	// Configure limits via memcontrol.ConfigureMemory().
	// Default: false (no tracking overhead)
	EnableMemoryTracking bool // [uTLS]

	// RequireCT controls whether Certificate Transparency validation is required.
	// When true, the client will verify that the server's certificate has valid
	// Signed Certificate Timestamps (SCTs) from trusted CT logs. SCTs can be
	// delivered via:
	//   - TLS extension (type 18) - most common
	//   - OCSP response extension
	//   - X.509v3 certificate extension (OID 1.3.6.1.4.1.11129.2.4.2)
	//
	// If validation fails (no valid SCTs from trusted logs), the handshake is
	// aborted with alertBadCertificate.
	//
	// Default: false (CT validation disabled for backward compatibility)
	//
	// [uTLS] This is a uTLS extension implementing RFC 6962 CT validation.
	RequireCT bool // [uTLS]

	// CTLogs specifies custom CT logs to use for SCT validation. The map key is
	// the log ID (SHA-256 hash of the log's SubjectPublicKeyInfo).
	//
	// If nil, DefaultCTLogs is used which contains well-known public CT logs
	// from Google, Cloudflare, DigiCert, Let's Encrypt, Sectigo, and others.
	//
	// To add custom logs while keeping the defaults, create a new map and copy:
	//   logs := make(map[[32]byte]*CTLogInfo)
	//   for k, v := range DefaultCTLogs { logs[k] = v }
	//   logs[customLogID] = &CTLogInfo{...}
	//   config.CTLogs = logs
	//
	// [uTLS] This is a uTLS extension implementing RFC 6962 CT validation.
	CTLogs map[[32]byte]*CTLogInfo // [uTLS]

	// mutex protects sessionTicketKeys and autoSessionTicketKeys.
	mutex sync.RWMutex
	// sessionTicketKeys contains zero or more ticket keys. If set, it means
	// the keys were set with SessionTicketKey or SetSessionTicketKeys. The
	// first key is used for new tickets and any subsequent keys can be used to
	// decrypt old tickets. The slice contents are not protected by the mutex
	// and are immutable.
	sessionTicketKeys []ticketKey
	// autoSessionTicketKeys is like sessionTicketKeys but is owned by the
	// auto-rotation logic. See Config.ticketKeys.
	autoSessionTicketKeys []ticketKey
}

// EncryptedClientHelloKey holds a private key that is associated
// with a specific ECH config known to a client.
type EncryptedClientHelloKey struct {
	// Config should be a marshalled ECHConfig associated with PrivateKey. This
	// must match the config provided to clients byte-for-byte. The config
	// should only specify the DHKEM(X25519, HKDF-SHA256) KEM ID (0x0020), the
	// HKDF-SHA256 KDF ID (0x0001), and a subset of the following AEAD IDs:
	// AES-128-GCM (0x0000), AES-256-GCM (0x0001), ChaCha20Poly1305 (0x0002).
	Config []byte
	// PrivateKey should be a marshalled private key. Currently, we expect
	// this to be the output of [ecdh.PrivateKey.Bytes].
	PrivateKey []byte
	// SendAsRetry indicates if Config should be sent as part of the list of
	// retry configs when ECH is requested by the client but rejected by the
	// server.
	SendAsRetry bool
}

const (
	// ticketKeyLifetime is how long a ticket key remains valid and can be used to
	// resume a client connection.
	ticketKeyLifetime = 7 * 24 * time.Hour // 7 days

	// ticketKeyRotation is how often the server should rotate the session ticket key
	// that is used for new tickets.
	ticketKeyRotation = 24 * time.Hour

	// defaultCloseNotifyTimeout is the default timeout for sending the close_notify
	// alert during connection shutdown if Config.CloseNotifyTimeout is not set.
	defaultCloseNotifyTimeout = 5 * time.Second // [uTLS]
)

// ticketKey is the internal representation of a session ticket key.
type ticketKey struct {
	aesKey  [16]byte
	hmacKey [16]byte
	// created is the time at which this ticket key was created. See Config.ticketKeys.
	created time.Time
}

// ticketKeyFromBytes converts from the external representation of a session
// ticket key to a ticketKey. Externally, session ticket keys are 32 random
// bytes and this function expands that into sufficient name and key material.
func (c *Config) ticketKeyFromBytes(b [32]byte) (key ticketKey) {
	hashed := sha512.Sum512(b[:])
	// The first 16 bytes of the hash used to be exposed on the wire as a ticket
	// prefix. They MUST NOT be used as a secret. In the future, it would make
	// sense to use a proper KDF here, like HKDF with a fixed salt.
	const legacyTicketKeyNameLen = 16
	copy(key.aesKey[:], hashed[legacyTicketKeyNameLen:])
	copy(key.hmacKey[:], hashed[legacyTicketKeyNameLen+len(key.aesKey):])
	key.created = c.time()
	return key
}

// maxSessionTicketLifetime is the maximum allowed lifetime of a TLS 1.3 session
// ticket, and the lifetime we set for all tickets we send.
const maxSessionTicketLifetime = 7 * 24 * time.Hour

// Clone returns a clone of c or nil if c is nil. It is safe to clone a [Config] that is
// being used concurrently by a TLS client or server. Slice fields are deep copied to prevent
// race conditions from modifications to the original affecting the clone.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	utlserrors.LogDebug(context.Background(), "config: cloning Config, ServerName=", c.ServerName, " MinVersion=", c.MinVersion, " MaxVersion=", c.MaxVersion)

	// Deep copy NameToCertificate map to prevent shared state
	var nameToCert map[string]*Certificate
	if c.NameToCertificate != nil {
		nameToCert = make(map[string]*Certificate, len(c.NameToCertificate))
		for k, v := range c.NameToCertificate {
			nameToCert[k] = v
		}
	}

	// Deep copy ApplicationSettings map including byte slice values
	var appSettings map[string][]byte
	if c.ApplicationSettings != nil {
		appSettings = make(map[string][]byte, len(c.ApplicationSettings))
		for k, v := range c.ApplicationSettings {
			appSettings[k] = append([]byte(nil), v...)
		}
	}

	// Deep copy all slice fields to prevent race conditions from shared backing arrays
	var certificates []Certificate
	if c.Certificates != nil {
		certificates = make([]Certificate, len(c.Certificates))
		copy(certificates, c.Certificates)
	}

	var nextProtos []string
	if c.NextProtos != nil {
		nextProtos = make([]string, len(c.NextProtos))
		copy(nextProtos, c.NextProtos)
	}

	var cipherSuites []uint16
	if c.CipherSuites != nil {
		cipherSuites = make([]uint16, len(c.CipherSuites))
		copy(cipherSuites, c.CipherSuites)
	}

	var curvePreferences []CurveID
	if c.CurvePreferences != nil {
		curvePreferences = make([]CurveID, len(c.CurvePreferences))
		copy(curvePreferences, c.CurvePreferences)
	}

	var echConfigList []byte
	if c.EncryptedClientHelloConfigList != nil {
		echConfigList = make([]byte, len(c.EncryptedClientHelloConfigList))
		copy(echConfigList, c.EncryptedClientHelloConfigList)
	}

	// Deep copy EncryptedClientHelloKeys including nested byte slices
	var echKeys []EncryptedClientHelloKey
	if c.EncryptedClientHelloKeys != nil {
		echKeys = make([]EncryptedClientHelloKey, len(c.EncryptedClientHelloKeys))
		for i, key := range c.EncryptedClientHelloKeys {
			echKeys[i] = EncryptedClientHelloKey{
				Config:      append([]byte(nil), key.Config...),
				PrivateKey:  append([]byte(nil), key.PrivateKey...),
				SendAsRetry: key.SendAsRetry,
			}
		}
	}

	// Deep copy internal ticket key slices
	var sessionKeys []ticketKey
	if c.sessionTicketKeys != nil {
		sessionKeys = make([]ticketKey, len(c.sessionTicketKeys))
		copy(sessionKeys, c.sessionTicketKeys)
	}

	var autoSessionKeys []ticketKey
	if c.autoSessionTicketKeys != nil {
		autoSessionKeys = make([]ticketKey, len(c.autoSessionTicketKeys))
		copy(autoSessionKeys, c.autoSessionTicketKeys)
	}

	// Deep copy ServerCertCompressionAlgorithms slice [uTLS]
	var serverCertCompAlgos []CertCompressionAlgo
	if c.ServerCertCompressionAlgorithms != nil {
		serverCertCompAlgos = make([]CertCompressionAlgo, len(c.ServerCertCompressionAlgorithms))
		copy(serverCertCompAlgos, c.ServerCertCompressionAlgorithms)
	}

	return &Config{
		Rand:                                c.Rand,
		Time:                                c.Time,
		Certificates:                        certificates,
		NameToCertificate:                   nameToCert,
		GetCertificate:                      c.GetCertificate,
		GetClientCertificate:                c.GetClientCertificate,
		GetConfigForClient:                  c.GetConfigForClient,
		VerifyPeerCertificate:               c.VerifyPeerCertificate,
		VerifyConnection:                    c.VerifyConnection,
		RootCAs:                             c.RootCAs,
		NextProtos:                          nextProtos,
		ApplicationSettings:                 appSettings,
		ServerName:                          c.ServerName,
		ClientAuth:                          c.ClientAuth,
		ClientCAs:                           c.ClientCAs,
		InsecureSkipVerify:                  c.InsecureSkipVerify,
		InsecureSkipTimeVerify:              c.InsecureSkipTimeVerify,
		InsecureMaxExpiredAge:               c.InsecureMaxExpiredAge, // [uTLS]
		AcceptDelegatedCredentials:          c.AcceptDelegatedCredentials, // [uTLS]
		InsecureServerNameToVerify:          c.InsecureServerNameToVerify,
		OmitEmptyPsk:                        c.OmitEmptyPsk,
		CipherSuites:                        cipherSuites,
		PreferServerCipherSuites:            c.PreferServerCipherSuites,
		SessionTicketsDisabled:              c.SessionTicketsDisabled,
		SessionTicketKey:                    c.SessionTicketKey,
		ClientSessionCache:                  c.ClientSessionCache,
		TicketAgeJitter:                     c.TicketAgeJitter, // [uTLS]
		UnwrapSession:                       c.UnwrapSession,
		WrapSession:                         c.WrapSession,
		MinVersion:                          c.MinVersion,
		MaxVersion:                          c.MaxVersion,
		CurvePreferences:                    curvePreferences,
		PQSignatureSchemesEnabled:           c.PQSignatureSchemesEnabled, // [UTLS]
		DynamicRecordSizingDisabled:         c.DynamicRecordSizingDisabled,
		RecordPadding:                       c.RecordPadding, // [uTLS]
		Renegotiation:                       c.Renegotiation,
		KeyLogWriter:                        c.KeyLogWriter,
		EncryptedClientHelloConfigList:      echConfigList,
		EncryptedClientHelloRejectionVerify: c.EncryptedClientHelloRejectionVerify,
		EncryptedClientHelloKeys:            echKeys,
		CloseNotifyTimeout:                  c.CloseNotifyTimeout,   // [uTLS]
		CloseNotifyJitter:                   c.CloseNotifyJitter,    // [uTLS]
		EnableMemoryTracking:                c.EnableMemoryTracking, // [uTLS]
		RequireCT:                           c.RequireCT,            // [uTLS]
		CTLogs:                              c.CTLogs,               // [uTLS] shallow copy is fine, logs don't change
		sessionTicketKeys:                   sessionKeys,
		autoSessionTicketKeys:               autoSessionKeys,

		PreferSkipResumptionOnNilExtension:  c.PreferSkipResumptionOnNilExtension,  // [UTLS]
		PSKBinderConstantTime:               c.PSKBinderConstantTime,               // [uTLS]
		ServerCertCompressionAlgorithms:     serverCertCompAlgos,                   // [uTLS]
		ServerMaxEarlyData:                  c.ServerMaxEarlyData,                  // [uTLS]
	}
}

// deprecatedSessionTicketKey is set as the prefix of SessionTicketKey if it was
// randomized for backwards compatibility but is not in use.
var deprecatedSessionTicketKey = []byte("DEPRECATED")

// initLegacySessionTicketKeyRLocked ensures the legacy SessionTicketKey field is
// randomized if empty, and that sessionTicketKeys is populated from it otherwise.
// Returns an error if random number generation fails.
func (c *Config) initLegacySessionTicketKeyRLocked() error {
	// Don't write if SessionTicketKey is already defined as our deprecated string,
	// or if it is defined by the user but sessionTicketKeys is already set.
	if c.SessionTicketKey != [32]byte{} &&
		(bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) || len(c.sessionTicketKeys) > 0) {
		return nil
	}

	// We need to write some data, so get an exclusive lock and re-check any conditions.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.SessionTicketKey == [32]byte{} {
		if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
			return fmt.Errorf("tls: unable to generate random session ticket key: %w", err)
		}
		// Write the deprecated prefix at the beginning so we know we created
		// it. This key with the DEPRECATED prefix isn't used as an actual
		// session ticket key, and is only randomized in case the application
		// reuses it for some reason.
		copy(c.SessionTicketKey[:], deprecatedSessionTicketKey)
	} else if !bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) && len(c.sessionTicketKeys) == 0 {
		c.sessionTicketKeys = []ticketKey{c.ticketKeyFromBytes(c.SessionTicketKey)}
	}

	return nil
}

// ticketKeys returns the ticketKeys for this connection.
// If configForClient has explicitly set keys, those will
// be returned. Otherwise, the keys on c will be used and
// may be rotated if auto-managed.
// During rotation, any expired session ticket keys are deleted from
// c.sessionTicketKeys. If the session ticket key that is currently
// encrypting tickets (ie. the first ticketKey in c.sessionTicketKeys)
// is not fresh, then a new session ticket key will be
// created and prepended to c.sessionTicketKeys.
// Returns an error if random number generation fails during key rotation.
func (c *Config) ticketKeys(configForClient *Config) ([]ticketKey, error) {
	// If the ConfigForClient callback returned a Config with explicitly set
	// keys, use those, otherwise just use the original Config.
	if configForClient != nil {
		configForClient.mutex.RLock()
		if configForClient.SessionTicketsDisabled {
			configForClient.mutex.RUnlock()
			return nil, nil
		}
		if err := configForClient.initLegacySessionTicketKeyRLocked(); err != nil {
			configForClient.mutex.RUnlock()
			return nil, err
		}
		if len(configForClient.sessionTicketKeys) != 0 {
			ret := configForClient.sessionTicketKeys
			configForClient.mutex.RUnlock()
			return ret, nil
		}
		configForClient.mutex.RUnlock()
	}

	c.mutex.RLock()
	defer c.mutex.RUnlock()
	if c.SessionTicketsDisabled {
		return nil, nil
	}
	if err := c.initLegacySessionTicketKeyRLocked(); err != nil {
		return nil, err
	}
	if len(c.sessionTicketKeys) != 0 {
		return c.sessionTicketKeys, nil
	}
	// Fast path for the common case where the key is fresh enough.
	if len(c.autoSessionTicketKeys) > 0 && c.time().Sub(c.autoSessionTicketKeys[0].created) < ticketKeyRotation {
		return c.autoSessionTicketKeys, nil
	}

	// autoSessionTicketKeys are managed by auto-rotation.
	c.mutex.RUnlock()
	defer c.mutex.RLock()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// Re-check the condition in case it changed since obtaining the new lock.
	if len(c.autoSessionTicketKeys) == 0 || c.time().Sub(c.autoSessionTicketKeys[0].created) >= ticketKeyRotation {
		var newKey [32]byte
		if _, err := io.ReadFull(c.rand(), newKey[:]); err != nil {
			return nil, fmt.Errorf("tls: unable to generate random session ticket key: %w", err)
		}
		valid := make([]ticketKey, 0, len(c.autoSessionTicketKeys)+1)
		valid = append(valid, c.ticketKeyFromBytes(newKey))
		for _, k := range c.autoSessionTicketKeys {
			// While rotating the current key, also remove any expired ones.
			if c.time().Sub(k.created) < ticketKeyLifetime {
				valid = append(valid, k)
			}
		}
		c.autoSessionTicketKeys = valid
	}
	return c.autoSessionTicketKeys, nil
}

// SetSessionTicketKeys updates the session ticket keys for a server.
//
// The first key will be used when creating new tickets, while all keys can be
// used for decrypting tickets. It is safe to call this function while the
// server is running in order to rotate the session ticket keys. The function
// returns an error if keys is empty.
//
// Calling this function will turn off automatic session ticket key rotation.
//
// If multiple servers are terminating connections for the same host they should
// all have the same session ticket keys. If the session ticket keys leaks,
// previously recorded and future TLS connections using those keys might be
// compromised.
func (c *Config) SetSessionTicketKeys(keys [][32]byte) error {
	if len(keys) == 0 {
		return utlserrors.New("tls: keys must have at least one key").AtError()
	}

	newKeys := make([]ticketKey, len(keys))
	for i, bytes := range keys {
		newKeys[i] = c.ticketKeyFromBytes(bytes)
	}

	c.mutex.Lock()
	c.sessionTicketKeys = newKeys
	c.mutex.Unlock()
	return nil
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

// closeNotifyTimeout returns the configured close notify timeout,
// or the default of 5 seconds if not set. [uTLS]
func (c *Config) closeNotifyTimeout() time.Duration {
	if c.CloseNotifyTimeout > 0 {
		return c.CloseNotifyTimeout
	}
	return defaultCloseNotifyTimeout
}

func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites == nil {
		// [uTLS] SECTION BEGIN
		// if fips140tls.Required() {
		// 	return defaultCipherSuitesFIPS
		// }
		// [uTLS] SECTION END
		suites := defaultCipherSuites()
		utlserrors.LogDebug(context.Background(), "config: using default cipherSuites count=", len(suites))
		return suites
	}
	utlserrors.LogDebug(context.Background(), "config: using custom cipherSuites count=", len(c.CipherSuites))
	// [uTLS] SECTION BEGIN
	// if fips140tls.Required() {
	// 	cipherSuites := slices.Clone(c.CipherSuites)
	// 	return slices.DeleteFunc(cipherSuites, func(id uint16) bool {
	// 		return !slices.Contains(defaultCipherSuitesFIPS, id)
	// 	})
	// }
	// [uTLS] SECTION END
	return c.CipherSuites
}

var supportedVersions = []uint16{
	VersionTLS13,
	VersionTLS12,
	VersionTLS11,
	VersionTLS10,
}

// roleClient and roleServer are meant to call supportedVersions and parents
// with more readability at the callsite.
const roleClient = true
const roleServer = false

// var tls10server = godebug.New("tls10server") // [UTLS] unsupported

func (c *Config) supportedVersions(isClient bool) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		// [uTLS] SECTION BEGIN
		// if fips140tls.Required() && !slices.Contains(defaultSupportedVersionsFIPS, v) {
		// 	continue
		// }
		// [uTLS] SECTION END
		if (c == nil || c.MinVersion == 0) && v < VersionTLS12 {
			// [uTLS SECTION BEGIN]
			// Disable unsupported godebug package
			// if isClient || tls10server.Value() != "1" {
			// 	continue
			// }
			if isClient {
				continue
			}
			// [uTLS SECTION END]
		}
		if isClient && c.EncryptedClientHelloConfigList != nil && v < VersionTLS13 {
			continue
		}
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}
	utlserrors.LogDebug(context.Background(), "config: supportedVersions isClient=", isClient, " versions=", versions)
	return versions
}

func (c *Config) maxSupportedVersion(isClient bool) uint16 {
	supportedVersions := c.supportedVersions(isClient)
	if len(supportedVersions) == 0 {
		return 0
	}
	return supportedVersions[0]
}

// supportedVersionsFromMax returns a list of supported versions derived from a
// legacy maximum version value. Note that only versions supported by this
// library are returned. Any newer peer will use supportedVersions anyway.
func supportedVersionsFromMax(maxVersion uint16) []uint16 {
	versions := make([]uint16, 0, len(supportedVersions))
	for _, v := range supportedVersions {
		if v > maxVersion {
			continue
		}
		versions = append(versions, v)
	}
	return versions
}

func (c *Config) curvePreferences(version uint16) []CurveID {
	var curvePreferences []CurveID
	// [uTLS] SECTION BEGIN
	// if fips140tls.Required() {
	// 	curvePreferences = slices.Clone(defaultCurvePreferencesFIPS)
	// } else {
	curvePreferences = defaultCurvePreferences()
	// }
	// [uTLS] SECTION END
	if c != nil && len(c.CurvePreferences) != 0 {
		curvePreferences = slices.DeleteFunc(curvePreferences, func(x CurveID) bool {
			return !slices.Contains(c.CurvePreferences, x)
		})
	}
	if version < VersionTLS13 {
		curvePreferences = slices.DeleteFunc(curvePreferences, isTLS13OnlyKeyExchange)
	}
	utlserrors.LogDebug(context.Background(), "config: curvePreferences version=", version, " curves=", curvePreferences)
	return curvePreferences
}

func (c *Config) supportsCurve(version uint16, curve CurveID) bool {
	for _, cc := range c.curvePreferences(version) {
		if cc == curve {
			return true
		}
	}
	return false
}

// mutualVersion returns the protocol version to use given the advertised
// versions of the peer. Priority is given to the peer preference order.
func (c *Config) mutualVersion(isClient bool, peerVersions []uint16) (uint16, bool) {
	supportedVersions := c.supportedVersions(isClient)
	for _, peerVersion := range peerVersions {
		for _, v := range supportedVersions {
			if v == peerVersion {
				utlserrors.LogDebug(context.Background(), "config: mutualVersion selected=", v, " peerVersions=", peerVersions)
				return v, true
			}
		}
	}
	utlserrors.LogDebug(context.Background(), "config: mutualVersion no common version, peer=", peerVersions, " supported=", supportedVersions)
	return 0, false
}

// errNoCertificates should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/xtls/xray-core
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname errNoCertificates
var errNoCertificates = utlserrors.New("tls: no certificates configured").AtError()

// getCertificate returns the best certificate for the given ClientHelloInfo,
// defaulting to the first element of c.Certificates.
func (c *Config) getCertificate(clientHello *ClientHelloInfo) (*Certificate, error) {
	utlserrors.LogDebug(context.Background(), "config: getCertificate for ServerName=", clientHello.ServerName, " certCount=", len(c.Certificates))
	if c.GetCertificate != nil &&
		(len(c.Certificates) == 0 || len(clientHello.ServerName) > 0) {
		cert, err := c.GetCertificate(clientHello)
		if cert != nil || err != nil {
			utlserrors.LogDebug(context.Background(), "config: getCertificate callback returned cert=", cert != nil, " err=", err)
			return cert, err
		}
	}

	if len(c.Certificates) == 0 {
		utlserrors.LogDebug(context.Background(), "config: getCertificate no certificates configured")
		return nil, errNoCertificates
	}

	if len(c.Certificates) == 1 {
		// There's only one choice, so no point doing any work.
		utlserrors.LogDebug(context.Background(), "config: getCertificate using single certificate")
		return &c.Certificates[0], nil
	}

	if c.NameToCertificate != nil {
		name := strings.ToLower(clientHello.ServerName)
		if cert, ok := c.NameToCertificate[name]; ok {
			return cert, nil
		}
		if len(name) > 0 {
			labels := strings.Split(name, ".")
			if len(labels) > 0 {
				labels[0] = "*"
				wildcardName := strings.Join(labels, ".")
				if cert, ok := c.NameToCertificate[wildcardName]; ok {
					return cert, nil
				}
			}
		}
	}

	for _, cert := range c.Certificates {
		if err := clientHello.SupportsCertificate(&cert); err == nil {
			return &cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &c.Certificates[0], nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the client that sent the ClientHello. Otherwise, it returns an error
// describing the reason for the incompatibility.
//
// If this [ClientHelloInfo] was passed to a GetConfigForClient or GetCertificate
// callback, this method will take into account the associated [Config]. Note that
// if GetConfigForClient returns a different [Config], the change can't be
// accounted for by this method.
//
// This function will call x509.ParseCertificate unless c.Leaf is set, which can
// incur a significant performance cost.
func (chi *ClientHelloInfo) SupportsCertificate(c *Certificate) error {
	// Note we don't currently support certificate_authorities nor
	// signature_algorithms_cert, and don't check the algorithms of the
	// signatures on the chain (which anyway are a SHOULD, see RFC 8446,
	// Section 4.4.2.2).

	config := chi.config
	if config == nil {
		config = &Config{}
	}
	vers, ok := config.mutualVersion(roleServer, chi.SupportedVersions)
	if !ok {
		return utlserrors.New("no mutually supported protocol versions").AtError()
	}

	// If the client specified the name they are trying to connect to, the
	// certificate needs to be valid for it.
	if chi.ServerName != "" {
		x509Cert, err := c.leaf()
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		if err := x509Cert.VerifyHostname(chi.ServerName); err != nil {
			return fmt.Errorf("certificate is not valid for requested server name: %w", err)
		}
	}

	// supportsRSAFallback returns nil if the certificate and connection support
	// the static RSA key exchange, and unsupported otherwise. The logic for
	// supporting static RSA is completely disjoint from the logic for
	// supporting signed key exchanges, so we just check it as a fallback.
	supportsRSAFallback := func(unsupported error) error {
		// TLS 1.3 dropped support for the static RSA key exchange.
		if vers == VersionTLS13 {
			return unsupported
		}
		// The static RSA key exchange works by decrypting a challenge with the
		// RSA private key, not by signing, so check the PrivateKey implements
		// crypto.Decrypter, like *rsa.PrivateKey does.
		if priv, ok := c.PrivateKey.(crypto.Decrypter); ok {
			if _, ok := priv.Public().(*rsa.PublicKey); !ok {
				return unsupported
			}
		} else {
			return unsupported
		}
		// Finally, there needs to be a mutual cipher suite that uses the static
		// RSA key exchange instead of ECDHE.
		rsaCipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
			if c.flags&suiteECDHE != 0 {
				return false
			}
			if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
				return false
			}
			return true
		})
		if rsaCipherSuite == nil {
			return unsupported
		}
		return nil
	}

	// If the client sent the signature_algorithms extension, ensure it supports
	// schemes we can use with this certificate and TLS version.
	if len(chi.SignatureSchemes) > 0 {
		if _, err := selectSignatureScheme(vers, c, chi.SignatureSchemes); err != nil {
			return supportsRSAFallback(err)
		}
	}

	// In TLS 1.3 we are done because supported_groups is only relevant to the
	// ECDHE computation, point format negotiation is removed, cipher suites are
	// only relevant to the AEAD choice, and static RSA does not exist.
	if vers == VersionTLS13 {
		return nil
	}

	// The only signed key exchange we support is ECDHE.
	if !supportsECDHE(config, vers, chi.SupportedCurves, chi.SupportedPoints) {
		return supportsRSAFallback(utlserrors.New("client doesn't support ECDHE, can only use legacy RSA key exchange").AtWarning())
	}

	var ecdsaCipherSuite bool
	if priv, ok := c.PrivateKey.(crypto.Signer); ok {
		switch pub := priv.Public().(type) {
		case *ecdsa.PublicKey:
			var curve CurveID
			switch pub.Curve {
			case elliptic.P256():
				curve = CurveP256
			case elliptic.P384():
				curve = CurveP384
			case elliptic.P521():
				curve = CurveP521
			default:
				return supportsRSAFallback(unsupportedCertificateError(c))
			}
			var curveOk bool
			for _, c := range chi.SupportedCurves {
				if c == curve && config.supportsCurve(vers, c) {
					curveOk = true
					break
				}
			}
			if !curveOk {
				return utlserrors.New("client doesn't support certificate curve").AtError()
			}
			ecdsaCipherSuite = true
		case ed25519.PublicKey:
			if vers < VersionTLS12 || len(chi.SignatureSchemes) == 0 {
				return utlserrors.New("connection doesn't support Ed25519").AtError()
			}
			ecdsaCipherSuite = true
		case *rsa.PublicKey:
		default:
			return supportsRSAFallback(unsupportedCertificateError(c))
		}
	} else {
		return supportsRSAFallback(unsupportedCertificateError(c))
	}

	// Make sure that there is a mutually supported cipher suite that works with
	// this certificate. Cipher suite selection will then apply the logic in
	// reverse to pick it. See also serverHandshakeState.cipherSuiteOk.
	cipherSuite := selectCipherSuite(chi.CipherSuites, config.cipherSuites(), func(c *cipherSuite) bool {
		if c.flags&suiteECDHE == 0 {
			return false
		}
		if c.flags&suiteECSign != 0 {
			if !ecdsaCipherSuite {
				return false
			}
		} else {
			if ecdsaCipherSuite {
				return false
			}
		}
		if vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
			return false
		}
		return true
	})
	if cipherSuite == nil {
		return supportsRSAFallback(utlserrors.New("client doesn't support any cipher suites compatible with the certificate").AtWarning())
	}

	return nil
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the server that sent the CertificateRequest. Otherwise, it returns an error
// describing the reason for the incompatibility.
func (cri *CertificateRequestInfo) SupportsCertificate(c *Certificate) error {
	if _, err := selectSignatureScheme(cri.Version, c, cri.SignatureSchemes); err != nil {
		return err
	}

	if len(cri.AcceptableCAs) == 0 {
		return nil
	}

	for j, cert := range c.Certificate {
		x509Cert := c.Leaf
		// Parse the certificate if this isn't the leaf node, or if
		// chain.Leaf was nil.
		if j != 0 || x509Cert == nil {
			var err error
			if x509Cert, err = x509.ParseCertificate(cert); err != nil {
				return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err)
			}
		}

		for _, ca := range cri.AcceptableCAs {
			if bytes.Equal(x509Cert.RawIssuer, ca) {
				return nil
			}
		}
	}
	return utlserrors.New("chain is not signed by an acceptable CA").AtError()
}

// BuildNameToCertificate parses c.Certificates and builds c.NameToCertificate
// from the CommonName and SubjectAlternateName fields of each of the leaf
// certificates.
//
// Deprecated: NameToCertificate only allows associating a single certificate
// with a given name. Leave that field nil to let the library select the first
// compatible chain from Certificates.
func (c *Config) BuildNameToCertificate() {
	if c == nil {
		return
	}
	c.NameToCertificate = make(map[string]*Certificate)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		x509Cert, err := cert.leaf()
		if err != nil {
			continue
		}
		// If SANs are *not* present, some clients will consider the certificate
		// valid for the name in the Common Name.
		if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
			c.NameToCertificate[x509Cert.Subject.CommonName] = cert
		}
		for _, san := range x509Cert.DNSNames {
			c.NameToCertificate[san] = cert
		}
	}
}

const (
	keyLogLabelTLS12              = "CLIENT_RANDOM"
	keyLogLabelClientHandshake    = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelServerHandshake    = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	keyLogLabelClientTraffic      = "CLIENT_TRAFFIC_SECRET_0"
	keyLogLabelServerTraffic      = "SERVER_TRAFFIC_SECRET_0"
	keyLogLabelClientEarlyTraffic = "CLIENT_EARLY_TRAFFIC_SECRET" // [uTLS] 0-RTT early data
)

func (c *Config) writeKeyLog(label string, clientRandom, secret []byte) error {
	if c.KeyLogWriter == nil {
		return nil
	}

	logLine := fmt.Appendf(nil, "%s %x %x\n", label, clientRandom, secret)

	writerMutex.Lock()
	_, err := c.KeyLogWriter.Write(logLine)
	writerMutex.Unlock()

	return err
}

// writerMutex protects all KeyLogWriters globally. It is rarely enabled,
// and is only for debugging, so a global mutex saves space.
var writerMutex sync.Mutex

// A Certificate is a chain of one or more certificates, leaf first.
type Certificate struct {
	Certificate [][]byte
	// PrivateKey contains the private key corresponding to the public key in
	// Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
	// For a server up to TLS 1.2, it can also implement crypto.Decrypter with
	// an RSA PublicKey.
	PrivateKey crypto.PrivateKey
	// SupportedSignatureAlgorithms is an optional list restricting what
	// signature algorithms the PrivateKey can be used for.
	SupportedSignatureAlgorithms []SignatureScheme
	// OCSPStaple contains an optional OCSP response which will be served
	// to clients that request it.
	OCSPStaple []byte
	// SignedCertificateTimestamps contains an optional list of Signed
	// Certificate Timestamps which will be served to clients that request it.
	SignedCertificateTimestamps [][]byte
	// Leaf is the parsed form of the leaf certificate, which may be initialized
	// using x509.ParseCertificate to reduce per-handshake processing. If nil,
	// the leaf certificate will be parsed as needed.
	Leaf *x509.Certificate
}

// leaf returns the parsed leaf certificate, either from c.Leaf or by parsing
// the corresponding c.Certificate[0].
func (c *Certificate) leaf() (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	return x509.ParseCertificate(c.Certificate[0])
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}

type handshakeMessageWithOriginalBytes interface {
	handshakeMessage

	// originalBytes should return the original bytes that were passed to
	// unmarshal to create the message. If the message was not produced by
	// unmarshal, it should return nil.
	originalBytes() []byte
}

// lruSessionCache is a ClientSessionCache implementation that uses an LRU
// caching strategy.
type lruSessionCache struct {
	sync.Mutex

	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type lruSessionCacheEntry struct {
	sessionKey string
	state      *ClientSessionState
}

// NewLRUClientSessionCache returns a [ClientSessionCache] with the given
// capacity that uses an LRU strategy. If capacity is < 1, a default capacity
// is used instead.
func NewLRUClientSessionCache(capacity int) ClientSessionCache {
	const defaultSessionCacheCapacity = 64

	if capacity < 1 {
		capacity = defaultSessionCacheCapacity
	}
	return &lruSessionCache{
		m:        make(map[string]*list.Element),
		q:        list.New(),
		capacity: capacity,
	}
}

// Put adds the provided (sessionKey, cs) pair to the cache. If cs is nil, the entry
// corresponding to sessionKey is removed from the cache instead.
func (c *lruSessionCache) Put(sessionKey string, cs *ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		if elem == nil {
			// Corrupted state: nil element in map, clean up
			delete(c.m, sessionKey)
			if cs == nil {
				// User wanted removal, already done
				return
			}
			// Fall through to add new entry
		} else if cs == nil {
			c.q.Remove(elem)
			delete(c.m, sessionKey)
			return
		} else {
			entry, ok := elem.Value.(*lruSessionCacheEntry)
			if !ok {
				// Corrupted cache entry type, remove and fall through to add new
				c.q.Remove(elem)
				delete(c.m, sessionKey)
			} else {
				entry.state = cs
				c.q.MoveToFront(elem)
				return
			}
		}
	}

	if c.q.Len() < c.capacity {
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}

	elem := c.q.Back()
	if elem == nil {
		// List is unexpectedly empty; create new entry instead of evicting
		entry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(entry)
		return
	}
	entry, ok := elem.Value.(*lruSessionCacheEntry)
	if !ok {
		// Corrupted cache entry type, remove old and create new
		c.q.Remove(elem)
		newEntry := &lruSessionCacheEntry{sessionKey, cs}
		c.m[sessionKey] = c.q.PushFront(newEntry)
		return
	}
	delete(c.m, entry.sessionKey)
	entry.sessionKey = sessionKey
	entry.state = cs
	c.q.MoveToFront(elem)
	c.m[sessionKey] = elem
}

// Get returns the [ClientSessionState] value associated with a given key. It
// returns (nil, false) if no value is found.
func (c *lruSessionCache) Get(sessionKey string) (*ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.m[sessionKey]; ok {
		c.q.MoveToFront(elem)
		entry, ok := elem.Value.(*lruSessionCacheEntry)
		if !ok {
			// Corrupted cache entry type, return not found
			return nil, false
		}
		return entry.state, true
	}
	return nil, false
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
}

func unexpectedMessageError(wanted, got any) error {
	return fmt.Errorf("tls: received unexpected handshake message of type %T when waiting for %T", got, wanted)
}

// supportedSignatureAlgorithms returns the supported signature algorithms.
func supportedSignatureAlgorithms() []SignatureScheme {
	// [uTLS] SECTION BEGIN
	// if !fips140tls.Required() {
	return defaultSupportedSignatureAlgorithms
	// }
	// return defaultSupportedSignatureAlgorithmsFIPS
	// [uTLS] SECTION END
}

func isSupportedSignatureAlgorithm(sigAlg SignatureScheme, supportedSignatureAlgorithms []SignatureScheme) bool {
	for _, s := range supportedSignatureAlgorithms {
		if s == sigAlg {
			return true
		}
	}
	return false
}

// CertificateVerificationError is returned when certificate verification fails during the handshake.
type CertificateVerificationError struct {
	// UnverifiedCertificates and its contents should not be modified.
	UnverifiedCertificates []*x509.Certificate
	Err                    error
}

func (e *CertificateVerificationError) Error() string {
	return fmt.Sprintf("tls: failed to verify certificate: %s", e.Err)
}

func (e *CertificateVerificationError) Unwrap() error {
	return e.Err
}

// fipsAllowedChains returns chains that are allowed to be used in a TLS connection
// based on the current fips140tls enforcement setting.
//
// If fips140tls is not required, the chains are returned as-is with no processing.
// Otherwise, the returned chains are filtered to only those allowed by FIPS 140-3.
// If this results in no chains it returns an error.
func fipsAllowedChains(chains [][]*x509.Certificate) ([][]*x509.Certificate, error) {
	if !fips140tls.Required() {
		return chains, nil
	}

	permittedChains := make([][]*x509.Certificate, 0, len(chains))
	for _, chain := range chains {
		if fipsAllowChain(chain) {
			permittedChains = append(permittedChains, chain)
		}
	}

	if len(permittedChains) == 0 {
		return nil, utlserrors.New("tls: no FIPS compatible certificate chains found").AtError()
	}

	return permittedChains, nil
}

func fipsAllowChain(chain []*x509.Certificate) bool {
	if len(chain) == 0 {
		return false
	}

	for _, cert := range chain {
		if !fipsAllowCert(cert) {
			return false
		}
	}

	return true
}

func fipsAllowCert(c *x509.Certificate) bool {
	// The key must be RSA 2048, RSA 3072, RSA 4096,
	// or ECDSA P-256, P-384, P-521.
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		size := k.N.BitLen()
		return size == 2048 || size == 3072 || size == 4096
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	}

	return false
}
