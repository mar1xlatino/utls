// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/refraction-networking/utls/dicttls"
	"golang.org/x/crypto/cryptobyte"
)

// ExtensionFromID returns a TLSExtension for the given extension ID.
func ExtensionFromID(id uint16) TLSExtension {
	// deep copy
	switch id {
	case extensionServerName:
		return &SNIExtension{}
	case extensionStatusRequest:
		return &StatusRequestExtension{}
	case extensionSupportedCurves:
		return &SupportedCurvesExtension{}
	case extensionSupportedPoints:
		return &SupportedPointsExtension{}
	case extensionSignatureAlgorithms:
		return &SignatureAlgorithmsExtension{}
	case extensionALPN:
		return &ALPNExtension{}
	case extensionStatusRequestV2:
		return &StatusRequestV2Extension{}
	case extensionSCT:
		return &SCTExtension{}
	case utlsExtensionPadding:
		return &UtlsPaddingExtension{}
	case extensionExtendedMasterSecret:
		return &ExtendedMasterSecretExtension{}
	case fakeExtensionEncryptThenMAC:
		return &FakeEncryptThenMACExtension{}
	case fakeExtensionTokenBinding:
		return &FakeTokenBindingExtension{}
	case utlsExtensionCompressCertificate:
		return &UtlsCompressCertExtension{}
	case fakeRecordSizeLimit:
		return &FakeRecordSizeLimitExtension{}
	case fakeExtensionDelegatedCredentials:
		return &FakeDelegatedCredentialsExtension{}
	case extensionSessionTicket:
		return &SessionTicketExtension{}
	case extensionPreSharedKey:
		return (PreSharedKeyExtension)(&FakePreSharedKeyExtension{}) // To use the result, caller needs further inspection to decide between Fake or Utls.
	// case extensionEarlyData:
	// 	return &EarlyDataExtension{}
	case extensionSupportedVersions:
		return &SupportedVersionsExtension{}
	// case extensionCookie:
	// 	return &CookieExtension{}
	case extensionPSKModes:
		return &PSKKeyExchangeModesExtension{}
	// case extensionCertificateAuthorities:
	// 	return &CertificateAuthoritiesExtension{}
	case extensionSignatureAlgorithmsCert:
		return &SignatureAlgorithmsCertExtension{}
	case extensionKeyShare:
		return &KeyShareExtension{}
	case extensionQUICTransportParameters:
		return &QUICTransportParametersExtension{}
	case extensionNextProtoNeg:
		return &NPNExtension{}
	case utlsExtensionApplicationSettings:
		return &ApplicationSettingsExtension{}
	case utlsExtensionApplicationSettingsNew:
		return &ApplicationSettingsExtensionNew{}
	case fakeOldExtensionChannelID:
		return &FakeChannelIDExtension{true}
	case fakeExtensionChannelID:
		return &FakeChannelIDExtension{}
	case utlsExtensionECH:
		return &GREASEEncryptedClientHelloExtension{}
	case extensionRenegotiationInfo:
		return &RenegotiationInfoExtension{}
	default:
		if isGREASEUint16(id) {
			return &UtlsGREASEExtension{}
		}
		return nil // not returning GenericExtension, it should be handled by caller
	}
}

type TLSExtension interface {
	writeToUConn(*UConn) error

	Len() int // includes header

	// Read reads up to len(p) bytes into p.
	// It returns the number of bytes read (0 <= n <= len(p)) and any error encountered.
	Read(p []byte) (n int, err error) // implements io.Reader
}

// TLSExtensionWriter is an interface allowing a TLS extension to be
// auto-constucted/recovered by reading in a byte stream.
type TLSExtensionWriter interface {
	TLSExtension

	// Write writes the extension data as a byte slice, up to len(b) bytes from b.
	// It returns the number of bytes written (0 <= n <= len(b)) and any error encountered.
	//
	// The implementation MUST NOT silently drop data if consumed less than len(b) bytes,
	// instead, it MUST return an error.
	Write(b []byte) (n int, err error)
}

type TLSExtensionJSON interface {
	TLSExtension

	// UnmarshalJSON unmarshals the JSON-encoded data into the extension.
	UnmarshalJSON([]byte) error
}

// SNIExtension implements server_name (0)
type SNIExtension struct {
	ServerName string // not an array because go crypto/tls doesn't support multiple SNIs
}

// validateSNIHostname validates hostname per RFC 6066 Section 3.
// Returns error if hostname contains invalid characters.
func validateSNIHostname(hostname string) error {
	if len(hostname) == 0 {
		return errors.New("tls: SNI hostname is empty")
	}
	// RFC 6066 Section 3: hostname must use ASCII encoding.
	// Control characters and non-ASCII bytes are not permitted.
	for i := 0; i < len(hostname); i++ {
		c := hostname[i]
		if c < 0x20 || c >= 0x7F {
			return errors.New("tls: SNI hostname contains invalid character")
		}
	}
	return nil
}

func (e *SNIExtension) Len() int {
	// Literal IP addresses, absolute FQDNs, and empty strings are not permitted as SNI values.
	// See RFC 6066, Section 3.
	hostName := hostnameInSNI(e.ServerName)
	if len(hostName) == 0 {
		return 0
	}
	return 4 + 2 + 1 + 2 + len(hostName)
}

func (e *SNIExtension) Read(b []byte) (int, error) {
	// Literal IP addresses, absolute FQDNs, and empty strings are not permitted as SNI values.
	// See RFC 6066, Section 3.
	hostName := hostnameInSNI(e.ServerName)
	if len(hostName) == 0 {
		return 0, io.EOF
	}
	// Validate hostname characters per RFC 6066.
	if err := validateSNIHostname(hostName); err != nil {
		return 0, err
	}
	// SNI extension data length is 5 + len(hostName), must fit in uint16.
	// Maximum hostname length is 65530 bytes (65535 - 5 byte overhead).
	if len(hostName) > 65530 {
		return 0, errors.New("tls: server name too long for SNI extension")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// RFC 3546, section 3.1
	b[0] = byte(extensionServerName >> 8)
	b[1] = byte(extensionServerName)
	b[2] = byte((len(hostName) + 5) >> 8)
	b[3] = byte(len(hostName) + 5)
	b[4] = byte((len(hostName) + 3) >> 8)
	b[5] = byte(len(hostName) + 3)
	// b[6] Server Name Type: host_name (0)
	b[7] = byte(len(hostName) >> 8)
	b[8] = byte(len(hostName))
	copy(b[9:], []byte(hostName))
	return e.Len(), io.EOF
}

func (e *SNIExtension) UnmarshalJSON(_ []byte) error {
	return nil // no-op
}

// Write is a no-op for StatusRequestExtension.
// SNI should not be fingerprinted and is user controlled.
func (e *SNIExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 6066, Section 3
	var nameList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return fullLen, errors.New("unable to read server name extension data")
	}
	var serverName string
	for !nameList.Empty() {
		var nameType uint8
		var serverNameBytes cryptobyte.String
		if !nameList.ReadUint8(&nameType) ||
			!nameList.ReadUint16LengthPrefixed(&serverNameBytes) ||
			serverNameBytes.Empty() {
			return fullLen, errors.New("unable to read server name extension data")
		}
		if nameType != 0 {
			continue
		}
		if len(serverName) != 0 {
			return fullLen, errors.New("multiple names of the same name_type in server name extension are prohibited")
		}
		serverName = string(serverNameBytes)
		if strings.HasSuffix(serverName, ".") {
			return fullLen, errors.New("SNI value may not include a trailing dot")
		}
		// Validate hostname characters per RFC 6066.
		if err := validateSNIHostname(serverName); err != nil {
			return fullLen, err
		}
	}
	// clientHelloSpec.Extensions = append(clientHelloSpec.Extensions, &SNIExtension{}) // gaukas moved this line out from the loop.

	// don't copy SNI from ClientHello to ClientHelloSpec!
	return fullLen, nil
}

func (e *SNIExtension) writeToUConn(uc *UConn) error {
	if uc.config.EncryptedClientHelloConfigList == nil { // with ech, e.ServerName is the outer public name and should not be copied
		uc.config.ServerName = e.ServerName
	}
	hostName := hostnameInSNI(e.ServerName)
	uc.HandshakeState.Hello.ServerName = hostName

	return nil
}

// StatusRequestExtension implements status_request (5)
type StatusRequestExtension struct {
}

func (e *StatusRequestExtension) Len() int {
	return 9
}

func (e *StatusRequestExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// RFC 4366, section 3.6
	b[0] = byte(extensionStatusRequest >> 8)
	b[1] = byte(extensionStatusRequest)
	b[2] = 0
	b[3] = 5
	b[4] = 1 // OCSP type
	// Two zero valued uint16s for the two lengths.
	return e.Len(), io.EOF
}

func (e *StatusRequestExtension) UnmarshalJSON(_ []byte) error {
	return nil // no-op
}

// Write is a no-op for StatusRequestExtension. No data for this extension.
func (e *StatusRequestExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 4366, Section 3.6
	var statusType uint8
	var ignored cryptobyte.String
	if !extData.ReadUint8(&statusType) ||
		!extData.ReadUint16LengthPrefixed(&ignored) ||
		!extData.ReadUint16LengthPrefixed(&ignored) {
		return fullLen, errors.New("unable to read status request extension data")
	}

	if statusType != statusTypeOCSP {
		return fullLen, errors.New("status request extension statusType is not statusTypeOCSP(1)")
	}

	if !extData.Empty() {
		return fullLen, errors.New("status request extension has trailing data")
	}

	return fullLen, nil
}

func (e *StatusRequestExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.OcspStapling = true
	return nil
}

// SupportedCurvesExtension implements supported_groups (renamed from "elliptic_curves") (10)
type SupportedCurvesExtension struct {
	Curves []CurveID
}

func (e *SupportedCurvesExtension) Len() int {
	return 6 + 2*len(e.Curves)
}

func (e *SupportedCurvesExtension) Read(b []byte) (int, error) {
	// Extension header (4) + list length (2) + 2 bytes per curve
	// Must fit in uint16 (max 65535), so max curves = (65535 - 6) / 2 = 32764
	if len(e.Curves) > 32764 {
		return 0, errors.New("tls: too many supported curves (max 32764)")
	}
	if len(e.Curves) == 0 {
		return 0, errors.New("tls: supported_groups extension cannot be empty")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// http://tools.ietf.org/html/rfc4492#section-5.5.1
	b[0] = byte(extensionSupportedCurves >> 8)
	b[1] = byte(extensionSupportedCurves)
	b[2] = byte((2 + 2*len(e.Curves)) >> 8)
	b[3] = byte(2 + 2*len(e.Curves))
	b[4] = byte((2 * len(e.Curves)) >> 8)
	b[5] = byte(2 * len(e.Curves))
	for i, curve := range e.Curves {
		b[6+2*i] = byte(curve >> 8)
		b[7+2*i] = byte(curve)
	}
	return e.Len(), io.EOF
}

func (e *SupportedCurvesExtension) UnmarshalJSON(data []byte) error {
	var namedGroups struct {
		NamedGroupList []string `json:"named_group_list"`
	}
	if err := json.Unmarshal(data, &namedGroups); err != nil {
		return err
	}

	for _, namedGroup := range namedGroups.NamedGroupList {
		if namedGroup == "GREASE" {
			e.Curves = append(e.Curves, GREASE_PLACEHOLDER)
			continue
		}

		if group, ok := dicttls.DictSupportedGroupsNameIndexed[namedGroup]; ok {
			e.Curves = append(e.Curves, CurveID(group))
		} else {
			return fmt.Errorf("unknown named group: %s", namedGroup)
		}
	}
	return nil
}

func (e *SupportedCurvesExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
	var curvesBytes cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&curvesBytes) || curvesBytes.Empty() {
		return 0, errors.New("unable to read supported curves extension data")
	}
	curves := []CurveID{}
	for !curvesBytes.Empty() {
		var curve uint16
		if !curvesBytes.ReadUint16(&curve) {
			return 0, errors.New("unable to read supported curves extension data")
		}
		curves = append(curves, CurveID(unGREASEUint16(curve)))
	}
	if !extData.Empty() {
		return 0, errors.New("tls: supported_groups extension has trailing data")
	}
	e.Curves = curves
	return fullLen, nil
}

func (e *SupportedCurvesExtension) writeToUConn(uc *UConn) error {
	uc.config.CurvePreferences = e.Curves
	uc.HandshakeState.Hello.SupportedCurves = e.Curves
	return nil
}

// SupportedPointsExtension implements ec_point_formats (11)
type SupportedPointsExtension struct {
	SupportedPoints []uint8
}

func (e *SupportedPointsExtension) Len() int {
	return 5 + len(e.SupportedPoints)
}

func (e *SupportedPointsExtension) Read(b []byte) (int, error) {
	// Points list is prefixed with 1-byte length, max 255 entries
	if len(e.SupportedPoints) > 255 {
		return 0, errors.New("tls: too many ec_point_formats (max 255)")
	}
	// RFC 4492: at minimum, uncompressed point format must be supported
	if len(e.SupportedPoints) == 0 {
		return 0, errors.New("tls: ec_point_formats extension cannot be empty")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// http://tools.ietf.org/html/rfc4492#section-5.5.2
	b[0] = byte(extensionSupportedPoints >> 8)
	b[1] = byte(extensionSupportedPoints)
	b[2] = byte((1 + len(e.SupportedPoints)) >> 8)
	b[3] = byte(1 + len(e.SupportedPoints))
	b[4] = byte(len(e.SupportedPoints))
	for i, pointFormat := range e.SupportedPoints {
		b[5+i] = pointFormat
	}
	return e.Len(), io.EOF
}

func (e *SupportedPointsExtension) UnmarshalJSON(data []byte) error {
	var pointFormatList struct {
		ECPointFormatList []string `json:"ec_point_format_list"`
	}
	if err := json.Unmarshal(data, &pointFormatList); err != nil {
		return err
	}

	for _, pointFormat := range pointFormatList.ECPointFormatList {
		if format, ok := dicttls.DictECPointFormatNameIndexed[pointFormat]; ok {
			e.SupportedPoints = append(e.SupportedPoints, format)
		} else {
			return fmt.Errorf("unknown point format: %s", pointFormat)
		}
	}
	return nil
}

func (e *SupportedPointsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 4492, Section 5.1.2
	supportedPoints := []uint8{}
	if !readUint8LengthPrefixed(&extData, &supportedPoints) ||
		len(supportedPoints) == 0 {
		return 0, errors.New("unable to read supported points extension data")
	}
	if !extData.Empty() {
		return 0, errors.New("tls: ec_point_formats extension has trailing data")
	}
	e.SupportedPoints = supportedPoints
	return fullLen, nil
}

func (e *SupportedPointsExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.SupportedPoints = e.SupportedPoints
	return nil
}

// SignatureAlgorithmsExtension implements signature_algorithms (13)
type SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsExtension) Len() int {
	return 6 + 2*len(e.SupportedSignatureAlgorithms)
}

func (e *SignatureAlgorithmsExtension) Read(b []byte) (int, error) {
	if len(e.SupportedSignatureAlgorithms) == 0 {
		return 0, errors.New("tls: signature_algorithms extension cannot be empty")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
	b[0] = byte(extensionSignatureAlgorithms >> 8)
	b[1] = byte(extensionSignatureAlgorithms)
	b[2] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)) >> 8)
	b[3] = byte(2 + 2*len(e.SupportedSignatureAlgorithms))
	b[4] = byte((2 * len(e.SupportedSignatureAlgorithms)) >> 8)
	b[5] = byte(2 * len(e.SupportedSignatureAlgorithms))
	for i, sigScheme := range e.SupportedSignatureAlgorithms {
		b[6+2*i] = byte(sigScheme >> 8)
		b[7+2*i] = byte(sigScheme)
	}
	return e.Len(), io.EOF
}

func (e *SignatureAlgorithmsExtension) UnmarshalJSON(data []byte) error {
	var signatureAlgorithms struct {
		Algorithms []string `json:"supported_signature_algorithms"`
	}
	if err := json.Unmarshal(data, &signatureAlgorithms); err != nil {
		return err
	}

	for _, sigScheme := range signatureAlgorithms.Algorithms {
		if sigScheme == "GREASE" {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, GREASE_PLACEHOLDER)
			continue
		}

		if scheme, ok := dicttls.DictSignatureSchemeNameIndexed[sigScheme]; ok {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, SignatureScheme(scheme))
		} else {
			return fmt.Errorf("unknown signature scheme: %s", sigScheme)
		}
	}
	return nil
}

func (e *SignatureAlgorithmsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 5246, Section 7.4.1.4.1
	var sigAndAlgs cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
		return 0, errors.New("unable to read signature algorithms extension data")
	}
	supportedSignatureAlgorithms := []SignatureScheme{}
	for !sigAndAlgs.Empty() {
		var sigAndAlg uint16
		if !sigAndAlgs.ReadUint16(&sigAndAlg) {
			return 0, errors.New("unable to read signature algorithms extension data")
		}
		supportedSignatureAlgorithms = append(
			supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
	}
	if !extData.Empty() {
		return 0, errors.New("tls: signature_algorithms extension has trailing data")
	}
	e.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	return fullLen, nil
}

func (e *SignatureAlgorithmsExtension) writeToUConn(uc *UConn) error {
	if len(e.SupportedSignatureAlgorithms) == 0 {
		return errors.New("tls: signature_algorithms extension cannot be empty")
	}
	uc.HandshakeState.Hello.SupportedSignatureAlgorithms = e.SupportedSignatureAlgorithms
	return nil
}

// StatusRequestV2Extension implements status_request_v2 (17)
type StatusRequestV2Extension struct {
}

func (e *StatusRequestV2Extension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.OcspStapling = true
	return nil
}

func (e *StatusRequestV2Extension) Len() int {
	return 13
}

func (e *StatusRequestV2Extension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// RFC 4366, section 3.6
	b[0] = byte(extensionStatusRequestV2 >> 8)
	b[1] = byte(extensionStatusRequestV2)
	b[2] = 0
	b[3] = 9
	b[4] = 0
	b[5] = 7
	b[6] = 2 // OCSP type
	b[7] = 0
	b[8] = 4
	// Two zero valued uint16s for the two lengths.
	return e.Len(), io.EOF
}

// Write is a no-op for StatusRequestV2Extension. No data for this extension.
func (e *StatusRequestV2Extension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 4366, Section 3.6
	var statusType uint8
	var ignored cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&ignored) || !ignored.ReadUint8(&statusType) {
		return fullLen, errors.New("unable to read status request v2 extension data")
	}

	if statusType != statusV2TypeOCSP {
		return fullLen, errors.New("status request v2 extension statusType is not statusV2TypeOCSP(2)")
	}

	if !extData.Empty() {
		return fullLen, errors.New("status request v2 extension has trailing data")
	}

	return fullLen, nil
}

func (e *StatusRequestV2Extension) UnmarshalJSON(_ []byte) error {
	return nil // no-op
}

// SignatureAlgorithmsCertExtension implements signature_algorithms_cert (50)
type SignatureAlgorithmsCertExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsCertExtension) Len() int {
	return 6 + 2*len(e.SupportedSignatureAlgorithms)
}

func (e *SignatureAlgorithmsCertExtension) Read(b []byte) (int, error) {
	// Extension data must fit in uint16 (max 65535): 2 + 2*N <= 65535, so max N = 32766
	if len(e.SupportedSignatureAlgorithms) > 32766 {
		return 0, errors.New("tls: too many cert signature algorithms (max 32766)")
	}
	if len(e.SupportedSignatureAlgorithms) == 0 {
		return 0, errors.New("tls: signature_algorithms_cert extension cannot be empty")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
	b[0] = byte(extensionSignatureAlgorithmsCert >> 8)
	b[1] = byte(extensionSignatureAlgorithmsCert)
	b[2] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)) >> 8)
	b[3] = byte(2 + 2*len(e.SupportedSignatureAlgorithms))
	b[4] = byte((2 * len(e.SupportedSignatureAlgorithms)) >> 8)
	b[5] = byte(2 * len(e.SupportedSignatureAlgorithms))
	for i, sigAndHash := range e.SupportedSignatureAlgorithms {
		b[6+2*i] = byte(sigAndHash >> 8)
		b[7+2*i] = byte(sigAndHash)
	}
	return e.Len(), io.EOF
}

// Copied from SignatureAlgorithmsExtension.UnmarshalJSON
func (e *SignatureAlgorithmsCertExtension) UnmarshalJSON(data []byte) error {
	var signatureAlgorithms struct {
		Algorithms []string `json:"supported_signature_algorithms"`
	}
	if err := json.Unmarshal(data, &signatureAlgorithms); err != nil {
		return err
	}

	for _, sigScheme := range signatureAlgorithms.Algorithms {
		if sigScheme == "GREASE" {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, GREASE_PLACEHOLDER)
			continue
		}

		if scheme, ok := dicttls.DictSignatureSchemeNameIndexed[sigScheme]; ok {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, SignatureScheme(scheme))
		} else {
			return fmt.Errorf("unknown cert signature scheme: %s", sigScheme)
		}
	}
	return nil
}

// Write implementation copied from SignatureAlgorithmsExtension.Write
//
// Warning: not tested.
func (e *SignatureAlgorithmsCertExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 8446, Section 4.2.3
	var sigAndAlgs cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
		return 0, errors.New("unable to read signature algorithms extension data")
	}
	supportedSignatureAlgorithms := []SignatureScheme{}
	for !sigAndAlgs.Empty() {
		var sigAndAlg uint16
		if !sigAndAlgs.ReadUint16(&sigAndAlg) {
			return 0, errors.New("unable to read signature algorithms extension data")
		}
		supportedSignatureAlgorithms = append(
			supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
	}
	if !extData.Empty() {
		return 0, errors.New("tls: signature_algorithms_cert extension has trailing data")
	}
	e.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	return fullLen, nil
}

func (e *SignatureAlgorithmsCertExtension) writeToUConn(uc *UConn) error {
	if len(e.SupportedSignatureAlgorithms) == 0 {
		return errors.New("tls: signature_algorithms_cert extension cannot be empty")
	}
	uc.HandshakeState.Hello.SupportedSignatureAlgorithms = e.SupportedSignatureAlgorithms
	return nil
}

// ALPNExtension implements application_layer_protocol_negotiation (16)
type ALPNExtension struct {
	AlpnProtocols []string
}

func (e *ALPNExtension) writeToUConn(uc *UConn) error {
	for _, proto := range e.AlpnProtocols {
		if len(proto) == 0 {
			return errors.New("tls: ALPN protocol cannot be empty")
		}
		if len(proto) > 255 {
			return errors.New("tls: ALPN protocol too long (max 255 bytes)")
		}
	}
	uc.config.NextProtos = e.AlpnProtocols
	uc.HandshakeState.Hello.AlpnProtocols = e.AlpnProtocols
	return nil
}

func (e *ALPNExtension) Len() int {
	bLen := 2 + 2 + 2
	for _, s := range e.AlpnProtocols {
		bLen += 1 + len(s)
	}
	return bLen
}

func (e *ALPNExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	// Validate protocol lengths before writing (defense in depth)
	for _, s := range e.AlpnProtocols {
		if len(s) == 0 || len(s) > 255 {
			return 0, errors.New("tls: invalid ALPN protocol length (must be 1-255 bytes)")
		}
	}

	b[0] = byte(extensionALPN >> 8)
	b[1] = byte(extensionALPN & 0xff)
	lengths := b[2:]
	b = b[6:]

	stringsLength := 0
	for _, s := range e.AlpnProtocols {
		l := len(s)
		b[0] = byte(l)
		copy(b[1:], s)
		b = b[1+l:]
		stringsLength += 1 + l
	}

	lengths[2] = byte(stringsLength >> 8)
	lengths[3] = byte(stringsLength)
	stringsLength += 2
	lengths[0] = byte(stringsLength >> 8)
	lengths[1] = byte(stringsLength)

	return e.Len(), io.EOF
}

func (e *ALPNExtension) UnmarshalJSON(b []byte) error {
	var protocolNames struct {
		ProtocolNameList []string `json:"protocol_name_list"`
	}

	if err := json.Unmarshal(b, &protocolNames); err != nil {
		return err
	}

	e.AlpnProtocols = protocolNames.ProtocolNameList
	return nil
}

func (e *ALPNExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 7301, Section 3.1
	var protoList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
		return 0, errors.New("unable to read ALPN extension data")
	}
	alpnProtocols := []string{}
	for !protoList.Empty() {
		var proto cryptobyte.String
		if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
			return 0, errors.New("unable to read ALPN extension data")
		}
		alpnProtocols = append(alpnProtocols, string(proto))
	}
	if !extData.Empty() {
		return 0, errors.New("tls: ALPN extension has trailing data")
	}
	e.AlpnProtocols = alpnProtocols
	return fullLen, nil
}

// applicationSettingsExtension represents the TLS ALPS extension.
// At the time of this writing, this extension is currently a draft:
// https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01
type applicationSettingsExtension struct {
	codePoint uint16
}

func (e *applicationSettingsExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *applicationSettingsExtension) Len(supportedProtocols []string) int {
	bLen := 2 + 2 + 2 // Type + Length + ALPS Extension length
	for _, s := range supportedProtocols {
		bLen += 1 + len(s) // Supported ALPN Length + actual length of protocol
	}
	return bLen
}

func (e *applicationSettingsExtension) Read(b []byte, supportedProtocols []string) (int, error) {
	if len(supportedProtocols) == 0 {
		return 0, errors.New("tls: ALPS extension requires at least one protocol")
	}

	if len(b) < e.Len(supportedProtocols) {
		return 0, io.ErrShortBuffer
	}

	// Validate protocol lengths and compute total size to check for uint16 overflow
	var totalProtocolBytes int
	for _, s := range supportedProtocols {
		if len(s) == 0 || len(s) > 255 {
			return 0, errors.New("tls: invalid ALPS protocol length (must be 1-255 bytes)")
		}
		totalProtocolBytes += 1 + len(s) // 1 byte length prefix + protocol string
	}

	// Extension data layout: 2 bytes (ALPS list length) + protocol entries
	// The ALPS list length field is uint16, so max value is 65535
	if totalProtocolBytes > 65535 {
		return 0, errors.New("tls: ALPS extension data too large (exceeds 65535 bytes)")
	}

	// Read Type.
	b[0] = byte(e.codePoint >> 8)   // hex: 44 dec: 68
	b[1] = byte(e.codePoint & 0xff) // hex: 69 dec: 105

	lengths := b[2:] // get the remaining buffer without Type
	b = b[6:]        // set the buffer to the buffer without Type, Length and ALPS Extension Length (so only the Supported ALPN list remains)

	stringsLength := 0
	for _, s := range supportedProtocols {
		l := len(s)            // Supported ALPN Length
		b[0] = byte(l)         // Supported ALPN Length in bytes hex: 02 dec: 2
		copy(b[1:], s)         // copy the Supported ALPN as bytes to the buffer
		b = b[1+l:]            // set the buffer to the buffer without the Supported ALPN Length and Supported ALPN (so we can continue to the next protocol in this loop)
		stringsLength += 1 + l // Supported ALPN Length (the field itself) + Supported ALPN Length (the value)
	}

	lengths[2] = byte(stringsLength >> 8) // ALPS Extension Length hex: 00 dec: 0
	lengths[3] = byte(stringsLength)      // ALPS Extension Length hex: 03 dec: 3
	stringsLength += 2                    // plus ALPS Extension Length field length
	lengths[0] = byte(stringsLength >> 8) // Length hex:00 dec: 0
	lengths[1] = byte(stringsLength)      // Length hex: 05 dec: 5

	return e.Len(supportedProtocols), io.EOF
}

// Write implementation copied from ALPNExtension.Write
func (e *applicationSettingsExtension) Write(b []byte) ([]string, int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01
	var protoList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
		return nil, 0, errors.New("unable to read ALPN extension data")
	}
	alpnProtocols := []string{}
	for !protoList.Empty() {
		var proto cryptobyte.String
		if !protoList.ReadUint8LengthPrefixed(&proto) || proto.Empty() {
			return nil, 0, errors.New("unable to read ALPN extension data")
		}
		alpnProtocols = append(alpnProtocols, string(proto))
	}
	if !extData.Empty() {
		return nil, 0, errors.New("tls: ALPS extension has trailing data")
	}
	return alpnProtocols, fullLen, nil
}

// ApplicationSettingsExtension embeds applicationSettingsExtension to implement the TLS ALPS extension on codepoint 17513
type ApplicationSettingsExtension struct {
	applicationSettingsExtension
	SupportedProtocols []string
}

func (e *ApplicationSettingsExtension) Len() int {
	return e.applicationSettingsExtension.Len(e.SupportedProtocols)
}

func (e *ApplicationSettingsExtension) Read(b []byte) (int, error) {
	e.applicationSettingsExtension.codePoint = utlsExtensionApplicationSettings
	return e.applicationSettingsExtension.Read(b, e.SupportedProtocols)
}

func (e *ApplicationSettingsExtension) UnmarshalJSON(b []byte) error {
	var applicationSettingsSupport struct {
		SupportedProtocols []string `json:"supported_protocols"`
	}

	if err := json.Unmarshal(b, &applicationSettingsSupport); err != nil {
		return err
	}

	e.SupportedProtocols = applicationSettingsSupport.SupportedProtocols
	return nil
}

// Write implementation copied from ALPNExtension.Write
func (e *ApplicationSettingsExtension) Write(b []byte) (int, error) {
	var (
		fullLen int
		err     error
	)
	e.SupportedProtocols, fullLen, err = e.applicationSettingsExtension.Write(b)
	return fullLen, err
}

// ApplicationSettingsExtensionNew embeds applicationSettingsExtension to implement the TLS ALPS extension on codepoint 17613
// More information can be found here: https://chromestatus.com/feature/5149147365900288
type ApplicationSettingsExtensionNew struct {
	applicationSettingsExtension
	SupportedProtocols []string
}

func (e *ApplicationSettingsExtensionNew) Len() int {
	return e.applicationSettingsExtension.Len(e.SupportedProtocols)
}

func (e *ApplicationSettingsExtensionNew) Read(b []byte) (int, error) {
	e.applicationSettingsExtension.codePoint = utlsExtensionApplicationSettingsNew
	return e.applicationSettingsExtension.Read(b, e.SupportedProtocols)
}

func (e *ApplicationSettingsExtensionNew) UnmarshalJSON(b []byte) error {
	var applicationSettingsSupport struct {
		SupportedProtocols []string `json:"supported_protocols"`
	}

	if err := json.Unmarshal(b, &applicationSettingsSupport); err != nil {
		return err
	}

	e.SupportedProtocols = applicationSettingsSupport.SupportedProtocols
	return nil
}

// Write implementation copied from ALPNExtension.Write
func (e *ApplicationSettingsExtensionNew) Write(b []byte) (int, error) {
	var (
		fullLen int
		err     error
	)
	e.SupportedProtocols, fullLen, err = e.applicationSettingsExtension.Write(b)
	return fullLen, err
}

// SCTExtension implements signed_certificate_timestamp (18)
// RFC 6962 Section 3.3.1
type SCTExtension struct {
	// SCTs holds Signed Certificate Timestamps received from server.
	// In ClientHello this should be empty (client advertises support).
	// Servers populate this field when sending SCTs.
	SCTs [][]byte
}

func (e *SCTExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.Scts = true
	return nil
}

func (e *SCTExtension) Len() int {
	if len(e.SCTs) == 0 {
		// Empty extension: 2 bytes type + 2 bytes length (0)
		return 4
	}
	// 2 bytes type + 2 bytes extension length + 2 bytes SCT list length
	extLen := 2
	for _, sct := range e.SCTs {
		// Each SCT: 2 bytes length + data
		extLen += 2 + len(sct)
	}
	return 4 + extLen
}

func (e *SCTExtension) Read(b []byte) (int, error) {
	// https://tools.ietf.org/html/rfc6962#section-3.3.1
	// In ClientHello, SCT extension must be empty (RFC 6962)
	// Only servers include actual SCTs in the extension
	extLen := e.Len()
	if len(b) < extLen {
		return 0, io.ErrShortBuffer
	}

	// Calculate extension data length (excluding type and length fields)
	dataLen := extLen - 4
	// Validate extension data fits in uint16 length field
	if dataLen > 65535 {
		return 0, errors.New("tls: SCT extension data too large for uint16 length field")
	}

	b[0] = byte(extensionSCT >> 8)
	b[1] = byte(extensionSCT)
	b[2] = byte(dataLen >> 8)
	b[3] = byte(dataLen)

	if len(e.SCTs) == 0 {
		// Empty extension is valid for ClientHello (advertising support)
		return extLen, io.EOF
	}

	// Write SCT list length
	sctListLen := dataLen - 2
	b[4] = byte(sctListLen >> 8)
	b[5] = byte(sctListLen)

	// Write individual SCTs
	offset := 6
	for _, sct := range e.SCTs {
		sctLen := len(sct)
		b[offset] = byte(sctLen >> 8)
		b[offset+1] = byte(sctLen)
		copy(b[offset+2:], sct)
		offset += 2 + sctLen
	}

	return extLen, io.EOF
}

func (e *SCTExtension) UnmarshalJSON(_ []byte) error {
	return nil // no-op
}

func (e *SCTExtension) Write(b []byte) (int, error) {
	fullLen := len(b)

	// Empty extension data is valid - client advertises support without timestamps
	if fullLen == 0 {
		e.SCTs = nil
		return 0, nil
	}

	extData := cryptobyte.String(b)

	// Read SCT list (uint16 length-prefixed)
	var sctList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&sctList) {
		return 0, errors.New("tls: unable to read SCT list length")
	}

	// Empty SCT list after length prefix is valid (advertises support)
	if sctList.Empty() {
		e.SCTs = nil
		return fullLen, nil
	}

	// Parse individual SCTs
	var scts [][]byte
	for !sctList.Empty() {
		var sct []byte
		if !readUint16LengthPrefixed(&sctList, &sct) {
			return 0, errors.New("tls: unable to read SCT data")
		}
		if len(sct) == 0 {
			return 0, errors.New("tls: empty SCT in SCT list")
		}
		scts = append(scts, sct)
	}
	e.SCTs = scts
	return fullLen, nil
}

// GenericExtension allows to include in ClientHello arbitrary unsupported extensions.
// It is not defined in TLS RFCs nor by IANA.
// If a server echoes this extension back, the handshake will likely fail due to no further support.
type GenericExtension struct {
	Id   uint16
	Data []byte
}

func (e *GenericExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *GenericExtension) Len() int {
	return 4 + len(e.Data)
}

func (e *GenericExtension) Read(b []byte) (int, error) {
	// Extension data length is stored as uint16 (max 65535).
	// Header is 4 bytes (2 type + 2 length), so max data is 65531.
	if len(e.Data) > 65531 {
		return 0, errors.New("tls: extension data too long")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(e.Id >> 8)
	b[1] = byte(e.Id)
	b[2] = byte(len(e.Data) >> 8)
	b[3] = byte(len(e.Data))
	if len(e.Data) > 0 {
		copy(b[4:], e.Data)
	}
	return e.Len(), io.EOF
}

func (e *GenericExtension) UnmarshalJSON(b []byte) error {
	var genericExtension struct {
		Name string `json:"name"`
		Data []byte `json:"data"`
	}
	if err := json.Unmarshal(b, &genericExtension); err != nil {
		return err
	}

	// lookup extension ID by name
	if id, ok := dicttls.DictExtTypeNameIndexed[genericExtension.Name]; ok {
		e.Id = id
	} else {
		return fmt.Errorf("unknown extension name %s", genericExtension.Name)
	}
	e.Data = genericExtension.Data
	return nil
}

// ExtendedMasterSecretExtension implements extended_master_secret (23)
//
// Was named as ExtendedMasterSecretExtension, renamed due to crypto/tls
// implemented this extension's support.
type ExtendedMasterSecretExtension struct {
}

// TODO: update when this extension is implemented in crypto/tls
// but we probably won't have to enable it in Config
func (e *ExtendedMasterSecretExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.Ems = true
	return nil
}

func (e *ExtendedMasterSecretExtension) Len() int {
	return 4
}

func (e *ExtendedMasterSecretExtension) Read(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7627
	// Extension type (23 = extended_master_secret)
	b[0] = byte(extensionExtendedMasterSecret >> 8)
	b[1] = byte(extensionExtendedMasterSecret)
	// Extension data length: 0 (this is a flag-only extension, no payload)
	b[2] = 0
	b[3] = 0
	return 4, io.EOF
}

func (e *ExtendedMasterSecretExtension) UnmarshalJSON(_ []byte) error {
	return nil // no-op
}

func (e *ExtendedMasterSecretExtension) Write(b []byte) (int, error) {
	// RFC 7627 Section 5.1: extended_master_secret extension MUST have
	// zero-length extension_data. The entire encoding is 00 17 00 00.
	if len(b) != 0 {
		return 0, errors.New("tls: extended_master_secret extension must have empty data per RFC 7627")
	}
	return 0, nil
}

// GREASE stinks with dead parrots, have to be super careful, and, if possible, not include GREASE
// https://github.com/google/boringssl/blob/1c68fa2350936ca5897a66b430ebaf333a0e43f5/ssl/internal.h
const (
	ssl_grease_cipher = iota
	ssl_grease_group
	ssl_grease_extension1
	ssl_grease_extension2
	ssl_grease_version
	ssl_grease_ticket_extension
	ssl_grease_last_index = ssl_grease_ticket_extension
)

// it is responsibility of user not to generate multiple grease extensions with same value
type UtlsGREASEExtension struct {
	Value uint16
	Body  []byte // in Chrome first grease has empty body, second grease has a single zero byte
}

func (e *UtlsGREASEExtension) writeToUConn(uc *UConn) error {
	return nil
}

// will panic if ssl_grease_last_index[index] is out of bounds.
func GetBoringGREASEValue(greaseSeed [ssl_grease_last_index]uint16, index int) uint16 {
	// GREASE value is back from deterministic to random.
	// https://github.com/google/boringssl/blob/a365138ac60f38b64bfc608b493e0f879845cb88/ssl/handshake_client.c#L530
	ret := uint16(greaseSeed[index])
	/* This generates a random value of the form 0xωaωa, for all 0 ≤ ω < 16. */
	ret = (ret & 0xf0) | 0x0a
	ret |= ret << 8
	return ret
}

func (e *UtlsGREASEExtension) Len() int {
	return 4 + len(e.Body)
}

func (e *UtlsGREASEExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	// Use GREASE_PLACEHOLDER if Value is unset (zero)
	value := e.Value
	if value == 0 {
		value = GREASE_PLACEHOLDER
	}

	// Validate that Value is a valid GREASE value per RFC 8701
	if !isGREASEUint16(value) {
		return 0, fmt.Errorf("invalid GREASE extension ID 0x%04x: must follow 0x?a?a pattern per RFC 8701", value)
	}

	b[0] = byte(value >> 8)
	b[1] = byte(value)
	b[2] = byte(len(e.Body) >> 8)
	b[3] = byte(len(e.Body))
	if len(e.Body) > 0 {
		copy(b[4:], e.Body)
	}
	return e.Len(), io.EOF
}

func (e *UtlsGREASEExtension) Write(b []byte) (int, error) {
	e.Value = GREASE_PLACEHOLDER
	e.Body = make([]byte, len(b))
	n := copy(e.Body, b)
	return n, nil
}

func (e *UtlsGREASEExtension) UnmarshalJSON(b []byte) error {
	var jsonObj struct {
		Id       uint16 `json:"id"`
		Data     []byte `json:"data"`
		KeepID   bool   `json:"keep_id"`
		KeepData bool   `json:"keep_data"`
	}

	if err := json.Unmarshal(b, &jsonObj); err != nil {
		return err
	}

	if jsonObj.Id == 0 {
		return nil
	}

	if isGREASEUint16(jsonObj.Id) {
		if jsonObj.KeepID {
			e.Value = jsonObj.Id
		}
		if jsonObj.KeepData {
			e.Body = jsonObj.Data
		}
		return nil
	} else {
		return errors.New("GREASE extension id must be a GREASE value")
	}
}

// UtlsPaddingExtension implements padding (21)
type UtlsPaddingExtension struct {
	PaddingLen int
	WillPad    bool // set to false to disable extension

	// Functor for deciding on padding length based on unpadded ClientHello length.
	// If willPad is false, then this extension should not be included.
	GetPaddingLen func(clientHelloUnpaddedLen int) (paddingLen int, willPad bool)
}

func (e *UtlsPaddingExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *UtlsPaddingExtension) Len() int {
	if e.WillPad {
		// Validate PaddingLen to prevent negative values or overflow
		if e.PaddingLen < 0 {
			return 0
		}
		// Max extension data is 65535 bytes (uint16), header is 4 bytes
		paddingLen := e.PaddingLen
		if paddingLen > 65531 {
			paddingLen = 65531
		}
		return 4 + paddingLen
	}
	return 0
}

func (e *UtlsPaddingExtension) Update(clientHelloUnpaddedLen int) {
	if e.GetPaddingLen != nil {
		e.PaddingLen, e.WillPad = e.GetPaddingLen(clientHelloUnpaddedLen)
		// Validate callback result to prevent negative or overflow values
		if e.PaddingLen < 0 {
			e.PaddingLen = 0
			e.WillPad = false
		} else if e.PaddingLen > 65531 {
			// Max extension data is 65535 bytes (uint16), header is 4 bytes
			e.PaddingLen = 65531
		}
	}
}

func (e *UtlsPaddingExtension) Read(b []byte) (int, error) {
	if !e.WillPad {
		return 0, io.EOF
	}
	// Validate PaddingLen before writing to buffer
	if e.PaddingLen < 0 {
		return 0, errors.New("tls: negative padding length")
	}
	// Max extension data is 65535 bytes (uint16), header is 4 bytes
	paddingLen := e.PaddingLen
	if paddingLen > 65531 {
		paddingLen = 65531
	}
	totalLen := 4 + paddingLen
	if len(b) < totalLen {
		return 0, io.ErrShortBuffer
	}
	// https://tools.ietf.org/html/rfc7685 (TLS padding extension)
	b[0] = byte(utlsExtensionPadding >> 8)
	b[1] = byte(utlsExtensionPadding)
	b[2] = byte(paddingLen >> 8)
	b[3] = byte(paddingLen)
	return totalLen, io.EOF
}

func (e *UtlsPaddingExtension) UnmarshalJSON(b []byte) error {
	var jsonObj struct {
		Length uint `json:"len"`
	}
	if err := json.Unmarshal(b, &jsonObj); err != nil {
		return err
	}

	if jsonObj.Length == 0 {
		e.GetPaddingLen = BoringPaddingStyle
	} else {
		e.PaddingLen = int(jsonObj.Length)
		e.WillPad = true
	}

	return nil
}

func (e *UtlsPaddingExtension) Write(_ []byte) (int, error) {
	e.GetPaddingLen = BoringPaddingStyle
	return 0, nil
}

// https://github.com/google/boringssl/blob/7d7554b6b3c79e707e25521e61e066ce2b996e4c/ssl/t1_lib.c#L2803
func BoringPaddingStyle(unpaddedLen int) (int, bool) {
	if unpaddedLen > 0xff && unpaddedLen < 0x200 {
		paddingLen := 0x200 - unpaddedLen
		if paddingLen >= 4+1 {
			paddingLen -= 4
		} else {
			paddingLen = 1
		}
		return paddingLen, true
	}
	return 0, false
}

// AlwaysPadToLen could be used for parsed ClientHello, since some fingerprints
// might not use BoringSSL padding style and we want to pad to a the same length.
func AlwaysPadToLen(padToLen int) func(int) (int, bool) {
	return func(unpaddedLen int) (int, bool) {
		if unpaddedLen < padToLen {
			paddingLen := padToLen - unpaddedLen
			if paddingLen >= 4+1 {
				paddingLen -= 4
			} else {
				paddingLen = 1
			}
			return paddingLen, true
		}
		return 0, false
	}
}

// UtlsCompressCertExtension implements compress_certificate (27) and is only implemented client-side
// for server certificates. Alternate certificate message formats
// (https://datatracker.ietf.org/doc/html/rfc7250) are not supported.
//
// See https://datatracker.ietf.org/doc/html/rfc8879#section-3
type UtlsCompressCertExtension struct {
	Algorithms []CertCompressionAlgo
}

func (e *UtlsCompressCertExtension) writeToUConn(uc *UConn) error {
	uc.certCompressionAlgs = e.Algorithms
	return nil
}

func (e *UtlsCompressCertExtension) Len() int {
	return 4 + 1 + (2 * len(e.Algorithms))
}

func (e *UtlsCompressCertExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	// Validate algorithms list is not empty (RFC 8879 requires at least one algorithm)
	if len(e.Algorithms) == 0 {
		return 0, errors.New("tls: compress_certificate extension requires at least one algorithm")
	}

	// Each algorithm is 2 bytes, length field is 1 byte (max 255), so max 127 algorithms
	if len(e.Algorithms) > 127 {
		return 0, errors.New("tls: too many compression algorithms (max 127)")
	}

	// Validate algorithm IDs per RFC 8879 Section 7.3:
	// - 1 = zlib (RFC 8879)
	// - 2 = brotli (RFC 8879)
	// - 3 = zstd (RFC 8879)
	// - 16384-65535 = reserved for private/experimental use
	for _, alg := range e.Algorithms {
		isStandardAlgorithm := alg == CertCompressionZlib || alg == CertCompressionBrotli || alg == CertCompressionZstd
		isExperimentalRange := alg >= 16384 && alg <= 65535
		if !isStandardAlgorithm && !isExperimentalRange {
			return 0, fmt.Errorf("tls: invalid certificate compression algorithm ID %d (valid: 1=zlib, 2=brotli, 3=zstd, or 16384-65535 for experimental)", alg)
		}
	}

	b[0] = byte(utlsExtensionCompressCertificate >> 8)
	b[1] = byte(utlsExtensionCompressCertificate & 0xff)

	extLen := 2 * len(e.Algorithms)

	// Extension data length.
	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte((extLen + 1) & 0xff)

	// Methods length.
	b[4] = byte(extLen)

	i := 5
	for _, compMethod := range e.Algorithms {
		b[i] = byte(compMethod >> 8)
		b[i+1] = byte(compMethod)
		i += 2
	}
	return e.Len(), io.EOF
}

func (e *UtlsCompressCertExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	methods := []CertCompressionAlgo{}
	methodsRaw := new(cryptobyte.String)
	if !extData.ReadUint8LengthPrefixed(methodsRaw) {
		return 0, errors.New("unable to read cert compression algorithms extension data")
	}
	for !methodsRaw.Empty() {
		var method uint16
		if !methodsRaw.ReadUint16(&method) {
			return 0, errors.New("unable to read cert compression algorithms extension data")
		}
		methods = append(methods, CertCompressionAlgo(method))
	}

	// Validate parsed algorithms per RFC 8879
	if len(methods) == 0 {
		return 0, errors.New("tls: compress_certificate extension requires at least one algorithm")
	}
	for _, alg := range methods {
		isStandardAlgorithm := alg == CertCompressionZlib || alg == CertCompressionBrotli || alg == CertCompressionZstd
		isExperimentalRange := alg >= 16384 && alg <= 65535
		if !isStandardAlgorithm && !isExperimentalRange {
			return 0, fmt.Errorf("tls: invalid certificate compression algorithm ID %d", alg)
		}
	}
	if !extData.Empty() {
		return 0, errors.New("tls: compress_certificate extension has trailing data")
	}

	e.Algorithms = methods
	return fullLen, nil
}

func (e *UtlsCompressCertExtension) UnmarshalJSON(b []byte) error {
	var certificateCompressionAlgorithms struct {
		Algorithms []string `json:"algorithms"`
	}
	if err := json.Unmarshal(b, &certificateCompressionAlgorithms); err != nil {
		return err
	}

	for _, algorithm := range certificateCompressionAlgorithms.Algorithms {
		if alg, ok := dicttls.DictCertificateCompressionAlgorithmNameIndexed[algorithm]; ok {
			e.Algorithms = append(e.Algorithms, CertCompressionAlgo(alg))
		} else {
			return fmt.Errorf("unknown certificate compression algorithm %s", algorithm)
		}
	}
	return nil
}

// KeyShareExtension implements key_share (51) and is for TLS 1.3 only.
type KeyShareExtension struct {
	KeyShares []KeyShare
}

func (e *KeyShareExtension) Len() int {
	return 4 + 2 + e.keySharesLen()
}

func (e *KeyShareExtension) keySharesLen() int {
	extLen := 0
	for _, ks := range e.KeyShares {
		extLen += 4 + len(ks.Data)
	}
	return extLen
}

func (e *KeyShareExtension) Read(b []byte) (int, error) {
	// Validate all key shares before serialization (defense-in-depth)
	for i, ks := range e.KeyShares {
		// For Read, Data must be present and non-empty for non-GREASE groups
		// GREASE key shares can have any data including empty (RFC 8701)
		if len(ks.Data) == 0 && !isGREASEUint16(uint16(ks.Group)) && ks.Group != GREASE_PLACEHOLDER {
			return 0, fmt.Errorf("tls: key_share at index %d has empty key data", i)
		}
		// Validate group ID and key size
		if err := validateKeyShare(ks); err != nil {
			return 0, err
		}
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	b[0] = byte(extensionKeyShare >> 8)
	b[1] = byte(extensionKeyShare)
	keySharesLen := e.keySharesLen()
	b[2] = byte((keySharesLen + 2) >> 8)
	b[3] = byte(keySharesLen + 2)
	b[4] = byte((keySharesLen) >> 8)
	b[5] = byte(keySharesLen)

	i := 6
	for _, ks := range e.KeyShares {
		b[i] = byte(ks.Group >> 8)
		b[i+1] = byte(ks.Group)
		b[i+2] = byte(len(ks.Data) >> 8)
		b[i+3] = byte(len(ks.Data))
		copy(b[i+4:], ks.Data)
		i += 4 + len(ks.Data)
	}

	return e.Len(), io.EOF
}

func (e *KeyShareExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 8446, Section 4.2.8
	var clientShares cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&clientShares) {
		return 0, errors.New("unable to read key share extension data")
	}
	keyShares := []KeyShare{}
	for !clientShares.Empty() {
		var ks KeyShare
		var group uint16
		if !clientShares.ReadUint16(&group) ||
			!readUint16LengthPrefixed(&clientShares, &ks.Data) ||
			len(ks.Data) == 0 {
			return 0, errors.New("unable to read key share extension data")
		}
		ks.Group = CurveID(unGREASEUint16(group))
		// if not GREASE, key share data will be discarded as it should
		// be generated per connection
		if ks.Group != GREASE_PLACEHOLDER {
			ks.Data = nil
		}
		keyShares = append(keyShares, ks)
	}
	if !extData.Empty() {
		return 0, errors.New("tls: key_share extension has trailing data")
	}
	e.KeyShares = keyShares
	return fullLen, nil
}

// expectedKeyShareSize returns the expected public key size for a given curve ID.
// Returns -1 if the curve ID is unknown or variable-length (GREASE).
//
// Key sizes per RFC 8446 Section 4.2.8.2 and RFC 7748/SEC1:
//   - X25519: 32 bytes (RFC 7748)
//   - P-256: 65 bytes (SEC1 uncompressed point: 0x04 || x || y, 1+32+32)
//   - P-384: 97 bytes (SEC1 uncompressed point: 0x04 || x || y, 1+48+48)
//   - P-521: 133 bytes (SEC1 uncompressed point: 0x04 || x || y, 1+66+66)
//   - X25519MLKEM768: 1216 bytes (MLKEM768 encapsulation key (1184) + X25519 (32))
//   - X25519Kyber768Draft00: 1216 bytes (X25519 (32) + MLKEM768 encapsulation key (1184))
func expectedKeyShareSize(group CurveID) int {
	switch group {
	case X25519:
		return 32
	case CurveP256:
		return 65
	case CurveP384:
		return 97
	case CurveP521:
		return 133
	case X25519MLKEM768, X25519Kyber768Draft00:
		// MLKEM768 encapsulation key size (1184) + X25519 public key size (32)
		return 1184 + 32
	default:
		// GREASE or unknown curves return -1 (variable/unknown size)
		return -1
	}
}

// isValidKeyShareGroup returns true if the CurveID is a valid group for key shares.
// Valid groups are: standard ECDH curves, X25519, post-quantum hybrids, and GREASE.
func isValidKeyShareGroup(group CurveID) bool {
	switch group {
	case X25519, CurveP256, CurveP384, CurveP521:
		return true
	case X25519MLKEM768, X25519Kyber768Draft00:
		return true
	case GREASE_PLACEHOLDER:
		return true
	default:
		// Check if it's a GREASE value (pattern: 0x?a?a where ? are same nibble)
		return isGREASEUint16(uint16(group))
	}
}

// validateKeyShare validates a single KeyShare entry.
// Group ID is always validated. If Data is nil, size validation is skipped
// (key will be auto-generated). For GREASE values, any data is accepted (including empty).
// For known curves, the data length must match the expected public key size.
func validateKeyShare(ks KeyShare) error {
	// Always validate group ID first - invalid groups must be rejected
	// regardless of whether Data is present
	if !isValidKeyShareGroup(ks.Group) {
		return fmt.Errorf("tls: key_share has invalid group ID %d", ks.Group)
	}

	// For GREASE values, any data is valid including empty (RFC 8701)
	// CRITICAL: Check GREASE BEFORE empty data check - GREASE key shares may have
	// minimal data (single byte or empty) and this is valid per RFC 8701
	if ks.Group == GREASE_PLACEHOLDER || isGREASEUint16(uint16(ks.Group)) {
		return nil
	}

	// If Data is nil, key will be auto-generated - skip size validation
	// but group validation above ensures only valid groups reach key generation
	if ks.Data == nil {
		return nil
	}

	// Empty key data is invalid per RFC 8446 Section 4.2.8 (for non-GREASE groups)
	if len(ks.Data) == 0 {
		return fmt.Errorf("tls: key_share for group %d has empty key data", ks.Group)
	}

	// Validate key size for known curves
	expectedSize := expectedKeyShareSize(ks.Group)
	if expectedSize > 0 && len(ks.Data) != expectedSize {
		return fmt.Errorf("tls: key_share for group %d has invalid size %d (expected %d bytes)",
			ks.Group, len(ks.Data), expectedSize)
	}

	return nil
}

func (e *KeyShareExtension) writeToUConn(uc *UConn) error {
	// Validate all key shares before applying to connection
	for i, ks := range e.KeyShares {
		if err := validateKeyShare(ks); err != nil {
			return fmt.Errorf("tls: invalid key share at index %d: %w", i, err)
		}
	}
	uc.HandshakeState.Hello.KeyShares = e.KeyShares
	return nil
}

func (e *KeyShareExtension) UnmarshalJSON(b []byte) error {
	var keyShareClientHello struct {
		ClientShares []struct {
			Group       string  `json:"group"`
			KeyExchange []uint8 `json:"key_exchange"`
		} `json:"client_shares"`
	}
	if err := json.Unmarshal(b, &keyShareClientHello); err != nil {
		return err
	}

	for _, clientShare := range keyShareClientHello.ClientShares {
		if clientShare.Group == "GREASE" {
			e.KeyShares = append(e.KeyShares, KeyShare{
				Group: GREASE_PLACEHOLDER,
				Data:  clientShare.KeyExchange,
			})
			continue
		}

		if groupID, ok := dicttls.DictSupportedGroupsNameIndexed[clientShare.Group]; ok {
			ks := KeyShare{
				Group: CurveID(groupID),
				Data:  clientShare.KeyExchange,
			}
			e.KeyShares = append(e.KeyShares, ks)
		} else {
			return fmt.Errorf("unknown group %s", clientShare.Group)
		}
	}
	return nil
}

// QUICTransportParametersExtension implements quic_transport_parameters (57).
//
// Currently, it works as a fake extension and does not support parsing, since
// the QUICConn provided by this package does not really understand these
// parameters.
type QUICTransportParametersExtension struct {
	TransportParameters TransportParameters

	marshalResult []byte // TransportParameters will be marshaled into this slice
}

func (e *QUICTransportParametersExtension) Len() int {
	if e.marshalResult == nil {
		e.marshalResult = e.TransportParameters.Marshal()
	}
	return 4 + len(e.marshalResult)
}

func (e *QUICTransportParametersExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	// e.Len() is called above, which sets e.marshalResult via Marshal()
	// TLS extension data length is encoded as uint16, so max 65535 bytes
	if len(e.marshalResult) > 65535 {
		return 0, errors.New("tls: QUIC transport parameters too large for TLS extension (max 65535 bytes)")
	}

	b[0] = byte(extensionQUICTransportParameters >> 8)
	b[1] = byte(extensionQUICTransportParameters)
	b[2] = byte((len(e.marshalResult)) >> 8)
	b[3] = byte(len(e.marshalResult))
	copy(b[4:], e.marshalResult)

	return e.Len(), io.EOF
}

func (e *QUICTransportParametersExtension) writeToUConn(*UConn) error {
	// no need to set *UConn.quic.transportParams, since it is unused
	return nil
}

// PSKKeyExchangeModesExtension implements psk_key_exchange_modes (45).
type PSKKeyExchangeModesExtension struct {
	Modes []uint8
}

func (e *PSKKeyExchangeModesExtension) Len() int {
	return 4 + 1 + len(e.Modes)
}

func (e *PSKKeyExchangeModesExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	if len(e.Modes) > 255 {
		return 0, errors.New("too many PSK Key Exchange modes")
	}

	// RFC 8446 Section 4.2.9: modes list cannot be empty
	if len(e.Modes) == 0 {
		return 0, errors.New("tls: PSK key exchange modes list cannot be empty per RFC 8446")
	}

	// Validate mode values and check for duplicates
	seen := make(map[uint8]bool, len(e.Modes))
	for _, mode := range e.Modes {
		// Valid modes per RFC 8446: psk_ke (0) and psk_dhe_ke (1)
		if mode != pskModePlain && mode != pskModeDHE {
			return 0, fmt.Errorf("tls: invalid PSK key exchange mode %d, must be 0 (psk_ke) or 1 (psk_dhe_ke)", mode)
		}
		if seen[mode] {
			return 0, fmt.Errorf("tls: duplicate PSK key exchange mode %d", mode)
		}
		seen[mode] = true
	}

	b[0] = byte(extensionPSKModes >> 8)
	b[1] = byte(extensionPSKModes)

	modesLen := len(e.Modes)
	b[2] = byte((modesLen + 1) >> 8)
	b[3] = byte(modesLen + 1)
	b[4] = byte(modesLen)

	if len(e.Modes) > 0 {
		copy(b[5:], e.Modes)
	}

	return e.Len(), io.EOF
}

func (e *PSKKeyExchangeModesExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 8446, Section 4.2.9
	// TODO: PSK Modes have their own form of GREASE-ing which is not currently implemented
	// the current functionality will NOT re-GREASE/re-randomize these values when using a fingerprinted spec
	// https://github.com/refraction-networking/utls/pull/58#discussion_r522354105
	// https://tools.ietf.org/html/draft-ietf-tls-grease-01#section-2
	pskModes := []uint8{}
	if !readUint8LengthPrefixed(&extData, &pskModes) {
		return 0, errors.New("unable to read PSK extension data")
	}
	if !extData.Empty() {
		return 0, errors.New("tls: psk_key_exchange_modes extension has trailing data")
	}
	e.Modes = pskModes
	return fullLen, nil
}

func (e *PSKKeyExchangeModesExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.PskModes = e.Modes
	return nil
}

func (e *PSKKeyExchangeModesExtension) UnmarshalJSON(b []byte) error {
	var pskKeyExchangeModes struct {
		Modes []string `json:"ke_modes"`
	}
	if err := json.Unmarshal(b, &pskKeyExchangeModes); err != nil {
		return err
	}

	for _, mode := range pskKeyExchangeModes.Modes {
		if modeID, ok := dicttls.DictPSKKeyExchangeModeNameIndexed[mode]; ok {
			e.Modes = append(e.Modes, modeID)
		} else {
			return fmt.Errorf("unknown PSK Key Exchange Mode %s", mode)
		}
	}
	return nil
}

// SupportedVersionsExtension implements supported_versions (43).
type SupportedVersionsExtension struct {
	Versions []uint16
}

func (e *SupportedVersionsExtension) writeToUConn(uc *UConn) error {
	uc.HandshakeState.Hello.SupportedVersions = e.Versions
	return nil
}

func (e *SupportedVersionsExtension) Len() int {
	return 4 + 1 + (2 * len(e.Versions))
}

func (e *SupportedVersionsExtension) Read(b []byte) (int, error) {
	if len(e.Versions) == 0 {
		return 0, errors.New("tls: supported_versions extension cannot be empty")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	extLen := 2 * len(e.Versions)
	if extLen > 255 {
		return 0, errors.New("too many supported versions")
	}

	// Validate versions: must be valid TLS versions (0x0300-0x0304) or GREASE values
	// Also check for duplicates
	seen := make(map[uint16]struct{}, len(e.Versions))
	for _, v := range e.Versions {
		// Check for duplicates
		if _, exists := seen[v]; exists {
			return 0, fmt.Errorf("tls: duplicate version 0x%04x in supported_versions extension", v)
		}
		seen[v] = struct{}{}

		// Valid versions: SSL 3.0 (0x0300), TLS 1.0-1.3 (0x0301-0x0304), or GREASE values
		isValidTLSVersion := v >= VersionSSL30 && v <= VersionTLS13
		if !isValidTLSVersion && !isGREASEUint16(v) {
			return 0, fmt.Errorf("tls: invalid version 0x%04x in supported_versions extension", v)
		}
	}

	b[0] = byte(extensionSupportedVersions >> 8)
	b[1] = byte(extensionSupportedVersions)
	b[2] = byte((extLen + 1) >> 8)
	b[3] = byte(extLen + 1)
	b[4] = byte(extLen)

	i := 5
	for _, sv := range e.Versions {
		b[i] = byte(sv >> 8)
		b[i+1] = byte(sv)
		i += 2
	}
	return e.Len(), io.EOF
}

func (e *SupportedVersionsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	// RFC 8446, Section 4.2.1
	var versList cryptobyte.String
	if !extData.ReadUint8LengthPrefixed(&versList) || versList.Empty() {
		return 0, errors.New("unable to read supported versions extension data")
	}
	supportedVersions := []uint16{}
	for !versList.Empty() {
		var vers uint16
		if !versList.ReadUint16(&vers) {
			return 0, errors.New("unable to read supported versions extension data")
		}
		supportedVersions = append(supportedVersions, unGREASEUint16(vers))
	}
	if !extData.Empty() {
		return 0, errors.New("tls: supported_versions extension has trailing data")
	}
	e.Versions = supportedVersions
	return fullLen, nil
}

func (e *SupportedVersionsExtension) UnmarshalJSON(b []byte) error {
	var supportedVersions struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(b, &supportedVersions); err != nil {
		return err
	}

	for _, version := range supportedVersions.Versions {
		switch version {
		case "GREASE":
			e.Versions = append(e.Versions, GREASE_PLACEHOLDER)
		case "TLS 1.3":
			e.Versions = append(e.Versions, VersionTLS13)
		case "TLS 1.2":
			e.Versions = append(e.Versions, VersionTLS12)
		case "TLS 1.1":
			e.Versions = append(e.Versions, VersionTLS11)
		case "TLS 1.0":
			e.Versions = append(e.Versions, VersionTLS10)
		case "SSL 3.0": // deprecated
			// 	e.Versions = append(e.Versions, VersionSSL30)
			return fmt.Errorf("SSL 3.0 is deprecated")
		default:
			return fmt.Errorf("unknown version %s", version)
		}
	}
	return nil
}

// CookieExtension implements cookie (44).
// MUST NOT be part of initial ClientHello
type CookieExtension struct {
	Cookie []byte
}

func (e *CookieExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *CookieExtension) Len() int {
	// The total length of the Cookie extension is:
	// 2 bytes for ExtensionType (extensionCookie)
	// 2 bytes for OuterExtensionDataLength
	// 2 bytes for InnerCookieLength (len(e.Cookie))
	// N bytes for the Cookie data itself (e.Cookie)
	// So, total = 6 + len(e.Cookie)
	return 6 + len(e.Cookie)
}

func (e *CookieExtension) Read(b []byte) (int, error) {
	if len(e.Cookie) == 0 {
		return 0, errors.New("tls: cookie extension cannot have empty cookie")
	}
	if len(e.Cookie) > 65531 {
		return 0, errors.New("tls: cookie too long")
	}

	cookieLen := len(e.Cookie)

	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	// Extension type
	b[0] = byte(extensionCookie >> 8)
	b[1] = byte(extensionCookie)

	// Copied from BoringSSL https://boringssl.googlesource.com/boringssl.git/%2B/chromium-stable/ssl/extensions.cc#2465
	// Total extension_data length
	extDataLen := 2 + cookieLen // 2 bytes for cookie length + cookie
	b[2] = byte(extDataLen >> 8)
	b[3] = byte(extDataLen)

	// Cookie length
	b[4] = byte(cookieLen >> 8)
	b[5] = byte(cookieLen)

	// Cookie value
	copy(b[6:], e.Cookie)

	return e.Len(), io.EOF
}

func (e *CookieExtension) UnmarshalJSON(data []byte) error {
	var cookie struct {
		Cookie []uint8 `json:"cookie"`
	}
	if err := json.Unmarshal(data, &cookie); err != nil {
		return err
	}
	e.Cookie = []byte(cookie.Cookie)
	return nil
}

// NPNExtension implements next_protocol_negotiation (Not IANA assigned)
type NPNExtension struct {
	NextProtos []string
}

func (e *NPNExtension) writeToUConn(uc *UConn) error {
	// Validate NextProtos for later use (client selection after server response)
	// Per NPN spec, protocol names have the same constraints as ALPN
	for _, proto := range e.NextProtos {
		if len(proto) == 0 {
			return errors.New("tls: NPN protocol cannot be empty")
		}
		if len(proto) > 255 {
			return errors.New("tls: NPN protocol too long (max 255 bytes)")
		}
	}
	uc.config.NextProtos = e.NextProtos
	uc.HandshakeState.Hello.NextProtoNeg = true
	return nil
}

func (e *NPNExtension) Len() int {
	return 4
}

func (e *NPNExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[0] = byte(extensionNextProtoNeg >> 8)
	b[1] = byte(extensionNextProtoNeg & 0xff)
	// The length is always 0
	return e.Len(), io.EOF
}

// Write is a no-op for NPNExtension. NextProtos are not included in the
// ClientHello.
func (e *NPNExtension) Write(_ []byte) (int, error) {
	return 0, nil
}

// draft-agl-tls-nextprotoneg-04:
// The "extension_data" field of a "next_protocol_negotiation" extension
// in a "ClientHello" MUST be empty.
func (e *NPNExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

// RenegotiationInfoExtension implements renegotiation_info (65281)
type RenegotiationInfoExtension struct {
	// Renegotiation field limits how many times client will perform renegotiation: no limit, once, or never.
	// The extension still will be sent, even if Renegotiation is set to RenegotiateNever.
	Renegotiation RenegotiationSupport // [UTLS] added for internal use only

	// RenegotiatedConnection is not yet properly handled, now we
	// are just copying it to the client hello.
	//
	// If this is the initial handshake for a connection, then the
	// "renegotiated_connection" field is of zero length in both the
	// ClientHello and the ServerHello.
	RenegotiatedConnection []byte
}

func (e *RenegotiationInfoExtension) Len() int {
	return 5 + len(e.RenegotiatedConnection)
}

func (e *RenegotiationInfoExtension) Read(b []byte) (int, error) {
	// RFC 5746: renegotiated_connection is prefixed with 1-byte length, max 255 bytes
	if len(e.RenegotiatedConnection) > 255 {
		return 0, errors.New("tls: renegotiation_info data exceeds maximum length of 255 bytes")
	}

	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}

	dataLen := len(e.RenegotiatedConnection)
	extBodyLen := 1 + dataLen

	b[0] = byte(extensionRenegotiationInfo >> 8)
	b[1] = byte(extensionRenegotiationInfo & 0xff)
	b[2] = byte(extBodyLen >> 8)
	b[3] = byte(extBodyLen)
	b[4] = byte(dataLen)
	copy(b[5:], e.RenegotiatedConnection)

	return e.Len(), io.EOF
}

func (e *RenegotiationInfoExtension) UnmarshalJSON(_ []byte) error {
	e.Renegotiation = RenegotiateOnceAsClient
	return nil
}

func (e *RenegotiationInfoExtension) Write(b []byte) (int, error) {
	e.Renegotiation = RenegotiateOnceAsClient // none empty or other modes are unsupported
	// extData := cryptobyte.String(b)
	// var renegotiatedConnection cryptobyte.String
	// if !extData.ReadUint8LengthPrefixed(&renegotiatedConnection) || !extData.Empty() {
	// 	return 0, errors.New("unable to read renegotiation info extension data")
	// }
	// e.RenegotiatedConnection = make([]byte, len(renegotiatedConnection))
	// copy(e.RenegotiatedConnection, renegotiatedConnection)

	// we don't really want to parse it at all.

	return len(b), nil
}

func (e *RenegotiationInfoExtension) writeToUConn(uc *UConn) error {
	uc.config.Renegotiation = e.Renegotiation
	switch e.Renegotiation {
	case RenegotiateOnceAsClient:
		fallthrough
	case RenegotiateFreelyAsClient:
		uc.HandshakeState.Hello.SecureRenegotiationSupported = true
		// TODO: don't do backward propagation here
		if uc.handshakes > 0 {
			e.RenegotiatedConnection = uc.clientFinished[:]
		}
	case RenegotiateNever:
	default:
	}
	return nil
}

/*
FAKE EXTENSIONS
*/

type FakeChannelIDExtension struct {
	// The extension ID changed from 30031 to 30032. Set to true to use the old extension ID.
	OldExtensionID bool
}

func (e *FakeChannelIDExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeChannelIDExtension) Len() int {
	return 4
}

func (e *FakeChannelIDExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	extensionID := fakeExtensionChannelID
	if e.OldExtensionID {
		extensionID = fakeOldExtensionChannelID
	}
	// https://tools.ietf.org/html/draft-balfanz-tls-channelid-00
	b[0] = byte(extensionID >> 8)
	b[1] = byte(extensionID & 0xff)
	// Zero-length extension data (signals support without payload)
	b[2] = 0
	b[3] = 0
	return e.Len(), io.EOF
}

func (e *FakeChannelIDExtension) Write(b []byte) (int, error) {
	// draft-balfanz-tls-channelid: Channel ID extension has zero-length data.
	// This is a flag-only extension signaling support without payload.
	if len(b) != 0 {
		return 0, errors.New("tls: channel_id extension must have empty data")
	}
	return 0, nil
}

func (e *FakeChannelIDExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

// FakeEncryptThenMACExtension implements encrypt_then_mac (22)
// RFC 7366: This is a flag extension with no data payload.
// The client sends this to indicate support for encrypt-then-MAC mode.
type FakeEncryptThenMACExtension struct{}

func (e *FakeEncryptThenMACExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeEncryptThenMACExtension) Len() int {
	return 4
}

func (e *FakeEncryptThenMACExtension) Read(b []byte) (int, error) {
	if len(b) < 4 {
		return 0, io.ErrShortBuffer
	}
	// RFC 7366: encrypt_then_mac extension type
	b[0] = byte(fakeExtensionEncryptThenMAC >> 8)
	b[1] = byte(fakeExtensionEncryptThenMAC)
	// Zero-length extension data (flag-only extension, no payload)
	b[2] = 0
	b[3] = 0
	return 4, io.EOF
}

func (e *FakeEncryptThenMACExtension) Write(b []byte) (int, error) {
	// RFC 7366: encrypt_then_mac extension MUST have zero-length extension_data.
	// This is a flag-only extension with no payload.
	if len(b) != 0 {
		return 0, errors.New("tls: encrypt_then_mac extension must have empty data per RFC 7366")
	}
	return 0, nil
}

func (e *FakeEncryptThenMACExtension) UnmarshalJSON(_ []byte) error {
	return nil
}

// FakeRecordSizeLimitExtension implements record_size_limit (28)
// but with no support.
type FakeRecordSizeLimitExtension struct {
	Limit uint16
}

func (e *FakeRecordSizeLimitExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeRecordSizeLimitExtension) Len() int {
	return 6
}

func (e *FakeRecordSizeLimitExtension) Read(b []byte) (int, error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// RFC 8449: record_size_limit must be between 64 and 16385 (2^14+1)
	if e.Limit < 64 || e.Limit > 16385 {
		return 0, errors.New("tls: record_size_limit must be between 64 and 16385")
	}
	b[0] = byte(fakeRecordSizeLimit >> 8)
	b[1] = byte(fakeRecordSizeLimit & 0xff)

	b[2] = byte(0)
	b[3] = byte(2)

	b[4] = byte(e.Limit >> 8)
	b[5] = byte(e.Limit & 0xff)
	return e.Len(), io.EOF
}

func (e *FakeRecordSizeLimitExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	if !extData.ReadUint16(&e.Limit) {
		return 0, errors.New("unable to read record size limit extension data")
	}
	// RFC 8449: record_size_limit must be between 64 and 16385 (2^14+1)
	if e.Limit < 64 || e.Limit > 16385 {
		return 0, errors.New("tls: record_size_limit must be between 64 and 16385")
	}
	return fullLen, nil
}

func (e *FakeRecordSizeLimitExtension) UnmarshalJSON(data []byte) error {
	var limitAccepter struct {
		Limit uint16 `json:"record_size_limit"`
	}
	if err := json.Unmarshal(data, &limitAccepter); err != nil {
		return err
	}

	e.Limit = limitAccepter.Limit
	return nil
}

type DelegatedCredentialsExtension = FakeDelegatedCredentialsExtension

// https://tools.ietf.org/html/rfc8472#section-2
type FakeTokenBindingExtension struct {
	MajorVersion, MinorVersion uint8
	KeyParameters              []uint8
}

func (e *FakeTokenBindingExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeTokenBindingExtension) Len() int {
	// extension ID + data length + versions + key parameters length + key parameters
	return 2 + 2 + 2 + 1 + len(e.KeyParameters)
}

func (e *FakeTokenBindingExtension) Read(b []byte) (int, error) {
	// Validate key parameters list is not empty
	if len(e.KeyParameters) == 0 {
		return 0, errors.New("tls: token_binding extension requires at least one key parameter")
	}
	// Key parameters length is stored in a single byte (uint8), max 255
	if len(e.KeyParameters) > 255 {
		return 0, errors.New("tls: token_binding extension key parameters list too long (max 255)")
	}
	// Validate version is reasonable (RFC 8472 defines version 1.0)
	// Allow some flexibility for future versions but catch obviously invalid values
	if e.MajorVersion > 10 {
		return 0, fmt.Errorf("tls: token_binding extension major version %d exceeds reasonable maximum (10)", e.MajorVersion)
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	dataLen := e.Len() - 4
	b[0] = byte(fakeExtensionTokenBinding >> 8)
	b[1] = byte(fakeExtensionTokenBinding & 0xff)
	b[2] = byte(dataLen >> 8)
	b[3] = byte(dataLen & 0xff)
	b[4] = e.MajorVersion
	b[5] = e.MinorVersion
	b[6] = byte(len(e.KeyParameters))
	if len(e.KeyParameters) > 0 {
		copy(b[7:], e.KeyParameters)
	}
	return e.Len(), io.EOF
}

func (e *FakeTokenBindingExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	var keyParameters cryptobyte.String
	if !extData.ReadUint8(&e.MajorVersion) ||
		!extData.ReadUint8(&e.MinorVersion) ||
		!extData.ReadUint8LengthPrefixed(&keyParameters) {
		return 0, errors.New("unable to read token binding extension data")
	}
	if !extData.Empty() {
		return 0, errors.New("tls: token_binding extension has trailing data")
	}
	e.KeyParameters = keyParameters
	return fullLen, nil
}

func (e *FakeTokenBindingExtension) UnmarshalJSON(data []byte) error {
	var tokenBindingAccepter struct {
		TB_ProtocolVersion struct {
			Major uint8 `json:"major"`
			Minor uint8 `json:"minor"`
		} `json:"token_binding_version"`
		TokenBindingKeyParameters []string `json:"key_parameters_list"`
	}
	if err := json.Unmarshal(data, &tokenBindingAccepter); err != nil {
		return err
	}

	e.MajorVersion = tokenBindingAccepter.TB_ProtocolVersion.Major
	e.MinorVersion = tokenBindingAccepter.TB_ProtocolVersion.Minor
	for _, param := range tokenBindingAccepter.TokenBindingKeyParameters {
		switch param {
		case "rsa2048_pkcs1.5":
			e.KeyParameters = append(e.KeyParameters, 0)
		case "rsa2048_pss":
			e.KeyParameters = append(e.KeyParameters, 1)
		case "ecdsap256":
			e.KeyParameters = append(e.KeyParameters, 2)
		default:
			return fmt.Errorf("unknown token binding key parameter: %s", param)
		}
	}
	return nil
}

// https://datatracker.ietf.org/doc/html/draft-ietf-tls-subcerts-15#section-4.1.1

type FakeDelegatedCredentialsExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *FakeDelegatedCredentialsExtension) writeToUConn(uc *UConn) error {
	return nil
}

func (e *FakeDelegatedCredentialsExtension) Len() int {
	return 6 + 2*len(e.SupportedSignatureAlgorithms)
}

func (e *FakeDelegatedCredentialsExtension) Read(b []byte) (int, error) {
	if len(e.SupportedSignatureAlgorithms) == 0 {
		return 0, errors.New("tls: delegated_credentials extension requires at least one signature algorithm")
	}
	// 2 bytes per algorithm, 2 byte length prefix, max 65533 for data in uint16 field
	// (65535 - 2 byte list length prefix) / 2 = 32766 max algorithms
	if len(e.SupportedSignatureAlgorithms) > 32766 {
		return 0, errors.New("tls: too many signature algorithms in delegated_credentials")
	}
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	// https://datatracker.ietf.org/doc/html/draft-ietf-tls-subcerts-15#section-4.1.1
	b[0] = byte(fakeExtensionDelegatedCredentials >> 8)
	b[1] = byte(fakeExtensionDelegatedCredentials)
	b[2] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)) >> 8)
	b[3] = byte((2 + 2*len(e.SupportedSignatureAlgorithms)))
	b[4] = byte((2 * len(e.SupportedSignatureAlgorithms)) >> 8)
	b[5] = byte((2 * len(e.SupportedSignatureAlgorithms)))
	for i, sigAndHash := range e.SupportedSignatureAlgorithms {
		b[6+2*i] = byte(sigAndHash >> 8)
		b[7+2*i] = byte(sigAndHash)
	}
	return e.Len(), io.EOF
}

func (e *FakeDelegatedCredentialsExtension) Write(b []byte) (int, error) {
	fullLen := len(b)
	extData := cryptobyte.String(b)
	//https://datatracker.ietf.org/doc/html/draft-ietf-tls-subcerts-15#section-4.1.1
	var supportedAlgs cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&supportedAlgs) || supportedAlgs.Empty() {
		return 0, errors.New("unable to read signature algorithms extension data")
	}
	supportedSignatureAlgorithms := []SignatureScheme{}
	for !supportedAlgs.Empty() {
		var sigAndAlg uint16
		if !supportedAlgs.ReadUint16(&sigAndAlg) {
			return 0, errors.New("unable to read signature algorithms extension data")
		}
		supportedSignatureAlgorithms = append(
			supportedSignatureAlgorithms, SignatureScheme(sigAndAlg))
	}
	if !extData.Empty() {
		return 0, errors.New("tls: delegated_credentials extension has trailing data")
	}
	e.SupportedSignatureAlgorithms = supportedSignatureAlgorithms
	return fullLen, nil
}

// Implementation copied from SignatureAlgorithmsExtension.UnmarshalJSON
func (e *FakeDelegatedCredentialsExtension) UnmarshalJSON(data []byte) error {
	var signatureAlgorithms struct {
		Algorithms []string `json:"supported_signature_algorithms"`
	}
	if err := json.Unmarshal(data, &signatureAlgorithms); err != nil {
		return err
	}

	for _, sigScheme := range signatureAlgorithms.Algorithms {
		if sigScheme == "GREASE" {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, GREASE_PLACEHOLDER)
			continue
		}

		if scheme, ok := dicttls.DictSignatureSchemeNameIndexed[sigScheme]; ok {
			e.SupportedSignatureAlgorithms = append(e.SupportedSignatureAlgorithms, SignatureScheme(scheme))
		} else {
			return fmt.Errorf("unknown delegated credentials signature scheme: %s", sigScheme)
		}
	}
	return nil
}
