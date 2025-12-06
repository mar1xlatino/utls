// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls13 implements the TLS 1.3 Key Schedule as specified in RFC 8446,
// Section 7.1 and allowed by FIPS 140-3 IG 2.4.B Resolution 7.
package tls13

import (
	"errors"
	"hash"

	"github.com/refraction-networking/utls/internal/byteorder"
	"github.com/refraction-networking/utls/internal/hkdf"
)

// ErrLabelTooLong is returned when the label or context passed to ExpandLabel
// exceeds the maximum allowed length (255 bytes for "tls13 "+label, 255 bytes for context).
var ErrLabelTooLong = errors.New("tls13: label or context too long")

// We don't set the service indicator in this package but we delegate that to
// the underlying functions because the TLS 1.3 KDF does not have a standard of
// its own.

// ExpandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
// Returns ErrLabelTooLong if the label (including "tls13 " prefix) or context
// exceeds 255 bytes.
func ExpandLabel[H hash.Hash](h func() H, secret []byte, label string, context []byte, length int) ([]byte, error) {
	if len("tls13 ")+len(label) > 255 || len(context) > 255 {
		return nil, ErrLabelTooLong
	}
	hkdfLabel := make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
	hkdfLabel = byteorder.BEAppendUint16(hkdfLabel, uint16(length))
	hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
	hkdfLabel = append(hkdfLabel, "tls13 "...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	return hkdf.Expand(h, secret, string(hkdfLabel), length)
}

func extract[H hash.Hash](h func() H, newSecret, currentSecret []byte) ([]byte, error) {
	if newSecret == nil {
		newSecret = make([]byte, h().Size())
	}
	return hkdf.Extract(h, newSecret, currentSecret)
}

func deriveSecret[H hash.Hash](h func() H, secret []byte, label string, transcript hash.Hash) ([]byte, error) {
	if transcript == nil {
		transcript = h()
	}
	return ExpandLabel(h, secret, label, transcript.Sum(nil), transcript.Size())
}

const (
	resumptionBinderLabel         = "res binder"
	clientEarlyTrafficLabel       = "c e traffic"
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	earlyExporterLabel            = "e exp master"
	exporterLabel                 = "exp master"
	resumptionLabel               = "res master"
)

type EarlySecret struct {
	secret []byte
	hash   func() hash.Hash
}

func NewEarlySecret[H hash.Hash](h func() H, psk []byte) (*EarlySecret, error) {
	secret, err := extract(h, psk, nil)
	if err != nil {
		return nil, err
	}
	return &EarlySecret{
		secret: secret,
		hash:   func() hash.Hash { return h() },
	}, nil
}

func (s *EarlySecret) ResumptionBinderKey() ([]byte, error) {
	return deriveSecret(s.hash, s.secret, resumptionBinderLabel, nil)
}

// ClientEarlyTrafficSecret derives the client_early_traffic_secret from the
// early secret and the transcript up to the ClientHello.
func (s *EarlySecret) ClientEarlyTrafficSecret(transcript hash.Hash) ([]byte, error) {
	return deriveSecret(s.hash, s.secret, clientEarlyTrafficLabel, transcript)
}

type HandshakeSecret struct {
	secret []byte
	hash   func() hash.Hash
}

func (s *EarlySecret) HandshakeSecret(sharedSecret []byte) (*HandshakeSecret, error) {
	derived, err := deriveSecret(s.hash, s.secret, "derived", nil)
	if err != nil {
		return nil, err
	}
	secret, err := extract(s.hash, sharedSecret, derived)
	if err != nil {
		return nil, err
	}
	return &HandshakeSecret{
		secret: secret,
		hash:   s.hash,
	}, nil
}

// ClientHandshakeTrafficSecret derives the client_handshake_traffic_secret from
// the handshake secret and the transcript up to the ServerHello.
func (s *HandshakeSecret) ClientHandshakeTrafficSecret(transcript hash.Hash) ([]byte, error) {
	return deriveSecret(s.hash, s.secret, clientHandshakeTrafficLabel, transcript)
}

// ServerHandshakeTrafficSecret derives the server_handshake_traffic_secret from
// the handshake secret and the transcript up to the ServerHello.
func (s *HandshakeSecret) ServerHandshakeTrafficSecret(transcript hash.Hash) ([]byte, error) {
	return deriveSecret(s.hash, s.secret, serverHandshakeTrafficLabel, transcript)
}

type MasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

func (s *HandshakeSecret) MasterSecret() (*MasterSecret, error) {
	derived, err := deriveSecret(s.hash, s.secret, "derived", nil)
	if err != nil {
		return nil, err
	}
	secret, err := extract(s.hash, nil, derived)
	if err != nil {
		return nil, err
	}
	return &MasterSecret{
		secret: secret,
		hash:   s.hash,
	}, nil
}

// ClientApplicationTrafficSecret derives the client_application_traffic_secret_0
// from the master secret and the transcript up to the server Finished.
func (s *MasterSecret) ClientApplicationTrafficSecret(transcript hash.Hash) ([]byte, error) {
	return deriveSecret(s.hash, s.secret, clientApplicationTrafficLabel, transcript)
}

// ServerApplicationTrafficSecret derives the server_application_traffic_secret_0
// from the master secret and the transcript up to the server Finished.
func (s *MasterSecret) ServerApplicationTrafficSecret(transcript hash.Hash) ([]byte, error) {
	return deriveSecret(s.hash, s.secret, serverApplicationTrafficLabel, transcript)
}

// ResumptionMasterSecret derives the resumption_master_secret from the master secret
// and the transcript up to the client Finished.
func (s *MasterSecret) ResumptionMasterSecret(transcript hash.Hash) ([]byte, error) {
	return deriveSecret(s.hash, s.secret, resumptionLabel, transcript)
}

type ExporterMasterSecret struct {
	secret []byte
	hash   func() hash.Hash
}

// ExporterMasterSecret derives the exporter_master_secret from the master secret
// and the transcript up to the server Finished.
func (s *MasterSecret) ExporterMasterSecret(transcript hash.Hash) (*ExporterMasterSecret, error) {
	secret, err := deriveSecret(s.hash, s.secret, exporterLabel, transcript)
	if err != nil {
		return nil, err
	}
	return &ExporterMasterSecret{
		secret: secret,
		hash:   s.hash,
	}, nil
}

// EarlyExporterMasterSecret derives the exporter_master_secret from the early secret
// and the transcript up to the ClientHello.
func (s *EarlySecret) EarlyExporterMasterSecret(transcript hash.Hash) (*ExporterMasterSecret, error) {
	secret, err := deriveSecret(s.hash, s.secret, earlyExporterLabel, transcript)
	if err != nil {
		return nil, err
	}
	return &ExporterMasterSecret{
		secret: secret,
		hash:   s.hash,
	}, nil
}

func (s *ExporterMasterSecret) Exporter(label string, context []byte, length int) ([]byte, error) {
	secret, err := deriveSecret(s.hash, s.secret, label, nil)
	if err != nil {
		return nil, err
	}
	h := s.hash()
	h.Write(context)
	return ExpandLabel(s.hash, secret, "exporter", h.Sum(nil), length)
}

func TestingOnlyExporterSecret(s *ExporterMasterSecret) []byte {
	return s.secret
}
