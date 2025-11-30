// Copyright 2024 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
	"time"
)

// ServerProfile defines server response fingerprint characteristics for JA4S/JA4X control.
type ServerProfile struct {
	ID          string
	Name        string
	Description string

	// ServerHello configuration
	ServerHello ServerHelloConfig

	// Certificate configuration
	Certificate CertificateConfig

	// Session ticket configuration
	SessionTicket SessionTicketServerConfig

	// Expected JA4S fingerprint
	ExpectedJA4S string
}

// ServerHelloConfig defines how to build ServerHello responses.
type ServerHelloConfig struct {
	// Cipher selection mode: "client" (prefer client order) or "server" (prefer server order)
	CipherSelectionMode string

	// Server's preferred cipher order (used when CipherSelectionMode is "server")
	CipherPreference []uint16

	// Extensions to include in ServerHello
	Extensions []uint16

	// Extension order (if specific order needed)
	ExtensionOrder []uint16

	// Session ID behavior: "echo" (echo client), "random", "none"
	SessionIDMode string

	// Session ID length when mode is "random"
	SessionIDLength int

	// ALPN selection preference
	ALPNPreference []string

	// Key share selection preference
	KeySharePreference []CurveID

	// Supported versions to advertise
	SupportedVersions []uint16
}

// CertificateConfig defines certificate generation parameters for JA4X control.
type CertificateConfig struct {
	// Issuer RDN configuration (controls JA4X issuer hash)
	Issuer RDNConfig

	// Subject RDN configuration (controls JA4X subject hash)
	Subject RDNConfig

	// Extensions (controls JA4X extension hash)
	Extensions CertExtensionConfig

	// Key configuration
	KeyType string // "rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ed25519"

	// Validity
	NotBeforeOffset time.Duration
	ValidityPeriod  time.Duration

	// Serial number generation
	SerialNumberBits int

	// Expected JA4X fingerprint
	ExpectedJA4X string
}

// RDNConfig defines RDN field order and values.
// Order matters for JA4X fingerprint calculation.
type RDNConfig struct {
	Fields []RDNField
}

// RDNField is a single RDN field.
type RDNField struct {
	OID   asn1.ObjectIdentifier
	Value string
}

// Common RDN OIDs for certificate configuration.
var (
	OIDCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	OIDOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	OIDOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	OIDCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	OIDLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	OIDProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	OIDStreetAddress      = asn1.ObjectIdentifier{2, 5, 4, 9}
	OIDPostalCode         = asn1.ObjectIdentifier{2, 5, 4, 17}
	OIDSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
)

// CertExtensionConfig defines which extensions to include in certificates.
type CertExtensionConfig struct {
	// Extensions in order (order matters for JA4X)
	Extensions []CertExtensionDef
}

// CertExtensionDef is a single certificate extension definition.
type CertExtensionDef struct {
	OID      asn1.ObjectIdentifier
	Critical bool
	Value    interface{}
}

// Common certificate extension OIDs.
var (
	OIDBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	OIDKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	OIDAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	OIDSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17}
	OIDCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31}
	OIDAuthorityInfoAccess    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OIDCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32}
	OIDSCT                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// SessionTicketServerConfig defines session ticket behavior.
type SessionTicketServerConfig struct {
	Enabled        bool
	Lifetime       time.Duration
	RotationPeriod time.Duration
}

// ServerProfileRegistry manages server profiles.
type ServerProfileRegistry struct {
	profiles map[string]*ServerProfile
	mu       sync.RWMutex
}

// NewServerProfileRegistry creates a new server profile registry.
func NewServerProfileRegistry() *ServerProfileRegistry {
	return &ServerProfileRegistry{
		profiles: make(map[string]*ServerProfile),
	}
}

// Register adds a server profile to the registry.
func (r *ServerProfileRegistry) Register(profile *ServerProfile) error {
	if profile == nil || profile.ID == "" {
		return errors.New("invalid profile: nil or empty ID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.profiles[profile.ID] = profile
	return nil
}

// Get retrieves a server profile by ID.
func (r *ServerProfileRegistry) Get(id string) (*ServerProfile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[id]
	return p, ok
}

// List returns all registered server profile IDs.
func (r *ServerProfileRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.profiles))
	for id := range r.profiles {
		ids = append(ids, id)
	}
	return ids
}

// DefaultServerProfileRegistry is the global server profile registry.
var DefaultServerProfileRegistry = NewServerProfileRegistry()

// Built-in server profiles for common server software.
var (
	CloudflareServerProfile = &ServerProfile{
		ID:          "cloudflare",
		Name:        "Cloudflare Edge",
		Description: "Cloudflare CDN edge server fingerprint",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			Extensions:      []uint16{51, 43}, // key_share, supported_versions
			SessionIDMode:   "random",
			SessionIDLength: 32,
			ALPNPreference:  []string{"h2", "http/1.1"},
		},
		Certificate: CertificateConfig{
			Issuer: RDNConfig{
				Fields: []RDNField{
					{OID: OIDCountry, Value: "US"},
					{OID: OIDOrganization, Value: "Cloudflare, Inc."},
					{OID: OIDCommonName, Value: "Cloudflare Inc ECC CA-3"},
				},
			},
			KeyType:        "ecdsa-p256",
			ValidityPeriod: 365 * 24 * time.Hour,
		},
	}

	NginxServerProfile = &ServerProfile{
		ID:          "nginx",
		Name:        "Nginx",
		Description: "Nginx web server fingerprint",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference: []uint16{
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
				TLS_AES_128_GCM_SHA256,
			},
			SessionIDMode:   "random",
			SessionIDLength: 32,
			ALPNPreference:  []string{"h2", "http/1.1"},
		},
		Certificate: CertificateConfig{
			KeyType:        "rsa-2048",
			ValidityPeriod: 90 * 24 * time.Hour,
		},
	}

	ApacheServerProfile = &ServerProfile{
		ID:          "apache",
		Name:        "Apache",
		Description: "Apache HTTPD server fingerprint",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "client",
			SessionIDMode:       "echo",
			ALPNPreference:      []string{"h2", "http/1.1"},
		},
		Certificate: CertificateConfig{
			KeyType:        "rsa-2048",
			ValidityPeriod: 365 * 24 * time.Hour,
		},
	}

	GoStdlibServerProfile = &ServerProfile{
		ID:          "go-stdlib",
		Name:        "Go Stdlib",
		Description: "Go standard library TLS server fingerprint",
		ServerHello: ServerHelloConfig{
			CipherSelectionMode: "server",
			CipherPreference: []uint16{
				TLS_AES_128_GCM_SHA256,
				TLS_AES_256_GCM_SHA384,
				TLS_CHACHA20_POLY1305_SHA256,
			},
			SessionIDMode:   "random",
			SessionIDLength: 32,
			// Go stdlib accepts ALPN from client but doesn't have explicit preference
			// It uses the first mutually supported protocol
			ALPNPreference: []string{"h2", "http/1.1"},
		},
		Certificate: CertificateConfig{
			KeyType:        "ecdsa-p256",
			ValidityPeriod: 365 * 24 * time.Hour,
		},
	}
)

// init registers built-in server profiles.
func init() {
	DefaultServerProfileRegistry.Register(CloudflareServerProfile)
	DefaultServerProfileRegistry.Register(NginxServerProfile)
	DefaultServerProfileRegistry.Register(ApacheServerProfile)
	DefaultServerProfileRegistry.Register(GoStdlibServerProfile)
}

// GenerateKey generates a private key based on the key type string.
func GenerateKey(keyType string) (crypto.PrivateKey, error) {
	switch keyType {
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, errors.New("unsupported key type: " + keyType)
	}
}

// GenerateCertificate generates a self-signed certificate matching the profile configuration.
// Note: For self-signed certificates, the issuer field will always equal the subject field
// per X.509 standard. To have a different issuer (for JA4X fingerprint control), use
// GenerateCertificateChain with chainLength > 1, which creates a CA with the desired
// issuer and signs the leaf certificate with it.
func GenerateCertificate(config *CertificateConfig, hostname string) (*x509.Certificate, crypto.PrivateKey, error) {
	if config == nil {
		return nil, nil, errors.New("nil certificate config")
	}

	// Generate key
	keyType := config.KeyType
	if keyType == "" {
		keyType = "ecdsa-p256"
	}
	priv, err := GenerateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	// Generate serial number
	serialBits := config.SerialNumberBits
	if serialBits <= 0 {
		serialBits = 128
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(serialBits)))
	if err != nil {
		return nil, nil, err
	}

	// Calculate validity period
	notBefore := time.Now().Add(config.NotBeforeOffset)
	validity := config.ValidityPeriod
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}
	notAfter := notBefore.Add(validity)

	// Build subject
	subject := buildPkixName(config.Subject)
	if subject.CommonName == "" && hostname != "" {
		subject.CommonName = hostname
	}

	// Build issuer (for self-signed, same as subject)
	issuer := buildPkixName(config.Issuer)
	if len(issuer.Names) == 0 {
		issuer = subject
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                issuer,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs
	if hostname != "" {
		template.DNSNames = []string{hostname}
	}

	// Get public key
	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		return nil, nil, errors.New("unsupported private key type")
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// buildPkixName builds a pkix.Name from RDNConfig.
func buildPkixName(config RDNConfig) pkix.Name {
	name := pkix.Name{}
	for _, field := range config.Fields {
		name.Names = append(name.Names, pkix.AttributeTypeAndValue{
			Type:  field.OID,
			Value: field.Value,
		})

		// Also set specific fields for convenience
		switch {
		case field.OID.Equal(OIDCountry):
			name.Country = []string{field.Value}
		case field.OID.Equal(OIDOrganization):
			name.Organization = []string{field.Value}
		case field.OID.Equal(OIDOrganizationalUnit):
			name.OrganizationalUnit = []string{field.Value}
		case field.OID.Equal(OIDCommonName):
			name.CommonName = field.Value
		case field.OID.Equal(OIDLocality):
			name.Locality = []string{field.Value}
		case field.OID.Equal(OIDProvince):
			name.Province = []string{field.Value}
		}
	}
	return name
}

// GenerateCertificateChain generates a certificate chain with the specified length.
// If chainLength is 1, generates a self-signed leaf certificate (issuer == subject).
// If chainLength > 1, generates a CA certificate with custom issuer, then signs leaf cert with it.
// This allows control over the JA4X fingerprint's issuer hash component.
func GenerateCertificateChain(config *CertificateConfig, hostname string, chainLength int) ([]*x509.Certificate, crypto.PrivateKey, error) {
	if chainLength < 1 {
		chainLength = 1
	}

	if chainLength == 1 {
		// Self-signed certificate - issuer will equal subject per X.509 spec
		cert, priv, err := GenerateCertificate(config, hostname)
		if err != nil {
			return nil, nil, err
		}
		return []*x509.Certificate{cert}, priv, nil
	}

	// Generate CA certificate first with custom issuer config
	// For a CA, the issuer equals subject (it's self-signed)
	caConfig := &CertificateConfig{
		Subject:          config.Issuer, // CA's subject = desired issuer
		KeyType:          config.KeyType,
		ValidityPeriod:   config.ValidityPeriod * 2, // CA lives longer
		SerialNumberBits: config.SerialNumberBits,
	}
	if caConfig.Subject.Fields == nil {
		// Default CA subject if no issuer configured
		caConfig.Subject = RDNConfig{
			Fields: []RDNField{
				{OID: OIDOrganization, Value: "Generated CA"},
				{OID: OIDCommonName, Value: "Generated CA"},
			},
		}
	}

	caCert, caPriv, err := generateCACertificate(caConfig)
	if err != nil {
		return nil, nil, err
	}

	// Generate leaf certificate signed by CA
	leafCert, leafPriv, err := generateLeafCertificate(config, hostname, caCert, caPriv)
	if err != nil {
		return nil, nil, err
	}

	// Return chain: [leaf, CA] with leaf's private key
	return []*x509.Certificate{leafCert, caCert}, leafPriv, nil
}

// generateCACertificate creates a CA certificate for signing leaf certs.
func generateCACertificate(config *CertificateConfig) (*x509.Certificate, crypto.PrivateKey, error) {
	keyType := config.KeyType
	if keyType == "" {
		keyType = "ecdsa-p256"
	}
	priv, err := GenerateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	serialBits := config.SerialNumberBits
	if serialBits <= 0 {
		serialBits = 128
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(serialBits)))
	if err != nil {
		return nil, nil, err
	}

	validity := config.ValidityPeriod
	if validity <= 0 {
		validity = 10 * 365 * 24 * time.Hour // 10 years for CA
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(validity)

	subject := buildPkixName(config.Subject)

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		return nil, nil, errors.New("unsupported private key type")
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// generateLeafCertificate creates a leaf certificate signed by a CA.
func generateLeafCertificate(config *CertificateConfig, hostname string, caCert *x509.Certificate, caPriv crypto.PrivateKey) (*x509.Certificate, crypto.PrivateKey, error) {
	keyType := config.KeyType
	if keyType == "" {
		keyType = "ecdsa-p256"
	}
	priv, err := GenerateKey(keyType)
	if err != nil {
		return nil, nil, err
	}

	serialBits := config.SerialNumberBits
	if serialBits <= 0 {
		serialBits = 128
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(serialBits)))
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now().Add(config.NotBeforeOffset)
	validity := config.ValidityPeriod
	if validity <= 0 {
		validity = 365 * 24 * time.Hour
	}
	notAfter := notBefore.Add(validity)

	subject := buildPkixName(config.Subject)
	if subject.CommonName == "" && hostname != "" {
		subject.CommonName = hostname
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if hostname != "" {
		template.DNSNames = []string{hostname}
	}

	var pub crypto.PublicKey
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		return nil, nil, errors.New("unsupported private key type")
	}

	// Sign with CA - this makes the issuer field correct
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caPriv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// SelectCipher selects a cipher suite based on the server profile and client preferences.
// It filters GREASE values and handles edge cases like empty preferences gracefully.
func SelectCipher(profile *ServerProfile, clientCiphers []uint16) uint16 {
	if profile == nil || len(clientCiphers) == 0 {
		return 0
	}

	cfg := &profile.ServerHello

	// Filter GREASE values from client ciphers
	validClientCiphers := make([]uint16, 0, len(clientCiphers))
	for _, c := range clientCiphers {
		if !isGREASEUint16(c) {
			validClientCiphers = append(validClientCiphers, c)
		}
	}

	if len(validClientCiphers) == 0 {
		return 0
	}

	switch cfg.CipherSelectionMode {
	case "server":
		// Server preference: find first server cipher that client supports
		if len(cfg.CipherPreference) == 0 {
			// No server preference in server mode: fall back to first valid client cipher
			return validClientCiphers[0]
		}
		for _, serverCipher := range cfg.CipherPreference {
			for _, clientCipher := range validClientCiphers {
				if serverCipher == clientCipher {
					return serverCipher
				}
			}
		}
	default:
		// Client preference (default): find first client cipher that server supports
		if len(cfg.CipherPreference) == 0 {
			// No server preference: accept first valid client cipher
			return validClientCiphers[0]
		}
		serverSet := make(map[uint16]bool)
		for _, c := range cfg.CipherPreference {
			serverSet[c] = true
		}
		for _, clientCipher := range validClientCiphers {
			if serverSet[clientCipher] {
				return clientCipher
			}
		}
	}

	return 0
}

// SelectALPN selects an ALPN protocol based on the server profile and client preferences.
func SelectALPN(profile *ServerProfile, clientProtocols []string) string {
	if profile == nil || len(clientProtocols) == 0 {
		return ""
	}

	serverPrefs := profile.ServerHello.ALPNPreference
	if len(serverPrefs) == 0 {
		// No server preference, accept first client protocol
		return clientProtocols[0]
	}

	// Find first server preference that client supports
	for _, serverProto := range serverPrefs {
		for _, clientProto := range clientProtocols {
			if serverProto == clientProto {
				return serverProto
			}
		}
	}

	return ""
}

// Clone creates a deep copy of the server profile.
func (p *ServerProfile) Clone() *ServerProfile {
	if p == nil {
		return nil
	}

	clone := *p

	// Deep copy slices in ServerHello
	if p.ServerHello.CipherPreference != nil {
		clone.ServerHello.CipherPreference = make([]uint16, len(p.ServerHello.CipherPreference))
		copy(clone.ServerHello.CipherPreference, p.ServerHello.CipherPreference)
	}
	if p.ServerHello.Extensions != nil {
		clone.ServerHello.Extensions = make([]uint16, len(p.ServerHello.Extensions))
		copy(clone.ServerHello.Extensions, p.ServerHello.Extensions)
	}
	if p.ServerHello.ExtensionOrder != nil {
		clone.ServerHello.ExtensionOrder = make([]uint16, len(p.ServerHello.ExtensionOrder))
		copy(clone.ServerHello.ExtensionOrder, p.ServerHello.ExtensionOrder)
	}
	if p.ServerHello.ALPNPreference != nil {
		clone.ServerHello.ALPNPreference = make([]string, len(p.ServerHello.ALPNPreference))
		copy(clone.ServerHello.ALPNPreference, p.ServerHello.ALPNPreference)
	}
	if p.ServerHello.KeySharePreference != nil {
		clone.ServerHello.KeySharePreference = make([]CurveID, len(p.ServerHello.KeySharePreference))
		copy(clone.ServerHello.KeySharePreference, p.ServerHello.KeySharePreference)
	}
	if p.ServerHello.SupportedVersions != nil {
		clone.ServerHello.SupportedVersions = make([]uint16, len(p.ServerHello.SupportedVersions))
		copy(clone.ServerHello.SupportedVersions, p.ServerHello.SupportedVersions)
	}

	// Deep copy Certificate fields including nested OID slices
	if p.Certificate.Issuer.Fields != nil {
		clone.Certificate.Issuer.Fields = make([]RDNField, len(p.Certificate.Issuer.Fields))
		for i, field := range p.Certificate.Issuer.Fields {
			clone.Certificate.Issuer.Fields[i] = RDNField{
				OID:   append([]int(nil), field.OID...), // Deep copy OID slice
				Value: field.Value,
			}
		}
	}
	if p.Certificate.Subject.Fields != nil {
		clone.Certificate.Subject.Fields = make([]RDNField, len(p.Certificate.Subject.Fields))
		for i, field := range p.Certificate.Subject.Fields {
			clone.Certificate.Subject.Fields[i] = RDNField{
				OID:   append([]int(nil), field.OID...), // Deep copy OID slice
				Value: field.Value,
			}
		}
	}
	if p.Certificate.Extensions.Extensions != nil {
		clone.Certificate.Extensions.Extensions = make([]CertExtensionDef, len(p.Certificate.Extensions.Extensions))
		for i, ext := range p.Certificate.Extensions.Extensions {
			clone.Certificate.Extensions.Extensions[i] = CertExtensionDef{
				OID:      append([]int(nil), ext.OID...), // Deep copy OID slice
				Critical: ext.Critical,
				Value:    ext.Value, // Note: Value is interface{}, deep copy depends on type
			}
		}
	}

	return &clone
}
