// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"fmt"
	"net"
	"strings"

	utlserrors "github.com/refraction-networking/utls/errors"
	"golang.org/x/net/idna"
)

// SNI Hostname Validation
//
// This file implements RFC-compliant SNI hostname validation matching browser behavior.
// Real browsers validate hostnames before sending them in the SNI extension.
// DPI systems can detect uTLS by probing with malformed SNI values that browsers would reject.
//
// References:
// - RFC 6066 Section 3 (TLS SNI Extension)
// - RFC 1035 Section 2.3.1 (DNS label format)
// - RFC 5891 (IDNA 2008)
// - RFC 952/1123 (hostname restrictions)

// SNI validation constants matching browser implementations
const (
	// MaxSNIHostnameLength is the maximum total length of an SNI hostname.
	// RFC 1035 specifies 253 octets max for a fully qualified domain name.
	MaxSNIHostnameLength = 253

	// MaxSNILabelLength is the maximum length of a single label in a hostname.
	// RFC 1035 specifies 63 octets max per label.
	MaxSNILabelLength = 63
)

// SNIValidationError provides detailed information about SNI validation failures.
type SNIValidationError struct {
	Hostname string
	Reason   string
	Label    string // The specific label that failed (if applicable)
}

func (e *SNIValidationError) Error() string {
	if e.Label != "" {
		return fmt.Sprintf("tls: invalid SNI hostname %q: %s (label: %q)", e.Hostname, e.Reason, e.Label)
	}
	return fmt.Sprintf("tls: invalid SNI hostname %q: %s", e.Hostname, e.Reason)
}

// ValidateSNI checks if the hostname is valid for use in the TLS SNI extension.
// This validation matches browser behavior to prevent DPI detection.
//
// Validation rules (per RFC 6066, RFC 1035, RFC 1123):
//   - Non-empty hostname
//   - Maximum 253 characters total
//   - Maximum 63 characters per label
//   - Labels separated by dots
//   - Each label contains only: a-z, A-Z, 0-9, hyphen (-)
//   - Labels cannot start or end with hyphen
//   - No empty labels (consecutive dots)
//   - No trailing dot (browsers strip it)
//   - IP addresses are rejected (not valid for SNI)
//   - Punycode prefixes (xn--) are validated for IDN domains
//
// Returns nil if the hostname is valid, otherwise returns a descriptive error.
func ValidateSNI(hostname string) error {
	if len(hostname) == 0 {
		return &SNIValidationError{Hostname: hostname, Reason: "hostname is empty"}
	}

	// Strip trailing dot if present (browsers do this)
	hostname = strings.TrimSuffix(hostname, ".")

	// Check total length
	if len(hostname) > MaxSNIHostnameLength {
		return &SNIValidationError{
			Hostname: hostname,
			Reason:   fmt.Sprintf("hostname exceeds maximum length of %d characters (got %d)", MaxSNIHostnameLength, len(hostname)),
		}
	}

	// Reject IP addresses - SNI is for hostnames only
	if isIPAddress(hostname) {
		return &SNIValidationError{Hostname: hostname, Reason: "IP addresses are not valid for SNI"}
	}

	// Split into labels and validate each
	labels := strings.Split(hostname, ".")
	if len(labels) == 0 {
		return &SNIValidationError{Hostname: hostname, Reason: "no labels in hostname"}
	}

	for _, label := range labels {
		if err := validateSNILabel(label); err != nil {
			return &SNIValidationError{Hostname: hostname, Reason: err.Error(), Label: label}
		}
	}

	return nil
}

// ValidateSNIStrict performs strict validation that rejects hostnames that
// may work but could be used for fingerprinting detection.
// This includes additional checks beyond ValidateSNI.
func ValidateSNIStrict(hostname string) error {
	// First perform basic validation
	if err := ValidateSNI(hostname); err != nil {
		return err
	}

	hostname = strings.TrimSuffix(hostname, ".")

	// Check for unusual but technically valid patterns that could be fingerprinting
	labels := strings.Split(hostname, ".")

	// 1. Check if ALL non-TLD labels are numeric (looks like IP address attempt)
	// Single numeric subdomains like "123.example.com" are perfectly normal.
	// Only flag patterns like "123.456.789" where every label except TLD is numeric.
	if len(labels) >= 2 {
		allNumericBeforeTLD := true
		for i := 0; i < len(labels)-1; i++ {
			if !isAllNumeric(labels[i]) {
				allNumericBeforeTLD = false
				break
			}
		}
		if allNumericBeforeTLD && len(labels) > 2 {
			// All non-TLD labels are numeric - suspicious IP-like pattern
			return &SNIValidationError{
				Hostname: hostname,
				Reason:   "all non-TLD labels are numeric (IP-like pattern)",
			}
		}
	}

	// 2. Single-label hostnames (no dots) are unusual for public TLS
	if len(labels) == 1 {
		return &SNIValidationError{
			Hostname: hostname,
			Reason:   "single-label hostname is unusual for public TLS",
		}
	}

	// 3. Very long labels might be suspicious
	for _, label := range labels {
		if len(label) > 50 {
			return &SNIValidationError{
				Hostname: hostname,
				Reason:   "very long label may be unusual",
				Label:    label,
			}
		}
	}

	return nil
}

// validateSNILabel validates a single label of a hostname.
func validateSNILabel(label string) error {
	if len(label) == 0 {
		return utlserrors.New("empty label (consecutive dots)").AtError()
	}

	if len(label) > MaxSNILabelLength {
		return fmt.Errorf("label exceeds maximum length of %d characters (got %d)", MaxSNILabelLength, len(label))
	}

	// Check for hyphen at start or end
	if label[0] == '-' {
		return utlserrors.New("label cannot start with hyphen").AtError()
	}
	if label[len(label)-1] == '-' {
		return utlserrors.New("label cannot end with hyphen").AtError()
	}

	// Validate each character
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !isValidSNILabelChar(c) {
			return fmt.Errorf("invalid character %q at position %d", c, i)
		}
	}

	// Additional validation for Punycode labels (IDN)
	if strings.HasPrefix(strings.ToLower(label), "xn--") {
		if err := validatePunycodeLabel(label); err != nil {
			return err
		}
	}

	return nil
}

// isValidSNILabelChar checks if a character is valid in an SNI hostname label.
// Valid characters per RFC 1035/1123: a-z, A-Z, 0-9, hyphen
func isValidSNILabelChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-'
}

// isIPAddress checks if the string is an IP address (v4 or v6).
func isIPAddress(s string) bool {
	// Handle bracketed IPv6
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	// Strip zone identifier
	if idx := strings.LastIndex(s, "%"); idx > 0 {
		s = s[:idx]
	}
	return net.ParseIP(s) != nil
}

// isAllNumeric checks if a string contains only digits.
func isAllNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validatePunycodeLabel performs additional validation for Punycode (xn--) labels.
// Note: We intentionally do NOT validate Punycode decoding. Real browsers pass
// Punycode directly to DNS without decoding validation. The syntactic checks
// (a-z, 0-9, hyphen) already performed in validateSNILabel are sufficient.
// Attempting to decode and validate would reject valid DNS names that browsers accept.
func validatePunycodeLabel(label string) error {
	// Punycode labels must be at least 4 characters (xn--)
	if len(label) < 4 {
		return utlserrors.New("invalid Punycode prefix").AtError()
	}

	// Syntactic validation already done by validateSNILabel:
	// - Length check (max 63 chars)
	// - No hyphen at start/end
	// - Only valid characters (a-z, A-Z, 0-9, hyphen)
	// No further Punycode-specific validation needed - browsers don't decode-validate either.

	return nil
}

// NormalizeSNI normalizes a hostname for SNI by applying common fixes.
// This matches browser behavior for hostname normalization.
//
// Normalization steps:
//   - Convert to lowercase (DNS is case-insensitive)
//   - Strip trailing dot
//   - Convert IDN to Punycode (if needed)
//
// Note: This function does NOT validate the hostname. Call ValidateSNI
// before or after normalization to ensure the hostname is valid.
func NormalizeSNI(hostname string) string {
	if len(hostname) == 0 {
		return hostname
	}

	// Convert to lowercase (DNS is case-insensitive)
	hostname = strings.ToLower(hostname)

	// Strip trailing dot (browsers do this)
	hostname = strings.TrimSuffix(hostname, ".")

	// Convert IDN to Punycode
	// idna.Lookup.ToASCII handles both pure ASCII and Unicode hostnames
	ascii, err := idna.Lookup.ToASCII(hostname)
	if err != nil {
		// If conversion fails, return the original
		return hostname
	}

	return ascii
}

// ValidateAndNormalizeSNI combines validation and normalization.
// Returns the normalized hostname if valid, or an error if invalid.
func ValidateAndNormalizeSNI(hostname string) (string, error) {
	// First normalize
	normalized := NormalizeSNI(hostname)

	// Then validate
	if err := ValidateSNI(normalized); err != nil {
		return "", err
	}

	return normalized, nil
}

// IsSNIValid is a convenience function that returns true if the hostname
// is valid for SNI, false otherwise. Use ValidateSNI for detailed errors.
func IsSNIValid(hostname string) bool {
	return ValidateSNI(hostname) == nil
}

// IsSNIValidStrict is a convenience function that returns true if the hostname
// passes strict SNI validation, false otherwise.
func IsSNIValidStrict(hostname string) bool {
	return ValidateSNIStrict(hostname) == nil
}
