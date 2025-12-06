// SNI Hostname Validation Edge Case Tests
// These tests verify browser-compliant SNI validation to prevent DPI detection.

package tls

import (
	"strings"
	"testing"
)

func TestValidateSNI_ValidHostnames(t *testing.T) {
	validHostnames := []string{
		"example.com",
		"www.example.com",
		"sub.domain.example.com",
		"test-site.example.com",
		"a.b.c.d.e.f.example.com",
		"123.example.com",        // numeric label (not TLD)
		"test123.example.com",    // alphanumeric
		"a-b-c.example.com",      // multiple hyphens
		"xn--nxasmq5b.example.com", // Punycode
		"a.co",                   // short TLD
		"example.museum",         // long TLD
		"a1.b2.c3.example.com",   // alphanumeric labels
	}

	for _, hostname := range validHostnames {
		t.Run(hostname, func(t *testing.T) {
			err := ValidateSNI(hostname)
			if err != nil {
				t.Errorf("ValidateSNI(%q) returned error: %v", hostname, err)
			}
		})
	}
}

func TestValidateSNI_InvalidHostnames(t *testing.T) {
	testCases := []struct {
		hostname string
		reason   string
	}{
		{"", "empty hostname"},
		{"-example.com", "label starts with hyphen"},
		{"example-.com", "label ends with hyphen"},
		{"-example-.com", "label starts and ends with hyphen"},
		{"example..com", "empty label (consecutive dots)"},
		{".example.com", "empty first label"},
		// Note: "example.com." is valid because we strip trailing dot (browser behavior)
		{"exam ple.com", "space in hostname"},
		{"exam\tple.com", "tab in hostname"},
		{"exam\nple.com", "newline in hostname"},
		{"192.168.1.1", "IPv4 address"},
		{"[2001:db8::1]", "IPv6 address"},
		{"::1", "IPv6 loopback"},
		// Very long hostnames
		{strings.Repeat("a", 64) + ".com", "label exceeds 63 chars"},
		{strings.Repeat("a.", 127) + "com", "hostname exceeds 253 chars"}, // 127 * 2 + 3 = 257
		// Invalid characters
		{"example_site.com", "underscore in hostname"},
		{"example@site.com", "@ in hostname"},
		{"example#site.com", "# in hostname"},
		{"example$.com", "$ in hostname"},
		{"example%.com", "% in hostname"},
		{"example&.com", "& in hostname"},
		{"example*.com", "* in hostname"},
		{"example!.com", "! in hostname"},
	}

	for _, tc := range testCases {
		t.Run(tc.reason, func(t *testing.T) {
			err := ValidateSNI(tc.hostname)
			if err == nil {
				t.Errorf("ValidateSNI(%q) should have returned error for: %s", tc.hostname, tc.reason)
			}
		})
	}
}

func TestValidateSNI_EdgeCases(t *testing.T) {
	// Test exact boundary conditions
	testCases := []struct {
		name     string
		hostname string
		valid    bool
	}{
		// Label length boundaries
		{"63-char label (valid)", strings.Repeat("a", 63) + ".com", true},
		{"64-char label (invalid)", strings.Repeat("a", 64) + ".com", false},

		// Total length boundaries
		{"253-char hostname (valid)", createValidHostname(253), true},
		{"254-char hostname (invalid)", createValidHostname(254), false},

		// Single character labels
		{"single-char labels", "a.b.c.d.e", true},

		// Hyphen positions
		{"hyphen in middle", "a-b.com", true},
		{"hyphen at start of label", "-ab.com", false},
		{"hyphen at end of label", "ab-.com", false},

		// Numeric labels
		{"numeric first label", "123.example.com", true},
		{"all-numeric hostname", "123.456.789", true}, // technically valid DNS
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSNI(tc.hostname)
			if tc.valid && err != nil {
				t.Errorf("ValidateSNI(%q) should be valid but got error: %v", tc.hostname, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("ValidateSNI(%q) should be invalid but got no error", tc.hostname)
			}
		})
	}
}

func TestNormalizeSNI(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"Example.Com", "example.com"},
		{"example.com.", "example.com"},
		{"EXAMPLE.COM.", "example.com"},
		{"  ", "  "}, // spaces not stripped (would be invalid anyway)
		{"", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := NormalizeSNI(tc.input)
			if result != tc.expected {
				t.Errorf("NormalizeSNI(%q) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestValidateAndNormalizeSNI(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
		valid    bool
	}{
		{"EXAMPLE.COM", "example.com", true},
		{"example.com.", "example.com", true},
		{"Example-Site.COM.", "example-site.com", true},
		{"", "", false},
		{"-invalid.com", "", false},
		{"192.168.1.1", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, err := ValidateAndNormalizeSNI(tc.input)
			if tc.valid {
				if err != nil {
					t.Errorf("ValidateAndNormalizeSNI(%q) unexpected error: %v", tc.input, err)
				}
				if result != tc.expected {
					t.Errorf("ValidateAndNormalizeSNI(%q) = %q, want %q", tc.input, result, tc.expected)
				}
			} else {
				if err == nil {
					t.Errorf("ValidateAndNormalizeSNI(%q) should have returned error", tc.input)
				}
			}
		})
	}
}

func TestIsSNIValid(t *testing.T) {
	if !IsSNIValid("example.com") {
		t.Error("IsSNIValid should return true for valid hostname")
	}
	if IsSNIValid("") {
		t.Error("IsSNIValid should return false for empty hostname")
	}
	if IsSNIValid("-invalid.com") {
		t.Error("IsSNIValid should return false for hostname starting with hyphen")
	}
}

func TestValidateSNIStrict(t *testing.T) {
	testCases := []struct {
		hostname string
		valid    bool
		reason   string
	}{
		{"example.com", true, "normal hostname"},
		{"www.example.com", true, "www subdomain"},
		{"123.example.com", true, "numeric subdomain"},
		{"example", false, "single-label hostname"},
		{"123.456.789", false, "all-numeric labels except TLD"}, // This catches numeric prefix
	}

	for _, tc := range testCases {
		t.Run(tc.hostname, func(t *testing.T) {
			err := ValidateSNIStrict(tc.hostname)
			if tc.valid && err != nil {
				t.Errorf("ValidateSNIStrict(%q) should be valid (%s) but got error: %v", tc.hostname, tc.reason, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("ValidateSNIStrict(%q) should be invalid (%s) but got no error", tc.hostname, tc.reason)
			}
		})
	}
}

func TestSNIValidationError(t *testing.T) {
	err := &SNIValidationError{
		Hostname: "test.com",
		Reason:   "test reason",
	}
	expected := `tls: invalid SNI hostname "test.com": test reason`
	if err.Error() != expected {
		t.Errorf("SNIValidationError.Error() = %q, want %q", err.Error(), expected)
	}

	errWithLabel := &SNIValidationError{
		Hostname: "test.com",
		Reason:   "test reason",
		Label:    "test",
	}
	expectedWithLabel := `tls: invalid SNI hostname "test.com": test reason (label: "test")`
	if errWithLabel.Error() != expectedWithLabel {
		t.Errorf("SNIValidationError.Error() = %q, want %q", errWithLabel.Error(), expectedWithLabel)
	}
}

func TestPunycodeValidation(t *testing.T) {
	testCases := []struct {
		hostname string
		valid    bool
	}{
		{"xn--nxasmq5b.com", true},  // Valid Punycode
		{"xn--a.com", true},         // Short Punycode
		{"example.xn--p1ai", true},  // .rf in Punycode (Russian)
		{"xn--.com", false},         // Invalid: label ends with hyphen (RFC 1035 violation)
	}

	for _, tc := range testCases {
		t.Run(tc.hostname, func(t *testing.T) {
			err := ValidateSNI(tc.hostname)
			if tc.valid && err != nil {
				t.Errorf("ValidateSNI(%q) should be valid but got error: %v", tc.hostname, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("ValidateSNI(%q) should be invalid but got no error", tc.hostname)
			}
		})
	}
}

// Helper to create a valid hostname of exact length
func createValidHostname(length int) string {
	if length < 5 {
		return strings.Repeat("a", length)
	}
	// Create hostname like: aaaa.aaaa.aaaa.com
	// Each label is max 63 chars, separated by dots
	var parts []string
	remaining := length - 4 // subtract ".com"

	for remaining > 0 {
		labelLen := remaining
		if labelLen > 63 {
			labelLen = 63
		}
		if remaining-labelLen > 0 && remaining-labelLen < 2 {
			// Avoid creating a 1-char final part before .com
			labelLen = remaining - 2
		}
		parts = append(parts, strings.Repeat("a", labelLen))
		remaining -= labelLen + 1 // +1 for the dot
		if remaining <= 0 {
			break
		}
	}

	result := strings.Join(parts, ".") + ".com"
	// Adjust if needed
	for len(result) < length {
		result = "a" + result
	}
	for len(result) > length {
		if len(parts[0]) > 1 {
			parts[0] = parts[0][1:]
			result = strings.Join(parts, ".") + ".com"
		} else {
			break
		}
	}
	return result
}

// Test IP address detection
func TestIsIPAddress(t *testing.T) {
	ipAddresses := []string{
		"192.168.1.1",
		"10.0.0.1",
		"127.0.0.1",
		"255.255.255.255",
		"::1",
		"2001:db8::1",
		"[2001:db8::1]",
		"fe80::1%eth0",
	}

	for _, ip := range ipAddresses {
		t.Run(ip, func(t *testing.T) {
			err := ValidateSNI(ip)
			if err == nil {
				t.Errorf("ValidateSNI(%q) should reject IP address", ip)
			}
		})
	}
}

// Benchmark SNI validation
func BenchmarkValidateSNI(b *testing.B) {
	hostname := "www.example.com"
	for i := 0; i < b.N; i++ {
		ValidateSNI(hostname)
	}
}

func BenchmarkNormalizeSNI(b *testing.B) {
	hostname := "WWW.EXAMPLE.COM."
	for i := 0; i < b.N; i++ {
		NormalizeSNI(hostname)
	}
}

func BenchmarkValidateAndNormalizeSNI(b *testing.B) {
	hostname := "WWW.EXAMPLE.COM."
	for i := 0; i < b.N; i++ {
		ValidateAndNormalizeSNI(hostname)
	}
}
