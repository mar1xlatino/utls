package tls

import (
	"bytes"
	"io"
	"testing"
)

// TestCookieExtensionPlaceholder tests the placeholder mode of CookieExtension.
// When Cookie is empty, the extension should return Len()=0 and Read()=0,io.EOF
// This allows it to be included in ClientHelloSpec without affecting the wire format.
func TestCookieExtensionPlaceholder(t *testing.T) {
	// Test placeholder mode (empty cookie)
	placeholder := &CookieExtension{}

	if placeholder.Len() != 0 {
		t.Errorf("Empty CookieExtension.Len() = %d, want 0", placeholder.Len())
	}

	buf := make([]byte, 100)
	n, err := placeholder.Read(buf)
	if n != 0 {
		t.Errorf("Empty CookieExtension.Read() returned %d bytes, want 0", n)
	}
	if err != io.EOF {
		t.Errorf("Empty CookieExtension.Read() error = %v, want io.EOF", err)
	}
}

// TestCookieExtensionActive tests active mode of CookieExtension.
// When Cookie is set, the extension should serialize normally.
func TestCookieExtensionActive(t *testing.T) {
	cookie := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	ext := &CookieExtension{Cookie: cookie}

	// Expected length: 2 (ext type) + 2 (ext len) + 2 (cookie len) + 5 (cookie data) = 11
	expectedLen := 6 + len(cookie)
	if ext.Len() != expectedLen {
		t.Errorf("CookieExtension.Len() = %d, want %d", ext.Len(), expectedLen)
	}

	buf := make([]byte, ext.Len())
	n, err := ext.Read(buf)
	if n != expectedLen {
		t.Errorf("CookieExtension.Read() returned %d bytes, want %d", n, expectedLen)
	}
	if err != io.EOF {
		t.Errorf("CookieExtension.Read() error = %v, want io.EOF", err)
	}

	// Verify extension type is correct (44 = 0x002c)
	if buf[0] != 0x00 || buf[1] != 0x2c {
		t.Errorf("CookieExtension type = 0x%02x%02x, want 0x002c", buf[0], buf[1])
	}

	// Verify cookie data
	if !bytes.Equal(buf[6:], cookie) {
		t.Errorf("CookieExtension data = %v, want %v", buf[6:], cookie)
	}
}

// TestCookieExtensionTransition tests transitioning from placeholder to active mode.
// This simulates what happens during HRR handling.
func TestCookieExtensionTransition(t *testing.T) {
	// Start as placeholder
	ext := &CookieExtension{}

	if ext.Len() != 0 {
		t.Errorf("Placeholder Len() = %d, want 0", ext.Len())
	}

	// Simulate HRR: set the cookie
	ext.Cookie = []byte{0xaa, 0xbb, 0xcc}

	expectedLen := 6 + 3
	if ext.Len() != expectedLen {
		t.Errorf("Active Len() = %d, want %d", ext.Len(), expectedLen)
	}

	buf := make([]byte, ext.Len())
	n, err := ext.Read(buf)
	if n != expectedLen {
		t.Errorf("Active Read() returned %d bytes, want %d", n, expectedLen)
	}
	if err != io.EOF {
		t.Errorf("Active Read() error = %v, want io.EOF", err)
	}
}

// TestBrowserProfilesHaveCookiePlaceholder verifies that standard browser profiles
// include a CookieExtension placeholder.
func TestBrowserProfilesHaveCookiePlaceholder(t *testing.T) {
	testCases := []struct {
		name string
		id   ClientHelloID
	}{
		{"Chrome_106", HelloChrome_106_Shuffle},
		{"Chrome_120", HelloChrome_120},
		{"Chrome_131", HelloChrome_131},
		{"Chrome_142", HelloChrome_142},
		{"Firefox_120", HelloFirefox_120},
		{"Firefox_145", HelloFirefox_145},
		{"Safari_18", HelloSafari_18},
		{"Safari_26", HelloSafari_26},
		{"iOS_18", HelloIOS_18},
		{"iOS_26", HelloIOS_26},
		{"Edge_106", HelloEdge_106},
		{"Edge_142", HelloEdge_142},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := UTLSIdToSpec(tc.id)
			if err != nil {
				t.Fatalf("UTLSIdToSpec(%v) failed: %v", tc.id, err)
			}

			foundCookie := false
			for _, ext := range spec.Extensions {
				if _, ok := ext.(*CookieExtension); ok {
					foundCookie = true
					break
				}
			}

			if !foundCookie {
				t.Errorf("Profile %s does not have CookieExtension placeholder", tc.name)
			}
		})
	}
}

// TestCookiePlaceholderDoesNotAffectWireFormat verifies that an empty cookie
// placeholder does not contribute to the serialized ClientHello.
func TestCookiePlaceholderDoesNotAffectWireFormat(t *testing.T) {
	// Create a minimal extensions list with and without placeholder
	withPlaceholder := []TLSExtension{
		&SNIExtension{ServerName: "example.com"},
		&CookieExtension{}, // Placeholder - should not serialize
		&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
	}

	withoutPlaceholder := []TLSExtension{
		&SNIExtension{ServerName: "example.com"},
		&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
	}

	// Calculate total lengths
	lenWith := 0
	for _, ext := range withPlaceholder {
		lenWith += ext.Len()
	}

	lenWithout := 0
	for _, ext := range withoutPlaceholder {
		lenWithout += ext.Len()
	}

	if lenWith != lenWithout {
		t.Errorf("With placeholder len = %d, without = %d, should be equal", lenWith, lenWithout)
	}
}
