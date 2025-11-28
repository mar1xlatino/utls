package tls

import (
	"fmt"
	"testing"
)

func TestNewBrowserProfiles(t *testing.T) {
	profiles := []ClientHelloID{
		HelloChrome_142,
		HelloFirefox_145,
		HelloSafari_18,
		HelloEdge_142,
		HelloChrome_Auto,
		HelloFirefox_Auto,
		HelloSafari_Auto,
		HelloEdge_Auto,
	}

	for _, id := range profiles {
		t.Run(id.Str(), func(t *testing.T) {
			spec, err := UTLSIdToSpec(id)
			if err != nil {
				t.Fatalf("Failed to get spec for %s: %v", id.Str(), err)
			}

			if len(spec.CipherSuites) == 0 {
				t.Error("No cipher suites")
			}
			if len(spec.Extensions) == 0 {
				t.Error("No extensions")
			}

			t.Logf("%s: %d ciphers, %d extensions", id.Str(), len(spec.CipherSuites), len(spec.Extensions))
		})
	}
}

func TestChrome142HasX25519MLKEM768(t *testing.T) {
	spec, err := UTLSIdToSpec(HelloChrome_142)
	if err != nil {
		t.Fatal(err)
	}

	// Check supported curves include X25519MLKEM768
	hasMLKEM := false
	for _, ext := range spec.Extensions {
		if curves, ok := ext.(*SupportedCurvesExtension); ok {
			for _, curve := range curves.Curves {
				// Skip GREASE placeholder
				if curve == GREASE_PLACEHOLDER {
					continue
				}
				// Check for X25519MLKEM768 (curve ID 4588)
				if curve == X25519MLKEM768 {
					hasMLKEM = true
					break
				}
			}
			if hasMLKEM {
				break
			}
		}
	}

	if !hasMLKEM {
		t.Error("Chrome 142 should have X25519MLKEM768 in supported curves")
	}
}

func TestFirefox145HasShuffledExtensions(t *testing.T) {
	// Run multiple iterations and verify that shuffle produces different orderings
	const iterations = 50
	uniqueOrderings := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		spec, err := UTLSIdToSpec(HelloFirefox_145)
		if err != nil {
			t.Fatal(err)
		}

		// Build a string representation of extension order
		var order string
		for _, ext := range spec.Extensions {
			order += fmt.Sprintf("%T,", ext)
		}
		uniqueOrderings[order] = true
	}

	// With 50 iterations, we should see at least 10 unique orderings
	// if shuffle is working properly. This is a probabilistic test but
	// very unlikely to fail if shuffle is correct.
	if len(uniqueOrderings) < 10 {
		t.Errorf("Firefox 145 shuffle not working: only %d unique orderings in %d iterations (expected >= 10)",
			len(uniqueOrderings), iterations)
	}
	t.Logf("Firefox 145 shuffle produced %d unique orderings in %d iterations", len(uniqueOrderings), iterations)
}

func TestEdge142FollowsChrome(t *testing.T) {
	chrome, err := UTLSIdToSpec(HelloChrome_142)
	if err != nil {
		t.Fatal(err)
	}
	edge, err := UTLSIdToSpec(HelloEdge_142)
	if err != nil {
		t.Fatal(err)
	}

	// Same cipher suites
	if len(chrome.CipherSuites) != len(edge.CipherSuites) {
		t.Errorf("Chrome has %d ciphers, Edge has %d", len(chrome.CipherSuites), len(edge.CipherSuites))
	}
}

func TestAutoAliasesPointToLatest(t *testing.T) {
	tests := []struct {
		auto   ClientHelloID
		latest ClientHelloID
	}{
		{HelloChrome_Auto, HelloChrome_142},
		{HelloFirefox_Auto, HelloFirefox_145},
		{HelloSafari_Auto, HelloSafari_26},
		{HelloEdge_Auto, HelloEdge_142},
		{HelloIOS_Auto, HelloIOS_26},
	}

	for _, tc := range tests {
		t.Run(tc.auto.Str(), func(t *testing.T) {
			if tc.auto != tc.latest {
				t.Errorf("%s should equal %s", tc.auto.Str(), tc.latest.Str())
			}
		})
	}
}
