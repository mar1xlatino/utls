package tls

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

func TestClientHelloSpecJSONUnmarshaler(t *testing.T) {
	// Chrome102, Firefox105, iOS14 removed - pre-shuffling profiles deprecated
	testClientHelloSpecJSONUnmarshaler(t, "testdata/ClientHello-JSON-Edge106.json", HelloEdge_106)
}

func testClientHelloSpecJSONUnmarshaler(
	t *testing.T,
	jsonFilepath string,
	truthClientHelloID ClientHelloID,
) {
	jsonCH, err := os.ReadFile(jsonFilepath)
	if err != nil {
		t.Fatal(err)
	}

	var chsju ClientHelloSpecJSONUnmarshaler
	if err := json.Unmarshal(jsonCH, &chsju); err != nil {
		t.Fatal(err)
	}

	truthSpec, _ := UTLSIdToSpec(truthClientHelloID)
	jsonSpec := chsju.ClientHelloSpec()

	// Compare CipherSuites
	if !reflect.DeepEqual(jsonSpec.CipherSuites, truthSpec.CipherSuites) {
		t.Errorf("JSONUnmarshaler %s: got %#v, want %#v", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.CipherSuites, truthSpec.CipherSuites)
	}

	// Compare CompressionMethods
	if !reflect.DeepEqual(jsonSpec.CompressionMethods, truthSpec.CompressionMethods) {
		t.Errorf("JSONUnmarshaler %s: got %#v, want %#v", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.CompressionMethods, truthSpec.CompressionMethods)
	}

	// Compare Extensions - use unordered comparison since modern profiles use extension shuffling
	if len(jsonSpec.Extensions) != len(truthSpec.Extensions) {
		t.Errorf("JSONUnmarshaler %s: len(jsonExtensions) = %d != %d = len(truthExtensions)", clientHelloSpecJSONTestIdentifier(truthClientHelloID), len(jsonSpec.Extensions), len(truthSpec.Extensions))
	}

	compareExtensionSets(t, "JSONUnmarshaler", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.Extensions, truthSpec.Extensions)
}

func TestClientHelloSpecUnmarshalJSON(t *testing.T) {
	// Chrome102, Firefox105, iOS14 removed - pre-shuffling profiles deprecated
	testClientHelloSpecUnmarshalJSON(t, "testdata/ClientHello-JSON-Edge106.json", HelloEdge_106)
}

func testClientHelloSpecUnmarshalJSON(
	t *testing.T,
	jsonFilepath string,
	truthClientHelloID ClientHelloID,
) {
	var jsonSpec ClientHelloSpec
	jsonCH, err := os.ReadFile(jsonFilepath)
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(jsonCH, &jsonSpec); err != nil {
		t.Fatal(err)
	}

	truthSpec, _ := UTLSIdToSpec(truthClientHelloID)

	// Compare CipherSuites
	if !reflect.DeepEqual(jsonSpec.CipherSuites, truthSpec.CipherSuites) {
		t.Errorf("UnmarshalJSON %s: got %#v, want %#v", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.CipherSuites, truthSpec.CipherSuites)
	}

	// Compare CompressionMethods
	if !reflect.DeepEqual(jsonSpec.CompressionMethods, truthSpec.CompressionMethods) {
		t.Errorf("UnmarshalJSON %s: got %#v, want %#v", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.CompressionMethods, truthSpec.CompressionMethods)
	}

	// Compare Extensions - use unordered comparison since modern profiles use extension shuffling
	if len(jsonSpec.Extensions) != len(truthSpec.Extensions) {
		t.Errorf("UnmarshalJSON %s: len(jsonExtensions) = %d != %d = len(truthExtensions)", jsonFilepath, len(jsonSpec.Extensions), len(truthSpec.Extensions))
	}

	compareExtensionSets(t, "UnmarshalJSON", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.Extensions, truthSpec.Extensions)
}

func clientHelloSpecJSONTestIdentifier(id ClientHelloID) string {
	return id.Client + id.Version
}

// extensionKey returns a unique key for an extension based on its type and values.
// For extensions that can appear multiple times (like GREASE), we append an index.
func extensionKey(ext TLSExtension) string {
	return reflect.TypeOf(ext).String()
}

// compareExtensionSets compares two extension slices as unordered sets.
// This is needed because modern browser profiles shuffle extension order for fingerprint resistance.
func compareExtensionSets(t *testing.T, testName, profileName string, jsonExts, truthExts []TLSExtension) {
	// Sort both slices by extension type for deterministic comparison
	sortedJSON := make([]TLSExtension, len(jsonExts))
	sortedTruth := make([]TLSExtension, len(truthExts))
	copy(sortedJSON, jsonExts)
	copy(sortedTruth, truthExts)

	sortByType := func(exts []TLSExtension) {
		sort.Slice(exts, func(i, j int) bool {
			return extensionKey(exts[i]) < extensionKey(exts[j])
		})
	}
	sortByType(sortedJSON)
	sortByType(sortedTruth)

	// Compare sorted extensions
	minLen := len(sortedJSON)
	if len(sortedTruth) < minLen {
		minLen = len(sortedTruth)
	}

	for i := 0; i < minLen; i++ {
		jsonExt := sortedJSON[i]
		truthExt := sortedTruth[i]

		// Check same type
		if extensionKey(jsonExt) != extensionKey(truthExt) {
			t.Errorf("%s %s: extension type mismatch at sorted index %d: got %s, want %s",
				testName, profileName, i, extensionKey(jsonExt), extensionKey(truthExt))
			continue
		}

		// Special handling for UtlsPaddingExtension (has function member that cannot be compared)
		if padJSON, ok := jsonExt.(*UtlsPaddingExtension); ok {
			padTruth := truthExt.(*UtlsPaddingExtension)
			if padJSON.PaddingLen != padTruth.PaddingLen || padJSON.WillPad != padTruth.WillPad {
				t.Errorf("%s %s: padding mismatch: got PaddingLen=%d WillPad=%v, want PaddingLen=%d WillPad=%v",
					testName, profileName, padJSON.PaddingLen, padJSON.WillPad, padTruth.PaddingLen, padTruth.WillPad)
			}
			continue
		}

		// Compare extension values
		if !reflect.DeepEqual(jsonExt, truthExt) {
			t.Errorf("%s %s: extension value mismatch for %s: got %#v, want %#v",
				testName, profileName, extensionKey(jsonExt), jsonExt, truthExt)
		}
	}
}
