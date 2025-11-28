package tls

import (
	"encoding/json"
	"os"
	"reflect"
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

	// Compare Extensions
	if len(jsonSpec.Extensions) != len(truthSpec.Extensions) {
		t.Errorf("JSONUnmarshaler %s: len(jsonExtensions) = %d != %d = len(truthExtensions)", clientHelloSpecJSONTestIdentifier(truthClientHelloID), len(jsonSpec.Extensions), len(truthSpec.Extensions))
	}

	for i := range jsonSpec.Extensions {
		if !reflect.DeepEqual(jsonSpec.Extensions[i], truthSpec.Extensions[i]) {
			if _, ok := jsonSpec.Extensions[i].(*UtlsPaddingExtension); ok {
				testedPaddingExt := jsonSpec.Extensions[i].(*UtlsPaddingExtension)
				savedPaddingExt := truthSpec.Extensions[i].(*UtlsPaddingExtension)
				if testedPaddingExt.PaddingLen != savedPaddingExt.PaddingLen || testedPaddingExt.WillPad != savedPaddingExt.WillPad {
					t.Errorf("got %#v, want %#v", testedPaddingExt, savedPaddingExt)
				} else {
					continue // UtlsPaddingExtension has non-nil function member
				}
			}
			t.Errorf("JSONUnmarshaler %s: got %#v, want %#v", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.Extensions[i], truthSpec.Extensions[i])
		}
	}
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

	// Compare Extensions
	if len(jsonSpec.Extensions) != len(truthSpec.Extensions) {
		t.Errorf("UnmarshalJSON %s: len(jsonExtensions) = %d != %d = len(truthExtensions)", jsonFilepath, len(jsonSpec.Extensions), len(truthSpec.Extensions))
	}

	for i := range jsonSpec.Extensions {
		if !reflect.DeepEqual(jsonSpec.Extensions[i], truthSpec.Extensions[i]) {
			if _, ok := jsonSpec.Extensions[i].(*UtlsPaddingExtension); ok {
				testedPaddingExt := jsonSpec.Extensions[i].(*UtlsPaddingExtension)
				savedPaddingExt := truthSpec.Extensions[i].(*UtlsPaddingExtension)
				if testedPaddingExt.PaddingLen != savedPaddingExt.PaddingLen || testedPaddingExt.WillPad != savedPaddingExt.WillPad {
					t.Errorf("got %#v, want %#v", testedPaddingExt, savedPaddingExt)
				} else {
					continue // UtlsPaddingExtension has non-nil function member
				}
			}
			t.Errorf("UnmarshalJSON %s: got %#v, want %#v", clientHelloSpecJSONTestIdentifier(truthClientHelloID), jsonSpec.Extensions[i], truthSpec.Extensions[i])
		}
	}
}

func clientHelloSpecJSONTestIdentifier(id ClientHelloID) string {
	return id.Client + id.Version
}
