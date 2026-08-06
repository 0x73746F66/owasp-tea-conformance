package spec

import (
	"strings"
	"testing"
)

func TestDuplicateKeysAreFoundAndNamed(t *testing.T) {
	// The shape upstream's publication document has: one object declaring the
	// same member twice, several levels down, with arrays and nested objects in
	// between to walk past.
	doc := `{
	  "openapi": "3.1.1",
	  "paths": {"/a": {"get": {"tags": ["x", "y"], "responses": {"200": {}}}}},
	  "components": {
	    "responses": {"first": {"description": "a"}},
	    "schemas": {"thing": {"type": "object"}},
	    "responses": {"second": {"description": "b"}},
	    "parameters": {"one": {}},
	    "parameters": {"two": {}}
	  }
	}`

	found := duplicateKeys([]byte(doc))
	joined := strings.Join(found, ", ")
	for _, want := range []string{"components.responses", "components.parameters"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the duplicate %q was not reported; found: %v", want, found)
		}
	}
	if len(found) != 2 {
		t.Errorf("reported %d duplicates, expected 2: %v", len(found), found)
	}
}

func TestDuplicateKeysAcceptsACleanDocument(t *testing.T) {
	doc := `{
	  "a": {"b": [1, 2, {"c": "d"}], "e": null},
	  "f": [{"g": 1}, {"g": 2}],
	  "h": true
	}`
	if found := duplicateKeys([]byte(doc)); len(found) != 0 {
		t.Errorf("a clean document reported duplicates: %v", found)
	}
}

func TestLoadAPIParsesJSONWithADuplicateKey(t *testing.T) {
	// A YAML parser refuses this outright. Every JSON parser accepts it and
	// keeps the last definition, so the suite has to as well — and say so.
	doc := `{
	  "openapi": "3.1.1",
	  "info": {"title": "Dup", "version": "0.0.2"},
	  "paths": {
	    "/thing": {"post": {"operationId": "createThing", "responses": {"201": {}}}}
	  },
	  "components": {
	    "responses": {"first": {"description": "a"}},
	    "responses": {"second": {"description": "b"}}
	  }
	}`

	api, err := LoadAPI(KindPublisher, "https://example.test/dup.json", []byte(doc))
	if err != nil {
		t.Fatalf("a JSON document with a duplicate key should still load: %v", err)
	}
	if !api.Declares("createThing") {
		t.Error("the operation table was not built")
	}
	if len(api.Warnings) == 0 {
		t.Fatal("the duplicate key was worked around silently")
	}
	if !strings.Contains(api.Warnings[0], "components.responses") {
		t.Errorf("the warning does not name the duplicated member: %v", api.Warnings)
	}
}
