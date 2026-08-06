package runner

// The specification owns the HTTP method of an operation, and this is the test
// that keeps it that way.
//
// A case that states its own method is a second copy of something the document
// already says. When the two disagree the provider answers 405, and the report
// blames it for an operation it implemented exactly as specified. That is not a
// hypothetical: the publisher document declares PUT for the two collection
// operations, this suite sent POST, and the run reported a conformant server as
// non-conformant. Worse, it cascaded, because the artifact case that followed
// had no collection to belong to.

import (
	"net/http"
	"testing"

	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

const methodSpec = `
openapi: 3.1.1
info:
  title: Methods
  version: 1.0.0
paths:
  /release/{uuid}/collection:
    put:
      operationId: publishCollection
      responses:
        "200":
          description: written
  /artifact:
    post:
      operationId: createArtifact
      responses:
        "201":
          description: created
`

func methodAPI(t *testing.T) *spec.API {
	t.Helper()
	api, err := spec.LoadAPI(spec.KindPublisher, "https://example.test/methods.yaml", []byte(methodSpec))
	if err != nil {
		t.Fatalf("LoadAPI: %v", err)
	}
	return api
}

func TestSpecMethodOverridesTheCase(t *testing.T) {
	api := methodAPI(t)

	cases := []Case{
		// The exact drift that produced the false failure.
		{OperationID: "publishCollection", Method: http.MethodPost},
		{OperationID: "createArtifact", Method: http.MethodPost},
	}
	alignMethods(api, cases)

	if cases[0].Method != http.MethodPut {
		t.Fatalf("publishCollection method = %s, want PUT from the specification", cases[0].Method)
	}
	if cases[1].Method != http.MethodPost {
		t.Fatalf("createArtifact method = %s, want POST from the specification", cases[1].Method)
	}
}

func TestCasesWithoutAnOperationKeepTheirMethod(t *testing.T) {
	api := methodAPI(t)

	// Artifact downloads and the discovery document are addressed by URL, not by
	// an operation the document declares. Rewriting those would break them.
	cases := []Case{
		{Name: "download an artifact", Method: http.MethodGet, AbsoluteURL: "https://example.test/blob"},
		{OperationID: "notInTheDocument", Method: http.MethodDelete},
	}
	alignMethods(api, cases)

	if cases[0].Method != http.MethodGet {
		t.Fatalf("method = %s, want GET left alone", cases[0].Method)
	}
	if cases[1].Method != http.MethodDelete {
		t.Fatalf("method = %s, want DELETE left alone when the document declares no such operation", cases[1].Method)
	}
}

func TestNilSpecLeavesEveryMethodAlone(t *testing.T) {
	cases := []Case{{OperationID: "publishCollection", Method: http.MethodPost}}
	alignMethods(nil, cases)
	if cases[0].Method != http.MethodPost {
		t.Fatalf("method = %s, want the case's own method when there is no specification", cases[0].Method)
	}
}
