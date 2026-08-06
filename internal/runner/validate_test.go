package runner

// Negative controls for the validator.
//
// A conformance report is only worth the validator behind it. A validator that
// silently accepted everything would produce exactly the same green report as a
// correct one, so these tests assert that known-bad payloads are *rejected*.
// and name the specific rule each one breaks. The positive controls exist so
// the negative ones cannot be satisfied by a validator that rejects everything
// instead.
//
// The document here is small and local on purpose: it carries the same kinds of
// constraint the TEA specification does, and it lets this run in CI without a
// network round-trip. The real specification is put through the same path by the
// online test in internal/spec.

import (
	"strings"
	"testing"

	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

const controlSpec = `
openapi: 3.1.1
info:
  title: Controls
  version: 1.0.0
paths:
  /thing:
    get:
      operationId: getThing
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/thing"
components:
  schemas:
    uuid:
      type: string
      pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    date-time:
      type: string
      pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
    thing:
      type: object
      properties:
        uuid:
          $ref: "#/components/schemas/uuid"
        name:
          type: string
        kind:
          type: string
          enum: [BOM, ATTESTATION]
        createdDate:
          $ref: "#/components/schemas/date-time"
      required: [uuid, name]
    paginated:
      type: object
      properties:
        hasNext:
          type: boolean
        nextPageToken:
          type: string
        results:
          type: array
          items:
            $ref: "#/components/schemas/thing"
      required: [hasNext, nextPageToken, results]
    error-response:
      type: object
      additionalProperties: false
      properties:
        error:
          type: string
          enum: [OBJECT_UNKNOWN, OBJECT_NOT_SHAREABLE]
      required: [error]
`

func controls(t *testing.T) *spec.API {
	t.Helper()
	api, err := spec.LoadAPI(spec.KindConsumer, "https://example.test/controls.yaml", []byte(controlSpec))
	if err != nil {
		t.Fatalf("load the control specification: %v", err)
	}
	return api
}

func validate(t *testing.T, api *spec.API, pointer, body string) []string {
	t.Helper()
	schema, err := api.SchemaFor(pointer)
	if err != nil {
		t.Fatalf("compile %s: %v", pointer, err)
	}
	return ValidateAgainst(schema, []byte(body))
}

func TestValidatorRejectsNonConformantBodies(t *testing.T) {
	api := controls(t)

	cases := []struct {
		name    string
		pointer string
		body    string
		expect  string // substring the failure message must contain
	}{{
		name:    "a required property is missing",
		pointer: "#/components/schemas/thing",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d"}`,
		expect:  "name",
	}, {
		name:    "the uuid is in the wrong case",
		pointer: "#/components/schemas/thing",
		body:    `{"uuid":"09E8C73B-AC45-4475-ACAC-33E6A7314E6D","name":"x"}`,
		expect:  "uuid",
	}, {
		name:    "the uuid is not a uuid at all",
		pointer: "#/components/schemas/thing",
		body:    `{"uuid":"not-a-uuid","name":"x"}`,
		expect:  "uuid",
	}, {
		name:    "an enum member that is not in the enum",
		pointer: "#/components/schemas/thing",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x","kind":"SARIF"}`,
		expect:  "kind",
	}, {
		name:    "a timestamp with fractional seconds",
		pointer: "#/components/schemas/thing",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x","createdDate":"2025-01-01T00:00:00.000Z"}`,
		expect:  "createdDate",
	}, {
		name:    "a timestamp with a numeric offset instead of Z",
		pointer: "#/components/schemas/thing",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x","createdDate":"2025-01-01T00:00:00+10:00"}`,
		expect:  "createdDate",
	}, {
		name:    "a paginated response with no nextPageToken",
		pointer: "#/components/schemas/paginated",
		body:    `{"hasNext":false,"results":[]}`,
		expect:  "nextPageToken",
	}, {
		name:    "a paginated response whose item is malformed",
		pointer: "#/components/schemas/paginated",
		body:    `{"hasNext":false,"nextPageToken":"","results":[{"name":"no uuid"}]}`,
		expect:  "uuid",
	}, {
		name:    "an error response carrying a helpful extra key",
		pointer: "#/components/schemas/error-response",
		body:    `{"error":"OBJECT_UNKNOWN","detail":"nope"}`,
		expect:  "detail",
	}, {
		name:    "an error code outside the enum",
		pointer: "#/components/schemas/error-response",
		body:    `{"error":"NOT_FOUND"}`,
		expect:  "error",
	}, {
		name:    "a response that is not JSON at all",
		pointer: "#/components/schemas/thing",
		body:    `<html>503</html>`,
		expect:  "not valid JSON",
	}, {
		name:    "an array where an object was promised",
		pointer: "#/components/schemas/thing",
		body:    `[{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x"}]`,
		expect:  "object",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validate(t, api, tc.pointer, tc.body)
			if len(errs) == 0 {
				t.Fatalf("the validator accepted a body that violates the specification: %s", tc.body)
			}
			joined := strings.Join(errs, " | ")
			if !strings.Contains(joined, tc.expect) {
				t.Errorf("the rejection did not mention %q; got: %s", tc.expect, joined)
			}
		})
	}
}

func TestValidatorAcceptsConformantBodies(t *testing.T) {
	api := controls(t)

	cases := []struct {
		name    string
		pointer string
		body    string
	}{{
		name:    "the minimum a thing can be",
		pointer: "#/components/schemas/thing",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x"}`,
	}, {
		name:    "every optional field populated",
		pointer: "#/components/schemas/thing",
		body: `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x","kind":"BOM",
		        "createdDate":"2025-05-07T18:08:00Z"}`,
	}, {
		name:    "an empty last page still carries its token",
		pointer: "#/components/schemas/paginated",
		body:    `{"hasNext":false,"nextPageToken":"","results":[]}`,
	}, {
		name:    "an error response with exactly one key",
		pointer: "#/components/schemas/error-response",
		body:    `{"error":"OBJECT_UNKNOWN"}`,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if errs := validate(t, api, tc.pointer, tc.body); len(errs) > 0 {
				t.Errorf("the validator rejected a conformant body: %s", strings.Join(errs, " | "))
			}
		})
	}
}

func TestSummariseReportsSpread(t *testing.T) {
	// Two samples with the same median and very different consistency must not
	// summarise identically, or the performance report's spread column would be
	// decorative.
	steady := SummariseSamples([]float64{10, 10, 10, 10, 10})
	jittery := SummariseSamples([]float64{1, 5, 10, 15, 30})

	if steady.P50Ms != jittery.P50Ms {
		t.Fatalf("the fixture is wrong: medians differ (%v vs %v)", steady.P50Ms, jittery.P50Ms)
	}
	if steady.StdDevMs != 0 {
		t.Errorf("a constant sample has spread %v", steady.StdDevMs)
	}
	if jittery.StdDevMs <= steady.StdDevMs {
		t.Errorf("a scattered sample reported spread %v, no more than a constant one",
			jittery.StdDevMs)
	}
	if jittery.MaxMs != 30 || jittery.MinMs != 1 {
		t.Errorf("min/max are %v/%v", jittery.MinMs, jittery.MaxMs)
	}
}
