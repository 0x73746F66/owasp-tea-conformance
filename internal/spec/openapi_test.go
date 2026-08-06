package spec

import "testing"

// miniSpec is a small OpenAPI 3.1 document carrying the same kinds of
// constraint the TEA specification does: a pattern-constrained uuid, a
// date-time format, an enum, and an error object that forbids extra keys.
//
// It exists so the indexing and validation plumbing can be tested without a
// network round-trip. The real specification is exercised by the online test in
// upstream_test.go.
const miniSpec = `
openapi: 3.1.1
info:
  title: Mini
  version: 9.9.9
paths:
  /thing/{uuid}:
    get:
      operationId: getThing
      tags: [Things]
      responses:
        "200":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/thing"
        "400":
          content:
            application/json: {}
        "404":
          $ref: "#/components/responses/not-found"
  /thing:
    post:
      operationId: createThing
      requestBody:
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/thing"
      responses:
        "201":
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/thing"
        "400":
          content:
            application/json: {}
components:
  responses:
    not-found:
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/error-response"
  schemas:
    uuid:
      type: string
      pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
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
          type: string
          pattern: "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$"
      required: [uuid, name]
    error-response:
      type: object
      additionalProperties: false
      properties:
        error:
          type: string
          enum: [OBJECT_UNKNOWN, OBJECT_NOT_SHAREABLE]
      required: [error]
`

func loadMini(t *testing.T) *API {
	t.Helper()
	api, err := LoadAPI(KindConsumer, "https://example.test/mini.yaml", []byte(miniSpec))
	if err != nil {
		t.Fatalf("load the test specification: %v", err)
	}
	return api
}

func TestIndexesOperations(t *testing.T) {
	api := loadMini(t)

	if api.Version != "9.9.9" {
		t.Errorf("info.version is %q, expected 9.9.9", api.Version)
	}
	if len(api.Operation) != 2 {
		t.Fatalf("indexed %d operations, expected 2", len(api.Operation))
	}

	get := api.Operation["getThing"]
	if get.Method != "GET" {
		t.Errorf("method is %q, expected GET", get.Method)
	}
	if get.PathPattern != "/thing/{uuid}" {
		t.Errorf("path is %q", get.PathPattern)
	}
	if get.Tag != "Things" {
		t.Errorf("tag is %q, expected Things", get.Tag)
	}
	if got := api.OK200("getThing"); got != "#/components/schemas/thing" {
		t.Errorf("200 schema pointer is %q", got)
	}
	// A declared status with no schema must index as "": inventing a shape for
	// it would fail servers that are in fact conformant.
	if got := api.Status("getThing", 400); got != "" {
		t.Errorf("400 has schema pointer %q, expected none", got)
	}
	if got := api.Status("getThing", 404); got != "#/components/schemas/error-response" {
		t.Errorf("404 schema pointer is %q", got)
	}
}

func TestSuccessStatusReadsTheDocument(t *testing.T) {
	api := loadMini(t)

	if status, _ := api.SuccessStatus("getThing"); status != 200 {
		t.Errorf("getThing success status is %d, expected 200", status)
	}
	if status, schema := api.SuccessStatus("createThing"); status != 201 ||
		schema != "#/components/schemas/thing" {
		t.Errorf("createThing success is %d/%q, expected 201 and the thing schema", status, schema)
	}
	if status, _ := api.SuccessStatus("nonesuch"); status != 0 {
		t.Errorf("an undeclared operation reported success status %d", status)
	}
	if api.Declares("nonesuch") {
		t.Error("Declares said yes for an operation the document does not have")
	}
}

func TestRequestBodySchemaIsIndexed(t *testing.T) {
	api := loadMini(t)
	if got := api.Operation["createThing"].RequestSchema; got != "#/components/schemas/thing" {
		t.Errorf("request body schema pointer is %q", got)
	}
}

func TestSchemaForRejectsAnUnknownPointer(t *testing.T) {
	api := loadMini(t)
	if _, err := api.SchemaFor("#/components/schemas/nope"); err == nil {
		t.Error("compiling a pointer that does not exist should fail")
	}
}
