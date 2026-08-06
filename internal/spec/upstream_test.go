package spec

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
)

// The online controls.
//
// The rest of this package's tests use a small local document so they run
// anywhere. These fetch what the suite will actually validate against, and are
// the ones that notice when upstream changes underneath us — an operation
// added, a schema renamed, the publication document moved.
//
// Skipped unless TEA_CONFORMANCE_ONLINE is set, so a network outage or a rate
// limit never fails an unrelated change.
func requireOnline(t *testing.T) {
	t.Helper()
	if os.Getenv("TEA_CONFORMANCE_ONLINE") == "" {
		t.Skip("set TEA_CONFORMANCE_ONLINE=1 to fetch the upstream specifications")
	}
}

func fetchUpstream(t *testing.T, kinds ...Kind) Bundle {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// An empty directory fetches without persisting, which is what a test wants.
	bundle, err := NewFetcher().Fetch(ctx, config.DefaultSpecs(), "", kinds)
	if err != nil {
		t.Fatalf("fetch the upstream specifications: %v", err)
	}
	return bundle
}

// decode turns a body into the value model the validator expects.
func decode(t *testing.T, body string) any {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
	if err != nil {
		t.Fatalf("decode the test body: %v", err)
	}
	return value
}

func TestUpstreamConsumptionSpecificationIsUsable(t *testing.T) {
	requireOnline(t)
	bundle := fetchUpstream(t, KindConsumer)
	doc, _ := bundle.Get(KindConsumer)

	api, err := LoadAPI(KindConsumer, doc.URL, doc.Raw())
	if err != nil {
		t.Fatalf("compile the consumption specification: %v", err)
	}
	if api.Version == "" {
		t.Error("the document declares no info.version")
	}
	t.Logf("TEA consumption specification %s, %d operations", api.Version, len(api.Operation))

	// The operations the suite's case catalogue is written against. If upstream
	// renames or removes one, this is what notices before a run reports it as a
	// provider's failure.
	for _, id := range []string{
		"queryTeaProducts", "getTeaProductByUuid", "getReleasesByProductId",
		"queryTeaProductReleases", "getTeaProductReleaseByUuid",
		"queryTeaComponents", "getTeaComponentById", "getReleasesByComponentId",
		"queryTeaComponentReleases", "getComponentReleaseById",
		"getLatestCollection", "getCollection", "getCollectionsByReleaseId",
		"getLatestCollectionForProductRelease", "getCollectionForProductRelease",
		"getCollectionsByProductReleaseId",
		"getLatestArtifact", "getArtifactByVersion", "discoveryByTei",
		"getCleByProductId", "getCleByProductReleaseId",
		"getCleByComponentId", "getCleByComponentReleaseId",
	} {
		op, ok := api.Operation[id]
		if !ok {
			t.Errorf("operation %q is no longer declared upstream", id)
			continue
		}
		if op.StatusSchema[200] == "" {
			t.Errorf("operation %q declares no 200 schema", id)
		}
	}
}

// TestUpstreamSchemasRejectKnownBadBodies is the negative control against the
// real specification.
//
// The equivalent test in internal/runner proves the validator can fail. This
// one proves the *specification* still constrains what the suite reports on: if
// upstream loosened one of these, a provider could start emitting it and every
// run would stay green while consumers broke.
func TestUpstreamSchemasRejectKnownBadBodies(t *testing.T) {
	requireOnline(t)
	bundle := fetchUpstream(t, KindConsumer)
	doc, _ := bundle.Get(KindConsumer)
	api, err := LoadAPI(KindConsumer, doc.URL, doc.Raw())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	cases := []struct {
		name    string
		pointer string
		body    string
		expect  string
	}{{
		name:    "a product with no identifiers",
		pointer: "#/components/schemas/product",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x"}`,
		expect:  "identifiers",
	}, {
		name:    "an uppercase uuid",
		pointer: "#/components/schemas/product",
		body:    `{"uuid":"09E8C73B-AC45-4475-ACAC-33E6A7314E6D","name":"x","identifiers":[]}`,
		expect:  "uuid",
	}, {
		name:    "an identifier type outside the enum",
		pointer: "#/components/schemas/product",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","name":"x","identifiers":[{"idType":"NOTATYPE","idValue":"y"}]}`,
		expect:  "idType",
	}, {
		name:    "a timestamp with fractional seconds",
		pointer: "#/components/schemas/release",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","version":"1","createdDate":"2025-01-01T00:00:00.000Z"}`,
		expect:  "createdDate",
	}, {
		name:    "an error response carrying an extra key",
		pointer: "#/components/schemas/error-response",
		body:    `{"error":"OBJECT_UNKNOWN","detail":"nope"}`,
		expect:  "detail",
	}, {
		name:    "an error code outside the enum",
		pointer: "#/components/schemas/error-response",
		body:    `{"error":"NOT_FOUND"}`,
		expect:  "error",
	}, {
		name:    "a paginated response with no nextPageToken",
		pointer: "#/components/schemas/paginated-product-response",
		body:    `{"hasNext":false,"results":[]}`,
		expect:  "nextPageToken",
	}, {
		name:    "an artifact with no formats",
		pointer: "#/components/schemas/artifact",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","type":"BOM"}`,
		expect:  "formats",
	}, {
		name:    "an artifact type outside the enum",
		pointer: "#/components/schemas/artifact",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","type":"SARIF","formats":[]}`,
		expect:  "type",
	}, {
		name:    "a collection belonging to something that is not a release",
		pointer: "#/components/schemas/collection",
		body:    `{"uuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d","version":1,"belongsTo":"RELEASE"}`,
		expect:  "belongsTo",
	}, {
		name:    "a checksum algorithm outside the enum",
		pointer: "#/components/schemas/checksum",
		body:    `{"algType":"sha256","algValue":"deadbeef"}`,
		expect:  "algType",
	}, {
		name:    "a discovery entry listing no servers",
		pointer: "#/components/schemas/discovery-info",
		body:    `{"productReleaseUuid":"09e8c73b-ac45-4475-acac-33e6a7314e6d"}`,
		expect:  "servers",
	}, {
		name:    "a lifecycle event with no effective date",
		pointer: "#/components/schemas/cle-event",
		body:    `{"id":1,"type":"released","published":"2025-01-01T00:00:00Z"}`,
		expect:  "effective",
	}, {
		name:    "a lifecycle event type outside the enum",
		pointer: "#/components/schemas/cle-event",
		body:    `{"id":1,"type":"nonesuch","effective":"2025-01-01T00:00:00Z","published":"2025-01-01T00:00:00Z"}`,
		expect:  "type",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schema, err := api.SchemaFor(tc.pointer)
			if err != nil {
				t.Skipf("%s is no longer in the upstream document: %v", tc.pointer, err)
			}
			if err := schema.Validate(decode(t, tc.body)); err == nil {
				t.Fatalf("the upstream schema accepted a body that should not validate: %s", tc.body)
			} else if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("the rejection does not mention %q: %v", tc.expect, err)
			}
		})
	}
}

func TestUpstreamPublicationSpecificationIsUsable(t *testing.T) {
	requireOnline(t)
	bundle := fetchUpstream(t, KindPublisher)
	doc, _ := bundle.Get(KindPublisher)

	// Parsing at all is the first assertion: this document has duplicate keys,
	// which a YAML parser refuses outright.
	api, err := LoadAPI(KindPublisher, doc.URL, doc.Raw())
	if err != nil {
		t.Fatalf("compile the publication specification: %v", err)
	}
	t.Logf("TEA publication specification %s, %d operations, %d document warnings",
		api.Version, len(api.Operation), len(api.Warnings))
	for _, warning := range api.Warnings {
		t.Logf("  document defect: %s", warning)
	}

	// Two publication models are in circulation and the suite has a round-trip
	// for each. What this test protects against is upstream moving to a third
	// without anybody noticing.
	release := []string{"createTeaProduct", "createTeaProductRelease", "createTeaComponentRelease"}
	leaf := []string{"createTeaProduct", "createTeaLeaf", "createTeaCollection"}

	declares := func(ids []string) int {
		n := 0
		for _, id := range ids {
			if api.Declares(id) {
				n++
			}
		}
		return n
	}
	switch {
	case declares(release) == len(release):
		t.Log("upstream publishes the product / component / release model")
	case declares(leaf) == len(leaf):
		t.Log("upstream publishes the product / leaf / collection model")
		// The models are different generations. Say so loudly, because it is
		// the single most surprising thing about the upstream specification set
		// and it is why a 0.4.0 server exercises none of these operations.
		if consumer := fetchUpstream(t, KindConsumer); true {
			doc, _ := consumer.Get(KindConsumer)
			if consumerAPI, err := LoadAPI(KindConsumer, doc.URL, doc.Raw()); err == nil {
				t.Logf("note: the consumption specification beside it is %s — the two "+
					"documents are different TEA generations and do not share an object model",
					consumerAPI.Version)
			}
		}
	default:
		t.Errorf("upstream declares neither publication model this suite knows: %v",
			api.OperationIDs())
	}

	// Every declared write must say what success looks like, or a client cannot
	// tell one from a failure.
	for _, id := range api.OperationIDs() {
		op := api.Operation[id]
		if op.Method == "GET" {
			continue
		}
		if status, _ := api.SuccessStatus(id); status == 0 {
			t.Logf("document defect: %s %s (%s) declares no 2xx response inline; its success "+
				"code is behind a component reference", op.Method, op.PathPattern, id)
		}
	}
}

func TestUpstreamWellKnownSchemaCompiles(t *testing.T) {
	requireOnline(t)
	bundle := fetchUpstream(t, KindWellKnown)
	doc, _ := bundle.Get(KindWellKnown)

	schema, err := LoadJSONSchema(doc.URL, doc.Raw())
	if err != nil {
		t.Fatalf("compile the discovery schema: %v", err)
	}
	good := `{"schemaVersion":1,"endpoints":[{"url":"https://api.example.com","versions":["0.4.0"]}]}`
	if err := schema.Validate(decode(t, good)); err != nil {
		t.Errorf("the schema rejected the specification's own example shape: %v", err)
	}
	bad := `{"schemaVersion":1,"endpoints":[{"url":"https://api.example.com","versions":["0.4.0"],"extra":1}]}`
	if err := schema.Validate(decode(t, bad)); err == nil {
		t.Error("the discovery schema accepted a stray key; it declares additionalProperties:false")
	}
}

func TestUpstreamLicenceListLoads(t *testing.T) {
	requireOnline(t)
	bundle := fetchUpstream(t, KindSPDX)
	doc, _ := bundle.Get(KindSPDX)

	list, err := LoadLicenseList(doc.Raw())
	if err != nil {
		t.Fatalf("load the SPDX licence list: %v", err)
	}
	t.Logf("SPDX licence list %s, %d identifiers", list.Version, len(list.IDs))
	for _, id := range []string{"Apache-2.0", "MIT", "GPL-3.0-or-later", "BSD-3-Clause"} {
		if verdict, _ := list.Check(id); verdict != LicenseValid {
			t.Errorf("%s is not current in the fetched list", id)
		}
	}
	if verdict, canonical := list.Check("apache-2.0"); verdict != LicenseWrongCase || canonical != "Apache-2.0" {
		t.Errorf("a case error resolved to %v/%q", verdict, canonical)
	}
}
