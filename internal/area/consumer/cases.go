// Package consumer exercises the consumption specification: every operation it
// declares, through the success path, the declared error paths, and the
// parameter behaviour its schemas constrain.
package consumer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

// AbsentUUID is well-formed and cannot exist: a v4-shaped all-zero UUID. It is
// what the 404 cases use, where the point is that a *valid* identifier for a
// missing object yields OBJECT_UNKNOWN rather than a 400.
const AbsentUUID = "00000000-0000-4000-8000-000000000000"

// MalformedUUID violates components/schemas/uuid, so a request carrying it must
// be rejected before it becomes a lookup.
const MalformedUUID = "not-a-uuid"

// BuildCases produces the full catalogue for a set of fixtures.
//
// The list is built in a fixed order and numbered afterwards, so a case's
// recording name depends on the catalogue rather than on the order results
// happened to arrive in.
func BuildCases(api *spec.API, f Fixtures) []runner.Case {
	var cs []runner.Case
	add := func(more ...runner.Case) { cs = append(cs, more...) }

	ok200 := func(id string) string { return api.OK200(id) }
	ptr404 := func(id string) string { return api.Status(id, 404) }

	// ── TEA Product ─────────────────────────────────────────────────────────
	add(listCases("queryTeaProducts", "/products", ok200("queryTeaProducts"),
		CheckPaginated("uuid", "name", "identifiers"))...)
	add(runner.Case{
		OperationID: "queryTeaProducts", Name: "filter by PURL identifier", Category: "filtering",
		Path: "/products", Query: url.Values{"idType": {"PURL"}, "idValue": {f.ProductPURL}},
		WantStatus: 200, SchemaPtr: ok200("queryTeaProducts"),
		Check: RequireNonEmptyResults,
	}, runner.Case{
		OperationID: "queryTeaProducts", Name: "reject unknown idType", Category: "negative",
		Path: "/products", Query: url.Values{"idType": {"NOTATYPE"}, "idValue": {"x"}},
		WantStatus: 400,
	})

	add(objectCases("getTeaProductByUuid", "/product/", f.ProductUUID, "",
		ok200("getTeaProductByUuid"), ptr404("getTeaProductByUuid"),
		func(b []byte) error { return RequireField(b, "uuid", f.ProductUUID) })...)

	add(listCases("getReleasesByProductId", "/product/"+f.ProductUUID+"/releases",
		ok200("getReleasesByProductId"), CheckPaginated("uuid", "version", "createdDate"))...)
	add(notFoundCases("getReleasesByProductId", "/product/", "/releases", ptr404("getReleasesByProductId"))...)
	add(sortCases("getReleasesByProductId", "/product/"+f.ProductUUID+"/releases",
		ok200("getReleasesByProductId"), []string{"createdDate", "releaseDate", "version"})...)

	add(objectCases("getCleByProductId", "/product/", f.ProductUUID, "/cle",
		ok200("getCleByProductId"), ptr404("getCleByProductId"), CheckCLE)...)

	// ── TEA Product Release ─────────────────────────────────────────────────
	add(listCases("queryTeaProductReleases", "/productReleases",
		ok200("queryTeaProductReleases"), CheckPaginated("uuid", "version", "createdDate"))...)
	add(runner.Case{
		OperationID: "queryTeaProductReleases", Name: "filter by TEI identifier", Category: "filtering",
		Path: "/productReleases", Query: url.Values{
			"idType":   {"TEI"},
			"idValue":  {f.TEI(f.ProductReleaseUUID)},
			"pageSize": {"100"},
		},
		WantStatus: 200, SchemaPtr: ok200("queryTeaProductReleases"),
	})

	add(objectCases("getTeaProductReleaseByUuid", "/productRelease/", f.ProductReleaseUUID, "",
		ok200("getTeaProductReleaseByUuid"), ptr404("getTeaProductReleaseByUuid"),
		func(b []byte) error {
			if err := RequireField(b, "uuid", f.ProductReleaseUUID); err != nil {
				return err
			}
			return RequireComponentRefs(b)
		})...)

	add(objectCases("getCleByProductReleaseId", "/productRelease/", f.ProductReleaseUUID, "/cle",
		ok200("getCleByProductReleaseId"), ptr404("getCleByProductReleaseId"), CheckCLE)...)

	add(objectCases("getLatestCollectionForProductRelease", "/productRelease/", f.ProductReleaseUUID,
		"/collection/latest", ok200("getLatestCollectionForProductRelease"),
		ptr404("getLatestCollectionForProductRelease"),
		CheckCollection(f.ProductReleaseUUID, "PRODUCT_RELEASE"))...)

	add(listCases("getCollectionsByProductReleaseId",
		"/productRelease/"+f.ProductReleaseUUID+"/collections",
		ok200("getCollectionsByProductReleaseId"), CheckPaginated("version"))...)
	add(notFoundCases("getCollectionsByProductReleaseId", "/productRelease/", "/collections",
		ptr404("getCollectionsByProductReleaseId"))...)

	add(versionCases("getCollectionForProductRelease",
		"/productRelease/"+f.ProductReleaseUUID+"/collection/", "collectionVersion",
		ok200("getCollectionForProductRelease"), ptr404("getCollectionForProductRelease"),
		CheckCollection(f.ProductReleaseUUID, "PRODUCT_RELEASE"))...)

	// ── TEA Component ───────────────────────────────────────────────────────
	add(listCases("queryTeaComponents", "/components", ok200("queryTeaComponents"),
		CheckPaginated("uuid", "name", "identifiers"))...)
	add(runner.Case{
		OperationID: "queryTeaComponents", Name: "reject unknown idType", Category: "negative",
		Path: "/components", Query: url.Values{"idType": {"NOTATYPE"}},
		WantStatus: 400,
	})

	add(objectCases("getTeaComponentById", "/component/", f.ComponentUUID, "",
		ok200("getTeaComponentById"), ptr404("getTeaComponentById"),
		func(b []byte) error { return RequireField(b, "uuid", f.ComponentUUID) })...)

	add(listCases("getReleasesByComponentId", "/component/"+f.ComponentUUID+"/releases",
		ok200("getReleasesByComponentId"), CheckPaginated("uuid", "version", "createdDate"))...)
	add(notFoundCases("getReleasesByComponentId", "/component/", "/releases",
		ptr404("getReleasesByComponentId"))...)

	add(objectCases("getCleByComponentId", "/component/", f.ComponentUUID, "/cle",
		ok200("getCleByComponentId"), ptr404("getCleByComponentId"), CheckCLE)...)

	// ── TEA Component Release ───────────────────────────────────────────────
	add(listCases("queryTeaComponentReleases", "/componentReleases",
		ok200("queryTeaComponentReleases"), CheckPaginated("uuid", "version", "createdDate"))...)

	add(objectCases("getComponentReleaseById", "/componentRelease/", f.ComponentReleaseUUID, "",
		ok200("getComponentReleaseById"), ptr404("getComponentReleaseById"),
		func(b []byte) error {
			var v struct {
				Release          map[string]any `json:"release"`
				LatestCollection map[string]any `json:"latestCollection"`
			}
			if err := json.Unmarshal(b, &v); err != nil {
				return fmt.Errorf("decode: %w", err)
			}
			if got, _ := v.Release["uuid"].(string); got != f.ComponentReleaseUUID {
				return fmt.Errorf("release.uuid is %q, expected the requested %q",
					got, f.ComponentReleaseUUID)
			}
			// tea-collection.md: a collection's uuid is identical to the uuid of
			// the release it belongs to.
			if got, _ := v.LatestCollection["uuid"].(string); got != f.ComponentReleaseUUID {
				return fmt.Errorf("latestCollection.uuid is %q, expected it to match the release uuid %q",
					got, f.ComponentReleaseUUID)
			}
			if got, _ := v.LatestCollection["belongsTo"].(string); got != "COMPONENT_RELEASE" {
				return fmt.Errorf("latestCollection.belongsTo is %q, expected COMPONENT_RELEASE", got)
			}
			return nil
		})...)

	add(objectCases("getCleByComponentReleaseId", "/componentRelease/", f.ComponentReleaseUUID, "/cle",
		ok200("getCleByComponentReleaseId"), ptr404("getCleByComponentReleaseId"), CheckCLE)...)

	add(objectCases("getLatestCollection", "/componentRelease/", f.ComponentReleaseUUID,
		"/collection/latest", ok200("getLatestCollection"), ptr404("getLatestCollection"),
		CheckCollection(f.ComponentReleaseUUID, "COMPONENT_RELEASE"))...)

	add(listCases("getCollectionsByReleaseId",
		"/componentRelease/"+f.ComponentReleaseUUID+"/collections",
		ok200("getCollectionsByReleaseId"), CheckPaginated("version"))...)
	add(notFoundCases("getCollectionsByReleaseId", "/componentRelease/", "/collections",
		ptr404("getCollectionsByReleaseId"))...)

	add(versionCases("getCollection",
		"/componentRelease/"+f.ComponentReleaseUUID+"/collection/", "collectionVersion",
		ok200("getCollection"), ptr404("getCollection"),
		CheckCollection(f.ComponentReleaseUUID, "COMPONENT_RELEASE"))...)

	// ── TEA Artifact ────────────────────────────────────────────────────────
	if f.ArtifactSeen {
		add(objectCases("getLatestArtifact", "/artifact/", f.ArtifactUUID, "/latest",
			ok200("getLatestArtifact"), ptr404("getLatestArtifact"),
			func(b []byte) error { return RequireField(b, "uuid", f.ArtifactUUID) })...)

		add(runner.Case{
			OperationID: "getArtifactByVersion", Name: "first revision", Category: "conformance",
			Path: "/artifact/" + f.ArtifactUUID + "/1", WantStatus: 200,
			SchemaPtr: ok200("getArtifactByVersion"),
			Check:     func(b []byte) error { return RequireField(b, "uuid", f.ArtifactUUID) },
		}, runner.Case{
			OperationID: "getArtifactByVersion", Name: "revision beyond history is unknown",
			Category: "negative",
			Path:     "/artifact/" + f.ArtifactUUID + "/99999", WantStatus: 404,
			SchemaPtr: api.Status("getArtifactByVersion", 404),
		}, runner.Case{
			OperationID: "getArtifactByVersion", Name: "reject non-integer version", Category: "negative",
			Path: "/artifact/" + f.ArtifactUUID + "/latest-ish", WantStatus: 400,
		}, runner.Case{
			OperationID: "getArtifactByVersion", Name: "reject malformed uuid", Category: "negative",
			Path: "/artifact/" + MalformedUUID + "/1", WantStatus: 400,
		})
	}

	// ── TEA Discovery ───────────────────────────────────────────────────────
	// The /discovery operation is declared by the consumption specification, so
	// it is exercised here; the DNS and .well-known steps that lead a consumer
	// to it are the discovery area's business.
	add(runner.Case{
		OperationID: "discoveryByTei", Name: "resolve uuid TEI", Category: "conformance",
		Path: "/discovery", Query: url.Values{"tei": {f.TEI(f.ProductReleaseUUID)}},
		WantStatus: 200, SchemaPtr: ok200("discoveryByTei"),
		Check: func(b []byte) error { return RequireDiscovery(b, f.ProductReleaseUUID) },
	}, runner.Case{
		OperationID: "discoveryByTei", Name: "reject TEI from another authority", Category: "negative",
		Path:       "/discovery",
		Query:      url.Values{"tei": {"urn:tei:uuid:tea-conformance.invalid:" + f.ProductReleaseUUID}},
		WantStatus: 404, SchemaPtr: ptr404("discoveryByTei"),
	}, runner.Case{
		OperationID: "discoveryByTei", Name: "unknown identifier in this authority", Category: "negative",
		Path: "/discovery", Query: url.Values{"tei": {f.TEI(AbsentUUID)}},
		WantStatus: 404, SchemaPtr: ptr404("discoveryByTei"),
	}, runner.Case{
		OperationID: "discoveryByTei", Name: "reject missing tei parameter", Category: "negative",
		Path: "/discovery", WantStatus: 400,
	}, runner.Case{
		OperationID: "discoveryByTei", Name: "reject malformed urn", Category: "negative",
		Path: "/discovery", Query: url.Values{"tei": {"not-a-tei"}}, WantStatus: 400,
	})

	// ── Authentication ──────────────────────────────────────────────────────
	//
	// The specification declares bearer and basic security schemes for the
	// whole API, and declares no 401 body, so these are status-only. What it
	// does *not* do is require every endpoint to be gated: a public catalogue
	// served to anyone is a first-class TEA use case, and the whole point of the
	// protocol is that a consumer can resolve a TEI without an agreement first.
	//
	// So these are advisory. They record whether anonymous access is refused,
	// which is a genuinely useful thing for a report to say, without failing a
	// provider for a deployment decision the specification leaves open.
	add(runner.Case{
		OperationID: "queryTeaProducts",
		Name:        "anonymous listing is refused",
		Category:    "security",
		Path:        "/products", Auth: runner.NoAuth, WantStatus: 401,
		AcceptStatus: []int{403},
		Optional:     true,
	}, runner.Case{
		OperationID: "getTeaProductByUuid",
		Name:        "anonymous object read is refused",
		Category:    "security",
		Path:        "/product/" + f.ProductUUID, Auth: runner.NoAuth, WantStatus: 401,
		// 404 is the other correct answer: a server that does not disclose the
		// existence of objects an anonymous caller may not read is behaving
		// better than one that admits to them.
		AcceptStatus: []int{403, 404},
		Optional:     true,
	})

	return Number(cs, config.AreaConsumer, 1)
}

// Number stamps an area and a deterministic sequence onto a built list.
func Number(cases []runner.Case, area config.Area, base int) []runner.Case {
	for i := range cases {
		cases[i].Area = area
		cases[i].Seq = base + i
		if cases[i].Category == "" {
			cases[i].Category = "conformance"
		}
	}
	return cases
}

// ── Case templates ──────────────────────────────────────────────────────────

// listCases covers a paginated collection endpoint: the default page, an
// explicit small page, and every way the pagination parameters can be invalid.
func listCases(opID, path, schema200 string, check func([]byte) error) []runner.Case {
	return []runner.Case{
		{OperationID: opID, Name: "default page", Category: "conformance",
			Path: path, WantStatus: 200, SchemaPtr: schema200, Check: check},
		{OperationID: opID, Name: "explicit page size", Category: "pagination",
			Path: path, Query: url.Values{"pageSize": {"1"}}, WantStatus: 200,
			SchemaPtr: schema200, Check: CheckPageSize(1)},
		{OperationID: opID, Name: "maximum page size", Category: "pagination",
			Path: path, Query: url.Values{"pageSize": {"100"}}, WantStatus: 200, SchemaPtr: schema200},
		{OperationID: opID, Name: "follow nextPageToken", Category: "pagination",
			Path: path, Query: url.Values{"pageSize": {"1"}}, WantStatus: 200,
			SchemaPtr: schema200, Check: CheckTokenShape},
		{OperationID: opID, Name: "reject pageSize below minimum", Category: "negative",
			Path: path, Query: url.Values{"pageSize": {"0"}}, WantStatus: 400},
		{OperationID: opID, Name: "reject pageSize above maximum", Category: "negative",
			Path: path, Query: url.Values{"pageSize": {"101"}}, WantStatus: 400},
		{OperationID: opID, Name: "reject non-numeric pageSize", Category: "negative",
			Path: path, Query: url.Values{"pageSize": {"many"}}, WantStatus: 400},
		{OperationID: opID, Name: "reject foreign pageToken", Category: "negative",
			Path: path, Query: url.Values{"pageToken": {"c29tZS1vdGhlci1zZXJ2ZXI"}}, WantStatus: 400},
		{OperationID: opID, Name: "reject unknown sortField", Category: "negative",
			Path: path, Query: url.Values{"sortField": {"nonesuch"}}, WantStatus: 400},
		{OperationID: opID, Name: "reject unknown sortOrder", Category: "negative",
			Path: path, Query: url.Values{"sortOrder": {"sideways"}}, WantStatus: 400},
		{OperationID: opID, Name: "descending order", Category: "pagination",
			Path: path, Query: url.Values{"sortOrder": {"desc"}}, WantStatus: 200, SchemaPtr: schema200},
	}
}

// sortCases exercises each sort field the operation's enum declares.
func sortCases(opID, path, schema200 string, fields []string) []runner.Case {
	out := make([]runner.Case, 0, len(fields)*2)
	for _, field := range fields {
		for _, order := range []string{"asc", "desc"} {
			out = append(out, runner.Case{
				OperationID: opID, Name: "sort by " + field + " " + order, Category: "pagination",
				Path: path, Query: url.Values{"sortField": {field}, "sortOrder": {order}},
				WantStatus: 200, SchemaPtr: schema200,
			})
		}
	}
	return out
}

// objectCases covers a single-object endpoint: the object, a well-formed but
// absent identifier, and a malformed one.
func objectCases(opID, prefix, uuid, suffix, schema200, schema404 string, check func([]byte) error) []runner.Case {
	return []runner.Case{
		{OperationID: opID, Name: "existing object", Category: "conformance",
			Path: prefix + uuid + suffix, WantStatus: 200, SchemaPtr: schema200, Check: check},
		{OperationID: opID, Name: "absent object reports OBJECT_UNKNOWN", Category: "negative",
			Path: prefix + AbsentUUID + suffix, WantStatus: 404, SchemaPtr: schema404,
			Check: CheckErrorEnum},
		{OperationID: opID, Name: "malformed uuid is rejected", Category: "negative",
			Path: prefix + MalformedUUID + suffix, WantStatus: 400},
	}
}

// notFoundCases covers the error paths of a list endpoint nested under an
// object identifier, which objectCases cannot express.
func notFoundCases(opID, prefix, suffix, schema404 string) []runner.Case {
	return []runner.Case{
		{OperationID: opID, Name: "absent parent reports OBJECT_UNKNOWN", Category: "negative",
			Path: prefix + AbsentUUID + suffix, WantStatus: 404, SchemaPtr: schema404,
			Check: CheckErrorEnum},
		{OperationID: opID, Name: "malformed parent uuid is rejected", Category: "negative",
			Path: prefix + MalformedUUID + suffix, WantStatus: 400},
	}
}

// versionCases covers a versioned sub-resource.
func versionCases(opID, prefix, paramName, schema200, schema404 string, check func([]byte) error) []runner.Case {
	return []runner.Case{
		{OperationID: opID, Name: "first version", Category: "conformance",
			Path: prefix + "1", WantStatus: 200, SchemaPtr: schema200, Check: check},
		{OperationID: opID, Name: "version beyond history is unknown", Category: "negative",
			Path: prefix + "99999", WantStatus: 404, SchemaPtr: schema404, Check: CheckErrorEnum},
		{OperationID: opID, Name: "reject non-integer " + paramName, Category: "negative",
			Path: prefix + "latest-ish", WantStatus: 400},
		{OperationID: opID, Name: "reject zero " + paramName, Category: "negative",
			Path: prefix + "0", WantStatus: 400},
	}
}

// ── Body assertions the schemas cannot express ──────────────────────────────

// CheckPaginated verifies the envelope invariants the specification states in
// prose: nextPageToken is present in every response, and every result carries
// the fields the object schema marks required.
func CheckPaginated(requiredFields ...string) func([]byte) error {
	return func(b []byte) error {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		if _, ok := raw["nextPageToken"]; !ok {
			return fmt.Errorf("nextPageToken is absent; the specification requires it in every response")
		}
		if _, ok := raw["hasNext"]; !ok {
			return fmt.Errorf("hasNext is absent")
		}
		var env struct {
			Results []map[string]any `json:"results"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			return fmt.Errorf("decode results: %w", err)
		}
		for i, item := range env.Results {
			for _, field := range requiredFields {
				if _, ok := item[field]; !ok {
					return fmt.Errorf("results[%d] is missing required field %q", i, field)
				}
			}
		}
		return nil
	}
}

// CheckPageSize asserts a page never exceeds what was asked for.
func CheckPageSize(max int) func([]byte) error {
	return func(b []byte) error {
		var env struct {
			Results []any `json:"results"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		if len(env.Results) > max {
			return fmt.Errorf("returned %d results for pageSize=%d", len(env.Results), max)
		}
		return nil
	}
}

// CheckTokenShape asserts the hasNext hint agrees with the token: the
// specification describes hasNext as a hint that a next page exists, so a
// client that trusts it must not be led into an empty fetch.
func CheckTokenShape(b []byte) error {
	var env struct {
		HasNext       bool   `json:"hasNext"`
		NextPageToken string `json:"nextPageToken"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if env.HasNext && env.NextPageToken == "" {
		return fmt.Errorf("hasNext is true but nextPageToken is empty")
	}
	if !env.HasNext && env.NextPageToken != "" {
		return fmt.Errorf("hasNext is false but a nextPageToken was supplied")
	}
	return nil
}

// CheckErrorEnum asserts an error body carries exactly one key, drawn from the
// specification's enum. error-response declares additionalProperties:false, so
// a helpful extra "detail" field breaks a strict client.
func CheckErrorEnum(b []byte) error {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	code, _ := v["error"].(string)
	if code != "OBJECT_UNKNOWN" && code != "OBJECT_NOT_SHAREABLE" {
		return fmt.Errorf("error is %q, expected an unknown-error-type enum member", code)
	}
	if len(v) != 1 {
		return fmt.Errorf("error-response declares additionalProperties:false but the body has %d keys", len(v))
	}
	return nil
}

// RequireField asserts a top-level string field has an expected value.
func RequireField(b []byte, field, want string) error {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	got, _ := v[field].(string)
	if got != want {
		return fmt.Errorf("%s is %q, expected the requested %q", field, got, want)
	}
	return nil
}

// RequireNonEmptyResults asserts a filter built from the server's own data
// matched something.
func RequireNonEmptyResults(b []byte) error {
	var env struct {
		Results []any `json:"results"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(env.Results) == 0 {
		return fmt.Errorf("the filter matched nothing, but it was built from an identifier this server published")
	}
	return nil
}

// RequireComponentRefs checks that a product release lists its components: the
// field is required by the schema, and a consumer's next hop depends on it.
func RequireComponentRefs(b []byte) error {
	var v struct {
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	for i, c := range v.Components {
		if u, _ := c["uuid"].(string); u == "" {
			return fmt.Errorf("components[%d] has no uuid", i)
		}
	}
	return nil
}

// CheckCollection asserts tea-collection.md's identity rule — a collection's
// uuid equals the uuid of the release it belongs to — and that the
// discriminator names the right flavour.
func CheckCollection(releaseUUID, belongsTo string) func([]byte) error {
	return func(b []byte) error {
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		if got, _ := v["uuid"].(string); got != releaseUUID {
			return fmt.Errorf("collection uuid is %q, expected it to match the release uuid %q",
				got, releaseUUID)
		}
		if got, _ := v["belongsTo"].(string); got != belongsTo {
			return fmt.Errorf("belongsTo is %q, expected %s", got, belongsTo)
		}
		if n, ok := v["version"].(float64); ok && n < 1 {
			return fmt.Errorf("collection version is %v; versions start at 1", n)
		}
		return nil
	}
}

// CheckCLE asserts the ordering rule the schema states in prose: events MUST be
// ordered by id descending.
func CheckCLE(b []byte) error {
	var v struct {
		Events []struct {
			ID        int    `json:"id"`
			Type      string `json:"type"`
			Effective string `json:"effective"`
			Published string `json:"published"`
		} `json:"events"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	seen := map[int]bool{}
	for i, e := range v.Events {
		if i > 0 && e.ID > v.Events[i-1].ID {
			return fmt.Errorf("events are not ordered by id descending: events[%d].id=%d follows %d",
				i, e.ID, v.Events[i-1].ID)
		}
		if seen[e.ID] {
			return fmt.Errorf("event id %d appears more than once", e.ID)
		}
		seen[e.ID] = true
		if e.Type == "" || e.Effective == "" || e.Published == "" {
			return fmt.Errorf("events[%d] is missing a required field", i)
		}
	}
	return nil
}

// RequireDiscovery asserts a discovery response points a consumer somewhere it
// can actually go.
func RequireDiscovery(b []byte, wantReleaseUUID string) error {
	var infos []struct {
		ProductReleaseUUID string `json:"productReleaseUuid"`
		Servers            []struct {
			RootURL  string   `json:"rootUrl"`
			Versions []string `json:"versions"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(b, &infos); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(infos) == 0 {
		return fmt.Errorf("discovery returned an empty array")
	}
	for _, info := range infos {
		if info.ProductReleaseUUID != wantReleaseUUID {
			return fmt.Errorf("resolved to %q, expected %q", info.ProductReleaseUUID, wantReleaseUUID)
		}
		if len(info.Servers) == 0 {
			return fmt.Errorf("discovery info lists no servers")
		}
		for _, s := range info.Servers {
			if strings.HasSuffix(s.RootURL, "/") {
				return fmt.Errorf("rootUrl %q has a trailing slash; the schema forbids it", s.RootURL)
			}
			// A discovery response is where a consumer learns the address to
			// call next. Publishing a plaintext one is both unusable on a
			// TLS-only deployment and a downgrade a consumer would follow.
			if strings.HasPrefix(s.RootURL, "http://") &&
				!strings.Contains(s.RootURL, "127.0.0.1") &&
				!strings.Contains(s.RootURL, "localhost") {
				return fmt.Errorf("rootUrl %q is plaintext; a published address must be https", s.RootURL)
			}
			if len(s.Versions) == 0 {
				return fmt.Errorf("server %q advertises no versions", s.RootURL)
			}
			for _, v := range s.Versions {
				if strings.HasPrefix(v, "v") {
					return fmt.Errorf("version %q carries a v prefix; the schema requires it without", v)
				}
			}
		}
	}
	return nil
}
