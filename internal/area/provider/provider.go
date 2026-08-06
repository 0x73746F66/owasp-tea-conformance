// Package provider exercises the publication specification: the operations
// that create, revise and remove TEA objects.
//
// This is the only area that writes to somebody else's server, and it is built
// around that fact.
//
// Every object it creates is named deterministically from the configuration, so
// a second run addresses the same records and does not accumulate new ones. The
// round-trip ends with the delete operations, which are therefore both the last
// conformance cases and the cleanup, so the suite does not need a separate
// teardown pass, because verifying that delete works *is* the teardown. And
// because a run can be interrupted between the create and the delete, it starts
// by reclaiming anything a previous run left behind under the same names.
//
// Whatever survives all of that is listed in the report's residual records, with
// the request that removes it, so an administrator can purge deliberately rather
// than by guessing which objects were ours.
package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

// Record is one object this area created on the provider.
type Record struct {
	Kind  string `json:"kind"`
	UUID  string `json:"uuid"`
	Label string `json:"label"`
	// DeletePath is the request that removes it, relative to the API root, so
	// the report can print something an operator can run.
	DeletePath string `json:"deletePath"`
	Method     string `json:"deleteMethod"`

	Deleted      bool   `json:"deleted"`
	DeleteStatus int    `json:"deleteStatus,omitempty"`
	Note         string `json:"note,omitempty"`
}

// Model names which publication object model the fetched specification
// describes.
//
// There are two in circulation, and they are not compatible. The document
// upstream publishes at spec/publisher/openapi.json is version 0.0.2 and
// describes products, *leaves* and collections; the consumption specification
// beside it is 0.4.0 and describes products, components, releases and
// collections. A suite that assumed either one would report a correct server as
// broken, so the round-trip is chosen from what the document actually declares.
type Model string

const (
	// ModelRelease is the product / component / release model that matches the
	// 0.4.x consumption specification.
	ModelRelease Model = "product-component-release"
	// ModelLeaf is the older product / leaf / collection model.
	ModelLeaf Model = "product-leaf-collection"
	// ModelUnknown is a document declaring neither.
	ModelUnknown Model = "unrecognised"
)

// Findings is what this area concluded.
type Findings struct {
	// Implemented is false when the provider does not serve the publication
	// operations at all, which is not a conformance failure: the publication
	// specification is a separate document and a read-only mirror is a
	// legitimate TEA server.
	Implemented bool   `json:"implemented"`
	Detail      string `json:"detail,omitempty"`

	// Model is the object model the publication specification describes.
	Model Model `json:"model"`
	// ModelMismatch is set when the provider serves the publication endpoints
	// but does not speak the model the fetched document describes. It is the
	// two upstream specifications being different generations, and it is a fact
	// about the documents and not a defect in the provider.
	ModelMismatch bool `json:"modelMismatch,omitempty"`
	// SpecVersion is that document's own version, which is worth printing next
	// to the consumption specification's.
	SpecVersion string `json:"specVersion,omitempty"`

	NamePrefix string `json:"namePrefix"`
	RunKey     string `json:"runKey"`
	PURL       string `json:"productPurl"`

	Reclaimed int `json:"recordsReclaimedFromAPreviousRun"`

	Created  []Record `json:"created,omitempty"`
	Residual []Record `json:"residual,omitempty"`

	// Unsupported lists publication operations the provider answered 404 or 405
	// for. A partial implementation is a real and useful thing to report.
	Unsupported []string `json:"operationsNotImplemented,omitempty"`
}

// Clean reports whether the round-trip removed everything it created.
func (f Findings) Clean() bool { return len(f.Residual) == 0 }

// flow carries state through the round-trip.
type flow struct {
	ctx       context.Context
	client    *runner.Client
	api       *spec.API
	cycle     config.WriteCycle
	authority string
	seq       int
	results   []runner.Result
	found     *Findings

	productUUID          string
	componentUUID        string
	componentReleaseUUID string
	productReleaseUUID   string
	artifactUUID         string
	distributionUUID     string
	leafUUID             string
	collectionUUID       string
}

// DetectModel reads which publication model a document describes.
func DetectModel(api *spec.API) Model {
	switch {
	case api.Declares("createTeaProductRelease") || api.Declares("createTeaComponentRelease"):
		return ModelRelease
	case api.Declares("createTeaLeaf") || api.Declares("createTeaCollection"):
		return ModelLeaf
	default:
		return ModelUnknown
	}
}

// Run performs the publication round-trip that matches the fetched
// specification.
//
// `authority` is the provider's discovery domain, which the older model needs:
// its object paths are addressed by TEI URN and not by UUID, and a TEI's
// authority is the domain a consumer started from.
func Run(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	cycle config.WriteCycle,
	authority string,
) ([]runner.Result, Findings) {
	found := Findings{
		NamePrefix:  cycle.NamePrefix,
		RunKey:      cycle.RunKey,
		PURL:        productPURL(cycle),
		Model:       DetectModel(api),
		SpecVersion: api.Version,
	}
	f := &flow{ctx: ctx, client: c, api: api, cycle: cycle, authority: authority, found: &found}

	// Refuse to write without a credential. A publication API that accepts
	// anonymous writes is a finding, but discovering it by creating objects on
	// an open server is not this suite's business.
	if c.Auth == "" {
		found.Detail = "no credential is configured for this provider, and the publication " +
			"round-trip writes objects; configure auth.credentialEnv to exercise it"
		f.note("the publication round-trip was not run", found.Detail)
		return f.results, found
	}
	if found.Model == ModelUnknown {
		found.Detail = fmt.Sprintf(
			"the publication specification fetched for this run (version %s) declares neither "+
				"a release model nor a leaf model, so there is no round-trip to run against it; "+
				"the operations it does declare are %s",
			dash(api.Version), strings.Join(api.OperationIDs(), ", "))
		f.note("no round-trip matches the publication specification", found.Detail)
		return f.results, found
	}

	if !f.preflight() {
		return f.results, found
	}
	found.Implemented = true

	if found.Model == ModelLeaf {
		f.leafRoundTrip()
		return f.results, found
	}

	f.reclaim()

	f.createProduct()
	if f.productUUID == "" {
		f.finish()
		return f.results, found
	}
	f.updateProduct()
	f.readBackProduct()

	f.createComponent()
	f.createComponentRelease()
	f.createProductRelease()

	f.publishCollections()
	f.createDistribution()
	f.createArtifact()
	f.uploadArtifact()
	f.updateArtifact()
	f.accessPolicy()

	f.finish()
	return f.results, found
}

func dash(s string) string {
	if s == "" {
		return "unversioned"
	}
	return s
}

// --- Naming ---
//
// Everything is derived from the configuration so a re-run addresses the same
// objects. The purl is the handle: it is the only identifier a publisher
// supplies and can therefore search on afterwards, which is what makes an
// interrupted run recoverable.

func productName(cycle config.WriteCycle) string {
	return cycle.NamePrefix + " " + cycle.RunKey
}

func productPURL(cycle config.WriteCycle) string {
	return strings.TrimRight(cycle.PurlNamespace, "/") + "/" + cycle.RunKey
}

func componentName(cycle config.WriteCycle) string {
	return cycle.NamePrefix + " component " + cycle.RunKey
}

// releaseVersion is fixed, never timestamped, because a timestamp would
// make every run a new object and leave the previous one behind.
const releaseVersion = "0.0.0-conformance"

// --- Phases ---

// preflight establishes whether the publication API is there at all, and that
// it refuses an unauthenticated write.
func (f *flow) preflight() bool {
	if !f.api.Declares("createTeaProduct") {
		f.found.Detail = "the publication specification this run fetched declares no createTeaProduct operation"
		f.note("the publication specification could not be indexed", f.found.Detail)
		return false
	}

	res := f.run(runner.Case{
		OperationID: "createTeaProduct",
		Name:        "an unauthenticated write is refused",
		Category:    "security",
		Method:      http.MethodPost,
		Path:        "/product",
		Auth:        runner.NoAuth,
		Body:        body(map[string]any{"name": productName(f.cycle)}),
		WantStatus:  http.StatusUnauthorized,
		AcceptStatus: []int{
			http.StatusForbidden,
			// A server that does not implement publication answers one of
			// these, and that is what the next check reads.
			http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented,
		},
	})
	switch res.GotStatus {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		f.found.Detail = fmt.Sprintf(
			"POST /product answered HTTP %d, so this provider does not implement the publication "+
				"specification; the consumption areas are unaffected", res.GotStatus)
		f.note("the publication API is not served by this provider", f.found.Detail)
		return false
	case http.StatusCreated, http.StatusOK:
		// It accepted an anonymous write. Report it loudly and stop: creating
		// objects on a server that lets anyone create them is not something to
		// do on purpose.
		f.fail("the publication API accepted an unauthenticated write",
			"POST /product succeeded with no credential; anyone can publish to this server. "+
				"The round-trip was stopped instead of writing more to it")
		f.found.Detail = "the publication API accepted an unauthenticated write"
		return false
	}
	return true
}

// reclaim removes anything a previous interrupted run left under these names,
// so the round-trip starts from a known state and a re-run is idempotent.
func (f *flow) reclaim() {
	body, res, err := runner.GetJSON(f.ctx, f.client, config.AreaProvider, f.next(),
		"look for records left by a previous run", "/products",
		url.Values{"idType": {"PURL"}, "idValue": {f.found.PURL}, "pageSize": {"100"}})
	res.Category = "cleanup"
	res.OperationID = "queryTeaProducts"
	f.results = append(f.results, res)
	if err != nil {
		return
	}
	for _, item := range runner.AsSlice(body["results"]) {
		uuid := runner.AsString(runner.AsMap(item), "uuid")
		if uuid == "" {
			continue
		}
		f.found.Reclaimed++
		f.run(runner.Case{
			OperationID: "deleteTeaProduct",
			Name:        "remove a record left by a previous run",
			Category:    "cleanup",
			Method:      http.MethodDelete,
			Path:        "/product/" + uuid,
			WantStatus:  f.successStatus("deleteTeaProduct", http.StatusNoContent),
			// Another run may have removed it between the search and here.
			AcceptStatus: []int{http.StatusNotFound},
		})
	}
}

func (f *flow) createProduct() {
	status, schema := f.api.SuccessStatus("createTeaProduct")
	res := f.run(runner.Case{
		OperationID: "createTeaProduct",
		Name:        "create a product",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/product",
		Body: body(map[string]any{
			"name": productName(f.cycle),
			"identifiers": []any{
				map[string]any{"idType": "PURL", "idValue": f.found.PURL},
			},
		}),
		WantStatus: status,
		SchemaPtr:  schema,
		Check: func(b []byte) error {
			// The specification is explicit that the server assigns the TEI,
			// because it names the server's own authority. A publisher that
			// could set it would be asserting something only the server knows.
			return requireAssignedIdentity(b, productName(f.cycle))
		},
	})
	f.productUUID = uuidOf(res.Body)
	f.record("product", f.productUUID, productName(f.cycle), "/product/"+f.productUUID)
}

func (f *flow) updateProduct() {
	status, schema := f.api.SuccessStatus("updateTeaProduct")
	f.run(runner.Case{
		OperationID: "updateTeaProduct",
		Name:        "update the product",
		Category:    "publication",
		Method:      http.MethodPatch,
		Path:        "/product/" + f.productUUID,
		Body:        body(map[string]any{"name": productName(f.cycle) + " (revised)"}),
		WantStatus:  status,
		SchemaPtr:   schema,
	})
}

// readBackProduct asserts the write is visible through the consumption API.
//
// This is the case that catches a publication API writing to a store the
// consumption API does not read, which is the two halves of the specification sharing
// object definitions but not data.
func (f *flow) readBackProduct() {
	f.run(runner.Case{
		OperationID: "getTeaProductByUuid",
		Name:        "the written product is visible through the consumption API",
		Category:    "publication",
		Path:        "/product/" + f.productUUID,
		WantStatus:  http.StatusOK,
		SchemaPtr:   f.api.OK200("getTeaProductByUuid"),
		Check: func(b []byte) error {
			var v map[string]any
			if err := json.Unmarshal(b, &v); err != nil {
				return fmt.Errorf("decode: %w", err)
			}
			if got := runner.AsString(v, "name"); got != productName(f.cycle)+" (revised)" {
				return fmt.Errorf("the consumption API serves name %q, but the update set %q; "+
					"the publication write is not visible to consumers",
					got, productName(f.cycle)+" (revised)")
			}
			return nil
		},
	})
}

func (f *flow) createComponent() {
	status, schema := f.api.SuccessStatus("createTeaComponent")
	res := f.run(runner.Case{
		OperationID: "createTeaComponent",
		Name:        "create a component",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/component",
		Body: body(map[string]any{
			"name": componentName(f.cycle),
			"identifiers": []any{
				map[string]any{"idType": "PURL", "idValue": f.found.PURL + "-component"},
			},
		}),
		WantStatus: status,
		SchemaPtr:  schema,
	})
	f.componentUUID = uuidOf(res.Body)
	f.record("component", f.componentUUID, componentName(f.cycle), "/component/"+f.componentUUID)
}

func (f *flow) createComponentRelease() {
	if f.componentUUID == "" {
		return
	}
	status, schema := f.api.SuccessStatus("createTeaComponentRelease")
	res := f.run(runner.Case{
		OperationID: "createTeaComponentRelease",
		Name:        "create a component release",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/componentRelease",
		Body: body(map[string]any{
			"component":   f.componentUUID,
			"version":     releaseVersion,
			"releaseDate": fixedDate,
			"preRelease":  true,
		}),
		WantStatus: status,
		SchemaPtr:  schema,
	})
	f.componentReleaseUUID = uuidOf(res.Body)
	f.record("componentRelease", f.componentReleaseUUID, releaseVersion,
		"/componentRelease/"+f.componentReleaseUUID)
}

func (f *flow) createProductRelease() {
	if f.productUUID == "" {
		return
	}
	payload := map[string]any{
		"product":     f.productUUID,
		"version":     releaseVersion,
		"releaseDate": fixedDate,
		"preRelease":  true,
	}
	if f.componentUUID != "" {
		ref := map[string]any{"uuid": f.componentUUID}
		if f.componentReleaseUUID != "" {
			ref["release"] = f.componentReleaseUUID
		}
		payload["components"] = []any{ref}
	}
	status, schema := f.api.SuccessStatus("createTeaProductRelease")
	res := f.run(runner.Case{
		OperationID: "createTeaProductRelease",
		Name:        "create a product release pinning the component release",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/productRelease",
		Body:        body(payload),
		WantStatus:  status,
		SchemaPtr:   schema,
	})
	f.productReleaseUUID = uuidOf(res.Body)
	f.record("productRelease", f.productReleaseUUID, releaseVersion,
		"/productRelease/"+f.productReleaseUUID)
}

func (f *flow) publishCollections() {
	reason := map[string]any{
		"type":    "INITIAL_RELEASE",
		"comment": "published by the OWASP TEA conformance suite",
	}
	if f.componentReleaseUUID != "" {
		status, schema := f.api.SuccessStatus("publishTeaComponentReleaseCollection")
		f.run(runner.Case{
			OperationID: "publishTeaComponentReleaseCollection",
			Name:        "publish a collection for the component release",
			Category:    "publication",
			Method:      http.MethodPost,
			Path:        "/componentRelease/" + f.componentReleaseUUID + "/collection",
			Body:        body(map[string]any{"updateReason": reason}),
			WantStatus:  status,
			SchemaPtr:   schema,
			Check:       requireCollectionIdentity(f.componentReleaseUUID, "COMPONENT_RELEASE"),
		})
	}
	if f.productReleaseUUID != "" {
		status, schema := f.api.SuccessStatus("publishTeaProductReleaseCollection")
		f.run(runner.Case{
			OperationID: "publishTeaProductReleaseCollection",
			Name:        "publish a collection for the product release",
			Category:    "publication",
			Method:      http.MethodPost,
			Path:        "/productRelease/" + f.productReleaseUUID + "/collection",
			Body:        body(map[string]any{"updateReason": reason}),
			WantStatus:  status,
			SchemaPtr:   schema,
			Check:       requireCollectionIdentity(f.productReleaseUUID, "PRODUCT_RELEASE"),
		})
	}
}

func (f *flow) createDistribution() {
	if f.componentReleaseUUID == "" {
		return
	}
	status, schema := f.api.SuccessStatus("createTeaDistribution")
	res := f.run(runner.Case{
		OperationID: "createTeaDistribution",
		Name:        "create a distribution",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/componentRelease/" + f.componentReleaseUUID + "/distribution",
		Body: body(map[string]any{
			"description": "conformance suite placeholder distribution",
		}),
		WantStatus: status,
		SchemaPtr:  schema,
	})
	f.distributionUUID = uuidOf(res.Body)
	if f.distributionUUID != "" {
		f.record("distribution", f.distributionUUID, "placeholder",
			"/distribution/"+f.distributionUUID)
	}
}

func (f *flow) createArtifact() {
	if f.componentReleaseUUID == "" {
		return
	}
	status, schema := f.api.SuccessStatus("createTeaArtifact")
	res := f.run(runner.Case{
		OperationID: "createTeaArtifact",
		Name:        "create an artifact",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/artifact",
		Body: body(map[string]any{
			// The collection's uuid is the release's uuid, which is the
			// identity rule the consumption specification states and the
			// publication one relies on.
			"collection": f.componentReleaseUUID,
			"name":       f.cycle.NamePrefix + " SBOM " + f.cycle.RunKey,
			"type":       "BOM",
			"formats": []any{
				map[string]any{
					"mediaType":   "application/vnd.cyclonedx+json",
					"description": "CycloneDX 1.6 document published by the conformance suite",
				},
			},
		}),
		WantStatus: status,
		SchemaPtr:  schema,
	})
	f.artifactUUID = uuidOf(res.Body)
	f.record("artifact", f.artifactUUID, "SBOM", "/artifact/"+f.artifactUUID)
}

// uploadArtifact sends the bytes for the format declared above.
//
// The payload is a minimal but genuinely valid CycloneDX document. A server
// that stores whatever it is handed will pass either way; one that validates
// what it stores would reject a placeholder, and failing a provider for being
// stricter than this suite is not a conformance finding.
func (f *flow) uploadArtifact() {
	if f.artifactUUID == "" {
		return
	}
	document := sampleBOM(f.cycle)
	status, schema := f.api.SuccessStatus("uploadTeaArtifactContent")
	f.run(runner.Case{
		OperationID: "uploadTeaArtifactContent",
		Name:        "upload the artifact bytes",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/artifact/" + f.artifactUUID + "/format/0/content",
		Body:        document,
		ContentType: "application/vnd.cyclonedx+json",
		WantStatus:  status,
		SchemaPtr:   schema,
		// A publisher that hosts its own bytes does not implement upload, and
		// the specification allows a format to carry a url instead.
		AcceptStatus: []int{http.StatusNotFound, http.StatusMethodNotAllowed},
		Optional:     true,
	})

	sigStatus, sigSchema := f.api.SuccessStatus("uploadTeaArtifactSignature")
	f.run(runner.Case{
		OperationID: "uploadTeaArtifactSignature",
		Name:        "upload a detached signature for the artifact",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/artifact/" + f.artifactUUID + "/format/0/signature",
		Body:        []byte("-----BEGIN CONFORMANCE PLACEHOLDER-----\n"),
		ContentType: "application/octet-stream",
		WantStatus:  sigStatus,
		AcceptStatus: []int{
			http.StatusNotFound, http.StatusMethodNotAllowed,
			// A server that verifies signatures is entitled to reject a
			// placeholder, and doing so is better behaviour than accepting it.
			http.StatusBadRequest, http.StatusUnprocessableEntity,
		},
		SchemaPtr: sigSchema,
		Optional:  true,
	})
}

func (f *flow) updateArtifact() {
	if f.artifactUUID == "" {
		return
	}
	status, schema := f.api.SuccessStatus("updateTeaArtifact")
	f.run(runner.Case{
		OperationID: "updateTeaArtifact",
		Name:        "update the artifact's metadata",
		Category:    "publication",
		Method:      http.MethodPatch,
		Path:        "/artifact/" + f.artifactUUID,
		Body:        body(map[string]any{"name": f.cycle.NamePrefix + " SBOM " + f.cycle.RunKey + " (revised)"}),
		WantStatus:  status,
		SchemaPtr:   schema,
	})
	f.run(runner.Case{
		OperationID: "getLatestArtifact",
		Name:        "the artifact revision is visible through the consumption API",
		Category:    "publication",
		Path:        "/artifact/" + f.artifactUUID + "/latest",
		WantStatus:  http.StatusOK,
		SchemaPtr:   f.api.OK200("getLatestArtifact"),
	})
}

// accessPolicy exercises the publication specification's access-policy
// operations, which have no counterpart in the consumption document.
func (f *flow) accessPolicy() {
	if f.productUUID == "" || !f.api.Declares("getTeaAccessPolicy") {
		return
	}
	getStatus, getSchema := f.api.SuccessStatus("getTeaAccessPolicy")
	f.run(runner.Case{
		OperationID:  "getTeaAccessPolicy",
		Name:         "read the product's access policy",
		Category:     "publication",
		Path:         "/accessPolicy/" + f.productUUID,
		WantStatus:   getStatus,
		SchemaPtr:    getSchema,
		AcceptStatus: []int{http.StatusNotFound, http.StatusMethodNotAllowed},
		Optional:     true,
	})

	setStatus, setSchema := f.api.SuccessStatus("setTeaAccessPolicy")
	f.run(runner.Case{
		OperationID: "setTeaAccessPolicy",
		Name:        "set the product's access policy to private",
		Category:    "publication",
		Method:      http.MethodPut,
		Path:        "/accessPolicy/" + f.productUUID,
		Body:        body(map[string]any{"visibility": "private"}),
		WantStatus:  setStatus,
		SchemaPtr:   setSchema,
		AcceptStatus: []int{
			http.StatusNotFound, http.StatusMethodNotAllowed,
			// The policy vocabulary is the one part of this payload the suite
			// cannot derive from the document, so a rejection is reported
			// rather than failed.
			http.StatusBadRequest,
		},
		Optional: true,
	})
}

// finish deletes everything this run created, in reverse dependency order.
//
// The delete cases are conformance cases in their own right, since a publication API
// that cannot remove what it created is not conformant, and they are also the
// cleanup. Anything that survives is recorded as residual.
func (f *flow) finish() {
	type target struct {
		record    Record
		operation string
	}
	targets := []target{
		{f.recordFor("artifact"), "deleteTeaArtifact"},
		{f.recordFor("distribution"), "deleteTeaDistribution"},
		{f.recordFor("productRelease"), "deleteTeaProductRelease"},
		{f.recordFor("componentRelease"), "deleteTeaComponentRelease"},
		{f.recordFor("component"), "deleteTeaComponent"},
		{f.recordFor("product"), "deleteTeaProduct"},
	}

	for _, t := range targets {
		if t.record.UUID == "" {
			continue
		}
		want := f.successStatus(t.operation, http.StatusNoContent)
		res := f.run(runner.Case{
			OperationID: t.operation,
			Name:        "delete the " + t.record.Kind,
			Category:    "publication",
			Method:      http.MethodDelete,
			Path:        t.record.DeletePath,
			WantStatus:  want,
			// A cascading delete removes children with their parent, so a child
			// that is already gone is correct behaviour and not a failure.
			AcceptStatus: []int{http.StatusNotFound},
		})
		f.markDeleted(t.record.Kind, res.GotStatus,
			res.GotStatus == want || res.GotStatus == http.StatusNotFound)
	}

	// The product is the root of everything created here, so its absence is the
	// check that the estate is genuinely clean.
	if f.productUUID != "" {
		f.run(runner.Case{
			OperationID: "getTeaProductByUuid",
			Name:        "the deleted product is gone from the consumption API",
			Category:    "publication",
			Path:        "/product/" + f.productUUID,
			WantStatus:  http.StatusNotFound,
			SchemaPtr:   f.api.Status("getTeaProductByUuid", 404),
		})
	}

	for _, r := range f.found.Created {
		if !r.Deleted {
			f.found.Residual = append(f.found.Residual, r)
		}
	}
}

// --- Plumbing ---

// fixedDate is a constant so a re-run writes the same values. A timestamp would
// make every run's objects different and defeat the reclaim step.
const fixedDate = "2020-01-01T00:00:00Z"

func (f *flow) next() int {
	f.seq++
	return f.seq
}

func (f *flow) run(tc runner.Case) runner.Result {
	tc.Area = config.AreaProvider
	tc.Seq = f.next()
	res := runner.RunSerial(f.ctx, f.client, f.api, []runner.Case{tc})[0]

	switch res.GotStatus {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		if tc.Method != "" && tc.Method != http.MethodGet && !contains(f.found.Unsupported, tc.OperationID) {
			f.found.Unsupported = append(f.found.Unsupported, tc.OperationID)
		}
	}
	f.results = append(f.results, res)
	return res
}

// downgrade turns an already-recorded failure into an advisory observation,
// for the case where what looked like a provider defect turns out to be a fact
// about the specification instead. The request and its response stay in the
// report; only the verdict changes, and the reason replaces the error.
func (f *flow) downgrade(seq int, reason string) {
	for i := range f.results {
		if f.results[i].Seq != seq {
			continue
		}
		f.results[i].Errors = nil
		f.results[i].Warnings = append(f.results[i].Warnings, reason)
		f.results[i].Optional = true
		f.results[i].Pass = true
		return
	}
}

func (f *flow) note(caseName, detail string) {
	f.results = append(f.results, runner.Result{
		Area: config.AreaProvider, Seq: f.next(),
		Case: caseName, Category: "publication", Method: "-",
		Pass: true, Optional: true, Warnings: []string{detail},
	})
}

func (f *flow) fail(caseName, detail string) {
	f.results = append(f.results, runner.Result{
		Area: config.AreaProvider, Seq: f.next(),
		Case: caseName, Category: "security", Method: "-",
		Errors: []string{detail},
	})
}

func (f *flow) record(kind, uuid, label, deletePath string) {
	if uuid == "" {
		return
	}
	f.found.Created = append(f.found.Created, Record{
		Kind: kind, UUID: uuid, Label: label,
		DeletePath: deletePath, Method: http.MethodDelete,
	})
}

func (f *flow) recordFor(kind string) Record {
	for _, r := range f.found.Created {
		if r.Kind == kind {
			return r
		}
	}
	return Record{}
}

func (f *flow) markDeleted(kind string, status int, ok bool) {
	for i := range f.found.Created {
		if f.found.Created[i].Kind != kind {
			continue
		}
		f.found.Created[i].DeleteStatus = status
		f.found.Created[i].Deleted = ok
		if !ok {
			f.found.Created[i].Note = fmt.Sprintf("the delete answered HTTP %d", status)
		}
		return
	}
}

// successStatus reads the declared success code, falling back where the
// document is silent.
func (f *flow) successStatus(operationID string, fallback int) int {
	if status, _ := f.api.SuccessStatus(operationID); status != 0 {
		return status
	}
	return fallback
}

func body(v map[string]any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// identifierOf reads the assigned identity out of a create response in the
// older model, which names it `identifier` and not `uuid`.
func identifierOf(payload []byte) string {
	var v map[string]any
	if err := json.Unmarshal(payload, &v); err != nil {
		return ""
	}
	for _, key := range []string{"identifier", "uuid"} {
		if id := runner.AsString(v, key); id != "" {
			return id
		}
	}
	return ""
}

func uuidOf(payload []byte) string {
	var v map[string]any
	if err := json.Unmarshal(payload, &v); err != nil {
		return ""
	}
	if id := runner.AsString(v, "uuid"); id != "" {
		return id
	}
	// A create that answers with the object wrapped under its own type still
	// carries the identifier a caller needs.
	for _, key := range []string{"product", "component", "release", "artifact", "distribution"} {
		if nested := runner.AsMap(v[key]); nested != nil {
			if id := runner.AsString(nested, "uuid"); id != "" {
				return id
			}
		}
	}
	return ""
}

// requireAssignedIdentity asserts the server minted what only it can mint.
func requireAssignedIdentity(payload []byte, wantName string) error {
	var v map[string]any
	if err := json.Unmarshal(payload, &v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if runner.AsString(v, "uuid") == "" {
		return fmt.Errorf("the created object carries no uuid, so a publisher has no handle on it")
	}
	if got := runner.AsString(v, "name"); got != wantName {
		return fmt.Errorf("the created object is named %q, but %q was written", got, wantName)
	}
	return nil
}

func requireCollectionIdentity(releaseUUID, belongsTo string) func([]byte) error {
	return func(payload []byte) error {
		var v map[string]any
		if err := json.Unmarshal(payload, &v); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		if got := runner.AsString(v, "uuid"); got != releaseUUID {
			return fmt.Errorf("the published collection's uuid is %q, but tea-collection.md "+
				"requires it to equal the release uuid %q", got, releaseUUID)
		}
		if got := runner.AsString(v, "belongsTo"); got != belongsTo {
			return fmt.Errorf("belongsTo is %q, expected %s", got, belongsTo)
		}
		return nil
	}
}

// sampleBOM is the document uploaded as artifact content: minimal, valid
// CycloneDX 1.6, and deterministic so a re-run uploads identical bytes.
func sampleBOM(cycle config.WriteCycle) []byte {
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:6d4f2e0a-0000-4000-8000-000000000001",
		"version":      1,
		"metadata": map[string]any{
			"timestamp": fixedDate,
			"component": map[string]any{
				"type":    "application",
				"name":    productName(cycle),
				"version": releaseVersion,
			},
		},
		"components": []any{},
	}
	b, _ := json.Marshal(doc)
	return b
}

func contains(items []string, want string) bool {
	for _, i := range items {
		if i == want {
			return true
		}
	}
	return false
}
