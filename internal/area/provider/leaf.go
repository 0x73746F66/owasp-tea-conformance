package provider

// The older publication model.
//
// The upstream main branch still carries spec/publisher/openapi.json at version
// 0.0.2, describing products, *leaves* and collections. That is a TEA generation
// before the 0.4.0 consumption specification and PR 147's matching publisher
// specification. The models do not share an object model or naming scheme.
//
// So this file is the round-trip for the older model. It is deliberately
// shorter than the newer one: the document declares thirteen operations rather
// than twenty-three, and there is no artifact upload, no distribution and no
// access policy in it.

import (
	"net/http"
	"net/url"

	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

// leafRoundTrip creates a product, a leaf beneath it and a collection beneath
// that, reads each one back, and deletes them again.
func (f *flow) leafRoundTrip() {
	f.reclaimLeafModel()

	f.createLeafProduct()
	if f.productUUID == "" {
		f.finishLeafModel()
		return
	}
	f.createLeaf()
	f.createLeafCollection()
	f.readBackLeafModel()
	f.finishLeafModel()
}

// productTEI is how this model addresses a product: its path parameter is a TEI
// URN and not the identifier the create call returned.
func (f *flow) productTEI() string {
	return "urn:tei:purl:" + f.authority + ":" + f.found.PURL
}

func (f *flow) reclaimLeafModel() {
	// Addressing is by TEI, and a TEI is derived from what this run publishes,
	// so a previous run's product is reachable without a search.
	res := f.run(runner.Case{
		OperationID: "getTeaProduct",
		Name:        "look for a product left by a previous run",
		Category:    "cleanup",
		Path:        "/product/" + url.PathEscape(f.productTEI()),
		WantStatus:  http.StatusOK,
		AcceptStatus: []int{
			http.StatusNotFound,
			// Some servers reject an unencoded or unknown URN outright rather
			// than reporting it absent; either way there is nothing to reclaim.
			http.StatusBadRequest,
		},
	})
	if res.GotStatus != http.StatusOK {
		return
	}
	f.found.Reclaimed++
	f.run(runner.Case{
		OperationID:  "deleteTeaProduct",
		Name:         "remove a product left by a previous run",
		Category:     "cleanup",
		Method:       http.MethodDelete,
		Path:         "/product/" + url.PathEscape(f.productTEI()),
		WantStatus:   f.successStatus("deleteTeaProduct", http.StatusNoContent),
		AcceptStatus: []int{http.StatusNotFound},
	})
}

func (f *flow) createLeafProduct() {
	status, schema := f.api.SuccessStatus("createTeaProduct")
	res := f.run(runner.Case{
		OperationID: "createTeaProduct",
		Name:        "create a product",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/product",
		Body: body(map[string]any{
			"product_name": productName(f.cycle),
			"purl":         f.found.PURL,
		}),
		WantStatus: status,
		SchemaPtr:  schema,
	})
	// This model names the assigned identifier `identifier` and not `uuid`.
	f.productUUID = identifierOf(res.Body)

	// A 400 on the very first write, from a server that answered 401 to the
	// anonymous probe a moment earlier, means the endpoint is there and does
	// not speak this document. That is the two upstream specifications being
	// different generations, not a defect in the provider: the request body
	// this model defines is simply not the one the provider implements.
	if res.GotStatus == http.StatusBadRequest {
		f.found.ModelMismatch = true
		f.found.Detail = "the publication endpoints are served, but rejected the request body " +
			"this specification defines: the fetched publication document (" + dash(f.api.Version) +
			", product/leaf/collection) is an older generation than the object model the " +
			"provider implements. Point specs.publisher at a document describing the same " +
			"generation as the consumption specification to exercise it."
		f.downgrade(res.Seq, "the publication model in the fetched specification is not the one "+
			"this provider implements")
		return
	}
	f.record("product", f.productUUID, productName(f.cycle),
		"/product/"+url.PathEscape(f.productTEI()))
}

func (f *flow) createLeaf() {
	if f.productUUID == "" || !f.api.Declares("createTeaLeaf") {
		return
	}
	status, schema := f.api.SuccessStatus("createTeaLeaf")
	res := f.run(runner.Case{
		OperationID: "createTeaLeaf",
		Name:        "create a leaf for the product",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/leaf",
		Body: body(map[string]any{
			"tea_product_identifier": f.productUUID,
			"product_version":        releaseVersion,
			"release_date":           fixedDate,
			"pre_release":            true,
		}),
		WantStatus: status,
		SchemaPtr:  schema,
	})
	f.leafUUID = identifierOf(res.Body)
	f.record("leaf", f.leafUUID, releaseVersion, "/leaf/"+f.leafUUID)
}

func (f *flow) createLeafCollection() {
	if f.leafUUID == "" || !f.api.Declares("createTeaCollection") {
		return
	}
	status, schema := f.api.SuccessStatus("createTeaCollection")
	res := f.run(runner.Case{
		OperationID: "createTeaCollection",
		Name:        "create a collection for the leaf",
		Category:    "publication",
		Method:      http.MethodPost,
		Path:        "/collection",
		Body: body(map[string]any{
			"tea_leaf_identifier": f.leafUUID,
			"product_name":        productName(f.cycle),
			"product_version":     releaseVersion,
			"release_date":        fixedDate,
			"artifacts":           []any{},
		}),
		WantStatus: status,
		SchemaPtr:  schema,
	})
	f.collectionUUID = identifierOf(res.Body)
	f.record("collection", f.collectionUUID, "empty collection",
		"/collection/"+f.collectionUUID)
}

// readBackLeafModel asserts the writes are visible through the read operations,
// which is what catches a publication API writing somewhere the consumption
// half does not read.
func (f *flow) readBackLeafModel() {
	if f.leafUUID != "" && f.api.Declares("getTeaLeaf") {
		status, schema := f.api.SuccessStatus("getTeaLeaf")
		f.run(runner.Case{
			OperationID: "getTeaLeaf",
			Name:        "the written leaf is readable",
			Category:    "publication",
			Path:        "/leaf/" + f.leafUUID,
			WantStatus:  status,
			SchemaPtr:   schema,
		})
	}
	if f.collectionUUID != "" && f.api.Declares("getTeaCollection") {
		status, schema := f.api.SuccessStatus("getTeaCollection")
		f.run(runner.Case{
			OperationID: "getTeaCollection",
			Name:        "the written collection is readable",
			Category:    "publication",
			Path:        "/collection/" + f.collectionUUID,
			WantStatus:  status,
			SchemaPtr:   schema,
		})
	}
}

// finishLeafModel deletes in reverse dependency order, which is both the last
// set of conformance cases and the cleanup.
func (f *flow) finishLeafModel() {
	for _, target := range []struct {
		kind      string
		operation string
	}{
		{"collection", "deleteTeaCollection"},
		{"leaf", "deleteTeaLeaf"},
		{"product", "deleteTeaProduct"},
	} {
		record := f.recordFor(target.kind)
		if record.UUID == "" || !f.api.Declares(target.operation) {
			continue
		}
		want := f.successStatus(target.operation, http.StatusNoContent)
		res := f.run(runner.Case{
			OperationID: target.operation,
			Name:        "delete the " + target.kind,
			Category:    "publication",
			Method:      http.MethodDelete,
			Path:        record.DeletePath,
			WantStatus:  want,
			// A cascading delete removes children with their parent, so a child
			// already gone is correct, not a failure.
			AcceptStatus: []int{http.StatusNotFound},
		})
		f.markDeleted(target.kind, res.GotStatus,
			res.GotStatus == want || res.GotStatus == http.StatusNotFound)
	}

	for _, r := range f.found.Created {
		if !r.Deleted {
			f.found.Residual = append(f.found.Residual, r)
		}
	}
}
