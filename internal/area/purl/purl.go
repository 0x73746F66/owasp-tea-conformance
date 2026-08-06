// Package purl checks how a provider handles package URLs: the identifiers it
// publishes, the filter it answers them on, and the purl-typed TEIs the
// discovery specification defines.
//
// A purl is the identifier a consumer most often arrives with. It is what a
// dependency scanner emits, what an SBOM component carries, and what a TEI
// looks like when the vendor has no product number to quote. If a provider
// publishes purls it cannot then be queried by, a consumer holding one has no
// route into the catalogue at all.
package purl

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"

	"github.com/0x73746F66/owasp-tea-conformance/internal/area/consumer"
	"github.com/0x73746F66/owasp-tea-conformance/internal/area/inventory"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

// Sequence bases for this area's recordings.
const (
	seqRoundTrip = 1
	seqTEI       = 100
	seqSample    = 1000
)

// SampleOutcome is what happened when the configured package sample was asked
// for. It is reported rather than asserted: a provider is not required to hold
// any particular open-source project, and a run that failed because somebody
// else's catalogue lacks a package would be testing the wrong thing.
type SampleOutcome struct {
	Requested int      `json:"requested"`
	Resolved  int      `json:"resolved"`
	Missing   int      `json:"missing"`
	Errors    int      `json:"errors"`
	Found     []string `json:"found,omitempty"`
	Absent    []string `json:"absent,omitempty"`
}

// Findings is everything this area learned beyond its pass/fail cases.
type Findings struct {
	PublishedPurls int            `json:"publishedPurls"`
	Malformed      []string       `json:"malformedPurls,omitempty"`
	Types          map[string]int `json:"purlTypes"`
	Sample         SampleOutcome  `json:"sample"`
}

// Run exercises the area and returns its cases plus what it observed.
func Run(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	f consumer.Fixtures,
	inv inventory.Inventory,
	packages []string,
	concurrency int,
) ([]runner.Result, Findings) {
	found := Findings{Types: map[string]int{}}
	var results []runner.Result

	// --- The purls this provider already publishes ---
	//
	// Checked locally rather than over the wire: a malformed identifier is a
	// fact about the response already in hand, and re-requesting it to say so
	// would only add load.
	var published []string
	for _, p := range inv.Products {
		if p.PURL == "" {
			continue
		}
		published = append(published, p.PURL)
		if problem := structural(p.PURL); problem != "" {
			found.Malformed = append(found.Malformed,
				fmt.Sprintf("%s (%s): %s", p.PURL, p.Name, problem))
			continue
		}
		if t := purlType(p.PURL); t != "" {
			found.Types[t]++
		}
	}
	found.PublishedPurls = len(published)
	sort.Strings(found.Malformed)

	local := runner.Result{
		Area: config.AreaPurl, Seq: 0,
		OperationID: "queryTeaProducts",
		Case:        "every published PURL identifier is well formed",
		Category:    "purl",
		Method:      "-",
		Pass:        len(found.Malformed) == 0,
	}
	if len(found.Malformed) > 0 {
		local.Errors = append(local.Errors, fmt.Sprintf(
			"%d of %d published purls are malformed: %s",
			len(found.Malformed), found.PublishedPurls, strings.Join(clip(found.Malformed, 5), "; ")))
	}
	results = append(results, local)

	// --- The round-trip ---
	//
	// A purl the provider published must find the object it was published on.
	// This is the check that catches a server which stores identifiers but
	// indexes only its own UUIDs.
	var cases []runner.Case
	if f.ProductPURL != "" {
		cases = append(cases, runner.Case{
			OperationID: "queryTeaProducts",
			Name:        "a published purl finds its own product",
			Category:    "purl",
			Path:        "/products",
			Query:       url.Values{"idType": {"PURL"}, "idValue": {f.ProductPURL}},
			WantStatus:  200, SchemaPtr: api.OK200("queryTeaProducts"),
			Check: requireProduct(f.ProductUUID),
		}, runner.Case{
			OperationID: "queryTeaProducts",
			Name:        "a purl for a package this provider does not hold matches nothing",
			Category:    "negative",
			Path:        "/products",
			Query: url.Values{"idType": {"PURL"},
				"idValue": {"pkg:generic/tea-conformance/definitely-not-published@0.0.0"}},
			WantStatus: 200, SchemaPtr: api.OK200("queryTeaProducts"),
			Check: requireEmpty,
		}, runner.Case{
			OperationID: "queryTeaProducts",
			Name:        "reject a purl that is not a purl",
			Category:    "negative",
			Path:        "/products",
			Query:       url.Values{"idType": {"PURL"}, "idValue": {"not-a-purl"}},
			WantStatus:  400,
			// A server that treats an unparseable identifier as "matches
			// nothing" is defensible; what it must not do is 500.
			AcceptStatus: []int{200},
		})
	}
	results = append(results, runner.Run(ctx, c, api,
		consumer.Number(cases, config.AreaPurl, seqRoundTrip), concurrency)...)

	// --- purl-typed TEIs ---
	//
	// urn:tei:purl:<domain>:<purl> is one of the identifier types the discovery
	// specification defines, and the only one a consumer can construct without
	// the vendor having told them anything.
	var teiCases []runner.Case
	if f.ProductPURL != "" {
		teiCases = append(teiCases, runner.Case{
			OperationID: "discoveryByTei",
			Name:        "resolve a purl-typed TEI",
			Category:    "purl",
			Path:        "/discovery",
			Query:       url.Values{"tei": {f.PurlTEI(f.ProductPURL)}},
			WantStatus:  200, SchemaPtr: api.OK200("discoveryByTei"),
		}, runner.Case{
			OperationID: "discoveryByTei",
			Name:        "a purl-typed TEI from another authority is not resolved",
			Category:    "negative",
			Path:        "/discovery",
			Query: url.Values{"tei": {
				"urn:tei:purl:tea-conformance.invalid:" + f.ProductPURL}},
			WantStatus: 404, SchemaPtr: api.Status("discoveryByTei", 404),
		})
	}
	results = append(results, runner.Run(ctx, c, api,
		consumer.Number(teiCases, config.AreaPurl, seqTEI), concurrency)...)

	// --- The configured sample ---
	found.Sample = runSample(ctx, c, api, packages, concurrency, &results)

	return results, found
}

// runSample asks the provider for each package in the configured list.
//
// The outcome is evidence, not a verdict: what it establishes is how much of a
// known open-source sample a catalogue actually covers, which is the number
// that makes two providers comparable.
func runSample(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	packages []string,
	concurrency int,
	results *[]runner.Result,
) SampleOutcome {
	out := SampleOutcome{Requested: len(packages)}
	if len(packages) == 0 {
		return out
	}

	sorted := append([]string(nil), packages...)
	sort.Strings(sorted)

	cases := make([]runner.Case, 0, len(sorted))
	for _, p := range sorted {
		cases = append(cases, runner.Case{
			OperationID: "queryTeaProducts",
			Name:        "sample package " + p,
			Category:    "sample",
			Path:        "/products",
			Query:       url.Values{"idType": {"PURL"}, "idValue": {p}},
			WantStatus:  200, SchemaPtr: api.OK200("queryTeaProducts"),
			// The sample never fails a run. A provider is not required to
			// publish anybody else's software.
			Optional: true,
		})
	}
	sampleResults := runner.Run(ctx, c, api,
		consumer.Number(cases, config.AreaPurl, seqSample), concurrency)

	for i, res := range sampleResults {
		switch {
		case res.GotStatus != 200:
			out.Errors++
		case hasResults(res.Body):
			out.Resolved++
			out.Found = append(out.Found, sorted[i])
		default:
			out.Missing++
			out.Absent = append(out.Absent, sorted[i])
		}
	}
	// The per-package results stay out of the case tally, because three hundred rows
	// saying "this provider does not publish somebody else's package" would
	// bury the conformance findings. The summary below carries the outcome.
	summary := runner.Result{
		Area: config.AreaPurl, Seq: seqSample - 1,
		OperationID: "queryTeaProducts",
		Case:        fmt.Sprintf("open-source sample: %d of %d packages resolved", out.Resolved, out.Requested),
		Category:    "sample",
		Method:      "GET",
		Pass:        out.Errors == 0,
		Optional:    true,
	}
	if out.Errors > 0 {
		summary.Errors = append(summary.Errors,
			fmt.Sprintf("%d sample queries did not return 200", out.Errors))
	}
	*results = append(*results, summary)
	return out
}

// structural reports what is wrong with a purl, or "" when it is usable.
//
// The parse itself is delegated to the shared CycloneDX module, so a purl means
// the same thing here as it does everywhere else in the toolchain. What is
// added on top are the spelling rules a consumer's exact-match lookup depends
// on.
func structural(p string) string {
	if !strings.HasPrefix(p, "pkg:") {
		return "does not start with the pkg: scheme"
	}
	rest := strings.TrimPrefix(p, "pkg:")
	if strings.HasPrefix(rest, "/") {
		return "the scheme is followed by a slash; a purl has no authority component"
	}
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return "has no type and name"
	}
	typ := rest[:slash]
	if typ != strings.ToLower(typ) {
		return "the type must be lowercase, and " + typ + " is not"
	}
	// A purl type outside the well-known set is legitimate, so an empty
	// ecosystem is not a fault. Only a name that will not parse means a
	// consumer cannot use the identifier.
	if _, name, _ := cdx.ParsePurl(p); name == "" {
		return "no package name could be parsed out of it"
	}
	return ""
}

func purlType(p string) string {
	rest := strings.TrimPrefix(p, "pkg:")
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return ""
}

func requireProduct(wantUUID string) func([]byte) error {
	return func(body []byte) error {
		for _, item := range decodeResults(body) {
			if runner.AsString(item, "uuid") == wantUUID {
				return nil
			}
		}
		return fmt.Errorf("the purl this provider published for %s did not find it again; "+
			"a consumer arriving with that identifier has no way in", wantUUID)
	}
}

func requireEmpty(body []byte) error {
	if n := len(decodeResults(body)); n > 0 {
		return fmt.Errorf("a purl naming a package that cannot exist matched %d product(s)", n)
	}
	return nil
}

func hasResults(body []byte) bool { return len(decodeResults(body)) > 0 }

func decodeResults(body []byte) []map[string]any {
	var env struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	return env.Results
}

func clip(items []string, max int) []string {
	if len(items) <= max {
		return items
	}
	out := append([]string(nil), items[:max]...)
	return append(out, fmt.Sprintf("and %d more", len(items)-max))
}
