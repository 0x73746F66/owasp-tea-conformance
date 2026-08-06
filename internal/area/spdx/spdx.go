// Package spdx checks the licence identifiers a provider publishes.
//
// A licence is the one field in a transparency document that is read by people
// who are not engineers, and it is read exactly: a compliance tool matches
// "Apache-2.0" and does not match "Apache 2.0", "apache-2.0" or "ASL 2.0".
// An identifier that is nearly right is worse than an absent one, because the
// absent one is visibly missing and the near-miss silently classifies as
// unknown.
//
// Two sources are checked: the licences inside the CycloneDX documents this run
// already downloaded, and the `license` field on lifecycle events, which the
// TEA schema also expects to be an SPDX identifier.
package spdx

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"

	"github.com/0x73746F66/owasp-tea-conformance/internal/area/cyclonedx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/area/inventory"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

// CLESampleLimit caps how many lifecycle documents are read for their licence
// field. The report states the cap.
const CLESampleLimit = 10

const seqCLE = 100

// Problem is one identifier that will not resolve.
type Problem struct {
	Identifier string `json:"identifier"`
	Where      string `json:"where"`
	Reason     string `json:"reason"`
	Verdict    string `json:"verdict"`
}

// Findings is what this area observed.
type Findings struct {
	ListVersion string `json:"licenceListVersion,omitempty"`

	Checked    int `json:"identifiersChecked"`
	Valid      int `json:"valid"`
	Deprecated int `json:"deprecated"`
	WrongCase  int `json:"wrongCase"`
	Unknown    int `json:"unknown"`

	// Named counts identifiers carried as a name or a free-text expression
	// where an SPDX id was available. CycloneDX allows it, and a consumer
	// cannot match on it, so it is reported as evidence rather than failure.
	FreeText int `json:"freeTextLicences"`

	Distinct   map[string]int `json:"distinctIdentifiers"`
	Problems   []Problem      `json:"problems,omitempty"`
	CLERead    int            `json:"lifecycleDocumentsRead"`
	CLESkipped int            `json:"lifecycleDocumentsSkippedByLimit"`
}

// Run checks every licence identifier this run can see.
func Run(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	list *spec.LicenseList,
	docs cyclonedx.Findings,
	inv inventory.Inventory,
	concurrency int,
) ([]runner.Result, Findings) {
	found := Findings{Distinct: map[string]int{}}
	if list != nil {
		found.ListVersion = list.Version
	}
	var results []runner.Result

	// ── Licences inside the BOM documents ───────────────────────────────────
	for _, doc := range docs.Documents {
		if len(doc.Raw) == 0 || !doc.Valid {
			continue
		}
		bom, err := cdx.ParseCDX(doc.Raw)
		if err != nil || bom == nil {
			continue
		}
		where := doc.ArtifactName
		if where == "" {
			where = doc.ArtifactUUID
		}
		if doc.ProductName != "" {
			where += " (" + doc.ProductName + ")"
		}
		for _, lic := range cdx.ExtractLicenses(bom) {
			found.check(list, lic.SPDXID, lic.Name, where)
		}
	}

	// ── The lifecycle documents' licence field ──────────────────────────────
	sampled := sampleReleases(inv)
	if n := len(inv.Releases) - len(sampled); n > 0 {
		found.CLESkipped = n
	}
	cases := make([]runner.Case, 0, len(sampled))
	for _, rel := range sampled {
		cases = append(cases, runner.Case{
			OperationID: "getCleByProductReleaseId",
			Name:        "lifecycle events of " + rel.UUID,
			Category:    "spdx",
			Path:        "/productRelease/" + rel.UUID + "/cle",
			WantStatus:  200, SchemaPtr: api.OK200("getCleByProductReleaseId"),
			// A publisher is not required to publish a lifecycle document, so
			// an absent one is not a conformance failure here. The consumer
			// area already asserts the operation itself behaves.
			AcceptStatus: []int{404},
			Optional:     true,
		})
	}
	for i := range cases {
		cases[i].Area = config.AreaSPDX
		cases[i].Seq = seqCLE + i
	}
	cleResults := runner.Run(ctx, c, api, cases, concurrency)
	for i, res := range cleResults {
		if res.GotStatus == 200 {
			found.CLERead++
			for _, licence := range cleLicences(res.Body) {
				found.check(list, licence, "", "lifecycle events of "+sampled[i].UUID)
			}
		}
	}
	results = append(results, cleResults...)

	// ── The verdict ─────────────────────────────────────────────────────────
	sort.Slice(found.Problems, func(i, j int) bool {
		if found.Problems[i].Identifier != found.Problems[j].Identifier {
			return found.Problems[i].Identifier < found.Problems[j].Identifier
		}
		return found.Problems[i].Where < found.Problems[j].Where
	})

	verdict := runner.Result{
		Area: config.AreaSPDX, Seq: 0,
		OperationID: "licenceIdentifiers",
		Case:        "every published licence identifier resolves against the SPDX licence list",
		Category:    "spdx",
		Method:      "—",
	}
	switch {
	case found.Checked == 0:
		verdict.Pass = true
		verdict.Optional = true
		verdict.Case = "no licence identifiers were published in anything this run could read"
	case found.Unknown > 0 || found.WrongCase > 0:
		verdict.Errors = append(verdict.Errors, fmt.Sprintf(
			"%d of %d identifiers do not resolve: %s",
			found.Unknown+found.WrongCase, found.Checked,
			strings.Join(summarise(found.Problems, 6), "; ")))
	default:
		verdict.Pass = true
	}
	results = append(results, verdict)

	if found.Deprecated > 0 {
		results = append(results, runner.Result{
			Area: config.AreaSPDX, Seq: 1,
			OperationID: "licenceIdentifiers",
			Case: fmt.Sprintf("%d identifier(s) are real but deprecated by SPDX",
				found.Deprecated),
			Category: "spdx", Method: "—", Pass: true, Optional: true,
		})
	}
	if found.CLESkipped > 0 {
		results = append(results, runner.Result{
			Area: config.AreaSPDX, Seq: 2,
			Case: fmt.Sprintf("%d further lifecycle document(s) were not read (limit %d)",
				found.CLESkipped, CLESampleLimit),
			Category: "coverage", Method: "—", Pass: true, Optional: true,
		})
	}
	return results, found
}

// check classifies one identifier and records it.
func (f *Findings) check(list *spec.LicenseList, id, name, where string) {
	id = strings.TrimSpace(id)
	if id == "" {
		// CycloneDX permits a free-text licence name where no identifier
		// exists. It is legitimate and unmatchable, so it is counted, not
		// failed.
		if strings.TrimSpace(name) != "" {
			f.FreeText++
		}
		return
	}
	f.Checked++
	f.Distinct[id]++
	if list == nil {
		return
	}
	problems := list.CheckExpression(id)
	if len(problems) == 0 {
		f.Valid++
		return
	}
	worst := spec.LicenseValid
	for _, p := range problems {
		if p.Verdict > worst {
			worst = p.Verdict
		}
		f.Problems = append(f.Problems, Problem{
			Identifier: p.Token,
			Where:      where,
			Reason:     p.Hint,
			Verdict:    verdictName(p.Verdict),
		})
	}
	switch worst {
	case spec.LicenseDeprecated:
		f.Deprecated++
	case spec.LicenseWrongCase:
		f.WrongCase++
	default:
		f.Unknown++
	}
}

func verdictName(v spec.Verdict) string {
	switch v {
	case spec.LicenseDeprecated:
		return "deprecated"
	case spec.LicenseWrongCase:
		return "wrong case"
	case spec.LicenseUnknown:
		return "unknown"
	default:
		return "valid"
	}
}

// sampleReleases picks the releases whose lifecycle documents are read, capped
// and deterministically ordered.
func sampleReleases(inv inventory.Inventory) []inventory.Release {
	sampled := append([]inventory.Release(nil), inv.Releases...)
	sort.Slice(sampled, func(i, j int) bool { return sampled[i].UUID < sampled[j].UUID })
	if len(sampled) > CLESampleLimit {
		sampled = sampled[:CLESampleLimit]
	}
	return sampled
}

// cleLicences pulls the licence field off lifecycle events.
func cleLicences(body []byte) []string {
	var doc struct {
		Events []struct {
			License string `json:"license"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	var out []string
	for _, e := range doc.Events {
		if e.License != "" {
			out = append(out, e.License)
		}
	}
	return out
}

func summarise(problems []Problem, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range problems {
		if p.Verdict == "deprecated" {
			continue
		}
		key := p.Identifier + " — " + p.Reason
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
		if len(out) == max {
			out = append(out, "…")
			break
		}
	}
	return out
}
