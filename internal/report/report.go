// Package report turns a run into the two artefacts it exists to produce: a
// JSON record that can be diffed between runs or gated on in CI, and a Markdown
// rendering of the same data for a person.
//
// Both come from one in-memory Report, so they cannot disagree.
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	celarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/cel"
	"github.com/0x73746F66/owasp-tea-conformance/internal/area/consumer"
	cdxarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/cyclonedx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/area/discovery"
	"github.com/0x73746F66/owasp-tea-conformance/internal/area/insights"
	"github.com/0x73746F66/owasp-tea-conformance/internal/area/inventory"
	perfarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/performance"
	provarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/provenance"
	pubarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/provider"
	purlarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/purl"
	spdxarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/spdx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

// Report is the whole outcome of one provider's run.
type Report struct {
	Title       string `json:"title"`
	GeneratedAt string `json:"generatedAt"`
	Mode        string `json:"mode"`

	Provider   string `json:"provider"`
	Domain     string `json:"domain,omitempty"`
	RootURL    string `json:"rootUrl,omitempty"`
	TEAVersion string `json:"teaVersion,omitempty"`
	Credential string `json:"credential"`

	Areas       []config.Area `json:"areas"`
	Concurrency int           `json:"concurrency"`

	Specs     []spec.Document      `json:"specifications"`
	Discovery discovery.Resolution `json:"discovery"`
	Fixtures  consumer.Fixtures    `json:"fixtures"`
	Efficacy  inventory.Stats      `json:"efficacy"`
	// Products is the catalogue as the API serves it, built by paging
	// /products and never read from anywhere else. It is the claim itself:
	// these specific projects are published as TEA products. A reader
	// should be able to check it instead of taking it on faith.
	Products  []inventory.Product `json:"products,omitempty"`
	Purl      purlarea.Findings   `json:"purl"`
	CycloneDX cdxarea.Findings    `json:"cyclonedx"`
	SPDX      spdxarea.Findings   `json:"spdx"`
	Insights  insights.Findings   `json:"insights"`
	CEL       celarea.Findings    `json:"cel"`
	Prov      provarea.Findings   `json:"provenance"`
	Perf      perfarea.Findings   `json:"performance"`
	Publisher pubarea.Findings    `json:"publication"`
	Results   []runner.Result     `json:"results"`

	Totals     Totals                 `json:"totals"`
	ByArea     map[config.Area]Totals `json:"byArea"`
	ByCategory map[string]Totals      `json:"byCategory"`
	Operations []OperationOutcome     `json:"operations"`
	Latency    runner.Latency         `json:"conformanceLatency"`

	// Coverage records which of the specifications' operations were exercised.
	// A conformance claim is only as good as its coverage, so an unexercised
	// operation is reported, never silently omitted.
	Coverage []Coverage `json:"coverage"`

	// Errors are conditions that broke the run itself rather than findings
	// about the provider.
	Errors []string `json:"errors,omitempty"`

	// SpecWarnings are defects in the specifications themselves. They belong in
	// the report because a reader comparing two providers judged by the same
	// document deserves to know that document has a problem in it, and because
	// a suite that worked around one silently would let it survive.
	SpecWarnings []string `json:"specificationWarnings,omitempty"`
}

// Totals counts case outcomes.
type Totals struct {
	Cases          int `json:"cases"`
	Passed         int `json:"passed"`
	Failed         int `json:"failed"`
	Advisory       int `json:"advisory"`
	SchemaChecked  int `json:"schemaChecked"`
	SchemaConforms int `json:"schemaConforms"`
}

func (t *Totals) add(r runner.Result) {
	t.Cases++
	switch {
	case r.Pass:
		t.Passed++
	case r.Optional:
		t.Advisory++
	default:
		t.Failed++
	}
	if r.SchemaChecked {
		t.SchemaChecked++
		if r.SchemaValid {
			t.SchemaConforms++
		}
	}
}

// Coverage is one specification's operation coverage.
type Coverage struct {
	Specification string   `json:"specification"`
	Version       string   `json:"version,omitempty"`
	Declared      int      `json:"declared"`
	Exercised     int      `json:"exercised"`
	Unexercised   []string `json:"unexercised,omitempty"`
}

// OperationOutcome is the per-operation rollup.
type OperationOutcome struct {
	OperationID string         `json:"operationId"`
	Method      string         `json:"method"`
	Path        string         `json:"path"`
	Totals      Totals         `json:"totals"`
	Latency     runner.Latency `json:"latency"`
	Conformant  bool           `json:"conformant"`
	Failures    []string       `json:"failures,omitempty"`
}

// Build rolls the results up. Everything it computes is derived, so a caller
// only has to fill in the raw sections.
func (r *Report) Build(apis map[spec.Kind]*spec.API) {
	r.ByArea = map[config.Area]Totals{}
	r.ByCategory = map[string]Totals{}
	byOp := map[string][]runner.Result{}

	var conformancePhase []runner.Result
	for _, res := range r.Results {
		r.Totals.add(res)

		area := r.ByArea[res.Area]
		area.add(res)
		r.ByArea[res.Area] = area

		cat := res.Category
		if cat == "" {
			cat = "conformance"
		}
		category := r.ByCategory[cat]
		category.add(res)
		r.ByCategory[cat] = category

		if res.OperationID != "" {
			byOp[res.OperationID] = append(byOp[res.OperationID], res)
		}
		// The load phase's own samples are not in Results, but its one recorded
		// request per shape is; excluding the performance area here keeps the
		// conformance-phase distribution describing the conformance phase.
		if res.Area != config.AreaPerformance && res.LatencyMs > 0 {
			conformancePhase = append(conformancePhase, res)
		}
	}
	r.Latency = runner.Summarise(conformancePhase)

	ids := make([]string, 0, len(byOp))
	for id := range byOp {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		results := byOp[id]
		out := OperationOutcome{OperationID: id, Latency: runner.Summarise(results)}
		for _, api := range apis {
			if api == nil {
				continue
			}
			if op, ok := api.Operation[id]; ok {
				out.Method, out.Path = op.Method, op.PathPattern
				break
			}
		}
		for _, res := range results {
			out.Totals.add(res)
			if res.Failed() {
				out.Failures = append(out.Failures,
					res.Case+": "+strings.Join(res.Errors, "; "))
			}
		}
		out.Conformant = out.Totals.Failed == 0
		r.Operations = append(r.Operations, out)
	}

	exercised := map[string]bool{}
	for id := range byOp {
		exercised[id] = true
	}
	for _, kind := range []spec.Kind{spec.KindConsumer, spec.KindPublisher, spec.KindInsights} {
		api := apis[kind]
		if api == nil {
			continue
		}
		cov := Coverage{
			Specification: specTitle(kind),
			Version:       api.Version,
			Declared:      len(api.Operation),
		}
		for _, id := range api.OperationIDs() {
			if exercised[id] {
				cov.Exercised++
			} else {
				cov.Unexercised = append(cov.Unexercised, id)
			}
		}
		r.Coverage = append(r.Coverage, cov)
	}
}

func specTitle(kind spec.Kind) string {
	switch kind {
	case spec.KindConsumer:
		return "TEA consumption API"
	case spec.KindPublisher:
		return "TEA publication API"
	case spec.KindInsights:
		return "TEA Insights API"
	default:
		return string(kind)
	}
}

// Conformant reports whether the run found nothing wrong.
//
// Three things count: every non-advisory case passed, every operation of the
// specifications the run covered was exercised, and nothing regressed under
// load. All three matter. A run that skipped operations is not a conformance
// result however green the cases it did run, and a server that answers
// correctly once but not under concurrency has not demonstrated conformance
// either.
func (r Report) Conformant() bool {
	if r.Totals.Failed != 0 {
		return false
	}
	for _, cov := range r.Coverage {
		// The publication specification is optional, so a provider that does
		// not implement it is not failed for leaving its operations
		// unexercised.
		if cov.Specification == "TEA publication API" && !r.Publisher.Implemented {
			continue
		}
		if cov.Specification == "TEA Insights API" && !r.Insights.Implemented {
			continue
		}
		if len(cov.Unexercised) > 0 {
			return false
		}
	}
	for _, m := range r.Perf.Measurements {
		if m.Failures > 0 {
			return false
		}
	}
	return true
}

// Verdict is the one-word summary.
func (r Report) Verdict() string {
	if r.Conformant() {
		return "CONFORMANT"
	}
	return "NOT CONFORMANT"
}

// Write persists the report: the JSON record always, and the Markdown either as
// one document or split per area.
func (r Report) Write(dir string, splitByArea bool) ([]string, error) {
	reportDir := filepath.Join(dir, "reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		return nil, err
	}
	var written []string

	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	jsonPath := filepath.Join(reportDir, "report.json")
	if err := os.WriteFile(jsonPath, append(encoded, '\n'), 0o644); err != nil {
		return nil, err
	}
	written = append(written, jsonPath)

	if splitByArea {
		index := filepath.Join(reportDir, "conformance.md")
		if err := os.WriteFile(index, []byte(r.summaryMarkdown(true)), 0o644); err != nil {
			return nil, err
		}
		written = append(written, index)
		for _, area := range r.Areas {
			path := filepath.Join(reportDir, string(area)+".md")
			if err := os.WriteFile(path, []byte(r.areaMarkdown(area)), 0o644); err != nil {
				return nil, err
			}
			written = append(written, path)
		}
	} else {
		path := filepath.Join(reportDir, "conformance.md")
		if err := os.WriteFile(path, []byte(r.Markdown()), 0o644); err != nil {
			return nil, err
		}
		written = append(written, path)
	}

	// The catalogue listing is always its own file. It answers a different
	// question from the conformance verdict: what is in here, not whether
	// it is correct. A reader usually wants one without the other.
	if len(r.Products) > 0 {
		path := filepath.Join(reportDir, "catalogue.md")
		if err := os.WriteFile(path, []byte(r.CatalogueMarkdown()), 0o644); err != nil {
			return nil, err
		}
		written = append(written, path)
	}

	// The residual record is always its own file, whether or not the Markdown
	// is split. It is the one section an administrator needs to find without
	// reading a conformance report, and it must be greppable.
	if r.Publisher.Implemented || len(r.Publisher.Residual) > 0 {
		path := filepath.Join(reportDir, "residual.md")
		if err := os.WriteFile(path, []byte(r.residualMarkdown()), 0o644); err != nil {
			return nil, err
		}
		written = append(written, path)

		residual, err := json.MarshalIndent(r.Publisher, "", "  ")
		if err != nil {
			return nil, err
		}
		jsonResidual := filepath.Join(reportDir, "residual.json")
		if err := os.WriteFile(jsonResidual, append(residual, '\n'), 0o644); err != nil {
			return nil, err
		}
		written = append(written, jsonResidual)
	}
	return written, nil
}

// resultsFor returns one area's results, in sequence order.
func (r Report) resultsFor(area config.Area) []runner.Result {
	var out []runner.Result
	for _, res := range r.Results {
		if res.Area == area {
			out = append(out, res)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}
