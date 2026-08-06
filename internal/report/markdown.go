package report

import (
	"fmt"
	"sort"
	"strings"

	pubarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/provider"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

// Markdown renders the whole report as one document.
func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString(r.summaryMarkdown(false))
	for _, area := range r.Areas {
		b.WriteString(r.areaSections(area))
	}
	b.WriteString(r.methodSection())
	return b.String()
}

// summaryMarkdown is the front matter: the verdict, what was tested, what it
// was tested against, and the coverage that claim rests on.
//
// When the report is split per area this is the index, and it links onward.
func (r Report) summaryMarkdown(withLinks bool) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# %s\n\n", r.Title)
	w("| | |\n|---|---|\n")
	w("| Verdict | **%s** |\n", r.Verdict())
	w("| Provider | %s |\n", r.Provider)
	if r.Domain != "" {
		w("| Discovery domain | `%s` |\n", r.Domain)
	}
	if r.RootURL != "" {
		w("| API root | `%s` |\n", r.RootURL)
	}
	if r.TEAVersion != "" {
		w("| TEA version served | %s |\n", r.TEAVersion)
	}
	w("| Credential | %s |\n", r.Credential)
	w("| Areas | %s |\n", config.JoinAreas(r.Areas, ", "))
	w("| Mode | %s |\n", r.Mode)
	w("| Request concurrency | %d |\n", r.Concurrency)
	w("| Generated | %s |\n", r.GeneratedAt)
	w("\n")

	if len(r.Errors) > 0 {
		w("> **This run did not complete.** %s\n\n", strings.Join(r.Errors, " "))
	}

	w("## Result\n\n")
	w("| Metric | Value |\n|---|---:|\n")
	w("| Cases | %d |\n", r.Totals.Cases)
	w("| Passed | %d |\n", r.Totals.Passed)
	w("| Failed | %d |\n", r.Totals.Failed)
	w("| Advisory (reported, not counted against conformance) | %d |\n", r.Totals.Advisory)
	w("| Responses schema-validated | %d |\n", r.Totals.SchemaChecked)
	w("| Responses conforming to schema | %d |\n", r.Totals.SchemaConforms)
	w("\n")

	w("### By area\n\n")
	w("| Area | Cases | Passed | Failed | Advisory |\n|---|---:|---:|---:|---:|\n")
	for _, area := range r.Areas {
		t := r.ByArea[area]
		name := string(area)
		if withLinks {
			name = fmt.Sprintf("[%s](%s.md)", area, area)
		}
		w("| %s | %d | %d | %d | %d |\n", name, t.Cases, t.Passed, t.Failed, t.Advisory)
	}
	w("\n")

	w("### Coverage\n\n")
	w("A conformance claim is only as good as its coverage, so an operation that was never\n")
	w("exercised is named, not quietly left out of the totals.\n\n")
	w("| Specification | Version | Declared | Exercised |\n|---|---|---:|---:|\n")
	for _, cov := range r.Coverage {
		w("| %s | %s | %d | %d |\n", cov.Specification, dash(cov.Version), cov.Declared, cov.Exercised)
	}
	w("\n")
	for _, cov := range r.Coverage {
		if len(cov.Unexercised) == 0 {
			continue
		}
		w("%s, not exercised: `%s`\n\n", cov.Specification, strings.Join(cov.Unexercised, "`, `"))
	}

	w("%s", r.specProvenance())

	if withLinks {
		w("## Areas\n\n")
		for _, area := range r.Areas {
			w("- [%s](%s.md): %s\n", area, area, config.Description[area])
		}
		w("\n")
		if r.Publisher.Implemented || len(r.Publisher.Residual) > 0 {
			w("- [residual records](residual.md): what the publication round-trip left behind\n\n")
		}
		w("%s", r.methodSection())
	}
	return b.String()
}

// specProvenance names exactly what every judgement in this report was made
// against, so a reader can fetch the same bytes and check them.
func (r Report) specProvenance() string {
	if len(r.Specs) == 0 {
		return ""
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("### Specifications this run validated against\n\n")
	w("Fetched from their authoritative repository at the start of this run and stored\n")
	w("alongside it in `spec/`. Nothing is vendored into the suite: a claim about a\n")
	w("specification should be checkable against the specification as published.\n\n")
	w("| Document | Source | Ref | Commit | SHA-256 |\n|---|---|---|---|---|\n")
	for _, doc := range r.Specs {
		source := doc.Repo + "/" + doc.Path
		if doc.Repo == "" {
			source = doc.URL
		}
		commit := doc.Commit
		if len(commit) > 12 {
			commit = commit[:12]
		}
		w("| %s | `%s` | %s | %s | `%s` |\n",
			doc.Kind, source, dash(doc.Ref), dash(commit), doc.SHA256[:min(16, len(doc.SHA256))])
	}
	w("\n")
	for _, doc := range r.Specs {
		if doc.Note != "" {
			w("- **%s**: %s\n", doc.Kind, doc.Note)
		}
	}
	w("\n")

	if len(r.SpecWarnings) > 0 {
		w("#### Defects in the specifications themselves\n\n")
		w("These are faults in the documents every provider here was judged by, not in any\n")
		w("provider. They are reported, not worked around silently.\n\n")
		for _, warning := range r.SpecWarnings {
			w("- %s\n", warning)
		}
		w("\n")
	}
	return b.String()
}

// areaMarkdown is one area as its own document.
func (r Report) areaMarkdown(area config.Area) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", r.Provider, area)
	fmt.Fprintf(&b, "%s\n\n", config.Description[area])
	t := r.ByArea[area]
	fmt.Fprintf(&b, "| Cases | Passed | Failed | Advisory |\n|---:|---:|---:|---:|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d |\n\n", t.Cases, t.Passed, t.Failed, t.Advisory)
	b.WriteString(r.areaSections(area))
	fmt.Fprintf(&b, "\n[Back to the summary](conformance.md)\n")
	return b.String()
}

// areaSections is the body for one area: its own narrative section, then its
// cases.
func (r Report) areaSections(area config.Area) string {
	var b strings.Builder
	switch area {
	case config.AreaDiscovery:
		b.WriteString(r.discoverySection())
	case config.AreaConsumer:
		b.WriteString(r.consumerSection())
	case config.AreaPurl:
		b.WriteString(r.purlSection())
	case config.AreaCycloneDX:
		b.WriteString(r.cyclonedxSection())
	case config.AreaSPDX:
		b.WriteString(r.spdxSection())
	case config.AreaInsights:
		b.WriteString(r.insightsSection())
	case config.AreaCEL:
		b.WriteString(r.celSection())
	case config.AreaProvenance:
		b.WriteString(r.provenanceSection())
	case config.AreaPerformance:
		b.WriteString(r.performanceSection())
	case config.AreaProvider:
		b.WriteString(r.publisherSection())
	}
	b.WriteString(caseTable(string(area)+" cases", r.resultsFor(area)))
	return b.String()
}

func (r Report) discoverySection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	d := r.Discovery

	w("## Discovery\n\n")
	if d.Explicit {
		w("This run was configured with an explicit API root, so the discovery chain was not\n")
		w("walked. The findings below cover only what a configured root can establish.\n\n")
		w("- API root: `%s`\n\n", d.RootURL)
		return b.String()
	}
	w("A consumer starts with a TEI, which carries a domain and nothing else. These are the\n")
	w("steps between that domain and an API it can call.\n\n")
	w("| Step | Result |\n|---|---|\n")
	dns := strings.Join(d.DNS.Addresses, ", ")
	if d.DNS.CNAME != "" {
		dns = "CNAME " + d.DNS.CNAME + " -> " + dns
	}
	if d.DNS.Error != "" {
		dns = "**" + d.DNS.Error + "**"
	}
	w("| DNS for `%s` | %s |\n", d.Domain, dash(dns))
	w("| Discovery document | `%s` |\n", dash(d.WellKnownURL))
	if d.Document != nil {
		w("| Endpoints advertised | %d |\n", len(d.Document.Endpoints))
	}
	w("| Endpoint selected | `%s` |\n", dash(d.Endpoint.URL))
	w("| Version selected | %s |\n", dash(d.Version))
	w("| API root | `%s` |\n", dash(d.RootURL))
	w("\n")
	if d.Document != nil && len(d.Document.Endpoints) > 0 {
		w("| Endpoint | Versions | Priority |\n|---|---|---:|\n")
		for _, e := range d.Document.Endpoints {
			priority := "-"
			if e.Priority != nil {
				priority = fmt.Sprintf("%.2f", *e.Priority)
			}
			w("| `%s` | %s | %s |\n", e.URL, strings.Join(e.Versions, ", "), priority)
		}
		w("\n")
	}
	if !d.SpecVersionMatch && d.Version != "" {
		w("> This provider advertises TEA %s, which is a different generation from the\n", d.Version)
		w("> specification this run validated against. Findings below are still measured against\n")
		w("> the document named in the summary, and differences between the two versions will\n")
		w("> appear here as failures.\n\n")
	}
	return b.String()
}

func (r Report) consumerSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	f := r.Fixtures

	w("## Fixtures\n\n")
	w("The run walked the object graph outwards from `/products`; these are the live\n")
	w("identifiers it resolved. Seeding from the API instead of from constants is what makes\n")
	w("a green run mean the graph is navigable, and not simply that a fixture exists.\n\n")
	w("| Object | Identifier |\n|---|---|\n")
	w("| TEA Product | `%s` (%s) |\n", f.ProductUUID, dash(f.ProductName))
	w("| TEA Product Release | `%s` (version `%s`) |\n", f.ProductReleaseUUID, dash(f.ReleaseVersion))
	w("| TEA Component | `%s` |\n", dash(f.ComponentUUID))
	w("| TEA Component Release | `%s` |\n", dash(f.ComponentReleaseUUID))
	if f.ArtifactSeen {
		w("| TEA Artifact | `%s` |\n", f.ArtifactUUID)
	} else {
		w("| TEA Artifact | none reachable, so the artifact operations were not exercised |\n")
	}
	w("| TEI authority | `%s` |\n", dash(f.Authority))
	w("\n")

	w("%s", r.consumerArtifactRetrievalSection())
	w("%s", r.efficacySection())
	return b.String()
}

const consumerArtifactRetrievalURL = "https://github.com/oej/tea-trust-architecture/blob/" +
	"main/tea-trust-arch/consumer/artifact-retrieval.md"

// consumerArtifactRetrievalSection assesses the draft artifact-retrieval
// profiles against evidence already collected by the consumer, CycloneDX and
// provenance areas. The configured consumption OpenAPI remains the source of
// the report's overall verdict; this separate table makes it explicit where a
// provider has, and has not, demonstrated the draft trust-architecture profile.
func (r Report) consumerArtifactRetrievalSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	content := r.matchingRequestEvidence(func(res runner.Result) bool {
		return res.OperationID == "artifactDownload"
	})
	metadata := r.matchingRequestEvidence(func(res runner.Result) bool {
		return res.Area == config.AreaConsumer &&
			(res.OperationID == "getLatestArtifact" || res.OperationID == "getArtifactByVersion")
	})
	signatures := r.matchingRequestEvidence(func(res runner.Result) bool {
		return res.OperationID == "artifactSignature"
	})
	artifactErrors := consumerArtifactErrorEvidence(r.Results)

	w("## Artifact retrieval and trust validation\n\n")
	w("The [TEA Consumer API artifact-retrieval document](%s), version 1.0, describes a draft,\n",
		consumerArtifactRetrievalURL)
	w("normative profile layered over the consumption API. It distinguishes Base TEA from TEA\n")
	w("with the Trust Architecture and from a high-assurance profile. The configured consumption\n")
	w("OpenAPI remains the source of the overall verdict; this table reports the additional\n")
	w("profile requirements separately. Because independent evidence-bundle retrieval is not\n")
	w("exercised, this run does **not demonstrate conformance to the Trust Architecture profile**,\n")
	w("even where Base TEA artifact retrieval succeeds.\n\n")
	w("| Requirement or profile | Evidence from this run | Assessment |\n")
	w("|---|---|---|\n")

	baseEvidence := fmt.Sprintf("Artifact metadata: %s Artifact content: %s",
		metadata.summary(), content.summary())
	if r.Efficacy.Artifacts > 0 {
		baseEvidence += fmt.Sprintf(" The sampled catalogue exposed a download URL for %d of %d artifacts.",
			r.Efficacy.WithDownloadURL, r.Efficacy.Artifacts)
	} else {
		baseEvidence += " Catalogue-wide artifact URL coverage was not collected."
	}
	baseEvidence += " Content URLs were learned through collections; retrieval by artifact identity " +
		"without first reading a collection was not probed."
	baseAssessment := "not demonstrated"
	if content.successful > 0 {
		baseAssessment = "partially demonstrated"
	}
	w("| Base TEA: artifact retrieval (MUST) | %s | %s |\n", baseEvidence, baseAssessment)

	signatureEvidence := fmt.Sprintf("The sampled catalogue exposed %d detached-signature URLs; %s ",
		r.Efficacy.WithSignature, signatures.summary())
	signatureEvidence += "Fetched signatures are not cryptographically verified and do not establish " +
		"timestamp, transparency or long-term validity."
	signatureAssessment := "not observed (optional)"
	if signatures.successful > 0 {
		signatureAssessment = "optional compatibility feature observed"
	}
	w("| Detached-signature retrieval (MAY) | %s | %s |\n",
		signatureEvidence, signatureAssessment)

	w("| Trust Architecture: independent evidence-bundle retrieval (MUST) | No conformance " +
		"case in this run retrieved an evidence bundle independently of a collection or tied a " +
		"bundle to the returned artifact. Attestation artifacts and detached signatures are not " +
		"treated as substitutes for an evidence bundle. | not demonstrated |\n")

	w("| Artifact plus evidence-bundle multipart retrieval (SHOULD) | This run did not negotiate " +
		"`multipart/mixed; profile=\"artifact+evidence\"`, identify its two parts, or test artifact " +
		"and bundle mismatch handling. | not assessed |\n")

	validationEvidence := fmt.Sprintf("%d artifact-content responses were retrieved and %d passed "+
		"their applicable document and digest checks.", content.successful, content.conforming)
	if r.Efficacy.Artifacts > 0 {
		validationEvidence += fmt.Sprintf(" %d of %d sampled artifact records carried a checksum.",
			r.Efficacy.WithChecksum, r.Efficacy.Artifacts)
	}
	validationEvidence += " Certificate chains, timestamp evidence, transparency inclusion and local " +
		"trust policy were not validated."
	validationAssessment := "not demonstrated"
	if content.conforming > 0 {
		validationAssessment = "content integrity partially demonstrated"
	}
	w("| Validation behavior and transport-versus-trust semantics | %s | %s |\n",
		validationEvidence, validationAssessment)

	w("| Collection inclusion versus independent authenticity | Collection UUID and `belongsTo` " +
		"rules are checked by the consumption cases. Artifact/evidence reuse across collections, " +
		"and authenticity validation without a collection, are not exercised. | partially assessed |\n")

	errorEvidence := fmt.Sprintf("%d artifact metadata error-path cases were exercised; %d conformed. ",
		artifactErrors.attempted, artifactErrors.conforming)
	errorEvidence += "The trust-profile errors for missing evidence, unsupported multipart profiles " +
		"and artifact/evidence or artifact/signature mismatch were not exercised."
	errorAssessment := "not assessed"
	if artifactErrors.attempted > 0 {
		errorAssessment = "base errors partially demonstrated"
	}
	w("| Error handling | %s | %s |\n", errorEvidence, errorAssessment)

	w("| High-assurance profile | Bundle caching and reuse, offline validation, and operation " +
		"without live timestamp or transparency services are outside this black-box run. | not assessed |\n\n")

	return b.String()
}

type requestEvidence struct {
	attempted  int
	successful int
	conforming int
}

func (r Report) matchingRequestEvidence(match func(runner.Result) bool) requestEvidence {
	var out requestEvidence
	for _, res := range r.Results {
		if !match(res) {
			continue
		}
		out.attempted++
		if res.GotStatus >= 200 && res.GotStatus < 300 {
			out.successful++
		}
		if res.Pass {
			out.conforming++
		}
	}
	return out
}

func (e requestEvidence) summary() string {
	if e.attempted == 0 {
		return "no matching request was exercised."
	}
	return fmt.Sprintf("%d requests were exercised, %d returned content successfully, and %d "+
		"passed their applicable checks.", e.attempted, e.successful, e.conforming)
}

func consumerArtifactErrorEvidence(results []runner.Result) requestEvidence {
	var out requestEvidence
	for _, res := range results {
		if res.Area != config.AreaConsumer || res.Category != "negative" ||
			(res.OperationID != "getLatestArtifact" && res.OperationID != "getArtifactByVersion") {
			continue
		}
		out.attempted++
		if res.GotStatus >= 400 && res.GotStatus < 500 {
			out.successful++
		}
		if res.Pass {
			out.conforming++
		}
	}
	return out
}

// efficacySection is what the published graph actually contains.
func (r Report) efficacySection() string {
	e := r.Efficacy
	if e.ProductsSampled == 0 {
		return ""
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("## Efficacy\n\n")
	w("Conformance proves the responses are well formed. It cannot prove they are complete:\n")
	w("a server that published one artifact per release and dropped the rest would validate\n")
	w("just as cleanly. This is what the published graph actually contains.\n\n")
	w("| Measure | Value |\n|---|---:|\n")
	w("| Products published | %d |\n", e.ProductsSampled)
	w("| Releases sampled | %d |\n", e.ReleasesSampled)
	w("| Collections read | %d |\n", e.Collections)
	w("| Collections with no artifacts | %d |\n", e.EmptyCollections)
	w("| Artifacts published | %d |\n", e.Artifacts)
	if e.Collections > 0 {
		w("| Artifacts per collection (mean) | %.1f |\n", float64(e.Artifacts)/float64(e.Collections))
	}
	w("| Artifacts carrying a checksum | %d |\n", e.WithChecksum)
	w("| Artifacts carrying a media type | %d |\n", e.WithMediaType)
	w("| Artifacts carrying a download URL | %d |\n", e.WithDownloadURL)
	w("| Artifacts carrying a signature | %d |\n", e.WithSignature)
	w("| Artifacts with more than one revision | %d |\n", e.MultiRevision)
	w("| Deepest artifact revision | %d |\n", e.MaxRevision)
	w("| Deepest collection version | %d |\n", e.MaxCollectionVersion)
	w("| Releases flagged pre-release | %d |\n", e.PreReleases)
	w("| Releases flagged final | %d |\n", e.FinalReleases)
	w("\n")

	if len(e.ArtifactTypes) > 0 {
		w("### Published artifact types\n\n| `artifact-type` | Count |\n|---|---:|\n")
		for _, k := range sortedKeys(e.ArtifactTypes) {
			w("| %s | %d |\n", k, e.ArtifactTypes[k])
		}
		w("\n")
	}
	if len(e.ArtifactNames) > 0 {
		w("### Published documents\n\n| Document | Count |\n|---|---:|\n")
		for _, k := range sortedKeys(e.ArtifactNames) {
			w("| %s | %d |\n", k, e.ArtifactNames[k])
		}
		w("\n")
	}
	if len(e.RevisionDepth) > 0 {
		w("### Artifact revision depth\n\n")
		w("How many immutable revisions each published artifact has. Depth beyond 1 is TEA's\n")
		w("`(uuid, version)` identity doing real work.\n\n")
		w("| Revisions | Artifacts |\n|---:|---:|\n")
		depths := make([]int, 0, len(e.RevisionDepth))
		for d := range e.RevisionDepth {
			depths = append(depths, d)
		}
		sort.Ints(depths)
		for _, d := range depths {
			w("| %d | %d |\n", d, e.RevisionDepth[d])
		}
		w("\n")
	}
	return b.String()
}

func (r Report) purlSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p := r.Purl

	w("## Package URLs\n\n")
	w("| Measure | Value |\n|---|---:|\n")
	w("| Published purl identifiers | %d |\n", p.PublishedPurls)
	w("| Malformed | %d |\n", len(p.Malformed))
	w("| Open-source sample requested | %d |\n", p.Sample.Requested)
	w("| Sample packages this provider publishes | %d |\n", p.Sample.Resolved)
	w("| Sample packages it does not | %d |\n", p.Sample.Missing)
	w("\n")
	if len(p.Types) > 0 {
		w("| purl type | Count |\n|---|---:|\n")
		for _, k := range sortedKeys(p.Types) {
			w("| `pkg:%s` | %d |\n", k, p.Types[k])
		}
		w("\n")
	}
	if len(p.Malformed) > 0 {
		w("### Malformed identifiers\n\n")
		for _, m := range p.Malformed {
			w("- %s\n", m)
		}
		w("\n")
	}
	if p.Sample.Requested > 0 {
		w("The sample is evidence, not a verdict: no provider is required to publish anybody\n")
		w("else's software. What it establishes is how much of a known open-source set a\n")
		w("catalogue covers, which is the number that makes two providers comparable.\n\n")
	}
	return b.String()
}

func (r Report) cyclonedxSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	c := r.CycloneDX

	w("## CycloneDX documents\n\n")
	w("The BOM documents behind the artifact records, downloaded and validated against the\n")
	w("version each one declares.\n\n")
	w("| Measure | Value |\n|---|---:|\n")
	w("| BOM artifacts found | %d |\n", c.Candidates)
	w("| Downloaded and validated | %d |\n", c.Downloaded)
	if c.Skipped > 0 {
		w("| Not downloaded (per-run limit) | %d |\n", c.Skipped)
	}
	w("\n")
	if len(c.SpecVersion) > 0 {
		w("| CycloneDX version | Documents |\n|---|---:|\n")
		for _, v := range sortedKeys(c.SpecVersion) {
			w("| %s | %d |\n", v, c.SpecVersion[v])
		}
		w("\n")
	}
	if len(c.Documents) > 0 {
		w("| Document | Product | Version | Components | Valid |\n|---|---|---|---:|---|\n")
		for _, d := range c.Documents {
			w("| %s | %s | %s | %d | %s |\n",
				dash(d.ArtifactName), dash(d.ProductName), dash(d.SpecVersion),
				d.Components, tick(d.Valid))
		}
		w("\n")
	}
	return b.String()
}

func (r Report) spdxSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	s := r.SPDX

	w("## Licence identifiers\n\n")
	w("A licence is the field read most often by people who are not engineers, and it is read\n")
	w("exactly: a compliance tool matches `Apache-2.0` and does not match `apache-2.0`. An\n")
	w("identifier that is nearly right classifies as unknown without anybody noticing.\n\n")
	w("| Measure | Value |\n|---|---:|\n")
	if s.ListVersion != "" {
		w("| SPDX licence list | %s |\n", s.ListVersion)
	}
	w("| Identifiers checked | %d |\n", s.Checked)
	w("| Valid | %d |\n", s.Valid)
	w("| Deprecated by SPDX | %d |\n", s.Deprecated)
	w("| Wrong case | %d |\n", s.WrongCase)
	w("| Not SPDX identifiers | %d |\n", s.Unknown)
	w("| Free-text licence names (unmatchable, but permitted) | %d |\n", s.FreeText)
	w("| Lifecycle documents read | %d |\n", s.CLERead)
	w("\n")
	if len(s.Problems) > 0 {
		w("| Identifier | Verdict | Where | Detail |\n|---|---|---|---|\n")
		for _, p := range s.Problems {
			w("| `%s` | %s | %s | %s |\n", p.Identifier, p.Verdict, dash(p.Where), p.Reason)
		}
		w("\n")
	}
	return b.String()
}

func (r Report) insightsSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	i := r.Insights

	w("## Insights API\n\n")
	if !i.Implemented {
		w("The Insights API was not exercised against this provider. That is not a conformance\n")
		w("failure: Insights is a separate specification and a TEA server is not required to\n")
		w("implement it. Where it answered 401, it is served but was not reachable with\n")
		w("this run's credential.\n\n")
		if i.Detail != "" {
			w("- %s\n\n", i.Detail)
		}
		return b.String()
	}
	w("A separate specification mounted at `%s`. Its responses are CycloneDX documents, so\n", i.BaseURL)
	w("they are validated against the CycloneDX schema and not against anything in the\n")
	w("Insights document. That is where its `$ref` points, and it is where conformance\n")
	w("actually lives.\n\n")
	w("| Measure | Value |\n|---|---|\n")
	if i.SpecVersion != "" {
		w("| Insights specification | %s |\n", i.SpecVersion)
	}
	w("| Component found for the efficacy queries | %s |\n", dash(i.Fixtures.ComponentName))
	w("| Vulnerability found for the efficacy queries | %s |\n", dash(i.Fixtures.VulnerabilityID))
	if i.DynamicStatus != "" {
		w("| Dynamic endpoint | %s |\n", i.DynamicStatus)
	}
	w("\n")
	return b.String()
}

func (r Report) celSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	c := r.CEL

	w("## Query language\n\n")
	w("Every expression below was compiled twice: once by `google/cel-go`, which is the\n")
	w("reference implementation, and once by this server. The finding is the disagreement,\n")
	w("not either result on its own. A server with its own parser can accept an expression\n")
	w("CEL rejects, and a client generated from the specification would then write queries\n")
	w("that quietly do not mean what its author thought.\n\n")
	w("| Measure | Value |\n|---|---:|\n")
	w("| Expressions checked | %d |\n", c.Checked)
	w("| Server agrees with the reference implementation | %d |\n", c.Agreements)
	w("| Disagreements | %d |\n", len(c.Disagreements))
	w("\n")
	if len(c.Disagreements) > 0 {
		w("| Expression | Reference implementation | This server |\n|---|---|---|\n")
		for _, d := range c.Disagreements {
			w("| `%s` | %s | %s |\n", d.Expression, d.Reference, d.Server)
		}
		w("\n")
	}
	return b.String()
}

func (r Report) provenanceSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p := r.Prov

	w("## Provenance\n\n")
	w("TEA's object model is careful about identity, but identity is only worth something if\n")
	w("a consumer can verify it: a checksum matches bytes to a record, a signature matches\n")
	w("the record to a publisher, and an attestation describes the build that produced it. A\n")
	w("publisher can conform to the object specification while supplying none of the three.\n\n")
	w("| Measure | Value |\n|---|---:|\n")
	w("| Artifacts inspected | %d |\n", p.Artifacts)
	w("| Carrying a checksum | %d |\n", p.WithChecksum)
	w("| Carrying a signature | %d |\n", p.WithSignature)
	w("| Carrying a media type | %d |\n", p.WithMediaType)
	w("| With more than one immutable revision | %d |\n", p.Immutable)
	w("| Signatures fetched | %d |\n", p.SignaturesChecked)
	w("\n")
	if len(p.ChecksumAlgorithms) > 0 {
		w("| Checksum algorithm | Count |\n|---|---:|\n")
		for _, k := range sortedKeys(p.ChecksumAlgorithms) {
			w("| %s | %d |\n", k, p.ChecksumAlgorithms[k])
		}
		w("\n")
	}
	if len(p.Attestations) > 0 {
		w("### Attestations\n\n")
		w("| Product | Statement | Predicate | Subjects | Digests |\n|---|---|---|---:|---|\n")
		for _, a := range p.Attestations {
			w("| %s | %s | %s | %d | %s |\n",
				dash(a.ProductName), dash(a.StatementType), dash(a.PredicateType),
				a.Subjects, dash(strings.Join(a.Digests, ", ")))
		}
		w("\n")
	}
	w("Signatures are fetched, not verified: verification needs a trust root this suite has\n")
	w("no way to establish, and inventing one would be worse than saying so.\n\n")
	return b.String()
}

func (r Report) performanceSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p := r.Perf

	w("## Performance\n\n")
	if p.NotMeasured != "" {
		w("Not measured: %s.\n\n", p.NotMeasured)
		return b.String()
	}
	w("Two conditions, reported separately because they are separate facts. **Cold** is first\n")
	w("contact: a fresh connection, nothing warmed, sampled %d times per shape. **Cached** is\n", p.ColdSamples)
	w("steady state: the same shape replayed %d times at %d in flight over a warm pool. A\n", p.Iterations, p.Concurrency)
	w("single averaged number would describe neither.\n\n")
	w("Every response was validated after its timer stopped, so validation never inflates a\n")
	w("measurement, and an endpoint that starts returning the wrong thing only once it is\n")
	w("contended fails here instead of passing everywhere.\n\n")

	w("| Request | Cold p50 | Cached p50 | Speed-up | Cached p95 | Cached p99 | Spread | req/s | Failures |\n")
	w("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, m := range p.Measurements {
		w("| %s | %s | %s | %s | %s | %s | %s | %s | %d |\n",
			m.Name, ms(m.Cold.P50Ms), ms(m.Cached.P50Ms), speedUp(m.SpeedUp),
			ms(m.Cached.P95Ms), ms(m.Cached.P99Ms), variance(m.Variance),
			rate(m.RequestsPerSecond), m.Failures)
	}
	w("\n")
	w("*Spread* is the cached standard deviation over the cached median. A low median with a\n")
	w("high spread is a worse experience than a slightly higher median that is consistent, and\n")
	w("only that column says so.\n\n")

	if r.Latency.Count > 0 {
		w("### Conformance-phase latency\n\n")
		w("The distribution across all %d conformance requests, including the error paths,\n", r.Latency.Count)
		w("measured client-side to the last byte of the response body.\n\n")
		w("| Requests | min | p50 | p95 | p99 | max | mean |\n|---:|---:|---:|---:|---:|---:|---:|\n")
		w("| %d | %s | %s | %s | %s | %s | %s |\n\n",
			r.Latency.Count, ms(r.Latency.MinMs), ms(r.Latency.P50Ms), ms(r.Latency.P95Ms),
			ms(r.Latency.P99Ms), ms(r.Latency.MaxMs), ms(r.Latency.AvgMs))
	}
	return b.String()
}

func (r Report) publisherSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p := r.Publisher

	w("## Publication\n\n")
	if p.SpecVersion != "" {
		w("Judged against the publication specification version **%s**, which describes the\n", p.SpecVersion)
		w("`%s` object model.\n\n", p.Model)
	}
	if p.Model == pubarea.ModelLeaf {
		w("> That is an older TEA generation than the consumption specification this run used.\n")
		w("> The two documents upstream are not the same version and do not share an object\n")
		w("> model, so a server implementing the current consumption API will not implement\n")
		w("> these operations, and the round-trip below reports that instead of failing it.\n\n")
	}
	if p.ModelMismatch {
		w("**This provider serves the publication endpoints but does not speak this document.**\n")
		w("It refused the request body this model defines while refusing anonymous writes a\n")
		w("moment earlier, which means the API is there and implements a different generation\n")
		w("of it. Nothing below is a defect in the provider.\n\n")
		if p.Detail != "" {
			w("%s\n\n", p.Detail)
		}
		w("%s", r.publisherWorkflowSection())
		return b.String()
	}
	if !p.Implemented {
		w("This provider does not serve the publication specification. That is not a\n")
		w("conformance failure. Publication is a separate document, and a read-only mirror is\n")
		w("a legitimate TEA server.\n\n")
		if p.Detail != "" {
			w("- %s\n\n", p.Detail)
		}
		w("%s", r.publisherWorkflowSection())
		return b.String()
	}
	w("The round-trip creates objects, revises them, reads them back through the consumption\n")
	w("API, and deletes them. The deletes are conformance cases in their own right and are\n")
	w("also the cleanup: there is no separate teardown, because verifying that delete works\n")
	w("*is* the teardown.\n\n")
	w("| | |\n|---|---|\n")
	w("| Record naming | `%s` / `%s` |\n", p.NamePrefix, p.RunKey)
	w("| Product identifier | `%s` |\n", p.PURL)
	w("| Objects created | %d |\n", len(p.Created))
	w("| Left behind by a previous run and reclaimed | %d |\n", p.Reclaimed)
	w("| Residual records | %d |\n", len(p.Residual))
	w("\n")
	if len(p.Unsupported) > 0 {
		w("Operations this provider does not implement: `%s`\n\n", strings.Join(p.Unsupported, "`, `"))
	}
	w("%s", r.publisherWorkflowSection())
	w("%s", r.residualTable())
	return b.String()
}

const publisherWorkflowURL = "https://raw.githubusercontent.com/oej/tea-trust-architecture/" +
	"refs/heads/main/tea-trust-arch/publisher/publisher-workflow.md"

// publisherWorkflowSection maps the informational publisher workflow onto
// evidence this black-box run actually collected. It deliberately does not
// produce a second verdict: the workflow says the publisher OpenAPI document
// is normative, and treating design guidance as a conformance requirement
// would fail providers against rules the specification does not declare.
func (r Report) publisherWorkflowSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p := r.Publisher

	w("### Publisher workflow design\n\n")
	w("The [TEA Trust Architecture publisher workflow](%s) is draft, informational design\n", publisherWorkflowURL)
	w("guidance. The publication OpenAPI document remains the normative conformance source.\n")
	w("This table maps the design to evidence collected by this run; its assessments do not\n")
	w("change the conformance verdict.\n\n")
	w("| Design concern | Evidence from this run | Assessment |\n")
	w("|---|---|---|\n")

	release := r.publisherOperationEvidence(
		"createTeaComponentRelease", "createTeaProductRelease",
		"publishTeaComponentReleaseCollection", "publishTeaProductReleaseCollection",
	)
	releaseEvidence := release.summary(4)
	if p.Implemented && p.Model == pubarea.ModelRelease {
		releaseEvidence += " Successful collection responses are checked against the stable " +
			"release UUID and `belongsTo` value; publishing a later version against that same " +
			"release is not exercised."
	}
	w("| Stable release identity | %s | %s |\n", releaseEvidence,
		workflowAssessment(p, release, 4, "partially demonstrated"))

	artifact := r.publisherOperationEvidence("createTeaArtifact", "uploadTeaArtifactContent")
	artifactEvidence := artifact.summary(2)
	if r.Efficacy.Artifacts > 0 {
		artifactEvidence += fmt.Sprintf(" The sampled catalogue contained %d artifacts: %d carried a "+
			"checksum and %d exposed a signature URL.", r.Efficacy.Artifacts,
			r.Efficacy.WithChecksum, r.Efficacy.WithSignature)
	} else {
		artifactEvidence += " Catalogue-wide checksum and signature coverage was not collected."
	}
	artifactEvidence += " Signature integrity, certificate validity, timestamps, transparency " +
		"inclusion and collection signatures are not cryptographically verified."
	w("| Artifact preparation, signing and validation | %s | %s |\n", artifactEvidence,
		workflowAssessment(p, artifact, 2, "partially demonstrated"))

	collection := r.publisherOperationEvidence(
		"publishTeaComponentReleaseCollection", "publishTeaProductReleaseCollection")
	collectionEvidence := collection.summary(2)
	if r.Efficacy.Collections > 0 {
		collectionEvidence += fmt.Sprintf(" The sampled graph contained %d collections, %d empty, "+
			"and %d referenced artifacts.", r.Efficacy.Collections,
			r.Efficacy.EmptyCollections, r.Efficacy.Artifacts)
	} else {
		collectionEvidence += " No catalogue-wide collection inventory was collected."
	}
	collectionEvidence += " The round-trip does not prove that a collection was assembled from " +
		"validated artifact digests or that the collection itself was signed."
	w("| Collection assembly and signing | %s | %s |\n", collectionEvidence,
		workflowAssessment(p, collection, 2, "partially demonstrated"))

	w("| Preparation, separation of duties and approval | CI/CD preparation, publisher-side " +
		"validation, human approval and separation of roles are internal controls that a " +
		"black-box HTTP client cannot observe. | not assessed |\n")

	commit := r.publisherOperationEvidence("getTeaProductByUuid", "getLatestArtifact")
	commitEvidence := commit.summary(2) + " These read-backs test that accepted writes become " +
		"visible through the consumption API. Atomic staging, a distinct commit boundary and DNS " +
		"trust-anchor updates are not exercised."
	commitAssessment := workflowAssessment(p, commit, 2, "partially demonstrated")
	if p.Implemented && p.Model == pubarea.ModelRelease && commit.successful == 2 && commit.failed == 0 {
		commitAssessment = "consumer visibility demonstrated"
	}
	w("| Commit and publication | %s | %s |\n", commitEvidence, commitAssessment)

	versions := r.publisherOperationEvidence("updateTeaArtifact", "getLatestArtifact")
	versionEvidence := versions.summary(2)
	if r.Efficacy.Artifacts > 0 {
		versionEvidence += fmt.Sprintf(" In the sampled catalogue, %d artifacts had more than one "+
			"revision (deepest revision %d), and the deepest collection version was %d.",
			r.Efficacy.MultiRevision, r.Efficacy.MaxRevision, r.Efficacy.MaxCollectionVersion)
	} else {
		versionEvidence += " Artifact and collection version depth was not inventoried."
	}
	versionEvidence += " The round-trip reads only `latest`; it does not re-fetch an older artifact, " +
		"collection or CLE version to prove immutability and continued availability."
	w("| Independent version streams, immutability and history | %s | %s |\n", versionEvidence,
		workflowAssessment(p, versions, 2, "partially observed"))

	cleEvidence := "The publication round-trip has no CLE or compliance-document publication case."
	if hasArea(r.Areas, config.AreaSPDX) {
		cleEvidence += fmt.Sprintf(" The read-side SPDX area inspected %d lifecycle documents, but "+
			"did not create a new CLE version.", r.SPDX.CLERead)
	} else {
		cleEvidence += " The read-side SPDX/CLE area was not selected."
	}
	w("| CLE and compliance-document lifecycle | %s | not assessed |\n\n", cleEvidence)

	return b.String()
}

type publisherOperationEvidence struct {
	exercised  int
	successful int
	failed     int
}

func (r Report) publisherOperationEvidence(operationIDs ...string) publisherOperationEvidence {
	wanted := make(map[string]bool, len(operationIDs))
	for _, id := range operationIDs {
		wanted[id] = true
	}
	seen := map[string]bool{}
	successful := map[string]bool{}
	failed := map[string]bool{}
	for _, res := range r.Results {
		if res.Area != config.AreaProvider || !wanted[res.OperationID] {
			continue
		}
		seen[res.OperationID] = true
		if res.Failed() {
			failed[res.OperationID] = true
		}
		if res.Pass && res.GotStatus >= 200 && res.GotStatus < 300 {
			successful[res.OperationID] = true
		}
	}
	return publisherOperationEvidence{
		exercised:  len(seen),
		successful: len(successful),
		failed:     len(failed),
	}
}

func (e publisherOperationEvidence) summary(expected int) string {
	if e.exercised == 0 {
		return "No matching publication operation was exercised."
	}
	text := fmt.Sprintf("%d of %d relevant operations completed successfully", e.successful, expected)
	if e.failed > 0 {
		text += fmt.Sprintf("; %d had a conformance failure", e.failed)
	}
	return text + "."
}

func workflowAssessment(
	p pubarea.Findings,
	e publisherOperationEvidence,
	expected int,
	success string,
) string {
	if !p.Implemented || p.Model != pubarea.ModelRelease {
		return "not assessed"
	}
	if e.failed > 0 {
		return "not demonstrated"
	}
	if e.successful == expected {
		return success
	}
	if e.exercised > 0 {
		return "partially exercised"
	}
	return "not exercised"
}

func hasArea(areas []config.Area, want config.Area) bool {
	for _, area := range areas {
		if area == want {
			return true
		}
	}
	return false
}

// CatalogueMarkdown lists what this provider publishes.
//
// It is built the way a consumer would build it, by paging `/products` and
// asking each one for its newest release. What it records is therefore exactly
// what the API serves, not what any database holds.
func (r Report) CatalogueMarkdown() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("# Catalogue for %s\n\n", r.Provider)
	w("The products this provider publishes, as its own API serves them.\n\n")
	w("| | |\n|---|---:|\n")
	w("| Products published | %d |\n", len(r.Products))
	w("| Releases sampled | %d |\n", r.Efficacy.ReleasesSampled)
	w("| Artifacts published across the sample | %d |\n", r.Efficacy.Artifacts)
	w("| API root | `%s` |\n", r.RootURL)
	w("| Generated | %s |\n", r.GeneratedAt)
	w("\n")
	w("Built by paging `/products` and asking each product for its newest release. Nothing\n")
	w("here is read from anywhere but the API, so the list is exactly what a consumer sees.\n\n")

	w("| Product | Latest version | Released | Identifier | UUID |\n")
	w("|---|---|---|---|---|\n")
	for _, p := range r.Products {
		version := dash(p.LatestVersion)
		if p.PreRelease && p.LatestVersion != "" {
			version += " *(pre-release)*"
		}
		date := p.LatestDate
		if len(date) >= 10 {
			date = date[:10]
		}
		identifier := p.PURL
		if identifier == "" {
			identifier = p.TEI
		}
		w("| %s | %s | %s | `%s` | `%s` |\n",
			dash(p.Name), version, dash(date), dash(identifier), p.UUID)
	}
	w("\n")
	return b.String()
}

// residualMarkdown is the standalone document an administrator reads.
func (r Report) residualMarkdown() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	p := r.Publisher

	w("# Residual conformance records for %s\n\n", r.Provider)
	w("Generated %s.\n\n", r.GeneratedAt)
	w("The conformance suite writes objects to exercise the publication specification and\n")
	w("deletes them again as its final cases. Anything listed here survived that, so it is\n")
	w("still in your catalogue.\n\n")
	w("Every record is named deterministically from the run configuration, prefix `%s`,\n", p.NamePrefix)
	w("key `%s`, so a re-run of the suite reclaims and removes them without any manual\n", p.RunKey)
	w("step. This list is for when you would rather purge them yourself.\n\n")
	w("| | |\n|---|---|\n")
	w("| API root | `%s` |\n", r.RootURL)
	w("| Product identifier | `%s` |\n", p.PURL)
	w("| Objects created this run | %d |\n", len(p.Created))
	w("| Still present | %d |\n", len(p.Residual))
	w("\n")

	if len(p.Residual) == 0 {
		w("**Nothing was left behind.** Every object this run created was deleted and the\n")
		w("deletion verified through the consumption API.\n")
		return b.String()
	}
	w("%s", r.residualTable())
	w("## Removing them\n\n")
	w("```sh\n")
	for _, rec := range p.Residual {
		w("curl -X DELETE -H \"Authorization: $TEA_CREDENTIAL\" \\\n  %s%s\n", r.RootURL, rec.DeletePath)
	}
	w("```\n\n")
	w("Deleting a product removes everything beneath it, so the product line alone is enough\n")
	w("if the whole tree is present.\n")
	return b.String()
}

func (r Report) residualTable() string {
	p := r.Publisher
	if len(p.Created) == 0 {
		return ""
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("### Records created by this run\n\n")
	w("| Object | UUID | Label | Deleted | Delete request |\n|---|---|---|---|---|\n")
	for _, rec := range p.Created {
		state := tick(rec.Deleted)
		if !rec.Deleted && rec.Note != "" {
			state = "**no**, " + rec.Note
		}
		w("| %s | `%s` | %s | %s | `DELETE %s` |\n",
			rec.Kind, rec.UUID, dash(rec.Label), state, rec.DeletePath)
	}
	w("\n")
	return b.String()
}

// caseTable renders one area's results.
func caseTable(title string, results []runner.Result) string {
	if len(results) == 0 {
		return ""
	}
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("### %s\n\n", title)
	w("| Case | Operation | Status | Schema | Latency | Verdict |\n|---|---|---:|---|---:|---|\n")
	for _, res := range results {
		schema := "-"
		if res.SchemaChecked {
			schema = tick(res.SchemaValid)
		}
		verdict := "pass"
		switch {
		case res.Failed():
			verdict = "**FAIL**"
		case !res.Pass:
			verdict = "advisory"
		}
		status := "-"
		if res.GotStatus > 0 {
			status = fmt.Sprint(res.GotStatus)
		}
		w("| %s | `%s` | %s | %s | %s | %s |\n",
			res.Case, dash(res.OperationID), status, schema, ms(res.LatencyMs), verdict)
	}
	w("\n")

	var failures []runner.Result
	for _, res := range results {
		if len(res.Errors) > 0 || len(res.Warnings) > 0 {
			failures = append(failures, res)
		}
	}
	if len(failures) > 0 {
		w("#### Detail\n\n")
		for _, res := range failures {
			w("**%s**", res.Case)
			if res.URL != "" {
				w(": `%s %s`", res.Method, res.URL)
			}
			w("\n\n")
			for _, e := range res.Errors {
				w("- %s\n", e)
			}
			for _, warn := range res.Warnings {
				w("- *%s*\n", warn)
			}
			if res.Recording != "" {
				w("- evidence: `responses/%s/%s.meta.json`\n", res.Area, res.Recording)
			}
			w("\n")
		}
	}
	return b.String()
}

func (r Report) methodSection() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("## Method\n\n")
	w("The suite is a black-box HTTP client. It knows nothing about any implementation, and\n")
	w("every judgement here comes from comparing a response against the specifications named\n")
	w("above, fetched from their authoritative repository at the start of this run.\n\n")
	w("OpenAPI 3.1 schema objects **are** JSON Schema 2020-12, so the specification's own\n")
	w("bytes are what was enforced. There is no intermediate model that could drift from it.\n\n")
	w("Some of what the specification requires cannot be written as a schema. Collection and\n")
	w("release UUID identity, lifecycle event ordering, pagination-token consistency and\n")
	w("`additionalProperties:false` on error bodies were each checked separately against the\n")
	w("normative prose, and are reported as case failures in the same way as schema\n")
	w("violations.\n\n")
	w("Every request and response is stored under `responses/`, named deterministically, so\n")
	w("this report can be regenerated offline from that directory and checked against the\n")
	w("bytes it was derived from.\n")
	return b.String()
}

// --- small renderers ---

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func tick(ok bool) string {
	if ok {
		return "yes"
	}
	return "**no**"
}

func ms(v float64) string {
	if v == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f ms", v)
}

func rate(v float64) string {
	if v == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f", v)
}

func speedUp(v float64) string {
	if v == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fx", v)
}

func variance(v float64) string {
	if v == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", v*100)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
