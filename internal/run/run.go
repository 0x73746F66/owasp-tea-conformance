// Package run wires everything together for one provider: fetch the
// specifications, follow discovery to an API root, seed fixtures, execute the
// areas the configuration asked for, and write the evidence and the report.
//
// The order here is a dependency order rather than a preference. Discovery
// produces the root every other area needs; seeding produces the identifiers the
// case catalogue is built from; the inventory walk produces the artifacts the
// document areas validate. Each stage can fail without the ones before it
// becoming untrue, so a partial run still reports what it did establish.
package run

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

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
	"github.com/0x73746F66/owasp-tea-conformance/internal/httpx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/report"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

// Options are the per-invocation choices the command line makes.
type Options struct {
	Mode httpx.Mode
	// ReplayDir is the recorded run to reproduce from. Only used in replay
	// mode.
	ReplayDir string
	// ReportsTo redirects where the reports are written, leaving the recordings
	// where they are. It is what lets a replayed run render a fresh set of
	// documents somewhere else without disturbing the run it read from.
	ReportsTo string
	// SplitByArea overrides the configuration's Markdown layout when set.
	SplitByArea *bool
	// Concurrency bounds in-flight requests. Zero picks a value from the
	// machine's parallelism.
	Concurrency int
	// Now is injectable so a report can be produced deterministically in tests.
	Now func() time.Time
	// Log receives progress lines.
	Log func(format string, args ...any)
}

// Provider executes one provider's run and returns its report.
func Provider(ctx context.Context, cfg *config.Config, p config.Resolved, opt Options) (report.Report, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Log == nil {
		opt.Log = func(string, ...any) {}
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = max(4, runtime.GOMAXPROCS(0)*2)
	}

	rep := report.Report{
		Title:       "OWASP Transparency Exchange API conformance report",
		GeneratedAt: opt.Now().UTC().Format(time.RFC3339),
		Mode:        opt.Mode.String(),
		Provider:    p.Name,
		Domain:      p.DNS,
		Areas:       p.Areas,
		Concurrency: opt.Concurrency,
		Credential:  credentialLabel(p),
	}

	dir := p.Output.Dir
	if opt.Mode == httpx.ModeReplay {
		resolved, err := replayDirFor(opt.ReplayDir, p)
		if err != nil {
			return rep, err
		}
		dir = resolved
	}

	retain := p.Output.RetainResponses && opt.Mode == httpx.ModeLive
	rec := httpx.New(opt.Mode, dir, retain, httpx.DefaultClient())
	rec.ColdHTTP = httpx.ColdClient()

	// --- Specifications ---
	kinds := spec.KindsFor(p.Areas)
	var bundle spec.Bundle
	var err error
	switch opt.Mode {
	case httpx.ModeReplay:
		bundle, err = spec.FromDir(dir, kinds)
	case httpx.ModeDryRun:
		bundle, err = spec.NewFetcher().Fetch(ctx, cfg.Specs, "", kinds)
	default:
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return rep, fmt.Errorf("create the run directory: %w", err)
		}
		bundle, err = spec.NewFetcher().Fetch(ctx, cfg.Specs, dir, kinds)
		if err == nil {
			err = bundle.WriteManifest(dir)
		}
	}
	if err != nil {
		return rep, err
	}
	rep.Specs = bundle.Documents
	opt.Log("specifications: %s", specSummary(bundle))

	apis, licences, err := compile(bundle)
	if err != nil {
		return rep, err
	}
	for _, kind := range []spec.Kind{spec.KindConsumer, spec.KindPublisher, spec.KindInsights} {
		api := apis[kind]
		if api == nil {
			continue
		}
		for _, warning := range api.Warnings {
			rep.SpecWarnings = append(rep.SpecWarnings, string(kind)+": "+warning)
		}
	}
	consumerAPI := apis[spec.KindConsumer]
	if consumerAPI == nil {
		return rep, fmt.Errorf("the consumption specification could not be compiled")
	}

	// --- Discovery ---
	//
	// Always run, even when the area is excluded: every other area needs the
	// root it produces. Only its findings are conditional.
	wellKnownSchema, err := wellKnownSchema(bundle)
	if err != nil {
		return rep, err
	}
	resolution, discoveryResults, err := discovery.Resolve(ctx, rec, p, wellKnownSchema, consumerAPI.Version)
	if err != nil {
		return rep, err
	}
	rep.Discovery = resolution
	rep.RootURL = resolution.RootURL
	rep.TEAVersion = resolution.Version
	if p.HasArea(config.AreaDiscovery) {
		rep.Results = append(rep.Results, discoveryResults...)
		// Recorded like any other case, so a replayed run produces the same
		// discovery report as the live one it came from.
		if !resolution.Explicit {
			rep.Results = append(rep.Results,
				runner.RunCase(ctx, &runner.Client{Rec: rec}, discovery.PlaintextCase(p.DNS), nil))
		}
	}
	if resolution.RootURL == "" {
		rep.Errors = append(rep.Errors, fmt.Sprintf(
			"discovery did not reach an API root for %s: %s", p.Name, resolution.Error))
		rep.Build(apis)
		return rep, nil
	}
	opt.Log("API root %s (TEA %s)", resolution.RootURL, dashed(resolution.Version))

	client := &runner.Client{
		BaseURL: strings.TrimRight(resolution.RootURL, "/"),
		Auth:    p.AuthHeader(),
		Rec:     rec,
	}

	// --- Fixtures ---
	fixtures, err := consumer.NewSeeder(client).Seed(ctx, p.DNS)
	fixtures.Authenticated = client.Auth != ""
	rep.Fixtures = fixtures
	if err != nil {
		rep.Errors = append(rep.Errors, "the object graph could not be seeded: "+err.Error())
		rep.Build(apis)
		return rep, nil
	}
	opt.Log("fixtures: product %s (%s)", fixtures.ProductUUID, fixtures.ProductName)

	// --- Areas ---
	if p.HasArea(config.AreaConsumer) {
		cases := consumer.BuildCases(consumerAPI, fixtures)
		rep.Results = append(rep.Results, runner.Run(ctx, client, consumerAPI, cases, opt.Concurrency)...)
		opt.Log("consumer: %d cases", len(cases))
	}

	// The inventory walk feeds four areas, so it runs once when any of them is
	// enabled rather than once per area.
	var inv inventory.Inventory
	if p.HasArea(config.AreaPurl) || p.HasArea(config.AreaCycloneDX) ||
		p.HasArea(config.AreaSPDX) || p.HasArea(config.AreaProvenance) ||
		p.HasArea(config.AreaConsumer) {
		inv = inventory.Build(ctx, client, 24, opt.Concurrency)
		rep.Efficacy = inv.Stats
		rep.Products = inv.Products
		opt.Log("inventory: %d products, %d releases, %d artifacts",
			inv.Stats.ProductsSampled, inv.Stats.ReleasesSampled, inv.Stats.Artifacts)
	}

	if p.HasArea(config.AreaPurl) {
		results, found := purlarea.Run(ctx, client, consumerAPI, fixtures, inv, p.Packages, opt.Concurrency)
		rep.Results = append(rep.Results, results...)
		rep.Purl = found
	}

	var documents cdxarea.Findings
	if p.HasArea(config.AreaCycloneDX) {
		results, found := cdxarea.Run(ctx, client, inv, opt.Concurrency)
		rep.Results = append(rep.Results, results...)
		rep.CycloneDX = found
		documents = found
	}
	if p.HasArea(config.AreaSPDX) {
		results, found := spdxarea.Run(ctx, client, consumerAPI, licences, documents, inv, opt.Concurrency)
		rep.Results = append(rep.Results, results...)
		rep.SPDX = found
	}

	var insightsFixtures insights.Fixtures
	if p.HasArea(config.AreaInsights) || p.HasArea(config.AreaCEL) {
		base := p.InsightsURL
		if base == "" {
			base = insights.Root(resolution.RootURL)
		}
		insightsClient := &runner.Client{
			BaseURL: strings.TrimRight(base, "/"),
			Auth:    client.Auth,
			Rec:     rec,
		}
		insightsAPI := apis[spec.KindInsights]

		if p.HasArea(config.AreaInsights) {
			results, found := insights.Run(ctx, insightsClient, insightsAPI, fixtures, opt.Concurrency)
			rep.Results = append(rep.Results, results...)
			rep.Insights = found
			insightsFixtures = found.Fixtures
		}
		if p.HasArea(config.AreaCEL) {
			if !p.HasArea(config.AreaInsights) {
				// The CEL area needs the same probe the insights area does, and
				// running it alone is a legitimate way to use the suite.
				results, found := insights.Run(ctx, insightsClient, insightsAPI, fixtures, opt.Concurrency)
				rep.Results = append(rep.Results, results[:1]...)
				insightsFixtures = found.Fixtures
			}
			results, found := celarea.Run(ctx, insightsClient, insightsAPI, insightsFixtures, opt.Concurrency)
			rep.Results = append(rep.Results, results...)
			rep.CEL = found
		}
	}

	if p.HasArea(config.AreaProvenance) {
		results, found := provarea.Run(ctx, client, inv, opt.Concurrency)
		rep.Results = append(rep.Results, results...)
		rep.Prov = found
	}

	if p.HasArea(config.AreaPerformance) {
		shapes := perfarea.Shapes(consumerAPI, fixtures)
		results, found := perfarea.Run(ctx, client, consumerAPI, shapes, p.Performance, opt.Concurrency)
		rep.Results = append(rep.Results, results...)
		rep.Perf = found
		opt.Log("performance: %d shapes measured", len(found.Measurements))
	}

	if p.HasArea(config.AreaProvider) {
		switch opt.Mode {
		case httpx.ModeDryRun:
			rep.Publisher.Detail = "a dry run writes nothing, and every publication operation " +
				"writes; the publication round-trip was not probed"
			rep.Results = append(rep.Results, runner.Result{
				Area: config.AreaProvider, Seq: 1, Method: "-",
				Case:     "the publication round-trip was not run in dry-run mode",
				Category: "publication", Pass: true, Optional: true,
			})
		default:
			publisherAPI := apis[spec.KindPublisher]
			if publisherAPI == nil {
				rep.Errors = append(rep.Errors, "the publication specification could not be compiled")
				break
			}
			results, found := pubarea.Run(ctx, client, publisherAPI, p.WriteCycle, p.DNS)
			rep.Results = append(rep.Results, results...)
			rep.Publisher = found
			if found.Implemented {
				opt.Log("publication: %d objects created, %d residual",
					len(found.Created), len(found.Residual))
			}
		}
	}

	rep.Build(apis)
	if err := rec.WriteIndex(); err != nil {
		rep.Errors = append(rep.Errors, "write the recording index: "+err.Error())
	}
	return rep, nil
}

// Write persists a report unless the mode says nothing should be written.
func Write(rep report.Report, p config.Resolved, opt Options) ([]string, error) {
	if opt.Mode == httpx.ModeDryRun {
		return nil, nil
	}
	dir := p.Output.Dir
	if opt.Mode == httpx.ModeReplay {
		resolved, err := replayDirFor(opt.ReplayDir, p)
		if err != nil {
			return nil, err
		}
		dir = resolved
	}
	if opt.ReportsTo != "" {
		dir = filepath.Join(opt.ReportsTo, p.Slug())
	}
	split := p.Output.SplitByArea
	if opt.SplitByArea != nil {
		split = *opt.SplitByArea
	}
	return rep.Write(dir, split)
}

// replayDirFor resolves which directory holds a provider's recorded run.
//
// A caller may point at the whole output tree or at one provider's directory
// inside it; both are natural, so both work.
func replayDirFor(root string, p config.Resolved) (string, error) {
	if root == "" {
		return "", fmt.Errorf("--reproduce-from-dir needs a directory")
	}
	candidates := []string{filepath.Join(root, p.Slug()), root}
	for _, dir := range candidates {
		if info, err := os.Stat(filepath.Join(dir, "responses")); err == nil && info.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no recorded run for %q under %s: expected a responses/ directory "+
		"at %s or %s", p.Name, root, candidates[0], candidates[1])
}

// compile turns fetched bytes into the compiled documents the areas use.
func compile(bundle spec.Bundle) (map[spec.Kind]*spec.API, *spec.LicenseList, error) {
	apis := map[spec.Kind]*spec.API{}
	for _, kind := range []spec.Kind{spec.KindConsumer, spec.KindPublisher, spec.KindInsights} {
		doc, ok := bundle.Get(kind)
		if !ok {
			continue
		}
		api, err := spec.LoadAPI(kind, resourceURL(doc), doc.Raw())
		if err != nil {
			return nil, nil, err
		}
		apis[kind] = api
	}

	var licences *spec.LicenseList
	if doc, ok := bundle.Get(spec.KindSPDX); ok {
		list, err := spec.LoadLicenseList(doc.Raw())
		if err != nil {
			return nil, nil, err
		}
		licences = list
	}
	return apis, licences, nil
}

// resourceURL is the identity a document's internal `$ref`s resolve against. It
// is the document's own published URL, so a pointer in a report names something
// a reader can fetch.
func resourceURL(doc spec.Document) string {
	if doc.URL != "" {
		return doc.URL
	}
	return "https://cyclonedx.github.io/transparency-exchange-api/" + string(doc.Kind) + ".json"
}

func wellKnownSchema(bundle spec.Bundle) (*jsonschema.Schema, error) {
	doc, ok := bundle.Get(spec.KindWellKnown)
	if !ok {
		// Not fetched, because no area in this run needs it. Discovery reports
		// the document's shape without schema validation in that case.
		return nil, nil
	}
	return spec.LoadJSONSchema(resourceURL(doc), doc.Raw())
}

func credentialLabel(p config.Resolved) string {
	switch {
	case p.Auth.Scheme == config.AuthNone || p.Auth.CredentialEnv == "":
		return "none: this catalogue was read unauthenticated"
	case p.CredentialMissing:
		return fmt.Sprintf("**missing**: %s is not set in the environment", p.Auth.CredentialEnv)
	default:
		return fmt.Sprintf("%s credential from $%s", p.Auth.Scheme, p.Auth.CredentialEnv)
	}
}

func specSummary(bundle spec.Bundle) string {
	parts := make([]string, 0, len(bundle.Documents))
	for _, doc := range bundle.Documents {
		parts = append(parts, fmt.Sprintf("%s@%s", doc.Kind, dashed(doc.Ref)))
	}
	return strings.Join(parts, ", ")
}

func dashed(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
