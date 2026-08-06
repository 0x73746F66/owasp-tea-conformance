// Command tea-conformance runs the OWASP Transparency Exchange API conformance
// suite against the providers named in a configuration file.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/httpx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/report"
	"github.com/0x73746F66/owasp-tea-conformance/internal/run"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

func main() {
	if err := app(); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

type flags struct {
	configPath string
	providers  stringList
	areas      stringList
	dryRun     bool
	replayDir  string
	plan       bool
	fetchTo    string
	reportsTo  string
	markdown   string
	quiet      bool
	failFast   bool
}

func app() error {
	var f flags
	flag.StringVar(&f.configPath, "config", "config.yaml", "path to the configuration file")
	flag.Var(&f.providers, "provider", "run only this provider; repeatable")
	flag.Var(&f.areas, "area", "run only this area; repeatable")
	flag.BoolVar(&f.dryRun, "dryrun", false,
		"check that every endpoint answers, storing nothing and evaluating nothing")
	flag.StringVar(&f.replayDir, "reproduce-from-dir", "",
		"regenerate reports from a recorded run, making no network requests")
	flag.BoolVar(&f.plan, "plan", false,
		"print what would run, and stop; makes no network requests")
	flag.StringVar(&f.fetchTo, "fetch-specs-to", "",
		"fetch the configured specifications into this directory and stop")
	flag.StringVar(&f.reportsTo, "reports-to", "",
		"write the reports under this directory instead of the configured one; recordings stay put")
	flag.StringVar(&f.markdown, "markdown", "",
		"override the Markdown layout: `single` for one document, `split` for one per area")
	flag.BoolVar(&f.quiet, "quiet", false, "suppress progress output")
	flag.BoolVar(&f.failFast, "fail-fast", false, "stop at the first provider that is not conformant")
	flag.Parse()

	if f.dryRun && f.replayDir != "" {
		return fmt.Errorf("--dryrun and --reproduce-from-dir are opposites: one issues every " +
			"request and keeps nothing, the other issues none and reads everything from disk")
	}

	cfg, err := config.Load(f.configPath)
	if err != nil {
		return err
	}

	areaFilter, err := config.ParseAreas(f.areas)
	if err != nil {
		return err
	}
	providers, err := cfg.Resolve(f.providers, areaFilter)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if f.fetchTo != "" {
		return fetchSpecs(ctx, cfg, providers, f.fetchTo)
	}
	if f.plan {
		printPlan(cfg, providers)
		return nil
	}

	opt := run.Options{
		Mode:      mode(f),
		ReplayDir: f.replayDir,
		ReportsTo: f.reportsTo,
	}
	switch f.markdown {
	case "":
	case "single":
		opt.SplitByArea = boolPtr(false)
	case "split":
		opt.SplitByArea = boolPtr(true)
	default:
		return fmt.Errorf("--markdown takes `single` or `split`, not %q", f.markdown)
	}
	if !f.quiet {
		opt.Log = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "  "+format+"\n", args...)
		}
	}

	failed := 0
	for _, p := range providers {
		if !f.quiet {
			fmt.Fprintf(os.Stderr, "\n%s (%s) — %s\n", p.Name, dashed(p.DNS),
				config.JoinAreas(p.Areas, ", "))
		}
		if p.CredentialMissing && !f.quiet {
			fmt.Fprintf(os.Stderr, "  warning: %s is not set, so this provider is read "+
				"unauthenticated\n", p.Auth.CredentialEnv)
		}

		rep, err := run.Provider(ctx, cfg, p, opt)
		if err != nil {
			return fmt.Errorf("%s: %w", p.Name, err)
		}
		written, err := run.Write(rep, p, opt)
		if err != nil {
			return fmt.Errorf("%s: %w", p.Name, err)
		}

		summarise(rep, written, f)
		if !rep.Conformant() {
			failed++
			if f.failFast {
				break
			}
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d provider(s) are not conformant", failed, len(providers))
	}
	return nil
}

func mode(f flags) httpx.Mode {
	switch {
	case f.dryRun:
		return httpx.ModeDryRun
	case f.replayDir != "":
		return httpx.ModeReplay
	default:
		return httpx.ModeLive
	}
}

// summarise prints the one-screen outcome. The reports carry the detail; this
// is what a person reads while the run is still on screen.
func summarise(rep report.Report, written []string, f flags) {
	fmt.Printf("%-24s %-16s %d cases, %d passed, %d failed, %d advisory\n",
		rep.Provider, rep.Verdict(),
		rep.Totals.Cases, rep.Totals.Passed, rep.Totals.Failed, rep.Totals.Advisory)
	for _, e := range rep.Errors {
		fmt.Printf("  ! %s\n", e)
	}
	if n := len(rep.Publisher.Residual); n > 0 {
		fmt.Printf("  ! %d record(s) were left in this provider's catalogue — see residual.md\n", n)
	}
	if !f.quiet {
		for _, path := range written {
			fmt.Printf("  → %s\n", path)
		}
	}
}

func fetchSpecs(ctx context.Context, cfg *config.Config, providers []config.Resolved, dir string) error {
	// Fetch the union of what every configured provider needs, so the preview
	// matches what a real run would use.
	need := map[spec.Kind]bool{}
	for _, p := range providers {
		for _, kind := range spec.KindsFor(p.Areas) {
			need[kind] = true
		}
	}
	var kinds []spec.Kind
	for _, kind := range []spec.Kind{
		spec.KindConsumer, spec.KindPublisher, spec.KindWellKnown, spec.KindInsights, spec.KindSPDX,
	} {
		if need[kind] {
			kinds = append(kinds, kind)
		}
	}

	bundle, err := spec.NewFetcher().Fetch(ctx, cfg.Specs, dir, kinds)
	if err != nil {
		return err
	}
	if err := bundle.WriteManifest(dir); err != nil {
		return err
	}
	for _, doc := range bundle.Documents {
		fmt.Printf("%-10s %-72s %s\n", doc.Kind, doc.URL, doc.SHA256[:16])
	}
	return nil
}

// printPlan says what a run would do without doing any of it. It is also the CI
// check that the configuration in the repository still resolves.
func printPlan(cfg *config.Config, providers []config.Resolved) {
	fmt.Printf("configuration: %s\n\n", cfg.Path())
	for _, p := range providers {
		fmt.Printf("%s\n", p.Name)
		fmt.Printf("  discovery from   %s\n", dashed(p.DNS))
		if p.RootURL != "" {
			fmt.Printf("  explicit root    %s\n", p.RootURL)
		}
		fmt.Printf("  areas            %s\n", config.JoinAreas(p.Areas, ", "))
		fmt.Printf("  reports          %s\n", p.Output.Dir)
		split := "one document"
		if p.Output.SplitByArea {
			split = "one document per area"
		}
		fmt.Printf("  markdown         %s\n", split)
		fmt.Printf("  responses kept   %t\n", p.Output.RetainResponses)
		fmt.Printf("  packages sampled %d\n", len(p.Packages))
		switch {
		case p.Auth.Scheme == config.AuthNone:
			fmt.Printf("  credential       none\n")
		case p.CredentialMissing:
			fmt.Printf("  credential       %s scheme, but $%s is NOT SET\n",
				p.Auth.Scheme, p.Auth.CredentialEnv)
		default:
			fmt.Printf("  credential       %s from $%s\n", p.Auth.Scheme, p.Auth.CredentialEnv)
		}
		if p.HasArea(config.AreaProvider) {
			fmt.Printf("  writes records   %s / %s (deleted again by the round-trip)\n",
				p.WriteCycle.NamePrefix, p.WriteCycle.RunKey)
		}
		fmt.Println()
	}
}

func boolPtr(b bool) *bool { return &b }

func dashed(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// stringList collects a repeatable flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}
