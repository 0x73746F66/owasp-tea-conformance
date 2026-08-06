// Package config loads the YAML that describes which providers to test, which
// areas to test them for, and where the evidence goes.
//
// The shape is deliberately two-level: a global block that is the sensible
// default for every provider, and a per-provider block that overrides it. Most
// real configurations set the global block once and then say only what is
// different about each provider: which areas it cannot serve, which credential
// it needs, where its reports should land.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the whole file.
type Config struct {
	// Version is the configuration schema version. It exists so a future
	// incompatible change can be rejected with a message rather than
	// misinterpreted.
	Version int `yaml:"version"`

	// Specs names where each specification is fetched from. Every run fetches
	// them afresh and writes the exact bytes it used into its own output
	// directory, so a report is always self-describing.
	Specs Specs `yaml:"specs"`

	Output      Output      `yaml:"output"`
	Areas       []string    `yaml:"areas"`
	Exclude     []string    `yaml:"exclude"`
	Performance Performance `yaml:"performance"`
	WriteCycle  WriteCycle  `yaml:"writeCycle"`

	// Packages is the open-source sample every provider is asked about, as
	// package URLs. A provider may narrow or replace it.
	Packages []string `yaml:"packages"`

	Providers []Provider `yaml:"providers"`

	// path is where this configuration was read from, used to resolve relative
	// output directories against the file and not the caller's cwd.
	path string `yaml:"-"`
}

// SpecSource addresses one specification document.
//
// Repo/Ref/Path address a file in a Git forge; URL is the escape hatch for a
// document that is not in one. Exactly one form must be set.
type SpecSource struct {
	Repo string `yaml:"repo"`
	Ref  string `yaml:"ref"`
	Path string `yaml:"path"`
	URL  string `yaml:"url"`

	// Note is carried into the report next to the digest. It is how a run
	// discloses that a document is not yet upstream.
	Note string `yaml:"note"`
}

// Specs is the set of documents a run validates against.
type Specs struct {
	Consumer  SpecSource `yaml:"consumer"`
	Publisher SpecSource `yaml:"publisher"`
	WellKnown SpecSource `yaml:"wellKnown"`
	Insights  SpecSource `yaml:"insights"`
	SPDX      SpecSource `yaml:"spdx"`
}

// Output says where a provider's evidence is written and how it is split.
type Output struct {
	Dir string `yaml:"dir"`
	// SplitByArea writes one Markdown file per area instead of one combined
	// report. The JSON record is always single, because it is machine input.
	SplitByArea *bool `yaml:"splitByArea"`
	// RetainResponses keeps every response body on disk. Turning it off makes
	// the run unreproducible, and the report says so.
	RetainResponses *bool `yaml:"retainResponses"`
}

// Performance configures the latency measurement.
type Performance struct {
	// ColdSamples is how many times each request shape is measured on a fresh
	// connection with no reuse. That is the cost a consumer pays on first
	// contact.
	ColdSamples int `yaml:"coldSamples"`
	// Iterations is how many times each shape is replayed warm.
	Iterations int `yaml:"iterations"`
	// Concurrency bounds in-flight requests during the warm replay.
	Concurrency int `yaml:"concurrency"`
}

// WriteCycle configures the records the provider area creates.
//
// The values are deterministic on purpose: a re-run addresses the same records,
// so the delete cases at the end of the round-trip clean up both this run's
// objects and anything a previous interrupted run left behind.
type WriteCycle struct {
	NamePrefix    string `yaml:"namePrefix"`
	RunKey        string `yaml:"runKey"`
	PurlNamespace string `yaml:"purlNamespace"`
}

// Auth describes how to authenticate to a provider. Credentials are never
// written in the file. Only the name of the environment variable holding one.
type Auth struct {
	Scheme        string `yaml:"scheme"`
	CredentialEnv string `yaml:"credentialEnv"`
}

// Supported authentication schemes. They are the specification's security
// schemes, the case of a catalogue that needs no credential at all, and the
// escape hatch for a credential that arrives already rendered.
const (
	AuthNone   = "none"
	AuthBearer = "bearer"
	AuthBasic  = "basic"
	AuthAPIKey = "apikey"
	// AuthHeader sends the credential verbatim as the Authorization header.
	//
	// It exists for credentials produced by something that already knows how to
	// render them: a vendor's own CLI, a credential helper, a token broker.
	// Splitting such a value back into scheme and secret so this suite can
	// rejoin them is a chance to get it wrong, and getting it wrong produces a
	// 401 that reads as a provider's failure.
	AuthHeader = "header"
)

// Provider is one server under test.
type Provider struct {
	Name string `yaml:"name"`

	// DNS is the domain a TEI names. It is the input to discovery, and the
	// authority half of every TEI this provider issues.
	DNS string `yaml:"dns"`

	// RootURL skips discovery and addresses the API directly. Only for servers
	// that do not publish a discovery document; the discovery area reports the
	// absence instead of hiding it.
	RootURL string `yaml:"rootUrl"`
	// Version is the TEA version to use when RootURL is set explicitly.
	Version string `yaml:"version"`
	// InsightsURL overrides the Insights root, which is otherwise derived from
	// the API origin.
	InsightsURL string `yaml:"insightsUrl"`

	Auth Auth `yaml:"auth"`

	Areas   []string `yaml:"areas"`
	Exclude []string `yaml:"exclude"`

	Output      *Output      `yaml:"output"`
	Performance *Performance `yaml:"performance"`
	WriteCycle  *WriteCycle  `yaml:"writeCycle"`
	Packages    []string     `yaml:"packages"`
}

// Resolved is one provider with every global default already folded in, so
// nothing downstream has to know the configuration had two levels.
type Resolved struct {
	Provider

	Areas       []Area
	Output      ResolvedOutput
	Performance Performance
	WriteCycle  WriteCycle
	Packages    []string

	// Credential is the value read from Auth.CredentialEnv. Empty means the
	// variable was unset, which is a fact the report states rather than a
	// failure: a public catalogue needs no credential.
	Credential string
	// CredentialMissing is true when a scheme other than "none" was configured
	// but the environment did not supply the secret.
	CredentialMissing bool
}

// ResolvedOutput is Output with its pointers collapsed to values.
type ResolvedOutput struct {
	Dir             string
	SplitByArea     bool
	RetainResponses bool
}

// Slug is a filesystem-safe name for this provider, used for its directory.
func (r Resolved) Slug() string { return Slug(r.Name) }

// HasArea reports whether an area survived resolution.
func (r Resolved) HasArea(a Area) bool {
	for _, got := range r.Areas {
		if got == a {
			return true
		}
	}
	return false
}

// AuthHeader renders the credential as an Authorization header value. Basic
// credentials are supplied as a raw "user:password" pair and encoded here, so
// nobody has to base64 a secret by hand to run the suite.
func (r Resolved) AuthHeader() string {
	cred := strings.TrimSpace(r.Credential)
	if cred == "" {
		return ""
	}
	switch r.Auth.Scheme {
	case AuthHeader:
		return cred
	case AuthBearer:
		return "Bearer " + cred
	case AuthBasic:
		if strings.Contains(cred, ":") {
			return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))
		}
		return "Basic " + cred
	case AuthAPIKey:
		return "ApiKey " + cred
	default:
		return ""
	}
}

// Defaults, applied where the file is silent.
const (
	DefaultOutputDir       = "reports"
	DefaultColdSamples     = 5
	DefaultIterations      = 300
	DefaultConcurrency     = 32
	DefaultNamePrefix      = "owasp-tea-conformance"
	DefaultRunKey          = "conformance-001"
	DefaultPurlNamespace   = "pkg:generic/owasp-tea-conformance"
	DefaultSpecRepo        = "CycloneDX/transparency-exchange-api"
	DefaultSpecRef         = "main"
	DefaultInsightsSpecRef = "insights"
)

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	// Unknown keys are an error: a misspelled `excludes:` that silently did
	// nothing would widen a run without anybody noticing.
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.path = path
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Output.Dir == "" {
		c.Output.Dir = DefaultOutputDir
	}
	if c.Output.SplitByArea == nil {
		c.Output.SplitByArea = boolPtr(true)
	}
	if c.Output.RetainResponses == nil {
		c.Output.RetainResponses = boolPtr(true)
	}
	if len(c.Areas) == 0 {
		for _, a := range AllAreas {
			c.Areas = append(c.Areas, string(a))
		}
	}
	if c.Performance.ColdSamples == 0 {
		c.Performance.ColdSamples = DefaultColdSamples
	}
	if c.Performance.Iterations == 0 {
		c.Performance.Iterations = DefaultIterations
	}
	if c.Performance.Concurrency == 0 {
		c.Performance.Concurrency = DefaultConcurrency
	}
	if c.WriteCycle.NamePrefix == "" {
		c.WriteCycle.NamePrefix = DefaultNamePrefix
	}
	if c.WriteCycle.RunKey == "" {
		c.WriteCycle.RunKey = DefaultRunKey
	}
	if c.WriteCycle.PurlNamespace == "" {
		c.WriteCycle.PurlNamespace = DefaultPurlNamespace
	}
	c.Specs.applyDefaults()
}

// DefaultSpecs is where each specification is fetched from when a
// configuration says nothing. It is exported so a caller can fetch the
// authoritative documents without writing a configuration file first.
func DefaultSpecs() Specs {
	var s Specs
	s.applyDefaults()
	return s
}

func (s *Specs) applyDefaults() {
	fill := func(src *SpecSource, repo, ref, path string) {
		if src.URL != "" {
			return
		}
		if src.Repo == "" {
			src.Repo = repo
		}
		if src.Ref == "" {
			src.Ref = ref
		}
		if src.Path == "" {
			src.Path = path
		}
	}
	fill(&s.Consumer, DefaultSpecRepo, DefaultSpecRef, "spec/openapi.yaml")
	fill(&s.Publisher, DefaultSpecRepo, DefaultSpecRef, "spec/publisher/openapi.json")
	fill(&s.WellKnown, DefaultSpecRepo, DefaultSpecRef, "discovery/tea-well-known.schema.json")
	fill(&s.Insights, "0x73746F66/transparency-exchange-api", DefaultInsightsSpecRef, "insights/openapi.json")
	fill(&s.SPDX, "spdx/license-list-data", "main", "json/licenses.json")
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("config version %d is not supported by this build (expected 1)", c.Version)
	}
	if _, err := ParseAreas(c.Areas); err != nil {
		return fmt.Errorf("areas: %w", err)
	}
	if _, err := ParseAreas(c.Exclude); err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	if len(c.Providers) == 0 {
		return errors.New("config lists no providers; add at least one with a dns name")
	}
	seen := map[string]bool{}
	for i, p := range c.Providers {
		where := fmt.Sprintf("providers[%d]", i)
		if p.Name == "" {
			return fmt.Errorf("%s has no name", where)
		}
		if seen[p.Name] {
			return fmt.Errorf("%s: provider name %q is used more than once", where, p.Name)
		}
		seen[p.Name] = true
		if p.DNS == "" && p.RootURL == "" {
			return fmt.Errorf("provider %q needs a dns name (or an explicit rootUrl)", p.Name)
		}
		if p.RootURL != "" && !strings.HasPrefix(p.RootURL, "https://") &&
			!strings.HasPrefix(p.RootURL, "http://") {
			return fmt.Errorf("provider %q rootUrl must be an absolute URL", p.Name)
		}
		switch p.Auth.Scheme {
		case "", AuthNone, AuthBearer, AuthBasic, AuthAPIKey, AuthHeader:
		default:
			return fmt.Errorf("provider %q has unknown auth scheme %q; use none, bearer, basic, "+
				"apikey or header", p.Name, p.Auth.Scheme)
		}
		if _, err := ParseAreas(p.Areas); err != nil {
			return fmt.Errorf("provider %q areas: %w", p.Name, err)
		}
		if _, err := ParseAreas(p.Exclude); err != nil {
			return fmt.Errorf("provider %q exclude: %w", p.Name, err)
		}
	}
	return nil
}

// Resolve folds the global defaults into every provider and returns them in
// file order.
//
// `only` narrows to named providers; empty means all. Unknown names are an
// error rather than a silent no-op, because "the run was green" and "the run
// did nothing" must not look the same.
func (c *Config) Resolve(only []string, areaFilter []Area) ([]Resolved, error) {
	want := map[string]bool{}
	for _, n := range only {
		want[strings.ToLower(n)] = true
	}
	matched := map[string]bool{}

	out := make([]Resolved, 0, len(c.Providers))
	for _, p := range c.Providers {
		if len(want) > 0 && !want[strings.ToLower(p.Name)] {
			continue
		}
		matched[strings.ToLower(p.Name)] = true

		r, err := c.resolveOne(p, areaFilter)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	for n := range want {
		if !matched[n] {
			return nil, fmt.Errorf("no provider named %q in %s", n, c.path)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no providers selected")
	}
	return out, nil
}

func (c *Config) resolveOne(p Provider, areaFilter []Area) (Resolved, error) {
	base := c.Areas
	if len(p.Areas) > 0 {
		base = p.Areas
	}
	areas, err := ParseAreas(base)
	if err != nil {
		return Resolved{}, fmt.Errorf("provider %q: %w", p.Name, err)
	}
	drop := map[Area]bool{}
	for _, list := range [][]string{c.Exclude, p.Exclude} {
		excluded, err := ParseAreas(list)
		if err != nil {
			return Resolved{}, fmt.Errorf("provider %q: %w", p.Name, err)
		}
		for _, a := range excluded {
			drop[a] = true
		}
	}
	keep := map[Area]bool{}
	if len(areaFilter) > 0 {
		for _, a := range areaFilter {
			keep[a] = true
		}
	}

	final := make([]Area, 0, len(areas))
	for _, a := range areas {
		if drop[a] {
			continue
		}
		if len(keep) > 0 && !keep[a] {
			continue
		}
		final = append(final, a)
	}

	r := Resolved{
		Provider:    p,
		Areas:       sortAreas(final),
		Performance: c.Performance,
		WriteCycle:  c.WriteCycle,
		Packages:    c.Packages,
	}
	if p.Performance != nil {
		if p.Performance.ColdSamples > 0 {
			r.Performance.ColdSamples = p.Performance.ColdSamples
		}
		if p.Performance.Iterations != 0 {
			r.Performance.Iterations = p.Performance.Iterations
		}
		if p.Performance.Concurrency > 0 {
			r.Performance.Concurrency = p.Performance.Concurrency
		}
	}
	if p.WriteCycle != nil {
		if p.WriteCycle.NamePrefix != "" {
			r.WriteCycle.NamePrefix = p.WriteCycle.NamePrefix
		}
		if p.WriteCycle.RunKey != "" {
			r.WriteCycle.RunKey = p.WriteCycle.RunKey
		}
		if p.WriteCycle.PurlNamespace != "" {
			r.WriteCycle.PurlNamespace = p.WriteCycle.PurlNamespace
		}
	}
	if len(p.Packages) > 0 {
		r.Packages = p.Packages
	}

	r.Output = ResolvedOutput{
		Dir:             filepath.Join(c.Output.Dir, Slug(p.Name)),
		SplitByArea:     *c.Output.SplitByArea,
		RetainResponses: *c.Output.RetainResponses,
	}
	if p.Output != nil {
		if p.Output.Dir != "" {
			r.Output.Dir = p.Output.Dir
		}
		if p.Output.SplitByArea != nil {
			r.Output.SplitByArea = *p.Output.SplitByArea
		}
		if p.Output.RetainResponses != nil {
			r.Output.RetainResponses = *p.Output.RetainResponses
		}
	}
	if !filepath.IsAbs(r.Output.Dir) && c.path != "" {
		// Relative to the configuration file, so `just run` from anywhere puts
		// the evidence in the same place.
		r.Output.Dir = filepath.Join(filepath.Dir(c.path), r.Output.Dir)
	}

	if r.Auth.Scheme == "" {
		r.Auth.Scheme = AuthNone
	}
	if r.Auth.CredentialEnv != "" {
		r.Credential = os.Getenv(r.Auth.CredentialEnv)
	}
	r.CredentialMissing = r.Auth.Scheme != AuthNone && r.Credential == ""

	return r, nil
}

// Path is where this configuration was loaded from.
func (c *Config) Path() string { return c.path }

// Slug renders a name as a lowercase, filesystem-safe token.
func Slug(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		case r == '.' || r == '_' || r == '-' || r == ' ' || r == '/':
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func boolPtr(b bool) *bool { return &b }
