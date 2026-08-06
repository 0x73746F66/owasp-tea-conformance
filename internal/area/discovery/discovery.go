// Package discovery walks the specification's resolution chain: a DNS name,
// then the .well-known document that name serves, then the endpoint and version
// a client should talk to, and finally the /discovery endpoint that turns a TEI
// into a product release.
//
// Everything else in this suite depends on this package's output, because
// everything else needs an API root. That is also why resolution runs even when
// the discovery area is excluded from a run — the difference is only whether
// its findings are reported.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/httpx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

// Sequence numbers for the resolution requests. They are fixed constants so a
// replayed run addresses the same recordings, and so the TEI cases that follow
// can start from a known offset.
const (
	seqWellKnownHTTPS = 1
	seqWellKnownHTTP  = 2
	// SeqTEIBase is where TEI resolution cases start numbering.
	SeqTEIBase = 10
)

// DNSResult is what the domain resolved to.
type DNSResult struct {
	Addresses []string `json:"addresses,omitempty"`
	CNAME     string   `json:"cname,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// Endpoint is one entry of the discovery document.
type Endpoint struct {
	URL      string   `json:"url"`
	Versions []string `json:"versions"`
	Priority *float64 `json:"priority,omitempty"`
}

// WellKnown is the discovery document.
type WellKnown struct {
	SchemaVersion int        `json:"schemaVersion"`
	Endpoints     []Endpoint `json:"endpoints"`
}

// Resolution is the outcome of following the chain.
type Resolution struct {
	Domain       string     `json:"domain"`
	DNS          DNSResult  `json:"dns"`
	WellKnownURL string     `json:"wellKnownUrl,omitempty"`
	Document     *WellKnown `json:"document,omitempty"`
	Endpoint     Endpoint   `json:"endpoint,omitempty"`
	Version      string     `json:"version,omitempty"`
	RootURL      string     `json:"rootUrl,omitempty"`
	InsightsURL  string     `json:"insightsUrl,omitempty"`

	// Explicit is true when the configuration supplied the root URL directly
	// and no discovery document was consulted.
	Explicit bool `json:"explicit,omitempty"`
	// SpecVersionMatch is false when the endpoint's advertised version is a
	// different TEA generation from the specification being validated against.
	// The run continues — the report says which document it judged by.
	SpecVersionMatch bool `json:"specVersionMatch"`

	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

// Authority is the domain half of every TEI this provider issues.
func (r Resolution) Authority() string { return r.Domain }

// Resolve follows the chain and returns both the resolution and the cases it
// checked along the way.
//
// It never returns an error for a provider that failed to resolve: an
// unreachable server is a conformance finding, and the report has to be able to
// say so. The error return is for conditions that break the run itself.
func Resolve(
	ctx context.Context,
	rec *httpx.Recorder,
	provider config.Resolved,
	wellKnownSchema *jsonschema.Schema,
	specVersion string,
) (Resolution, []runner.Result, error) {
	res := Resolution{Domain: provider.DNS}

	// A configuration that pins the root URL is testing a server that does not
	// publish a discovery document, or is being pointed at a staging host. Both
	// are legitimate; the report states that discovery was not exercised.
	if provider.RootURL != "" {
		res.Explicit = true
		res.RootURL = strings.TrimRight(provider.RootURL, "/")
		res.Version = provider.Version
		res.InsightsURL = insightsRoot(provider, res.RootURL)
		res.Ready = true
		res.SpecVersionMatch = res.Version == "" ||
			SameMajorMinor(ParseVersion(res.Version), ParseVersion(specVersion))
		return res, nil, nil
	}

	var results []runner.Result

	// DNS is the one step with no HTTP response to record, so it is persisted
	// on its own and read back when replaying. Everything after it replays
	// through the recorder like any other request.
	if rec.Mode == httpx.ModeReplay {
		recorded, err := replayResolution(rec.Dir)
		if err != nil {
			return res, nil, err
		}
		res.DNS = recorded.DNS
	} else {
		res.DNS = resolveDNS(ctx, provider.DNS)
	}
	if res.DNS.Error != "" {
		res.Error = res.DNS.Error
		_ = persistResolution(rec, res)
		return res, results, nil
	}

	client := &runner.Client{Rec: rec}

	// The document is fetched unauthenticated on purpose: it is what a consumer
	// reads before it holds any credential, so requiring one would break the
	// entry point of the protocol.
	res.WellKnownURL = "https://" + provider.DNS + "/.well-known/tea"
	wellKnown := runner.Case{
		Area:        config.AreaDiscovery,
		Seq:         seqWellKnownHTTPS,
		OperationID: "wellKnownDiscoveryDocument",
		Name:        "discovery document conforms to tea-well-known.schema.json",
		Category:    "discovery",
		AbsoluteURL: res.WellKnownURL,
		Auth:        runner.NoAuth,
		WantStatus:  http.StatusOK,
		Schema:      wellKnownSchema,
	}
	wellKnown.Check = func(body []byte) error {
		doc, err := parseWellKnown(body)
		if err != nil {
			return err
		}
		res.Document = doc
		return checkWellKnownRules(doc)
	}
	result := runner.RunCase(ctx, client, wellKnown, nil)
	results = append(results, result)

	if res.Document == nil && len(result.Body) > 0 {
		// The case failed before the check ran — a non-200, most likely. Parse
		// anyway so the report can still say what was served.
		if doc, err := parseWellKnown(result.Body); err == nil {
			res.Document = doc
		}
	}
	if res.Document == nil || len(res.Document.Endpoints) == 0 {
		res.Error = "no usable discovery document at " + res.WellKnownURL
		_ = persistResolution(rec, res)
		return res, results, nil
	}

	endpoint, version, matched := pickEndpoint(*res.Document, specVersion)
	res.Endpoint = endpoint
	res.Version = version
	res.SpecVersionMatch = matched
	res.RootURL = strings.TrimRight(endpoint.URL, "/")
	if version != "" {
		res.RootURL += "/v" + version
	}
	res.InsightsURL = insightsRoot(provider, res.RootURL)
	res.Ready = res.RootURL != ""

	if err := persistResolution(rec, res); err != nil {
		return res, results, err
	}
	return res, results, nil
}

// PlaintextCase asserts the rule the discovery readme states outright: the
// .well-known endpoint must only be available over HTTPS.
//
// A server answering it in the clear hands a consumer an endpoint list over an
// unauthenticated channel, and that list is the address the consumer will then
// trust for every artifact it downloads.
func PlaintextCase(domain string) runner.Case {
	return runner.Case{
		Area:        config.AreaDiscovery,
		Seq:         seqWellKnownHTTP,
		OperationID: "wellKnownDiscoveryDocument",
		Name:        "discovery document is not served over plaintext HTTP",
		Category:    "security",
		AbsoluteURL: "http://" + domain + "/.well-known/tea",
		Auth:        runner.NoAuth,
		// A redirect to HTTPS is the correct answer, and Go follows it, so a
		// 200 here means the client ended up on HTTPS. What must not happen is
		// the document being served in the clear, which the check below tests
		// by refusing to accept a response that never left HTTP.
		WantStatus:   http.StatusOK,
		AcceptStatus: []int{http.StatusNotFound, http.StatusMovedPermanently, http.StatusFound},
	}
}

func parseWellKnown(body []byte) (*WellKnown, error) {
	var doc WellKnown
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("discovery document is not JSON: %w", err)
	}
	return &doc, nil
}

// checkWellKnownRules asserts what the schema cannot: that the URLs in the
// document are usable as published.
func checkWellKnownRules(doc *WellKnown) error {
	if doc.SchemaVersion != 1 {
		return fmt.Errorf("schemaVersion is %d; the discovery schema pins it to 1", doc.SchemaVersion)
	}
	if len(doc.Endpoints) == 0 {
		return fmt.Errorf("the document advertises no endpoints, so a consumer has nowhere to go")
	}
	for _, e := range doc.Endpoints {
		if strings.HasSuffix(e.URL, "/") {
			return fmt.Errorf("endpoint url %q has a trailing slash; a client appending /v<version> "+
				"would produce a double slash", e.URL)
		}
		if !strings.HasPrefix(e.URL, "http") {
			return fmt.Errorf("endpoint url %q is not absolute", e.URL)
		}
		if strings.HasPrefix(e.URL, "http://") && !isLoopback(e.URL) {
			return fmt.Errorf("endpoint url %q is plaintext; a published address must be https", e.URL)
		}
		if len(e.Versions) == 0 {
			return fmt.Errorf("endpoint %q advertises no versions, so no client can select it", e.URL)
		}
		for _, v := range e.Versions {
			if strings.HasPrefix(v, "v") {
				return fmt.Errorf("version %q carries a v prefix; the schema requires it without", v)
			}
			if !ParseVersion(v).Valid {
				return fmt.Errorf("version %q is not a SemVer 2.0.0 version, so the "+
					"specification's endpoint-selection rule cannot be applied to it", v)
			}
		}
		if e.Priority != nil && (*e.Priority < 0 || *e.Priority > 1) {
			return fmt.Errorf("priority %v is outside the 0..1 range the specification defines", *e.Priority)
		}
	}
	return nil
}

// pickEndpoint implements the specification's selection rule: the highest
// version both sides support, then the highest priority among the endpoints
// offering it.
//
// "Both sides" means the version this suite validated the responses against. If
// no endpoint offers it, the highest advertised version is used instead and the
// caller is told the generations differ, because a run that silently judged a
// 1.x server by a 0.4 document would be reporting nonsense.
func pickEndpoint(doc WellKnown, specVersion string) (Endpoint, string, bool) {
	want := ParseVersion(specVersion)

	type candidate struct {
		endpoint Endpoint
		version  Version
		priority float64
	}
	var exact, any []candidate
	for _, e := range doc.Endpoints {
		priority := 0.0
		if e.Priority != nil {
			priority = *e.Priority
		}
		for _, raw := range e.Versions {
			v := ParseVersion(raw)
			c := candidate{endpoint: e, version: v, priority: priority}
			any = append(any, c)
			if SameMajorMinor(v, want) {
				exact = append(exact, c)
			}
		}
	}

	pool, matched := exact, true
	if len(pool) == 0 {
		pool, matched = any, false
	}
	if len(pool) == 0 {
		return Endpoint{}, "", false
	}
	sort.SliceStable(pool, func(i, j int) bool {
		if c := Compare(pool[i].version, pool[j].version); c != 0 {
			return c > 0 // highest version first
		}
		return pool[i].priority > pool[j].priority
	})
	best := pool[0]
	return best.endpoint, best.version.Raw, matched
}

// insightsRoot derives the Insights API root. It shares an origin with the TEA
// API and sits at /insights, outside the version prefix.
func insightsRoot(provider config.Resolved, rootURL string) string {
	if provider.InsightsURL != "" {
		return strings.TrimRight(provider.InsightsURL, "/")
	}
	u, err := url.Parse(rootURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/insights"
}

func resolveDNS(ctx context.Context, domain string) DNSResult {
	var out DNSResult
	resolver := &net.Resolver{}

	timeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if cname, err := resolver.LookupCNAME(timeout, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, domain) {
			out.CNAME = cname
		}
	}
	addrs, err := resolver.LookupHost(timeout, domain)
	if err != nil {
		out.Error = fmt.Sprintf("%s does not resolve: %v", domain, err)
		return out
	}
	sort.Strings(addrs)
	out.Addresses = addrs
	return out
}

func isLoopback(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// persistResolution records what discovery found, so a replayed run resolves
// identically without touching DNS.
func persistResolution(rec *httpx.Recorder, res Resolution) error {
	if rec.Mode != httpx.ModeLive || !rec.Retain {
		return nil
	}
	dir := filepath.Join(rec.Dir, "responses", string(config.AreaDiscovery))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "resolution.json"), append(encoded, '\n'), 0o644)
}

func replayResolution(dir string) (Resolution, error) {
	path := filepath.Join(dir, "responses", string(config.AreaDiscovery), "resolution.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return Resolution{}, fmt.Errorf("replay: the recorded run has no discovery resolution at %s", path)
	}
	var res Resolution
	if err := json.Unmarshal(raw, &res); err != nil {
		return Resolution{}, fmt.Errorf("replay: %s is not readable: %w", path, err)
	}
	return res, nil
}
