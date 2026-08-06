// Package runner turns a list of cases into a list of results.
//
// A case is one request together with what the specification says the answer
// must look like. The runner knows nothing about any particular provider: it
// issues the request through the recorder, compares the response with the
// declared schema, runs whatever assertion the schemas could not express, and
// reports what it found.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/httpx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

// NoAuth, used as a Case.Auth override, sends the request with no
// Authorization header at all, the way an unauthenticated client would.
const NoAuth = "-"

// Client addresses one TEA server.
type Client struct {
	// BaseURL is the API root with no trailing slash, e.g.
	// https://api.example.com/tea/v1.
	BaseURL string
	// Auth is the Authorization header value used unless a case overrides it.
	Auth string
	// Rec issues every request; it is what makes a run recordable and
	// replayable.
	Rec *httpx.Recorder
}

// Case is one request the suite makes.
type Case struct {
	Area config.Area
	// Seq orders this case's recording within its area. It must come from the
	// case's position in a deterministically-built list, not from the order
	// results happen to arrive in.
	Seq int

	OperationID string
	Name        string
	Method      string

	// Path is relative to Client.BaseURL. AbsoluteURL overrides both, for the
	// documents that live outside the API root: the discovery document, and
	// artifact downloads that point wherever the publisher put them.
	Path        string
	AbsoluteURL string
	Query       url.Values

	// Auth overrides the client credential: NoAuth omits the header entirely.
	Auth string

	WantStatus int
	// AcceptStatus lists further statuses that count as a pass. The Insights
	// specification leaves a deployment free to answer 503 when its inference
	// backend is absent, and failing on that would be testing the deployment's
	// configuration rather than its conformance.
	AcceptStatus []int

	// SchemaPtr is a JSON Pointer into the API document; "" means the case is a
	// status-only check.
	SchemaPtr string
	// Schema is a pre-compiled schema used instead of SchemaPtr, for responses
	// validated against a document other than the one under test, since the
	// Insights responses are CycloneDX.
	Schema any

	Body        []byte
	ContentType string
	// Accept overrides the request's Accept header, for content negotiation.
	Accept string
	// Header carries any further request headers a case needs.
	Header http.Header

	// Check runs assertions the schema cannot express: ordering, pagination
	// arithmetic, cross-field identity. Returning an error fails the case with
	// that message.
	Check func(body []byte) error

	// Category groups cases in the report: conformance, negative, pagination,
	// filtering, security, and so on.
	Category string

	// Optional marks a case whose failure is reported but does not make the
	// provider non-conformant: an operation the specification does not
	// require, or a document a publisher is free not to hold.
	Optional bool

	// AnyContentType turns off the application/json assertion.
	//
	// Every response the TEA specifications declare is JSON, so the default is
	// to require it. An artifact download is the exception: the bytes behind an
	// artifact are whatever the publisher stored, which may be a lockfile or a
	// shell script. Demanding JSON of those would report a correctly-served
	// go.mod as a conformance failure.
	AnyContentType bool
}

// Result is the outcome of one case.
type Result struct {
	Area        config.Area `json:"area"`
	Seq         int         `json:"seq"`
	OperationID string      `json:"operationId"`
	Case        string      `json:"case"`
	Category    string      `json:"category"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`

	WantStatus int `json:"wantStatus"`
	GotStatus  int `json:"gotStatus"`

	SchemaPointer string `json:"schemaPointer,omitempty"`
	SchemaChecked bool   `json:"schemaChecked"`
	SchemaValid   bool   `json:"schemaValid"`

	Errors    []string `json:"errors,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	LatencyMs float64  `json:"latencyMs"`
	Bytes     int      `json:"bytes"`
	Pass      bool     `json:"pass"`
	Optional  bool     `json:"optional,omitempty"`

	// Recording is the filename stem this case's evidence was stored under, so
	// a report can point a reader at the bytes behind a verdict.
	Recording string `json:"recording,omitempty"`

	// Body is the response, kept in memory for whatever comes next in the same
	// area. It is not serialised: the bytes live in the recording.
	Body []byte `json:"-"`
}

// Failed reports whether this result should count against conformance.
func (r Result) Failed() bool { return !r.Pass && !r.Optional }

// Run executes every case and returns results in the order the cases were
// given.
//
// Requests are issued concurrently because a serial run measures queuing rather
// than the server, and because this suite is also a load check. Concurrency is
// bounded so the numbers describe a realistic client rather than a thundering
// herd. Recording names come from Case.Seq, so concurrency never perturbs the
// evidence on disk.
func Run(ctx context.Context, c *Client, api *spec.API, cases []Case, concurrency int) []Result {
	if concurrency < 1 {
		concurrency = 8
	}
	results := make([]Result, len(cases))

	// Compile every schema up front, single-threaded. The compiler caches into
	// shared state, and doing it here keeps compilation out of the measured
	// latency of the first request to use each schema.
	schemas := map[string]any{}
	for _, tc := range cases {
		if tc.SchemaPtr == "" || api == nil {
			continue
		}
		if _, seen := schemas[tc.SchemaPtr]; seen {
			continue
		}
		sch, err := api.SchemaFor(tc.SchemaPtr)
		if err != nil {
			schemas[tc.SchemaPtr] = err
			continue
		}
		schemas[tc.SchemaPtr] = sch
	}

	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i := range cases {
		g.Go(func() error {
			mu.Lock()
			entry := schemas[cases[i].SchemaPtr]
			mu.Unlock()
			results[i] = RunCase(gctx, c, cases[i], entry)
			return nil
		})
	}
	_ = g.Wait()
	return results
}

// RunSerial executes cases strictly in order, for flows where one case's
// outcome decides the next. The publisher round-trip is the reason it exists:
// an object has to exist before it can be read, revised and deleted.
func RunSerial(ctx context.Context, c *Client, api *spec.API, cases []Case) []Result {
	results := make([]Result, 0, len(cases))
	for _, tc := range cases {
		var entry any
		if tc.SchemaPtr != "" && api != nil {
			if sch, err := api.SchemaFor(tc.SchemaPtr); err != nil {
				entry = err
			} else {
				entry = sch
			}
		}
		results = append(results, RunCase(ctx, c, tc, entry))
	}
	return results
}

// RunCase issues one case.
func RunCase(ctx context.Context, c *Client, tc Case, schemaEntry any) Result {
	res := Result{
		Area:          tc.Area,
		Seq:           tc.Seq,
		OperationID:   tc.OperationID,
		Case:          tc.Name,
		Category:      tc.Category,
		Method:        tc.Method,
		WantStatus:    tc.WantStatus,
		SchemaPointer: tc.SchemaPtr,
		Optional:      tc.Optional,
	}
	if res.Method == "" {
		res.Method = http.MethodGet
	}
	res.Recording = httpx.RecordKey(tc.Seq, res.Method, tc.Name)

	target := tc.AbsoluteURL
	if target == "" {
		target = c.BaseURL + tc.Path
	}
	if len(tc.Query) > 0 {
		target += "?" + tc.Query.Encode()
	}
	res.URL = target

	header := http.Header{}
	for k, vs := range tc.Header {
		for _, v := range vs {
			header.Add(k, v)
		}
	}
	if tc.Accept != "" {
		header.Set("Accept", tc.Accept)
	} else if header.Get("Accept") == "" {
		header.Set("Accept", "application/json")
	}
	if len(tc.Body) > 0 {
		ct := tc.ContentType
		if ct == "" {
			ct = "application/json"
		}
		header.Set("Content-Type", ct)
	}
	switch tc.Auth {
	case NoAuth:
		// Deliberately unauthenticated.
	case "":
		if c.Auth != "" {
			header.Set("Authorization", c.Auth)
		}
	default:
		header.Set("Authorization", tc.Auth)
	}

	resp, err := c.Rec.Do(ctx, httpx.Request{
		Area:   string(tc.Area),
		Seq:    tc.Seq,
		Name:   tc.Name,
		Method: res.Method,
		URL:    target,
		Header: header,
		Body:   tc.Body,
	})
	if err != nil {
		// A recorder error means the run itself is broken: a duplicate
		// recording name, an unwritable directory, a replay with no recording.
		// That is not a finding about the provider, so it is surfaced as one
		// loud failure rather than folded into the conformance tally.
		res.Errors = append(res.Errors, "harness: "+err.Error())
		return res
	}

	res.LatencyMs = resp.LatencyMs
	res.Bytes = resp.Bytes
	res.GotStatus = resp.Status
	res.Body = resp.Body

	if resp.TransportError != "" {
		res.Errors = append(res.Errors, resp.TransportError)
		return res
	}

	// A dry run asks one question only: does this endpoint answer at all.
	if c.Rec.Mode == httpx.ModeDryRun {
		res.Pass = resp.Status > 0
		if !res.Pass {
			res.Errors = append(res.Errors, "no response")
		}
		return res
	}

	statusOK := res.GotStatus == res.WantStatus
	for _, alt := range tc.AcceptStatus {
		if res.GotStatus == alt {
			statusOK = true
		}
	}
	if !statusOK {
		res.Errors = append(res.Errors, fmt.Sprintf("expected HTTP %d, got %d: %s",
			res.WantStatus, res.GotStatus, snippet(resp.Body)))
	}

	// Content-Type is part of the contract: every declared response in the
	// specification is application/json, and a client selects its parser from
	// this header. Artifact downloads opt out; see Case.AnyContentType.
	if ct := resp.Header.Get("Content-Type"); !tc.AnyContentType && ct != "" && !isJSONContentType(ct) {
		res.Errors = append(res.Errors, "Content-Type is not application/json: "+ct)
	}

	if tc.Schema != nil {
		schemaEntry = tc.Schema
	}
	// Validation applies only to the response the case was written for: a case
	// that accepted an alternative status has, by definition, no schema for it.
	if !isNilSchema(schemaEntry) && res.GotStatus == res.WantStatus {
		res.SchemaChecked = true
		if schemaErr, isErr := schemaEntry.(error); isErr {
			res.Errors = append(res.Errors, "schema unavailable: "+schemaErr.Error())
		} else if errs := ValidateAgainst(schemaEntry, resp.Body); len(errs) > 0 {
			res.Errors = append(res.Errors, errs...)
		} else {
			res.SchemaValid = true
		}
	}

	if tc.Check != nil && res.GotStatus == res.WantStatus {
		if err := tc.Check(resp.Body); err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
	}

	res.Pass = len(res.Errors) == 0
	return res
}

// isNilSchema reports whether a schema entry is absent.
//
// A plain `== nil` is not enough. A compiler that returns (*jsonschema.Schema)(nil)
// for a document this run did not fetch produces a typed nil, and a typed nil
// stored in an `any` compares as non-nil. The suite then called Validate on it
// and panicked, which is a worse failure than the missing schema it was trying
// to describe: it takes down a run that had already gathered real findings.
func isNilSchema(entry any) bool {
	if entry == nil {
		return true
	}
	v := reflect.ValueOf(entry)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return v.IsNil()
	default:
		return false
	}
}

// ValidateAgainst decodes a body the way a JSON Schema validator requires and
// reports every violation it finds, because a conformance report is only
// actionable if it lists everything that is wrong.
func ValidateAgainst(schemaEntry any, body []byte) []string {
	type validator interface{ Validate(any) error }
	v, ok := schemaEntry.(validator)
	if !ok {
		return []string{"schema is not usable for validation"}
	}
	var instance any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&instance); err != nil {
		return []string{"response is not valid JSON: " + err.Error()}
	}
	if err := v.Validate(instance); err != nil {
		return flattenValidationError(err)
	}
	return nil
}

// flattenValidationError turns the validator's nested causes into one line per
// concrete violation.
func flattenValidationError(err error) []string {
	lines := strings.Split(strings.TrimSpace(err.Error()), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, "schema: "+l)
	}
	if len(out) == 0 {
		out = append(out, "schema: validation failed")
	}
	return out
}

func isJSONContentType(ct string) bool {
	base := strings.TrimSpace(strings.Split(ct, ";")[0])
	if base == "application/json" {
		return true
	}
	// The CycloneDX media type and any other +json structured syntax suffix
	// are JSON as far as a client's parser is concerned.
	return strings.HasSuffix(base, "+json")
}

func snippet(b []byte) string {
	const max = 220
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// --- Latency statistics ---

// Latency is the distribution of response times for a set of measurements.
type Latency struct {
	Count int     `json:"count"`
	MinMs float64 `json:"minMs"`
	P50Ms float64 `json:"p50Ms"`
	P95Ms float64 `json:"p95Ms"`
	P99Ms float64 `json:"p99Ms"`
	MaxMs float64 `json:"maxMs"`
	AvgMs float64 `json:"avgMs"`
	// StdDevMs is reported because the question "is this fast" is not
	// answerable without "is this consistent": two endpoints with the same
	// median feel completely different if one of them scatters.
	StdDevMs float64 `json:"stdDevMs"`
}

// Summarise computes the latency distribution over results.
func Summarise(results []Result) Latency {
	xs := make([]float64, 0, len(results))
	for _, r := range results {
		xs = append(xs, r.LatencyMs)
	}
	return SummariseSamples(xs)
}

// SummariseSamples computes the distribution over raw millisecond samples.
func SummariseSamples(xs []float64) Latency {
	if len(xs) == 0 {
		return Latency{}
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	total := 0.0
	for _, x := range sorted {
		total += x
	}
	mean := total / float64(len(sorted))
	variance := 0.0
	for _, x := range sorted {
		d := x - mean
		variance += d * d
	}
	variance /= float64(len(sorted))
	return Latency{
		Count:    len(sorted),
		MinMs:    Round2(sorted[0]),
		P50Ms:    percentile(sorted, 0.50),
		P95Ms:    percentile(sorted, 0.95),
		P99Ms:    percentile(sorted, 0.99),
		MaxMs:    Round2(sorted[len(sorted)-1]),
		AvgMs:    Round2(mean),
		StdDevMs: Round2(math.Sqrt(variance)),
	}
}

// percentile uses nearest-rank on the sorted sample: at these sample sizes,
// interpolation would invent precision the measurement does not have.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted)-1) + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return Round2(sorted[idx])
}

// Round2 rounds to two decimal places, which is the precision a millisecond
// measurement over a network actually carries.
func Round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
