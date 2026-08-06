// Package performance measures how a provider behaves under two conditions a
// consumer actually meets, and reports them separately because they are
// separate facts.
//
// **Cold** is first contact: a fresh connection, nothing warmed, whatever index
// or cache the server builds on demand not yet built. A consumer pays this once
// per session, and it is the number that decides whether an interactive tool
// feels usable.
//
// **Cached** is steady state: the same request shape replayed over a warm
// connection pool. This is what a consumer walking an object graph experiences
// for every hop after the first.
//
// Reporting one number for both would misrepresent both. A server whose cold
// start is two seconds and whose warm p50 is ten milliseconds is a good server
// with an expensive first request; averaging those produces a figure that
// describes nothing that ever happened.
//
// Correctness is asserted once per shape, through the recorder, before any
// timing begins — and the responses collected under load are validated too,
// after the timer stops. Correctness under contention is a distinct claim from
// correctness at rest, and an endpoint that starts truncating results once its
// caches are contended would pass every other area and fail here.
package performance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/0x73746F66/owasp-tea-conformance/internal/area/consumer"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/httpx"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

const seqShape = 1

// Shape is one request pattern worth measuring.
type Shape struct {
	Name        string
	OperationID string
	Path        string
	Query       url.Values
	SchemaPtr   string
}

// Measurement is what one shape cost.
type Measurement struct {
	Name        string `json:"name"`
	OperationID string `json:"operationId"`
	URL         string `json:"url"`

	Cold   runner.Latency `json:"cold"`
	Cached runner.Latency `json:"cached"`

	// SpeedUp is how many times faster the cached median is than the cold one.
	// It is the single number that says whether this endpoint has a warm path
	// at all.
	SpeedUp float64 `json:"cachedSpeedUp"`
	// Variance is the cached standard deviation as a fraction of the cached
	// median. A low median with a high spread is a worse experience than a
	// slightly higher median that is consistent, and only this number says so.
	Variance float64 `json:"cachedVariance"`

	Requests          int     `json:"cachedRequests"`
	Failures          int     `json:"failuresUnderLoad"`
	SchemaViolations  int     `json:"schemaViolationsUnderLoad"`
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	ResponseBytes     int     `json:"responseBytes"`

	Errors []string `json:"errors,omitempty"`
}

// Findings is the performance section of a report.
type Findings struct {
	ColdSamples  int           `json:"coldSamples"`
	Iterations   int           `json:"iterationsPerShape"`
	Concurrency  int           `json:"concurrency"`
	Measurements []Measurement `json:"measurements"`
	// NotMeasured is set when the run could not take timings — a replayed run
	// in particular, where every latency on record belongs to the run that
	// produced the directory.
	NotMeasured string `json:"notMeasured,omitempty"`
}

// Shapes picks the request patterns worth measuring: the consumer's entry
// point, the list endpoints that page over the largest collections, the
// single-object reads a client bookmarks, the collection read that touches
// storage, and TEI resolution.
func Shapes(api *spec.API, f consumer.Fixtures) []Shape {
	ok := func(id string) string { return api.OK200(id) }
	shapes := []Shape{
		{Name: "list products", OperationID: "queryTeaProducts",
			Path: "/products", SchemaPtr: ok("queryTeaProducts")},
		{Name: "list product releases (full page)", OperationID: "queryTeaProductReleases",
			Path: "/productReleases", Query: url.Values{"pageSize": {"100"}},
			SchemaPtr: ok("queryTeaProductReleases")},
		{Name: "list component releases (full page, descending)", OperationID: "queryTeaComponentReleases",
			Path: "/componentReleases", Query: url.Values{"pageSize": {"100"}, "sortOrder": {"desc"}},
			SchemaPtr: ok("queryTeaComponentReleases")},
		{Name: "read one product", OperationID: "getTeaProductByUuid",
			Path: "/product/" + f.ProductUUID, SchemaPtr: ok("getTeaProductByUuid")},
		{Name: "read one product release", OperationID: "getTeaProductReleaseByUuid",
			Path: "/productRelease/" + f.ProductReleaseUUID, SchemaPtr: ok("getTeaProductReleaseByUuid")},
		{Name: "releases of one product", OperationID: "getReleasesByProductId",
			Path: "/product/" + f.ProductUUID + "/releases", Query: url.Values{"pageSize": {"100"}},
			SchemaPtr: ok("getReleasesByProductId")},
		{Name: "component release with latest collection", OperationID: "getComponentReleaseById",
			Path: "/componentRelease/" + f.ComponentReleaseUUID, SchemaPtr: ok("getComponentReleaseById")},
		{Name: "latest collection", OperationID: "getLatestCollection",
			Path:      "/componentRelease/" + f.ComponentReleaseUUID + "/collection/latest",
			SchemaPtr: ok("getLatestCollection")},
		{Name: "resolve a TEI", OperationID: "discoveryByTei",
			Path: "/discovery", Query: url.Values{"tei": {f.TEI(f.ProductReleaseUUID)}},
			SchemaPtr: ok("discoveryByTei")},
	}
	if f.ArtifactSeen {
		shapes = append(shapes, Shape{
			Name: "artifact metadata", OperationID: "getLatestArtifact",
			Path: "/artifact/" + f.ArtifactUUID + "/latest", SchemaPtr: ok("getLatestArtifact"),
		})
	}
	return shapes
}

// Run measures every shape.
func Run(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	shapes []Shape,
	perf config.Performance,
	concurrency int,
) ([]runner.Result, Findings) {
	found := Findings{
		ColdSamples: perf.ColdSamples,
		Iterations:  perf.Iterations,
		Concurrency: concurrency,
	}
	if c.Rec.Mode == httpx.ModeDryRun {
		found.NotMeasured = "a dry run checks reachability only"
		return nil, found
	}

	// A replayed run still exercises every shape's correctness case, because
	// those were recorded like any other. What it cannot reproduce is a
	// measurement: a latency read back off disk describes the run that took it.
	measure := c.Rec.Mode == httpx.ModeLive
	if !measure {
		found.NotMeasured = "this run replayed a recorded directory, so no timings were taken; " +
			"the figures in that run's report.json are the measured ones"
	}

	var results []runner.Result

	// One recorded, validated request per shape. This is the correctness half:
	// there is no point reporting how fast an endpoint returns the wrong thing,
	// and it also warms the shape so the cached measurement is not the one that
	// populates the server's cache.
	//
	// Cold sampling happens before it, because "cold" stops being true the
	// moment anything has asked.
	for i, s := range shapes {
		m := Measurement{Name: s.Name, OperationID: s.OperationID, URL: s.Path}
		if measure {
			m.Cold = measureCold(ctx, c, s, perf.ColdSamples)
		}

		res := runner.RunCase(ctx, c, runner.Case{
			Area: config.AreaPerformance, Seq: seqShape + i,
			OperationID: s.OperationID,
			Name:        s.Name,
			Category:    "performance",
			Path:        s.Path,
			Query:       s.Query,
			WantStatus:  http.StatusOK,
			SchemaPtr:   s.SchemaPtr,
		}, schemaFor(api, s.SchemaPtr))
		results = append(results, res)
		if res.GotStatus != http.StatusOK {
			m.Errors = append(m.Errors, fmt.Sprintf(
				"the shape was not measured: it answered HTTP %d", res.GotStatus))
			found.Measurements = append(found.Measurements, m)
			continue
		}
		m.ResponseBytes = res.Bytes
		if !measure {
			found.Measurements = append(found.Measurements, m)
			continue
		}

		m.Cached = measureCached(ctx, c, api, s, perf.Iterations, concurrency, &m)
		if m.Cached.P50Ms > 0 {
			m.SpeedUp = runner.Round2(m.Cold.P50Ms / m.Cached.P50Ms)
			m.Variance = runner.Round2(m.Cached.StdDevMs / m.Cached.P50Ms)
		}
		found.Measurements = append(found.Measurements, m)

		if m.Failures > 0 {
			results = append(results, runner.Result{
				Area: config.AreaPerformance, Seq: seqShape + len(shapes) + i,
				OperationID: s.OperationID,
				Case:        s.Name + " stays correct under load",
				Category:    "performance", Method: http.MethodGet, URL: s.Path,
				Errors: append([]string{fmt.Sprintf(
					"%d of %d requests failed once the shape was under %d-way concurrency, "+
						"having passed at rest", m.Failures, m.Requests, concurrency)}, m.Errors...),
			})
		}
	}
	return results, found
}

// measureCold samples first contact on connections that have never been used.
func measureCold(ctx context.Context, c *runner.Client, s Shape, samples int) runner.Latency {
	if samples < 1 {
		samples = 1
	}
	target := c.BaseURL + s.Path
	if len(s.Query) > 0 {
		target += "?" + s.Query.Encode()
	}
	header := http.Header{"Accept": {"application/json"}}
	if c.Auth != "" {
		header.Set("Authorization", c.Auth)
	}

	xs := make([]float64, 0, samples)
	for range samples {
		resp := c.Rec.DoCold(ctx, httpx.Request{
			Area: string(config.AreaPerformance), Name: s.Name,
			Method: http.MethodGet, URL: target, Header: header,
		})
		if resp.TransportError == "" {
			xs = append(xs, resp.LatencyMs)
		}
	}
	return runner.SummariseSamples(xs)
}

// measureCached replays a warmed shape at a fixed concurrency.
func measureCached(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	s Shape,
	iterations, concurrency int,
	m *Measurement,
) runner.Latency {
	if iterations < 1 {
		return runner.Latency{}
	}
	if concurrency < 1 {
		concurrency = 8
	}
	target := c.BaseURL + s.Path
	if len(s.Query) > 0 {
		target += "?" + s.Query.Encode()
	}
	header := http.Header{"Accept": {"application/json"}}
	if c.Auth != "" {
		header.Set("Authorization", c.Auth)
	}

	var schema any
	if api != nil && s.SchemaPtr != "" {
		if compiled, err := api.SchemaFor(s.SchemaPtr); err == nil {
			schema = compiled
		}
	}

	samples := make([]float64, iterations)
	var mu sync.Mutex
	errs := map[string]int{}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	start := time.Now()
	for i := range iterations {
		g.Go(func() error {
			resp := c.Rec.DoUnrecorded(gctx, httpx.Request{
				Area: string(config.AreaPerformance), Name: s.Name,
				Method: http.MethodGet, URL: target, Header: header,
			})
			samples[i] = resp.LatencyMs

			// Validation happens after the timer has stopped for this request,
			// so it never inflates the measurement.
			var problem string
			switch {
			case resp.TransportError != "":
				problem = resp.TransportError
			case resp.Status != http.StatusOK:
				problem = fmt.Sprintf("HTTP %d under load", resp.Status)
			case schema != nil:
				if violations := runner.ValidateAgainst(schema, resp.Body); len(violations) > 0 {
					problem = violations[0]
					mu.Lock()
					m.SchemaViolations++
					mu.Unlock()
				}
			default:
				if !json.Valid(resp.Body) {
					problem = "the response under load is not valid JSON"
				}
			}
			if problem != "" {
				mu.Lock()
				m.Failures++
				errs[problem]++
				mu.Unlock()
			}
			return nil
		})
	}
	_ = g.Wait()
	elapsed := time.Since(start).Seconds()

	m.Requests = iterations
	if elapsed > 0 {
		m.RequestsPerSecond = runner.Round2(float64(iterations) / elapsed)
	}
	for e := range errs {
		m.Errors = append(m.Errors, e)
	}
	return runner.SummariseSamples(samples)
}

func schemaFor(api *spec.API, pointer string) any {
	if api == nil || pointer == "" {
		return nil
	}
	compiled, err := api.SchemaFor(pointer)
	if err != nil {
		return err
	}
	return compiled
}
