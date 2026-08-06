// Package httpx is the single door every request in this suite goes through.
//
// It exists so that three very different modes share one call site:
//
//	live      issue the request, keep the response, write both to disk
//	dry run   issue the request, measure it, keep nothing and evaluate nothing
//	replay    issue nothing at all; serve the response recorded by an earlier run
//
// Replay is the reason the naming rules here are strict. A recorded run is only
// reproducible if the same suite, given the same configuration, asks for the
// same files in the same order. A recording's filename is derived from the
// area, a caller-supplied sequence number and a stable slug, never from wall
// clock, execution order or a hash of a response.
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Mode selects how Recorder answers a request.
type Mode int

const (
	// ModeLive issues the request and records it.
	ModeLive Mode = iota
	// ModeDryRun issues the request to prove the endpoint is addressable, then
	// discards the body. Nothing is written and nothing is validated.
	ModeDryRun
	// ModeReplay reads a previous run's recordings and never touches the
	// network.
	ModeReplay
)

func (m Mode) String() string {
	switch m {
	case ModeDryRun:
		return "dry run"
	case ModeReplay:
		return "replay"
	default:
		return "live"
	}
}

// Request is one call the suite wants to make.
type Request struct {
	// Area names the surface being tested; it is the recording's directory.
	Area string
	// Seq orders the recording within its area. It must be deterministic:
	// derived from a case's position in a deterministically-built list, or
	// from a strictly sequential flow. It is what lets the same URL appear
	// twice in one area with two different expected answers, such as a provider's
	// object read before and after its delete, for instance.
	Seq int
	// Name is a human-readable label, slugged into the filename.
	Name string

	Method string
	URL    string
	Header http.Header
	Body   []byte
}

// Response is what came back, or what a recording said came back.
type Response struct {
	Status    int         `json:"status"`
	Header    http.Header `json:"header,omitempty"`
	Body      []byte      `json:"-"`
	LatencyMs float64     `json:"latencyMs"`
	Bytes     int         `json:"bytes"`

	// TransportError is set when no HTTP response was obtained at all. It is
	// carried instead of returned as an error because a refused connection is
	// a conformance result, not a reason to abandon the run.
	TransportError string `json:"transportError,omitempty"`

	// BodyDiscarded marks a dry-run response: the body was read, but nothing
	// was written to disk and nothing was validated.
	BodyDiscarded bool `json:"bodyDiscarded,omitempty"`

	// Replayed marks a response that came from disk and not from a server.
	Replayed bool `json:"replayed,omitempty"`
}

// indexFile is the manifest of everything a run recorded, written beside the
// recordings so a replay can be reasoned about without opening each one.
const indexFile = "index.json"

// meta is the sidecar written next to every recorded body.
type meta struct {
	Area      string      `json:"area"`
	Seq       int         `json:"seq"`
	Name      string      `json:"name"`
	Method    string      `json:"method"`
	URL       string      `json:"url"`
	Request   requestMeta `json:"request"`
	Status    int         `json:"status"`
	Header    http.Header `json:"responseHeader,omitempty"`
	Bytes     int         `json:"bytes"`
	LatencyMs float64     `json:"latencyMs"`
	BodyFile  string      `json:"bodyFile"`

	TransportError string `json:"transportError,omitempty"`
}

type requestMeta struct {
	Header http.Header `json:"header,omitempty"`
	Body   string      `json:"body,omitempty"`
}

// Recorder issues, records and replays requests for one provider's run.
type Recorder struct {
	Mode Mode
	// Dir is the run directory. Recordings live under Dir/responses.
	Dir string
	// Retain turns off body persistence while still issuing live requests. The
	// report says when a run is therefore not reproducible.
	Retain bool
	// HTTP is the client used for warm requests.
	HTTP *http.Client
	// ColdHTTP is a client configured to open a fresh connection every time,
	// used by the performance area to measure first contact. Optional.
	ColdHTTP *http.Client

	mu sync.Mutex
	// written guards against two callers claiming the same recording name,
	// which would silently make a run unreplayable.
	written map[string]string
	// index is the manifest of everything recorded, written at the end.
	index []meta
}

// New builds a recorder for a run.
func New(mode Mode, dir string, retain bool, client *http.Client) *Recorder {
	if client == nil {
		client = DefaultClient()
	}
	return &Recorder{
		Mode:    mode,
		Dir:     dir,
		Retain:  retain,
		HTTP:    client,
		written: map[string]string{},
	}
}

// DefaultClient is a keep-alive-capable client sized for a consumer walking an
// object graph. Measuring a fresh TCP and TLS handshake on every request would
// report the network and not the server.
func DefaultClient() *http.Client {
	return &http.Client{
		// Generous, because a cold catalogue's first request legitimately
		// builds an index and that cost is reported separately rather than
		// failing the run.
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        64,
			MaxIdleConnsPerHost: 64,
			MaxConnsPerHost:     64,
		},
	}
}

// ColdClient never reuses a connection, so every request it makes pays DNS, TCP
// and TLS afresh, which is what a consumer's first contact actually costs.
func ColdClient() *http.Client {
	return &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
}

// Do issues, records or replays one request.
//
// It returns an error only for conditions that make the run itself invalid: a
// replay with no recording, a directory it cannot write. A server that refused
// the connection comes back as a Response with TransportError set, because that
// is a finding.
func (r *Recorder) Do(ctx context.Context, req Request) (Response, error) {
	key := RecordKey(req.Seq, req.Method, req.Name)
	if err := r.claim(req.Area, key); err != nil {
		return Response{}, err
	}

	if r.Mode == ModeReplay {
		return r.replay(req, key)
	}

	resp := r.issue(ctx, req, r.HTTP)

	if r.Mode == ModeDryRun {
		return resp, nil
	}
	if !r.Retain {
		return resp, nil
	}
	if err := r.persist(req, key, resp); err != nil {
		return resp, err
	}
	return resp, nil
}

// DoUnrecorded issues a request without claiming a recording name or writing
// anything.
//
// The performance area is the caller: it replays one request shape hundreds of
// times, and hundreds of byte-identical recordings would bury the run's actual
// evidence while telling a reader nothing the first one did not. The shape's
// correctness is asserted once, through Do, before the replays begin.
func (r *Recorder) DoUnrecorded(ctx context.Context, req Request) Response {
	if r.Mode == ModeReplay {
		return Response{Replayed: true, TransportError: "timing samples are not replayable"}
	}
	return r.issue(ctx, req, r.HTTP)
}

// DoCold issues a request on a connection that has never been used, for the
// performance area's first-contact measurement. Cold samples are timing
// evidence rather than response evidence, so they are never recorded: replaying
// a measured latency would be meaningless.
func (r *Recorder) DoCold(ctx context.Context, req Request) Response {
	if r.Mode == ModeReplay {
		return Response{Replayed: true, TransportError: "cold samples are not replayable"}
	}
	client := r.ColdHTTP
	if client == nil {
		client = ColdClient()
	}
	return r.issue(ctx, req, client)
}

func (r *Recorder) issue(ctx context.Context, req Request, client *http.Client) Response {
	var res Response

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		res.TransportError = "build request: " + err.Error()
		return res
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}

	start := time.Now()
	httpResp, err := client.Do(httpReq)
	if err != nil {
		res.LatencyMs = msSince(start)
		res.TransportError = "request failed: " + err.Error()
		return res
	}
	defer httpResp.Body.Close()

	payload, readErr := io.ReadAll(httpResp.Body)
	// Measured to the last byte: a consumer cannot use a response it has not
	// finished reading, so time-to-headers would flatter an endpoint that
	// streams a large collection.
	res.LatencyMs = msSince(start)
	if readErr != nil {
		res.TransportError = "read body: " + readErr.Error()
	}
	res.Body = payload
	res.Bytes = len(payload)

	// A dry run reads every body. It has to, because the endpoints it is
	// checking are addressed by identifiers that only exist in earlier
	// responses. It then keeps none of it. What "stores nothing" means is
	// that nothing reaches the disk, and what "judges nothing" means is that no
	// schema or assertion runs; neither is a claim about memory.
	if r.Mode == ModeDryRun {
		res.BodyDiscarded = true
	}

	res.Status = httpResp.StatusCode
	res.Header = httpResp.Header.Clone()
	return res
}

func (r *Recorder) claim(area, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	full := area + "/" + key
	if prev, ok := r.written[full]; ok {
		return fmt.Errorf("recording name %q is claimed twice (first by %q); "+
			"sequence numbers must be unique within an area or the run cannot be replayed", full, prev)
	}
	r.written[full] = key
	return nil
}

func (r *Recorder) persist(req Request, key string, resp Response) error {
	dir := filepath.Join(r.Dir, "responses", req.Area)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create recording directory: %w", err)
	}

	bodyName := key + bodyExtension(resp)
	if len(resp.Body) > 0 {
		// Stored verbatim. Re-indenting the JSON would read better and would
		// also make a replayed run judge different bytes from the live one:
		// the checksum verification in the CycloneDX area digests exactly what
		// is on disk, and a reformatted copy would never match.
		if err := os.WriteFile(filepath.Join(dir, bodyName), resp.Body, 0o644); err != nil {
			return fmt.Errorf("write recording body: %w", err)
		}
	}

	m := meta{
		Area:           req.Area,
		Seq:            req.Seq,
		Name:           req.Name,
		Method:         req.Method,
		URL:            req.URL,
		Request:        requestMeta{Header: redact(req.Header), Body: string(req.Body)},
		Status:         resp.Status,
		Header:         resp.Header,
		Bytes:          resp.Bytes,
		LatencyMs:      resp.LatencyMs,
		BodyFile:       bodyName,
		TransportError: resp.TransportError,
	}
	encoded, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode recording metadata: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, key+".meta.json"), append(encoded, '\n'), 0o644); err != nil {
		return fmt.Errorf("write recording metadata: %w", err)
	}

	r.mu.Lock()
	r.index = append(r.index, m)
	r.mu.Unlock()
	return nil
}

// Recorded reports whether an area left any recordings in the run directory.
//
// It answers the question a replay has to ask before running an area at all:
// whether the recorded run exercised it. A run that skipped an area recorded
// nothing under it, and replaying that as though it had would ask for a
// recording per case and find none.
func (r *Recorder) Recorded(area string) bool {
	if r == nil || r.Dir == "" || area == "" {
		return false
	}
	entries, err := os.ReadDir(filepath.Join(r.Dir, "responses", area))
	return err == nil && len(entries) > 0
}

// RecordedAuth reports whether the recorded run sent a credential.
//
// A replay must describe the run it reproduces, not the environment it is
// reproduced in. Without this a report regenerated on a machine with the
// credential variable unset said the credential was missing, directly above a
// publication round-trip that only an authenticated run can perform.
func (r *Recorder) RecordedAuth() bool {
	if r == nil || r.Dir == "" {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(r.Dir, "responses", indexFile))
	if err != nil {
		return false
	}
	var entries []meta
	if json.Unmarshal(raw, &entries) != nil {
		return false
	}
	for _, m := range entries {
		if len(m.Request.Header.Values("Authorization")) > 0 {
			return true
		}
	}
	return false
}

func (r *Recorder) replay(req Request, key string) (Response, error) {
	dir := filepath.Join(r.Dir, "responses", req.Area)
	metaPath := filepath.Join(dir, key+".meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return Response{}, fmt.Errorf("replay: no recording at %s. The recorded run did not "+
			"make this request, so this configuration cannot be reproduced from that directory", metaPath)
	}
	var m meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return Response{}, fmt.Errorf("replay: %s is not readable: %w", metaPath, err)
	}
	resp := Response{
		Status:         m.Status,
		Header:         m.Header,
		Bytes:          m.Bytes,
		LatencyMs:      m.LatencyMs,
		TransportError: m.TransportError,
		Replayed:       true,
	}
	if m.BodyFile != "" {
		body, err := os.ReadFile(filepath.Join(dir, m.BodyFile))
		if err == nil {
			resp.Body = body
		}
	}
	return resp, nil
}

// WriteIndex writes the manifest of every recording made, sorted, so a reader
// can see the whole run without walking the tree.
func (r *Recorder) WriteIndex() error {
	if r.Mode != ModeLive || !r.Retain {
		return nil
	}
	r.mu.Lock()
	entries := append([]meta(nil), r.index...)
	r.mu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Area != entries[j].Area {
			return entries[i].Area < entries[j].Area
		}
		return entries[i].Seq < entries[j].Seq
	})
	encoded, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(r.Dir, "responses", indexFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

// RecordKey renders the deterministic filename stem for a recording.
func RecordKey(seq int, method, name string) string {
	m := strings.ToUpper(method)
	if m == "" {
		m = http.MethodGet
	}
	return fmt.Sprintf("%04d-%s-%s", seq, strings.ToLower(m), Slug(name))
}

// Slug renders a case name as a stable filename component.
func Slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) && r < unicode.MaxASCII, unicode.IsDigit(r) && r < unicode.MaxASCII:
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	const max = 72
	if len(out) > max {
		out = strings.Trim(out[:max], "-")
	}
	if out == "" {
		out = "request"
	}
	return out
}

func bodyExtension(resp Response) string {
	if isJSON(resp.Header, resp.Body) {
		return ".json"
	}
	ct := ""
	if resp.Header != nil {
		ct = resp.Header.Get("Content-Type")
	}
	switch {
	case strings.HasPrefix(ct, "text/"), strings.Contains(ct, "xml"), strings.Contains(ct, "yaml"):
		return ".txt"
	case len(resp.Body) == 0:
		return ".empty"
	default:
		return ".bin"
	}
}

func isJSON(header http.Header, body []byte) bool {
	if header != nil {
		ct := header.Get("Content-Type")
		if strings.Contains(ct, "json") {
			return json.Valid(body)
		}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return false
	}
	return json.Valid(trimmed)
}

// redact strips credentials from a recorded request. A conformance run's
// evidence is meant to be publishable, and an Authorization header in a
// committed report is a leak.
func redact(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := h.Clone()
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key"} {
		if out.Get(name) != "" {
			out.Set(name, "redacted")
		}
	}
	return out
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}
