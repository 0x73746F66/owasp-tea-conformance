// Package spec fetches the specifications a run validates against and turns
// them into something the runner can compare a response with.
//
// Documents are fetched from their authoritative repository on every run and
// the exact bytes are written into that run's own directory. Nothing is
// vendored into this repository: a conformance claim that quotes a
// specification should be checkable against the specification as published, and
// a vendored copy is a claim about a copy.
package spec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
)

// Kind names one of the documents a run needs.
type Kind string

const (
	KindConsumer  Kind = "consumer"
	KindPublisher Kind = "publisher"
	KindWellKnown Kind = "wellKnown"
	KindInsights  Kind = "insights"
	KindSPDX      Kind = "spdx"
)

// Filenames the documents are stored under inside a run directory. They are
// fixed so that replaying a run finds them without consulting anything.
var filenames = map[Kind]string{
	KindConsumer:  "consumer-openapi.yaml",
	KindPublisher: "publisher-openapi.json",
	KindWellKnown: "tea-well-known.schema.json",
	KindInsights:  "insights-openapi.json",
	KindSPDX:      "spdx-licenses.json",
}

// Document is one fetched specification, with the provenance a reader needs to
// check it independently.
type Document struct {
	Kind   Kind   `json:"kind"`
	Repo   string `json:"repo,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Path   string `json:"path,omitempty"`
	URL    string `json:"url"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	// Commit is the resolved commit the ref pointed at, when it could be
	// determined without credentials. A branch moves; this is what makes a
	// report reproducible against the same upstream state.
	Commit string `json:"commit,omitempty"`
	// Note carries the configuration's disclosure, such as a document that is
	// not yet upstream.
	Note string `json:"note,omitempty"`
	// FetchedAt is when the bytes were retrieved, or empty on a replayed run.
	FetchedAt string `json:"fetchedAt,omitempty"`
	// Replayed marks a document read from a previous run's directory.
	Replayed bool `json:"replayed,omitempty"`

	raw []byte
}

// Raw is the document's bytes as validated.
func (d Document) Raw() []byte { return d.raw }

// Bundle is every document a run uses, in a fixed order.
type Bundle struct {
	Documents []Document `json:"documents"`
	byKind    map[Kind]Document
}

// Get returns one document.
func (b Bundle) Get(kind Kind) (Document, bool) {
	d, ok := b.byKind[kind]
	return d, ok
}

// Fetcher retrieves specifications.
type Fetcher struct {
	HTTP *http.Client
}

// NewFetcher builds a fetcher with a client suited to reading a few files.
func NewFetcher() *Fetcher {
	return &Fetcher{HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Fetch retrieves every configured document and writes it into dir/spec.
//
// Documents that fail to fetch are returned as an error: a run cannot judge
// conformance against a specification it does not have, and guessing at the
// missing half would be worse than stopping.
func (f *Fetcher) Fetch(ctx context.Context, specs config.Specs, dir string, want []Kind) (Bundle, error) {
	sources := map[Kind]config.SpecSource{
		KindConsumer:  specs.Consumer,
		KindPublisher: specs.Publisher,
		KindWellKnown: specs.WellKnown,
		KindInsights:  specs.Insights,
		KindSPDX:      specs.SPDX,
	}

	out := Bundle{byKind: map[Kind]Document{}}

	// An empty directory means "fetch but do not persist", which is what a dry
	// run wants: it still needs the operation table to know which endpoints
	// exist, and it stores nothing.
	specDir := ""
	if dir != "" {
		specDir = filepath.Join(dir, "spec")
		if err := os.MkdirAll(specDir, 0o755); err != nil {
			return out, fmt.Errorf("create spec directory: %w", err)
		}
	}

	for _, kind := range want {
		src, ok := sources[kind]
		if !ok {
			return out, fmt.Errorf("no source configured for the %s specification", kind)
		}
		doc, err := f.one(ctx, kind, src)
		if err != nil {
			return out, err
		}
		if specDir != "" {
			if err := os.WriteFile(filepath.Join(specDir, doc.File), doc.raw, 0o644); err != nil {
				return out, fmt.Errorf("write %s specification: %w", kind, err)
			}
		}
		out.Documents = append(out.Documents, doc)
		out.byKind = doc.register(out.byKind)
	}

	if specDir == "" {
		return out, nil
	}
	if err := writeChecksums(specDir, out.Documents); err != nil {
		return out, err
	}
	return out, nil
}

func (d Document) register(m map[Kind]Document) map[Kind]Document {
	m[d.Kind] = d
	return m
}

func (f *Fetcher) one(ctx context.Context, kind Kind, src config.SpecSource) (Document, error) {
	doc := Document{
		Kind: kind,
		Repo: src.Repo,
		Ref:  src.Ref,
		Path: src.Path,
		Note: src.Note,
		File: filenames[kind],
		URL:  src.URL,
	}
	if doc.URL == "" {
		if src.Repo == "" || src.Path == "" {
			return doc, fmt.Errorf("%s specification: set either url, or repo and path", kind)
		}
		ref := src.Ref
		if ref == "" {
			ref = "main"
		}
		doc.URL = "https://raw.githubusercontent.com/" + src.Repo + "/" + ref + "/" + src.Path
	}

	body, err := f.get(ctx, doc.URL)
	if err != nil {
		return doc, fmt.Errorf("fetch the %s specification from %s: %w", kind, doc.URL, err)
	}
	sum := sha256.Sum256(body)
	doc.raw = body
	doc.SHA256 = hex.EncodeToString(sum[:])
	doc.Bytes = len(body)
	doc.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	if src.Repo != "" {
		doc.Commit = f.resolveCommit(ctx, src.Repo, src.Ref)
	}
	return doc, nil
}

func (f *Fetcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "*/*")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// resolveCommit turns a branch name into the commit it pointed at, so a report
// records the upstream state and not a moving name.
//
// Best effort: the call is unauthenticated and rate-limited, and a run whose
// specifications fetched cleanly should not fail because a provenance nicety
// did not. A GITHUB_TOKEN in the environment is used when present.
func (f *Fetcher) resolveCommit(ctx context.Context, repo, ref string) string {
	if ref == "" {
		ref = "main"
	}
	url := "https://api.github.com/repos/" + repo + "/commits/" + ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var payload struct {
		SHA string `json:"sha"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return ""
	}
	return payload.SHA
}

// FromDir reads the specifications a previous run recorded, for replay.
func FromDir(dir string, want []Kind) (Bundle, error) {
	out := Bundle{byKind: map[Kind]Document{}}
	specDir := filepath.Join(dir, "spec")

	// The manifest carries the provenance; the files carry the bytes. Both are
	// needed, and a run directory missing either cannot be replayed honestly.
	manifest := map[Kind]Document{}
	if raw, err := os.ReadFile(filepath.Join(specDir, "manifest.json")); err == nil {
		var docs []Document
		if err := json.Unmarshal(raw, &docs); err == nil {
			for _, d := range docs {
				manifest[d.Kind] = d
			}
		}
	}

	for _, kind := range want {
		name, ok := filenames[kind]
		if !ok {
			return out, fmt.Errorf("unknown specification kind %q", kind)
		}
		body, err := os.ReadFile(filepath.Join(specDir, name))
		if err != nil {
			return out, fmt.Errorf("replay: the recorded run has no %s specification at %s",
				kind, filepath.Join(specDir, name))
		}
		doc := manifest[kind]
		doc.Kind = kind
		doc.File = name
		doc.raw = body
		doc.Bytes = len(body)
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if doc.SHA256 != "" && doc.SHA256 != got {
			return out, fmt.Errorf("replay: %s has been modified since it was recorded "+
				"(recorded %s, found %s)", name, doc.SHA256[:12], got[:12])
		}
		doc.SHA256 = got
		doc.Replayed = true
		out.Documents = append(out.Documents, doc)
		out.byKind = doc.register(out.byKind)
	}
	return out, nil
}

// WriteManifest records provenance next to the bytes.
func (b Bundle) WriteManifest(dir string) error {
	encoded, err := json.MarshalIndent(b.Documents, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "spec", "manifest.json"), append(encoded, '\n'), 0o644)
}

func writeChecksums(specDir string, docs []Document) error {
	lines := make([]string, 0, len(docs))
	for _, d := range docs {
		lines = append(lines, d.SHA256+"  "+d.File)
	}
	sort.Strings(lines)
	body := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(filepath.Join(specDir, "SHA256SUMS"), []byte(body), 0o644)
}

// KindsFor maps the areas a run will execute to the documents it needs, so a
// run that excludes the publisher area does not fail because an upstream
// publisher document moved.
func KindsFor(areas []config.Area) []Kind {
	need := map[Kind]bool{}
	for _, a := range areas {
		switch a {
		case config.AreaDiscovery:
			need[KindWellKnown] = true
			need[KindConsumer] = true
		case config.AreaConsumer, config.AreaPurl, config.AreaPerformance,
			config.AreaCycloneDX, config.AreaProvenance:
			need[KindConsumer] = true
		case config.AreaSPDX:
			need[KindConsumer] = true
			need[KindSPDX] = true
		case config.AreaInsights, config.AreaCEL:
			need[KindConsumer] = true
			need[KindInsights] = true
		case config.AreaProvider:
			need[KindConsumer] = true
			need[KindPublisher] = true
		}
	}
	// A fixed order, so the manifest and the report read the same every run.
	var out []Kind
	for _, k := range []Kind{KindConsumer, KindPublisher, KindWellKnown, KindInsights, KindSPDX} {
		if need[k] {
			out = append(out, k)
		}
	}
	return out
}

// FileName is the name a document is stored under in a run directory.
func FileName(kind Kind) string { return filenames[kind] }

// BaseName strips a URL down to its file name, for a report cell.
func BaseName(url string) string { return path.Base(url) }
