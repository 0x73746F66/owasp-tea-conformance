// Package inventory walks a provider's published object graph once and hands
// the result to everything that needs to know what is actually in it.
//
// Four areas ask the same question in different words — what did this publisher
// actually publish? Efficacy counts it, the CycloneDX area validates the BOM
// documents in it, the SPDX area reads the licences out of those documents, and
// the provenance area looks for attestations and signatures. Walking the
// catalogue four times would quadruple the load a conformance run puts on
// somebody else's server for no extra information, so it is walked once here.
package inventory

import (
	"context"
	"net/url"
	"sort"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

// Area is where the walk's requests are recorded.
const Area = config.Area("inventory")

// Sequence bases, so concurrent phases of the walk cannot collide on a
// recording name however many products a provider publishes.
const (
	seqProductPageBase = 1
	seqPreReleaseTally = 500
	seqReleaseProbe    = 1000
	seqCollectionRead  = 5000
)

// Checksum is one digest published for an artifact format.
type Checksum struct {
	AlgType  string `json:"algType"`
	AlgValue string `json:"algValue"`
}

// Format is one downloadable rendering of an artifact.
type Format struct {
	MediaType    string     `json:"mediaType,omitempty"`
	Description  string     `json:"description,omitempty"`
	URL          string     `json:"url,omitempty"`
	SignatureURL string     `json:"signatureUrl,omitempty"`
	Checksums    []Checksum `json:"checksums,omitempty"`
}

// Artifact is one published document, as the API describes it.
type Artifact struct {
	UUID    string   `json:"uuid"`
	Name    string   `json:"name,omitempty"`
	Type    string   `json:"type,omitempty"`
	Version int      `json:"version"`
	Formats []Format `json:"formats,omitempty"`

	ReleaseUUID string `json:"releaseUuid"`
	ProductUUID string `json:"productUuid,omitempty"`
	ProductName string `json:"productName,omitempty"`
}

// Release is one sampled product release and the collection it carries.
type Release struct {
	UUID              string     `json:"uuid"`
	ProductUUID       string     `json:"productUuid"`
	ProductName       string     `json:"productName,omitempty"`
	Version           string     `json:"version,omitempty"`
	ReleaseDate       string     `json:"releaseDate,omitempty"`
	PreRelease        bool       `json:"preRelease,omitempty"`
	CollectionVersion int        `json:"collectionVersion,omitempty"`
	Artifacts         []Artifact `json:"artifacts,omitempty"`
	Error             string     `json:"error,omitempty"`
}

// Product is one entry of the published catalogue.
type Product struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	PURL string `json:"purl,omitempty"`
	TEI  string `json:"tei,omitempty"`
	CPE  string `json:"cpe,omitempty"`
}

// Stats is the efficacy tally: what the published graph actually contains.
//
// Conformance proves the responses are well-formed. It cannot prove they are
// complete — a server that published one artifact per release and dropped the
// rest would validate exactly as cleanly. These counts are how a reader tells
// a rich publication from a hollow one.
type Stats struct {
	ProductsSampled int `json:"productsSampled"`
	ReleasesSampled int `json:"releasesSampled"`

	Collections      int `json:"collections"`
	EmptyCollections int `json:"emptyCollections"`
	Artifacts        int `json:"artifacts"`

	// ArtifactTypes counts published artifacts by TEA artifact-type. A
	// publisher that only ever emits BOM is not exposing its findings, its
	// build metadata or its exploitability statements.
	ArtifactTypes map[string]int `json:"artifactTypes"`
	// ArtifactNames counts by the human label, which is where the underlying
	// document kind shows up — CBOM, AI-BOM, build manifest, analysis report.
	ArtifactNames map[string]int `json:"artifactNames"`

	WithChecksum    int            `json:"artifactsWithChecksum"`
	ChecksumAlgs    map[string]int `json:"checksumAlgorithms"`
	WithDownloadURL int            `json:"artifactsWithDownloadUrl"`
	WithMediaType   int            `json:"artifactsWithMediaType"`
	WithSignature   int            `json:"artifactsWithSignature"`

	// RevisionDepth is a histogram of how many immutable revisions each
	// artifact has. A publisher with no artifact deeper than one revision has
	// not implemented TEA's versioning, whatever its schema says.
	RevisionDepth map[int]int `json:"revisionDepth"`
	MaxRevision   int         `json:"maxRevision"`
	MultiRevision int         `json:"artifactsWithMultipleRevisions"`

	PreReleases   int `json:"preReleaseReleases"`
	FinalReleases int `json:"finalReleases"`

	MaxCollectionVersion int `json:"maxCollectionVersion"`
}

// Inventory is the whole walk.
type Inventory struct {
	Products  []Product  `json:"products"`
	Releases  []Release  `json:"releases"`
	Artifacts []Artifact `json:"artifacts"`
	Stats     Stats      `json:"stats"`
	Errors    []string   `json:"errors,omitempty"`

	// Results are the walk's own requests, so its cost and its failures appear
	// in the report rather than happening invisibly.
	Results []runner.Result `json:"-"`
}

// Build walks the catalogue.
//
// Sampling spreads across products rather than taking the first N releases of
// one: a single product's releases all look alike, and the question is whether
// the publisher is complete.
func Build(ctx context.Context, c *runner.Client, sample, concurrency int) Inventory {
	inv := Inventory{Stats: Stats{
		ArtifactTypes: map[string]int{},
		ArtifactNames: map[string]int{},
		ChecksumAlgs:  map[string]int{},
		RevisionDepth: map[int]int{},
	}}
	if sample < 1 {
		sample = 24
	}
	if concurrency < 1 {
		concurrency = 8
	}

	// Page through rather than reading one page: a catalogue larger than the
	// maximum page size would otherwise be reported as exactly that page size,
	// which reads as a limit the publisher does not have.
	token := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		body, res, err := runner.GetJSON(ctx, c, Area, seqProductPageBase+page,
			"catalogue page", "/products", q)
		inv.Results = append(inv.Results, res)
		if err != nil {
			inv.Errors = append(inv.Errors, "list products: "+err.Error())
			break
		}
		for _, item := range runner.AsSlice(body["results"]) {
			p := runner.AsMap(item)
			entry := Product{
				UUID: runner.AsString(p, "uuid"),
				Name: runner.AsString(p, "name"),
			}
			for _, idAny := range runner.AsSlice(p["identifiers"]) {
				id := runner.AsMap(idAny)
				switch runner.AsString(id, "idType") {
				case "PURL":
					entry.PURL = runner.AsString(id, "idValue")
				case "TEI":
					entry.TEI = runner.AsString(id, "idValue")
				case "CPE":
					entry.CPE = runner.AsString(id, "idValue")
				}
			}
			if entry.UUID != "" {
				inv.Products = append(inv.Products, entry)
			}
		}
		next := runner.AsString(body, "nextPageToken")
		if !runner.AsBool(body, "hasNext") || next == "" || next == token {
			break
		}
		token = next
	}
	if len(inv.Products) == 0 {
		return inv
	}
	// Sorted so the sample — and therefore every recording name derived from
	// it — does not depend on the order the server happened to page in.
	sort.Slice(inv.Products, func(i, j int) bool { return inv.Products[i].UUID < inv.Products[j].UUID })
	inv.Stats.ProductsSampled = len(inv.Products)

	// The pre-release tally is counted over a broad page rather than over the
	// collection sample: sampling oldest and newest picks release-branch heads
	// almost every time, which would report zero pre-releases on a publisher
	// that has plenty.
	if body, res, err := runner.GetJSON(ctx, c, Area, seqPreReleaseTally,
		"release flags across a broad page", "/productReleases",
		url.Values{"pageSize": {"100"}}); err == nil {
		inv.Results = append(inv.Results, res)
		for _, item := range runner.AsSlice(body["results"]) {
			if runner.AsBool(runner.AsMap(item), "preRelease") {
				inv.Stats.PreReleases++
			} else {
				inv.Stats.FinalReleases++
			}
		}
	} else {
		inv.Results = append(inv.Results, res)
	}

	// Two releases per product, oldest and newest, until the sample is full.
	type probe struct {
		product Product
		order   string
		seq     int
	}
	var probes []probe
	seq := seqReleaseProbe
	for _, order := range []string{"desc", "asc"} {
		for _, p := range inv.Products {
			if len(probes) >= sample {
				break
			}
			probes = append(probes, probe{product: p, order: order, seq: seq})
			seq++
		}
	}

	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for _, pr := range probes {
		g.Go(func() error {
			body, res, err := runner.GetJSON(gctx, c, Area, pr.seq,
				"newest or oldest release of a sampled product",
				"/product/"+pr.product.UUID+"/releases",
				url.Values{"pageSize": {"1"}, "sortOrder": {pr.order}, "sortField": {"releaseDate"}})
			mu.Lock()
			defer mu.Unlock()
			inv.Results = append(inv.Results, res)
			if err != nil {
				return nil
			}
			for _, item := range runner.AsSlice(body["results"]) {
				rel := runner.AsMap(item)
				uuid := runner.AsString(rel, "uuid")
				if uuid == "" {
					continue
				}
				inv.Releases = append(inv.Releases, Release{
					UUID:        uuid,
					ProductUUID: pr.product.UUID,
					ProductName: pr.product.Name,
					Version:     runner.AsString(rel, "version"),
					ReleaseDate: runner.AsString(rel, "releaseDate"),
					PreRelease:  runner.AsBool(rel, "preRelease"),
				})
			}
			return nil
		})
	}
	_ = g.Wait()

	// De-duplicate: a product with exactly one release yields it twice.
	sort.Slice(inv.Releases, func(i, j int) bool { return inv.Releases[i].UUID < inv.Releases[j].UUID })
	unique := inv.Releases[:0]
	for i, r := range inv.Releases {
		if i > 0 && r.UUID == inv.Releases[i-1].UUID {
			continue
		}
		unique = append(unique, r)
	}
	inv.Releases = unique
	inv.Stats.ReleasesSampled = len(inv.Releases)

	// Collections, one per sampled release. Sequence numbers come from the
	// sorted position, so concurrency does not perturb the evidence.
	g2, g2ctx := errgroup.WithContext(ctx)
	g2.SetLimit(concurrency)
	for i := range inv.Releases {
		g2.Go(func() error {
			rel := &inv.Releases[i]
			body, res, err := runner.GetJSON(g2ctx, c, Area, seqCollectionRead+i,
				"latest collection of a sampled release",
				"/productRelease/"+rel.UUID+"/collection/latest", nil)
			mu.Lock()
			inv.Results = append(inv.Results, res)
			mu.Unlock()
			if err != nil {
				rel.Error = err.Error()
				return nil
			}
			rel.CollectionVersion = runner.AsInt(body, "version")
			for _, item := range runner.AsSlice(body["artifacts"]) {
				a := runner.AsMap(item)
				artifact := Artifact{
					UUID:        runner.AsString(a, "uuid"),
					Name:        runner.AsString(a, "name"),
					Type:        runner.AsString(a, "type"),
					Version:     runner.AsInt(a, "version"),
					ReleaseUUID: rel.UUID,
					ProductUUID: rel.ProductUUID,
					ProductName: rel.ProductName,
				}
				if artifact.Version == 0 {
					artifact.Version = 1
				}
				for _, fi := range runner.AsSlice(a["formats"]) {
					f := runner.AsMap(fi)
					format := Format{
						MediaType:    runner.AsString(f, "mediaType"),
						Description:  runner.AsString(f, "description"),
						URL:          runner.AsString(f, "url"),
						SignatureURL: runner.AsString(f, "signatureUrl"),
					}
					for _, ci := range runner.AsSlice(f["checksums"]) {
						ck := runner.AsMap(ci)
						format.Checksums = append(format.Checksums, Checksum{
							AlgType:  runner.AsString(ck, "algType"),
							AlgValue: runner.AsString(ck, "algValue"),
						})
					}
					artifact.Formats = append(artifact.Formats, format)
				}
				rel.Artifacts = append(rel.Artifacts, artifact)
			}
			return nil
		})
	}
	_ = g2.Wait()

	inv.tally()
	sort.Slice(inv.Results, func(i, j int) bool { return inv.Results[i].Seq < inv.Results[j].Seq })
	return inv
}

// tally rolls the walk up into the efficacy counts.
func (inv *Inventory) tally() {
	for _, rel := range inv.Releases {
		if rel.Error != "" {
			inv.Errors = append(inv.Errors, "collection "+rel.UUID+": "+rel.Error)
			continue
		}
		inv.Stats.Collections++
		if len(rel.Artifacts) == 0 {
			inv.Stats.EmptyCollections++
		}
		if rel.CollectionVersion > inv.Stats.MaxCollectionVersion {
			inv.Stats.MaxCollectionVersion = rel.CollectionVersion
		}
		for _, a := range rel.Artifacts {
			inv.Artifacts = append(inv.Artifacts, a)
			inv.Stats.Artifacts++
			if a.Type != "" {
				inv.Stats.ArtifactTypes[a.Type]++
			}
			if a.Name != "" {
				inv.Stats.ArtifactNames[a.Name]++
			}
			inv.Stats.RevisionDepth[a.Version]++
			if a.Version > inv.Stats.MaxRevision {
				inv.Stats.MaxRevision = a.Version
			}
			if a.Version > 1 {
				inv.Stats.MultiRevision++
			}
			// Counted once per artifact rather than once per format: the
			// question is whether the publisher supplied the evidence, not how
			// many renderings it supplied it in.
			for _, f := range a.Formats {
				if f.URL != "" {
					inv.Stats.WithDownloadURL++
				}
				if f.MediaType != "" {
					inv.Stats.WithMediaType++
				}
				if f.SignatureURL != "" {
					inv.Stats.WithSignature++
				}
				if len(f.Checksums) > 0 {
					inv.Stats.WithChecksum++
				}
				for _, ck := range f.Checksums {
					if ck.AlgType != "" {
						inv.Stats.ChecksumAlgs[ck.AlgType]++
					}
				}
				break
			}
		}
	}
	sort.Slice(inv.Artifacts, func(i, j int) bool {
		if inv.Artifacts[i].UUID != inv.Artifacts[j].UUID {
			return inv.Artifacts[i].UUID < inv.Artifacts[j].UUID
		}
		return inv.Artifacts[i].Version < inv.Artifacts[j].Version
	})
}
