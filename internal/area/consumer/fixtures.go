package consumer

// Fixture discovery.
//
// Cases are built from live identifiers taken from the server under test rather
// than from constants. A suite seeded with hard-coded UUIDs only ever proves
// that a fixture exists; seeding by walking the object graph the way a consumer
// walks it proves the graph is navigable, which is the thing a TEA client
// actually depends on.

import (
	"context"
	"fmt"
	"net/url"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

// Fixtures are the live identifiers the case catalogue is built around.
type Fixtures struct {
	ProductUUID          string `json:"productUuid"`
	ProductName          string `json:"productName"`
	ProductPURL          string `json:"productPurl"`
	ProductReleaseUUID   string `json:"productReleaseUuid"`
	ComponentUUID        string `json:"componentUuid"`
	ComponentReleaseUUID string `json:"componentReleaseUuid"`
	ArtifactUUID         string `json:"artifactUuid,omitempty"`
	ReleaseVersion       string `json:"releaseVersion"`

	// Authority is the TEI domain this provider issues identifiers under. It
	// comes from discovery, never from a constant: a TEI's authority is the
	// domain a consumer started from.
	Authority string `json:"authority"`

	// RequiresAuth turns on the cases that assert an unauthenticated request is
	// refused. It is set when the run holds a credential for this provider: an
	// open catalogue answering 200 without one is correct, not a failure, and
	// asserting otherwise would fail every public TEA server on the internet.
	RequiresAuth bool `json:"requiresAuth"`

	// Counts observed while seeding, reported alongside the results so a reader
	// can tell a green run over real data from a green run over none.
	ProductCount int  `json:"productCount"`
	ReleaseCount int  `json:"releaseCount"`
	ArtifactSeen bool `json:"artifactSeen"`
}

// TEI renders a uuid-typed TEI for this provider.
func (f Fixtures) TEI(uuid string) string {
	return "urn:tei:uuid:" + f.Authority + ":" + uuid
}

// PurlTEI renders a purl-typed TEI for this provider.
func (f Fixtures) PurlTEI(purl string) string {
	return "urn:tei:purl:" + f.Authority + ":" + purl
}

// seedArea is where fixture-discovery requests are recorded. Keeping them out
// of the areas they feed means an area's recordings are exactly its cases, and
// replaying rebuilds the fixtures before any case is built.
const seedArea = "seed"

// Seeder walks the object graph, numbering its requests as it goes.
//
// The walk is strictly sequential, so the counter is deterministic: replaying
// the same recordings issues the same requests in the same order and arrives at
// the same fixtures, which is what makes the case list — and therefore every
// recording name after it — reproducible.
type Seeder struct {
	client *runner.Client
	seq    int
}

// NewSeeder builds a seeder against a client.
func NewSeeder(c *runner.Client) *Seeder { return &Seeder{client: c} }

// Seed discovers the identifiers the catalogue needs.
func (s *Seeder) Seed(ctx context.Context, authority string) (Fixtures, error) {
	f := Fixtures{Authority: authority}

	products, err := s.get(ctx, "list products", "/products", url.Values{"pageSize": {"5"}})
	if err != nil {
		return f, fmt.Errorf("seed /products: %w", err)
	}
	items, _ := products["results"].([]any)
	f.ProductCount = len(items)
	if len(items) == 0 {
		return f, fmt.Errorf("the server reports no TEA products for this credential, " +
			"so there is nothing to test conformance against")
	}

	// Prefer a product that actually has releases, so the release-dependent
	// cases exercise data rather than empty lists.
	for _, it := range items {
		p, _ := it.(map[string]any)
		uuid, _ := p["uuid"].(string)
		if uuid == "" {
			continue
		}
		rels, err := s.get(ctx, "releases of a candidate product",
			"/product/"+uuid+"/releases", url.Values{"pageSize": {"5"}})
		if err != nil {
			continue
		}
		relItems, _ := rels["results"].([]any)
		if len(relItems) == 0 {
			continue
		}
		f.ProductUUID = uuid
		f.ProductName, _ = p["name"].(string)
		f.ProductPURL = FirstIdentifier(p, "PURL")
		f.ReleaseCount = len(relItems)

		rel, _ := relItems[0].(map[string]any)
		f.ProductReleaseUUID, _ = rel["uuid"].(string)
		f.ReleaseVersion, _ = rel["version"].(string)
		if comps, ok := rel["components"].([]any); ok && len(comps) > 0 {
			cr, _ := comps[0].(map[string]any)
			f.ComponentUUID, _ = cr["uuid"].(string)
			f.ComponentReleaseUUID, _ = cr["release"].(string)
		}
		break
	}
	if f.ProductUUID == "" {
		return f, fmt.Errorf("no product has at least one release")
	}

	// Fall back to the component list when the product release did not pin one.
	if f.ComponentUUID == "" {
		if comps, err := s.get(ctx, "list components", "/components", url.Values{"pageSize": {"1"}}); err == nil {
			if items, _ := comps["results"].([]any); len(items) > 0 {
				cp, _ := items[0].(map[string]any)
				f.ComponentUUID, _ = cp["uuid"].(string)
			}
		}
	}
	if f.ComponentReleaseUUID == "" && f.ComponentUUID == "" {
		return f, fmt.Errorf("no component is reachable from product %s", f.ProductUUID)
	}
	if f.ComponentReleaseUUID == "" {
		if rels, err := s.get(ctx, "releases of a component",
			"/component/"+f.ComponentUUID+"/releases", url.Values{"pageSize": {"1"}}); err == nil {
			if items, _ := rels["results"].([]any); len(items) > 0 {
				cr, _ := items[0].(map[string]any)
				f.ComponentReleaseUUID, _ = cr["uuid"].(string)
			}
		}
	}
	if f.ComponentReleaseUUID == "" {
		return f, fmt.Errorf("no component release is reachable from product %s", f.ProductUUID)
	}

	// An artifact, taken from the release's latest collection.
	if coll, err := s.get(ctx, "latest collection of the seed component release",
		"/componentRelease/"+f.ComponentReleaseUUID+"/collection/latest", nil); err == nil {
		if arts, _ := coll["artifacts"].([]any); len(arts) > 0 {
			a, _ := arts[0].(map[string]any)
			f.ArtifactUUID, _ = a["uuid"].(string)
			f.ArtifactSeen = f.ArtifactUUID != ""
		}
	}
	return f, nil
}

// get issues one seed request and decodes it, advancing the sequence.
func (s *Seeder) get(ctx context.Context, name, path string, query url.Values) (map[string]any, error) {
	s.seq++
	body, _, err := runner.GetJSON(ctx, s.client, config.Area(seedArea), s.seq, name, path, query)
	return body, err
}

// Get exposes the seeder's recorded fetch to the areas that need to walk the
// graph beyond what the fixtures carry — the CycloneDX and provenance areas
// both do, and routing them through here keeps every request in the run's
// evidence.
func (s *Seeder) Get(ctx context.Context, name, path string, query url.Values) (map[string]any, error) {
	return s.get(ctx, name, path, query)
}

// FirstIdentifier returns the first identifier of a given type on a TEA object.
func FirstIdentifier(obj map[string]any, idType string) string {
	ids, _ := obj["identifiers"].([]any)
	for _, it := range ids {
		id, _ := it.(map[string]any)
		if t, _ := id["idType"].(string); t == idType {
			v, _ := id["idValue"].(string)
			return v
		}
	}
	return ""
}
