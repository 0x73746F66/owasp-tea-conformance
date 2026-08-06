package config

import (
	"fmt"
	"sort"
	"strings"
)

// Area is one testable surface of the Transparency Exchange API.
//
// They are separate because they fail separately: a server can serve the object
// graph perfectly and publish CycloneDX documents that do not validate, and a
// report that folded those together would tell an implementer to look in the
// wrong place.
type Area string

const (
	// AreaDiscovery starts where a consumer starts, at a DNS name, and follows
	// the specification's resolution chain to an API root.
	AreaDiscovery Area = "discovery"
	// AreaConsumer is the consumption OpenAPI document: the object graph, its
	// error paths and its pagination rules.
	AreaConsumer Area = "consumer"
	// AreaProvider is the publication OpenAPI document: the write operations,
	// exercised as a round-trip that ends by deleting what it created.
	AreaProvider Area = "provider"
	// AreaInsights is the Insights API, a separate specification whose
	// responses are CycloneDX documents.
	AreaInsights Area = "insights"
	// AreaCEL is the query language Insights is driven by, tested against the
	// reference CEL implementation, not only against the server.
	AreaCEL Area = "cel"
	// AreaPurl is package-URL handling: identifiers, filters and purl-typed
	// TEIs.
	AreaPurl Area = "purl"
	// AreaCycloneDX validates the BOM documents a provider actually publishes.
	AreaCycloneDX Area = "cyclonedx"
	// AreaSPDX validates the licence identifiers those documents carry.
	AreaSPDX Area = "spdx"
	// AreaProvenance covers build provenance, attestations and signatures.
	AreaProvenance Area = "provenance"
	// AreaPerformance measures cold and cached latency separately.
	AreaPerformance Area = "performance"
)

// AllAreas is the canonical order areas run and are reported in. Later areas
// depend on fixtures earlier ones discover, so this order is a dependency
// order, not a preference.
var AllAreas = []Area{
	AreaDiscovery,
	AreaConsumer,
	AreaPurl,
	AreaCycloneDX,
	AreaSPDX,
	AreaInsights,
	AreaCEL,
	AreaProvenance,
	AreaPerformance,
	AreaProvider,
}

// Description is the one-line summary the report and `--plan` print.
var Description = map[Area]string{
	AreaDiscovery:   "DNS, the .well-known/tea document, endpoint selection and TEI resolution",
	AreaConsumer:    "every operation of the consumption specification, including its error paths",
	AreaProvider:    "the publication specification, as a create-read-update-delete round-trip",
	AreaInsights:    "the Insights API and the CycloneDX documents it answers with",
	AreaCEL:         "the query language, cross-checked against the reference CEL implementation",
	AreaPurl:        "package-URL identifiers, filters and purl-typed TEIs",
	AreaCycloneDX:   "the published BOM documents, validated against the version each declares",
	AreaSPDX:        "the licence identifiers those documents carry",
	AreaProvenance:  "build provenance, attestations, signatures and checksum coverage",
	AreaPerformance: "cold and cached latency, reported separately",
}

// ParseArea resolves a name from configuration or the command line.
func ParseArea(name string) (Area, error) {
	want := Area(strings.ToLower(strings.TrimSpace(name)))
	for _, a := range AllAreas {
		if a == want {
			return a, nil
		}
	}
	return "", fmt.Errorf("unknown area %q; known areas are %s", name, JoinAreas(AllAreas, ", "))
}

// ParseAreas resolves a list, rejecting duplicates so a typo that silently
// widened a run cannot hide in a long list.
func ParseAreas(names []string) ([]Area, error) {
	seen := map[Area]bool{}
	out := make([]Area, 0, len(names))
	for _, n := range names {
		a, err := ParseArea(n)
		if err != nil {
			return nil, err
		}
		if seen[a] {
			return nil, fmt.Errorf("area %q is listed more than once", n)
		}
		seen[a] = true
		out = append(out, a)
	}
	return out, nil
}

// JoinAreas renders a list for a message or a report cell.
func JoinAreas(areas []Area, sep string) string {
	parts := make([]string, len(areas))
	for i, a := range areas {
		parts[i] = string(a)
	}
	return strings.Join(parts, sep)
}

// sortAreas puts a set back into AllAreas order, which is the order the runner
// needs regardless of how the configuration listed them.
func sortAreas(areas []Area) []Area {
	rank := map[Area]int{}
	for i, a := range AllAreas {
		rank[a] = i
	}
	out := append([]Area(nil), areas...)
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i]] < rank[out[j]] })
	return out
}
