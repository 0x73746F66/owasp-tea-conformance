package discovery

import (
	"strings"
	"testing"
)

func TestCompareFollowsSemVerPrecedence(t *testing.T) {
	// From the SemVer 2.0.0 specification's own precedence example, plus the
	// case a string sort gets wrong.
	ordered := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.9.0",
		"1.10.0",
		"2.0.0",
	}
	for i := 1; i < len(ordered); i++ {
		lower, higher := ParseVersion(ordered[i-1]), ParseVersion(ordered[i])
		if Compare(lower, higher) >= 0 {
			t.Errorf("%s should have lower precedence than %s", ordered[i-1], ordered[i])
		}
		if Compare(higher, lower) <= 0 {
			t.Errorf("comparison is not symmetric for %s and %s", ordered[i-1], ordered[i])
		}
	}
	if Compare(ParseVersion("1.2.3"), ParseVersion("1.2.3+build.9")) != 0 {
		t.Error("build metadata must not affect precedence")
	}
}

func TestParseVersionFlagsWhatItCannotRead(t *testing.T) {
	for _, raw := range []string{"", "latest", "1", "1.2", "1.2.3.4", "one.two.three"} {
		if ParseVersion(raw).Valid {
			t.Errorf("ParseVersion(%q) reported a valid version", raw)
		}
	}
	// A leading v is forbidden by the discovery schema, but it must still parse
	// so the report can say "carries a v prefix" rather than "unreadable".
	if v := ParseVersion("v1.0.0"); !v.Valid || v.Major != 1 {
		t.Errorf("a v-prefixed version did not parse: %+v", v)
	}
}

func TestPickEndpointPrefersTheMatchingGenerationThenPriority(t *testing.T) {
	priority := func(f float64) *float64 { return &f }

	doc := WellKnown{
		SchemaVersion: 1,
		Endpoints: []Endpoint{
			{URL: "https://low.example", Versions: []string{"0.4.0"}, Priority: priority(0.2)},
			{URL: "https://high.example", Versions: []string{"0.4.0"}, Priority: priority(0.9)},
			{URL: "https://newer.example", Versions: []string{"1.0.0"}, Priority: priority(1.0)},
		},
	}

	endpoint, version, matched := pickEndpoint(doc, "0.4.0")
	if !matched {
		t.Error("an endpoint advertising the version under test was not treated as a match")
	}
	if version != "0.4.0" {
		t.Errorf("selected version %q", version)
	}
	// Among endpoints offering the version the client speaks, priority decides
	// and not the highest version on offer anywhere.
	if endpoint.URL != "https://high.example" {
		t.Errorf("selected %q, expected the higher-priority endpoint", endpoint.URL)
	}

	// With nothing matching, the highest advertised version is used and the
	// caller is told the generations differ: silently judging a 1.x server by a
	// 0.4 document would produce a report about nothing.
	endpoint, version, matched = pickEndpoint(WellKnown{
		Endpoints: []Endpoint{
			{URL: "https://a.example", Versions: []string{"0.9.0"}},
			{URL: "https://b.example", Versions: []string{"2.1.0"}},
		},
	}, "0.4.0")
	if matched {
		t.Error("a document offering no matching generation reported a match")
	}
	if version != "2.1.0" || endpoint.URL != "https://b.example" {
		t.Errorf("fell back to %q at %q", version, endpoint.URL)
	}
}

func TestWellKnownRulesRejectUnusableDocuments(t *testing.T) {
	priority := func(f float64) *float64 { return &f }

	cases := map[string]struct {
		doc    WellKnown
		expect string
	}{
		"a schema version the client cannot read": {
			WellKnown{SchemaVersion: 2, Endpoints: []Endpoint{
				{URL: "https://a.example", Versions: []string{"0.4.0"}}}},
			"schemaVersion",
		},
		"no endpoints at all": {
			WellKnown{SchemaVersion: 1},
			"no endpoints",
		},
		"a trailing slash a client would double up": {
			WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
				{URL: "https://a.example/tea/", Versions: []string{"0.4.0"}}}},
			"trailing slash",
		},
		"a plaintext address a consumer would follow": {
			WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
				{URL: "http://a.example", Versions: []string{"0.4.0"}}}},
			"plaintext",
		},
		"an endpoint no client can select": {
			WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
				{URL: "https://a.example"}}},
			"no versions",
		},
		"a v prefix the schema forbids": {
			WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
				{URL: "https://a.example", Versions: []string{"v0.4.0"}}}},
			"v prefix",
		},
		"a version the selection rule cannot be applied to": {
			WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
				{URL: "https://a.example", Versions: []string{"latest"}}}},
			"SemVer",
		},
		"a priority outside the defined range": {
			WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
				{URL: "https://a.example", Versions: []string{"0.4.0"}, Priority: priority(7)}}},
			"priority",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkWellKnownRules(&tc.doc)
			if err == nil {
				t.Fatal("the document was accepted but is not usable")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("the rejection does not mention %q: %v", tc.expect, err)
			}
		})
	}

	good := WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
		{URL: "https://api.example.com/tea", Versions: []string{"0.4.0", "1.0.0"},
			Priority: priority(0.5)},
	}}
	if err := checkWellKnownRules(&good); err != nil {
		t.Errorf("a usable document was rejected: %v", err)
	}
	// Loopback is the one place plaintext is legitimate, because a local
	// development server has nothing to downgrade.
	local := WellKnown{SchemaVersion: 1, Endpoints: []Endpoint{
		{URL: "http://localhost:8080/tea", Versions: []string{"0.4.0"}},
	}}
	if err := checkWellKnownRules(&local); err != nil {
		t.Errorf("a loopback development endpoint was rejected: %v", err)
	}
}
