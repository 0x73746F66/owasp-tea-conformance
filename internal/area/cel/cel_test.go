package cel

import (
	"testing"

	insightsarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/insights"
)

// The catalogue is the yardstick this area holds a server to, so it has to be
// right. If an expression marked valid does not in fact compile — or one marked
// invalid does — every provider gets measured against a mistake, and the
// disagreement reported would be the suite's, not theirs.
func TestCatalogueMatchesTheReferenceImplementation(t *testing.T) {
	env, err := environment()
	if err != nil {
		t.Fatalf("build the reference environment: %v", err)
	}

	for _, e := range Catalogue(insightsarea.Fixtures{
		ProductID: "09e8c73b-ac45-4475-acac-33e6a7314e6d",
	}) {
		t.Run(e.Name, func(t *testing.T) {
			if e.ReferenceUndecidable {
				t.Skip("the reference implementation cannot judge this without a schema")
			}
			valid, detail := compile(env, e.Text)
			switch {
			case e.Valid && !valid:
				t.Errorf("the catalogue calls %q valid, but the reference implementation "+
					"rejects it: %s", e.Text, detail)
			case !e.Valid && valid:
				t.Errorf("the catalogue calls %q invalid, but the reference implementation "+
					"accepts it", e.Text)
			}
		})
	}
}

func TestCatalogueCoversBothOutcomes(t *testing.T) {
	var valid, invalid int
	for _, e := range Catalogue(insightsarea.Fixtures{}) {
		if e.Valid {
			valid++
		} else {
			invalid++
		}
		if e.Why == "" {
			t.Errorf("expression %q has no explanation, so a report cannot say why it is here", e.Name)
		}
	}
	// A catalogue of only-valid expressions would never catch a permissive
	// parser, and one of only-invalid expressions would never catch a broken
	// one.
	if valid == 0 || invalid == 0 {
		t.Errorf("the catalogue has %d valid and %d invalid expressions; it needs both", valid, invalid)
	}
}

func TestCompileRejectsANonPredicate(t *testing.T) {
	env, err := environment()
	if err != nil {
		t.Fatalf("build the reference environment: %v", err)
	}
	// Well-formed CEL that yields a string. A filter has to yield a boolean, and
	// this is the case a hand-written parser most often lets through.
	if valid, detail := compile(env, "'a' + 'b'"); valid {
		t.Errorf("a string-valued expression was accepted as a filter (%s)", detail)
	}
	if valid, detail := compile(env, "1 + 1"); valid {
		t.Errorf("an int-valued expression was accepted as a filter (%s)", detail)
	}
	if valid, _ := compile(env, "true"); !valid {
		t.Error("the simplest possible predicate was rejected")
	}
}
