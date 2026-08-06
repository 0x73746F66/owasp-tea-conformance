package purl

import (
	"strings"
	"testing"
)

func TestStructuralAcceptsUsablePurls(t *testing.T) {
	for _, p := range []string{
		"pkg:github/apache/echarts",
		"pkg:npm/lodash@4.17.21",
		"pkg:maven/org.apache.logging.log4j/log4j-api@2.17.1",
		"pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
		"pkg:golang/github.com/gorilla/mux@v1.8.0",
		// An unregistered type is legitimate: the purl specification is open,
		// and a consumer can still match the coordinate.
		"pkg:vendorthing/acme/widget@1.0",
	} {
		if problem := structural(p); problem != "" {
			t.Errorf("structural(%q) reported %q", p, problem)
		}
	}
}

func TestStructuralNamesWhatIsWrong(t *testing.T) {
	cases := map[string]string{
		"github/apache/echarts":  "pkg: scheme",
		"pkg://npm/lodash":       "authority",
		"pkg:npm":                "no type and name",
		"pkg:NPM/lodash":         "lowercase",
		"":                       "pkg: scheme",
		"https://github.com/a/b": "pkg: scheme",
	}
	for input, expect := range cases {
		problem := structural(input)
		if problem == "" {
			t.Errorf("structural(%q) accepted an identifier a consumer cannot use", input)
			continue
		}
		if !strings.Contains(problem, expect) {
			t.Errorf("structural(%q) said %q, expected it to mention %q", input, problem, expect)
		}
	}
}

func TestPurlType(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:github/apache/echarts": "github",
		"pkg:npm/lodash@1.0.0":      "npm",
		"pkg:npm":                   "",
		"not-a-purl":                "",
	} {
		if got := purlType(in); got != want {
			t.Errorf("purlType(%q) is %q, expected %q", in, got, want)
		}
	}
}

func TestResultDecodingIsForgiving(t *testing.T) {
	// Every one of these is something a non-conformant server might return, and
	// none of them should panic the area that reads it.
	for _, body := range []string{
		`{"results":[{"uuid":"a"}]}`,
		`{"results":[]}`,
		`{}`,
		`[]`,
		`not json at all`,
		``,
	} {
		_ = hasResults([]byte(body))
	}
	if !hasResults([]byte(`{"results":[{"uuid":"a"}]}`)) {
		t.Error("a populated result set was read as empty")
	}
	if hasResults([]byte(`{"results":[]}`)) {
		t.Error("an empty result set was read as populated")
	}
}

func TestRequireProductNamesTheConsumerConsequence(t *testing.T) {
	check := requireProduct("wanted-uuid")
	if err := check([]byte(`{"results":[{"uuid":"wanted-uuid"}]}`)); err != nil {
		t.Errorf("a matching product was rejected: %v", err)
	}
	err := check([]byte(`{"results":[{"uuid":"something-else"}]}`))
	if err == nil {
		t.Fatal("a purl that found the wrong product was accepted")
	}
	if !strings.Contains(err.Error(), "no way in") {
		t.Errorf("the failure does not say what it costs a consumer: %v", err)
	}
}
