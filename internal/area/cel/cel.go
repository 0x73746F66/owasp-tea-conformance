// Package cel tests the query language the Insights API is driven by.
//
// It is a separate area from insights because it answers a separate question.
// The insights area asks "does this server answer the specification's
// queries?"; this one asks "does this server's idea of the language match the
// language?" Those come apart in a way that matters: a server with its own
// parser can accept an expression CEL rejects, or reject one CEL accepts, and
// either way a client generated from the specification will write expressions
// that quietly do not mean what its author thought.
//
// Every expression here is therefore compiled twice — once locally against
// google/cel-go, which is the reference implementation, and once by the server.
// The finding is the disagreement, not either result on its own.
package cel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	celgo "github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/0x73746F66/owasp-tea-conformance/internal/area/consumer"
	insightsarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/insights"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

const seqBase = 1

// Expression is one query and what the specification says about it.
type Expression struct {
	Name string
	Text string
	// Valid is what the server must conclude: a well-formed expression that
	// evaluates to a boolean is accepted, anything else is a 400.
	Valid bool
	// Why explains what the case is probing, for the report.
	Why string

	// ReferenceUndecidable marks an expression the reference implementation
	// cannot judge on its own.
	//
	// The Insights specification does not publish a type for its variables, so
	// they are declared dynamically here — which is the honest thing to do and
	// costs exactly one thing: an expression like `component.name` is a string
	// to a server that knows its own schema and is type `dyn` to a compiler
	// that does not. The server must still reject it, and the cross-check must
	// not call the difference a disagreement.
	ReferenceUndecidable bool
}

// Findings is what this area observed.
type Findings struct {
	Checked       int          `json:"expressionsChecked"`
	Agreements    int          `json:"agreements"`
	Disagreements []Disagreent `json:"disagreements,omitempty"`
}

// Disagreent records one place the server and the reference implementation
// reached different conclusions.
type Disagreent struct {
	Expression string `json:"expression"`
	Reference  string `json:"referenceImplementation"`
	Server     string `json:"server"`
}

// Catalogue is the expression set.
//
// The valid half is the specification's own worked examples plus the standard
// spellings a generated client would produce. The invalid half is what a server
// with a permissive hand-written parser tends to let through.
func Catalogue(f insightsarea.Fixtures) []Expression {
	product := f.ProductID
	if product == "" {
		product = "00000000-0000-4000-8000-000000000000"
	}
	return []Expression{
		{Name: "the always-true selector", Text: "true", Valid: true,
			Why: "the cheapest possible query, and the one every client starts with"},
		{Name: "equality on a scalar field",
			Text:  fmt.Sprintf("productId == '%s'", product),
			Valid: true, Why: "the specification's own filter form"},
		{Name: "conjunction of two predicates",
			Text:  fmt.Sprintf("productId == '%s' && component.type == 'third-party'", product),
			Valid: true, Why: "the specification's worked example"},
		{Name: "a macro over a list field",
			Text:  "component.vulnerabilities.size() > 0",
			Valid: true, Why: "CEL's size() macro, which a hand-written parser usually lacks"},
		{Name: "membership with the in operator",
			Text:  "'CVE-2021-44228' in component.vulnerabilities",
			Valid: true, Why: "standard CEL membership, an alternative spelling of contains()"},
		{Name: "membership with contains()",
			Text:  "component.vulnerabilities.contains('CVE-2021-44228')",
			Valid: true, Why: "the spelling the specification's examples use"},
		{Name: "null comparison",
			Text:  "component.cryptography != null",
			Valid: true, Why: "how the specification asks whether a facet is present"},
		{Name: "disjunction with grouping",
			Text:  "(component.type == 'library' || component.type == 'framework') && component.ai == null",
			Valid: true, Why: "operator precedence made explicit"},
		{Name: "negation",
			Text:  "!component.isProduct",
			Valid: true, Why: "unary not over a boolean field"},
		{Name: "a ternary",
			Text:  "component.isProduct ? component.ai != null : true",
			Valid: true, Why: "CEL's conditional operator"},

		{Name: "an unterminated comparison", Text: "component.name ==", Valid: false,
			Why: "a syntax error the specification requires be rejected with 400"},
		{Name: "an expression that is not a predicate", Text: "component.name", Valid: false,
			ReferenceUndecidable: true,
			Why: "well-formed CEL, but it yields a string; a filter has to yield a boolean, " +
				"and only a server that knows its own schema can see that"},
		{Name: "an unbalanced parenthesis", Text: "(component.type == 'library'", Valid: false,
			Why: "a syntax error"},
		{Name: "an assignment", Text: "component.name = 'x'", Valid: false,
			Why: "CEL has no assignment; a permissive parser may accept it as equality"},
		{Name: "a SQL fragment", Text: "1=1 OR '1'='1'", Valid: false,
			Why: "not CEL at all — a server that accepts it is not parsing CEL"},
		{Name: "an empty expression", Text: "", Valid: false,
			Why: "the request schema requires a non-empty expression"},
	}
}

// Run compiles every expression locally and asks the server about each one.
func Run(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	f insightsarea.Fixtures,
	concurrency int,
) ([]runner.Result, Findings) {
	found := Findings{}
	if !f.Reachable {
		return []runner.Result{{
			Area: config.AreaCEL, Seq: 0,
			OperationID: "postStaticInsights",
			Case:        "the query language was not exercised: this provider does not serve Insights",
			Category:    "cel", Method: "—", Pass: true, Optional: true,
		}}, found
	}

	env, err := environment()
	if err != nil {
		return []runner.Result{{
			Area: config.AreaCEL, Seq: 0,
			Case:     "build the reference CEL environment",
			Category: "cel", Method: "—",
			Errors: []string{"harness: " + err.Error()},
		}}, found
	}

	catalogue := Catalogue(f)
	cases := make([]runner.Case, 0, len(catalogue))
	for _, e := range catalogue {
		want := http.StatusOK
		if !e.Valid {
			want = http.StatusBadRequest
		}
		tc := runner.Case{
			OperationID: "postStaticInsights",
			Name:        e.Name,
			Category:    "cel",
			Method:      http.MethodPost,
			Path:        "/static",
			Body:        body(e.Text),
			WantStatus:  want,
		}
		if e.Valid {
			tc.Check = insightsarea.RequireCycloneDX
		} else {
			tc.Check = insightsarea.RequireErrorObject
		}
		cases = append(cases, tc)
	}
	results := runner.Run(ctx, c, api, consumer.Number(cases, config.AreaCEL, seqBase), concurrency)

	// The cross-check. A case can pass against the server and still be a
	// finding, if the reference implementation disagrees about the expression
	// the specification told a client to write.
	for i, e := range catalogue {
		if e.ReferenceUndecidable {
			// The server is still held to the case; there is simply nothing to
			// compare it against.
			continue
		}
		found.Checked++
		refValid, refDetail := compile(env, e.Text)
		serverValid := results[i].GotStatus == http.StatusOK

		if refValid == serverValid {
			found.Agreements++
			continue
		}
		reference := "accepts it"
		server := "rejects it"
		if !refValid {
			reference = "rejects it: " + refDetail
			server = "accepts it"
		}
		found.Disagreements = append(found.Disagreements, Disagreent{
			Expression: e.Text,
			Reference:  reference,
			Server:     server,
		})
		results[i].Errors = append(results[i].Errors, fmt.Sprintf(
			"the reference CEL implementation %s while this server %s — a client generated "+
				"from the specification would write expressions this server does not read the "+
				"same way", reference, server))
		results[i].Pass = false
	}
	sort.Slice(found.Disagreements, func(i, j int) bool {
		return found.Disagreements[i].Expression < found.Disagreements[j].Expression
	})
	return results, found
}

// environment declares the variables the Insights specification's examples use.
//
// They are dynamically typed on purpose: this suite is checking the grammar and
// the result type, not the Insights data model, and pinning field types here
// would fail servers over a schema the specification does not define.
func environment() (*celgo.Env, error) {
	return celgo.NewEnv(
		celgo.Variable("productId", celgo.DynType),
		celgo.Variable("product", celgo.DynType),
		celgo.Variable("component", celgo.DynType),
	)
}

// compile reports whether the reference implementation accepts an expression as
// a filter: it must parse, type-check, and yield a boolean.
func compile(env *celgo.Env, text string) (bool, string) {
	if text == "" {
		return false, "the expression is empty"
	}
	ast, issues := env.Compile(text)
	if issues != nil && issues.Err() != nil {
		return false, firstLine(issues.Err().Error())
	}
	if ast.OutputType() != types.BoolType && ast.OutputType() != celgo.DynType {
		return false, fmt.Sprintf("it evaluates to %s, and a filter must evaluate to bool",
			ast.OutputType())
	}
	return true, ""
}

func body(expression string) []byte {
	b, _ := json.Marshal(map[string]any{"expression": expression})
	return b
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
