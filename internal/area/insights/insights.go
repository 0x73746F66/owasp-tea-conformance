// Package insights exercises the TEA Insights API.
//
// Insights is a separate specification with its own version, its own paths and
// its own response format, and it is a different testing problem from the
// object API for two reasons:
//
//   - The responses are CycloneDX documents. The Insights document simply
//     `$ref`s CycloneDX, so that is where conformance actually lives, and a
//     suite that only checked the Insights document would be validating almost
//     nothing.
//   - The queries are the specification's own worked examples. The API is
//     motivated by "does product X use this library, and is it exposed" — so
//     those exact expressions are the case catalogue. An implementation that
//     cannot compile the specification's own examples is not conformant however
//     well-formed its output.
//
// A TEA server is not required to implement Insights. An unreachable Insights
// root is recorded and the run continues.
package insights

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	cdx "github.com/Vulnetix/vdb-cyclonedx"

	"github.com/0x73746F66/owasp-tea-conformance/internal/area/consumer"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
	"github.com/0x73746F66/owasp-tea-conformance/internal/spec"
)

const (
	seqSeed  = 1
	seqCases = 10
)

// Fixtures are the live values the Insights cases are built from.
//
// A conformance run whose every query returns an empty document proves only
// that the server can produce an empty document. These probes find a component
// and a vulnerability the server says it holds, and the catalogue then asserts
// that asking for them returns them.
type Fixtures struct {
	ProductID       string `json:"productId"`
	ProductName     string `json:"productName"`
	ComponentName   string `json:"componentName,omitempty"`
	VulnerabilityID string `json:"vulnerabilityId,omitempty"`
	Reachable       bool   `json:"reachable"`
	Detail          string `json:"detail,omitempty"`
}

// Findings is the Insights section of a report.
type Findings struct {
	BaseURL       string   `json:"baseUrl"`
	SpecVersion   string   `json:"specVersion,omitempty"`
	Fixtures      Fixtures `json:"fixtures"`
	DynamicStatus string   `json:"dynamicEndpointStatus,omitempty"`
	Implemented   bool     `json:"implemented"`
	// Detail explains an unimplemented Insights API, so a reader is not left
	// guessing whether the suite failed to reach it or the provider does not
	// serve it.
	Detail string `json:"detail,omitempty"`
}

// Root derives the Insights root from a TEA API root.
//
// Insights shares an origin with the TEA API and sits at /insights, outside the
// version prefix — which is also how the specification's own server URL plus
// its /insights/static path resolve.
func Root(teaRoot string) string {
	u, err := url.Parse(teaRoot)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/insights"
}

// Run exercises the Insights API.
func Run(
	ctx context.Context,
	c *runner.Client,
	api *spec.API,
	teaFixtures consumer.Fixtures,
	concurrency int,
) ([]runner.Result, Findings) {
	found := Findings{BaseURL: c.BaseURL}
	if api != nil {
		found.SpecVersion = api.Version
	}

	fixtures, seedResult := seed(ctx, c, teaFixtures)
	found.Fixtures = fixtures
	found.Detail = fixtures.Detail
	results := []runner.Result{seedResult}
	if !fixtures.Reachable {
		// Not a conformance failure: Insights is a separate specification and a
		// TEA server may simply not serve it. The report says which happened.
		return results, found
	}
	found.Implemented = true

	cases := BuildCases(api, fixtures)
	results = append(results, runner.Run(ctx, c, api, cases, concurrency)...)

	for _, r := range results {
		if r.OperationID == "postDynamicInsights" && r.WantStatus == http.StatusOK {
			switch r.GotStatus {
			case http.StatusOK:
				found.DynamicStatus = "answered by the inference backend"
			case http.StatusServiceUnavailable:
				found.DynamicStatus = "no inference backend is configured on this deployment"
			case http.StatusUnprocessableEntity:
				found.DynamicStatus = "the model's translation did not compile"
			}
			break
		}
	}
	return results, found
}

// seed discovers what the tenant actually holds so the catalogue asks
// answerable questions.
func seed(ctx context.Context, c *runner.Client, tea consumer.Fixtures) (Fixtures, runner.Result) {
	f := Fixtures{ProductID: tea.ProductUUID, ProductName: tea.ProductName}

	// "true" selects everything, which is the cheapest way to see a real
	// component and a real vulnerability identifier.
	res := runner.RunCase(ctx, c, runner.Case{
		Area: config.AreaInsights, Seq: seqSeed,
		OperationID: "postStaticInsights",
		Name:        "the Insights API is reachable and answers a static query",
		Category:    "insights",
		Method:      http.MethodPost,
		Path:        "/static",
		Body:        payload(map[string]any{"expression": "true"}),
		WantStatus:  http.StatusOK,
		Check:       RequireCycloneDX,
		// An Insights root that is simply not there is reported, not failed.
		Optional: true,
	}, nil)

	if res.GotStatus != http.StatusOK {
		switch res.GotStatus {
		case 0:
			f.Detail = "the Insights root could not be reached"
		case http.StatusUnauthorized, http.StatusForbidden:
			f.Detail = fmt.Sprintf("the Insights root answered HTTP %d: it is served, but not "+
				"to this run's credential", res.GotStatus)
		default:
			f.Detail = fmt.Sprintf("the Insights root answered HTTP %d", res.GotStatus)
		}
		// Downgraded from a failure to an observation, so the case must stop
		// carrying the failure's language: leaving "expected HTTP 200" behind a
		// passing case reads as a contradiction.
		res.Case = "the Insights API was not exercised"
		res.Errors = nil
		res.Warnings = append(res.Warnings, f.Detail)
		res.Pass = true
		return f, res
	}
	f.Reachable = true

	var bom struct {
		Components []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"components"`
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(res.Body, &bom); err == nil {
		for _, comp := range bom.Components {
			if comp.Name != "" && comp.Type == "library" {
				f.ComponentName = comp.Name
				break
			}
		}
		for _, v := range bom.Vulnerabilities {
			if v.ID != "" {
				f.VulnerabilityID = v.ID
				break
			}
		}
	}
	return f, res
}

// BuildCases produces the Insights catalogue.
func BuildCases(api *spec.API, f Fixtures) []runner.Case {
	expr := func(name, expression string, check func([]byte) error) runner.Case {
		return runner.Case{
			OperationID: "postStaticInsights",
			Name:        name,
			Category:    "insights",
			Method:      http.MethodPost,
			Path:        "/static",
			Body:        payload(map[string]any{"expression": expression}),
			WantStatus:  http.StatusOK,
			Check:       check,
		}
	}

	cases := []runner.Case{
		// The specification's own worked examples. These are the queries its
		// readme uses to justify the API existing.
		expr("select every component", "true", RequireCycloneDX),
		expr("third-party components of a product",
			fmt.Sprintf("productId == '%s' && component.type == 'third-party'", f.ProductID),
			RequireCycloneDX),
		expr("open-source components of a product",
			fmt.Sprintf("productId == '%s' && component.licenseType == 'Open Source'", f.ProductID),
			RequireCycloneDX),
		expr("components with any vulnerability",
			fmt.Sprintf("productId == '%s' && component.vulnerabilities.size() > 0", f.ProductID),
			RequireCycloneDX),
		expr("cryptographic assets", "component.cryptography != null", RequireCycloneDX),
		expr("AI components", "component.ai != null", RequireCycloneDX),
		expr("components with an OpenSSF Scorecard", "component.scorecard != null", RequireCycloneDX),
		expr("components with build provenance", "component.provenance != null", RequireCycloneDX),

		// Error paths the specification declares.
		{
			OperationID: "postStaticInsights", Name: "reject an invalid CEL expression",
			Category: "negative",
			Method:   http.MethodPost, Path: "/static",
			Body:       payload(map[string]any{"expression": "component.name =="}),
			WantStatus: 400, Check: RequireErrorObject,
		},
		{
			OperationID: "postStaticInsights", Name: "reject a non-boolean expression",
			Category: "negative",
			Method:   http.MethodPost, Path: "/static",
			Body:       payload(map[string]any{"expression": "component.name"}),
			WantStatus: 400, Check: RequireErrorObject,
		},
		{
			OperationID: "postStaticInsights", Name: "reject a missing expression",
			Category: "negative",
			Method:   http.MethodPost, Path: "/static",
			Body:       payload(map[string]any{}),
			WantStatus: 400,
		},
		{
			OperationID: "postStaticInsights", Name: "reject a malformed body", Category: "negative",
			Method: http.MethodPost, Path: "/static",
			Body:       []byte("{not json"),
			WantStatus: 400,
		},
		{
			OperationID: "postStaticInsights", Name: "unauthenticated request is rejected",
			Category: "security",
			Method:   http.MethodPost, Path: "/static", Auth: runner.NoAuth,
			Body:         payload(map[string]any{"expression": "true"}),
			WantStatus:   401,
			AcceptStatus: []int{403},
			// A public Insights deployment is legitimate, so this is evidence
			// about the deployment rather than about the specification.
			Optional: true,
		},

		// Content negotiation. The Insights specification pins its response to
		// CycloneDX 1.6, so that is what an unqualified request must get: a
		// server defaulting to a newer version would break every client
		// validating against the schema the specification names. A client that
		// wants newer asks for it.
		{
			OperationID: "postStaticInsights",
			Name:        "defaults to the specification's CycloneDX 1.6",
			Category:    "conformance",
			Method:      http.MethodPost, Path: "/static",
			Body:       payload(map[string]any{"expression": "true"}),
			WantStatus: http.StatusOK,
			Check:      RequireSpecVersion("1.6"),
		},
		{
			OperationID: "postStaticInsights",
			Name:        "negotiates CycloneDX 1.7 on request",
			Category:    "conformance",
			Method:      http.MethodPost, Path: "/static",
			Body:       payload(map[string]any{"expression": "true"}),
			WantStatus: http.StatusOK,
			Accept:     "application/vnd.cyclonedx+json; version=1.7",
			Check:      RequireSpecVersion("1.7"),
			// Negotiation is a SHOULD in practice: a server that only speaks
			// 1.6 is still usable, and the report says which it did.
			Optional: true,
		},

		// Dynamic. A deployment with no inference backend answers 503, which is
		// a configuration fact rather than a conformance failure.
		{
			OperationID: "postDynamicInsights", Name: "natural-language query", Category: "insights",
			Method: http.MethodPost, Path: "/dynamic",
			Body: payload(map[string]any{
				"prompt": "Which third-party dependencies does " + f.ProductName + " use?",
			}),
			WantStatus:   http.StatusOK,
			AcceptStatus: []int{http.StatusServiceUnavailable, http.StatusUnprocessableEntity, http.StatusNotFound},
			Check:        RequireCycloneDX,
			Optional:     true,
		},
		{
			OperationID: "postDynamicInsights", Name: "reject a missing prompt", Category: "negative",
			Method: http.MethodPost, Path: "/dynamic",
			Body:         payload(map[string]any{"systemPrompt": "You are a security expert."}),
			WantStatus:   400,
			AcceptStatus: []int{http.StatusNotFound},
			Optional:     true,
		},
	}

	// Efficacy cases: the specification's motivating question, asked of data the
	// server has just said it holds. These distinguish a working query engine
	// from one that always answers "nothing found".
	if f.ComponentName != "" {
		cases = append(cases, expr("find a component by name",
			fmt.Sprintf("component.name == '%s'", celQuote(f.ComponentName)),
			RequireMatch("the component named "+f.ComponentName)))
	}
	if f.VulnerabilityID != "" {
		cases = append(cases,
			expr("find a component by vulnerability identifier",
				fmt.Sprintf("component.vulnerabilities.contains('%s')", celQuote(f.VulnerabilityID)),
				RequireMatch("a component affected by "+f.VulnerabilityID)),
			// The `in` spelling is standard CEL; both must work, since a client
			// generated from the specification may use either.
			expr("find a component by vulnerability identifier using in",
				fmt.Sprintf("'%s' in component.vulnerabilities", celQuote(f.VulnerabilityID)),
				RequireMatch("a component affected by "+f.VulnerabilityID)),
		)
	}
	return consumer.Number(cases, config.AreaInsights, seqCases)
}

// celQuote escapes a value for interpolation into a single-quoted CEL literal.
func celQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

func payload(v map[string]any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// RequireCycloneDX asserts the response really is a usable CycloneDX document.
//
// Validation goes through the shared CycloneDX module, so whichever version the
// server answered with is validated against that version's schema — which is
// also what makes the 1.6-default and 1.7-negotiated cases meaningful rather
// than a string comparison.
func RequireCycloneDX(body []byte) error {
	version, violations, err := cdx.ValidateCycloneDX(body)
	if err != nil {
		return fmt.Errorf("the response is not a usable CycloneDX document: %w", err)
	}
	if version == "" {
		return fmt.Errorf("the response does not declare bomFormat CycloneDX and a specVersion")
	}
	if len(violations) > 0 {
		parts := make([]string, 0, 5)
		for _, v := range violations[:min(len(violations), 5)] {
			where := v.Path
			if where == "" {
				where = "(document root)"
			}
			parts = append(parts, where+": "+v.Message)
		}
		return fmt.Errorf("the response does not validate against CycloneDX %s: %s",
			version, strings.Join(parts, "; "))
	}
	var bom map[string]any
	if err := json.Unmarshal(body, &bom); err != nil {
		return fmt.Errorf("the response is not JSON: %w", err)
	}
	if sn, _ := bom["serialNumber"].(string); sn != "" && !strings.HasPrefix(sn, "urn:uuid:") {
		return fmt.Errorf("serialNumber %q is not a urn:uuid", sn)
	}
	if _, ok := bom["components"]; !ok {
		return fmt.Errorf("there is no components key: a fragment with nothing in it should still say so")
	}
	return nil
}

// RequireMatch asserts the query actually selected something. An empty answer to
// a question the server said it could answer means the engine is not working,
// and no schema check would notice.
func RequireMatch(what string) func([]byte) error {
	return func(body []byte) error {
		if err := RequireCycloneDX(body); err != nil {
			return err
		}
		var bom struct {
			Components []any `json:"components"`
		}
		if err := json.Unmarshal(body, &bom); err != nil {
			return err
		}
		if len(bom.Components) == 0 {
			return fmt.Errorf("the query for %s returned no components, but the server "+
				"reported that it holds one", what)
		}
		return nil
	}
}

// RequireSpecVersion asserts the negotiated CycloneDX version came back.
//
// This is the check that catches a server quietly upgrading its default: the
// response would still be a valid CycloneDX document and still pass schema
// validation, while breaking every client that pinned the version the
// specification names.
func RequireSpecVersion(want string) func([]byte) error {
	return func(body []byte) error {
		if err := RequireCycloneDX(body); err != nil {
			return err
		}
		var bom struct {
			SpecVersion string `json:"specVersion"`
		}
		if err := json.Unmarshal(body, &bom); err != nil {
			return err
		}
		if bom.SpecVersion != want {
			return fmt.Errorf("specVersion is %q, expected %q", bom.SpecVersion, want)
		}
		return nil
	}
}

// RequireErrorObject asserts a rejection tells the caller what was wrong.
func RequireErrorObject(body []byte) error {
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("the error response is not JSON: %w", err)
	}
	if msg, _ := v["error"].(string); msg == "" {
		return fmt.Errorf("the error response carries no `error` message, so a caller cannot " +
			"tell what to fix")
	}
	return nil
}
