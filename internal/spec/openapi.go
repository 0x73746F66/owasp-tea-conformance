package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// API is a compiled OpenAPI document: the operations it declares and the
// schemas it promises for them.
//
// OpenAPI 3.1 schema objects *are* JSON Schema 2020-12, so the specification's
// own bytes compile directly and there is no translation step between what the
// document says and what this suite enforces. Compilation is lazy, which also
// means an older 3.0 document — the Insights specification is one — can still
// be used for its operation table without every one of its schemas having to be
// 2020-12 clean.
type API struct {
	Kind        Kind
	Version     string
	Title       string
	ResourceURL string

	// Warnings are defects in the specification document itself rather than in
	// any provider. They are carried into the report because a suite that
	// silently worked around a broken specification would let the defect
	// survive, and because a reader comparing two providers deserves to know
	// the document they were both judged by has a problem in it.
	Warnings []string

	compiler  *jsonschema.Compiler
	compiled  map[string]*jsonschema.Schema
	Operation map[string]Operation
}

// Operation is the part of an OpenAPI operation this suite needs: how to
// address it, and which schema each status code promises.
type Operation struct {
	OperationID string
	Method      string
	PathPattern string
	Tag         string
	Summary     string

	// StatusSchema maps an HTTP status code to a JSON Pointer into the
	// document, or to "" where the document declares a status with no schema.
	// The specification's 400 responses do exactly that, and inventing a shape
	// for them would fail servers that are in fact conformant.
	StatusSchema map[int]string

	// RequestSchema points at the request body schema, where there is one. The
	// publisher area validates its own payloads against it before sending, so
	// a malformed fixture cannot be reported as a provider's failure.
	RequestSchema string
}

// Statuses lists the declared status codes in ascending order.
func (o Operation) Statuses() []int {
	out := make([]int, 0, len(o.StatusSchema))
	for code := range o.StatusSchema {
		out = append(out, code)
	}
	sort.Ints(out)
	return out
}

// LoadAPI compiles an OpenAPI document from its bytes.
//
// YAML and JSON are both accepted, because upstream publishes the consumption
// specification as YAML and the publication specification as JSON.
func LoadAPI(kind Kind, resourceURL string, raw []byte) (*API, error) {
	doc, warnings, err := parseDocument(kind, raw)
	if err != nil {
		return nil, err
	}

	// Round-trip through JSON so the compiler sees the value model a JSON
	// document produces — json.Number for numerics in particular.
	asJSON, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("re-encode the %s specification: %w", kind, err)
	}
	resource, err := jsonschema.UnmarshalJSON(bytes.NewReader(asJSON))
	if err != nil {
		return nil, fmt.Errorf("decode the %s specification: %w", kind, err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(resourceURL, resource); err != nil {
		return nil, fmt.Errorf("register the %s specification: %w", kind, err)
	}

	api := &API{
		Kind:        kind,
		ResourceURL: resourceURL,
		Warnings:    warnings,
		compiler:    compiler,
		compiled:    map[string]*jsonschema.Schema{},
		Operation:   map[string]Operation{},
	}
	if info, ok := doc["info"].(map[string]any); ok {
		api.Version, _ = info["version"].(string)
		api.Title, _ = info["title"].(string)
	}
	if err := api.index(doc); err != nil {
		return nil, err
	}
	return api, nil
}

// parseDocument decodes an OpenAPI document, using the parser its own syntax
// calls for.
//
// This matters more than it looks. A JSON document with a duplicated key is
// accepted by every JSON parser — last value wins — and rejected outright by a
// YAML one. Upstream's publication document has exactly that defect, so parsing
// it as YAML would make the suite unusable over a fault that no real client
// notices. It is parsed as JSON, and the duplication is reported instead.
func parseDocument(kind Kind, raw []byte) (map[string]any, []string, error) {
	if looksLikeJSON(raw) {
		var doc map[string]any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&doc); err != nil {
			return nil, nil, fmt.Errorf("parse the %s specification: %w", kind, err)
		}
		var warnings []string
		for _, path := range duplicateKeys(raw) {
			warnings = append(warnings, fmt.Sprintf(
				"the document defines %q more than once; JSON parsers keep the last "+
					"definition and silently discard the earlier one", path))
		}
		return doc, warnings, nil
	}

	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse the %s specification: %w", kind, err)
	}
	return doc, nil, nil
}

func looksLikeJSON(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// duplicateKeys walks a JSON document's tokens and reports every object that
// declares the same member twice, by path.
func duplicateKeys(raw []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var (
		found []string
		seen  = map[string]bool{}
		path  []string
		// stack tracks, per open object, the member names already declared.
		stack []map[string]bool
		// inObject distinguishes an object frame from an array frame, since
		// only objects have member names.
		inObject []bool
		// pending is the member name the next value belongs to.
		expectKey bool
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			return found
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, map[string]bool{})
				inObject = append(inObject, true)
				expectKey = true
			case '[':
				inObject = append(inObject, false)
				expectKey = false
			case '}':
				stack = stack[:len(stack)-1]
				inObject = inObject[:len(inObject)-1]
				if len(path) > 0 {
					path = path[:len(path)-1]
				}
				expectKey = len(inObject) > 0 && inObject[len(inObject)-1]
			case ']':
				inObject = inObject[:len(inObject)-1]
				if len(path) > 0 {
					path = path[:len(path)-1]
				}
				expectKey = len(inObject) > 0 && inObject[len(inObject)-1]
			}
		case string:
			if expectKey && len(stack) > 0 {
				frame := stack[len(stack)-1]
				if frame[t] {
					full := strings.Join(append(append([]string{}, path...), t), ".")
					if !seen[full] {
						seen[full] = true
						found = append(found, full)
					}
				}
				frame[t] = true
				path = append(path, t)
				expectKey = false
				break
			}
			closeMember(&path, inObject, &expectKey)
		default:
			closeMember(&path, inObject, &expectKey)
		}
	}
}

// closeMember pops the member a scalar value belonged to, so the next token in
// an object is read as a key again.
func closeMember(path *[]string, inObject []bool, expectKey *bool) {
	if len(inObject) == 0 || !inObject[len(inObject)-1] {
		return
	}
	if len(*path) > 0 {
		*path = (*path)[:len(*path)-1]
	}
	*expectKey = true
}

// index walks paths → methods → responses, recording which schema each declared
// status promises. Response `$ref`s into components are followed so the suite
// compares against the same schema a generated client would.
func (a *API) index(doc map[string]any) error {
	paths, _ := doc["paths"].(map[string]any)
	componentResponses := map[string]any{}
	componentBodies := map[string]any{}
	if comps, ok := doc["components"].(map[string]any); ok {
		if rs, ok := comps["responses"].(map[string]any); ok {
			componentResponses = rs
		}
		if rb, ok := comps["requestBodies"].(map[string]any); ok {
			componentBodies = rb
		}
	}

	for pattern, item := range paths {
		methods, _ := item.(map[string]any)
		for method, opAny := range methods {
			op, ok := opAny.(map[string]any)
			if !ok {
				continue
			}
			id, _ := op["operationId"].(string)
			if id == "" {
				continue
			}
			entry := Operation{
				OperationID:  id,
				Method:       strings.ToUpper(method),
				PathPattern:  pattern,
				StatusSchema: map[int]string{},
			}
			entry.Summary, _ = op["summary"].(string)
			if entry.Summary == "" {
				entry.Summary, _ = op["description"].(string)
			}
			if tags, ok := op["tags"].([]any); ok && len(tags) > 0 {
				entry.Tag, _ = tags[0].(string)
			}

			responses, _ := op["responses"].(map[string]any)
			for code, respAny := range responses {
				status, err := strconv.Atoi(code)
				if err != nil {
					continue // "default"
				}
				inline := "#/paths/" + escapePointer(pattern) + "/" + method + "/responses/" + code
				entry.StatusSchema[status] = resolveContentSchema(respAny, componentResponses,
					"#/components/responses/", inline)
			}
			if body, ok := op["requestBody"]; ok {
				inline := "#/paths/" + escapePointer(pattern) + "/" + method + "/requestBody"
				entry.RequestSchema = resolveContentSchema(body, componentBodies,
					"#/components/requestBodies/", inline)
			}
			a.Operation[id] = entry
		}
	}
	if len(a.Operation) == 0 {
		return fmt.Errorf("the %s specification declares no operations", a.Kind)
	}
	return nil
}

// resolveContentSchema returns the JSON Pointer of an application/json schema,
// following one level of component `$ref`.
//
// Inline schemas — the discovery response wraps an array around a component
// schema — are addressed by their own location in the document rather than
// flattened, so validation still runs against the specification's own bytes.
func resolveContentSchema(node any, components map[string]any, componentPrefix, inlineBase string) string {
	obj, ok := node.(map[string]any)
	if !ok {
		return ""
	}
	base := inlineBase
	if ref, ok := obj["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, componentPrefix)
		target, ok := components[name]
		if !ok {
			return ""
		}
		obj, ok = target.(map[string]any)
		if !ok {
			return ""
		}
		base = componentPrefix + escapePointer(name)
	}
	content, _ := obj["content"].(map[string]any)
	appJSON, _ := content["application/json"].(map[string]any)
	schema, ok := appJSON["schema"].(map[string]any)
	if !ok {
		return ""
	}
	if ref, ok := schema["$ref"].(string); ok {
		return ref
	}
	return base + "/content/application~1json/schema"
}

// SchemaFor compiles and caches a schema by JSON Pointer, e.g.
// "#/components/schemas/product".
func (a *API) SchemaFor(pointer string) (*jsonschema.Schema, error) {
	if pointer == "" {
		return nil, nil
	}
	if sch, ok := a.compiled[pointer]; ok {
		return sch, nil
	}
	sch, err := a.compiler.Compile(a.ResourceURL + pointer)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", pointer, err)
	}
	a.compiled[pointer] = sch
	return sch, nil
}

// OK200 is the 200-response schema pointer for an operation, or "" when the
// operation or the status is not declared. It reads better than the map lookup
// at every call site in the case catalogue.
func (a *API) OK200(operationID string) string {
	return a.Operation[operationID].StatusSchema[200]
}

// Status is the schema pointer an operation declares for a status code.
func (a *API) Status(operationID string, code int) string {
	return a.Operation[operationID].StatusSchema[code]
}

// SuccessStatus is the lowest 2xx an operation declares, or 0 when it declares
// none.
//
// The publication operations do not agree on one success code — a create
// answers 201, an update 200, a delete 204 — so the suite reads the expected
// code out of the document rather than hard-coding a table that would drift
// from it. Returns the schema pointer alongside, since the two are always
// wanted together.
func (a *API) SuccessStatus(operationID string) (int, string) {
	op, ok := a.Operation[operationID]
	if !ok {
		return 0, ""
	}
	best := 0
	for code := range op.StatusSchema {
		if code < 200 || code > 299 {
			continue
		}
		if best == 0 || code < best {
			best = code
		}
	}
	return best, op.StatusSchema[best]
}

// Declares reports whether the document declares an operation at all. It is how
// an area tells "this provider did not implement it" from "the specification
// does not have it".
func (a *API) Declares(operationID string) bool {
	_, ok := a.Operation[operationID]
	return ok
}

// OperationIDs lists every declared operation, sorted.
func (a *API) OperationIDs() []string {
	out := make([]string, 0, len(a.Operation))
	for id := range a.Operation {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// LoadJSONSchema compiles a standalone JSON Schema document, such as the
// discovery document's schema which lives outside any OpenAPI file.
func LoadJSONSchema(resourceURL string, raw []byte) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(resourceURL, doc); err != nil {
		return nil, fmt.Errorf("register schema: %w", err)
	}
	return compiler.Compile(resourceURL)
}

// escapePointer applies RFC 6901 token escaping so a path template such as
// /product/{uuid}/releases can be used inside a JSON Pointer.
func escapePointer(tok string) string {
	out := make([]byte, 0, len(tok))
	for i := 0; i < len(tok); i++ {
		switch tok[i] {
		case '~':
			out = append(out, '~', '0')
		case '/':
			out = append(out, '~', '1')
		default:
			out = append(out, tok[i])
		}
	}
	return string(out)
}
