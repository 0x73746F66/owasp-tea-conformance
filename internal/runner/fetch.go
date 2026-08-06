package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
)

// GetJSON issues one recorded GET and decodes the body.
//
// Areas that need to walk the object graph rather than assert against it — the
// fixture seed, the artifact inventory — go through here, so every request a
// run makes ends up in the same evidence directory as the cases do. The caller
// supplies the sequence number, because only the caller knows the
// deterministic order its walk visits things in.
func GetJSON(ctx context.Context, c *Client, area config.Area, seq int, name, path string, query url.Values) (map[string]any, Result, error) {
	res := RunCase(ctx, c, Case{
		Area:       area,
		Seq:        seq,
		Name:       name,
		Category:   "walk",
		Path:       path,
		Query:      query,
		WantStatus: http.StatusOK,
	}, nil)
	if res.GotStatus != http.StatusOK {
		if len(res.Errors) > 0 {
			return nil, res, fmt.Errorf("%s", res.Errors[0])
		}
		return nil, res, fmt.Errorf("HTTP %d", res.GotStatus)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Body, &out); err != nil {
		return nil, res, fmt.Errorf("decode %s: %w", path, err)
	}
	return out, res, nil
}

// GetRaw issues one recorded GET against an absolute URL and returns the body.
// Artifact downloads use it: a format's URL points wherever the publisher put
// the bytes, which is frequently not the API host at all.
func GetRaw(ctx context.Context, c *Client, area config.Area, seq int, name, absoluteURL, accept string) ([]byte, Result) {
	res := RunCase(ctx, c, Case{
		Area:        area,
		Seq:         seq,
		Name:        name,
		Category:    "download",
		AbsoluteURL: absoluteURL,
		Accept:      accept,
		WantStatus:  http.StatusOK,
	}, nil)
	return res.Body, res
}

// AsSlice is the "it might not be an array" accessor these walks need
// constantly, since every field being read comes from an untrusted response.
func AsSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// AsMap is the object counterpart of AsSlice.
func AsMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// AsString reads a string field, returning "" for anything else.
func AsString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// AsInt reads a JSON number as an int, returning 0 for anything else.
func AsInt(m map[string]any, key string) int {
	switch n := m[key].(type) {
	case float64:
		return int(n)
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0
		}
		return int(i)
	default:
		return 0
	}
}

// AsBool reads a boolean field, returning false for anything else.
func AsBool(m map[string]any, key string) bool {
	b, _ := m[key].(bool)
	return b
}
