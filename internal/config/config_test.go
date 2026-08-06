package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const twoProviders = `
version: 1
output:
  dir: out
  splitByArea: false
areas: [discovery, consumer, provider, performance]
exclude: [performance]
packages:
  - pkg:npm/lodash
providers:
  - name: alpha
    dns: alpha.example
    auth: {scheme: bearer, credentialEnv: ALPHA_TOKEN}
    exclude: [provider]
  - name: Beta Two
    dns: beta.example
    output: {dir: elsewhere, splitByArea: true}
    packages: [pkg:pypi/requests]
`

func TestResolveAppliesGlobalThenProviderOverrides(t *testing.T) {
	t.Setenv("ALPHA_TOKEN", "s3cret")
	path := write(t, twoProviders)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	providers, err := cfg.Resolve(nil, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("resolved %d providers, expected 2", len(providers))
	}

	alpha := providers[0]
	// performance is excluded globally, provider is excluded for alpha; what
	// remains must be in AllAreas order regardless of how the file listed it.
	if got := JoinAreas(alpha.Areas, ","); got != "discovery,consumer" {
		t.Errorf("alpha areas are %q, expected discovery,consumer", got)
	}
	if alpha.Credential != "s3cret" || alpha.CredentialMissing {
		t.Errorf("alpha credential was not read from the environment: %+v", alpha.Auth)
	}
	if got := alpha.AuthHeader(); got != "Bearer s3cret" {
		t.Errorf("alpha auth header is %q", got)
	}
	if alpha.Output.SplitByArea {
		t.Error("alpha inherited splitByArea:false but reports true")
	}
	if !strings.HasSuffix(alpha.Output.Dir, filepath.Join("out", "alpha")) {
		t.Errorf("alpha output dir is %q", alpha.Output.Dir)
	}
	if len(alpha.Packages) != 1 || alpha.Packages[0] != "pkg:npm/lodash" {
		t.Errorf("alpha did not inherit the global package list: %v", alpha.Packages)
	}

	beta := providers[1]
	if got := JoinAreas(beta.Areas, ","); got != "discovery,consumer,provider" {
		t.Errorf("beta areas are %q", got)
	}
	if !beta.Output.SplitByArea {
		t.Error("beta overrode splitByArea to true but reports false")
	}
	if !strings.HasSuffix(beta.Output.Dir, "elsewhere") {
		t.Errorf("beta output dir is %q", beta.Output.Dir)
	}
	if len(beta.Packages) != 1 || beta.Packages[0] != "pkg:pypi/requests" {
		t.Errorf("beta package list is %v", beta.Packages)
	}
	if beta.Slug() != "beta-two" {
		t.Errorf("beta slug is %q, expected beta-two", beta.Slug())
	}
	// No credentialEnv and no scheme means an unauthenticated read, which is a
	// legitimate configuration and not a missing secret.
	if beta.CredentialMissing {
		t.Error("beta is configured with no auth but reports a missing credential")
	}
}

func TestResolveNarrowsByProviderAndArea(t *testing.T) {
	path := write(t, twoProviders)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	only, err := cfg.Resolve([]string{"alpha"}, []Area{AreaConsumer})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(only) != 1 || only[0].Name != "alpha" {
		t.Fatalf("narrowing by name returned %d providers", len(only))
	}
	if got := JoinAreas(only[0].Areas, ","); got != "consumer" {
		t.Errorf("narrowing by area gave %q", got)
	}

	// An unknown name must be an error: "the run was green" and "the run did
	// nothing" must not look the same.
	if _, err := cfg.Resolve([]string{"nonesuch"}, nil); err == nil {
		t.Error("resolving an unknown provider name should fail")
	}
}

func TestAuthHeaderRendersEachScheme(t *testing.T) {
	cases := []struct {
		scheme     string
		credential string
		want       string
	}{
		{AuthBearer, "tok", "Bearer tok"},
		{AuthAPIKey, "org:hex", "ApiKey org:hex"},
		{AuthBasic, "user:pass", "Basic dXNlcjpwYXNz"},
		// Already base64: passed through instead of encoded twice.
		{AuthBasic, "dXNlcjpwYXNz", "Basic dXNlcjpwYXNz"},
		// The escape hatch: whatever produced the value already rendered it, so
		// the suite must not take it apart and put it back together.
		{AuthHeader, "ApiKey org:hex", "ApiKey org:hex"},
		{AuthHeader, "Bearer tok", "Bearer tok"},
		{AuthNone, "ignored", ""},
	}
	for _, tc := range cases {
		r := Resolved{Credential: tc.credential}
		r.Auth.Scheme = tc.scheme
		if got := r.AuthHeader(); got != tc.want {
			t.Errorf("scheme %q with credential %q rendered %q, expected %q",
				tc.scheme, tc.credential, got, tc.want)
		}
	}

	// An empty credential never produces a header, whatever the scheme says.
	for _, scheme := range []string{AuthBearer, AuthAPIKey, AuthBasic, AuthHeader} {
		r := Resolved{}
		r.Auth.Scheme = scheme
		if got := r.AuthHeader(); got != "" {
			t.Errorf("scheme %q with no credential rendered %q", scheme, got)
		}
	}
}

func TestMissingCredentialIsReportedNotGuessed(t *testing.T) {
	path := write(t, `
version: 1
providers:
  - name: alpha
    dns: alpha.example
    auth: {scheme: apikey, credentialEnv: DEFINITELY_NOT_SET_TEA}
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	providers, err := cfg.Resolve(nil, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !providers[0].CredentialMissing {
		t.Error("a scheme with an unset environment variable did not report a missing credential")
	}
	if providers[0].AuthHeader() != "" {
		t.Error("an empty credential produced an Authorization header")
	}
}

func TestLoadRejectsMistakes(t *testing.T) {
	cases := map[string]string{
		"a misspelled key": `
version: 1
excludes: [provider]
providers:
  - {name: a, dns: a.example}
`,
		"an unknown area": `
version: 1
areas: [discovery, nonesuch]
providers:
  - {name: a, dns: a.example}
`,
		"a duplicate provider name": `
version: 1
providers:
  - {name: a, dns: a.example}
  - {name: a, dns: b.example}
`,
		"a provider with no way to reach it": `
version: 1
providers:
  - {name: a}
`,
		"an unknown auth scheme": `
version: 1
providers:
  - {name: a, dns: a.example, auth: {scheme: magic}}
`,
		"no providers at all": `
version: 1
providers: []
`,
		"a future config version": `
version: 2
providers:
  - {name: a, dns: a.example}
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(write(t, body)); err == nil {
				t.Error("the configuration was accepted but should have been rejected")
			}
		})
	}
}

func TestDefaultsFillEverySpecSource(t *testing.T) {
	cfg, err := Load(write(t, "version: 1\nproviders:\n  - {name: a, dns: a.example}\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for name, src := range map[string]SpecSource{
		"consumer":  cfg.Specs.Consumer,
		"publisher": cfg.Specs.Publisher,
		"wellKnown": cfg.Specs.WellKnown,
		"insights":  cfg.Specs.Insights,
		"spdx":      cfg.Specs.SPDX,
	} {
		if src.Repo == "" || src.Ref == "" || src.Path == "" {
			t.Errorf("the %s specification source is incomplete: %+v", name, src)
		}
	}
	providers, err := cfg.Resolve(nil, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := len(providers[0].Areas); got != len(AllAreas) {
		t.Errorf("a configuration naming no areas ran %d, expected all %d", got, len(AllAreas))
	}
	if providers[0].WriteCycle.RunKey == "" || providers[0].Performance.Iterations == 0 {
		t.Error("performance and write-cycle defaults were not applied")
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"vulnetix":             "vulnetix",
		"Beta Two":             "beta-two",
		"products.example.com": "products-example-com",
		"  spaced  ":           "spaced",
		"!!!":                  "",
	} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) is %q, expected %q", in, got, want)
		}
	}
}
