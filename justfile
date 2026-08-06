# OWASP TEA conformance suite.
#
# Every recipe reads config.yaml if it exists and falls back to
# config.example.yaml, so a fresh clone runs without editing anything.

config := if path_exists("config.yaml") == "true" { "config.yaml" } else { "config.example.yaml" }

_default:
    @just --list

# Compile the binary to ./bin/tea-conformance.
build:
    go build -o bin/tea-conformance ./cmd/tea-conformance

# Unit tests, including the validator's own negative controls.
test:
    go test ./...

fmt:
    gofmt -w .

vet:
    go vet ./...

lint: fmt vet

# Print the resolved configuration: which areas run against which provider,
# where each report lands, and which credentials are missing from the
# environment. Makes no network requests.
plan:
    go run ./cmd/tea-conformance --config {{config}} --plan

# Full run. Pass a provider name to narrow: `just run vulnetix`.
run provider="":
    go run ./cmd/tea-conformance --config {{config}} {{ if provider != "" { "--provider " + provider } else { "" } }}

# Run one area against one provider: `just area consumer vulnetix`.
area name provider="":
    go run ./cmd/tea-conformance --config {{config}} --area {{name}} {{ if provider != "" { "--provider " + provider } else { "" } }}

# Reachability only: check every declared endpoint answers, store nothing,
# evaluate nothing, write nothing to any provider.
dryrun provider="":
    go run ./cmd/tea-conformance --config {{config}} --dryrun {{ if provider != "" { "--provider " + provider } else { "" } }}

# Regenerate reports from a previous run's directory with no network at all.
reproduce dir:
    go run ./cmd/tea-conformance --config {{config}} --reproduce-from-dir {{dir}}

# Fetch the authoritative specifications into ./spec-preview and print their
# digests. A normal run does this itself, into the run directory; this recipe is
# for inspecting what upstream currently says.
fetch-specs:
    go run ./cmd/tea-conformance --config {{config}} --fetch-specs-to spec-preview
