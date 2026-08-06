# OWASP TEA conformance suite.
#
# Every recipe reads config.yaml if it exists and falls back to
# config.example.yaml, so a fresh clone runs without editing anything.

config := if path_exists("config.yaml") == "true" { "config.yaml" } else { "config.example.yaml" }

# INTERNAL USE ONLY — see the recipes at the bottom of this file. Everything
# above them is for anybody running the suite; those two paths wire it to
# Vulnetix's own CLI and documentation site, and are useless to anyone else.
hugo_docs := env("VULNETIX_CLI_TEA_DOCS", "../cli/website/content/docs/tea")
credential_tool := "./tools/vulnetix-credential"

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

# Show what a run would do, without making a single request.
plan:
    go run ./cmd/tea-conformance --config {{config}} --plan

# Full run. Pass a provider name to narrow: `just run vulnetix`.
run provider="":
    go run ./cmd/tea-conformance --config {{config}} {{ if provider != "" { "--provider " + provider } else { "" } }}

# Run one area against one provider: `just area consumer vulnetix`.
area name provider="":
    go run ./cmd/tea-conformance --config {{config}} --area {{name}} {{ if provider != "" { "--provider " + provider } else { "" } }}

# Check every endpoint answers; store nothing, judge nothing, write nothing.
dryrun provider="":
    go run ./cmd/tea-conformance --config {{config}} --dryrun {{ if provider != "" { "--provider " + provider } else { "" } }}

# Regenerate reports from a previous run's directory with no network at all.
reproduce dir:
    go run ./cmd/tea-conformance --config {{config}} --reproduce-from-dir {{dir}}

# A normal run fetches the specifications itself, into its own run directory.
# This recipe is for inspecting what upstream currently says.

# Fetch the authoritative specifications into ./spec-preview and print digests.
fetch-specs:
    go run ./cmd/tea-conformance --config {{config}} --fetch-specs-to spec-preview

# ─── INTERNAL USE ONLY ──────────────────────────────────────────────────────
#
# Both recipes below wire this suite to Vulnetix's own tooling. They are not
# part of using the suite: no test touches them, no other recipe depends on
# them, and someone testing a different provider should ignore them entirely.
#
# ── Credentials ─────────────────────────────────────────────────────────────
#
# The Vulnetix CLI already knows how to authenticate. It resolves a credential
# from six sources in precedence order, any of which may keep the secret in the
# OS keychain rather than on disk, and renders one of three header shapes from
# it. Rather than copy that here — where it would drift, and where a drifted
# copy fails as a 401 that reads like the provider's fault — these recipes ask
# the CLI's own package for the finished Authorization header.
#
# The provider entry that consumes it uses `scheme: header`, which sends the
# value verbatim. There is then nothing left to disagree about: whichever method
# the CLI is authenticated with, the suite sends exactly what the CLI would.
#
#   eval "$(just vulnetix-env)"     # set it in this shell
#   just run-authed vulnetix        # or set it for one run and no longer
#
# The value is printed to stdout and never logged, so it stays inside a command
# substitution instead of landing in a scrollback buffer.

# INTERNAL: print the Vulnetix CLI's credential as an Authorization header.
vulnetix-credential:
    @cd {{credential_tool}} && go run . -v

# Usage: eval "$(just vulnetix-env)"

# INTERNAL: print an export line for TEA_VULNETIX_CREDENTIAL.
vulnetix-env:
    @cd {{credential_tool}} && go run . -export

# The credential is set for this command only, so it never persists in a shell
# that outlives the run.

# INTERNAL: run against a provider using the Vulnetix CLI's credential.
run-authed provider="vulnetix":
    #!/usr/bin/env bash
    set -euo pipefail
    cred="$(cd {{credential_tool}} && go run . -v)"
    TEA_VULNETIX_CREDENTIAL="$cred" \
      go run ./cmd/tea-conformance --config {{config}} --provider {{provider}}

# ── Documentation ───────────────────────────────────────────────────────────
#
# Publishes a recorded run into the Vulnetix CLI documentation site, which is a
# separate repository. It is here rather than there because the report
# format belongs to this suite: when a section is renamed the recipe that maps
# it onto Hugo pages should move in the same commit.
#
# Nobody outside Vulnetix has a reason to run this. It is not part of using the
# suite, nothing else depends on it, and deleting it would not affect a single
# conformance result. The generic way to publish a report is to read the
# Markdown in `reports/<provider>/reports/` and do whatever your own site needs.
#
# It writes into ../cli, which is another working copy on this machine. Override
# with VULNETIX_CLI_TEA_DOCS. Nothing is committed or pushed — the CLI repository
# has its own review and release process, and this only stages the files for it.
#
#   just publish-hugo                       # from reports/vulnetix
#   just publish-hugo reports/vulnetix      # explicit
#
# Reports are regenerated offline from the run's own recordings rather than
# copied, so what lands on the site is reproducible from the evidence beside it,
# and a stale hand-edit on either end shows up as a diff.

# INTERNAL: stage a recorded run into the Vulnetix CLI documentation site.
publish-hugo dir="reports/vulnetix":
    #!/usr/bin/env bash
    set -euo pipefail

    run_dir="{{dir}}"
    docs="{{hugo_docs}}"

    if [ ! -d "$run_dir/responses" ]; then
      echo "no recorded run at $run_dir — run 'just run vulnetix' first" >&2
      exit 1
    fi
    if [ ! -d "$docs" ]; then
      echo "the CLI documentation tree is not at $docs" >&2
      echo "set VULNETIX_CLI_TEA_DOCS to where it is checked out" >&2
      exit 1
    fi

    staging="$(mktemp -d)"
    trap 'rm -rf "$staging"' EXIT

    # Single-document Markdown: the Hugo page set has one conformance page, and
    # the split layout's inter-page links would resolve to nothing there.
    go run ./cmd/tea-conformance \
      --config {{config}} \
      --reproduce-from-dir "$run_dir" \
      --reports-to "$staging" \
      --markdown single \
      --quiet

    generated="$staging/$(basename "$run_dir")/reports"

    # Front matter is prepended rather than emitted by the suite: the weights
    # and descriptions belong to the site's information architecture, not to a
    # conformance report, and a report that carried them would be wrong
    # everywhere else.
    {
      printf -- '---\n'
      printf 'title: Conformance report\n'
      printf 'weight: 2\n'
      printf 'description: "Independent conformance and performance results for the Vulnetix TEA server, generated by the OWASP TEA conformance suite."\n'
      printf -- '---\n\n'
      # The suite writes an H1; Hugo renders the title from front matter, so
      # carrying both would print the heading twice.
      tail -n +2 "$generated/conformance.md"
    } > "$docs/conformance.md"

    if [ -f "$generated/catalogue.md" ]; then
      {
        printf -- '---\n'
        printf 'title: Open-source catalogue\n'
        printf 'weight: 3\n'
        printf 'description: "The open-source projects the Vulnetix TEA server publishes as TEA products, listed by paging the API itself."\n'
        printf -- '---\n\n'
        tail -n +2 "$generated/catalogue.md"
      } > "$docs/catalogue.md"
    fi

    # residual.md is deliberately NOT published. It names records left in a
    # catalogue for an operator to purge, which is an internal maintenance note
    # and not something a public documentation site should carry.

    echo "staged into $docs:"
    ls -1 "$docs"
    echo
    echo "review and commit in the CLI repository; nothing was committed here or there"
