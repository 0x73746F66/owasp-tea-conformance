# OWASP TEA conformance suite.
#
# Every recipe reads config.yaml if it exists and falls back to
# config.example.yaml, so a fresh clone runs without editing anything.

config := if path_exists("config.yaml") == "true" { "config.yaml" } else { "config.example.yaml" }

# INTERNAL USE ONLY. See the recipes at the bottom of this file. Everything
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

# --- INTERNAL USE ONLY ---
#
# Both recipes below wire this suite to Vulnetix's own tooling. They are not
# part of using the suite: no test touches them, no other recipe depends on
# them, and someone testing a different provider should ignore them entirely.
#
# --- Credentials ---
#
# The Vulnetix CLI already knows how to authenticate. It resolves a credential
# from six sources in precedence order, any of which may keep the secret in the
# OS keychain instead of on disk, and renders one of three header shapes from
# it. Rather than copy that here, where it would drift and where a drifted
# copy fails as a 401 that reads like the provider's fault, these recipes ask
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

# --- Documentation ---
#
# Publishes a recorded run into the Vulnetix CLI documentation site, which is a
# separate repository. It is here and not there because the report
# format belongs to this suite: when a section is renamed the recipe that maps
# it onto Hugo pages should move in the same commit.
#
# Nobody outside Vulnetix has a reason to run this. It is not part of using the
# suite, nothing else depends on it, and deleting it would not affect a single
# conformance result. The generic way to publish a report is to read the
# Markdown in `reports/<provider>/reports/` and do whatever your own site needs.
#
# It writes into ../cli, which is another working copy on this machine. Override
# with VULNETIX_CLI_TEA_DOCS. Nothing is committed or pushed. The CLI repository
# has its own review and release process, and this only stages the files for it.
#
#   just publish-hugo                            # both defaults
#   just publish-hugo ../cli/website             # a Hugo site root
#   just publish-hugo ../cli/website/content/docs/tea
#   just publish-hugo ../cli/website reports/vulnetix
#
# The destination comes first because it is the argument anybody actually
# overrides; the run directory is almost always the default.
#
# Reports are regenerated offline from the run's own recordings rather than
# copied, so what lands on the site is reproducible from the evidence beside it,
# and a stale hand-edit on either end shows up as a diff.

# INTERNAL: stage a recorded run into the Vulnetix CLI documentation site.
publish-hugo docs=hugo_docs dir="reports/vulnetix":
    #!/usr/bin/env bash
    set -euo pipefail

    run_dir="{{dir}}"
    docs="{{docs}}"

    if [ ! -d "$run_dir/responses" ]; then
      echo "no recorded run at $run_dir; run 'just run vulnetix' first" >&2
      exit 1
    fi

    # Accept either the TEA docs directory itself or the Hugo site root above
    # it. Both are natural things to type, and guessing wrong here writes two
    # pages into a directory nobody is serving.
    if [ -d "$docs/content/docs/tea" ]; then
      docs="$docs/content/docs/tea"
    fi
    if [ ! -d "$docs" ]; then
      echo "no TEA documentation directory at $docs" >&2
      echo "pass the Hugo site root or the docs/tea directory, or set VULNETIX_CLI_TEA_DOCS" >&2
      exit 1
    fi
    if [ ! -f "$docs/_index.md" ]; then
      echo "$docs does not look like the TEA documentation section (no _index.md)" >&2
      exit 1
    fi

    staging="$(mktemp -d)"
    trap 'rm -rf "$staging"' EXIT

    # Split Markdown: the summary becomes the section index and every area
    # becomes a page beneath it, which is how a reader reaches an area report at
    # all. A single document put ten areas behind one anchor list and left the
    # site's navigation with nothing to show.
    #
    # A non-conformant verdict exits non-zero, and that is the exit code of the
    # regeneration, not a failure to regenerate. Publishing must not depend on
    # the answer being yes: a suite that only publishes when the provider passes
    # is a marketing page. What decides success here is whether the report was
    # written, which is checked directly below.
    go run ./cmd/tea-conformance \
      --config {{config}} \
      --reproduce-from-dir "$run_dir" \
      --reports-to "$staging" \
      --markdown split \
      --quiet || true

    generated="$staging/$(basename "$run_dir")/reports"

    if [ ! -f "$generated/conformance.md" ]; then
      echo "the run was not regenerated from $run_dir; nothing to publish" >&2
      exit 1
    fi

    section="$docs/conformance"
    # Cleared rather than overwritten: an area the suite no longer reports must
    # not survive as a page describing a run that never happened.
    rm -rf "$section"
    mkdir -p "$section"
    # An earlier version of this recipe published one leaf page at this URL.
    # Hugo cannot serve a leaf and a section from the same path, so the leaf
    # goes; without this the build fails on a duplicate target.
    rm -f "$docs/conformance.md"

    # Front matter is prepended instead of being emitted by the suite: the
    # weights and titles belong to the site's information architecture, not to a
    # conformance report, and a report that carried them would be wrong
    # everywhere else.
    frontmatter() {
      printf -- '---\n'
      printf 'title: %s\n' "$1"
      printf 'weight: %s\n' "$2"
      printf 'description: "%s"\n' "$3"
      printf -- '---\n\n'
    }

    # A page's description is the area's own one-line summary, which the report
    # already writes as its third line. Taking it from there rather than
    # restating it here is what keeps the two from drifting.
    describe() {
      sed -n '3p' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
    }

    # Titles mirror the report's own vocabulary rather than improving on it. A
    # sidebar entry reading "Publication" above a table row reading "provider"
    # is two names for one thing, and the reader has to work out that it is one.
    area_title() {
      case "$1" in
        cyclonedx) echo 'CycloneDX' ;;
        spdx)      echo 'SPDX' ;;
        cel)       echo 'CEL' ;;
        purl)      echo 'purl' ;;
        *)         echo "$(printf '%s' "${1:0:1}" | tr '[:lower:]' '[:upper:]')${1:1}" ;;
      esac
    }

    # The suite writes an H1 on line 1; Hugo renders the title from front
    # matter, so carrying both would print the heading twice.
    #
    # The links are rewritten because the report is written to be read as files
    # in a directory, where `discovery.md` is a sibling. Under Hugo's pretty
    # URLs the index lives at conformance/ and an area at conformance/discovery/,
    # so a sibling link resolves to nothing.
    {
      frontmatter 'Conformance report' 2 \
        'Independent conformance and performance results for the Vulnetix TEA server, generated by the OWASP TEA conformance suite.'
      tail -n +2 "$generated/conformance.md" \
        | grep -v '](residual\.md)' \
        | sed -E 's#\]\(([a-z]+)\.md\)#](\1/)#g'
    } > "$section/_index.md"

    publish_area() {
      local src="$1" name="$2" weight="$3"
      {
        frontmatter "$(area_title "$name")" "$weight" "$(describe "$src")"
        tail -n +2 "$src" | sed -E 's#\]\(conformance\.md\)#](../)#g'
      } > "$section/$name.md"
    }

    # Ordered as the report orders its areas, so the sidebar reads in the same
    # sequence as the summary table above it.
    weight=0
    for area in discovery consumer purl cyclonedx spdx insights cel provenance performance provider; do
      [ -f "$generated/$area.md" ] || continue
      weight=$((weight + 1))
      publish_area "$generated/$area.md" "$area" "$weight"
    done

    # Anything the list above does not name is still published, at the end. An
    # area added to the suite must not disappear from the site merely because
    # this recipe was not updated in the same commit.
    for src in "$generated"/*.md; do
      name="$(basename "$src" .md)"
      case "$name" in conformance|catalogue|residual) continue ;; esac
      if [ -f "$section/$name.md" ]; then continue; fi
      weight=$((weight + 1))
      echo "note: publishing unlisted area $name; add it to the ordered list in publish-hugo" >&2
      publish_area "$src" "$name" "$weight"
    done

    if [ -f "$generated/catalogue.md" ]; then
      {
        frontmatter 'Open-source catalogue' 3 \
          'The open-source projects the Vulnetix TEA server publishes as TEA products, listed by paging the API itself.'
        tail -n +2 "$generated/catalogue.md"
      } > "$docs/catalogue.md"
    fi

    # residual.md is deliberately NOT published. It names records left in a
    # catalogue for an operator to purge, which is an internal maintenance note
    # and not something a public documentation site should carry. Its link is
    # stripped from the index above for the same reason.

    echo "staged into $docs:"
    ls -1 "$docs"
    echo
    echo "review and commit in the CLI repository; nothing was committed here or there"
