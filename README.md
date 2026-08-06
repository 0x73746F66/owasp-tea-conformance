# owasp-tea-conformance

A conformance and performance test suite for the [OWASP Transparency Exchange
API][tea]. Point it at a provider's DNS name and it follows the specification's
own discovery chain to that provider's API, then checks the whole surface —
consumption, publication, Insights, CEL, purls, CycloneDX, SPDX licences,
provenance and latency — against the specifications fetched live from their
authoritative repositories.

It is a black-box HTTP client. It knows nothing about any implementation, every
judgement comes from comparing a response against the specification's own bytes,
and every request and response it makes is kept so a report can be regenerated
and checked offline.

[tea]: https://github.com/CycloneDX/transparency-exchange-api

## Test areas

| Area | What it establishes |
|---|---|
| `discovery` | DNS resolves, `.well-known/tea` is HTTPS-only and schema-valid, endpoint and version selection follow SemVer and priority, TEIs resolve |
| `consumer` | Every operation of the consumption API, through its success path, its declared error paths and its pagination rules |
| `purl` | Published package URLs parse, round-trip through the identifier filter, and resolve as purl-typed TEIs |
| `cyclonedx` | The BOM documents behind the artifact records download, validate against the version each declares, and match their published checksums |
| `spdx` | Licence identifiers in those documents and in lifecycle events are real, current, correctly-cased SPDX identifiers |
| `insights` | The Insights API answers the specification's own worked examples with valid CycloneDX, defaults to 1.6 and negotiates 1.7 |
| `cel` | The server's idea of the query language matches `google/cel-go`, the reference implementation |
| `provenance` | Checksum, signature and attestation coverage, and whatever attestations exist parse as in-toto statements |
| `performance` | Cold latency and cached latency, measured and reported separately, with spread — and correctness under concurrency |
| `provider` | The publication API, as a create → revise → read-back → delete round-trip |

Two things are reported alongside rather than as pass/fail. **Efficacy** is what
the published graph actually contains: conformance cannot tell a complete
publisher from one that emits a tenth of its data, because both validate. The
**open-source sample** is how much of a known 300-project set a catalogue
covers, which is what makes two providers comparable.

## Configuration

Copy `config.example.yaml` to `config.yaml` and edit. It has two levels: a global
block that is the default for every provider, and a per-provider block that says
only what is different.

```yaml
areas: [discovery, consumer, purl, cyclonedx, spdx, insights, cel, provenance, performance, provider]
exclude: []                    # dropped for every provider

output:
  dir: reports
  splitByArea: true            # one Markdown file per area, plus an index
  retainResponses: true        # keep every response body; needed to reproduce

packages:                      # the open-source sample, as purls
  - pkg:github/apache/echarts
  # …300 of them ship in the example

providers:
  - name: vulnetix
    dns: vulnetix.com          # discovery starts here
    auth:
      scheme: apikey           # none | bearer | basic | apikey
      credentialEnv: TEA_VULNETIX_CREDENTIAL
    exclude: [provider]        # dropped for this provider only
    output:                    # overrides the global block
      dir: reports/vulnetix
      splitByArea: false
    packages: []               # empty inherits the global list
```

Credentials are never written in the file — only the name of the environment
variable holding one. A provider with no credential is read unauthenticated, and
the report says so.

`just plan` prints exactly what the file resolves to — which areas run against
which provider, where each report lands, and which credentials are missing from
your environment — without making a single request. Run it after any edit.

### Which specifications are used

Fetched at the start of every run and written into that run's own directory, so
a report is always checkable against the document it judged by. Change `specs.*.ref`
to pin a tag or a commit instead of tracking a branch.

Two things about the upstream set are worth knowing before you read a report,
and both are disclosed in every report the suite writes:

- **The publication document is a different generation from the consumption
  one.** Upstream's `spec/openapi.yaml` is 0.4.0 and describes products,
  components and releases; `spec/publisher/openapi.json` beside it is 0.0.2 and
  describes products, *leaves* and collections. The suite detects which model a
  document describes and runs the matching round-trip, so a server implementing
  the current consumption API reports the publication operations as
  not-implemented rather than as failures. `config.example.yaml` shows how to
  point `specs.publisher` at the publication overlay proposed for the 0.4.x
  model instead.
- **The Insights specification is not upstream yet.** The example points at the
  branch it is proposed from, and every report says so next to the digest.

The publication document also declares `components.responses` and
`components.parameters` twice. JSON parsers keep the last definition, so the
suite parses JSON documents with a JSON parser — as any client would — and
reports the duplication instead of failing on it.

### The publication round-trip writes to your provider

The `provider` area creates real objects. They are named deterministically from
`writeCycle` in the config, and the round-trip's final cases delete them — so
verifying that delete works *is* the cleanup, and a re-run reclaims anything an
interrupted run left behind. Whatever survives is listed in `reports/residual.md`
with the exact `DELETE` request that removes it.

Exclude the area for any provider you do not own.

## Running

```sh
just plan                  # what would run; no requests
just run                   # every provider
just run vulnetix          # one provider
just area consumer         # one area, every provider
just area cel vulnetix     # one area, one provider

just dryrun                # check every endpoint answers; store nothing, judge nothing
just reproduce reports/vulnetix   # regenerate the reports offline from a recorded run

just test                  # the suite's own tests
just lint                  # gofmt + go vet
just build                 # ./bin/tea-conformance
just fetch-specs           # download the specifications and print their digests
```

`just test` includes the suite's negative controls: a set of known-bad payloads
that must be *rejected*, because a validator that silently accepted everything
would produce exactly the same green report as a correct one, plus positive
controls so it cannot pass by rejecting everything either. Setting
`TEA_CONFORMANCE_ONLINE=1` adds the tests that fetch the real upstream documents
and check the suite has not drifted from them.

`--dryrun` issues one request per declared endpoint to confirm it is reachable,
reads each response to completion so the latency is comparable, and then discards
it: nothing is written, nothing is validated, and no publication operation is
attempted.

`--reproduce-from-dir` makes no network requests at all. It reads the
specifications and every recorded response out of a previous run's directory and
regenerates the reports from them. A missing recording is a hard error naming the
file it expected, so a directory that cannot reproduce a run says so rather than
quietly producing a different report.

## Output

Each provider's run directory holds everything the report was derived from:

```
reports/<provider>/
  spec/            the exact specification bytes used, with SHA256SUMS
  responses/       every request and response, deterministically named
  reports/         conformance.md (or one file per area), report.json,
                   residual.md and residual.json
```

Recording filenames are derived from the area, a deterministic sequence number
and the case name — never from execution order — which is what lets a replay ask
for the same files in the same order. Authorization headers are redacted from the
stored requests.

The process exits non-zero when any provider is not conformant, so `just run` is
usable as a CI gate.

## Licence

Apache-2.0.
