// Package provenance checks the evidence that says where a published artifact
// came from and that it has not been altered since.
//
// TEA's object model is careful about identity — an artifact is immutable and
// versioned — but identity is only worth something if a consumer can verify it.
// That verification has three parts, and a publisher can conform to the object
// specification while supplying none of them:
//
//   - a checksum, so the bytes can be matched to the record;
//   - a signature, so the record can be matched to the publisher;
//   - an attestation, so the build that produced the bytes can be described.
//
// This area reports how much of that a provider actually publishes, and
// validates whatever it finds.
package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/0x73746F66/owasp-tea-conformance/internal/area/inventory"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

// Limits on how much of somebody else's catalogue one run pulls down. Both are
// stated in the report when they bite.
const (
	AttestationLimit = 10
	SignatureLimit   = 10
)

const (
	seqAttestation = 1
	seqSignature   = 100
)

// Attestation is one downloaded provenance or attestation document.
type Attestation struct {
	ArtifactUUID  string   `json:"artifactUuid"`
	ArtifactType  string   `json:"artifactType"`
	ProductName   string   `json:"productName,omitempty"`
	URL           string   `json:"url"`
	StatementType string   `json:"statementType,omitempty"`
	PredicateType string   `json:"predicateType,omitempty"`
	Subjects      int      `json:"subjects"`
	Digests       []string `json:"digestAlgorithms,omitempty"`
	Recognised    bool     `json:"recognised"`
}

// Findings is what this area observed.
type Findings struct {
	Artifacts int `json:"artifactsInspected"`

	// Coverage is the part a reader compares between providers.
	WithChecksum  int `json:"artifactsWithChecksum"`
	WithSignature int `json:"artifactsWithSignature"`
	WithMediaType int `json:"artifactsWithMediaType"`
	Immutable     int `json:"artifactsWithMoreThanOneRevision"`

	ChecksumAlgorithms map[string]int `json:"checksumAlgorithms"`
	ArtifactTypes      map[string]int `json:"artifactTypes"`

	Attestations        []Attestation `json:"attestations,omitempty"`
	AttestationsSkipped int           `json:"attestationsSkippedByLimit,omitempty"`
	SignaturesChecked   int           `json:"signaturesChecked"`
	SignaturesSkipped   int           `json:"signaturesSkippedByLimit,omitempty"`
}

// Run inspects the provenance evidence in an inventory.
func Run(ctx context.Context, c *runner.Client, inv inventory.Inventory, concurrency int) ([]runner.Result, Findings) {
	found := Findings{
		ChecksumAlgorithms: map[string]int{},
		ArtifactTypes:      map[string]int{},
		Artifacts:          len(inv.Artifacts),
	}
	var results []runner.Result

	// ── Coverage, counted from what the API already told us ─────────────────
	var attestations []inventory.Artifact
	var signatures []struct {
		artifact inventory.Artifact
		url      string
	}
	for _, a := range inv.Artifacts {
		if a.Type != "" {
			found.ArtifactTypes[a.Type]++
		}
		if a.Version > 1 {
			found.Immutable++
		}
		for _, f := range a.Formats {
			if f.MediaType != "" {
				found.WithMediaType++
			}
			if len(f.Checksums) > 0 {
				found.WithChecksum++
			}
			for _, ck := range f.Checksums {
				if ck.AlgType != "" {
					found.ChecksumAlgorithms[ck.AlgType]++
				}
			}
			if f.SignatureURL != "" {
				found.WithSignature++
				signatures = append(signatures, struct {
					artifact inventory.Artifact
					url      string
				}{a, f.SignatureURL})
			}
			break
		}
		if isAttestation(a) {
			attestations = append(attestations, a)
		}
	}

	// ── The attestations themselves ─────────────────────────────────────────
	sort.Slice(attestations, func(i, j int) bool { return attestations[i].UUID < attestations[j].UUID })
	if len(attestations) > AttestationLimit {
		found.AttestationsSkipped = len(attestations) - AttestationLimit
		attestations = attestations[:AttestationLimit]
	}
	cases := make([]runner.Case, 0, len(attestations))
	// Kept alongside the cases rather than indexed back into `attestations`:
	// an artifact with no download URL gets no case, and the two slices would
	// otherwise drift apart by one and mislabel every finding after it.
	attTargets := make([]inventory.Artifact, 0, len(attestations))
	for _, a := range attestations {
		url := firstURL(a)
		if url == "" {
			continue
		}
		attTargets = append(attTargets, a)
		cases = append(cases, runner.Case{
			Area: config.AreaProvenance, Seq: seqAttestation + len(cases),
			OperationID: "artifactDownload",
			Name:        "attestation document for " + label(a),
			Category:    "provenance",
			AbsoluteURL: url,
			WantStatus:  http.StatusOK,
			Accept:      "application/json",
			// TEA names no required format for an attestation, so the bytes are
			// whatever the publisher chose.
			AnyContentType: true,
			// And for the same reason a document this suite cannot parse is a
			// fact to report, not a conformance failure: it may be a perfectly
			// valid attestation in a format the specification never named.
			Optional: true,
		})
	}
	attResults := runner.Run(ctx, c, nil, cases, concurrency)
	for i, res := range attResults {
		if res.GotStatus != http.StatusOK {
			attResults[i] = res
			continue
		}
		att, problems := inspectAttestation(attTargets[i], cases[i].AbsoluteURL, res.Body)
		found.Attestations = append(found.Attestations, att)
		res.Errors = append(res.Errors, problems...)
		res.Pass = len(res.Errors) == 0
		attResults[i] = res
	}
	results = append(results, attResults...)

	// ── Signatures ──────────────────────────────────────────────────────────
	//
	// The signature is not verified — that needs a trust root this suite has no
	// way to establish, and inventing one would be worse than saying so. What
	// is checked is that the published URL serves something, because a
	// signature a consumer cannot fetch protects nothing.
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].artifact.UUID < signatures[j].artifact.UUID })
	if len(signatures) > SignatureLimit {
		found.SignaturesSkipped = len(signatures) - SignatureLimit
		signatures = signatures[:SignatureLimit]
	}
	sigCases := make([]runner.Case, 0, len(signatures))
	for i, s := range signatures {
		sigCases = append(sigCases, runner.Case{
			Area: config.AreaProvenance, Seq: seqSignature + i,
			OperationID: "artifactSignature",
			Name:        "published signature for " + label(s.artifact),
			Category:    "provenance",
			AbsoluteURL: s.url,
			WantStatus:  http.StatusOK,
			Accept:      "*/*",
		})
	}
	found.SignaturesChecked = len(sigCases)
	results = append(results, runner.Run(ctx, c, nil, sigCases, concurrency)...)

	// ── Coverage verdicts ───────────────────────────────────────────────────
	//
	// These are reported, never failed. TEA does not require a publisher to
	// sign or attest anything, and a suite that failed providers for choosing
	// not to would be enforcing a policy rather than a specification.
	results = append(results,
		coverage("artifacts carry a checksum", found.WithChecksum, found.Artifacts,
			"a consumer cannot verify the bytes it downloads against the record"),
		coverage("artifacts carry a signature", found.WithSignature, found.Artifacts,
			"a consumer cannot verify who published the record"),
		coverage("artifacts carry a media type", found.WithMediaType, found.Artifacts,
			"a consumer has to guess how to parse the download"),
	)
	if found.AttestationsSkipped > 0 {
		results = append(results, runner.Result{
			Area: config.AreaProvenance, Seq: 0,
			Case: fmt.Sprintf("%d further attestation(s) were not downloaded (limit %d)",
				found.AttestationsSkipped, AttestationLimit),
			Category: "coverage", Method: "—", Pass: true, Optional: true,
		})
	}
	return results, found
}

func coverage(what string, have, total int, why string) runner.Result {
	res := runner.Result{
		Area: config.AreaProvenance, Seq: 0,
		OperationID: "provenanceCoverage",
		Category:    "coverage",
		Method:      "—",
		Pass:        true,
		Optional:    true,
		Case:        fmt.Sprintf("%d of %d %s", have, total, what),
	}
	if total > 0 && have == 0 {
		res.Warnings = append(res.Warnings, "none do, so "+why)
	}
	return res
}

// isAttestation recognises artifacts that carry a signed claim about a build.
//
// `BUILD_META` is deliberately not on the list. TEA uses it for build metadata,
// and in practice that means the archived inputs — a go.mod, a Cargo.lock, a
// workflow file, a pre-commit hook. Those are exactly what a publisher should
// be publishing under that type, and treating them as attestations made the
// suite demand an in-toto Statement of a lockfile and report a correctly-served
// one as a failure.
//
// `FORMULATION` is likewise a description of how something was built rather
// than a signed statement about it.
func isAttestation(a inventory.Artifact) bool {
	switch a.Type {
	case "ATTESTATION", "CERTIFICATION":
		return true
	}
	// Outside those types, only an explicit signal counts. A name is weak
	// evidence, so it has to name the format rather than merely mention the
	// subject.
	haystack := strings.ToLower(a.Name)
	for _, f := range a.Formats {
		haystack += " " + strings.ToLower(f.MediaType+" "+f.Description)
	}
	for _, marker := range []string{"in-toto", "slsa", "attestation", "provenance"} {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}

// inspectAttestation parses whatever the publisher served and says what it is.
//
// in-toto Statements are the shape SLSA provenance and most attestation
// tooling emits, so they are recognised specifically; anything else is
// reported as unrecognised rather than as wrong, because TEA does not name a
// required format for this artifact type.
func inspectAttestation(a inventory.Artifact, url string, body []byte) (Attestation, []string) {
	att := Attestation{
		ArtifactUUID: a.UUID,
		ArtifactType: a.Type,
		ProductName:  a.ProductName,
		URL:          url,
	}
	var statement struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(body, &statement); err != nil {
		return att, []string{"the attestation is not JSON: " + err.Error()}
	}
	att.StatementType = statement.Type
	att.PredicateType = statement.PredicateType
	att.Subjects = len(statement.Subject)

	algs := map[string]bool{}
	for _, s := range statement.Subject {
		for alg := range s.Digest {
			algs[alg] = true
		}
	}
	for alg := range algs {
		att.Digests = append(att.Digests, alg)
	}
	sort.Strings(att.Digests)

	if statement.Type == "" && statement.PredicateType == "" {
		// Not an in-toto Statement. Say so and stop: judging an unknown format
		// against in-toto's rules would manufacture failures.
		return att, nil
	}
	att.Recognised = true

	var problems []string
	if !strings.Contains(statement.Type, "in-toto.io/Statement") {
		problems = append(problems, fmt.Sprintf(
			"_type is %q; an in-toto Statement declares in-toto.io/Statement", statement.Type))
	}
	if statement.PredicateType == "" {
		problems = append(problems, "the statement declares no predicateType, so a consumer "+
			"cannot tell what kind of claim it is")
	}
	if len(statement.Subject) == 0 {
		problems = append(problems, "the statement has no subject, so it attests to nothing")
	}
	for i, s := range statement.Subject {
		if len(s.Digest) == 0 {
			problems = append(problems, fmt.Sprintf(
				"subject[%d] (%s) carries no digest, so it cannot be matched to any artifact", i, s.Name))
		}
	}
	return att, problems
}

func firstURL(a inventory.Artifact) string {
	for _, f := range a.Formats {
		if f.URL != "" {
			return f.URL
		}
	}
	return ""
}

func label(a inventory.Artifact) string {
	name := a.Name
	if name == "" {
		name = a.Type
	}
	if a.ProductName != "" {
		return name + " of " + a.ProductName
	}
	return name
}
