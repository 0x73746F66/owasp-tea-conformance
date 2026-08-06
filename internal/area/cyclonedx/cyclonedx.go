// Package cyclonedx downloads the BOM documents a provider publishes and
// validates them against the CycloneDX version each one declares.
//
// This is the area that separates "the API is correct" from "the documents are
// usable". A TEA server can serve a perfectly conformant artifact record whose
// download URL returns a CycloneDX document that no consumer can parse, and
// nothing in the object API would notice: the artifact metadata is TEA's, the
// bytes behind it are not.
//
// Validation is delegated to the shared CycloneDX module rather than
// reimplemented, so a document means the same thing here as it does in every
// other tool built on it.
package cyclonedx

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	cdx "github.com/Vulnetix/vdb-cyclonedx"

	"github.com/0x73746F66/owasp-tea-conformance/internal/area/inventory"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

// DownloadLimit caps how many BOM documents one run fetches.
//
// A large catalogue can publish thousands, and a conformance run is a guest on
// somebody else's infrastructure. The report always states the cap and how many
// documents were skipped by it, because a truncated sample presented as a full
// one is the kind of quiet dishonesty this suite exists to catch.
const DownloadLimit = 25

const seqDownload = 1

// Document is one downloaded BOM.
type Document struct {
	ArtifactUUID string `json:"artifactUuid"`
	ArtifactName string `json:"artifactName,omitempty"`
	ArtifactType string `json:"artifactType,omitempty"`
	ProductName  string `json:"productName,omitempty"`
	URL          string `json:"url"`
	MediaType    string `json:"mediaType,omitempty"`
	SpecVersion  string `json:"specVersion,omitempty"`
	Components   int    `json:"components"`
	Valid        bool   `json:"valid"`

	// Raw is kept so the SPDX area can read licences out of the same bytes
	// rather than downloading everything twice.
	Raw []byte `json:"-"`
}

// Findings is what this area observed.
type Findings struct {
	Candidates  int            `json:"bomArtifacts"`
	Downloaded  int            `json:"downloaded"`
	Skipped     int            `json:"skippedByLimit"`
	SpecVersion map[string]int `json:"specVersions"`
	Documents   []Document     `json:"documents"`
}

// Run downloads and validates the BOM documents in an inventory.
func Run(ctx context.Context, c *runner.Client, inv inventory.Inventory, concurrency int) ([]runner.Result, Findings) {
	found := Findings{SpecVersion: map[string]int{}}

	type target struct {
		artifact inventory.Artifact
		format   inventory.Format
	}
	var targets []target
	for _, a := range inv.Artifacts {
		for _, f := range a.Formats {
			if f.URL == "" || !looksLikeCycloneDX(a, f) {
				continue
			}
			targets = append(targets, target{artifact: a, format: f})
			break // one format per artifact is enough to judge the document
		}
	}
	// Sorted so the sample, and every recording name in it, is the same on a
	// re-run against an unchanged catalogue.
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].artifact.UUID != targets[j].artifact.UUID {
			return targets[i].artifact.UUID < targets[j].artifact.UUID
		}
		return targets[i].artifact.Version < targets[j].artifact.Version
	})
	found.Candidates = len(targets)
	if len(targets) > DownloadLimit {
		found.Skipped = len(targets) - DownloadLimit
		targets = targets[:DownloadLimit]
	}
	found.Downloaded = len(targets)

	results := make([]runner.Result, len(targets))
	docs := make([]Document, len(targets))

	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, t := range targets {
		g.Go(func() error {
			doc, res := fetchAndValidate(gctx, c, seqDownload+i, t.artifact, t.format)
			mu.Lock()
			results[i] = res
			docs[i] = doc
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	for _, d := range docs {
		if d.SpecVersion != "" {
			found.SpecVersion[d.SpecVersion]++
		}
	}
	found.Documents = docs

	// The cap is stated as a result rather than a log line, so it survives into
	// the report a reader actually sees.
	if found.Skipped > 0 {
		results = append(results, runner.Result{
			Area: config.AreaCycloneDX, Seq: 0,
			Case: fmt.Sprintf("%d further BOM document(s) were not downloaded (limit %d)",
				found.Skipped, DownloadLimit),
			Category: "coverage", Method: "—", Pass: true, Optional: true,
		})
	}
	return results, found
}

func fetchAndValidate(
	ctx context.Context,
	c *runner.Client,
	seq int,
	a inventory.Artifact,
	f inventory.Format,
) (Document, runner.Result) {
	doc := Document{
		ArtifactUUID: a.UUID,
		ArtifactName: a.Name,
		ArtifactType: a.Type,
		ProductName:  a.ProductName,
		URL:          f.URL,
		MediaType:    f.MediaType,
	}
	name := "download and validate " + describe(a)
	body, res := runner.GetRaw(ctx, c, config.AreaCycloneDX, seq, name, f.URL, acceptFor(f.MediaType))
	res.OperationID = "artifactDownload"
	res.Category = "cyclonedx"
	if res.GotStatus != 200 {
		res.Pass = false
		if len(res.Errors) == 0 {
			res.Errors = append(res.Errors, fmt.Sprintf(
				"the published download URL answered HTTP %d; a consumer following this artifact "+
					"record gets nothing", res.GotStatus))
		}
		return doc, res
	}
	doc.Raw = body

	version, violations, err := cdx.ValidateCycloneDX(body)
	doc.SpecVersion = version
	switch {
	case err != nil:
		res.Errors = append(res.Errors, "not a usable CycloneDX document: "+err.Error())
	case version == "":
		// The shared validator passes through anything that is not CycloneDX,
		// which is right for a general parser and wrong here: this artifact was
		// advertised as a CycloneDX BOM.
		res.Errors = append(res.Errors, "the document does not declare bomFormat CycloneDX and a "+
			"specVersion, but the artifact record advertises it as a CycloneDX BOM")
	case len(violations) > 0:
		for _, v := range violations[:min(len(violations), 10)] {
			res.Errors = append(res.Errors, fmt.Sprintf("CycloneDX %s: %s", version, describeViolation(v)))
		}
		if len(violations) > 10 {
			res.Errors = append(res.Errors,
				fmt.Sprintf("and %d further schema violations", len(violations)-10))
		}
	default:
		doc.Valid = true
	}
	res.SchemaChecked = true
	res.SchemaValid = doc.Valid
	res.SchemaPointer = "CycloneDX " + version

	if parsed, perr := cdx.ParseCDX(body); perr == nil && parsed != nil {
		doc.Components = len(parsed.Components)
	}

	// Assertions the CycloneDX schema does not make but a consumer relies on.
	if problem := checkSerialNumber(body); problem != "" {
		res.Errors = append(res.Errors, problem)
	}
	if problem := f.ChecksumMismatch(body); problem != "" {
		res.Errors = append(res.Errors, problem)
	}

	res.Pass = len(res.Errors) == 0
	return doc, res
}

// looksLikeCycloneDX decides whether an artifact format is worth downloading as
// a BOM. The media type is authoritative where it is present; the artifact type
// and name are the fallback, because publishers do sometimes omit it.
func looksLikeCycloneDX(a inventory.Artifact, f inventory.Format) bool {
	mt := strings.ToLower(f.MediaType)
	switch {
	case strings.Contains(mt, "cyclonedx"):
		return true
	case strings.Contains(mt, "spdx"):
		return false // a real BOM, but not one this area validates
	}
	if a.Type != "BOM" {
		return false
	}
	name := strings.ToLower(a.Name + " " + f.Description)
	return strings.Contains(name, "cyclonedx") || strings.Contains(name, "cdx") ||
		strings.Contains(name, "sbom") || strings.Contains(name, "bom")
}

func acceptFor(mediaType string) string {
	if mediaType != "" {
		return mediaType
	}
	return "application/vnd.cyclonedx+json, application/json"
}

// checkSerialNumber asserts the identity a consumer deduplicates BOMs by.
func checkSerialNumber(body []byte) string {
	var bom struct {
		SerialNumber string `json:"serialNumber"`
	}
	if err := json.Unmarshal(body, &bom); err != nil {
		return ""
	}
	if bom.SerialNumber == "" {
		return ""
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		return fmt.Sprintf("serialNumber %q is not a urn:uuid, so a consumer cannot use it "+
			"to tell two documents apart", bom.SerialNumber)
	}
	return ""
}

func describe(a inventory.Artifact) string {
	name := a.Name
	if name == "" {
		name = a.Type
	}
	if a.ProductName != "" {
		return name + " of " + a.ProductName
	}
	return name
}

func describeViolation(v cdx.ValidationViolation) string {
	where := v.Path
	if where == "" {
		where = "(document root)"
	}
	return where + ": " + v.Message
}

func short(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[:16] + "…"
}
