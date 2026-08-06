package report

import (
	"strings"
	"testing"

	pubarea "github.com/0x73746F66/owasp-tea-conformance/internal/area/provider"
	"github.com/0x73746F66/owasp-tea-conformance/internal/config"
	"github.com/0x73746F66/owasp-tea-conformance/internal/runner"
)

func TestPublisherSectionMapsInformationalWorkflowToRunEvidence(t *testing.T) {
	r := Report{
		Areas: []config.Area{config.AreaProvider, config.AreaSPDX},
		Publisher: pubarea.Findings{
			Implemented: true,
			Model:       pubarea.ModelRelease,
			SpecVersion: "0.4.0",
			NamePrefix:  "conformance",
			RunKey:      "run-1",
			PURL:        "pkg:generic/conformance/run-1",
		},
	}
	r.Efficacy.Artifacts = 8
	r.Efficacy.WithChecksum = 7
	r.Efficacy.WithSignature = 3
	r.Efficacy.Collections = 4
	r.Efficacy.EmptyCollections = 1
	r.Efficacy.MultiRevision = 2
	r.Efficacy.MaxRevision = 3
	r.Efficacy.MaxCollectionVersion = 5
	r.SPDX.CLERead = 6

	for _, id := range []string{
		"createTeaComponentRelease", "createTeaProductRelease",
		"publishTeaComponentReleaseCollection", "publishTeaProductReleaseCollection",
		"createTeaArtifact", "uploadTeaArtifactContent", "updateTeaArtifact",
		"getTeaProductByUuid", "getLatestArtifact",
	} {
		r.Results = append(r.Results, runner.Result{
			Area: config.AreaProvider, OperationID: id,
			GotStatus: 200, Pass: true,
		})
	}

	got := r.publisherSection()
	for _, want := range []string{
		"### Publisher workflow design",
		publisherWorkflowURL,
		"draft, informational design",
		"do not\nchange the conformance verdict",
		"| Stable release identity |",
		"| Artifact preparation, signing and validation |",
		"7 carried a checksum and 3 exposed a signature URL",
		"consumer visibility demonstrated",
		"2 artifacts had more than one revision (deepest revision 3)",
		"inspected 6 lifecycle documents",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("publisher report does not contain %q:\n%s", want, got)
		}
	}
}

func TestPublisherWorkflowSectionStillExplainsAnUnimplementedAPI(t *testing.T) {
	r := Report{Publisher: pubarea.Findings{
		Model:  pubarea.ModelRelease,
		Detail: "the publication endpoint was not found",
	}}

	got := r.publisherSection()
	if !strings.Contains(got, "### Publisher workflow design") {
		t.Fatalf("workflow section was omitted when publication was unavailable:\n%s", got)
	}
	if !strings.Contains(got, "No matching publication operation was exercised") ||
		!strings.Contains(got, "| not assessed |") {
		t.Errorf("unavailable workflow evidence was not disclosed:\n%s", got)
	}
}

func TestConsumerSectionAssessesArtifactRetrievalProfiles(t *testing.T) {
	r := Report{Areas: []config.Area{
		config.AreaConsumer, config.AreaCycloneDX, config.AreaProvenance,
	}}
	r.Fixtures.ArtifactSeen = true
	r.Fixtures.ArtifactUUID = "2c7909ca-ce13-4b27-9cfa-d99a756884ac"
	r.Efficacy.Artifacts = 4
	r.Efficacy.WithDownloadURL = 4
	r.Efficacy.WithChecksum = 3
	r.Efficacy.WithSignature = 2
	r.Results = []runner.Result{
		{Area: config.AreaConsumer, OperationID: "getLatestArtifact", GotStatus: 200, Pass: true},
		{Area: config.AreaConsumer, OperationID: "getArtifactByVersion", GotStatus: 200, Pass: true},
		{Area: config.AreaConsumer, OperationID: "getArtifactByVersion", Category: "negative", GotStatus: 404, Pass: true},
		{Area: config.AreaConsumer, OperationID: "getArtifactByVersion", Category: "negative", GotStatus: 400, Pass: true},
		{Area: config.AreaCycloneDX, OperationID: "artifactDownload", GotStatus: 200, Pass: true},
		{Area: config.AreaProvenance, OperationID: "artifactDownload", GotStatus: 200, Optional: true},
		{Area: config.AreaProvenance, OperationID: "artifactSignature", GotStatus: 200, Pass: true},
	}

	got := r.consumerSection()
	for _, want := range []string{
		"## Artifact retrieval and trust validation",
		consumerArtifactRetrievalURL,
		"version 1.0, describes a draft",
		"not demonstrate conformance to the Trust Architecture profile",
		"| Base TEA: artifact retrieval (MUST) |",
		"4 of 4 artifacts",
		"partially demonstrated",
		"optional compatibility feature observed",
		"independent evidence-bundle retrieval (MUST)",
		"Attestation artifacts and detached signatures are not",
		"| not demonstrated |",
		"2 artifact-content responses were retrieved and 1 passed",
		"2 artifact metadata error-path cases were exercised; 2 conformed",
		"| High-assurance profile |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("consumer report does not contain %q:\n%s", want, got)
		}
	}
}
