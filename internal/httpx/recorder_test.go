package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordThenReplayReturnsTheSameResponse(t *testing.T) {
	served := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	req := Request{
		Area: "consumer", Seq: 7, Name: "read one product",
		Method: http.MethodGet, URL: srv.URL,
		Header: http.Header{"Authorization": {"Bearer very-secret"}},
	}

	live := New(ModeLive, dir, true, srv.Client())
	first, err := live.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("live request: %v", err)
	}
	if first.Status != http.StatusTeapot || string(first.Body) != `{"hello":"world"}` {
		t.Fatalf("live response is %d %q", first.Status, first.Body)
	}
	if err := live.WriteIndex(); err != nil {
		t.Fatalf("write index: %v", err)
	}

	// The evidence must be named from the area, the sequence and the case,
	// because that is what a replay reconstructs the filename from.
	stem := filepath.Join(dir, "responses", "consumer", "0007-get-read-one-product")
	if _, err := os.Stat(stem + ".json"); err != nil {
		t.Errorf("the response body was not stored where a replay will look: %v", err)
	}
	meta, err := os.ReadFile(stem + ".meta.json")
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	if strings.Contains(string(meta), "very-secret") {
		t.Error("the recorded request contains the credential; reports are meant to be publishable")
	}
	if !strings.Contains(string(meta), "redacted") {
		t.Error("the Authorization header was dropped rather than redacted")
	}

	replay := New(ModeReplay, dir, true, srv.Client())
	second, err := replay.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if served != 1 {
		t.Errorf("the server was asked %d times; a replay must make no requests", served)
	}
	if second.Status != first.Status || string(second.Body) != string(first.Body) {
		t.Errorf("replay returned %d %q, live returned %d %q",
			second.Status, second.Body, first.Status, first.Body)
	}
	if !second.Replayed {
		t.Error("a replayed response is not marked as replayed")
	}
}

func TestReplayNamesTheFileItExpected(t *testing.T) {
	dir := t.TempDir()
	replay := New(ModeReplay, dir, true, nil)
	_, err := replay.Do(context.Background(), Request{
		Area: "consumer", Seq: 3, Name: "a case the recorded run never ran",
		Method: http.MethodGet, URL: "https://example.test/x",
	})
	if err == nil {
		t.Fatal("replaying a request with no recording should fail")
	}
	if !strings.Contains(err.Error(), "0003-get-a-case-the-recorded-run-never-ran.meta.json") {
		t.Errorf("the error does not name the missing file: %v", err)
	}
}

func TestDryRunStoresNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	rec := New(ModeDryRun, dir, true, srv.Client())
	res, err := rec.Do(context.Background(), Request{
		Area: "consumer", Seq: 1, Name: "probe", Method: http.MethodGet, URL: srv.URL,
	})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if res.Status != http.StatusOK {
		t.Errorf("status is %d", res.Status)
	}
	if !res.BodyDiscarded {
		t.Error("a dry-run response is not marked as one")
	}
	// The body is read: a dry run has to follow discovery and seed fixtures to
	// know which endpoints to check at all. What it must not do is write.
	if len(res.Body) == 0 || res.Bytes == 0 {
		t.Error("a dry run did not read the body, so it cannot navigate the object graph")
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		t.Errorf("a dry run wrote %d entries to disk", len(entries))
	}
}

func TestDuplicateSequenceIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	rec := New(ModeLive, t.TempDir(), true, srv.Client())
	req := Request{Area: "consumer", Seq: 1, Name: "same name", Method: http.MethodGet, URL: srv.URL}

	if _, err := rec.Do(context.Background(), req); err != nil {
		t.Fatalf("first request: %v", err)
	}
	// Two cases claiming one recording name would silently overwrite each
	// other's evidence and make the run unreplayable, so it is a hard error.
	if _, err := rec.Do(context.Background(), req); err == nil {
		t.Error("a second case with the same area, sequence and name was accepted")
	}
}

func TestTransportFailureIsAFindingNotAnError(t *testing.T) {
	rec := New(ModeLive, t.TempDir(), false, DefaultClient())
	res, err := rec.Do(context.Background(), Request{
		Area: "discovery", Seq: 1, Name: "unreachable",
		Method: http.MethodGet, URL: "https://127.0.0.1:1/nope",
	})
	if err != nil {
		t.Fatalf("a refused connection should not abandon the run: %v", err)
	}
	if res.TransportError == "" {
		t.Error("a refused connection produced no transport error to report")
	}
}

func TestRecordKeyIsStable(t *testing.T) {
	for _, tc := range []struct {
		seq                int
		method, name, want string
	}{
		{1, "GET", "default page", "0001-get-default-page"},
		{42, "post", "reject a malformed body", "0042-post-reject-a-malformed-body"},
		{7, "", "", "0007-get-request"},
		{3, "DELETE", "delete the product/release", "0003-delete-delete-the-product-release"},
	} {
		if got := RecordKey(tc.seq, tc.method, tc.name); got != tc.want {
			t.Errorf("RecordKey(%d, %q, %q) is %q, expected %q",
				tc.seq, tc.method, tc.name, got, tc.want)
		}
	}
}
