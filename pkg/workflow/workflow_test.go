package workflow_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/chainguard-dev/ghscan/pkg/workflow"
	"github.com/google/go-github/v86/github"
)

// buildLogZip wraps logBody in a one-entry zip archive of the same
// shape that GitHub's logs API returns. The entry name is irrelevant
// to ExtractLogs.
func buildLogZip(t *testing.T, logBody string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("0_job.txt")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(logBody)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestExtractLogs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		body    []byte
		wantErr bool
		wantSub string
	}{
		{
			name:    "valid single-entry zip",
			body:    buildLogZip(t, "hello world"),
			wantSub: "hello world",
		},
		{
			name:    "non-zip data errors",
			body:    []byte("not a zip archive"),
			wantErr: true,
		},
		{
			name:    "empty input errors",
			body:    []byte{},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := workflow.ExtractLogs(bytes.NewReader(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("got %q, want substring %q", got, tc.wantSub)
			}
		})
	}
}

func TestParseLogs(t *testing.T) {
	t.Parallel()

	predef, ok := ioc.GetPredefinedIOC("tj-actions/changed-files")
	if !ok {
		t.Fatal("predefined IOC tj-actions/changed-files not found")
	}

	customMatcher, err := ioc.NewIOC(&ioc.Config{
		Name:    "test-custom",
		Content: []string{"DROP_THIS_TOKEN"},
	})
	if err != nil {
		t.Fatalf("build custom IOC: %v", err)
	}

	cases := []struct {
		name        string
		ioc         *ioc.IOC
		log         string
		wantHit     bool
		wantLineSub string
	}{
		{
			name:    "predefined ioc literal hit",
			ioc:     predef,
			log:     "2025-01-01T00:00:00.000Z something SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67 trailing\n",
			wantHit: true,
			// timestamp prefix is stripped from LineData.
			wantLineSub: "SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67",
		},
		{
			name:        "custom ioc literal hit",
			ioc:         customMatcher,
			log:         "innocent line\nDROP_THIS_TOKEN appears here\nthird\n",
			wantHit:     true,
			wantLineSub: "DROP_THIS_TOKEN",
		},
		{
			name:    "no match in benign log",
			ioc:     predef,
			log:     "nothing suspicious here at all\n",
			wantHit: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, found := workflow.ParseLogs(newTestLogger(), tc.log, 12345, tc.ioc)
			if !found {
				t.Fatal("ParseLogs always reports found=true for nil-checked IOC")
			}
			if len(findings) != 1 {
				t.Fatalf("expected exactly 1 finding envelope, got %d", len(findings))
			}
			f := findings[0]
			gotHit := f.LineData != "" || f.Encoded != "" || f.Decoded != ""
			if gotHit != tc.wantHit {
				t.Fatalf("hit=%v, want %v (line=%q encoded=%q decoded=%q)",
					gotHit, tc.wantHit, f.LineData, f.Encoded, f.Decoded)
			}
			if tc.wantLineSub != "" && !strings.Contains(f.LineData, tc.wantLineSub) {
				t.Fatalf("LineData=%q, want substring %q", f.LineData, tc.wantLineSub)
			}
		})
	}
}

func TestParseLogs_NilIOCReturnsNotFound(t *testing.T) {
	t.Parallel()

	findings, found := workflow.ParseLogs(newTestLogger(), "anything", 1, nil)
	if found {
		t.Fatal("expected found=false for nil IOC")
	}
	if findings != nil {
		t.Fatalf("expected nil findings, got %+v", findings)
	}
}

// makeWorkflowPage materializes one page of /actions/workflows as the
// envelope go-github expects: {"total_count": N, "workflows": [...]}.
// Each workflow carries a distinct ID and path so the test can assert
// which page produced the hit.
func makeWorkflowPage(t *testing.T, ids []int64, pathFor func(int64) string) []byte {
	t.Helper()
	wfs := make([]*github.Workflow, 0, len(ids))
	for _, id := range ids {
		wfs = append(wfs, &github.Workflow{
			ID:   new(id),
			Path: new(pathFor(id)),
		})
	}
	body, err := json.Marshal(struct {
		TotalCount int                `json:"total_count"`
		Workflows  []*github.Workflow `json:"workflows"`
	}{TotalCount: len(wfs), Workflows: wfs})
	if err != nil {
		t.Fatalf("marshal workflows: %v", err)
	}
	return body
}

// TestGetWorkflowByPath_PaginatesUntilMatch covers paging behavior:
// the list-workflows endpoint must be paged through until either the
// target path is found or NextPage is zero. The earlier implementation
// read only page 1 and silently missed any workflow on page 2+.
func TestGetWorkflowByPath_PaginatesUntilMatch(t *testing.T) {
	t.Parallel()

	const targetPath = ".github/workflows/page2.yml"

	cases := []struct {
		name      string
		wantPath  string
		wantID    int64
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "match on page two requires pagination",
			wantPath: targetPath,
			wantID:   201,
		},
		{
			name:      "missing path errors after exhausting pages",
			wantPath:  ".github/workflows/does-not-exist.yml",
			wantErr:   true,
			errSubstr: "not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var server *httptest.Server
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/actions/workflows") {
					t.Errorf("unexpected path: %s", r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				page := r.URL.Query().Get("page")
				w.Header().Set("Content-Type", "application/json")
				switch page {
				case "", "1":
					// Advertise page 2 via Link header so go-github
					// surfaces resp.NextPage=2.
					w.Header().Set(
						"Link",
						fmt.Sprintf(`<%s/repos/o/r/actions/workflows?page=2>; rel="next"`, server.URL),
					)
					ids := make([]int64, 100)
					for i := range ids {
						ids[i] = int64(i + 1)
					}
					_, _ = w.Write(makeWorkflowPage(t, ids, func(id int64) string {
						return fmt.Sprintf(".github/workflows/page1-%d.yml", id)
					}))
				case "2":
					// Page 2 holds the target workflow only.
					_, _ = w.Write(makeWorkflowPage(t, []int64{201}, func(_ int64) string {
						return targetPath
					}))
				default:
					t.Errorf("unexpected page: %s", page)
					w.WriteHeader(http.StatusInternalServerError)
				}
			})
			server = httptest.NewServer(handler)
			t.Cleanup(server.Close)

			gh, _ := newTestClients(t, server)

			got, err := workflow.GetWorkflowByPath(t.Context(), gh, "o", "r", tc.wantPath)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got workflow %+v", got)
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("err=%v, want substring %q", err, tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Fatal("expected non-nil workflow")
			}
			if got.GetID() != tc.wantID {
				t.Fatalf("ID=%d, want %d", got.GetID(), tc.wantID)
			}
			if got.GetPath() != tc.wantPath {
				t.Fatalf("Path=%q, want %q", got.GetPath(), tc.wantPath)
			}
		})
	}
}

// TestGetWorkflowByPath_ExceedsMaxPagesReturnsError pins the
// defensive cap on pagination: a server that perpetually advertises
// NextPage>0 must not pin the scanner indefinitely. After hitting the
// page cap the caller must see an explicit "exceeded maximum pages"
// error rather than spinning forever.
func TestGetWorkflowByPath_ExceedsMaxPagesReturnsError(t *testing.T) {
	t.Parallel()

	const pageCap = 3

	var server *httptest.Server
	var pagesServed int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/actions/workflows") {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Always advertise a next page. The target path is never on
		// any page so the loop must terminate via the page cap.
		pagesServed++
		nextPage := pagesServed + 1
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(
			"Link",
			fmt.Sprintf(`<%s/repos/o/r/actions/workflows?page=%d>; rel="next"`, server.URL, nextPage),
		)
		_, _ = w.Write(makeWorkflowPage(t, []int64{int64(pagesServed)}, func(id int64) string {
			return fmt.Sprintf(".github/workflows/decoy-%d.yml", id)
		}))
	})
	server = httptest.NewServer(handler)
	t.Cleanup(server.Close)

	gh, _ := newTestClients(t, server)

	wf, err := workflow.GetWorkflowByPathWithMaxPages(t.Context(), gh, "o", "r", ".github/workflows/never.yml", pageCap)
	if err == nil {
		t.Fatalf("expected error after exceeding max pages, got workflow %+v", wf)
	}
	if !strings.Contains(err.Error(), "exceeded maximum pages") {
		t.Fatalf("error %q does not mention exceeded maximum pages", err.Error())
	}
	if pagesServed > int32(pageCap) {
		t.Fatalf("server returned %d pages, want at most %d", pagesServed, pageCap)
	}
}

// TestGetWorkflowByPath_PropagatesAPIError covers the negative case
// where the upstream API fails on page 1 -- the caller must see the
// original error rather than a misleading "not found".
func TestGetWorkflowByPath_PropagatesAPIError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)

	gh, _ := newTestClients(t, ts)
	wf, err := workflow.GetWorkflowByPath(t.Context(), gh, "o", "r", ".github/workflows/whatever.yml")
	if err == nil {
		t.Fatalf("expected error, got workflow %+v", wf)
	}
	if strings.Contains(err.Error(), "not found") {
		t.Fatalf("got misleading not-found error: %v", err)
	}
}

// TestPaginate_PageCapTerminates pins the shared paginator helper: a
// server that perpetually advertises a non-zero next page must not
// pin the caller indefinitely.
func TestPaginate_PageCapTerminates(t *testing.T) {
	t.Parallel()

	const pageCap = 4
	calls := 0
	err := workflow.PaginateForTest(pageCap, "unit", func(_ int) (int, error) {
		calls++
		return calls + 1, nil
	})
	if err == nil {
		t.Fatal("expected error after exceeding cap")
	}
	if !strings.Contains(err.Error(), "exceeded maximum pages") {
		t.Fatalf("error %q does not mention exceeded maximum pages", err.Error())
	}
	if calls > pageCap {
		t.Fatalf("step invoked %d times, want at most %d", calls, pageCap)
	}
}

// TestListAllJobsCapped_ExceedsMaxPagesReturnsError verifies the
// jobs-listing pagination cap surfaces a precise error.
func TestListAllJobsCapped_ExceedsMaxPagesReturnsError(t *testing.T) {
	t.Parallel()

	const pageCap = 3
	var server *httptest.Server
	var pagesServed int32
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/actions/runs/55/jobs", func(w http.ResponseWriter, _ *http.Request) {
		pagesServed++
		nextPage := pagesServed + 1
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(
			"Link",
			fmt.Sprintf(`<%s/repos/o/r/actions/runs/55/jobs?page=%d>; rel="next"`, server.URL, nextPage),
		)
		_ = json.NewEncoder(w).Encode(github.Jobs{
			TotalCount: new(1),
			Jobs: []*github.WorkflowJob{
				{ID: new(int64(pagesServed)), Name: new("decoy"), Status: new("completed")},
			},
		})
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, _ := newTestClients(t, server)
	_, err := workflow.ListAllJobsWithMaxPages(t.Context(), gh, "o", "r", 55, pageCap)
	if err == nil {
		t.Fatal("expected error after exceeding job-list cap")
	}
	if !strings.Contains(err.Error(), "exceeded maximum pages") {
		t.Fatalf("error %q does not mention exceeded maximum pages", err.Error())
	}
	if pagesServed > int32(pageCap) {
		t.Fatalf("server saw %d pages, want at most %d", pagesServed, pageCap)
	}
}

// TestListAllJobsCapped_HappyPath confirms paginated job listing
// returns the union of every page on its happy path.
func TestListAllJobsCapped_HappyPath(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/actions/runs/77/jobs", func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "", "1":
			w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/actions/runs/77/jobs?page=2>; rel="next"`, server.URL))
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(2),
				Jobs: []*github.WorkflowJob{
					{ID: new(int64(1)), Name: new("a")},
				},
			})
		case "2":
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(2),
				Jobs: []*github.WorkflowJob{
					{ID: new(int64(2)), Name: new("b")},
				},
			})
		default:
			t.Errorf("unexpected page: %s", page)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, _ := newTestClients(t, server)
	jobs, err := workflow.ListAllJobsWithMaxPages(t.Context(), gh, "o", "r", 77, 5)
	if err != nil {
		t.Fatalf("ListAllJobsCapped: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
}

// TestSearchWorkflowFiles_ExceedsPagesReturnsError pins the search
// pagination cap. A server that always advertises a next page should
// not pin the scanner indefinitely.
func TestSearchWorkflowFiles_ExceedsPagesReturnsError(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	pages := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/search/code", func(w http.ResponseWriter, _ *http.Request) {
		pages++
		next := pages + 1
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s/search/code?page=%d>; rel="next"`, server.URL, next))
		_ = json.NewEncoder(w).Encode(github.CodeSearchResult{
			Total: new(0),
			CodeResults: []*github.CodeResult{
				{Path: new(fmt.Sprintf("decoy-%d.yml", pages))},
			},
		})
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, _ := newTestClients(t, server)

	// Run with a context that times out so the pagination cap is the
	// only reason iteration stops (200 pages * tiny payload is fast).
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, err := workflow.SearchWorkflowFiles(ctx, gh, "repo:o/r path:.github/workflows")
	if err == nil {
		t.Fatal("expected error after exceeding search pagination cap")
	}
	if !strings.Contains(err.Error(), "exceeded maximum pages") {
		t.Fatalf("error %q does not mention exceeded maximum pages", err.Error())
	}
}

// TestListWorkflowRuns_CancelledContextStops verifies that a
// cancellation while iterating chunks/pages propagates to the
// returned error and does not waste cycles in 100ms sleeps.
func TestListWorkflowRuns_CancelledContextStops(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/actions/workflows/42/runs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Always advertise a next page so the loop reaches the
		// inter-page select.
		w.Header().Set("Link", fmt.Sprintf(`<%s/repos/o/r/actions/workflows/42/runs?page=99>; rel="next"`, server.URL))
		_ = json.NewEncoder(w).Encode(github.WorkflowRuns{
			TotalCount: new(0),
		})
	})
	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, _ := newTestClients(t, server)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	start := time.Now()
	_, err := workflow.ListWorkflowRuns(ctx, newTestLogger(), gh, "o", "r", 42, time.Now().Add(-48*time.Hour), time.Now(), 1)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v; ctx-aware sleep regressed", elapsed)
	}
}
