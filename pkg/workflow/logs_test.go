package workflow_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/chainguard-dev/ghscan/pkg/workflow"
	"github.com/google/go-github/v86/github"
	"golang.org/x/time/rate"
)

// newTestClients wires both go-github and httpclient at the supplied
// httptest server. The httpclient instance is permissive on redirects
// (so httptest's 127.0.0.1 host bypasses the prod allowlist) and runs
// at rate.Inf so the bucket never throttles in CI.
func newTestClients(t *testing.T, ts *httptest.Server) (*github.Client, *httpclient.Client) {
	t.Helper()

	gh := github.NewClient(ts.Client())
	parsed, err := url.Parse(ts.URL + "/")
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}
	gh.BaseURL = parsed
	gh.UploadURL = parsed

	hc := httpclient.New(
		httpclient.WithHTTPClient(&http.Client{
			Timeout:       5 * time.Second,
			Transport:     ts.Client().Transport,
			CheckRedirect: nil,
		}),
		httpclient.WithRateLimit(rate.Inf, 10),
	)
	return gh, hc
}

func newTestLogger() *clog.Logger {
	return clog.New(slog.Default().Handler())
}

func runStatusBody(status, conclusion string) string {
	body, _ := json.Marshal(github.WorkflowRun{
		Status:     new(status),
		Conclusion: new(conclusion),
	})
	return string(body)
}

func TestGetLogs_NilHTTPClient(t *testing.T) {
	t.Parallel()

	gh := github.NewClient(nil)
	_, err := workflow.GetLogs(t.Context(), newTestLogger(), nil, gh, "o", "r", 1, "tok")
	if err == nil || !strings.Contains(err.Error(), "httpclient must not be nil") {
		t.Fatalf("expected nil httpclient error, got %v", err)
	}
}

func TestGetLogs_NilGithubClient(t *testing.T) {
	t.Parallel()

	hc := httpclient.New(httpclient.WithRateLimit(rate.Inf, 10))
	_, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, nil, "o", "r", 1, "tok")
	if err == nil || !strings.Contains(err.Error(), "github client must not be nil") {
		t.Fatalf("expected nil github client error, got %v", err)
	}
}

func TestGetLogs_RunStatusFailure(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(ts.Close)

	gh, hc := newTestClients(t, ts)
	_, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 99, "tok")
	if err == nil {
		t.Fatal("expected error on 403 run status, got nil")
	}
	if !strings.Contains(err.Error(), "fetching run status") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestGetLogs_CancelledRunNoJobs covers the fast path: a cancelled run
// with zero jobs short-circuits before any log fetch. The signal is a
// typed sentinel error so callers cannot be tricked by attacker-shaped
// log content.
func TestGetLogs_CancelledRunNoJobs(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/runs/42/jobs"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(0),
				Jobs:       nil,
			})
		case strings.HasSuffix(r.URL.Path, "/actions/runs/42"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runStatusBody("cancelled", "cancelled"))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(ts.Close)

	gh, hc := newTestClients(t, ts)
	rc, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 42, "tok")
	if rc != nil {
		t.Fatalf("expected nil ReadCloser on no-logs sentinel; got %T", rc)
	}
	if !errors.Is(err, workflow.ErrRunHasNoLogs) {
		t.Fatalf("expected errors.Is(err, ErrRunHasNoLogs); got %v", err)
	}
}

// TestGetLogs_ArchiveSuccess covers the happy path: GitHub returns a
// 302 from the run-level logs endpoint pointing at a signed URL, and
// httpclient fetches the archive bytes.
func TestGetLogs_ArchiveSuccess(t *testing.T) {
	t.Parallel()

	const archive = "ZIP-CONTENT-PLACEHOLDER"

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/runs/7/logs"):
			w.Header().Set("Location", server.URL+"/raw/run-archive.zip")
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/actions/runs/7"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runStatusBody("completed", "success"))
		case strings.HasSuffix(r.URL.Path, "/raw/run-archive.zip"):
			w.Header().Set("Content-Type", "application/zip")
			_, _ = io.WriteString(w, archive)
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, hc := newTestClients(t, server)
	rc, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 7, "tok")
	if err != nil {
		t.Fatalf("GetLogs: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	body, _ := io.ReadAll(rc)
	if string(body) != archive {
		t.Fatalf("body mismatch: got %q want %q", string(body), archive)
	}
}

// TestGetLogs_FallbackPerJobLogs exercises the new go-github-driven
// fallback. The run-level archive endpoint returns 410 Gone (the
// observed production behavior after the 30-day retention window),
// after which GetLogs lists jobs and downloads each job's plain-text
// log via the per-job endpoint.
func TestGetLogs_FallbackPerJobLogs(t *testing.T) {
	t.Parallel()

	type call struct {
		path string
	}
	var (
		hitsMu sync.Mutex
		hits   []call
	)

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hitsMu.Lock()
		hits = append(hits, call{path: r.URL.Path})
		hitsMu.Unlock()

		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/runs/100/jobs"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(2),
				Jobs: []*github.WorkflowJob{
					{ID: new(int64(11)), Name: new("build"), Status: new("completed")},
					{ID: new(int64(22)), Name: new("test"), Status: new("completed")},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/actions/runs/100/logs"):
			w.WriteHeader(http.StatusGone)

		case strings.HasSuffix(r.URL.Path, "/actions/runs/100"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runStatusBody("completed", "success"))

		case strings.HasSuffix(r.URL.Path, "/actions/jobs/11/logs"):
			w.Header().Set("Location", server.URL+"/raw/job-11.txt")
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/actions/jobs/22/logs"):
			w.Header().Set("Location", server.URL+"/raw/job-22.txt")
			w.WriteHeader(http.StatusFound)

		case strings.HasSuffix(r.URL.Path, "/raw/job-11.txt"):
			_, _ = io.WriteString(w, "build-log-line\n")
		case strings.HasSuffix(r.URL.Path, "/raw/job-22.txt"):
			_, _ = io.WriteString(w, "test-log-line\n")

		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, hc := newTestClients(t, server)
	rc, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 100, "tok")
	if err != nil {
		t.Fatalf("GetLogs: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	body, _ := io.ReadAll(rc)
	got := string(body)
	for _, want := range []string{
		"===== JOB ID: 11 =====",
		"build-log-line",
		"===== JOB ID: 22 =====",
		"test-log-line",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("combined logs missing %q\nfull body:\n%s", want, got)
		}
	}

	var sawJob11, sawJob22 bool
	hitsMu.Lock()
	for _, h := range hits {
		if strings.HasSuffix(h.path, "/actions/jobs/11/logs") {
			sawJob11 = true
		}
		if strings.HasSuffix(h.path, "/actions/jobs/22/logs") {
			sawJob22 = true
		}
	}
	hitsCopy := append([]call(nil), hits...)
	hitsMu.Unlock()
	if !sawJob11 || !sawJob22 {
		t.Fatalf("missing per-job hits: 11=%v 22=%v hits=%+v", sawJob11, sawJob22, hitsCopy)
	}
}

// TestGetLogs_FallbackPaginatedJobs covers the multi-page jobs listing
// branch. The server emits a Link header pointing to ?page=2; the
// client must follow it and download logs for jobs from both pages.
func TestGetLogs_FallbackPaginatedJobs(t *testing.T) {
	t.Parallel()

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/runs/300/jobs"):
			w.Header().Set("Content-Type", "application/json")
			page := r.URL.Query().Get("page")
			switch page {
			case "", "1":
				w.Header().Set(
					"Link",
					`<`+server.URL+`/repos/o/r/actions/runs/300/jobs?page=2>; rel="next"`,
				)
				_ = json.NewEncoder(w).Encode(github.Jobs{
					TotalCount: new(2),
					Jobs: []*github.WorkflowJob{
						{ID: new(int64(31)), Name: new("build"), Status: new("completed")},
					},
				})
			case "2":
				_ = json.NewEncoder(w).Encode(github.Jobs{
					TotalCount: new(2),
					Jobs: []*github.WorkflowJob{
						{ID: new(int64(32)), Name: new("test"), Status: new("completed")},
					},
				})
			default:
				t.Errorf("unexpected page: %s", page)
				w.WriteHeader(http.StatusInternalServerError)
			}

		case strings.HasSuffix(r.URL.Path, "/actions/runs/300/logs"):
			w.WriteHeader(http.StatusGone)

		case strings.HasSuffix(r.URL.Path, "/actions/runs/300"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runStatusBody("completed", "success"))

		case strings.HasSuffix(r.URL.Path, "/actions/jobs/31/logs"):
			w.Header().Set("Location", server.URL+"/raw/31.txt")
			w.WriteHeader(http.StatusFound)
		case strings.HasSuffix(r.URL.Path, "/actions/jobs/32/logs"):
			w.Header().Set("Location", server.URL+"/raw/32.txt")
			w.WriteHeader(http.StatusFound)

		case strings.HasSuffix(r.URL.Path, "/raw/31.txt"):
			_, _ = io.WriteString(w, "page-one-job\n")
		case strings.HasSuffix(r.URL.Path, "/raw/32.txt"):
			_, _ = io.WriteString(w, "page-two-job\n")

		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})

	server = httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, hc := newTestClients(t, server)
	rc, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 300, "tok")
	if err != nil {
		t.Fatalf("GetLogs: %v", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	body, _ := io.ReadAll(rc)
	got := string(body)
	for _, want := range []string{"page-one-job", "page-two-job", "JOB ID: 31", "JOB ID: 32"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}

// TestGetPerJobLogs_EmptyJobsReturnsSentinel asserts that the per-job
// fetch path surfaces a typed sentinel when GitHub lists zero jobs for
// a run. Callers rely on errors.Is to make the terminal-skip decision
// rather than substring-matching the error text.
func TestGetPerJobLogs_EmptyJobsReturnsSentinel(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/actions/runs/77/jobs") {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(github.Jobs{
			TotalCount: new(0),
			Jobs:       nil,
		})
	}))
	t.Cleanup(ts.Close)

	gh, hc := newTestClients(t, ts)
	err := workflow.GetPerJobLogsForTest(t.Context(), hc, gh, "o", "r", 77, "tok")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, workflow.ErrNoJobsForRun) {
		t.Fatalf("expected errors.Is(err, ErrNoJobsForRun); got %v", err)
	}
}

// TestFallbackPerJobLogs_NoJobsNonCancelled covers the generalized
// terminal-skip branch: an in-progress or completed run that GitHub
// reports with zero jobs (typical for reusable-workflow callee shells)
// must surface ErrRunHasNoLogs so the caller treats the run as a
// terminal skip without re-reading any attacker-influenced bytes.
func TestFallbackPerJobLogs_NoJobsNonCancelled(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/runs/501/jobs"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(0),
				Jobs:       nil,
			})
		case strings.HasSuffix(r.URL.Path, "/actions/runs/501/logs"):
			w.WriteHeader(http.StatusGone)
		case strings.HasSuffix(r.URL.Path, "/actions/runs/501"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runStatusBody("completed", "success"))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, hc := newTestClients(t, server)
	rc, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 501, "tok")
	if rc != nil {
		t.Fatalf("expected nil ReadCloser on no-logs sentinel; got %T", rc)
	}
	if !errors.Is(err, workflow.ErrRunHasNoLogs) {
		t.Fatalf("expected errors.Is(err, ErrRunHasNoLogs); got %v", err)
	}
}

// TestFallbackPerJobLogs_NoJobsCancelledPreserved covers the
// cancelled-with-no-jobs branch under the fallback path. The skip is
// signalled by the sentinel error rather than by any byte content in
// the returned reader, so attacker-shaped job names cannot trigger an
// out-of-band skip.
func TestFallbackPerJobLogs_NoJobsCancelledPreserved(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/runs/502/jobs"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(1),
				Jobs:       nil,
			})
		case strings.HasSuffix(r.URL.Path, "/actions/runs/502/logs"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/actions/runs/502"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runStatusBody("cancelled", "cancelled"))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, hc := newTestClients(t, server)
	rc, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 502, "tok")
	if rc != nil {
		t.Fatalf("expected nil ReadCloser on no-logs sentinel; got %T", rc)
	}
	if !errors.Is(err, workflow.ErrRunHasNoLogs) {
		t.Fatalf("expected errors.Is(err, ErrRunHasNoLogs); got %v", err)
	}
}

// TestGetLogs_CancelledFallbackEmpty covers the cancelled-run fallback
// path: archive is gone, jobs listing is empty. Expect the typed
// no-logs sentinel rather than synthetic content.
func TestGetLogs_CancelledFallbackEmpty(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/actions/runs/200/jobs"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(1),
				Jobs:       nil,
			})
		case strings.HasSuffix(r.URL.Path, "/actions/runs/200/logs"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/actions/runs/200"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, runStatusBody("cancelled", "cancelled"))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	gh, hc := newTestClients(t, server)
	rc, err := workflow.GetLogs(t.Context(), newTestLogger(), hc, gh, "o", "r", 200, "tok")
	if rc != nil {
		t.Fatalf("expected nil ReadCloser on no-logs sentinel; got %T", rc)
	}
	if !errors.Is(err, workflow.ErrRunHasNoLogs) {
		t.Fatalf("expected errors.Is(err, ErrRunHasNoLogs); got %v", err)
	}
}
