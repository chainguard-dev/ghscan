package action_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/ghscan/internal/action"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
	"github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/google/go-github/v86/github"
	"github.com/spf13/viper"
	"golang.org/x/time/rate"
)

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

func buildLogZipBytes(t *testing.T, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("0_job.txt")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// fakeGitHub returns an httptest server that mimics the subset of the
// GitHub REST API exercised by action.Scan: search/code, list
// workflows, list runs, get run, and the run logs redirect chain.
//
// logBody is what the scanner will see after extracting the zip.
func fakeGitHub(t *testing.T, owner, repo, wfPath string, logBody string) *httptest.Server {
	t.Helper()

	// We need a sub-server for the signed-URL log download because the
	// run-logs handler returns an absolute URL.
	logZip := buildLogZipBytes(t, logBody)

	mux := http.NewServeMux()

	// Repositories.Get
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Repository{
				Name:  new(repo),
				Owner: &github.User{Login: new(owner)},
			})
		})

	// Search.Code
	mux.HandleFunc("/search/code", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.CodeSearchResult{
			Total: new(1),
			CodeResults: []*github.CodeResult{
				{Path: new(wfPath)},
			},
		})
	})

	// Actions.ListWorkflows
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Workflows{
				TotalCount: new(1),
				Workflows: []*github.Workflow{
					{ID: new(int64(42)), Path: new(wfPath)},
				},
			})
		})

	// Actions.ListWorkflowRunsByID -- /repos/{owner}/{repo}/actions/workflows/{id}/runs
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows/42/runs", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.WorkflowRuns{
				TotalCount: new(1),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:        new(int64(99)),
						Status:    new("completed"),
						CreatedAt: &github.Timestamp{Time: time.Now().Add(-12 * time.Hour)},
					},
				},
			})
		})

	// Actions.GetWorkflowRunByID
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/runs/99", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.WorkflowRun{
				ID:         new(int64(99)),
				Status:     new("completed"),
				Conclusion: new("success"),
			})
		})

	// Actions.GetWorkflowRunLogs returns a redirect to the signed URL.
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/runs/99/logs", owner, repo),
		func(w http.ResponseWriter, r *http.Request) {
			// Construct an absolute URL to the same server pointing at /signed.
			u := "http://" + r.Host + "/signed"
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
		})

	// Signed URL serves the zip blob.
	mux.HandleFunc("/signed", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(logZip)
	})

	return httptest.NewServer(mux)
}

func TestScan_NilRequest(t *testing.T) {
	if err := action.Scan(t.Context(), newSilentLogger(), nil, nil); err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestScan_HappyPath(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 1)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "30s")
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"
	logBody := strings.Repeat("benign log line\n", 20) +
		"DROP_THIS_TOKEN appears here\n" +
		strings.Repeat("benign log line\n", 20)

	srv := fakeGitHub(t, owner, repo, wfPath, logBody)
	t.Cleanup(srv.Close)

	gh, hc := newTestClients(t, srv)

	customIOC, err := ioc.NewIOC(&ioc.Config{
		Name:    "test-only",
		Content: []string{"DROP_THIS_TOKEN"},
	})
	if err != nil {
		t.Fatalf("build IOC: %v", err)
	}

	// Run-list time chunks at 48h granularity in workflow.go; the
	// fixture run is created 12h ago, so a 7-day window covers it.
	end := time.Now().Add(time.Hour)
	start := end.Add(-7 * 24 * time.Hour)

	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache:         ghscan.Cache{},
		CacheFile:     "cache.json",
		CachedResults: map[string]bool{},
		Client:        gh,
		HTTPClient:    hc,
		EndTime:       end,
		IOC:           customIOC,
		StartTime:     start,
		Token:         "test-token",
	})

	repos := []*github.Repository{{
		Name:  new(repo),
		Owner: &github.User{Login: new(owner)},
	}}

	if err := action.Scan(t.Context(), newSilentLogger(), req, repos); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(req.Cache.Results) == 0 {
		t.Fatal("expected at least one finding in cache, got 0")
	}
	got := req.Cache.Results[0]
	if !strings.Contains(got.LineData, "DROP_THIS_TOKEN") {
		t.Fatalf("LineData=%q, want substring DROP_THIS_TOKEN", got.LineData)
	}
}

func TestScan_ContextCancelled(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 0)
	viper.Set("max_concurrency", 1)
	viper.Set("operation_timeout", "30s")
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	srv := fakeGitHub(t, owner, repo, ".github/workflows/ci.yml", "no IOC here\n")
	t.Cleanup(srv.Close)

	gh, hc := newTestClients(t, srv)
	predef, _ := ioc.GetPredefinedIOC("tj-actions/changed-files")

	end := time.Now().Add(time.Hour)
	start := end.Add(-24 * time.Hour)

	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache:         ghscan.Cache{},
		CacheFile:     "cache.json",
		CachedResults: map[string]bool{},
		Client:        gh,
		HTTPClient:    hc,
		EndTime:       end,
		IOC:           predef,
		StartTime:     start,
		Token:         "tok",
	})

	repos := []*github.Repository{{
		Name:  new(repo),
		Owner: &github.User{Login: new(owner)},
	}}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := action.Scan(ctx, newSilentLogger(), req, repos)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

// fakeGitHubNoJobs returns an httptest server that drives a workflow
// run all the way to log fetch, where the per-job fallback discovers
// zero jobs. The expected scan outcome is a clean nil error with zero
// findings recorded for the run.
func fakeGitHubNoJobs(t *testing.T, owner, repo, wfPath string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Repository{
				Name:  new(repo),
				Owner: &github.User{Login: new(owner)},
			})
		})

	mux.HandleFunc("/search/code", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.CodeSearchResult{
			Total: new(1),
			CodeResults: []*github.CodeResult{
				{Path: new(wfPath)},
			},
		})
	})

	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Workflows{
				TotalCount: new(1),
				Workflows: []*github.Workflow{
					{ID: new(int64(42)), Path: new(wfPath)},
				},
			})
		})

	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows/42/runs", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.WorkflowRuns{
				TotalCount: new(1),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:        new(int64(99)),
						Status:    new("completed"),
						CreatedAt: &github.Timestamp{Time: time.Now().Add(-12 * time.Hour)},
					},
				},
			})
		})

	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/runs/99", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.WorkflowRun{
				ID:         new(int64(99)),
				Status:     new("completed"),
				Conclusion: new("success"),
			})
		})

	// Run-level logs 410 forces the per-job fallback.
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/runs/99/logs", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusGone)
		})

	// Empty jobs response drives the terminal-skip branch.
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/runs/99/jobs", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Jobs{
				TotalCount: new(0),
				Jobs:       nil,
			})
		})

	return httptest.NewServer(mux)
}

func TestScanRuns_NoJobsSkipsCleanly(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 1)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "30s")
	viper.Set("scan_yaml", false)
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"
	srv := fakeGitHubNoJobs(t, owner, repo, wfPath)
	t.Cleanup(srv.Close)

	gh, hc := newTestClients(t, srv)
	customIOC, err := ioc.NewIOC(&ioc.Config{
		Name:    "test-only",
		Content: []string{"DROP_THIS_TOKEN"},
	})
	if err != nil {
		t.Fatalf("build IOC: %v", err)
	}

	end := time.Now().Add(time.Hour)
	start := end.Add(-7 * 24 * time.Hour)

	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache:         ghscan.Cache{},
		CacheFile:     "cache.json",
		CachedResults: map[string]bool{},
		Client:        gh,
		HTTPClient:    hc,
		EndTime:       end,
		IOC:           customIOC,
		StartTime:     start,
		Token:         "tok",
	})

	repos := []*github.Repository{{
		Name:  new(repo),
		Owner: &github.User{Login: new(owner)},
	}}

	if err := action.Scan(t.Context(), newSilentLogger(), req, repos); err != nil {
		t.Fatalf("Scan() must succeed for no-jobs run; got %v", err)
	}
	if len(req.Cache.Results) != 0 {
		t.Fatalf("expected zero findings for no-jobs run; got %d (%+v)", len(req.Cache.Results), req.Cache.Results)
	}
}

// TestScanRuns_NoJobsBodyContentIgnored is the regression guard for
// the attacker-controlled-content skip bypass. A run with real log
// content whose first 100 bytes happen to spell "had no jobs to scan"
// or "was canceled with no jobs" (achievable by naming a workflow job
// to match, since zip local-file headers embed the filename) must NOT
// be skipped: the IOC scanner must read the full archive and surface
// the embedded indicator. The skip path is reserved for the typed
// sentinel returned by GetLogs.
func TestScanRuns_NoJobsBodyContentIgnored(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 1)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "30s")
	viper.Set("scan_yaml", false)
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"

	// The zip carries a real IOC plus the two literal substrings the
	// pre-fix code treated as skip signals when found in the first 100
	// bytes of the reader. The archive member name is forced to a
	// 64-byte string so the local-file header for the first member
	// embeds both phrases inside the preview window.
	memberName := "had no jobs to scan_was canceled with no jobs_padding"
	logBody := "DROP_THIS_TOKEN appears here\n" + strings.Repeat("benign\n", 4)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(memberName)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(logBody)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	zipBytes := buf.Bytes()

	// Sanity: the preview window covers both phrases before scanning.
	previewLen := 100
	if len(zipBytes) < previewLen {
		previewLen = len(zipBytes)
	}
	preview := string(zipBytes[:previewLen])
	for _, want := range []string{"had no jobs to scan", "was canceled with no jobs"} {
		if !strings.Contains(preview, want) {
			t.Fatalf("preview missing %q; fixture would not exercise bypass surface: %q", want, preview)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Repository{
				Name:  new(repo),
				Owner: &github.User{Login: new(owner)},
			})
		})
	mux.HandleFunc("/search/code", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.CodeSearchResult{
			Total: new(1),
			CodeResults: []*github.CodeResult{
				{Path: new(wfPath)},
			},
		})
	})
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Workflows{
				TotalCount: new(1),
				Workflows: []*github.Workflow{
					{ID: new(int64(42)), Path: new(wfPath)},
				},
			})
		})
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/workflows/42/runs", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.WorkflowRuns{
				TotalCount: new(1),
				WorkflowRuns: []*github.WorkflowRun{
					{
						ID:        new(int64(99)),
						Status:    new("completed"),
						CreatedAt: &github.Timestamp{Time: time.Now().Add(-12 * time.Hour)},
					},
				},
			})
		})
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/runs/99", owner, repo),
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.WorkflowRun{
				ID:         new(int64(99)),
				Status:     new("completed"),
				Conclusion: new("success"),
			})
		})
	mux.HandleFunc(fmt.Sprintf("/repos/%s/%s/actions/runs/99/logs", owner, repo),
		func(w http.ResponseWriter, r *http.Request) {
			u := "http://" + r.Host + "/signed"
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
		})
	mux.HandleFunc("/signed", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	gh, hc := newTestClients(t, srv)
	customIOC, err := ioc.NewIOC(&ioc.Config{
		Name:    "test-only",
		Content: []string{"DROP_THIS_TOKEN"},
	})
	if err != nil {
		t.Fatalf("build IOC: %v", err)
	}

	end := time.Now().Add(time.Hour)
	start := end.Add(-7 * 24 * time.Hour)

	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache:         ghscan.Cache{},
		CacheFile:     "cache.json",
		CachedResults: map[string]bool{},
		Client:        gh,
		HTTPClient:    hc,
		EndTime:       end,
		IOC:           customIOC,
		StartTime:     start,
		Token:         "tok",
	})

	repos := []*github.Repository{{
		Name:  new(repo),
		Owner: &github.User{Login: new(owner)},
	}}

	if err := action.Scan(t.Context(), newSilentLogger(), req, repos); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(req.Cache.Results) == 0 {
		t.Fatal("expected IOC finding despite attacker-shaped preview bytes; got zero results (skip-bypass regression)")
	}
	got := req.Cache.Results[0]
	if !strings.Contains(got.LineData, "DROP_THIS_TOKEN") {
		t.Fatalf("LineData=%q, want substring DROP_THIS_TOKEN", got.LineData)
	}
}

func TestScan_MaxConcurrencyClamped(t *testing.T) {
	chdirTemp(t)
	// max_concurrency=0 must clamp to fanOutLimit (32). We can't observe
	// the clamp directly, but we verify Scan still produces results.
	viper.Set("max_concurrency", 0)
	viper.Set("max_retries", 1)
	viper.Set("operation_timeout", "30s")
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"
	srv := fakeGitHub(t, owner, repo, wfPath, "DROP_THIS_TOKEN here\n")
	t.Cleanup(srv.Close)

	gh, hc := newTestClients(t, srv)
	customIOC, err := ioc.NewIOC(&ioc.Config{
		Name:    "test-only",
		Content: []string{"DROP_THIS_TOKEN"},
	})
	if err != nil {
		t.Fatalf("build IOC: %v", err)
	}

	end := time.Now().Add(time.Hour)
	start := end.Add(-24 * time.Hour)

	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache:         ghscan.Cache{},
		CacheFile:     "cache.json",
		CachedResults: map[string]bool{},
		Client:        gh,
		HTTPClient:    hc,
		EndTime:       end,
		IOC:           customIOC,
		StartTime:     start,
		Token:         "tok",
	})

	repos := []*github.Repository{{
		Name:  new(repo),
		Owner: &github.User{Login: new(owner)},
	}}

	if err := action.Scan(t.Context(), newSilentLogger(), req, repos); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
}
