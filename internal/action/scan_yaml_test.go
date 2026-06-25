package action_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/ghscan/internal/action"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/google/go-github/v86/github"
	"github.com/spf13/viper"
)

// fakeGitHubWithYAML returns an httptest server that serves the YAML
// scanning surface: contents listing for .github/workflows/ and a
// single file under that directory.
func fakeGitHubWithYAML(t *testing.T, wfPath, yamlBody string) *httptest.Server {
	t.Helper()
	const (
		owner = "octo"
		repo  = "demo"
	)
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/"+owner+"/"+repo,
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Repository{
				Name:  new(repo),
				Owner: &github.User{Login: new(owner)},
			})
		})

	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/.github/workflows",
		func(w http.ResponseWriter, _ *http.Request) {
			items := []*github.RepositoryContent{
				{
					Type: new("file"),
					Name: new(strings.TrimPrefix(wfPath, ".github/workflows/")),
					Path: new(wfPath),
					SHA:  new("deadbeef"),
				},
			}
			_ = json.NewEncoder(w).Encode(items)
		})

	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/"+wfPath,
		func(w http.ResponseWriter, _ *http.Request) {
			enc := base64.StdEncoding.EncodeToString([]byte(yamlBody))
			item := github.RepositoryContent{
				Type:     new("file"),
				Name:     new(strings.TrimPrefix(wfPath, ".github/workflows/")),
				Path:     new(wfPath),
				Encoding: new("base64"),
				Content:  new(enc),
				SHA:      new("deadbeef"),
				Size:     new(len(yamlBody)),
			}
			_ = json.NewEncoder(w).Encode(item)
		})

	// Stubs needed only when scan-logs is also on.
	mux.HandleFunc("/search/code", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.CodeSearchResult{
			Total:       new(0),
			CodeResults: []*github.CodeResult{},
		})
	})

	return httptest.NewServer(mux)
}

func TestScan_YAMLOnly_FindsKnownBadRef(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 1)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "30s")
	viper.Set("scan_yaml", true)
	viper.Set("scan_logs", false)
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"
	yamlBody := `name: ci
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: changed
        uses: tj-actions/changed-files@v36
`

	srv := fakeGitHubWithYAML(t, wfPath, yamlBody)
	t.Cleanup(srv.Close)
	gh, hc := newTestClients(t, srv)

	// Use the predefined corpus so the v36 tag is a known bad ref.
	predef, ok := ioc.GetPredefinedIOC("tj-actions/changed-files")
	if !ok {
		t.Fatal("predefined IOC tj-actions/changed-files not found")
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
		IOC:           predef,
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
		t.Fatal("expected at least one YAML finding")
	}
	got := req.Cache.Results[0]
	if got.OffendingUsesLine != "tj-actions/changed-files@v36" {
		t.Fatalf("OffendingUsesLine=%q, want tj-actions/changed-files@v36", got.OffendingUsesLine)
	}
	if got.ResolvedRefForm != "tag" {
		t.Fatalf("ResolvedRefForm=%q, want tag", got.ResolvedRefForm)
	}
	if got.WorkflowFileSHA != "deadbeef" {
		t.Fatalf("WorkflowFileSHA=%q, want deadbeef", got.WorkflowFileSHA)
	}
	if got.JobName != "build" {
		t.Fatalf("JobName=%q, want build", got.JobName)
	}
	if got.StepName != "changed" {
		t.Fatalf("StepName=%q, want changed", got.StepName)
	}
	if got.Source != "yaml" {
		t.Fatalf("Source=%q, want yaml", got.Source)
	}
}

func TestScan_YAMLOnly_BenignRefProducesNoFinding(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 1)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "30s")
	viper.Set("scan_yaml", true)
	viper.Set("scan_logs", false)
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"
	yamlBody := `name: ci
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`

	srv := fakeGitHubWithYAML(t, wfPath, yamlBody)
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

	if err := action.Scan(t.Context(), newSilentLogger(), req, repos); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(req.Cache.Results) != 0 {
		t.Fatalf("expected zero results for benign workflow, got %d: %+v",
			len(req.Cache.Results), req.Cache.Results)
	}
}

func TestScan_YAMLOnly_CarriesReachableSecrets(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 1)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "30s")
	viper.Set("scan_yaml", true)
	viper.Set("scan_logs", false)
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/publish.yml"
	yamlBody := `name: publish
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: ship
        uses: tj-actions/changed-files@v36
        with:
          token: ${{ secrets.NPM_TOKEN }}
        env:
          AUTH: ${{ secrets.RELEASE_TOKEN }}
`
	srv := fakeGitHubWithYAML(t, wfPath, yamlBody)
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

	if err := action.Scan(t.Context(), newSilentLogger(), req, repos); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(req.Cache.Results) == 0 {
		t.Fatal("expected at least one YAML finding")
	}
	got := req.Cache.Results[0]
	for _, want := range []string{"NPM_TOKEN", "RELEASE_TOKEN"} {
		if !slices.Contains(got.ReachableSecrets, want) {
			t.Errorf("ReachableSecrets=%v, want to contain %q", got.ReachableSecrets, want)
		}
	}
}

func TestScan_BothPathsDeduplicatePerActionRef(t *testing.T) {
	chdirTemp(t)
	viper.Set("max_retries", 1)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "30s")
	viper.Set("scan_yaml", true)
	viper.Set("scan_logs", true)
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"
	yamlBody := `jobs:
  build:
    steps:
      - uses: tj-actions/changed-files@v36
`
	// The log body contains the same compromised SHA -- log scan should
	// also fire, but dedup must keep the YAML record (it's richer).
	logBody := "2025-01-01T00:00:00.000Z SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+owner+"/"+repo,
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Repository{
				Name:  new(repo),
				Owner: &github.User{Login: new(owner)},
			})
		})
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/.github/workflows",
		func(w http.ResponseWriter, _ *http.Request) {
			items := []*github.RepositoryContent{
				{Type: new("file"), Name: new("ci.yml"), Path: new(wfPath), SHA: new("aabb")},
			}
			_ = json.NewEncoder(w).Encode(items)
		})
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/"+wfPath,
		func(w http.ResponseWriter, _ *http.Request) {
			enc := base64.StdEncoding.EncodeToString([]byte(yamlBody))
			item := github.RepositoryContent{
				Type: new("file"), Name: new("ci.yml"), Path: new(wfPath),
				Encoding: new("base64"), Content: new(enc), SHA: new("aabb"),
				Size: new(len(yamlBody)),
			}
			_ = json.NewEncoder(w).Encode(item)
		})
	mux.HandleFunc("/search/code", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.CodeSearchResult{
			Total: new(1),
			CodeResults: []*github.CodeResult{
				{Path: new(wfPath)},
			},
		})
	})
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/actions/workflows",
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.Workflows{
				TotalCount: new(1),
				Workflows: []*github.Workflow{
					{ID: new(int64(42)), Path: new(wfPath)},
				},
			})
		})
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/actions/workflows/42/runs",
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
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/actions/runs/99",
		func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(github.WorkflowRun{
				ID:         new(int64(99)),
				Status:     new("completed"),
				Conclusion: new("success"),
			})
		})
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/actions/runs/99/logs",
		func(w http.ResponseWriter, r *http.Request) {
			u := "http://" + r.Host + "/signed"
			w.Header().Set("Location", u)
			w.WriteHeader(http.StatusFound)
		})
	logZip := buildLogZipBytes(t, logBody)
	mux.HandleFunc("/signed", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(logZip)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gh, hc := newTestClients(t, srv)

	predef, _ := ioc.GetPredefinedIOC("tj-actions/changed-files")

	end := time.Now().Add(time.Hour)
	start := end.Add(-7 * 24 * time.Hour)

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

	if err := action.Scan(t.Context(), newSilentLogger(), req, repos); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Dedup invariant: a YAML hit + a log hit on the same action must
	// collapse to a single Result that retains the YAML metadata.
	yamlHits := 0
	logHits := 0
	for _, r := range req.Cache.Results {
		if r.OffendingUsesLine != "" {
			yamlHits++
		}
		if r.OffendingUsesLine == "" && r.LineData != "" {
			logHits++
		}
	}
	if yamlHits == 0 {
		t.Fatalf("expected at least one YAML hit; results=%+v", req.Cache.Results)
	}
	// The log hit should be merged-away because it shares the action coord.
	if logHits != 0 {
		t.Fatalf("expected log hit to be deduped; results=%+v", req.Cache.Results)
	}
}

func TestScan_BothFlagsFalseIsError(t *testing.T) {
	chdirTemp(t)
	viper.Set("scan_yaml", false)
	viper.Set("scan_logs", false)
	t.Cleanup(viper.Reset)

	owner, repo := "octo", "demo"
	srv := fakeGitHubWithYAML(t, ".github/workflows/ci.yml", "jobs: {}\n")
	t.Cleanup(srv.Close)
	gh, hc := newTestClients(t, srv)

	predef, _ := ioc.GetPredefinedIOC("tj-actions/changed-files")
	end := time.Now().Add(time.Hour)
	start := end.Add(-24 * time.Hour)
	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache: ghscan.Cache{}, CacheFile: "cache.json",
		CachedResults: map[string]bool{}, Client: gh, HTTPClient: hc,
		EndTime: end, IOC: predef, StartTime: start, Token: "tok",
	})
	repos := []*github.Repository{{
		Name:  new(repo),
		Owner: &github.User{Login: new(owner)},
	}}

	err := action.Scan(t.Context(), newSilentLogger(), req, repos)
	if err == nil {
		t.Fatal("expected error when both scan_yaml and scan_logs are false")
	}
	if !strings.Contains(err.Error(), "at least one of scan_yaml or scan_logs") {
		t.Fatalf("error %q does not mention both flags disabled", err.Error())
	}
}
