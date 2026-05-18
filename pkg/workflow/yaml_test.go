package workflow_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chainguard-dev/ghscan/pkg/workflow"
	"github.com/google/go-github/v86/github"
)

func TestListWorkflowFilePaths_OnlyDotGitHubWorkflows(t *testing.T) {
	t.Parallel()

	owner, repo := "octo", "demo"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/.github/workflows",
		func(w http.ResponseWriter, _ *http.Request) {
			items := []*github.RepositoryContent{
				{Type: new("file"), Name: new("ci.yml"), Path: new(".github/workflows/ci.yml")},
				{Type: new("file"), Name: new("release.yaml"), Path: new(".github/workflows/release.yaml")},
				{Type: new("file"), Name: new("not-a-workflow.txt"), Path: new(".github/workflows/not-a-workflow.txt")},
				{Type: new("dir"), Name: new("nested"), Path: new(".github/workflows/nested")},
			}
			_ = json.NewEncoder(w).Encode(items)
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gh, _ := newTestClients(t, srv)

	paths, err := workflow.ListWorkflowFilePaths(t.Context(), gh, owner, repo, "")
	if err != nil {
		t.Fatalf("ListWorkflowFilePaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("got %d paths, want 2: %v", len(paths), paths)
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, ".github/workflows/") {
			t.Errorf("path %q does not have .github/workflows/ prefix", p)
		}
		if !strings.HasSuffix(p, ".yml") && !strings.HasSuffix(p, ".yaml") {
			t.Errorf("path %q is not a yml/yaml file", p)
		}
	}
}

func TestListWorkflowFilePaths_NoDirectoryReturnsEmpty(t *testing.T) {
	t.Parallel()

	owner, repo := "octo", "demo"
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/.github/workflows",
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gh, _ := newTestClients(t, srv)

	paths, err := workflow.ListWorkflowFilePaths(t.Context(), gh, owner, repo, "")
	if err != nil {
		t.Fatalf("expected nil err for missing directory, got %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected zero paths, got %v", paths)
	}
}

func TestFetchWorkflowYAML_ReturnsRawBytes(t *testing.T) {
	t.Parallel()

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/ci.yml"
	body := "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/"+wfPath,
		func(w http.ResponseWriter, _ *http.Request) {
			enc := base64.StdEncoding.EncodeToString([]byte(body))
			item := github.RepositoryContent{
				Type:     new("file"),
				Name:     new("ci.yml"),
				Path:     new(wfPath),
				Encoding: new("base64"),
				Content:  new(enc),
				SHA:      new("deadbeef"),
				Size:     new(len(body)),
			}
			_ = json.NewEncoder(w).Encode(item)
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gh, _ := newTestClients(t, srv)

	got, err := workflow.FetchWorkflowYAML(t.Context(), gh, owner, repo, wfPath, "")
	if err != nil {
		t.Fatalf("FetchWorkflowYAML: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body=%q, want %q", string(got), body)
	}
}

func TestFetchWorkflowYAML_RejectsPathOutsideWorkflows(t *testing.T) {
	t.Parallel()

	owner, repo := "octo", "demo"
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be called when path is rejected, got %s", r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	gh, _ := newTestClients(t, srv)

	bad := []string{
		".github/actions/custom/action.yml",
		"src/main.go",
		"random/path/wf.yml",
		"",
	}
	for _, p := range bad {
		_, err := workflow.FetchWorkflowYAML(t.Context(), gh, owner, repo, p, "")
		if err == nil {
			t.Fatalf("FetchWorkflowYAML(%q) returned nil err, want rejection", p)
		}
	}
}

func TestFetchWorkflowYAML_EnforcesSizeCap(t *testing.T) {
	t.Parallel()

	owner, repo := "octo", "demo"
	wfPath := ".github/workflows/big.yml"

	huge := strings.Repeat("a", (1<<20)+1)
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+owner+"/"+repo+"/contents/"+wfPath,
		func(w http.ResponseWriter, _ *http.Request) {
			enc := base64.StdEncoding.EncodeToString([]byte(huge))
			item := github.RepositoryContent{
				Type:     new("file"),
				Name:     new("big.yml"),
				Path:     new(wfPath),
				Encoding: new("base64"),
				Content:  new(enc),
				SHA:      new("ff"),
				Size:     new(len(huge)),
			}
			_ = json.NewEncoder(w).Encode(item)
		})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	gh, _ := newTestClients(t, srv)

	_, err := workflow.FetchWorkflowYAML(t.Context(), gh, owner, repo, wfPath, "")
	if err == nil {
		t.Fatal("expected size-cap error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("error %q does not mention exceeds maximum size", err.Error())
	}
}
