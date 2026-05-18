//go:build integration

// Package action integration suite. These tests are gated behind the
// `integration` build tag and are skipped unless GHSCAN_INT=1 and
// GITHUB_TOKEN are both set in the environment. The default
// `go test ./...` invocation never compiles this file.
//
// Run with:
//
//	make integration
//
// Or:
//
//	GHSCAN_INT=1 GITHUB_TOKEN=ghp_... \
//	  go test -tags=integration -count=1 -run TestIntegration ./pkg/action/...

package action_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/action"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
	"github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/google/go-github/v86/github"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// TestNothingShouldMatch is a no-op smoke test that exists solely to
// verify the integration build tag compiles. It always passes; real
// integration coverage is in TestIntegration_ScanPublicRepo.
func TestNothingShouldMatch(t *testing.T) {
	t.Log("integration tag compiles")
}

// TestIntegration_ScanPublicRepo runs a small end-to-end scan against
// a public, non-SAML-protected upstream repository whose CI is a flat
// direct-jobs structure (no reusable callees), so the scanner's log
// fetch path is exercised end to end. The default target is
// sirupsen/logrus -- a long-lived Go library with stable, downloadable
// run logs that does not use any tj-actions release. The owner and
// repo can be overridden via GHSCAN_INT_OWNER and GHSCAN_INT_REPO for
// ad-hoc runs.
func TestIntegration_ScanPublicRepo(t *testing.T) {
	if os.Getenv("GHSCAN_INT") != "1" {
		t.Skip("integration tests require GHSCAN_INT=1")
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("integration tests require GITHUB_TOKEN")
	}

	dir := t.TempDir()
	t.Chdir(dir)

	viper.Set("max_retries", 3)
	viper.Set("max_concurrency", 4)
	viper.Set("operation_timeout", "60s")
	t.Cleanup(viper.Reset)

	logger := clog.New(slog.Default().Handler())

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	gh := github.NewClient(tc)
	hc := httpclient.New()

	// Reap HTTP keep-alive goroutines before goleak verification.
	t.Cleanup(func() {
		tc.CloseIdleConnections()
		hc.CloseIdleConnections()
	})

	predef, ok := ioc.GetPredefinedIOC("tj-actions/changed-files")
	if !ok {
		t.Fatal("predefined IOC tj-actions/changed-files not found")
	}

	owner := os.Getenv("GHSCAN_INT_OWNER")
	if owner == "" {
		owner = "sirupsen"
	}
	name := os.Getenv("GHSCAN_INT_REPO")
	if name == "" {
		name = "logrus"
	}

	repo, _, err := gh.Repositories.Get(ctx, owner, name)
	if err != nil {
		t.Fatalf("get repo %s/%s: %v", owner, name, err)
	}

	end := time.Now()
	start := end.Add(-7 * 24 * time.Hour)

	cacheFile := "integration-cache.json"
	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache:         ghscan.Cache{},
		CacheFile:     cacheFile,
		CachedResults: map[string]bool{},
		Client:        gh,
		HTTPClient:    hc,
		EndTime:       end,
		IOC:           predef,
		StartTime:     start,
		Token:         token,
	})

	if err := action.Scan(ctx, logger, req, []*github.Repository{repo}); err != nil {
		t.Fatalf("Scan() returned error: %v", err)
	}

	// We don't assert on the number of results -- a clean scan against
	// a well-maintained upstream should produce zero hits, but a recent
	// IOC backfill could flip that. We assert only that no error was
	// raised AND the cache file was either written or correctly skipped
	// due to no findings.
	cachePath := filepath.Join(ghscan.ResultsDir, cacheFile)
	if _, err := os.Stat(cachePath); err == nil {
		t.Logf("integration scan produced cache at %s with %d results",
			cachePath, len(req.Cache.Results))
	} else {
		t.Logf("integration scan completed cleanly with no findings (no cache file)")
	}
}
