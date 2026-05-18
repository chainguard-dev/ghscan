package file_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/file"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

// LoadCache reads from filepath.Join(ghscan.ResultsDir, cacheFile). To
// avoid clobbering an actual results/ directory, the tests redirect
// using a relative cacheFile that resolves under the test's TempDir.
//
// Strategy: chdir into a t.TempDir so the relative ResultsDir is
// project-isolated, then write fixtures under <tempdir>/results/.
func chdirTemp(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

func newSilentLogger() *clog.Logger {
	return clog.New(slog.Default().Handler())
}

func TestLoadCache(t *testing.T) {
	cases := []struct {
		name        string
		seed        *ghscan.Cache // nil → no file on disk
		cleanCache  bool
		ctxFn       func() context.Context
		corrupt     bool
		wantResults int
	}{
		{
			name:        "missing file returns empty",
			seed:        nil,
			wantResults: 0,
		},
		{
			name: "valid cache round-trips",
			seed: &ghscan.Cache{Results: []ghscan.Result{
				{Repository: "o/r", LineData: "ioc seen"},
				{Repository: "o/r", LineData: "ioc again"},
			}},
			wantResults: 2,
		},
		{
			name: "clean_cache flag forces empty",
			seed: &ghscan.Cache{Results: []ghscan.Result{
				{Repository: "o/r", LineData: "x"},
			}},
			cleanCache:  true,
			wantResults: 0,
		},
		{
			name: "cancelled context returns empty",
			seed: &ghscan.Cache{Results: []ghscan.Result{
				{Repository: "o/r", LineData: "x"},
			}},
			ctxFn: func() context.Context {
				c, cancel := context.WithCancel(t.Context())
				cancel()
				return c
			},
			wantResults: 0,
		},
		{
			name:        "corrupt JSON returns empty",
			corrupt:     true,
			wantResults: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chdirTemp(t)
			logger := newSilentLogger()

			cacheRel := "cache.json"
			if tc.seed != nil {
				if err := os.MkdirAll(ghscan.ResultsDir, 0o750); err != nil {
					t.Fatalf("mkdir results: %v", err)
				}
				blob, err := json.Marshal(tc.seed)
				if err != nil {
					t.Fatalf("marshal seed: %v", err)
				}
				if err := os.WriteFile(filepath.Join(ghscan.ResultsDir, cacheRel), blob, 0o600); err != nil {
					t.Fatalf("seed write: %v", err)
				}
			}
			if tc.corrupt {
				if err := os.MkdirAll(ghscan.ResultsDir, 0o750); err != nil {
					t.Fatalf("mkdir results: %v", err)
				}
				if err := os.WriteFile(filepath.Join(ghscan.ResultsDir, cacheRel), []byte("{not valid json"), 0o600); err != nil {
					t.Fatalf("corrupt write: %v", err)
				}
			}

			ctx := t.Context()
			if tc.ctxFn != nil {
				ctx = tc.ctxFn()
			}

			got := file.LoadCache(ctx, logger, cacheRel, tc.cleanCache)
			if len(got.Results) != tc.wantResults {
				t.Fatalf("results=%d, want %d", len(got.Results), tc.wantResults)
			}
		})
	}
}
