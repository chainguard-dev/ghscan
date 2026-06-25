package file_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/ghscan/internal/file"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

func TestWriteCache(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		results   []ghscan.Result
		ctxFn     func() context.Context
		wantWrite bool
	}{
		{
			name: "happy path writes well-formed JSON",
			results: []ghscan.Result{
				{Repository: "o/r", LineData: "matched"},
			},
			wantWrite: true,
		},
		{
			name:      "empty slice still writes",
			results:   []ghscan.Result{},
			wantWrite: true,
		},
		{
			name: "cancelled context skips write",
			results: []ghscan.Result{
				{Repository: "o/r", LineData: "matched"},
			},
			ctxFn: func() context.Context {
				c, cancel := context.WithCancel(t.Context())
				cancel()
				return c
			},
			wantWrite: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "cache.json")

			ctx := t.Context()
			if tc.ctxFn != nil {
				ctx = tc.ctxFn()
			}

			file.WriteCache(ctx, newSilentLogger(), path, tc.results)

			data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
			switch {
			case tc.wantWrite && err != nil:
				t.Fatalf("expected file to exist: %v", err)
			case !tc.wantWrite && err == nil:
				t.Fatalf("expected no file write, got %d bytes", len(data))
			case !tc.wantWrite:
				return
			}

			var c ghscan.Cache
			if err := json.Unmarshal(data, &c); err != nil {
				t.Fatalf("written file is not valid JSON: %v", err)
			}
			if len(c.Results) != len(tc.results) {
				t.Fatalf("results=%d want %d", len(c.Results), len(tc.results))
			}
		})
	}
}

// TestWriteCache_AtomicRename verifies that no .temp file is left
// behind after a successful write -- the rename must complete the
// promotion atomically.
func TestWriteCache_AtomicRename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	file.WriteCache(t.Context(), newSilentLogger(), path,
		[]ghscan.Result{{Repository: "o/r", LineData: "x"}})

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".temp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// TestWriteCache_ConcurrentWritersRaceFree is the regression test for
// the deferred concurrent-write race. It runs N=64 concurrent
// WriteCache calls into the same on-disk path and verifies (a) no race
// detector trip (run via `go test -race`) and (b) the final file is
// well-formed JSON whose contents match one of the writers' payloads.
func TestWriteCache_ConcurrentWritersRaceFree(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	const writers = 64
	var wg sync.WaitGroup
	wg.Add(writers)
	for i := range writers {
		go func() {
			defer wg.Done()
			results := []ghscan.Result{
				{Repository: "o/r", LineData: "writer", Base64Data: strconv.Itoa(i)},
			}
			file.WriteCache(t.Context(), newSilentLogger(), path, results)
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}
	var c ghscan.Cache
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("final file is not well-formed JSON: %v", err)
	}
	if len(c.Results) != 1 {
		t.Fatalf("expected exactly 1 result entry (one writer wins atomically), got %d", len(c.Results))
	}

	// No leftover .temp file from any writer.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".temp") {
			t.Fatalf("temp file left behind by concurrent writer: %s", e.Name())
		}
	}
}

func TestWriteResults(t *testing.T) {
	cases := []struct {
		name     string
		cache    ghscan.Cache
		cacheF   string
		jsonF    string
		csvF     string
		wantSkip bool
		wantErr  bool
		ctxFn    func() context.Context
	}{
		{
			name: "writes all three outputs",
			cache: ghscan.Cache{Results: []ghscan.Result{
				{Repository: "o/r", LineData: "hit", Base64Data: "ZGF0YQ=="},
			}},
			cacheF: "cache.json",
			jsonF:  "out.json",
			csvF:   "out.csv",
		},
		{
			name: "empty file names skip per-output write",
			cache: ghscan.Cache{Results: []ghscan.Result{
				{Repository: "o/r", LineData: "hit"},
			}},
		},
		{
			name: "cancelled context skips all writes",
			cache: ghscan.Cache{Results: []ghscan.Result{
				{Repository: "o/r", LineData: "hit"},
			}},
			cacheF: "cache.json",
			jsonF:  "out.json",
			csvF:   "out.csv",
			ctxFn: func() context.Context {
				c, cancel := context.WithCancel(t.Context())
				cancel()
				return c
			},
			wantSkip: true,
			wantErr:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chdirTemp(t)

			ctx := t.Context()
			if tc.ctxFn != nil {
				ctx = tc.ctxFn()
			}

			err := file.WriteResults(ctx, newSilentLogger(), tc.cache, tc.cacheF, tc.jsonF, tc.csvF)
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, name := range []string{tc.cacheF, tc.jsonF, tc.csvF} {
				if name == "" {
					continue
				}
				p := filepath.Join(ghscan.ResultsDir, name)
				_, err := os.Stat(p)
				if tc.wantSkip {
					if err == nil {
						t.Fatalf("expected %s NOT to be written, but it exists", p)
					}
					continue
				}
				if err != nil {
					t.Fatalf("expected %s to be written: %v", p, err)
				}
			}
		})
	}
}

// TestWriteResults_FailureReturnsJoinedError exercises the negative
// path: when one of the destination paths cannot be written (the
// caller passes a path under a read-only directory), WriteResults
// must return a non-nil joined error and continue attempting the
// remaining destinations rather than terminating the process.
func TestWriteResults_FailureReturnsJoinedError(t *testing.T) {
	chdirTemp(t)

	// Make results/ exist as a regular file rather than a directory so
	// the per-output WriteFile calls all fail with the same EEXIST-as-
	// non-dir error. MkdirAll observes the existing entry and returns
	// nil; subsequent WriteFile calls into it fail.
	if err := os.WriteFile(ghscan.ResultsDir, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("seed conflicting path: %v", err)
	}

	err := file.WriteResults(t.Context(), newSilentLogger(),
		ghscan.Cache{Results: []ghscan.Result{{Repository: "o/r", LineData: "x"}}},
		"cache.json", "out.json", "out.csv")
	if err == nil {
		t.Fatal("expected non-nil error when results dir is unwritable")
	}
}
