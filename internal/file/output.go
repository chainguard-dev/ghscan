package file

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/chainguard-dev/clog"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

// writeCacheMu serializes concurrent WriteCache callers. The streaming
// scanner and the per-repo fan-out in pkg/action both flush
// intermediate results to the same on-disk path; without serialization
// two goroutines can race on the tmp file and the rename, leaving a
// half-written cache or losing one writer's payload entirely.
var writeCacheMu sync.Mutex

func writeCSV(filename string, results []ghscan.Result) error {
	clean := filepath.Clean(filename)
	fileInfo, err := os.Stat(clean)
	if err == nil && fileInfo.IsDir() {
		return fmt.Errorf("cannot write to %s: is a directory", clean)
	}

	dir := filepath.Dir(clean)
	if dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	file, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer func() { _ = file.Close() }()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{
		"Repository",
		"WorkflowFileName",
		"WorkflowURL",
		"WorkflowRunURL",
		"Base64Data",
		"DecodedData",
		"LineData",
	}); err != nil {
		return err
	}

	for _, res := range results {
		if res.IsEmpty() {
			continue
		}
		record := []string{
			res.Repository,
			res.WorkflowFileName,
			res.WorkflowURL,
			res.WorkflowRunURL,
			res.Base64Data,
			res.DecodedData,
			res.LineData,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}

// WriteCache atomically persists the in-memory results slice to disk.
// ctx is consulted at function entry; long writes don't otherwise
// interleave system calls so finer-grained checks would not pay off.
//
// Concurrent calls are serialized by writeCacheMu so the tmp+rename
// dance is observed atomically by readers; without the lock two
// goroutines can race on the same tmp file and silently overwrite
// each other's payloads.
func WriteCache(ctx context.Context, logger *clog.Logger, cacheFile string, results []ghscan.Result) {
	if err := ctx.Err(); err != nil {
		logger.Warnf("WriteCache: context already cancelled: %v", err)
		return
	}

	writeCacheMu.Lock()
	defer writeCacheMu.Unlock()

	clean := filepath.Clean(cacheFile)
	dir := filepath.Dir(clean)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logger.Errorf("Error creating directory for intermediate results: %v", err)
		return
	}

	cache := ghscan.Cache{Results: results}
	cacheData, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		logger.Errorf("Error marshaling intermediate results: %v", err)
		return
	}

	tempFile := clean + ".temp"
	if err = os.WriteFile(tempFile, cacheData, 0o600); err != nil {
		logger.Errorf("Error writing intermediate results: %v", err)
		return
	}

	if err = os.Rename(tempFile, clean); err != nil {
		logger.Errorf("Error renaming intermediate results file: %v", err)
	}

	logger.Infof("Wrote intermediate results with %d entries", len(results))
}

// WriteResults persists the final cache, JSON, and CSV outputs. It
// returns the joined error across every output destination so a
// failure in one path does not silently mask a later success or
// prevent the others from being attempted. Pre-condition: ctx must
// be non-nil; ctx cancellation aborts the write attempt and surfaces
// ctx.Err() to the caller.
func WriteResults(ctx context.Context, logger *clog.Logger, cache ghscan.Cache, cacheFile, jsonFile, csvFile string) error {
	if err := ctx.Err(); err != nil {
		logger.Warnf("WriteResults: context already cancelled: %v", err)
		return err
	}
	if err := os.MkdirAll(ghscan.ResultsDir, 0o750); err != nil {
		return fmt.Errorf("creating results directory: %w", err)
	}
	cacheData, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cache: %w", err)
	}

	var errs error
	if cacheFile != "" {
		if werr := os.WriteFile(filepath.Join(ghscan.ResultsDir, cacheFile), cacheData, 0o600); werr != nil {
			logger.Errorf("Error writing cache file: %v", werr)
			errs = errors.Join(errs, fmt.Errorf("writing cache file: %w", werr))
		}
	}

	if jsonFile != "" {
		if werr := os.WriteFile(filepath.Join(ghscan.ResultsDir, jsonFile), cacheData, 0o600); werr != nil {
			logger.Errorf("Error writing JSON output: %v", werr)
			errs = errors.Join(errs, fmt.Errorf("writing JSON output: %w", werr))
		}
	}

	if csvFile != "" {
		if werr := writeCSV(filepath.Join(ghscan.ResultsDir, csvFile), cache.Results); werr != nil {
			logger.Errorf("Error writing CSV output: %v", werr)
			errs = errors.Join(errs, fmt.Errorf("writing CSV output: %w", werr))
		}
	}

	if errs == nil {
		logger.Infof("Successfully wrote %d results to outputs", len(cache.Results))
	}
	return errs
}
