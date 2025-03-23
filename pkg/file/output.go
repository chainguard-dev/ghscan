package file

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	tjscan "github.com/chainguard-dev/tj-scan/pkg/tj-scan"
)

func writeCSV(filename string, results []tjscan.Result) error {
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
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{
		"Repository",
		"WorkflowFileName",
		"WorkflowURL",
		"WorkflowRunURL",
		"Base64Data",
		"DecodedData",
	}); err != nil {
		return err
	}

	for _, res := range results {
		record := []string{
			res.Repository,
			res.WorkflowFileName,
			res.WorkflowURL,
			res.WorkflowRunURL,
			res.Base64Data,
			res.DecodedData,
			res.EmptyLines,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func WriteCache(logger *clog.Logger, cacheFile string, results []tjscan.Result) {
	clean := filepath.Clean(cacheFile)
	dir := filepath.Dir(clean)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logger.Errorf("Error creating directory for intermediate results: %v", err)
		return
	}

	cache := tjscan.Cache{Results: results}
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

func WriteResults(logger *clog.Logger, cache tjscan.Cache, cacheFile, jsonFile, csvFile string) {
	err := os.MkdirAll(tjscan.ResultsDir, 0o750)
	if err != nil {
		logger.Fatalf("Error creating results directory: %v", err)
	}
	cacheData, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		logger.Fatalf("Error marshaling cache: %v", err)
	}

	if cacheFile != "" {
		if err = os.WriteFile(filepath.Join(tjscan.ResultsDir, cacheFile), cacheData, 0o600); err != nil {
			logger.Fatalf("Error writing cache file: %v", err)
		}
	}

	if jsonFile != "" {
		if err = os.WriteFile(filepath.Join(tjscan.ResultsDir, jsonFile), cacheData, 0o600); err != nil {
			logger.Fatalf("Error writing JSON output: %v", err)
		}
	}

	if csvFile != "" {
		if err = writeCSV(filepath.Join(tjscan.ResultsDir, csvFile), cache.Results); err != nil {
			logger.Fatalf("Error writing CSV output: %v", err)
		}
	}

	logger.Infof("Successfully wrote %d results to outputs", len(cache.Results))
}
