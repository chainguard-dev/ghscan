package file

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	tjscan "github.com/chainguard-dev/tj-scan/pkg/tj-scan"
)

func LoadCache(logger *clog.Logger, cacheFile string, cleanCache bool) tjscan.Cache {
	var cache tjscan.Cache

	cf := filepath.Clean(filepath.Join(filepath.Clean(tjscan.ResultsDir), filepath.Clean(cacheFile)))
	data, err := os.ReadFile(cf)
	if err != nil || cleanCache {
		logger.Infof("No existing cache found at %s, starting fresh", cacheFile)
		return cache
	}

	err = json.Unmarshal(data, &cache)
	if err != nil {
		logger.Warnf("Error parsing existing cache file: %v, starting fresh", err)
		return tjscan.Cache{}
	}

	logger.Infof("Loaded %d existing results from cache", len(cache.Results))
	return cache
}
