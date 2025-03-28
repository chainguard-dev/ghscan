package file

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

func LoadCache(logger *clog.Logger, cacheFile string, cleanCache bool) ghscan.Cache {
	var cache ghscan.Cache

	cf := filepath.Clean(filepath.Join(filepath.Clean(ghscan.ResultsDir), filepath.Clean(cacheFile)))
	data, err := os.ReadFile(cf)
	if err != nil || cleanCache {
		logger.Infof("No existing cache found at %s, starting fresh", cacheFile)
		return cache
	}

	err = json.Unmarshal(data, &cache)
	if err != nil {
		logger.Warnf("Error parsing existing cache file: %v, starting fresh", err)
		return ghscan.Cache{}
	}

	logger.Infof("Loaded %d existing results from cache", len(cache.Results))
	return cache
}
