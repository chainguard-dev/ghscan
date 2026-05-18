package file

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

// LoadCache reads and decodes the on-disk findings cache. The ctx is
// honored before each filesystem touch so a cancelled program does
// not perform spurious IO; if ctx is already cancelled, an empty
// cache is returned.
func LoadCache(ctx context.Context, logger *clog.Logger, cacheFile string, cleanCache bool) ghscan.Cache {
	var cache ghscan.Cache
	if err := ctx.Err(); err != nil {
		logger.Warnf("LoadCache: context already cancelled: %v", err)
		return cache
	}

	cf := filepath.Clean(filepath.Join(filepath.Clean(ghscan.ResultsDir), filepath.Clean(cacheFile)))
	data, err := os.ReadFile(cf)
	if err != nil || cleanCache {
		logger.Infof("No existing cache found at %s, starting fresh", cacheFile)
		return cache
	}

	if err := json.Unmarshal(data, &cache); err != nil {
		logger.Warnf("Error parsing existing cache file: %v, starting fresh", err)
		return ghscan.Cache{}
	}

	logger.Infof("Loaded %d existing results from cache", len(cache.Results))
	return cache
}
