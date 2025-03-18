package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/chainguard-dev/clog"
	tjscan "github.com/chainguard-dev/tj-scan/pkg/tj-scan"
)

func LoadExistingCache(logger *clog.Logger, cacheFile string) tjscan.Cache {
	var cache tjscan.Cache
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		logger.Infof("No existing cache found at %s, starting fresh", cacheFile)
		return cache
	}

	err = json.Unmarshal(data, &cache)
	if err != nil {
		logger.Warnf("Error parsing existing cache file: %v, starting fresh", err)
		return tjscan.Cache{}
	}

	//nolint:nestif //ignore nested complexity of 12
	for i, result := range cache.Results {
		if result.WorkflowRunURL == "" {
			repoParts := strings.Split(result.Repository, "/")
			if len(repoParts) == 2 {
				owner, repo := repoParts[0], repoParts[1]

				var runID int64
				if strings.Contains(result.LineLinkOrNum, "runs/") {
					parts := strings.Split(result.LineLinkOrNum, "runs/")
					if len(parts) > 1 {
						idStr := strings.Split(parts[1], "/")[0]
						id, err := strconv.ParseInt(idStr, 10, 64)
						if err == nil {
							runID = id
						}
					}
				}

				if runID > 0 {
					cache.Results[i].WorkflowRunURL = fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d",
						owner, repo, runID)
				}
			}
		}
	}

	logger.Infof("Loaded %d existing results from cache", len(cache.Results))
	return cache
}
