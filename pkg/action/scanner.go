package action

import (
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/pkg/file"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
)

type Scanner struct {
	logger    *clog.Logger
	results   chan []ghscan.Result
	cache     *ghscan.Cache
	cacheFile string
	flushSize int
	done      chan struct{}
}

func NewScanner(logger *clog.Logger, cache *ghscan.Cache, cacheFile string, flushSize int) *Scanner {
	s := &Scanner{
		logger:    logger,
		results:   make(chan []ghscan.Result, 10),
		cache:     cache,
		cacheFile: cacheFile,
		flushSize: flushSize,
		done:      make(chan struct{}),
	}

	go s.collect()
	return s
}

func (s *Scanner) collect() {
	for results := range s.results {
		s.cache.Results = append(s.cache.Results, results...)
		if len(s.cache.Results)%s.flushSize == 0 {
			file.WriteCache(s.logger, filepath.Join(ghscan.ResultsDir, s.cacheFile), s.cache.Results)
		}
	}

	if len(s.cache.Results) > 0 {
		file.WriteCache(s.logger, filepath.Join(ghscan.ResultsDir, s.cacheFile), s.cache.Results)
	}
	close(s.done)
}

func (s *Scanner) Add(results []ghscan.Result) {
	if len(results) > 0 {
		s.results <- results
	}
}

func (s *Scanner) Close() {
	close(s.results)
	<-s.done
}
