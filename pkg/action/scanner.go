package action

import (
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/tj-scan/pkg/file"
	tjscan "github.com/chainguard-dev/tj-scan/pkg/tj-scan"
)

type Scanner struct {
	logger    *clog.Logger
	results   chan []tjscan.Result
	cache     *tjscan.Cache
	cacheFile string
	flushSize int
	done      chan struct{}
}

func NewScanner(logger *clog.Logger, cache *tjscan.Cache, cacheFile string, flushSize int) *Scanner {
	s := &Scanner{
		logger:    logger,
		results:   make(chan []tjscan.Result, 10),
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
			file.WriteCache(s.logger, filepath.Join(tjscan.ResultsDir, s.cacheFile), s.cache.Results)
		}
	}

	if len(s.cache.Results) > 0 {
		file.WriteCache(s.logger, filepath.Join(tjscan.ResultsDir, s.cacheFile), s.cache.Results)
	}
	close(s.done)
}

func (s *Scanner) Add(results []tjscan.Result) {
	if len(results) > 0 {
		s.results <- results
	}
}

func (s *Scanner) Close() {
	close(s.results)
	<-s.done
}
