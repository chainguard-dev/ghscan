package ioc

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/cloudflare/ahocorasick"
)

// Hit is a single confirmed substring match: the IOC text and the byte
// offset within the scanned log where the match starts. Offset is -1
// when only existence is known (Aho-Corasick backend with thread-safe
// path that is not asked to return positions).
type Hit struct {
	IOC    string
	Offset int
}

// Matcher locates literal IOC substrings inside a log blob. Implementations
// must satisfy the no-false-negative invariant: every real substring match
// of a configured IOC in the input is reported.
type Matcher interface {
	// Match returns every IOC hit in log. The same IOC may appear multiple
	// times in the result if it occurs at multiple offsets.
	Match(log []byte) []Hit
	// MatchAny is the allocation-free yes/no path: it short-circuits as
	// soon as any configured IOC is confirmed in log. The deterministic
	// backend never builds a hit slice.
	MatchAny(log []byte) bool
	// MatchAnyString is the string-input twin of MatchAny. It avoids the
	// []byte(s) conversion that the call site would otherwise force when
	// the log is already in hand as a string (e.g. bufio.Scanner.Text()).
	MatchAnyString(log string) bool
}

// MatcherKind selects the deterministic matcher backend. The bloom
// prefilter wraps every backend.
type MatcherKind int

const (
	// MatcherAuto picks strings.Contains for tiny corpora and Aho-Corasick
	// at and above ahocorasickThreshold.
	MatcherAuto MatcherKind = iota
	// MatcherStrings forces the strings.Contains loop. Useful for tests
	// and tiny corpora where the AC build cost dominates.
	MatcherStrings
	// MatcherAhoCorasick forces the Aho-Corasick backend.
	MatcherAhoCorasick
)

const (
	// defaultNGramSize is the sliding-window width used to build and
	// query the bloom filter. Four bytes is the sweet spot for typical
	// IOC corpora (URLs, hex hashes, domains): three bytes admits too
	// many windows and inflates the false-positive rate; five bytes
	// rejects IOCs shorter than five characters.
	defaultNGramSize = 4
	// defaultBloomFP is the target bloom-filter false-positive rate.
	// One percent keeps the bit array small while leaving the
	// downstream deterministic matcher with very little extra work.
	defaultBloomFP = 0.01
	// ahocorasickThreshold is the corpus size at which MatcherAuto
	// switches from the strings.Contains loop to Aho-Corasick. Below
	// this threshold the AC build cost outweighs its asymptotic win.
	ahocorasickThreshold = 10
	// defaultBloomSkipThreshold is the corpus size at and below which the
	// bloom prefilter is skipped by default. For small corpora the
	// per-window hashing cost of the bloom Test() call dominates: at
	// M <= 50, deterministic strings.Contains (which short-circuits a
	// negative scan via Boyer-Moore-Horspool, leveraging Go's runtime
	// SIMD-accelerated bytealg) beats a per-window bloom test by a
	// constant factor; at M up to ~100, even the Aho-Corasick backend
	// outruns the bloom-then-AC pipeline because per-line bloom hashing
	// approaches the cost of a single AC scan. The empirical crossover
	// where bloom + AC starts to win sits near M ~= 500 on modern
	// hardware; 50 is a conservative threshold that captures the gains
	// for small-M production workloads (M=1, M=10) without giving up the
	// asymptotic win at large M. Override via WithBloomSkipThreshold.
	defaultBloomSkipThreshold = 50
)

// Option configures a Matcher at construction.
type Option func(*matcherConfig)

type matcherConfig struct {
	nGram             int
	bloomFP           float64
	kind              MatcherKind
	bloomSkipThresh   int
	bloomSkipThreshOK bool
	caseInsensitive   bool
}

// WithNGramSize overrides the default n-gram width used to build the
// bloom prefilter. Values <= 0 are rejected by NewMatcher.
func WithNGramSize(n int) Option {
	return func(c *matcherConfig) { c.nGram = n }
}

// WithBloomFP overrides the bloom-filter target false-positive rate.
// Values outside (0, 1) are rejected by NewMatcher.
func WithBloomFP(fp float64) Option {
	return func(c *matcherConfig) { c.bloomFP = fp }
}

// WithMatcher forces a specific deterministic backend. Defaults to
// MatcherAuto, which picks per corpus size.
func WithMatcher(k MatcherKind) Option {
	return func(c *matcherConfig) { c.kind = k }
}

// WithBloomSkipThreshold overrides the corpus-size threshold at and below
// which the bloom prefilter is bypassed when the resolved backend is
// MatcherStrings. Negative values are rejected by NewMatcher; zero
// disables the bypass entirely (always run the prefilter). The default is
// 50 -- see defaultBloomSkipThreshold for the empirical rationale.
func WithBloomSkipThreshold(n int) Option {
	return func(c *matcherConfig) {
		c.bloomSkipThresh = n
		c.bloomSkipThreshOK = true
	}
}

// WithCaseInsensitive folds both the corpus and every scanned log to
// ASCII lower case before matching. This is the right setting for IOCs
// whose canonical form is case-stable but whose appearances in
// real-world logs are not (hex digests, SHAs, URL paths). Folding is
// byte-level and uses strings.ToLower; it is not Unicode-aware beyond
// what strings.ToLower provides.
func WithCaseInsensitive() Option {
	return func(c *matcherConfig) { c.caseInsensitive = true }
}

// matcher is the concrete Matcher returned by NewMatcher. The bloom
// prefilter and the deterministic backend are both immutable after
// construction so the value is safe to share across goroutines.
//
// Bloom-filter sizing semantics: the bloom is built once at
// construction over every n-gram window of every IOC; the parameter
// n passed to bloom.NewWithEstimates is the count of unique windows.
// Once frozen, the bit array does NOT grow as the IOC corpus is later
// resized (the matcher is immutable). The reported false-positive
// rate (defaultBloomFP) is the per-window union-bound at the bloom
// gate, not a per-line nor per-log rate; per-line FPR for a log of L
// windows approaches 1 - (1 - fp)^L which is loose by Kolmogorov's
// inequality when n is small. The deterministic backend behind the
// bloom always confirms hits so this constant-factor noise affects
// throughput, not correctness (the no-false-negative invariant
// holds: every real substring match is reported).
//
// Hash function: bits-and-blooms uses Murmur3 internally. Murmur3 is
// non-cryptographic. The threat model here assumes log content is
// non-adversarial -- IOC scanning targets accidental disclosure of
// known-bad strings, not a deliberate attacker crafting collisions
// to evade detection. Adversarial settings (defender vs. a producer
// of log content) would need a keyed cryptographic hash and a
// rebuilt bloom; that is out of scope.
type matcher struct {
	iocs      []string
	iocsB     [][]byte // pre-encoded byte slices to avoid per-call []byte(s) allocation
	nGram     int
	bloom     *bloom.BloomFilter
	kind      MatcherKind
	ac        *ahocorasick.Matcher
	acIndex   []string
	acIndexB  [][]byte // byte forms of acIndex reused per AC hit
	skipBloom bool
	foldCase  bool
}

var _ Matcher = (*matcher)(nil)

// NewMatcher builds a Matcher over iocs. Empty entries are dropped.
// If iocs is empty the returned Matcher always reports no hits.
func NewMatcher(iocs []string, opts ...Option) (Matcher, error) {
	cfg := matcherConfig{
		nGram:           defaultNGramSize,
		bloomFP:         defaultBloomFP,
		kind:            MatcherAuto,
		bloomSkipThresh: defaultBloomSkipThreshold,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.nGram <= 0 {
		return nil, fmt.Errorf("n-gram size must be positive, got %d", cfg.nGram)
	}
	if cfg.bloomFP <= 0 || cfg.bloomFP >= 1 {
		return nil, fmt.Errorf("bloom false-positive rate must be in (0, 1), got %v", cfg.bloomFP)
	}
	if cfg.bloomSkipThreshOK && cfg.bloomSkipThresh < 0 {
		return nil, fmt.Errorf("bloom-skip threshold must be non-negative, got %d", cfg.bloomSkipThresh)
	}

	cleaned := make([]string, 0, len(iocs))
	for _, s := range iocs {
		if s == "" {
			continue
		}
		if cfg.caseInsensitive {
			s = strings.ToLower(s)
		}
		cleaned = append(cleaned, s)
	}

	cleanedB := make([][]byte, len(cleaned))
	for i, s := range cleaned {
		cleanedB[i] = []byte(s)
	}

	m := &matcher{
		iocs:     cleaned,
		iocsB:    cleanedB,
		nGram:    cfg.nGram,
		kind:     cfg.kind,
		foldCase: cfg.caseInsensitive,
	}

	if len(cleaned) == 0 {
		// Empty corpus: no n-grams to add. Build a token bloom filter
		// so Test never panics, and skip the deterministic backend.
		m.bloom = bloom.NewWithEstimates(1, cfg.bloomFP)
		return m, nil
	}

	// IOCs shorter than nGram cannot contribute any window. The bloom
	// prefilter would silently miss them, violating the no-false-
	// negative invariant. Fall back to MatcherStrings or fail loudly.
	for _, s := range cleaned {
		if len(s) < cfg.nGram {
			// Force MatcherStrings: short IOCs bypass the bloom filter
			// because they cannot generate any n-gram window of size
			// nGram. The bloom prefilter applies only to IOCs >= nGram;
			// for shorter IOCs, the deterministic matcher is queried
			// unconditionally.
			m.kind = MatcherStrings
			break
		}
	}

	// Build the bloom filter over every n-gram of every IOC. The
	// running total is summed in int (string lengths are non-negative
	// by construction, so the difference cannot underflow given the
	// len(s) >= cfg.nGram guard) and converted to uint for the bloom
	// library at the end.
	totalNGrams := 0
	for _, s := range cleaned {
		if len(s) >= cfg.nGram {
			totalNGrams += len(s) - cfg.nGram + 1
		}
	}
	if totalNGrams <= 0 {
		totalNGrams = 1
	}
	m.bloom = bloom.NewWithEstimates(uint(totalNGrams), cfg.bloomFP)
	for _, s := range cleaned {
		b := []byte(s)
		if len(b) < cfg.nGram {
			continue
		}
		for i := 0; i+cfg.nGram <= len(b); i++ {
			m.bloom.Add(b[i : i+cfg.nGram])
		}
	}

	// Decide deterministic backend.
	resolvedKind := m.kind
	if resolvedKind == MatcherAuto {
		if len(cleaned) >= ahocorasickThreshold {
			resolvedKind = MatcherAhoCorasick
		} else {
			resolvedKind = MatcherStrings
		}
	}
	m.kind = resolvedKind

	if resolvedKind == MatcherAhoCorasick {
		m.ac = ahocorasick.NewStringMatcher(cleaned)
		m.acIndex = cleaned
		m.acIndexB = make([][]byte, len(cleaned))
		for i, s := range cleaned {
			m.acIndexB[i] = []byte(s)
		}
	}

	// Small corpora skip the bloom prefilter entirely: hashing every
	// n-gram window via bloom Test() is constant-factor expensive and
	// at small M the deterministic backend (strings.Contains or AC) is
	// fast enough to scan the whole line directly. The no-false-negative
	// invariant is preserved because the deterministic backend always
	// runs after a bloom skip. Threshold is configurable via
	// WithBloomSkipThreshold; the default (50) reflects the empirical
	// crossover on the per-line scan workload for both backends.
	if len(cleaned) <= cfg.bloomSkipThresh {
		m.skipBloom = true
	}

	return m, nil
}

// Match runs the bloom prefilter and, on any window hit, the
// deterministic backend. Matches are returned in stable order (per IOC
// occurrence in the configured list).
func (m *matcher) Match(log []byte) []Hit {
	if len(m.iocs) == 0 || len(log) == 0 {
		return nil
	}

	if m.foldCase {
		log = bytes.ToLower(log)
	}

	if !m.skipBloom && !m.maybeContainsAny(log) {
		return nil
	}

	switch m.kind {
	case MatcherAhoCorasick:
		return m.matchAhoCorasick(log)
	default:
		return m.matchStrings(log)
	}
}

// maybeContainsAny is the bloom-prefilter gate. It returns true iff at
// least one log window hits the filter; on a miss for every window, no
// configured IOC can possibly match (zero false negatives by
// construction). When the corpus contains any IOC shorter than nGram
// this gate is bypassed -- those short IOCs are not represented in the
// bloom filter and the deterministic matcher must run unconditionally.
func (m *matcher) maybeContainsAny(log []byte) bool {
	for _, s := range m.iocs {
		if len(s) < m.nGram {
			return true
		}
	}
	if len(log) < m.nGram {
		// Any IOC of length nGram or more cannot fit in this log;
		// only short IOCs (handled above) could match. Since none
		// did, no match is possible.
		return false
	}
	for i := 0; i+m.nGram <= len(log); i++ {
		if m.bloom.Test(log[i : i+m.nGram]) {
			return true
		}
	}
	return false
}

// matchStrings runs the strings.Contains backend, recording every
// occurrence of every IOC. Offsets are computed via bytes.Index.
func (m *matcher) matchStrings(log []byte) []Hit {
	var hits []Hit
	for i, needle := range m.iocsB {
		if len(needle) == 0 {
			continue
		}
		s := m.iocs[i]
		offset := 0
		for {
			rel := bytes.Index(log[offset:], needle)
			if rel < 0 {
				break
			}
			hits = append(hits, Hit{IOC: s, Offset: offset + rel})
			offset += rel + 1
		}
	}
	return hits
}

// matchAhoCorasick runs the Aho-Corasick backend, then computes per-IOC
// offsets via bytes.Index for the matched dictionary entries. The
// upstream library only returns dictionary indices, not offsets.
func (m *matcher) matchAhoCorasick(log []byte) []Hit {
	// MatchThreadSafe is read-only on the constructed automaton and
	// safe to call from multiple goroutines concurrently.
	idxs := m.ac.MatchThreadSafe(log)
	if len(idxs) == 0 {
		return nil
	}
	var hits []Hit
	for _, i := range idxs {
		s := m.acIndex[i]
		needle := m.acIndexB[i]
		offset := 0
		for {
			rel := bytes.Index(log[offset:], needle)
			if rel < 0 {
				break
			}
			hits = append(hits, Hit{IOC: s, Offset: offset + rel})
			offset += rel + 1
		}
	}
	return hits
}

// MatcherKindOf returns the resolved deterministic backend for m. It is
// exposed for tests that assert backend selection behavior.
func MatcherKindOf(m Matcher) MatcherKind {
	if mm, ok := m.(*matcher); ok {
		return mm.kind
	}
	return MatcherAuto
}

// MatchAny is the allocation-free yes/no path. It short-circuits as soon
// as any IOC is confirmed, so the deterministic backend never builds a
// hit slice. Allocates nothing on the happy path (case-insensitive mode
// allocates a single per-call lower-cased copy).
func (m *matcher) MatchAny(log []byte) bool {
	if len(m.iocs) == 0 || len(log) == 0 {
		return false
	}
	if m.foldCase {
		log = bytes.ToLower(log)
	}
	if !m.skipBloom && !m.maybeContainsAny(log) {
		return false
	}
	if m.kind == MatcherAhoCorasick {
		return m.ac.Contains(log)
	}
	for _, b := range m.iocsB {
		if bytes.Contains(log, b) {
			return true
		}
	}
	return false
}

// MatchAnyString is the string-input twin of MatchAny. It avoids the
// []byte(s) conversion that the caller would otherwise have to do when
// the log is already in hand as a string (e.g. bufio.Scanner.Text()).
//
// The hot path -- skipBloom && MatcherStrings -- is the M=1 production
// default and is inlined in full so the loop body avoids any extra
// branches.
func (m *matcher) MatchAnyString(log string) bool {
	if len(m.iocs) == 0 || len(log) == 0 {
		return false
	}
	if m.foldCase {
		log = strings.ToLower(log)
	}
	// Hot path: small-corpus, strings.Contains backend, bloom skipped.
	// This is the production default for M <= bloomSkipThreshold and is
	// the dominant cost in per-line workflow log scanning.
	if m.skipBloom && m.kind == MatcherStrings {
		for _, s := range m.iocs {
			if strings.Contains(log, s) {
				return true
			}
		}
		return false
	}
	if !m.skipBloom && !m.maybeContainsAnyString(log) {
		return false
	}
	if m.kind == MatcherAhoCorasick {
		// ahocorasick.Matcher only exposes a []byte API; the
		// conversion here is unavoidable, but it happens at most once
		// per line (no per-IOC inner loop). Aho-Corasick is selected
		// only at M >= 10, so the cost is amortized over the corpus.
		return m.ac.Contains([]byte(log))
	}
	for _, s := range m.iocs {
		if strings.Contains(log, s) {
			return true
		}
	}
	return false
}

// maybeContainsAnyString is the string-input twin of maybeContainsAny.
// It walks the log byte-by-byte without converting it to a []byte.
func (m *matcher) maybeContainsAnyString(log string) bool {
	for _, s := range m.iocs {
		if len(s) < m.nGram {
			return true
		}
	}
	if len(log) < m.nGram {
		return false
	}
	// bloom.Test takes []byte; allocate a single backing buffer and
	// reuse it across windows by re-slicing log via unsafe-free
	// conversion. The bloom library hashes the bytes; we must hand it
	// a []byte. Per-window []byte(log[i:j]) would allocate; instead
	// pass through TestString-equivalent: bits-and-blooms only ships
	// AddString/TestString that accept strings directly.
	for i := 0; i+m.nGram <= len(log); i++ {
		if m.bloom.TestString(log[i : i+m.nGram]) {
			return true
		}
	}
	return false
}
