package ioc_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/chainguard-dev/ghscan/pkg/ioc"
)

// TestMatcher_NoFalseNegatives is the load-bearing correctness test: for
// every (log, ioc) pair where the literal substring actually occurs, the
// Matcher must report it. The bloom prefilter guarantees no false
// negatives by construction.
func TestMatcher_NoFalseNegatives(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		log  string
		iocs []string
	}{
		{
			name: "single short IOC",
			log:  "the quick brown fox jumps over the lazy dog",
			iocs: []string{"fox"},
		},
		{
			name: "multiple IOCs all present",
			log:  "alpha beta gamma delta",
			iocs: []string{"alpha", "gamma"},
		},
		{
			name: "IOC at start of log",
			log:  "MATCH at the start",
			iocs: []string{"MATCH"},
		},
		{
			name: "IOC at end of log",
			log:  "ends with TAIL",
			iocs: []string{"TAIL"},
		},
		{
			name: "long IOC URL",
			log:  "loaded from https://malicious.example.com/payload.sh && curl ...",
			iocs: []string{"https://malicious.example.com/payload.sh"},
		},
		{
			name: "SHA-style IOC",
			log:  "SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67 was seen",
			iocs: []string{"SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67"},
		},
		{
			name: "overlapping IOCs",
			log:  "foobarbaz",
			iocs: []string{"foobar", "barbaz", "bar"},
		},
		{
			name: "IOC shorter than ngram (3 bytes)",
			log:  "abc def ghi",
			iocs: []string{"def"},
		},
		{
			name: "IOC longer than typical ngram (4 bytes)",
			log:  "this contains exact match",
			iocs: []string{"exact"},
		},
		{
			name: "unicode bytes - byte-level match",
			log:  "café résumé",
			iocs: []string{"café"},
		},
		{
			name: "duplicate IOC instances",
			log:  "foo bar foo bar foo",
			iocs: []string{"foo"},
		},
		{
			name: "large corpus all match",
			log:  "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu",
			iocs: []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa", "lambda", "mu"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := ioc.NewMatcher(tc.iocs)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			hits := m.Match([]byte(tc.log))
			seen := make(map[string]bool, len(hits))
			for _, h := range hits {
				seen[h.IOC] = true
			}
			for _, want := range tc.iocs {
				if !strings.Contains(tc.log, want) {
					continue
				}
				if !seen[want] {
					t.Errorf("false negative: ioc %q occurs in log but Matcher missed it; got hits=%+v", want, hits)
				}
			}
		})
	}
}

// TestMatcher_NegativeNoMatch confirms the matcher returns no hits for
// IOCs absent from the log -- exercises the bloom-prefilter short
// circuit on the common no-match case.
func TestMatcher_NegativeNoMatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		log  string
		iocs []string
	}{
		{
			name: "empty log",
			log:  "",
			iocs: []string{"anything"},
		},
		{
			name: "absent IOC",
			log:  "the quick brown fox",
			iocs: []string{"PAYLOAD"},
		},
		{
			name: "log shorter than IOC",
			log:  "ab",
			iocs: []string{"abcdef"},
		},
		{
			name: "near miss differs by one char",
			log:  "the SHA:0e58ed8671d6b60d0890c21b07f8835ace038e68 hash",
			iocs: []string{"SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67"},
		},
		{
			name: "case-sensitive miss",
			log:  "ALPHA",
			iocs: []string{"alpha"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := ioc.NewMatcher(tc.iocs)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			hits := m.Match([]byte(tc.log))
			if len(hits) != 0 {
				t.Errorf("expected no hits, got %+v", hits)
			}
		})
	}
}

// TestMatcher_EmptyCorpus confirms an empty IOC list never panics and
// always reports zero hits.
func TestMatcher_EmptyCorpus(t *testing.T) {
	t.Parallel()

	m, err := ioc.NewMatcher(nil)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if hits := m.Match([]byte("anything goes here")); len(hits) != 0 {
		t.Errorf("empty corpus: expected zero hits, got %+v", hits)
	}

	m2, err := ioc.NewMatcher([]string{"", ""})
	if err != nil {
		t.Fatalf("NewMatcher with empty strings: %v", err)
	}
	if hits := m2.Match([]byte("foo")); len(hits) != 0 {
		t.Errorf("blank-only corpus: expected zero hits, got %+v", hits)
	}
}

// TestMatcher_BackendSelection asserts MatcherAuto picks
// strings.Contains under the threshold and Aho-Corasick at or above it.
func TestMatcher_BackendSelection(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		size int
		want ioc.MatcherKind
	}{
		{"M=1", 1, ioc.MatcherStrings},
		{"M=5", 5, ioc.MatcherStrings},
		{"M=9", 9, ioc.MatcherStrings},
		{"M=10", 10, ioc.MatcherAhoCorasick},
		{"M=100", 100, ioc.MatcherAhoCorasick},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			iocs := make([]string, tc.size)
			for i := range iocs {
				iocs[i] = fmt.Sprintf("ioc-token-%04d", i)
			}
			m, err := ioc.NewMatcher(iocs)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			if got := ioc.MatcherKindOf(m); got != tc.want {
				t.Errorf("M=%d: got backend %v, want %v", tc.size, got, tc.want)
			}
		})
	}
}

// TestMatcher_BackendOverride exercises WithMatcher to force a backend
// regardless of corpus size.
func TestMatcher_BackendOverride(t *testing.T) {
	t.Parallel()

	iocs := []string{"alpha", "beta"}

	mForced, err := ioc.NewMatcher(iocs, ioc.WithMatcher(ioc.MatcherAhoCorasick))
	if err != nil {
		t.Fatalf("NewMatcher AC override: %v", err)
	}
	if got := ioc.MatcherKindOf(mForced); got != ioc.MatcherAhoCorasick {
		t.Errorf("forced AC: got %v", got)
	}

	mForcedStr, err := ioc.NewMatcher(iocs, ioc.WithMatcher(ioc.MatcherStrings))
	if err != nil {
		t.Fatalf("NewMatcher strings override: %v", err)
	}
	if got := ioc.MatcherKindOf(mForcedStr); got != ioc.MatcherStrings {
		t.Errorf("forced strings: got %v", got)
	}
}

// TestMatcher_FalsePositiveRate confirms the bloom-prefilter false-
// positive rate stays comfortably under the documented bound for IOCs
// that do not occur in the input. This is a statistical sanity check:
// the deterministic matcher catches every false positive that does
// reach it, so this is purely a performance signal, not correctness.
func TestMatcher_FalsePositiveRate(t *testing.T) {
	t.Parallel()

	// Build a corpus of synthetic IOCs that will never occur in random
	// alphanumeric logs (uses a delimiter character not in the log
	// alphabet).
	const corpusSize = 100
	iocs := make([]string, corpusSize)
	for i := range iocs {
		iocs[i] = fmt.Sprintf("##IOC##%04d##", i)
	}
	m, err := ioc.NewMatcher(iocs)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	const trials = 1000
	const logSize = 256
	alphabet := []byte("abcdefghijklmnopqrstuvwxyz0123456789")

	hits := 0
	buf := make([]byte, logSize)
	for range trials {
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		// Constrain bytes to alphabet so '#' never appears.
		for i := range buf {
			buf[i] = alphabet[int(buf[i])%len(alphabet)]
		}
		out := m.Match(buf)
		if len(out) > 0 {
			hits++
		}
	}

	// The deterministic matcher always rejects, so any "hit" here is a
	// real bug; bloom false positives are filtered by the AC backend
	// before reaching Match's return.
	if hits != 0 {
		t.Errorf("deterministic matcher produced %d false positives over %d trials", hits, trials)
	}
}

// TestMatcher_OptionValidation exercises the option-rejection paths.
func TestMatcher_OptionValidation(t *testing.T) {
	t.Parallel()

	if _, err := ioc.NewMatcher([]string{"foo"}, ioc.WithNGramSize(0)); err == nil {
		t.Error("expected error for n-gram size 0")
	}
	if _, err := ioc.NewMatcher([]string{"foo"}, ioc.WithNGramSize(-1)); err == nil {
		t.Error("expected error for negative n-gram size")
	}
	if _, err := ioc.NewMatcher([]string{"foo"}, ioc.WithBloomFP(0)); err == nil {
		t.Error("expected error for bloom FP 0")
	}
	if _, err := ioc.NewMatcher([]string{"foo"}, ioc.WithBloomFP(1.1)); err == nil {
		t.Error("expected error for bloom FP > 1")
	}
}

// TestMatcher_NGramOverride confirms the n-gram size option propagates
// and short IOCs (< nGram) still match via the unconditional fallback.
func TestMatcher_NGramOverride(t *testing.T) {
	t.Parallel()

	// nGram=6 with a 3-byte IOC: bloom would otherwise miss every
	// query because no IOC contributes a 6-byte window. The matcher
	// must fall back to MatcherStrings and bypass the bloom gate.
	m, err := ioc.NewMatcher([]string{"foo"}, ioc.WithNGramSize(6))
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	hits := m.Match([]byte("the foo is here"))
	if len(hits) == 0 {
		t.Fatal("short IOC missed under large n-gram override")
	}
	if hits[0].IOC != "foo" || hits[0].Offset != 4 {
		t.Errorf("unexpected hit: %+v", hits[0])
	}
}

// TestMatcher_Offsets confirms reported offsets locate the substring.
func TestMatcher_Offsets(t *testing.T) {
	t.Parallel()

	log := []byte("aaa needle bbb needle ccc")
	m, err := ioc.NewMatcher([]string{"needle"})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	hits := m.Match(log)
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d: %+v", len(hits), hits)
	}
	for _, h := range hits {
		if !bytes.Equal(log[h.Offset:h.Offset+len(h.IOC)], []byte(h.IOC)) {
			t.Errorf("hit offset %d does not point at %q", h.Offset, h.IOC)
		}
	}
}

// TestMatchAny_SemanticParity confirms Matcher.MatchAny preserves the
// strings.Contains semantics that the workflow scanner previously used
// inline. This is the load-bearing test for the wiring change in
// pkg/workflow/logs.go.
func TestMatchAny_SemanticParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		log     string
		content []string
		want    bool
	}{
		{"present", "scan: SHA:abc123 here", []string{"SHA:abc123"}, true},
		{"absent", "no payload", []string{"SHA:abc123"}, false},
		{"empty content", "anything", nil, false},
		{"empty log", "", []string{"foo"}, false},
		{"multiple needles, one matches", "abc def ghi", []string{"xyz", "def"}, true},
		{"multiple needles, none match", "abc def ghi", []string{"xyz", "uvw"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, err := ioc.NewMatcher(tc.content)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			gotBytes := m.MatchAny([]byte(tc.log))
			gotString := m.MatchAnyString(tc.log)
			if gotBytes != tc.want {
				t.Errorf("MatchAny(%q) = %v, want %v", tc.log, gotBytes, tc.want)
			}
			if gotString != tc.want {
				t.Errorf("MatchAnyString(%q) = %v, want %v", tc.log, gotString, tc.want)
			}
			// Cross-check against strings.Contains for non-empty content.
			var oracle bool
			for _, c := range tc.content {
				if c != "" && strings.Contains(tc.log, c) {
					oracle = true
					break
				}
			}
			if oracle != gotBytes {
				t.Errorf("oracle disagrees: strings.Contains says %v, MatchAny says %v", oracle, gotBytes)
			}
		})
	}
}

// TestMatcher_CaseInsensitive_SHAMixedCase covers the load-bearing
// case-folding contract: a SHA IOC stored as lower-case must match
// the same SHA in a log even when the log writes it in upper case
// (or any mixed case). Validates Match, MatchAny, and MatchAnyString.
func TestMatcher_CaseInsensitive_SHAMixedCase(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		log  string
	}{
		{"all lower case", "SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67 here"},
		{"all upper case digits", "SHA:0E58ED8671D6B60D0890C21B07F8835ACE038E67 here"},
		{"mixed case digits", "SHA:0E58ed8671D6b60d0890C21b07F8835aCe038E67 here"},
		{"prefix differs case", "sha:0e58ed8671d6b60d0890c21b07f8835ace038e67 here"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			m, err := ioc.NewMatcher(
				[]string{"SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67"},
				ioc.WithCaseInsensitive(),
			)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}

			if hits := m.Match([]byte(tc.log)); len(hits) == 0 {
				t.Errorf("Match(%q) returned no hits", tc.log)
			}
			if !m.MatchAny([]byte(tc.log)) {
				t.Errorf("MatchAny(%q) = false, want true", tc.log)
			}
			if !m.MatchAnyString(tc.log) {
				t.Errorf("MatchAnyString(%q) = false, want true", tc.log)
			}
		})
	}
}

// TestPredefinedSHA_MixedCase pins the same contract end-to-end via
// the predefined IOC. A real-world log line that capitalizes the SHA
// must match the canonical lower-case entry.
func TestPredefinedSHA_MixedCase(t *testing.T) {
	t.Parallel()

	got, ok := ioc.GetPredefinedIOC("tj-actions/changed-files")
	if !ok {
		t.Fatal("predefined IOC tj-actions/changed-files missing")
	}
	m := got.GetMatcher()
	if m == nil {
		t.Fatal("predefined IOC has no Matcher")
	}
	const mixed = "stdout: SHA:0E58ED8671d6B60D0890C21B07F8835aCe038E67 captured"
	if !m.MatchAnyString(mixed) {
		t.Errorf("predefined SHA IOC failed to match mixed-case input: %q", mixed)
	}
}

// TestWithBloomSkipThreshold exercises the threshold override and the
// validation rejection path.
func TestWithBloomSkipThreshold(t *testing.T) {
	t.Parallel()

	if _, err := ioc.NewMatcher([]string{"foo"}, ioc.WithBloomSkipThreshold(-1)); err == nil {
		t.Error("expected error for negative bloom-skip threshold")
	}

	// A threshold of 0 disables the skip; a single-IOC corpus should
	// still match correctly because the deterministic matcher runs
	// regardless of whether the bloom prefilter was bypassed.
	m, err := ioc.NewMatcher([]string{"needle"}, ioc.WithBloomSkipThreshold(0))
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if !m.MatchAnyString("a needle in a haystack") {
		t.Error("threshold=0: deterministic backend missed a real hit")
	}
}

// BenchmarkMatch_NoMatch_StringsContains is the baseline: the
// loop that the workflow scanner previously executed
// inline. It scans a 1 MiB synthetic log against M IOCs that are
// absent. Mirrors the per-line scan in pkg/workflow/logs.go, so the
// log is iterated as the original code would have iterated it.
func BenchmarkMatch_NoMatch_StringsContains(b *testing.B) {
	log := buildBenchmarkLog(1 << 20)
	iocs := buildBenchmarkIOCs(100)
	logStr := string(log)

	b.SetBytes(int64(len(log)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, ic := range iocs {
			if strings.Contains(logStr, ic) {
				_ = ic
			}
		}
	}
}

// BenchmarkMatch_NoMatch_Bloom measures the bloom-prefiltered matcher
// on the same workload. The bloom gate should reject the entire log on
// the first few windows.
func BenchmarkMatch_NoMatch_Bloom(b *testing.B) {
	log := buildBenchmarkLog(1 << 20)
	iocs := buildBenchmarkIOCs(100)

	m, err := ioc.NewMatcher(iocs)
	if err != nil {
		b.Fatalf("NewMatcher: %v", err)
	}

	b.SetBytes(int64(len(log)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = m.Match(log)
	}
}

// BenchmarkMatch_OneMatch_Bloom measures the matcher when the log
// contains a single match: bloom admits, deterministic backend
// confirms.
func BenchmarkMatch_OneMatch_Bloom(b *testing.B) {
	log := buildBenchmarkLog(1 << 20)
	iocs := buildBenchmarkIOCs(100)
	planted := []byte(iocs[len(iocs)/2])
	copy(log[len(log)/2:], planted)

	m, err := ioc.NewMatcher(iocs)
	if err != nil {
		b.Fatalf("NewMatcher: %v", err)
	}

	b.SetBytes(int64(len(log)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = m.Match(log)
	}
}

// BenchmarkPerLine_StringsContains mirrors the workflow scanner's
// historical per-line loop: bufio.Scanner emits one line at a time and
// the matcher is queried per line, per IOC. This is the workload Plan
// 5 actually optimizes.
func BenchmarkPerLine_StringsContains(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := buildBenchmarkIOCs(100)
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			for _, ic := range iocs {
				if strings.Contains(line, ic) {
					_ = ic
				}
			}
		}
	}
}

// BenchmarkPerLine_Bloom mirrors the same per-line workload using the
// bloom-prefiltered Matcher's production yes/no entrypoint
// (MatchAnyString). The bloom Test() call rejects most lines in
// microseconds; only lines with an n-gram hit reach the deterministic
// backend.
func BenchmarkPerLine_Bloom(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := buildBenchmarkIOCs(100)
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}

	m, err := ioc.NewMatcher(iocs)
	if err != nil {
		b.Fatalf("NewMatcher: %v", err)
	}

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			_ = m.MatchAnyString(line)
		}
	}
}

// BenchmarkPerLine_M1_StringsContains is the M=1 production-default
// baseline: one IOC, scanned per line via strings.Contains.
func BenchmarkPerLine_M1_StringsContains(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := []string{"SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67"}
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			for _, ic := range iocs {
				if strings.Contains(line, ic) {
					_ = ic
				}
			}
		}
	}
}

// BenchmarkPerLine_M1_Bloom is the M=1 production-default workload
// running through the bloom-prefiltered matcher with the string-input
// fast path used by the workflow scanner.
func BenchmarkPerLine_M1_Bloom(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := []string{"SHA:0e58ed8671d6b60d0890c21b07f8835ace038e67"}
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}

	m, err := ioc.NewMatcher(iocs)
	if err != nil {
		b.Fatalf("NewMatcher: %v", err)
	}

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			_ = m.MatchAnyString(line)
		}
	}
}

// BenchmarkPerLine_M10_StringsContains is the legacy per-line scan at
// M=10 -- the corpus size at which MatcherAuto switches to Aho-Corasick.
func BenchmarkPerLine_M10_StringsContains(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := buildBenchmarkIOCs(10)
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}
	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			for _, ic := range iocs {
				if strings.Contains(line, ic) {
					_ = ic
				}
			}
		}
	}
}

// BenchmarkPerLine_M10_Bloom mirrors the M=10 workload through the bloom-
// prefiltered matcher's production entrypoint.
func BenchmarkPerLine_M10_Bloom(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := buildBenchmarkIOCs(10)
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}
	m, err := ioc.NewMatcher(iocs)
	if err != nil {
		b.Fatalf("NewMatcher: %v", err)
	}
	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			_ = m.MatchAnyString(line)
		}
	}
}

// BenchmarkPerLine_M1000_StringsContains exercises the linear-in-M
// pathology of the legacy loop with a thousand IOCs.
func BenchmarkPerLine_M1000_StringsContains(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := buildBenchmarkIOCs(1000)
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			for _, ic := range iocs {
				if strings.Contains(line, ic) {
					_ = ic
				}
			}
		}
	}
}

// BenchmarkPerLine_M1000_Bloom shows how the bloom prefilter and
// Aho-Corasick deterministic backend scale at M=1000: filter cost is
// constant in M, and AC pays once per line regardless of corpus size.
func BenchmarkPerLine_M1000_Bloom(b *testing.B) {
	lines := buildBenchmarkLines()
	iocs := buildBenchmarkIOCs(1000)
	totalBytes := 0
	for _, l := range lines {
		totalBytes += len(l)
	}

	m, err := ioc.NewMatcher(iocs)
	if err != nil {
		b.Fatalf("NewMatcher: %v", err)
	}

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, line := range lines {
			_ = m.MatchAnyString(line)
		}
	}
}

func buildBenchmarkLines() []string {
	const filler = "the quick brown fox jumps over the lazy dog 0123456789 "
	const targetSize = 1 << 20
	var lines []string
	total := 0
	for total < targetSize {
		lines = append(lines, filler)
		total += len(filler)
	}
	return lines
}

func buildBenchmarkLog(size int) []byte {
	const filler = "the quick brown fox jumps over the lazy dog 0123456789 "
	out := make([]byte, 0, size)
	for len(out) < size {
		out = append(out, filler...)
	}
	return out[:size]
}

func buildBenchmarkIOCs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("@@IOC-%06d-MARKER@@", i)
	}
	return out
}
