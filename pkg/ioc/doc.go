// Package ioc models indicators of compromise (literal substrings and
// optional regex patterns) and exposes a substring [Matcher] that
// scans log payloads for them.
//
// Public surface:
//
//   - [NewIOC] builds an [IOC] from a [Config] containing a name,
//     content list, and/or regex pattern. [GetPredefinedIOC] resolves a
//     name against the embedded corpus shipped with the binary.
//   - [LoadEmbeddedCorpus] / [LoadCorpusFile] return a parsed [Corpus]
//     whose [CorpusEntry] values are turned into [IOC] instances via
//     [CorpusEntry.BuildIOC]. The on-disk schema lives in iocs.json and
//     pins a single integer version field.
//   - [NewMatcher] builds a [Matcher] over a literal IOC corpus. The
//     matcher transparently selects between strings.Contains and
//     Aho-Corasick at construction time and is fronted by a bloom
//     prefilter for medium and large corpora.
//   - [Matcher.Match] / [Matcher.MatchAny] / [Matcher.MatchAnyString]
//     are the per-line scan entry points. MatchAnyString avoids the
//     []byte conversion when callers already hold a string.
//
// Invariants:
//
//   - The matcher is sound: every real substring match of any
//     configured IOC in the input is reported (no false negatives).
//   - Adding more IOCs to the corpus monotonically widens the set of
//     admitted log windows -- it never causes a previously matched
//     pair to be rejected.
//   - The matcher is immutable after construction and safe for
//     concurrent reads from multiple goroutines.
package ioc
