package ioc

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/text/unicode/norm"
)

//go:embed iocs.json
var embeddedCorpus []byte

// CorpusEntry is a single indicator-of-compromise record sourced from
// the JSON corpus. Fields mirror the on-disk schema 1:1.
type CorpusEntry struct {
	Action             string   `json:"action"`
	Refs               []string `json:"refs,omitempty"`
	Tags               []string `json:"tags,omitempty"`
	CaseInsensitive    bool     `json:"case_insensitive,omitempty"`
	Incident           string   `json:"incident,omitempty"`
	DisclosureDate     string   `json:"disclosure_date,omitempty"`
	References         []string `json:"references,omitempty"`
	VerificationStatus string   `json:"verification_status,omitempty"`
}

// Corpus is the parsed shape of a corpus file. Version pins the schema
// so future changes can be detected and rejected.
type Corpus struct {
	Version int           `json:"version"`
	IOCs    []CorpusEntry `json:"iocs"`
}

// LoadEmbeddedCorpus parses and validates the corpus baked into the
// binary at build time.
func LoadEmbeddedCorpus() (*Corpus, error) {
	return parseCorpus(embeddedCorpus)
}

// LoadCorpusFile loads a corpus from a user-supplied path. The path is
// cleaned and the file is read in full because corpus files are small.
// Validation errors include the source path so the operator can tell
// embedded-vs-override failures apart.
func LoadCorpusFile(path string) (*Corpus, error) {
	clean := filepath.Clean(path)
	// #nosec G304 -- corpus path is an explicit user-supplied operational
	// override of the embedded baseline. Treating it as untrusted at this
	// boundary would defeat the flag's purpose.
	data, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("reading corpus file %s: %w", clean, err)
	}
	c, err := parseCorpus(data)
	if err != nil {
		return nil, fmt.Errorf("parsing corpus file %s: %w", clean, err)
	}
	return c, nil
}

func parseCorpus(data []byte) (*Corpus, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("corpus is empty")
	}
	var c Corpus
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decoding corpus JSON: %w", err)
	}
	if c.Version != 1 {
		return nil, fmt.Errorf("unsupported corpus version %d (want 1)", c.Version)
	}
	if len(c.IOCs) == 0 {
		return nil, fmt.Errorf("corpus contains no entries")
	}
	for i, e := range c.IOCs {
		if strings.TrimSpace(e.Action) == "" {
			return nil, fmt.Errorf("entry %d: action is required", i)
		}
		if len(e.Refs) == 0 && len(e.Tags) == 0 {
			return nil, fmt.Errorf("entry %d (%s): at least one ref or tag is required", i, e.Action)
		}
	}
	return &c, nil
}

// normalizeMatchInput applies NFKC Unicode normalization so visually
// equivalent forms (precomposed vs. decomposed accents, compatibility
// digit variants, etc.) match. Lower-casing is left to the matcher's
// WithCaseInsensitive option so the normalization is reversible.
func normalizeMatchInput(s string) string {
	if s == "" {
		return s
	}
	return norm.NFKC.String(s)
}

// FindEntry returns the corpus entry for action, or nil if absent.
// Action lookup is exact (no normalization) because action names are
// owner/repo paths whose canonical form is the GitHub-rendered string.
func (c *Corpus) FindEntry(action string) *CorpusEntry {
	if c == nil {
		return nil
	}
	for i := range c.IOCs {
		if c.IOCs[i].Action == action {
			return &c.IOCs[i]
		}
	}
	return nil
}

// MatchActionRef reports whether the (action, ref) pair appears in the
// corpus as a known-bad coordinate. Ref comparison honors the entry's
// case-insensitive flag and applies NFKC normalization on both sides
// so equivalence holds across visually-equal Unicode forms. An empty
// ref matches an entry only when the entry itself lists an empty ref
// (effectively "any ref of this action is bad").
func (c *Corpus) MatchActionRef(action, ref string) bool {
	if c == nil {
		return false
	}
	entry := c.FindEntry(action)
	if entry == nil {
		return false
	}
	needle := normalizeMatchInput(ref)
	if entry.CaseInsensitive {
		needle = strings.ToLower(needle)
	}
	for _, candidate := range entry.Refs {
		if matchOne(candidate, needle, entry.CaseInsensitive) {
			return true
		}
	}
	for _, candidate := range entry.Tags {
		if matchOne(candidate, needle, entry.CaseInsensitive) {
			return true
		}
	}
	return false
}

func matchOne(corpusVal, needle string, ci bool) bool {
	got := normalizeMatchInput(corpusVal)
	if ci {
		got = strings.ToLower(got)
	}
	return got == needle
}

// BuildIOC turns a corpus entry into the in-memory IOC value the
// scanner consumes. Refs and tags are normalized via NFKC; the matcher
// folds case when entry.CaseInsensitive is set so callers do not
// double-normalize.
func (e *CorpusEntry) BuildIOC() (*IOC, error) {
	if e == nil {
		return nil, fmt.Errorf("nil corpus entry")
	}
	content := make([]string, 0, len(e.Refs)+len(e.Tags))
	for _, r := range e.Refs {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		content = append(content, normalizeMatchInput(r))
	}
	for _, t := range e.Tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		content = append(content, normalizeMatchInput(t))
	}
	if len(content) == 0 {
		return nil, fmt.Errorf("entry %s: no usable refs or tags after normalization", e.Action)
	}

	var opts []Option
	if e.CaseInsensitive {
		opts = append(opts, WithCaseInsensitive())
	}
	matcher, err := NewMatcher(content, opts...)
	if err != nil {
		return nil, fmt.Errorf("entry %s: building matcher: %w", e.Action, err)
	}

	return &IOC{
		name:    e.Action,
		content: content,
		regex:   nil,
		matcher: matcher,
	}, nil
}
