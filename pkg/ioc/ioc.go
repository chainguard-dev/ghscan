package ioc

import (
	"fmt"
	"regexp"
	"sync"
)

type Config struct {
	Name    string
	Content []string
	Pattern string
	// Corpus, when non-nil, overrides the embedded corpus used to
	// resolve Name. Callers wire this from cmd/ghscan when the
	// operator supplied --ioc-file.
	Corpus *Corpus
}

type IOC struct {
	name    string
	content []string
	regex   *regexp.Regexp
	matcher Matcher
}

// embeddedCorpusOnce memoizes the parsed embedded corpus so repeated
// GetPredefinedIOC calls do not reparse the JSON. Errors are returned
// to the caller verbatim on every call.
var (
	embeddedCorpusOnce sync.Once
	embeddedCorpusVal  *Corpus
	errEmbeddedCorpus  error
)

func getEmbeddedCorpus() (*Corpus, error) {
	embeddedCorpusOnce.Do(func() {
		embeddedCorpusVal, errEmbeddedCorpus = LoadEmbeddedCorpus()
	})
	return embeddedCorpusVal, errEmbeddedCorpus
}

// GetPredefinedIOC resolves an IOC by action name from the embedded
// corpus. It exists so external callers (and the legacy CLI path) can
// look up a known indicator without supplying a Config.
func GetPredefinedIOC(name string) (*IOC, bool) {
	c, err := getEmbeddedCorpus()
	if err != nil || c == nil {
		return nil, false
	}
	entry := c.FindEntry(name)
	if entry == nil {
		return nil, false
	}
	built, err := entry.BuildIOC()
	if err != nil {
		return nil, false
	}
	return built, true
}

// NewIOC constructs an IOC from a Config. When Config.Name is set and
// no inline content/pattern is provided, it resolves against the
// corpus on Config.Corpus when present, falling back to the embedded
// corpus otherwise.
func NewIOC(config *Config) (*IOC, error) {
	if config.Name != "" && len(config.Content) == 0 && config.Pattern == "" {
		var (
			entry *CorpusEntry
			src   = config.Corpus
		)
		if src != nil {
			entry = src.FindEntry(config.Name)
		}
		if entry == nil {
			c, err := getEmbeddedCorpus()
			if err != nil {
				return nil, fmt.Errorf("loading embedded corpus: %w", err)
			}
			entry = c.FindEntry(config.Name)
		}
		if entry == nil {
			return nil, fmt.Errorf("predefined IOC not found: %s", config.Name)
		}
		return entry.BuildIOC()
	}

	if config.Pattern == "" && len(config.Content) == 0 {
		return nil, fmt.Errorf("either content or pattern is required for novel IOC")
	}

	var regex *regexp.Regexp
	var err error
	if config.Pattern != "" {
		regex, err = regexp.Compile(config.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	name := config.Name
	if name == "" {
		name = "custom"
	}

	normalized := make([]string, 0, len(config.Content))
	for _, s := range config.Content {
		if s == "" {
			continue
		}
		normalized = append(normalized, normalizeMatchInput(s))
	}

	matcher, err := NewMatcher(normalized)
	if err != nil {
		return nil, fmt.Errorf("building IOC matcher: %w", err)
	}

	return &IOC{
		name:    name,
		content: normalized,
		regex:   regex,
		matcher: matcher,
	}, nil
}

func (i *IOC) GetName() string {
	return i.name
}

func (i *IOC) GetContent() []string {
	return i.content
}

func (i *IOC) GetRegex() *regexp.Regexp {
	return i.regex
}

// GetMatcher returns the precomputed bloom-prefiltered substring matcher
// over the IOC's content list. The Matcher is constructed once at IOC
// creation and is safe for concurrent reads at the per-line scan site.
func (i *IOC) GetMatcher() Matcher {
	return i.matcher
}
