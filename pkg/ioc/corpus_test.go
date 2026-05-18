package ioc_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/chainguard-dev/ghscan/pkg/ioc"
)

// actionCoordPattern matches a valid `owner/repo` coordinate that may
// appear on the right side of a `uses:` directive. Owner and repo are
// each composed of ASCII alphanumerics, hyphens, underscores, or dots.
// No `@` scoping prefix, no leading slash, no path beyond the single
// owner/repo segment.
var actionCoordPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$`)

func TestLoadEmbeddedCorpus_Shape(t *testing.T) {
	t.Parallel()

	c, err := ioc.LoadEmbeddedCorpus()
	if err != nil {
		t.Fatalf("LoadEmbeddedCorpus: %v", err)
	}
	if c.Version != 1 {
		t.Fatalf("version=%d, want 1", c.Version)
	}
	if len(c.IOCs) < 5 {
		t.Fatalf("expected >=5 seeded entries, got %d", len(c.IOCs))
	}

	wantActions := []string{
		"tj-actions/changed-files",
		"reviewdog/action-setup",
		"ctrf-io/github-actions-test-reporter",
		"aquasecurity/trivy-action",
		"aquasecurity/setup-trivy",
		"Checkmarx/kics-github-action",
		"Checkmarx/ast-github-action",
	}
	for _, want := range wantActions {
		if c.FindEntry(want) == nil {
			t.Errorf("missing seeded entry %q", want)
		}
	}
}

func TestLoadEmbeddedCorpus_NoSocketCitations(t *testing.T) {
	t.Parallel()

	c, err := ioc.LoadEmbeddedCorpus()
	if err != nil {
		t.Fatalf("LoadEmbeddedCorpus: %v", err)
	}
	for _, e := range c.IOCs {
		for _, ref := range e.References {
			lower := strings.ToLower(ref)
			if strings.Contains(lower, "socket.dev") || strings.Contains(lower, "socket.io/blog") {
				t.Errorf("entry %q references forbidden Socket source: %s", e.Action, ref)
			}
		}
	}
}

func TestLoadEmbeddedCorpus_SchemaInvariants(t *testing.T) {
	t.Parallel()

	c, err := ioc.LoadEmbeddedCorpus()
	if err != nil {
		t.Fatalf("LoadEmbeddedCorpus: %v", err)
	}
	for _, e := range c.IOCs {
		if strings.TrimSpace(e.Action) == "" {
			t.Errorf("entry has empty action")
		}
		if len(e.Refs) == 0 && len(e.Tags) == 0 {
			t.Errorf("entry %q has neither refs nor tags", e.Action)
		}
		if strings.TrimSpace(e.Incident) == "" {
			t.Errorf("entry %q is missing incident", e.Action)
		}
		if strings.TrimSpace(e.DisclosureDate) == "" {
			t.Errorf("entry %q is missing disclosure_date", e.Action)
		}
		if len(e.Refs) > 0 && !e.CaseInsensitive {
			t.Errorf("entry %q has SHA refs but case_insensitive=false; SHAs may appear in mixed case", e.Action)
		}
	}
}

func TestLoadEmbeddedCorpus_AllEntriesAreActions(t *testing.T) {
	t.Parallel()

	c, err := ioc.LoadEmbeddedCorpus()
	if err != nil {
		t.Fatalf("LoadEmbeddedCorpus: %v", err)
	}
	for _, e := range c.IOCs {
		if strings.HasPrefix(e.Action, "@") {
			t.Errorf("entry %q starts with @ (npm scope prefix); not a GitHub Action coordinate", e.Action)
		}
		if strings.HasPrefix(e.Action, "/") {
			t.Errorf("entry %q has leading slash; not a GitHub Action coordinate", e.Action)
		}
		if !actionCoordPattern.MatchString(e.Action) {
			t.Errorf("entry %q does not match owner/repo pattern; not a GitHub Action coordinate", e.Action)
		}
	}
}

func TestLoadCorpusFile_Negative(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		wantSub string
	}{
		{
			name:    "malformed JSON",
			content: `{"version": 1, "iocs": [`,
			wantSub: "parsing corpus file",
		},
		{
			name:    "unknown field",
			content: `{"version":1,"iocs":[{"action":"x","tags":["v1"],"surprise":true}]}`,
			wantSub: "unknown field",
		},
		{
			name:    "wrong version",
			content: `{"version":99,"iocs":[{"action":"x","tags":["v1"]}]}`,
			wantSub: "unsupported corpus version",
		},
		{
			name:    "empty corpus",
			content: `{"version":1,"iocs":[]}`,
			wantSub: "no entries",
		},
		{
			name:    "missing action",
			content: `{"version":1,"iocs":[{"tags":["v1"]}]}`,
			wantSub: "action is required",
		},
		{
			name:    "entry with neither refs nor tags",
			content: `{"version":1,"iocs":[{"action":"x"}]}`,
			wantSub: "ref or tag is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "corpus.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := ioc.LoadCorpusFile(path)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadCorpusFile_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := ioc.LoadCorpusFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "reading corpus file") {
		t.Fatalf("error %q does not mention reading corpus file", err.Error())
	}
}

func TestLoadCorpusFile_HappyPath(t *testing.T) {
	t.Parallel()
	body := `{
		"version": 1,
		"iocs": [
			{"action": "user/repo", "tags": ["v1"], "case_insensitive": true},
			{"action": "another/action", "refs": ["abc123def456"]}
		]
	}`
	dir := t.TempDir()
	path := filepath.Join(dir, "corpus.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := ioc.LoadCorpusFile(path)
	if err != nil {
		t.Fatalf("LoadCorpusFile: %v", err)
	}
	if len(c.IOCs) != 2 {
		t.Fatalf("entries=%d, want 2", len(c.IOCs))
	}
	if c.FindEntry("user/repo") == nil {
		t.Fatal("missing user/repo")
	}
}

func TestCorpusEntry_BuildIOC_SeededEntries(t *testing.T) {
	t.Parallel()

	c, err := ioc.LoadEmbeddedCorpus()
	if err != nil {
		t.Fatalf("LoadEmbeddedCorpus: %v", err)
	}

	cases := []struct {
		action      string
		needles     []string
		caseFolding bool
	}{
		{
			action:      "tj-actions/changed-files",
			needles:     []string{"0e58ed8671d6b60d0890c21b07f8835ace038e67", "v36", "V37"},
			caseFolding: true,
		},
		{
			action:  "reviewdog/action-setup",
			needles: []string{"v1"},
		},
		{
			action:  "ctrf-io/github-actions-test-reporter",
			needles: []string{"v1"},
		},
		{
			action:      "aquasecurity/trivy-action",
			needles:     []string{"v0.34.2", "v0.0.1", "v0.16.0", "ddb9da4475c1cef7d5389062bdfdfbdbd1394648", "DDB9DA4475C1CEF7D5389062BDFDFBDBD1394648"},
			caseFolding: true,
		},
		{
			action:      "aquasecurity/setup-trivy",
			needles:     []string{"v0.2.6", "8afa9b9f9183b4e00c46e2b82d34047e3c177bd0"},
			caseFolding: true,
		},
		{
			action:      "Checkmarx/kics-github-action",
			needles:     []string{"v2.1.7", "0e22ec8d1e0dda3c62bf4beffcd4a8a5db1abda1"},
			caseFolding: true,
		},
		{
			action:  "Checkmarx/ast-github-action",
			needles: []string{"2.3.28"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			t.Parallel()
			entry := c.FindEntry(tc.action)
			if entry == nil {
				t.Fatalf("missing entry %s", tc.action)
			}
			built, err := entry.BuildIOC()
			if err != nil {
				t.Fatalf("BuildIOC: %v", err)
			}
			m := built.GetMatcher()
			if m == nil {
				t.Fatal("nil matcher")
			}
			for _, n := range tc.needles {
				// Mimic the scan pipeline's normalization step so the
				// test mirrors real input shaping.
				probe := "uses: " + tc.action + "@" + n
				if !m.MatchAnyString(probe) {
					t.Errorf("matcher missed %q (line=%q, case_fold=%v)", n, probe, tc.caseFolding)
				}
			}
		})
	}
}

func TestCorpusEntry_BuildIOC_NoNeedles(t *testing.T) {
	t.Parallel()
	entry := &ioc.CorpusEntry{Action: "x"}
	_, err := entry.BuildIOC()
	if err == nil {
		t.Fatal("expected error for entry with no refs or tags")
	}
}

func TestNormalizeMatchInput_NFKCRoundTrip(t *testing.T) {
	t.Parallel()

	// Decomposed e + combining acute should fold to the precomposed
	// form via NFKC normalization.
	const decomposed = "café"
	const precomposed = "café"
	corpus := `{"version":1,"iocs":[{"action":"unicode/test","refs":["` + precomposed + `"]}]}`

	dir := t.TempDir()
	path := filepath.Join(dir, "corpus.json")
	if err := os.WriteFile(path, []byte(corpus), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := ioc.LoadCorpusFile(path)
	if err != nil {
		t.Fatalf("LoadCorpusFile: %v", err)
	}
	entry := c.FindEntry("unicode/test")
	built, err := entry.BuildIOC()
	if err != nil {
		t.Fatalf("BuildIOC: %v", err)
	}
	m := built.GetMatcher()

	// Direct precomposed match is the baseline.
	if !m.MatchAnyString(precomposed) {
		t.Fatal("precomposed needle missed")
	}

	// Without normalization on the scan side, raw decomposed bytes
	// would miss the precomposed needle. Apply the package helper.
	probe := ioc.NormalizeForTest(decomposed)
	if !m.MatchAnyString(probe) {
		t.Fatalf("decomposed input failed to match after NFKC normalization: %q", probe)
	}
}

func TestNewIOC_UserCorpusOverridesEmbedded(t *testing.T) {
	t.Parallel()

	custom := &ioc.Corpus{
		Version: 1,
		IOCs: []ioc.CorpusEntry{
			{Action: "my/private-action", Tags: []string{"v9.9.9"}},
		},
	}
	cfg := &ioc.Config{Name: "my/private-action", Corpus: custom}
	built, err := ioc.NewIOC(cfg)
	if err != nil {
		t.Fatalf("NewIOC: %v", err)
	}
	if !built.GetMatcher().MatchAnyString("uses: my/private-action@v9.9.9") {
		t.Fatal("custom corpus entry did not match")
	}

	// The embedded baseline must still resolve when the user corpus
	// does not contain the requested name.
	cfg2 := &ioc.Config{Name: "tj-actions/changed-files", Corpus: custom}
	if _, err := ioc.NewIOC(cfg2); err != nil {
		t.Fatalf("embedded fallback NewIOC: %v", err)
	}
}

func TestNewIOC_UnknownNameSurfacesError(t *testing.T) {
	t.Parallel()
	_, err := ioc.NewIOC(&ioc.Config{Name: "no/such-action"})
	if err == nil {
		t.Fatal("expected error for unknown predefined IOC")
	}
	if !strings.Contains(err.Error(), "predefined IOC not found") {
		t.Fatalf("error %q does not mention predefined IOC not found", err.Error())
	}
}
