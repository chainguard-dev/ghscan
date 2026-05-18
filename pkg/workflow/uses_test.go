package workflow_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/ghscan/pkg/workflow"
)

func TestClassifyRef(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ref  string
		want string
	}{
		{name: "empty ref is unspecified", ref: "", want: "unspecified"},
		{name: "lowercase 40-char hex is commit-sha", ref: "0e58ed8671d6b60d0890c21b07f8835ace038e67", want: "commit-sha"},
		{name: "uppercase 40-char hex is commit-sha", ref: "0E58ED8671D6B60D0890C21B07F8835ACE038E67", want: "commit-sha"},
		{name: "mixed-case 40-char hex is commit-sha", ref: "0e58ED8671d6b60D0890c21b07f8835ACE038E67", want: "commit-sha"},
		{name: "lowercase 7-char hex is short-sha", ref: "0e58ed8", want: "short-sha"},
		{name: "uppercase 7-char hex is short-sha", ref: "0E58ED8", want: "short-sha"},
		{name: "v-prefixed tag", ref: "v36", want: "tag"},
		{name: "semver tag without v prefix", ref: "1.2.3", want: "tag"},
		{name: "v-prefixed semver tag", ref: "v1.2.3", want: "tag"},
		{name: "branch name main", ref: "main", want: "branch"},
		{name: "branch name master", ref: "master", want: "branch"},
		{name: "branch name with slash", ref: "release/2024", want: "branch"},
		{name: "8-char hex is not short-sha and not tag is branch", ref: "0e58ed8a", want: "branch"},
		{name: "non-hex 40 chars is branch", ref: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", want: "branch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := workflow.ClassifyRef(tc.ref)
			if got != tc.want {
				t.Fatalf("ClassifyRef(%q)=%q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

func TestParseUsesEdges(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		yamlSrc       string
		wantUses      []string
		wantActions   []string
		wantRefs      []string
		wantRefForms  []string
		wantSecrets   map[string][]string
		wantJobNames  []string
		wantStepNames map[string]string
		wantErr       bool
	}{
		{
			name: "lowercase commit sha",
			yamlSrc: `jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67
`,
			wantUses:     []string{"tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{"0e58ed8671d6b60d0890c21b07f8835ace038e67"},
			wantRefForms: []string{"commit-sha"},
			wantJobNames: []string{"build"},
		},
		{
			name: "uppercase commit sha",
			yamlSrc: `jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@0E58ED8671D6B60D0890C21B07F8835ACE038E67
`,
			wantUses:     []string{"tj-actions/changed-files@0E58ED8671D6B60D0890C21B07F8835ACE038E67"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{"0E58ED8671D6B60D0890C21B07F8835ACE038E67"},
			wantRefForms: []string{"commit-sha"},
		},
		{
			name: "short sha 7 chars",
			yamlSrc: `jobs:
  build:
    steps:
      - uses: tj-actions/changed-files@0e58ed8
`,
			wantUses:     []string{"tj-actions/changed-files@0e58ed8"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{"0e58ed8"},
			wantRefForms: []string{"short-sha"},
		},
		{
			name: "tag form",
			yamlSrc: `jobs:
  build:
    steps:
      - uses: tj-actions/changed-files@v36
`,
			wantUses:     []string{"tj-actions/changed-files@v36"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{"v36"},
			wantRefForms: []string{"tag"},
		},
		{
			name: "branch form",
			yamlSrc: `jobs:
  build:
    steps:
      - uses: aquasecurity/trivy-action@main
`,
			wantUses:     []string{"aquasecurity/trivy-action@main"},
			wantActions:  []string{"aquasecurity/trivy-action"},
			wantRefs:     []string{"main"},
			wantRefForms: []string{"branch"},
		},
		{
			name: "trailing comment form",
			yamlSrc: `jobs:
  build:
    steps:
      - uses: tj-actions/changed-files@v36 # pinned tag
`,
			wantUses:     []string{"tj-actions/changed-files@v36"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{"v36"},
			wantRefForms: []string{"tag"},
		},
		{
			name: "single-quoted uses",
			yamlSrc: `jobs:
  build:
    steps:
      - uses: 'tj-actions/changed-files@v36'
`,
			wantUses:     []string{"tj-actions/changed-files@v36"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{"v36"},
			wantRefForms: []string{"tag"},
		},
		{
			name: "double-quoted uses",
			yamlSrc: `jobs:
  build:
    steps:
      - uses: "tj-actions/changed-files@v36"
`,
			wantUses:     []string{"tj-actions/changed-files@v36"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{"v36"},
			wantRefForms: []string{"tag"},
		},
		{
			name: "job-level reusable workflow uses",
			yamlSrc: `jobs:
  call-shared:
    uses: org/repo/.github/workflows/wf.yml@v1
    secrets: inherit
`,
			wantUses:     []string{"org/repo/.github/workflows/wf.yml@v1"},
			wantActions:  []string{"org/repo/.github/workflows/wf.yml"},
			wantRefs:     []string{"v1"},
			wantRefForms: []string{"tag"},
			wantJobNames: []string{"call-shared"},
		},
		{
			name: "secrets reachable via with",
			yamlSrc: `jobs:
  publish:
    steps:
      - name: pub
        uses: some-org/publisher@v1
        with:
          token: ${{ secrets.NPM_TOKEN }}
`,
			wantUses:     []string{"some-org/publisher@v1"},
			wantActions:  []string{"some-org/publisher"},
			wantRefs:     []string{"v1"},
			wantRefForms: []string{"tag"},
			wantSecrets: map[string][]string{
				"some-org/publisher": {"NPM_TOKEN"},
			},
			wantStepNames: map[string]string{
				"some-org/publisher": "pub",
			},
		},
		{
			name: "secrets reachable via env at step",
			yamlSrc: `jobs:
  publish:
    steps:
      - uses: some-org/publisher@v1
        env:
          NPM_AUTH: ${{ secrets.NPM_TOKEN }}
`,
			wantUses:     []string{"some-org/publisher@v1"},
			wantActions:  []string{"some-org/publisher"},
			wantRefs:     []string{"v1"},
			wantRefForms: []string{"tag"},
			wantSecrets: map[string][]string{
				"some-org/publisher": {"NPM_TOKEN"},
			},
		},
		{
			name: "secrets reachable via env at job",
			yamlSrc: `jobs:
  publish:
    env:
      NPM_AUTH: ${{ secrets.NPM_TOKEN }}
    steps:
      - uses: some-org/publisher@v1
`,
			wantUses:     []string{"some-org/publisher@v1"},
			wantActions:  []string{"some-org/publisher"},
			wantRefs:     []string{"v1"},
			wantRefForms: []string{"tag"},
			wantSecrets: map[string][]string{
				"some-org/publisher": {"NPM_TOKEN"},
			},
		},
		{
			name: "missing ref classified unspecified",
			yamlSrc: `jobs:
  build:
    steps:
      - uses: tj-actions/changed-files
`,
			wantUses:     []string{"tj-actions/changed-files"},
			wantActions:  []string{"tj-actions/changed-files"},
			wantRefs:     []string{""},
			wantRefForms: []string{"unspecified"},
		},
		{
			name: "step without uses is skipped",
			yamlSrc: `jobs:
  build:
    steps:
      - name: shell-only
        run: echo hello
`,
			wantUses:    nil,
			wantActions: nil,
		},
		{
			name: "multiple jobs and steps",
			yamlSrc: `jobs:
  a:
    steps:
      - uses: foo/bar@v1
      - uses: baz/qux@v2
  b:
    steps:
      - uses: alpha/beta@main
`,
			wantUses:     []string{"foo/bar@v1", "baz/qux@v2", "alpha/beta@main"},
			wantActions:  []string{"foo/bar", "baz/qux", "alpha/beta"},
			wantRefs:     []string{"v1", "v2", "main"},
			wantRefForms: []string{"tag", "tag", "branch"},
		},
		{
			name:    "malformed yaml returns error",
			yamlSrc: ":\n  - this is not valid yaml: [",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			edges, err := workflow.ParseUsesEdges([]byte(tc.yamlSrc))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got edges=%+v", edges)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(edges) != len(tc.wantUses) {
				t.Fatalf("got %d edges (%+v), want %d (%v)", len(edges), edges, len(tc.wantUses), tc.wantUses)
			}
			for i, e := range edges {
				if e.Uses != tc.wantUses[i] {
					t.Errorf("edge[%d].Uses=%q, want %q", i, e.Uses, tc.wantUses[i])
				}
				if i < len(tc.wantActions) && e.Action != tc.wantActions[i] {
					t.Errorf("edge[%d].Action=%q, want %q", i, e.Action, tc.wantActions[i])
				}
				if i < len(tc.wantRefs) && e.Ref != tc.wantRefs[i] {
					t.Errorf("edge[%d].Ref=%q, want %q", i, e.Ref, tc.wantRefs[i])
				}
				if i < len(tc.wantRefForms) && e.RefForm != tc.wantRefForms[i] {
					t.Errorf("edge[%d].RefForm=%q, want %q", i, e.RefForm, tc.wantRefForms[i])
				}
				if i < len(tc.wantJobNames) && e.JobName != tc.wantJobNames[i] {
					t.Errorf("edge[%d].JobName=%q, want %q", i, e.JobName, tc.wantJobNames[i])
				}
				if want, ok := tc.wantSecrets[e.Action]; ok {
					for _, s := range want {
						if !slices.Contains(e.Secrets, s) {
							t.Errorf("edge[%d].Secrets=%v, want to contain %q", i, e.Secrets, s)
						}
					}
				}
				if want, ok := tc.wantStepNames[e.Action]; ok {
					if e.StepName != want {
						t.Errorf("edge[%d].StepName=%q, want %q", i, e.StepName, want)
					}
				}
				if e.LineNumber <= 0 {
					t.Errorf("edge[%d].LineNumber=%d, want > 0", i, e.LineNumber)
				}
			}
		})
	}
}

func TestParseUsesEdges_RespectsSizeLimit(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("# padding line that goes on\n", 1<<20/16)
	_, err := workflow.ParseUsesEdges([]byte(huge))
	if err == nil {
		t.Fatal("expected error for oversized input")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("error %q does not mention exceeds maximum size", err.Error())
	}
}

func TestParseUsesEdges_EmptyInput(t *testing.T) {
	t.Parallel()

	edges, err := workflow.ParseUsesEdges(nil)
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
	if len(edges) != 0 {
		t.Fatalf("expected zero edges, got %d", len(edges))
	}
}
