package ghscan

import (
	"time"

	httpclient "github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/google/go-github/v86/github"
)

const ResultsDir string = "results"

// Request carries the per-scan state shared across internal/action and
// pkg/workflow call sites. The embedded GitHub and raw HTTP clients
// are unexported so external callers must go through the accessors
// below; this keeps the public surface narrow and lets the package
// substitute the concrete client types in the future without breaking
// consumers.
type Request struct {
	Cache         Cache
	CacheFile     string
	CachedResults map[string]bool
	Corpus        *ioc.Corpus
	EndTime       time.Time
	IOC           *ioc.IOC
	Owner         string
	RepoName      string
	StartTime     time.Time
	Timeout       time.Duration
	Token         string
	Workflows     []string

	client     *github.Client
	httpClient *httpclient.Client
}

// RequestConfig is the constructor input for [NewRequest]. Every field
// mirrors its counterpart on Request; scalar fields with a zero value
// remain zero on the resulting Request.
type RequestConfig struct {
	Cache         Cache
	CacheFile     string
	CachedResults map[string]bool
	Client        *github.Client
	HTTPClient    *httpclient.Client
	Corpus        *ioc.Corpus
	EndTime       time.Time
	IOC           *ioc.IOC
	Owner         string
	RepoName      string
	StartTime     time.Time
	Timeout       time.Duration
	Token         string
	Workflows     []string
}

// NewRequest returns a Request populated from cfg. The returned value
// is a Request (not a pointer) so callers retain control of allocation
// and per-repo shallow cloning continues to work without an extra heap
// hop.
func NewRequest(cfg RequestConfig) *Request {
	return &Request{
		Cache:         cfg.Cache,
		CacheFile:     cfg.CacheFile,
		CachedResults: cfg.CachedResults,
		Corpus:        cfg.Corpus,
		EndTime:       cfg.EndTime,
		IOC:           cfg.IOC,
		Owner:         cfg.Owner,
		RepoName:      cfg.RepoName,
		StartTime:     cfg.StartTime,
		Timeout:       cfg.Timeout,
		Token:         cfg.Token,
		Workflows:     cfg.Workflows,
		client:        cfg.Client,
		httpClient:    cfg.HTTPClient,
	}
}

// Client returns the GitHub SDK client wired into this Request. It is
// nil-safe so a zero-value Request is observable without panicking.
func (r *Request) Client() *github.Client {
	if r == nil {
		return nil
	}
	return r.client
}

// HTTPClient returns the shared hardened HTTP client used for direct
// GitHub API/UI fetches (log archives, run pages). Plumbed from main
// so singleflight + ETag caching apply across all callers. Nil-safe.
func (r *Request) HTTPClient() *httpclient.Client {
	if r == nil {
		return nil
	}
	return r.httpClient
}

type Result struct {
	Base64Data        string   `json:"base64_data,omitempty"`
	DecodedData       string   `json:"decoded_data,omitempty"`
	LineData          string   `json:"line_data,omitempty"`
	Repository        string   `json:"repository,omitempty"`
	WorkflowFileName  string   `json:"workflow_file_name,omitempty"`
	WorkflowRunURL    string   `json:"workflow_run_url,omitempty"`
	WorkflowURL       string   `json:"workflow_url,omitempty"`
	WorkflowFileSHA   string   `json:"workflow_file_sha,omitempty"`
	OffendingUsesLine string   `json:"offending_uses_line,omitempty"`
	ResolvedRefForm   string   `json:"resolved_ref_form,omitempty"`
	JobName           string   `json:"job_name,omitempty"`
	StepName          string   `json:"step_name,omitempty"`
	ReachableSecrets  []string `json:"reachable_secrets,omitempty"`
	Source            string   `json:"source,omitempty"`
}

func (r *Result) IsEmpty() bool {
	return r.Base64Data == "" && r.DecodedData == "" && r.LineData == "" && r.OffendingUsesLine == ""
}

type Cache struct {
	Results []Result `json:"results,omitempty"`
}
