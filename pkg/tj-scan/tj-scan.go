package tjscan

import (
	"time"

	"github.com/chainguard-dev/tj-scan/pkg/ioc"
	"github.com/google/go-github/v69/github"
)

const ResultsDir string = "results"

type Request struct {
	Cache         Cache
	CacheFile     string
	CachedResults map[string]bool
	Client        *github.Client
	EndTime       time.Time
	IOC           *ioc.IOC
	Owner         string
	RepoName      string
	StartTime     time.Time
	Timeout       time.Duration
	Token         string
	Workflows     []string
}

type Result struct {
	Base64Data       string `json:"base64_data,omitempty"`
	DecodedData      string `json:"decoded_data,omitempty"`
	LineData         string `json:"line_data,omitempty"`
	Repository       string `json:"repository,omitempty"`
	WorkflowFileName string `json:"workflow_file_name,omitempty"`
	WorkflowRunURL   string `json:"workflow_run_url,omitempty"`
	WorkflowURL      string `json:"workflow_url,omitempty"`
}

func (r *Result) IsEmpty() bool {
	return r.Base64Data == "" && r.DecodedData == "" && r.LineData == ""
}

type Cache struct {
	Results []Result `json:"results,omitempty"`
}
