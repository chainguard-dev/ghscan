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
	Repository       string `json:"repository"`
	WorkflowFileName string `json:"workflow_file_name"`
	WorkflowURL      string `json:"workflow_url"`
	WorkflowRunURL   string `json:"workflow_run_url"`
	Base64Data       string `json:"base64_data"`
	DecodedData      string `json:"decoded_data"`
	EmptyLines       string `json:"empty_lines"`
}

type Cache struct {
	Results []Result `json:"results"`
}
