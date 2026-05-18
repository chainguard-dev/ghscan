package workflow

import (
	"context"
	"io"

	"github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/google/go-github/v86/github"
)

// GetPerJobLogsForTest exposes the unexported per-job fetch path so
// tests can assert that the empty-jobs response surfaces the typed
// sentinel rather than a string-wrapped error. Successful responses
// are drained and closed before returning so a passing call leaks
// no descriptors back to the test.
func GetPerJobLogsForTest(ctx context.Context, hc *httpclient.Client, gh *github.Client, owner, repo string, runID int64, token string) error {
	logs, err := getPerJobLogs(ctx, hc, gh, owner, repo, runID, token)
	for _, rc := range logs {
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}
	return err
}

// GetWorkflowByPathWithMaxPages exposes the page-capped pagination
// helper to *_test.go files so the cap-exceeded branch can be exercised
// without mutating package globals (which would race with parallel
// tests calling the production GetWorkflowByPath).
func GetWorkflowByPathWithMaxPages(ctx context.Context, client *github.Client, owner, repo, wfPath string, maxPages int) (*github.Workflow, error) {
	return getWorkflowByPathPaginated(ctx, client, owner, repo, wfPath, maxPages)
}

// ListAllJobsWithMaxPages exposes the page-capped jobs listing helper
// to *_test.go files so the cap-exceeded branch can be exercised
// without mutating package globals.
func ListAllJobsWithMaxPages(ctx context.Context, client *github.Client, owner, repo string, runID int64, maxPages int) ([]*github.WorkflowJob, error) {
	return listAllJobsPaginated(ctx, client, owner, repo, runID, maxPages)
}

// PaginateForTest exposes the internal pagination helper.
func PaginateForTest(maxPages int, kind string, step func(page int) (int, error)) error {
	return paginate(maxPages, kind, step)
}
