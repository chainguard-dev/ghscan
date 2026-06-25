package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/request"
	"github.com/google/go-github/v86/github"
)

// maxWorkflowListPages caps pagination in every paged GitHub listing
// loop so a pathological / malicious server that always advertises
// NextPage>0 cannot pin the scanner indefinitely. With the API's
// per-page maximum of 100 entries and 100 pages, the cap covers up
// to 10,000 entries per call -- well above any realistic ceiling.
const maxWorkflowListPages = 100

// paginate is the shared loop body for every Search/List call that
// must walk multi-page results. step is invoked once per page and
// returns the resp.NextPage value harvested from that call; returning
// 0 ends iteration. Iteration also halts at maxPages with an error
// surfaced via the kind label so the caller's diagnostic is precise.
func paginate(maxPages int, kind string, step func(page int) (nextPage int, err error)) error {
	page := 0
	for pages := 0; ; pages++ {
		if pages >= maxPages {
			return fmt.Errorf("%s pagination exceeded maximum pages (%d)", kind, maxPages)
		}
		next, err := step(page)
		if err != nil {
			return err
		}
		if next == 0 {
			return nil
		}
		page = next
	}
}

func SearchWorkflowFiles(ctx context.Context, client *github.Client, query string) ([]string, error) {
	var paths []string
	opts := &github.SearchOptions{ListOptions: github.ListOptions{PerPage: 100}}
	err := paginate(maxWorkflowListPages, "workflow file search", func(page int) (int, error) {
		opts.Page = page
		result, resp, err := client.Search.Code(ctx, query, opts)
		if err != nil {
			return 0, err
		}
		for _, item := range result.CodeResults {
			if item.Path != nil {
				paths = append(paths, *item.Path)
			}
		}
		if resp == nil {
			return 0, nil
		}
		return resp.NextPage, nil
	})
	return paths, err
}

func GetWorkflowByPath(ctx context.Context, client *github.Client, owner, repo, wfPath string) (*github.Workflow, error) {
	return getWorkflowByPathPaginated(ctx, client, owner, repo, wfPath, maxWorkflowListPages)
}

func getWorkflowByPathPaginated(ctx context.Context, client *github.Client, owner, repo, wfPath string, maxPages int) (*github.Workflow, error) {
	opts := &github.ListOptions{PerPage: 100}
	var found *github.Workflow
	perr := paginate(maxPages, "workflow path lookup", func(page int) (int, error) {
		opts.Page = page
		wfs, resp, err := client.Actions.ListWorkflows(ctx, owner, repo, opts)
		if err != nil {
			return 0, err
		}
		for _, wf := range wfs.Workflows {
			if wf.GetPath() == wfPath {
				found = wf
				return 0, nil
			}
		}
		if resp == nil {
			return 0, nil
		}
		return resp.NextPage, nil
	})
	if perr != nil {
		return nil, perr
	}
	if found == nil {
		return nil, fmt.Errorf("workflow with path %s not found", wfPath)
	}
	return found, nil
}

func ListWorkflowRuns(ctx context.Context, logger *clog.Logger, client *github.Client, owner, repo string, workflowID int64, start, end time.Time, maxRetries int) ([]*github.WorkflowRun, error) {
	var allRuns []*github.WorkflowRun

	chunkDuration := 48 * time.Hour

	var timeChunks []struct {
		chunkStart time.Time
		chunkEnd   time.Time
	}

	for chunkStart := start; chunkStart.Before(end); chunkStart = chunkStart.Add(chunkDuration) {
		chunkEnd := chunkStart.Add(chunkDuration)
		if chunkEnd.After(end) {
			chunkEnd = end
		}
		timeChunks = append(timeChunks, struct {
			chunkStart time.Time
			chunkEnd   time.Time
		}{chunkStart, chunkEnd})
	}

	logger.Infof("Split time range into %d chunks for workflow %d in %s/%s",
		len(timeChunks), workflowID, owner, repo)

	var chunkErrs error
	for i, chunk := range timeChunks {
		stopOuter, err := func() (bool, error) {
			chunkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()

			logger.Debugf("Processing time chunk %d/%d for workflow %d in %s/%s",
				i+1, len(timeChunks), workflowID, owner, repo)

			opts := &github.ListWorkflowRunsOptions{
				ListOptions: github.ListOptions{PerPage: 30},
				Created:     fmt.Sprintf("%s..%s", chunk.chunkStart.Format(time.RFC3339), chunk.chunkEnd.Format(time.RFC3339)),
			}

			var chunkRuns []*github.WorkflowRun
			retryErr := request.WithRetryN(chunkCtx, logger, maxRetries, func() error {
				return paginate(maxWorkflowListPages, "workflow runs", func(page int) (int, error) {
					opts.Page = page
					wr, resp, err := client.Actions.ListWorkflowRunsByID(chunkCtx, owner, repo, workflowID, opts)
					if err != nil {
						return 0, err
					}
					if wr.GetTotalCount() > 0 {
						chunkRuns = append(chunkRuns, wr.WorkflowRuns...)
					}
					if resp == nil || resp.NextPage == 0 {
						return 0, nil
					}
					// Brief inter-page courtesy delay; honor context
					// cancellation so a Ctrl-C does not block on a
					// timer.
					select {
					case <-chunkCtx.Done():
						return 0, chunkCtx.Err()
					case <-time.After(100 * time.Millisecond):
					}
					return resp.NextPage, nil
				})
			})
			if retryErr != nil {
				logger.Warnf("Error listing runs for chunk %d/%d for workflow %d in %s/%s: %v",
					i+1, len(timeChunks), workflowID, owner, repo, retryErr)
				if errors.Is(retryErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
					return true, retryErr
				}
				return false, fmt.Errorf("chunk %d/%d: %w", i+1, len(timeChunks), retryErr)
			}
			for _, run := range chunkRuns {
				createdAt := run.GetCreatedAt().Time
				if createdAt.After(chunk.chunkStart) && createdAt.Before(chunk.chunkEnd) {
					allRuns = append(allRuns, run)
				}
			}

			logger.Debugf("Found %d runs in time chunk %d/%d for workflow %d in %s/%s",
				len(chunkRuns), i+1, len(timeChunks), workflowID, owner, repo)
			return false, nil
		}()
		chunkErrs = errors.Join(chunkErrs, err)
		if stopOuter {
			break
		}
	}

	logger.Infof("Found total of %d runs for workflow %d in %s/%s", len(allRuns), workflowID, owner, repo)

	return allRuns, chunkErrs
}

// listAllJobsPaginated is the internal helper exposed for tests that
// exercise the page-cap branch of listAllJobs.
func listAllJobsPaginated(ctx context.Context, gh *github.Client, owner, repo string, runID int64, maxPages int) ([]*github.WorkflowJob, error) {
	opts := &github.ListWorkflowJobsOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var all []*github.WorkflowJob
	err := paginate(maxPages, "workflow jobs", func(page int) (int, error) {
		opts.Page = page
		out, resp, err := gh.Actions.ListWorkflowJobs(ctx, owner, repo, runID, opts)
		if err != nil {
			return 0, err
		}
		if out != nil {
			all = append(all, out.Jobs...)
		}
		if resp == nil {
			return 0, nil
		}
		return resp.NextPage, nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}
