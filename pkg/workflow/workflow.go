package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/tj-scan/pkg/request"
	"github.com/google/go-github/v69/github"
)

func SearchWorkflowFiles(ctx context.Context, client *github.Client, query string) ([]string, error) {
	var paths []string
	opts := &github.SearchOptions{ListOptions: github.ListOptions{PerPage: 100}}
	for {
		result, resp, err := client.Search.Code(ctx, query, opts)
		if err != nil {
			return paths, err
		}
		for _, item := range result.CodeResults {
			if item.Path != nil {
				paths = append(paths, *item.Path)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return paths, nil
}

func GetWorkflowByPath(ctx context.Context, client *github.Client, owner, repo, wfPath string) (*github.Workflow, error) {
	wfs, _, err := client.Actions.ListWorkflows(ctx, owner, repo, &github.ListOptions{PerPage: 100})
	if err != nil {
		return nil, err
	}
	for _, wf := range wfs.Workflows {
		if wf.GetPath() == wfPath {
			return wf, nil
		}
	}
	return nil, fmt.Errorf("workflow with path %s not found", wfPath)
}

func ListWorkflowRuns(ctx context.Context, logger *clog.Logger, client *github.Client, owner, repo string, workflowID int64, start, end time.Time) ([]*github.WorkflowRun, error) {
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

	for i, chunk := range timeChunks {
		func() {
			chunkCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()

			logger.Debugf("Processing time chunk %d/%d for workflow %d in %s/%s",
				i+1, len(timeChunks), workflowID, owner, repo)

			opts := &github.ListWorkflowRunsOptions{
				ListOptions: github.ListOptions{PerPage: 30},
				Created:     fmt.Sprintf("%s..%s", chunk.chunkStart.Format(time.RFC3339), chunk.chunkEnd.Format(time.RFC3339)),
			}

			var chunkRuns []*github.WorkflowRun
			err := request.WithRetry(chunkCtx, logger, func() error {
				for {
					wr, resp, err := client.Actions.ListWorkflowRunsByID(chunkCtx, owner, repo, workflowID, opts)
					if err != nil {
						return err
					}

					if wr.GetTotalCount() > 0 {
						chunkRuns = append(chunkRuns, wr.WorkflowRuns...)
					}

					if resp.NextPage == 0 {
						break
					}

					time.Sleep(100 * time.Millisecond)
					opts.Page = resp.NextPage
				}
				return nil
			})
			if err != nil {
				logger.Warnf("Error listing runs for chunk %d/%d for workflow %d in %s/%s: %v",
					i+1, len(timeChunks), workflowID, owner, repo, err)
			}
			for _, run := range chunkRuns {
				createdAt := run.GetCreatedAt().Time
				if createdAt.After(chunk.chunkStart) && createdAt.Before(chunk.chunkEnd) {
					allRuns = append(allRuns, run)
				}
			}

			logger.Debugf("Found %d runs in time chunk %d/%d for workflow %d in %s/%s",
				len(chunkRuns), i+1, len(timeChunks), workflowID, owner, repo)
		}()
	}

	logger.Infof("Found total of %d runs for workflow %d in %s/%s", len(allRuns), workflowID, owner, repo)

	return allRuns, nil
}
