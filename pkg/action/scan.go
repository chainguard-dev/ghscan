package action

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/tj-scan/pkg/file"
	"github.com/chainguard-dev/tj-scan/pkg/request"
	tjscan "github.com/chainguard-dev/tj-scan/pkg/tj-scan"
	wf "github.com/chainguard-dev/tj-scan/pkg/workflow"
	"github.com/google/go-github/v69/github"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

func scanWorkflows(ctx context.Context, logger *clog.Logger, req *tjscan.Request) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(2)

	if req == nil {
		return fmt.Errorf("req cannot be nil")
	}

	for _, wfPath := range req.Workflows {
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
				wfFileName := filepath.Base(wfPath)
				repoKey := fmt.Sprintf("%s/%s", req.Owner, req.RepoName)
				cacheKey := fmt.Sprintf("%s|%s", repoKey, wfFileName)

				if req.CachedResults[cacheKey] {
					logger.Infof("Skipping already processed workflow %s in %s", wfFileName, repoKey)
					return nil
				}

				wfCtx, wfCancel := context.WithTimeout(ctx, req.Timeout*2)
				defer wfCancel()

				var workflow *github.Workflow
				err := request.WithRetry(wfCtx, logger, func() error {
					var err error
					workflow, err = wf.GetWorkflowByPath(wfCtx, req.Client, req.Owner, req.RepoName, wfPath)
					return err
				})
				if err != nil {
					return fmt.Errorf("error retrieving workflow for %s in %s/%s: %v", wfPath, req.Owner, req.RepoName, err)
				}

				workflowID := workflow.GetID()

				var runs []*github.WorkflowRun
				err = request.WithRetry(ctx, logger, func() error {
					var err error
					runs, err = wf.ListWorkflowRuns(wfCtx, logger, req.Client, req.Owner, req.RepoName, workflowID, req.StartTime, req.EndTime)
					return err
				})
				if err != nil {
					return fmt.Errorf("error listing runs for workflow %d in %s/%s: %v", workflowID, req.Owner, req.RepoName, err)
				}

				return scanRuns(ctx, logger, req, runs, wfFileName, wfPath)
			}
		})
	}

	return g.Wait()
}

func scanRuns(ctx context.Context, logger *clog.Logger, req *tjscan.Request, runs []*github.WorkflowRun, wfFileName, wfPath string) error {
	var rc io.ReadCloser
	var resultsMu sync.Mutex

	if req == nil {
		return fmt.Errorf("req cannot be nil")
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(2)

	logger.Infof("Found %d runs for workflow %s in %s/%s", len(runs), wfFileName, req.Owner, req.RepoName)

	var runResults []tjscan.Result
	for _, run := range runs {
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
				runID := run.GetID()
				runCtx, runCancel := context.WithTimeout(ctx, req.Timeout)
				defer runCancel()

				err := request.WithRetry(runCtx, logger, func() error {
					var err error
					rc, err = wf.GetLogs(runCtx, logger, req.Owner, req.RepoName, runID, req.Token)
					return err
				})
				if err != nil {
					return fmt.Errorf("failed to download logs for run %d after retries: %v", runID, err)
				}
				defer rc.Close()

				var buf bytes.Buffer
				tee := io.TeeReader(rc, &buf)

				previewBuf := make([]byte, 100)
				n, _ := tee.Read(previewBuf)
				preview := string(previewBuf[:n])

				if strings.Contains(preview, "was canceled with no jobs") {
					return nil
				}

				full := io.MultiReader(&buf, rc)

				logText, err := wf.ExtractLogs(full)
				if err != nil {
					return fmt.Errorf("error extracting logs for run %d: %v", runID, err)
				}
				base64Findings, emptyLines, found := wf.ParseLogs(logger, logText, runID, true)
				if !found || len(base64Findings) == 0 {
					return nil
				}

				workflowUIURL := fmt.Sprintf("https://github.com/%s/%s/actions/workflows/%s",
					req.Owner, req.RepoName, url.PathEscape(wfPath))

				workflowRunUIURL := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d",
					req.Owner, req.RepoName, runID)

				var findings []tjscan.Result
				for _, finding := range base64Findings {
					res := tjscan.Result{
						Repository:       fmt.Sprintf("%s/%s", req.Owner, req.RepoName),
						WorkflowFileName: wfFileName,
						WorkflowURL:      workflowUIURL,
						WorkflowRunURL:   workflowRunUIURL,
						Base64Data:       finding.Encoded,
						DecodedData:      finding.Decoded,
						EmptyLines:       emptyLines,
					}
					findings = append(findings, res)
				}

				resultsMu.Lock()
				runResults = append(runResults, findings...)
				resultsMu.Unlock()

				if len(req.Cache.Results)%10 == 0 {
					file.WriteCache(logger, filepath.Join(tjscan.ResultsDir, req.CacheFile), req.Cache.Results)
				}

				return nil
			}
		})
	}
	err := g.Wait()
	if err != nil {
		return err
	}

	req.Cache.Results = append(req.Cache.Results, runResults...)
	return nil
}

func Scan(ctx context.Context, logger *clog.Logger, req *tjscan.Request, repos []*github.Repository) error {
	if req == nil {
		return fmt.Errorf("req cannot be nil")
	}

	scanner := NewScanner(logger, &req.Cache, req.CacheFile, 10)
	defer scanner.Close()

	maxConcurrency := viper.GetInt("max_concurrency")
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrency)

	for _, repo := range repos {
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
				owner := repo.GetOwner().GetLogin()
				repoName := repo.GetName()
				logger.Infof("Processing repository: %s/%s", owner, repoName)

				opTimeout := viper.GetDuration("operation_timeout")
				repoCtx, repoCancel := context.WithTimeout(ctx, opTimeout*5)
				defer repoCancel()

				query := fmt.Sprintf("repo:%s/%s path:.github/workflows language:YAML", owner, repoName)

				var workflowPaths []string
				err := request.WithRetry(repoCtx, logger, func() error {
					var err error
					workflowPaths, err = wf.SearchWorkflowFiles(repoCtx, req.Client, query)
					return err
				})
				if err != nil {
					return fmt.Errorf("error searching workflows in %s/%s: %v", owner, repoName, err)
				}

				logger.Infof("Found %d workflow files in %s/%s", len(workflowPaths), owner, repoName)

				req.Owner = owner
				req.RepoName = repoName
				req.Timeout = opTimeout
				req.Workflows = workflowPaths

				return scanWorkflows(ctx, logger, req)
			}
		})
	}

	return g.Wait()
}
