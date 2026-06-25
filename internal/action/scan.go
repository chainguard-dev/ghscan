package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/request"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	wf "github.com/chainguard-dev/ghscan/pkg/workflow"
	"github.com/google/go-github/v86/github"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"
)

// fanOutLimit caps every concurrent dispatch site in this package.
// It is set well below GitHub's documented secondary rate-limit
// threshold of 100 concurrent requests, leaving headroom for the
// singleflight tier in pkg/httpclient and the rate-limit aware
// retry loop.
const fanOutLimit = 32

// Per-operation timeout budgets resolved from viper. Each key has a
// default supplied by cmd/ghscan.setDefaults so a fresh checkout with
// no config.yaml still operates with sensible bounds.
const (
	// workflowFetchBudgetKey bounds the wfCtx used to resolve a
	// workflow definition and enumerate its runs.
	workflowFetchBudgetKey = "workflow_fetch_budget"
	// runScanBudgetKey bounds the per-run log download and parse.
	runScanBudgetKey = "run_scan_budget"
	// repoEnumBudgetKey bounds the per-repository workflow search and
	// dispatch.
	repoEnumBudgetKey = "repo_enum_budget"
	// scanYAMLKey enables the YAML-scanning path. Defaults to true.
	scanYAMLKey = "scan_yaml"
	// scanLogsKey enables the log-scanning path. Defaults to true.
	scanLogsKey = "scan_logs"
)

// scanPathEnabled returns the configured boolean for key, defaulting
// to true when the key has not been explicitly set. Both YAML and log
// paths are on by default so existing users observe no behavior
// change.
func scanPathEnabled(key string) bool {
	if !viper.IsSet(key) {
		return true
	}
	return viper.GetBool(key)
}

// resolveDuration returns the configured duration for key, falling
// back to fallback when the value is unset, unparseable, or
// non-positive. Centralized so each call site reads viper exactly
// once with the same semantics.
func resolveDuration(key string, fallback time.Duration) time.Duration {
	d := viper.GetDuration(key)
	if d > 0 {
		return d
	}
	return fallback
}

// defaultMaxRetries is the fallback retry budget used when viper has
// no positive "max_retries" configured. It mirrors the default seeded
// by the CLI entrypoint so library callers that bypass main get the
// same behavior.
const defaultMaxRetries = 3

// resolveMaxRetries returns the configured retry budget, falling back
// to defaultMaxRetries when the value is unset or non-positive. Read
// once per Scan/scanWorkflows/scanRuns invocation and threaded through
// to WithRetryN so the package never reaches into viper from a hot
// loop.
func resolveMaxRetries() int {
	n := viper.GetInt("max_retries")
	if n > 0 {
		return n
	}
	return defaultMaxRetries
}

// Error-wrap convention: errors propagated up to the caller may embed
// go-github's error string verbatim, which can include the request URL
// (e.g. https://api.github.com/repos/<owner>/<repo>/...). Repository
// paths are not secret in this CLI threat model -- the user already
// supplied them as -target -- so this is intentional. Authorization
// tokens and other credentials never appear in go-github error
// strings; the SDK strips them before formatting.

func scanWorkflows(ctx context.Context, logger *clog.Logger, req *ghscan.Request) error {
	if req == nil {
		return fmt.Errorf("req cannot be nil")
	}

	maxRetries := resolveMaxRetries()

	// fanOutLimit stays well under GitHub's documented secondary
	// rate-limit concurrency budget (100).
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(fanOutLimit)

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

				wfCtx, wfCancel := context.WithTimeout(ctx, resolveDuration(workflowFetchBudgetKey, req.Timeout*2))
				defer wfCancel()

				var workflow *github.Workflow
				err := request.WithRetryN(wfCtx, logger, maxRetries, func() error {
					var err error
					workflow, err = wf.GetWorkflowByPath(wfCtx, req.Client(), req.Owner, req.RepoName, wfPath)
					return err
				})
				if err != nil {
					return fmt.Errorf("error retrieving workflow for %s in %s/%s: %v", wfPath, req.Owner, req.RepoName, err)
				}

				workflowID := workflow.GetID()

				var runs []*github.WorkflowRun
				err = request.WithRetryN(ctx, logger, maxRetries, func() error {
					var err error
					runs, err = wf.ListWorkflowRuns(wfCtx, logger, req.Client(), req.Owner, req.RepoName, workflowID, req.StartTime, req.EndTime, maxRetries)
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

func scanRuns(ctx context.Context, logger *clog.Logger, req *ghscan.Request, runs []*github.WorkflowRun, wfFileName, wfPath string) error {
	if req == nil {
		return fmt.Errorf("req cannot be nil")
	}

	maxRetries := resolveMaxRetries()

	var resultsMu sync.Mutex

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(fanOutLimit)

	logger.Infof("Found %d runs for workflow %s in %s/%s", len(runs), wfFileName, req.Owner, req.RepoName)

	var runResults []ghscan.Result
	for _, run := range runs {
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
				runID := run.GetID()
				runCtx, runCancel := context.WithTimeout(ctx, resolveDuration(runScanBudgetKey, req.Timeout))
				defer runCancel()

				// rc is goroutine-local so concurrent runs don't clobber
				// each other's ReadClosers.
				var rc io.ReadCloser
				err := request.WithRetryN(runCtx, logger, maxRetries, func() error {
					var err error
					rc, err = wf.GetLogs(runCtx, logger, req.HTTPClient(), req.Client(), req.Owner, req.RepoName, runID, req.Token)
					if errors.Is(err, wf.ErrRunHasNoLogs) {
						return request.Permanent(err)
					}
					return err
				})
				if err != nil {
					if errors.Is(err, wf.ErrRunHasNoLogs) {
						return nil
					}
					return fmt.Errorf("failed to download logs for run %d after retries: %v", runID, err)
				}
				defer func() { _ = rc.Close() }()

				logText, err := wf.ExtractLogs(rc)
				if err != nil {
					return fmt.Errorf("error extracting logs for run %d: %v", runID, err)
				}
				wfFindings, found := wf.ParseLogs(logger, logText, runID, req.IOC)
				if !found || len(wfFindings) == 0 {
					return nil
				}

				workflowUIURL := fmt.Sprintf("https://github.com/%s/%s/actions/workflows/%s",
					req.Owner, req.RepoName, url.PathEscape(wfPath))

				workflowRunUIURL := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d",
					req.Owner, req.RepoName, runID)

				// Every finding in wfFindings shares the same
				// (workflowRunUIURL) key, so collapse to a single
				// Result accumulator and let later non-empty fields
				// overwrite earlier ones. This matches the previous
				// map-based behavior without the round-trip alloc.
				var (
					acc      ghscan.Result
					accDirty bool
				)
				for _, finding := range wfFindings {
					if finding.Encoded == "" && finding.Decoded == "" && finding.LineData == "" {
						continue
					}
					if !accDirty {
						acc = ghscan.Result{
							Repository:       fmt.Sprintf("%s/%s", req.Owner, req.RepoName),
							WorkflowFileName: wfFileName,
							WorkflowURL:      workflowUIURL,
							WorkflowRunURL:   workflowRunUIURL,
							Base64Data:       finding.Encoded,
							DecodedData:      finding.Decoded,
							LineData:         finding.LineData,
						}
						accDirty = true
						continue
					}
					if finding.LineData != "" {
						acc.LineData = finding.LineData
					}
					if finding.Encoded != "" {
						acc.Base64Data = finding.Encoded
					}
					if finding.Decoded != "" {
						acc.DecodedData = finding.Decoded
					}
				}

				if !accDirty {
					return nil
				}

				resultsMu.Lock()
				runResults = append(runResults, acc)
				resultsMu.Unlock()

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

// scanYAML walks every workflow file under .github/workflows for the
// repo carried on req, parses uses: edges, and emits a finding for
// each edge whose (action, ref) matches the embedded IOC corpus.
// Results are appended to req.Cache.Results under cacheMu.
//
// scanYAML is independent of the runs-and-logs path: it catches
// known-bad refs before the action ever runs (preventing secret
// exfiltration), while the log path catches behavioral IOCs that
// surface only after execution.
func scanYAML(ctx context.Context, logger *clog.Logger, req *ghscan.Request, maxRetries int) error {
	corpus, err := iocCorpusFor(req)
	if err != nil {
		return err
	}
	if corpus == nil || len(corpus.IOCs) == 0 {
		return nil
	}

	wfCtx, wfCancel := context.WithTimeout(ctx, resolveDuration(workflowFetchBudgetKey, req.Timeout*2))
	defer wfCancel()

	var paths []string
	err = request.WithRetryN(wfCtx, logger, maxRetries, func() error {
		var err error
		paths, err = wf.ListWorkflowFilePaths(wfCtx, req.Client(), req.Owner, req.RepoName, "")
		return err
	})
	if err != nil {
		return fmt.Errorf("listing workflow files: %w", err)
	}

	var (
		mu       sync.Mutex
		findings []ghscan.Result
	)

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(fanOutLimit)

	for _, wfPath := range paths {
		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}

			fileCtx, fileCancel := context.WithTimeout(ctx, resolveDuration(runScanBudgetKey, req.Timeout))
			defer fileCancel()

			var (
				body []byte
				sha  string
			)
			err := request.WithRetryN(fileCtx, logger, maxRetries, func() error {
				var err error
				body, sha, err = wf.FetchWorkflowYAMLWithSHA(fileCtx, req.Client(), req.Owner, req.RepoName, wfPath, "")
				return err
			})
			if err != nil {
				logger.Warnf("fetching %s/%s %s: %v", req.Owner, req.RepoName, wfPath, err)
				return nil
			}

			edges, err := wf.ParseUsesEdges(body)
			if err != nil {
				logger.Warnf("parsing %s/%s %s: %v", req.Owner, req.RepoName, wfPath, err)
				return nil
			}

			wfFileName := filepath.Base(wfPath)
			workflowUIURL := fmt.Sprintf("https://github.com/%s/%s/actions/workflows/%s",
				req.Owner, req.RepoName, url.PathEscape(wfPath))

			for _, e := range edges {
				if !corpus.MatchActionRef(e.Action, e.Ref) {
					continue
				}
				res := ghscan.Result{
					Repository:        fmt.Sprintf("%s/%s", req.Owner, req.RepoName),
					WorkflowFileName:  wfFileName,
					WorkflowURL:       workflowUIURL,
					WorkflowFileSHA:   sha,
					OffendingUsesLine: e.Uses,
					ResolvedRefForm:   e.RefForm,
					JobName:           e.JobName,
					StepName:          e.StepName,
					ReachableSecrets:  e.Secrets,
					Source:            "yaml",
				}
				mu.Lock()
				findings = append(findings, res)
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	if len(findings) > 0 {
		req.Cache.Results = append(req.Cache.Results, findings...)
	}
	return nil
}

// iocCorpusFor returns the corpus the YAML scanner should consult.
// When the operator supplied --ioc-file the request carries an
// explicit override; otherwise the embedded corpus is used.
func iocCorpusFor(req *ghscan.Request) (*ioc.Corpus, error) {
	if req != nil && req.Corpus != nil {
		return req.Corpus, nil
	}
	c, err := ioc.LoadEmbeddedCorpus()
	if err != nil {
		return nil, fmt.Errorf("loading embedded IOC corpus: %w", err)
	}
	return c, nil
}

func Scan(ctx context.Context, logger *clog.Logger, req *ghscan.Request, repos []*github.Repository) error {
	if req == nil {
		return fmt.Errorf("req cannot be nil")
	}

	yamlEnabled := scanPathEnabled(scanYAMLKey)
	logsEnabled := scanPathEnabled(scanLogsKey)
	if !yamlEnabled && !logsEnabled {
		return fmt.Errorf("at least one of scan_yaml or scan_logs must be enabled")
	}

	maxRetries := resolveMaxRetries()

	// max_concurrency is honored only when it is a positive value
	// tighter than fanOutLimit. errgroup.SetLimit(<=0) disables the
	// limit entirely, which would defeat the bounded-dispatch
	// invariant.
	maxConcurrency := viper.GetInt("max_concurrency")
	if maxConcurrency <= 0 || maxConcurrency > fanOutLimit {
		maxConcurrency = fanOutLimit
	}
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrency)

	// cacheMu guards merging per-repo result slices back into the
	// shared req.Cache.Results once each repository finishes.
	var cacheMu sync.Mutex

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
				repoCtx, repoCancel := context.WithTimeout(ctx, resolveDuration(repoEnumBudgetKey, opTimeout*5))
				defer repoCancel()

				repoReq := *req
				repoReq.Cache = ghscan.Cache{}
				repoReq.Owner = owner
				repoReq.RepoName = repoName
				repoReq.Timeout = opTimeout

				if yamlEnabled {
					if err := scanYAML(repoCtx, logger, &repoReq, maxRetries); err != nil {
						return fmt.Errorf("YAML scan of %s/%s: %w", owner, repoName, err)
					}
				}

				if logsEnabled {
					query := fmt.Sprintf("repo:%s/%s path:.github/workflows language:YAML", owner, repoName)

					var workflowPaths []string
					err := request.WithRetryN(repoCtx, logger, maxRetries, func() error {
						var err error
						workflowPaths, err = wf.SearchWorkflowFiles(repoCtx, req.Client(), query)
						return err
					})
					if err != nil {
						return fmt.Errorf("error searching workflows in %s/%s: %v", owner, repoName, err)
					}

					logger.Infof("Found %d workflow files in %s/%s", len(workflowPaths), owner, repoName)
					repoReq.Workflows = workflowPaths

					if err := scanWorkflows(ctx, logger, &repoReq); err != nil {
						return err
					}
				}

				merged := dedupResults(repoReq.Cache.Results)
				if len(merged) > 0 {
					cacheMu.Lock()
					req.Cache.Results = append(req.Cache.Results, merged...)
					cacheMu.Unlock()
				}
				return nil
			}
		})
	}

	return g.Wait()
}

// dedupResults merges results emitted by the YAML and log paths so a
// single workflow file produces one record when both paths fire.
// The YAML record wins because it carries the richer attribution
// context (job/step name, ref form, reachable secrets) needed to
// triage the finding. Log records on a workflow file with no YAML
// finding remain in place.
func dedupResults(in []ghscan.Result) []ghscan.Result {
	if len(in) == 0 {
		return in
	}
	yamlFiles := make(map[string]struct{}, len(in))
	for _, r := range in {
		if r.Source == "yaml" && r.WorkflowFileName != "" {
			yamlFiles[r.Repository+"|"+r.WorkflowFileName] = struct{}{}
		}
	}
	if len(yamlFiles) == 0 {
		return in
	}
	out := make([]ghscan.Result, 0, len(in))
	for _, r := range in {
		if r.Source != "yaml" {
			if _, ok := yamlFiles[r.Repository+"|"+r.WorkflowFileName]; ok {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
