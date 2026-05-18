package workflow

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/chainguard-dev/clog"
	httpclient "github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/google/go-github/v86/github"
	"golang.org/x/sync/errgroup"
)

// ErrNoJobsForRun marks runs that GitHub lists but expose no per-job
// logs (cancelled runs and reusable-workflow callee shells are the
// common producers). Callers should treat this as a terminal skip for
// the run rather than a transient fetch failure. The sentinel is
// internal to the per-job fetch path; the public no-logs signal is
// ErrRunHasNoLogs below.
var ErrNoJobsForRun = errors.New("workflow: run has no jobs")

// ErrRunHasNoLogs signals that a workflow run has no log content to
// scan. Callers should treat it as a terminal skip rather than a
// fetch failure, and must use errors.Is to detect it -- the signal is
// out of band so attacker-controllable log content cannot trigger an
// inadvertent skip.
var ErrRunHasNoLogs = errors.New("workflow: run has no logs to scan")

// timestampRE strips the leading RFC3339-like prefix that GitHub
// prepends to every log line. Compiled once at init so per-line scans
// pay zero regex build cost.
var timestampRE = regexp.MustCompile(timestampRegex)

const (
	cancelled      string = "cancelled"
	timestampRegex string = `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+`
	// runLogsMaxRedirects bounds redirect follows when GitHub points the
	// run-level logs endpoint at a signed objects.githubusercontent.com
	// URL. httpclient.redirectGuard separately enforces the host
	// allowlist, so this only protects against a malicious chain that
	// would still resolve to allowed hosts.
	runLogsMaxRedirects = 5
	// jobLogsMaxRedirects mirrors runLogsMaxRedirects for the per-job
	// fallback path.
	jobLogsMaxRedirects = 5
	// perJobFanOutLimit caps the number of concurrent per-job log
	// downloads when GetLogs falls back to the per-job endpoint.
	// Mirrors internal/action.fanOutLimit; chosen well below GitHub's
	// documented 100-request secondary concurrency limit.
	perJobFanOutLimit = 32
)

type Finding struct {
	Encoded           string   `json:"encoded,omitempty"`
	Decoded           string   `json:"decoded,omitempty"`
	LineData          string   `json:"line_data,omitempty"`
	WorkflowFileSHA   string   `json:"workflow_file_sha,omitempty"`
	OffendingUsesLine string   `json:"offending_uses_line,omitempty"`
	ResolvedRefForm   string   `json:"resolved_ref_form,omitempty"`
	JobName           string   `json:"job_name,omitempty"`
	StepName          string   `json:"step_name,omitempty"`
	ReachableSecrets  []string `json:"reachable_secrets,omitempty"`
}

func ExtractLogs(rc io.Reader) (string, error) {
	data, err := io.ReadAll(rc)
	if err != nil {
		return "", fmt.Errorf("read logs: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}
	var logsBuilder strings.Builder
	for _, file := range zr.File {
		err = func() error {
			f, err := file.Open()
			if err != nil {
				return fmt.Errorf("open zip member: %w", err)
			}
			defer func() { _ = f.Close() }()
			b, err := io.ReadAll(f)
			if err != nil {
				return fmt.Errorf("read zip member: %w", err)
			}
			logsBuilder.Write(b)
			logsBuilder.WriteString("\n")
			return nil
		}()
		if err != nil {
			return "", err
		}
	}
	return logsBuilder.String(), nil
}

// GetLogs fetches the workflow run log archive. When the run-level logs
// endpoint returns 404/410 (typical after the 30-day archive window or
// for cancelled runs), it falls back to the per-job logs API exposed by
// go-github's [github.ActionsService.ListWorkflowJobs] and
// [github.ActionsService.GetWorkflowJobLogs]. The prior HTML-scraping
// fallback was deleted in favor of these REST endpoints. The shared
// hc carries retry, ETag caching, rate limiting and the redirect
// allowlist for the log payload itself; gh handles all REST envelopes
// (status, listing, redirect resolution).
//
// token is used on raw log download requests (signed
// objects.githubusercontent.com URLs may not embed credentials). It
// is not consulted on REST envelope calls because gh is expected to
// carry its own authentication.
func GetLogs(ctx context.Context, logger *clog.Logger, hc *httpclient.Client, gh *github.Client, owner, repo string, runID int64, token string) (io.ReadCloser, error) {
	if hc == nil {
		return nil, fmt.Errorf("httpclient must not be nil")
	}
	if gh == nil {
		return nil, fmt.Errorf("github client must not be nil")
	}

	run, _, err := gh.Actions.GetWorkflowRunByID(ctx, owner, repo, runID)
	if err != nil {
		return nil, fmt.Errorf("fetching run status: %w", err)
	}

	status := run.GetStatus()
	conclusion := run.GetConclusion()
	if status == cancelled || conclusion == cancelled {
		// For cancelled runs we proactively check job count; if there
		// are no jobs the per-job fallback can't help us either.
		jobCount, err := countJobs(ctx, gh, owner, repo, runID)
		if err == nil && jobCount == 0 {
			logger.Infof("Run %d was canceled with no jobs, skipping log retrieval", runID)
			return nil, fmt.Errorf("run %d: %w", runID, ErrRunHasNoLogs)
		}
	}

	logURL, resp, err := gh.Actions.GetWorkflowRunLogs(ctx, owner, repo, runID, runLogsMaxRedirects)
	switch {
	case err == nil && logURL != nil:
		body, err := fetchRawLogs(ctx, hc, logURL.String(), token)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(body)), nil

	case resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone):
		logger.Warnf("Logs API returned %d for run %d; falling back to per-job logs API", resp.StatusCode, runID)
		return fallbackPerJobLogs(ctx, logger, hc, gh, owner, repo, runID, token, status, conclusion)

	default:
		if resp != nil && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
			if status == cancelled || conclusion == cancelled {
				logger.Infof("Run %d was canceled, no job logs found in API response", runID)
				return nil, fmt.Errorf("run %d: %w", runID, ErrRunHasNoLogs)
			}
			return nil, fmt.Errorf("failed to download logs: status %d", resp.StatusCode)
		}
		if err != nil {
			return nil, fmt.Errorf("executing logs request: %w", err)
		}
		return nil, fmt.Errorf("logs API returned no URL and no error")
	}
}

func fallbackPerJobLogs(
	ctx context.Context,
	logger *clog.Logger,
	hc *httpclient.Client,
	gh *github.Client,
	owner, repo string,
	runID int64,
	token, status, conclusion string,
) (io.ReadCloser, error) {
	jobLogs, err := getPerJobLogs(ctx, hc, gh, owner, repo, runID, token)
	if err != nil {
		if errors.Is(err, ErrNoJobsForRun) {
			if status == cancelled || conclusion == cancelled {
				logger.Infof("Run %d was canceled with no jobs; skipping", runID)
			} else {
				logger.Warnf("Run %d has no jobs; skipping (likely reusable-workflow callee or empty run)", runID)
			}
			return nil, fmt.Errorf("run %d: %w", runID, ErrRunHasNoLogs)
		}
		return nil, fmt.Errorf("fetching per-job logs: %w", err)
	}

	if len(jobLogs) == 0 {
		if status == cancelled || conclusion == cancelled {
			logger.Infof("Run %d was canceled with no jobs; skipping", runID)
			return nil, fmt.Errorf("run %d: %w", runID, ErrRunHasNoLogs)
		}
		return nil, fmt.Errorf("no per-job logs returned")
	}

	combinedLogs, err := combineLogs(jobLogs)
	if err != nil {
		return nil, fmt.Errorf("combining logs: %w", err)
	}
	return combinedLogs, nil
}

func ParseLogs(logger *clog.Logger, logData string, runID int64, findIOC *ioc.IOC) ([]Finding, bool) {
	if findIOC == nil {
		logger.Errorf("provided IOC is nil, unable to scan logs")
		return nil, false
	}

	scanner := bufio.NewScanner(strings.NewReader(logData))
	regex := findIOC.GetRegex()

	lineMap := make(map[string]struct{}, 16)
	encodedMap := make(map[string]struct{}, 16)
	decodedMap := make(map[string]struct{}, 16)

	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		lineMap = findMatch(line, findIOC, timestampRE, lineMap, logger, runID)

		if regex == nil {
			continue
		}

		encodedMap, decodedMap = processMatch(line, regex, lineNum, encodedMap, decodedMap, logger, runID)
	}

	finding := Finding{
		Encoded:  strings.Join(setToSlice(encodedMap), ","),
		Decoded:  strings.Join(setToSlice(decodedMap), ","),
		LineData: strings.Join(setToSlice(lineMap), ","),
	}

	findings := []Finding{finding}
	foundIssues := len(findings) > 0
	return findings, foundIssues
}

// setToSlice flattens a set into a slice via a single pass with the
// final capacity known up-front. Avoids the two-pass collect/copy that
// slices.Collect(maps.Keys(...)) performs.
func setToSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func findMatch(line string, findIOC *ioc.IOC, timestamp *regexp.Regexp, lineMap map[string]struct{}, logger *clog.Logger, runID int64) map[string]struct{} {
	if len(findIOC.GetContent()) == 0 {
		return lineMap
	}

	// The IOC carries a precomputed bloom-prefiltered Matcher built once
	// at construction. The bloom prefilter rejects lines that contain no
	// n-gram from any IOC -- the common case for log scanning at
	// internet scale -- without invoking the deterministic backend. The
	// string-input variant skips the []byte(line) conversion that the
	// generic Match() entrypoint would otherwise force.
	matcher := findIOC.GetMatcher()
	if matcher == nil || !matcher.MatchAnyString(line) {
		return lineMap
	}

	clean := timestamp.ReplaceAllString(line, "")
	lineMap[clean] = struct{}{}
	logger.Warnf("IOC log entry found in Run ID: %d", runID)

	return lineMap
}

func processMatch(line string, regex *regexp.Regexp, lineNum int, encodedMap, decodedMap map[string]struct{}, logger *clog.Logger, runID int64) (map[string]struct{}, map[string]struct{}) {
	matches := regex.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) <= 1 {
			continue
		}

		encoded := match[1]
		decoded, err := tryBase64Decode(encoded)
		if err != nil {
			continue
		}

		encodedMap[encoded] = struct{}{}
		decodedMap = handleDecoded(decoded, lineNum, decodedMap, logger, runID)
	}

	return encodedMap, decodedMap
}

func handleDecoded(decoded string, lineNum int, decodedMap map[string]struct{}, logger *clog.Logger, runID int64) map[string]struct{} {
	secondDecoded, err := tryBase64Decode(decoded)
	if err == nil {
		decodedMap[secondDecoded] = struct{}{}
		logger.Warnf("Found valid double base64-encoded content at log line %d in Run ID: %d", lineNum, runID)
	} else {
		decodedMap[decoded] = struct{}{}
		logger.Infof("Found valid base64-encoded content at log line %d in Run ID: %d", lineNum, runID)
	}
	return decodedMap
}

// countJobs returns the total number of jobs in a workflow run. It is
// used as a sanity check on the cancelled-run fast path.
func countJobs(ctx context.Context, gh *github.Client, owner, repo string, runID int64) (int, error) {
	res, _, err := gh.Actions.ListWorkflowJobs(ctx, owner, repo, runID, &github.ListWorkflowJobsOptions{
		ListOptions: github.ListOptions{PerPage: 1},
	})
	if err != nil {
		return 0, err
	}
	if res == nil {
		return 0, nil
	}
	return res.GetTotalCount(), nil
}

// getPerJobLogs enumerates all jobs in a workflow run via the GitHub
// REST API and downloads each job's plain-text logs via the redirect
// URL returned by the per-job logs endpoint. The returned map is keyed
// by job ID so combineLogs produces deterministic output ordered by
// numeric job ID.
//
// Per-job downloads run concurrently capped at perJobFanOutLimit so
// runs with many jobs amortize GitHub's API round-trip latency without
// exceeding the documented secondary rate-limit budget.
func getPerJobLogs(ctx context.Context, hc *httpclient.Client, gh *github.Client, owner, repo string, runID int64, token string) (map[int64]io.ReadCloser, error) {
	jobs, err := listAllJobs(ctx, gh, owner, repo, runID)
	if err != nil {
		return nil, fmt.Errorf("listing jobs: %w", err)
	}
	if len(jobs) == 0 {
		return nil, fmt.Errorf("run %d: %w", runID, ErrNoJobsForRun)
	}

	var (
		mu           sync.Mutex
		results      = make(map[int64]io.ReadCloser, len(jobs))
		fetchErrors  []string
		recordResult = func(id int64, body []byte) {
			mu.Lock()
			results[id] = io.NopCloser(bytes.NewReader(body))
			mu.Unlock()
		}
		recordError = func(format string, args ...any) {
			mu.Lock()
			fetchErrors = append(fetchErrors, fmt.Sprintf(format, args...))
			mu.Unlock()
		}
	)

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(perJobFanOutLimit)

	for _, job := range jobs {
		jobID := job.GetID()
		if jobID == 0 {
			continue
		}

		jobName := job.GetName()
		if jobName == "" {
			jobName = fmt.Sprintf("Job-%d", jobID)
		}

		g.Go(func() error {
			select {
			case <-gCtx.Done():
				return gCtx.Err()
			default:
			}

			logURL, _, err := gh.Actions.GetWorkflowJobLogs(gCtx, owner, repo, jobID, jobLogsMaxRedirects)
			if err != nil {
				recordError("job %s (ID: %d) get-url: %v", jobName, jobID, err)
				return nil
			}
			if logURL == nil {
				recordError("job %s (ID: %d): empty log URL", jobName, jobID)
				return nil
			}

			body, err := fetchRawLogs(gCtx, hc, logURL.String(), token)
			if err != nil {
				recordError("job %s (ID: %d) fetch: %v", jobName, jobID, err)
				return nil
			}
			recordResult(jobID, body)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("per-job log fetch interrupted: %w", err)
	}

	if len(results) == 0 && len(fetchErrors) > 0 {
		return nil, fmt.Errorf("failed to fetch any job logs: %s", strings.Join(fetchErrors, "; "))
	}
	if len(fetchErrors) > 0 {
		clog.WarnContextf(ctx, "failed to fetch some job logs: %s", strings.Join(fetchErrors, "; "))
	}

	return results, nil
}

// listAllJobs iterates ListWorkflowJobs across every page so the caller
// observes every job for the run. PerPage is set to the API maximum of
// 100 to minimize round trips on large fan-out workflows. The page
// count is capped to bound a misbehaving server.
func listAllJobs(ctx context.Context, gh *github.Client, owner, repo string, runID int64) ([]*github.WorkflowJob, error) {
	return listAllJobsPaginated(ctx, gh, owner, repo, runID, maxWorkflowListPages)
}

// fetchRawLogs downloads the plain-text log payload pointed at by the
// signed URL returned by the run-level or per-job logs endpoint. The
// shared httpclient enforces redirect allowlisting and body capping;
// the token is forwarded as a GitHub bearer in case the URL does not
// already carry credentials in the query string.
func fetchRawLogs(ctx context.Context, hc *httpclient.Client, rawLogURL, token string) ([]byte, error) {
	rawReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawLogURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating raw logs request: %w", err)
	}
	if token != "" {
		rawReq.Header.Set("Authorization", "token "+token)
	}

	body, rawResp, err := hc.DoWithRetry(ctx, rawReq) //nolint:bodyclose // httpclient drains body and reassigns to http.NoBody.
	if err != nil {
		return nil, fmt.Errorf("fetching raw logs: %w", err)
	}
	if rawResp == nil {
		return nil, fmt.Errorf("fetching raw logs: nil response")
	}

	if rawResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve raw logs, status code: %d", rawResp.StatusCode)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty raw logs")
	}

	return body, nil
}

func combineLogs(logsMap map[int64]io.ReadCloser) (io.ReadCloser, error) {
	var combinedBuilder strings.Builder

	jobIDs := make([]int64, 0, len(logsMap))
	for jobID := range logsMap {
		jobIDs = append(jobIDs, jobID)
	}
	slices.Sort(jobIDs)

	for _, jobID := range jobIDs {
		logs := logsMap[jobID]
		if logs == nil {
			continue
		}
		fmt.Fprintf(&combinedBuilder, "===== JOB ID: %d =====\n", jobID)

		logContent, err := io.ReadAll(logs)
		if err != nil {
			return nil, fmt.Errorf("reading logs for job %d: %w", jobID, err)
		}
		err = logs.Close()
		if err != nil {
			return nil, fmt.Errorf("closing logs for job %d: %w", jobID, err)
		}

		combinedBuilder.Write(logContent)
		combinedBuilder.WriteString("\n\n")
	}

	return io.NopCloser(strings.NewReader(combinedBuilder.String())), nil
}

func tryBase64Decode(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	if !utf8.Valid(decoded) {
		return "", fmt.Errorf("decoded content is not valid UTF8")
	}

	return string(decoded), nil
}
