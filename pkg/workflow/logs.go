package workflow

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PuerkitoBio/goquery"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/tj-scan/pkg/ioc"
)

const (
	cancelled      string = "cancelled"
	header         string = "Mozilla/5.0 (compatible; IOCScanner/1.0)"
	timestampRegex string = `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+`
)

var selectors = []string{
	".js-build-log pre",
	".js-job-log-content pre",
	".js-log-output pre",
	".log-body pre",
	".log-body-container pre",
	"div.job-log-container pre",
	"div[data-test-selector='job-log'] pre",
	"pre.js-file-line-container",
	"pre.logs",
}

type Finding struct {
	Encoded  string
	Decoded  string
	LineData string
}

func ExtractLogs(rc io.Reader) (string, error) {
	data, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", err
	}
	var logsBuilder strings.Builder
	for _, file := range zr.File {
		err = func() error {
			f, err := file.Open()
			if err != nil {
				return err
			}
			b, err := io.ReadAll(f)
			defer f.Close()
			if err != nil {
				return err
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

func GetLogs(ctx context.Context, logger *clog.Logger, owner, repo string, runID int64, token string) (io.ReadCloser, error) {
	runStatusURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/runs/%d", owner, repo, runID)
	statusReq, err := http.NewRequestWithContext(ctx, "GET", runStatusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating run status request: %w", err)
	}
	statusReq.Header.Set("Authorization", "token "+token)
	statusReq.Header.Set("Accept", "application/vnd.github.v3+json")

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	statusResp, err := httpClient.Do(statusReq)
	if err != nil {
		return nil, fmt.Errorf("fetching run status: %w", err)
	}
	defer statusResp.Body.Close()

	if statusResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get run status: status %d", statusResp.StatusCode)
	}

	var runInfo struct {
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		Jobs       struct {
			TotalCount int `json:"total_count"`
		} `json:"jobs"`
	}

	if err := json.NewDecoder(statusResp.Body).Decode(&runInfo); err != nil {
		return nil, fmt.Errorf("parsing run status: %w", err)
	}

	if (runInfo.Status == cancelled || runInfo.Conclusion == cancelled) && runInfo.Jobs.TotalCount == 0 {
		logger.Infof("Run %d was canceled with no jobs, skipping log retrieval", runID)
		return io.NopCloser(strings.NewReader(fmt.Sprintf("Run %d was canceled with no jobs", runID))), nil
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/runs/%d/logs", owner, repo, runID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating API request: %w", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing API request: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		logger.Warnf("Logs API returned %d for run %d; falling back to UI", resp.StatusCode, runID)
		defer resp.Body.Close()

		jobLogs, err := getUILogs(ctx, owner, repo, runID)
		if err != nil {
			if strings.Contains(err.Error(), "no job IDs found") &&
				(runInfo.Status == cancelled || runInfo.Conclusion == cancelled) {
				logger.Infof("Run %d was canceled, no job logs found", runID)
				return io.NopCloser(strings.NewReader(fmt.Sprintf("Run %d was canceled, no job logs available", runID))), nil
			}
			return nil, fmt.Errorf("crawling UI logs: %w", err)
		}

		if len(jobLogs) == 0 {
			if runInfo.Status == cancelled || runInfo.Conclusion == cancelled {
				logger.Infof("Run %d was canceled, no job logs found", runID)
				return io.NopCloser(strings.NewReader(fmt.Sprintf("Run %d was canceled, no job logs available", runID))), nil
			}
			return nil, fmt.Errorf("no job logs found via UI")
		}

		combinedLogs, err := combineLogs(jobLogs)
		if err != nil {
			return nil, fmt.Errorf("combining logs: %w", err)
		}

		return combinedLogs, nil
	}

	if resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		if loc == "" {
			defer resp.Body.Close()
			return nil, fmt.Errorf("redirect location empty")
		}
		defer resp.Body.Close()

		redirectReq, err := http.NewRequestWithContext(ctx, "GET", loc, nil)
		if err != nil {
			return nil, fmt.Errorf("creating redirect request: %w", err)
		}

		redirectResp, err := httpClient.Do(redirectReq)
		if err != nil {
			return nil, fmt.Errorf("following redirect: %w", err)
		}

		if redirectResp.StatusCode != http.StatusOK {
			defer redirectResp.Body.Close()
			if runInfo.Status == cancelled || runInfo.Conclusion == cancelled {
				logger.Infof("Run %d was canceled, no job logs found at redirect", runID)
				return io.NopCloser(strings.NewReader(fmt.Sprintf("Run %d was canceled, no job logs available", runID))), nil
			}

			return nil, fmt.Errorf("failed to download logs from redirect: status %d", redirectResp.StatusCode)
		}

		return redirectResp.Body, nil
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()

		if runInfo.Status == cancelled || runInfo.Conclusion == cancelled {
			logger.Infof("Run %d was canceled, no job logs found in API response", runID)
			return io.NopCloser(strings.NewReader(fmt.Sprintf("Run %d was canceled, no job logs available", runID))), nil
		}

		return nil, fmt.Errorf("failed to download logs: status %d", resp.StatusCode)
	}

	return resp.Body, nil
}

func ParseLogs(logger *clog.Logger, logData string, runID int64, findIOC *ioc.IOC) ([]Finding, bool) {
	if findIOC == nil {
		logger.Errorf("provided IOC is nil, unable to scan logs")
		return nil, false
	}

	scanner := bufio.NewScanner(strings.NewReader(logData))
	regex := findIOC.GetRegex()
	timestamp := regexp.MustCompile(timestampRegex)

	lineMap := make(map[string]struct{})
	encodedMap := make(map[string]struct{})
	decodedMap := make(map[string]struct{})

	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		lineMap = findMatch(line, findIOC, timestamp, lineMap, logger, runID)

		if regex == nil {
			continue
		}

		encodedMap, decodedMap = processMatch(line, regex, lineNum, encodedMap, decodedMap, logger, runID)
	}

	lineData := slices.Collect(maps.Keys(lineMap))
	encodedData := slices.Collect(maps.Keys(encodedMap))
	decodedData := slices.Collect(maps.Keys(decodedMap))

	finding := Finding{
		Encoded:  strings.Join(encodedData, ","),
		Decoded:  strings.Join(decodedData, ","),
		LineData: strings.Join(lineData, ","),
	}

	findings := []Finding{finding}
	foundIssues := len(findings) > 0
	return findings, foundIssues
}

func findMatch(line string, findIOC *ioc.IOC, timestamp *regexp.Regexp, lineMap map[string]struct{}, logger *clog.Logger, runID int64) map[string]struct{} {
	for _, content := range findIOC.GetContent() {
		if !strings.Contains(line, content) {
			continue
		}

		clean := timestamp.ReplaceAllString(line, "")
		lineMap[clean] = struct{}{}
		logger.Warnf("IOC log entry found in Run ID: %d", runID)
	}

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

func getUILogs(ctx context.Context, owner, repo string, runID int64) (map[int64]io.ReadCloser, error) {
	doc, err := fetchRunPage(ctx, owner, repo, runID)
	if err != nil {
		return nil, err
	}

	jobIDs := getJobIDs(doc, runID)
	if len(jobIDs) == 0 {
		return nil, fmt.Errorf("no job IDs found in run page")
	}

	return fetchJobLogs(ctx, owner, repo, runID, jobIDs)
}

func fetchRunPage(ctx context.Context, owner, repo string, runID int64) (*goquery.Document, error) {
	runURL := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d", owner, repo, runID)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, runURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating run page request: %w", err)
	}

	req.Header.Set("User-Agent", header)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching run page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve run page, status code: %d", resp.StatusCode)
	}

	return goquery.NewDocumentFromReader(resp.Body)
}

func getJobIDs(doc *goquery.Document, runID int64) map[int64]string {
	jobIDs := make(map[int64]string)

	getJobByLink(doc, runID, jobIDs)

	if len(jobIDs) == 0 {
		getJobByAttr(doc, jobIDs)
	}

	return jobIDs
}

func getJobByLink(doc *goquery.Document, runID int64, jobIDs map[int64]string) {
	patterns := []string{
		fmt.Sprintf("/actions/runs/%d/job/", runID),
		fmt.Sprintf("/actions/runs/%d/jobs/", runID),
		"/job/",
		"/jobs/",
	}

	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		for _, pattern := range patterns {
			if !strings.Contains(href, pattern) {
				continue
			}

			parts := strings.Split(href, pattern)
			if len(parts) < 2 {
				continue
			}

			jobIDStr := strings.Split(parts[1], "/")[0]
			jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
			if err != nil || jobID <= 0 {
				continue
			}

			jobName := getJobName(s, jobID)
			jobIDs[jobID] = jobName
		}
	})
}

func getJobByAttr(doc *goquery.Document, jobIDs map[int64]string) {
	doc.Find("div[data-job-id], div[data-job], div.job").Each(func(_ int, s *goquery.Selection) {
		jobIDStr := getJobByElement(s)

		if jobIDStr == "" {
			jobIDStr = getJobByNestedElement(s)
		}

		if jobIDStr == "" {
			return
		}

		jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
		if err != nil || jobID <= 0 {
			return
		}

		jobName := s.Find("h3, h4, .job-name").First().Text()
		jobName = strings.TrimSpace(jobName)
		if jobName == "" {
			jobName = fmt.Sprintf("Job-%d", jobID)
		}

		jobIDs[jobID] = jobName
	})
}

func getJobByElement(s *goquery.Selection) string {
	if jobIDStr, exists := s.Attr("data-job-id"); exists {
		return jobIDStr
	}
	if jobIDStr, exists := s.Attr("data-job"); exists {
		return jobIDStr
	}
	return ""
}

func getJobByNestedElement(s *goquery.Selection) string {
	var jobIDStr string

	s.Find("[data-job-id], [data-job]").Each(func(_ int, nested *goquery.Selection) {
		if jobIDStr != "" {
			return
		}

		if idStr, hasAttr := nested.Attr("data-job-id"); hasAttr {
			jobIDStr = idStr
		} else if idStr, hasAttr := nested.Attr("data-job"); hasAttr {
			jobIDStr = idStr
		}
	})

	return jobIDStr
}

func getJobName(s *goquery.Selection, jobID int64) string {
	jobName := strings.TrimSpace(s.Text())

	if jobName == "" {
		jobName = strings.TrimSpace(s.ParentsFiltered("div.job").Find("h3").Text())
	}

	if jobName == "" {
		jobName = fmt.Sprintf("Job-%d", jobID)
	}

	return jobName
}

func fetchJobLogs(ctx context.Context, owner, repo string, runID int64, jobIDs map[int64]string) (map[int64]io.ReadCloser, error) {
	results := make(map[int64]io.ReadCloser)
	var fetchErrors []string
	client := &http.Client{Timeout: 30 * time.Second}

	for jobID, jobName := range jobIDs {
		log, err := scanUI(ctx, client, owner, repo, runID, jobID)
		if err != nil {
			fetchErrors = append(fetchErrors, fmt.Sprintf("job %s (ID: %d): %v", jobName, jobID, err))
			continue
		}
		results[jobID] = log
	}

	if len(results) == 0 && len(fetchErrors) > 0 {
		return nil, fmt.Errorf("failed to fetch any job logs: %s", strings.Join(fetchErrors, "; "))
	}

	if len(fetchErrors) > 0 {
		fmt.Printf("Warning: failed to fetch some job logs: %s\n", strings.Join(fetchErrors, "; "))
	}

	return results, nil
}

func scanUI(ctx context.Context, client *http.Client, owner, repo string, runID, jobID int64) (io.ReadCloser, error) {
	doc, err := fetchJobPage(ctx, client, owner, repo, runID, jobID)
	if err != nil {
		return nil, err
	}

	logs, found := getLogsBySelector(doc)
	if !found {
		logs, found = getLogsByTag(doc)
	}

	if !found {
		logs, err := getLogData(ctx, client, doc)
		if err == nil {
			return logs, nil
		}
	}

	if logs == "" {
		return nil, fmt.Errorf("no logs found for job ID %d", jobID)
	}

	return io.NopCloser(strings.NewReader(logs)), nil
}

func fetchJobPage(ctx context.Context, client *http.Client, owner, repo string, runID, jobID int64) (*goquery.Document, error) {
	jobURL := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d/job/%d", owner, repo, runID, jobID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jobURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating job page request: %w", err)
	}

	req.Header.Set("User-Agent", header)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching job page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve job page, status code: %d", resp.StatusCode)
	}

	return goquery.NewDocumentFromReader(resp.Body)
}

func getLogsBySelector(doc *goquery.Document) (string, bool) {
	var logsBuilder strings.Builder
	found := false

	for _, selector := range selectors {
		selections := doc.Find(selector)
		if selections.Length() == 0 {
			continue
		}

		selections.Each(func(_ int, s *goquery.Selection) {
			logsBuilder.WriteString(s.Text())
			logsBuilder.WriteString("\n")
		})
		found = true
		break
	}

	return logsBuilder.String(), found
}

func getLogsByTag(doc *goquery.Document) (string, bool) {
	var logsBuilder strings.Builder
	found := false

	doc.Find("pre").Each(func(_ int, s *goquery.Selection) {
		text := s.Text()
		if len(text) <= 100 && !strings.Contains(text, "Starting job") {
			return
		}

		logsBuilder.WriteString(text)
		logsBuilder.WriteString("\n")
		found = true
	})

	return logsBuilder.String(), found
}

func getLogData(ctx context.Context, client *http.Client, doc *goquery.Document) (io.ReadCloser, error) {
	rawLogURL := findLogURL(doc)
	if rawLogURL == "" {
		return nil, fmt.Errorf("raw log URL not found")
	}

	if !strings.HasPrefix(rawLogURL, "http") {
		rawLogURL = "https://github.com" + rawLogURL
	}

	return fetchLogs(ctx, client, rawLogURL)
}

func findLogURL(doc *goquery.Document) string {
	var rawLogURL string

	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		if rawLogURL != "" {
			return
		}

		href, exists := s.Attr("href")
		if !exists {
			return
		}

		text := s.Text()
		if strings.Contains(text, "Download log") ||
			strings.Contains(text, "Raw log") ||
			strings.Contains(href, "logs") ||
			strings.Contains(href, "raw") {
			rawLogURL = href
		}
	})

	return rawLogURL
}

func fetchLogs(ctx context.Context, client *http.Client, rawLogURL string) (io.ReadCloser, error) {
	rawReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawLogURL, nil)
	if err != nil {
		return nil, err
	}

	rawReq.Header.Set("User-Agent", header)
	rawResp, err := client.Do(rawReq)
	if err != nil {
		return nil, err
	}

	if rawResp.StatusCode != http.StatusOK {
		rawResp.Body.Close()
		return nil, fmt.Errorf("failed to retrieve raw logs, status code: %d", rawResp.StatusCode)
	}

	var buffer bytes.Buffer
	_, err = buffer.ReadFrom(rawResp.Body)
	rawResp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading raw logs: %w", err)
	}

	if buffer.Len() == 0 {
		return nil, fmt.Errorf("empty raw logs")
	}

	return io.NopCloser(bytes.NewReader(buffer.Bytes())), nil
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
		combinedBuilder.WriteString(fmt.Sprintf("===== JOB ID: %d =====\n", jobID))

		logContent, err := io.ReadAll(logs)
		if err != nil {
			return nil, fmt.Errorf("reading logs for job %d: %w", jobID, err)
		}
		err = logs.Close()
		if err != nil {
			return nil, err
		}

		combinedBuilder.Write(logContent)
		combinedBuilder.WriteString("\n\n")
	}

	return io.NopCloser(strings.NewReader(combinedBuilder.String())), nil
}

func tryBase64Decode(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}

	if !utf8.Valid(decoded) {
		return "", fmt.Errorf("decoded content is not valid UTF8")
	}

	return string(decoded), nil
}
