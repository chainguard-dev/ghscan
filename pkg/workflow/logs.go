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
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PuerkitoBio/goquery"
	"github.com/chainguard-dev/clog"
)

const (
	cancelled         string = "cancelled"
	compromisedDigest string = "0e58ed8671d6b60d0890c21b07f8835ace038e67"
)

type Base64Finding struct {
	Encoded string
	Decoded string
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

func ParseLogs(logger *clog.Logger, logData string, runID int64, checkEmptyLines bool) ([]Base64Finding, string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(logData))

	regex := regexp.MustCompile(`(?:^|\s+)([A-Za-z0-9+/]{40,}={0,3})`)

	timestampRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+`)

	lineNum := 0
	var base64Findings []Base64Finding

	foundChangedFilesHeader := false
	emptyLinesSeen := []int{}
	emptyLinesFound := false
	var emptyLinesInfo string

	hasCompromisedSHA := strings.Contains(logData, fmt.Sprintf("SHA:%s", compromisedDigest))
	if hasCompromisedSHA {
		logger.Warnf("Compromised SHA found in Run ID: %d", runID)
	}

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++
		contentLine := timestampRegex.ReplaceAllString(line, "")

		isLineEmpty := strings.TrimSpace(contentLine) == ""

		allMatches := regex.FindAllStringSubmatch(line, -1)
		if len(allMatches) > 0 {
			for _, ms := range allMatches {
				if len(ms) > 1 {
					m := ms[1]
					decoded, err := tryBase64Decode(m)
					if err == nil {
						finding := Base64Finding{
							Encoded: m,
							Decoded: decoded,
						}
						base64Findings = append(base64Findings, finding)
						logger.Warnf("Found valid base64 content at log line %d in Run ID: %d", lineNum, runID)
					}
				}
			}
		}

		//nolint:nestif //ignore complexity of 17
		if checkEmptyLines {
			if !foundChangedFilesHeader && strings.Contains(contentLine, "##[group]changed-files") {
				foundChangedFilesHeader = true
				emptyLinesSeen = []int{}
				logger.Debugf("Found changed-files header at log line %d in Run ID: %d", lineNum, runID)
			} else if foundChangedFilesHeader {
				if isLineEmpty {
					emptyLinesSeen = append(emptyLinesSeen, lineNum)

					if len(emptyLinesSeen) >= 2 {
						if emptyLinesSeen[len(emptyLinesSeen)-1] == emptyLinesSeen[len(emptyLinesSeen)-2]+1 {
							logger.Infof("Found consecutive empty lines at log line %d and %d in Run ID: %d!",
								emptyLinesSeen[len(emptyLinesSeen)-2],
								emptyLinesSeen[len(emptyLinesSeen)-1],
								runID)
							emptyLinesFound = true
							for l := range emptyLinesSeen {
								if emptyLinesSeen[l+1] == emptyLinesSeen[l]+1 {
									emptyLinesInfo = fmt.Sprintf("Log lines %d-%d after changed-files",
										emptyLinesSeen[l], emptyLinesSeen[l])
									break
								}
							}
						}
					}
				} else if strings.Contains(contentLine, "Using local .git directory") ||
					!strings.Contains(contentLine, "##[group]changed-files") {
					foundChangedFilesHeader = false
				}
			}
		}
	}

	foundIssues := len(base64Findings) > 0 || emptyLinesFound

	switch {
	case len(base64Findings) > 0:
		emptyLinesInfo = ""
		logger.Infof("Returning %d unique base64 findings in Run ID: %d", len(base64Findings), runID)
	case emptyLinesFound:
		logger.Infof("Returning empty lines result: %s in Run ID: %d", emptyLinesInfo, runID)
	default:
		logger.Infof("No issues found in Run ID: %d", runID)
	}

	return slices.Compact(base64Findings), emptyLinesInfo, foundIssues
}

func getUILogs(ctx context.Context, owner, repo string, runID int64) (map[int64]io.ReadCloser, error) {
	runURL := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d", owner, repo, runID)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, runURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating run page request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LogScraper/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching run page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve run page, status code: %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing run page HTML: %w", err)
	}

	jobIDs := make(map[int64]string)

	doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		patterns := []string{
			fmt.Sprintf("/actions/runs/%d/job/", runID),
			fmt.Sprintf("/actions/runs/%d/jobs/", runID),
			"/job/",
			"/jobs/",
		}

		//nolint:nestif //ignore complexity of 9
		for _, pattern := range patterns {
			if strings.Contains(href, pattern) {
				parts := strings.Split(href, pattern)
				if len(parts) >= 2 {
					jobIDStr := strings.Split(parts[1], "/")[0]
					jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
					if err == nil && jobID > 0 {
						jobName := s.Text()
						jobName = strings.TrimSpace(jobName)
						if jobName == "" {
							jobName = s.ParentsFiltered("div.job").Find("h3").Text()
							jobName = strings.TrimSpace(jobName)
						}
						if jobName == "" {
							jobName = fmt.Sprintf("Job-%d", jobID)
						}
						jobIDs[jobID] = jobName
					}
				}
			}
		}
	})

	//nolint:nestif //ignore complexity of 11
	if len(jobIDs) == 0 {
		doc.Find("div[data-job-id], div[data-job], div.job").Each(func(_ int, s *goquery.Selection) {
			jobIDStr, exists := s.Attr("data-job-id")
			if !exists {
				jobIDStr, exists = s.Attr("data-job")
			}
			if !exists {
				s.Find("[data-job-id], [data-job]").Each(func(_ int, nested *goquery.Selection) {
					if idStr, hasAttr := nested.Attr("data-job-id"); hasAttr {
						jobIDStr = idStr
					} else if idStr, hasAttr := nested.Attr("data-job"); hasAttr {
						jobIDStr = idStr
					}
				})
			}

			if jobIDStr != "" {
				jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
				if err == nil && jobID > 0 {
					jobName := s.Find("h3, h4, .job-name").First().Text()
					jobName = strings.TrimSpace(jobName)
					if jobName == "" {
						jobName = fmt.Sprintf("Job-%d", jobID)
					}
					jobIDs[jobID] = jobName
				}
			}
		})
	}

	if len(jobIDs) == 0 {
		return nil, fmt.Errorf("no job IDs found in run page")
	}

	results := make(map[int64]io.ReadCloser)
	var fetchErrors []string

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
	jobURL := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d/job/%d", owner, repo, runID, jobID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jobURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating job page request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LogScraper/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching job page: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve job page, status code: %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing job page HTML: %w", err)
	}

	var logsBuilder strings.Builder
	found := false

	selectors := []string{
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

	for _, selector := range selectors {
		selections := doc.Find(selector)
		if selections.Length() > 0 {
			selections.Each(func(_ int, s *goquery.Selection) {
				logsBuilder.WriteString(s.Text())
				logsBuilder.WriteString("\n")
			})
			found = true
			break
		}
	}

	if !found {
		doc.Find("pre").Each(func(_ int, s *goquery.Selection) {
			if len(s.Text()) > 100 || strings.Contains(s.Text(), "Starting job") {
				logsBuilder.WriteString(s.Text())
				logsBuilder.WriteString("\n")
				found = true
			}
		})
	}

	//nolint:nestif //ignore complexity of 13
	if !found {
		rawLogURL := ""
		doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
			href, exists := s.Attr("href")
			text := s.Text()
			if exists && (strings.Contains(text, "Download log") || strings.Contains(text, "Raw log") ||
				strings.Contains(href, "logs") || strings.Contains(href, "raw")) {
				rawLogURL = href
				if !strings.HasPrefix(rawLogURL, "http") {
					rawLogURL = "https://github.com" + rawLogURL
				}
			}
		})

		if rawLogURL != "" {
			rawReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawLogURL, nil)
			if err == nil {
				rawReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LogScraper/1.0)")
				rawResp, err := client.Do(rawReq)
				if err == nil && rawResp.StatusCode == http.StatusOK {
					defer rawResp.Body.Close()
					rawLogs, err := io.ReadAll(rawResp.Body)
					if err == nil && len(rawLogs) > 0 {
						return io.NopCloser(bytes.NewReader(rawLogs)), nil
					}
				}
			}
		}
	}

	logsText := logsBuilder.String()
	if logsText == "" {
		return nil, fmt.Errorf("no logs found for job ID %d", jobID)
	}

	return io.NopCloser(strings.NewReader(logsText)), nil
}

func combineLogs(logsMap map[int64]io.ReadCloser) (io.ReadCloser, error) {
	var combinedBuilder strings.Builder

	jobIDs := make([]int64, 0, len(logsMap))
	for jobID := range logsMap {
		jobIDs = append(jobIDs, jobID)
	}
	sort.Slice(jobIDs, func(i, j int) bool { return jobIDs[i] < jobIDs[j] })

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
	doubleDecoded, err := base64.StdEncoding.DecodeString(string(decoded))
	if err != nil {
		return "", err
	}
	return string(doubleDecoded), nil
}
