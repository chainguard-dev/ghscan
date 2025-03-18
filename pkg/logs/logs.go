package logs

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/tj-scan/pkg/util"
)

func ExtractLogsFromZip(rc io.Reader) (string, error) {
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
		f, err := file.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			continue
		}
		logsBuilder.Write(b)
		logsBuilder.WriteString("\n")
	}
	return logsBuilder.String(), nil
}

func DownloadRunLogs(ctx context.Context, logger *clog.Logger, owner, repo string, runID int64, token string) (io.ReadCloser, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/actions/runs/%d/logs", owner, repo, runID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		logger.Warnf("Logs API returned %d for run %d; falling back to UI scraping", resp.StatusCode, runID)
		resp.Body.Close()
		return ScrapeLogsFromUI(ctx, owner, repo, runID)
	}
	if resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		if loc == "" {
			resp.Body.Close()
			return nil, fmt.Errorf("redirect location empty")
		}
		resp.Body.Close()
		redirectReq, err := http.NewRequestWithContext(ctx, "GET", loc, nil)
		if err != nil {
			return nil, err
		}
		redirectResp, err := httpClient.Do(redirectReq)
		if err != nil {
			return nil, err
		}
		if redirectResp.StatusCode != http.StatusOK {
			redirectResp.Body.Close()
			return nil, fmt.Errorf("failed to download logs from redirect: status %d", redirectResp.StatusCode)
		}
		return redirectResp.Body, nil
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to download logs: status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func ScanLogData(logger *clog.Logger, logData string) (string, string, string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(logData))

	regex := regexp.MustCompile(`[A-Za-z0-9+/]{60,}={0,2}`)

	emptyLineCount := 0
	lineNum := 0

	foundMatch := false
	var matchedText, decodedText, lineInfo string

	// Store multiple matches if found
	var matches []struct {
		encoded    string
		decoded    string
		lineNumber int
	}

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if strings.TrimSpace(line) == "" {
			emptyLineCount++
			if emptyLineCount >= 2 {
				if !foundMatch {
					return "", "", fmt.Sprintf("Line %d", lineNum), true
				}
			}
		} else {
			emptyLineCount = 0
		}
		allMatches := regex.FindAllString(line, -1)
		for _, match := range allMatches {
			decoded, err := util.TryBase64Decode(match)
			if err == nil {
				matches = append(matches, struct {
					encoded    string
					decoded    string
					lineNumber int
				}{match, decoded, lineNum})

				if !foundMatch {
					matchedText = match
					decodedText = decoded
					lineInfo = fmt.Sprintf("Line %d", lineNum)
					foundMatch = true
				}
			}
		}
	}

	if len(matches) > 1 {
		logger.Infof("Found %d potential base64 encoded secrets", len(matches))
	}

	if foundMatch {
		return matchedText, decodedText, lineInfo, true
	}

	return "", "", "", false
}

func ScrapeLogsFromUI(ctx context.Context, owner, repo string, runID int64) (io.ReadCloser, error) {
	url := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d", owner, repo, runID)
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	var body io.Reader
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, body)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to retrieve UI page, status code: %d", resp.StatusCode)
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	var logsText string
	doc.Find("pre.logs").Each(func(_ int, s *goquery.Selection) {
		logsText += s.Text() + "\n"
	})
	resp.Body.Close()
	if logsText == "" {
		return nil, fmt.Errorf("no logs found via UI scraping")
	}
	return io.NopCloser(strings.NewReader(logsText)), nil
}
