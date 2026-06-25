package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/action"
	"github.com/chainguard-dev/ghscan/internal/file"
	ghscan "github.com/chainguard-dev/ghscan/pkg/ghscan"
	httpclient "github.com/chainguard-dev/ghscan/pkg/httpclient"
	"github.com/chainguard-dev/ghscan/pkg/ioc"
	"github.com/google/go-github/v86/github"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

var logger *clog.Logger

// Exit codes are part of the binary's public contract:
//
//	0 — clean run (zero IOC matches)
//	2 — at least one IOC match
//	3 — scan pipeline failure (network, auth, IO, etc.)
const (
	exitClean      = 0
	exitFindings   = 2
	exitScanFailed = 3
)

// resolveGitHubToken returns the viper-resolved token when non-empty,
// otherwise falls back to invoking `gh auth token`. The fallback lets
// users avoid exporting GITHUB_TOKEN when the gh CLI is already
// authenticated. Errors never include the token value.
func resolveGitHubToken(ctx context.Context, v *viper.Viper) (string, error) {
	if t := strings.TrimSpace(v.GetString("token")); t != "" {
		return t, nil
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "gh", "auth", "token")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("GITHUB_TOKEN not set and 'gh auth token' failed: %w", err)
	}
	tok := strings.TrimRight(stdout.String(), " \t\r\n")
	if tok == "" {
		return "", fmt.Errorf("GITHUB_TOKEN not set and 'gh auth token' returned empty output")
	}
	return tok, nil
}

// setDefaults seeds the supplied viper instance with every key main()
// reads. Keeping the list in one helper makes the binary safe to run
// with no config.yaml present and lets tests assert the defaults
// without driving the full flag pipeline. The duration values are
// stored as strings so a future config.yaml can override them with the
// natural "1h"/"45s" syntax that time.ParseDuration accepts. The
// concrete numbers (global_timeout=3h, operation_timeout=30s,
// max_retries=3, max_concurrency=32) are chosen so a fresh checkout
// scans without exhausting the GitHub rate limit while leaving headroom
// under the 100-request secondary concurrency budget; none of these
// values are zero or negative, which would disable the corresponding
// safeguard.
func setDefaults(v *viper.Viper) {
	v.SetDefault("token", os.Getenv("GITHUB_TOKEN"))
	v.SetDefault("clean_cache", false)
	v.SetDefault("ioc.name", "tj-actions/changed-files")
	v.SetDefault("ioc_file", "")
	v.SetDefault("global_timeout", "3h")
	v.SetDefault("operation_timeout", "30s")
	v.SetDefault("max_retries", 3)
	v.SetDefault("max_concurrency", 32)
	// Per-operation budgets derived from the legacy literal multipliers
	// (req.Timeout*2, req.Timeout*1, operation_timeout*5) so the
	// resulting wall-clock budgets are unchanged for callers that do
	// not override them.
	v.SetDefault("workflow_fetch_budget", "60s")
	v.SetDefault("run_scan_budget", "30s")
	v.SetDefault("repo_enum_budget", "150s")
	// YAML and log scanning are complementary: YAML catches known-bad
	// uses: refs before a step runs (preventing secret exfiltration),
	// logs catch behavioral IOCs that surface only after execution.
	// Both default on so existing users observe no behavior change.
	v.SetDefault("scan_yaml", true)
	v.SetDefault("scan_logs", true)
}

// resolveExitCode maps the outcome of a scan to the binary's exit-code
// contract. Pure function so it is trivially testable; the io paths
// in main() route through it.
func resolveExitCode(scanErr, writeErr error, findings int) int {
	if scanErr != nil || writeErr != nil {
		return exitScanFailed
	}
	if findings > 0 {
		return exitFindings
	}
	return exitClean
}

func main() {
	logger = clog.New(slog.Default().Handler())

	// Use an explicit viper instance instead of the package singleton.
	// This keeps the binary's config state self-contained and lets
	// tests construct their own *viper.Viper without leaking globals.
	// internal/action still reads max_retries / max_concurrency / per-op
	// budgets off the global viper instance, so we mirror those keys
	// from v below.
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		logger.Info("No config file found; using defaults and flags")
	}

	targetFlag := flag.String("target", v.GetString("target"), "Organization name or owner/repository (e.g. octocat/Hello-World)")
	tokenFlag := flag.String("token", v.GetString("token"), "GitHub Personal Access Token")
	cacheFileFlag := flag.String("cache", v.GetString("cache_file"), "Path to JSON cache file")
	cleanCacheFlag := flag.Bool("clean-cache", v.GetBool("clean_cache"), "Reset the findings cache")
	jsonOutputFlag := flag.String("json", v.GetString("json_output"), "Path to final JSON output file")
	csvOutputFlag := flag.String("csv", v.GetString("csv_output"), "Path to final CSV output file")
	startTimeFlag := flag.String("start", v.GetString("start_time"), "Start time for workflow run filtering (RFC3339)")
	endTimeFlag := flag.String("end", v.GetString("end_time"), "End time for workflow run filtering (RFC3339)")
	iocNameFlag := flag.String("ioc-name", v.GetString("ioc.name"), "IOC Logs to scan for (e.g. tj-actions/changed-files")
	iocContentFlag := flag.String("ioc-content", v.GetString("ioc.content"), "Comma-separated string(s) to search for in logs")
	iocPatternFlag := flag.String("ioc-pattern", v.GetString("ioc.pattern"), "Regex pattern to search logs with")
	iocFileFlag := flag.String("ioc-file", v.GetString("ioc_file"), "Path to a JSON corpus file overriding the embedded IOC list")
	scanYAMLFlag := flag.Bool("scan-yaml", v.GetBool("scan_yaml"), "Scan workflow YAML for known-bad uses: refs before execution")
	scanLogsFlag := flag.Bool("scan-logs", v.GetBool("scan_logs"), "Scan workflow run logs for behavioral IOCs after execution")
	flag.Parse()

	if !*scanYAMLFlag && !*scanLogsFlag {
		logger.Fatal("At least one of -scan-yaml or -scan-logs must be enabled")
	}

	if *targetFlag == "" {
		logger.Fatal("Target must be provided")
	}

	globalTimeoutStr := v.GetString("global_timeout")
	globalTimeout, err := time.ParseDuration(globalTimeoutStr)
	if err != nil {
		logger.Fatalf("Invalid global timeout: %v", err)
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(rootCtx, globalTimeout)
	defer cancel()
	ctx = clog.WithLogger(ctx, logger)

	v.Set("token", *tokenFlag)
	token, err := resolveGitHubToken(ctx, v)
	if err != nil {
		logger.Fatal("GITHUB_TOKEN not set, -token not provided, and 'gh auth token' fallback failed")
	}
	*tokenFlag = token

	// Mirror the keys consumed by package-level viper readers (e.g.
	// internal/action.Scan) into the global instance so those call sites see
	// the resolved values. This is the single point in the binary that
	// touches the global instance.
	gv := viper.GetViper()
	gv.Set("max_retries", v.GetInt("max_retries"))
	gv.Set("max_concurrency", v.GetInt("max_concurrency"))
	gv.Set("operation_timeout", v.GetString("operation_timeout"))
	gv.Set("workflow_fetch_budget", v.GetString("workflow_fetch_budget"))
	gv.Set("run_scan_budget", v.GetString("run_scan_budget"))
	gv.Set("repo_enum_budget", v.GetString("repo_enum_budget"))
	gv.Set("scan_yaml", *scanYAMLFlag)
	gv.Set("scan_logs", *scanLogsFlag)

	contentParts := make([]string, 0)
	if *iocContentFlag != "" {
		for part := range strings.SplitSeq(*iocContentFlag, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				contentParts = append(contentParts, trimmed)
			}
		}

		if len(contentParts) == 0 {
			logger.Warn("ioc-content flag was provided but no valid content was parsed")
		}
	}

	var corpus *ioc.Corpus
	if strings.TrimSpace(*iocFileFlag) != "" {
		c, lerr := ioc.LoadCorpusFile(*iocFileFlag)
		if lerr != nil {
			logger.Fatalf("Failed to load IOC corpus: %v", lerr)
		}
		corpus = c
	}

	ic := &ioc.Config{
		Name:    *iocNameFlag,
		Content: contentParts,
		Pattern: *iocPatternFlag,
		Corpus:  corpus,
	}

	findIOC, err := ioc.NewIOC(ic)
	if err != nil {
		logger.Fatalf("Failed to initialize IOC: %v", err)
	}

	logger.With(*targetFlag)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *tokenFlag})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Single shared HTTP client. Singleflight + ETag caching only
	// dedupe correctly when the same instance is reused across all
	// callers, so we construct exactly one and plumb it through
	// ghscan.Request.
	hc := httpclient.New()

	var repos []*github.Repository
	switch {
	case strings.Contains(*targetFlag, "/"):
		parts := strings.Split(*targetFlag, "/")
		if len(parts) != 2 {
			logger.Fatalf("Invalid repository format. Expected owner/repository, got: %s", *targetFlag)
		}
		owner, repoName := parts[0], parts[1]
		repo, _, err := client.Repositories.Get(ctx, owner, repoName)
		if err != nil {
			logger.Fatalf("Error retrieving repository: %v", err)
		}
		repos = append(repos, repo)
	default:
		org := *targetFlag
		opt := &github.RepositoryListByOrgOptions{
			ListOptions: github.ListOptions{PerPage: 100},
		}
		for {
			orgRepos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
			if err != nil {
				logger.Fatalf("Error listing repos for org %s: %v", org, err)
			}
			repos = append(repos, orgRepos...)
			if resp.NextPage == 0 {
				break
			}
			opt.Page = resp.NextPage
		}
	}

	logger.Infof("Found %d repositories to scan", len(repos))

	startTime, err := time.Parse(time.RFC3339, *startTimeFlag)
	if err != nil {
		logger.Fatalf("Error parsing start time: %v", err)
	}
	endTime, err := time.Parse(time.RFC3339, *endTimeFlag)
	if err != nil {
		logger.Fatalf("Error parsing end time: %v", err)
	}

	cache := file.LoadCache(ctx, logger, *cacheFileFlag, *cleanCacheFlag)
	cachedResults := make(map[string]bool)
	for _, result := range cache.Results {
		key := fmt.Sprintf("%s|%s", result.Repository, result.WorkflowFileName)
		cachedResults[key] = true
	}

	req := ghscan.NewRequest(ghscan.RequestConfig{
		Cache:         cache,
		CacheFile:     *cacheFileFlag,
		CachedResults: cachedResults,
		Client:        client,
		HTTPClient:    hc,
		Corpus:        corpus,
		EndTime:       endTime,
		IOC:           findIOC,
		StartTime:     startTime,
		Token:         *tokenFlag,
	})

	scanErr := action.Scan(ctx, logger, req, repos)
	if scanErr != nil {
		logger.Errorf("Failed to scan Workflows in repos: %v", scanErr)
	}

	cr := ghscan.Cache{Results: req.Cache.Results}
	writeErr := file.WriteResults(ctx, logger, cr, *cacheFileFlag, *jsonOutputFlag, *csvOutputFlag)
	if writeErr != nil {
		logger.Errorf("Failed to write outputs: %v", writeErr)
	}
	logger.Info("Processing complete")

	exitCode := resolveExitCode(scanErr, writeErr, len(req.Cache.Results))
	if exitCode != exitClean {
		// Release deferred cancel + signal handlers before os.Exit
		// short-circuits the runtime; otherwise the timer goroutine
		// outlives main.
		cancel()
		stop()
		os.Exit(exitCode) //nolint:gocritic // cancel + stop are invoked above.
	}
}
