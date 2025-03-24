package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/tj-scan/pkg/action"
	"github.com/chainguard-dev/tj-scan/pkg/file"
	"github.com/chainguard-dev/tj-scan/pkg/ioc"
	tjscan "github.com/chainguard-dev/tj-scan/pkg/tj-scan"
	"github.com/google/go-github/v69/github"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

var logger *clog.Logger

func main() {
	logger = clog.New(slog.Default().Handler())
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetDefault("token", os.Getenv("GITHUB_TOKEN"))
	viper.SetDefault("clean_cache", false)
	viper.SetDefault("ioc.name", "tj-actions/changed-files")

	if err := viper.ReadInConfig(); err != nil {
		logger.Info("No config file found; using defaults and flags")
	}

	targetFlag := flag.String("target", viper.GetString("target"), "Organization name or owner/repository (e.g. octocat/Hello-World)")
	tokenFlag := flag.String("token", viper.GetString("token"), "GitHub Personal Access Token")
	cacheFileFlag := flag.String("cache", viper.GetString("cache_file"), "Path to JSON cache file")
	cleanCacheFlag := flag.Bool("clean-cache", viper.GetBool("clean_cache"), "Reset the findings cache")
	jsonOutputFlag := flag.String("json", viper.GetString("json_output"), "Path to final JSON output file")
	csvOutputFlag := flag.String("csv", viper.GetString("csv_output"), "Path to final CSV output file")
	startTimeFlag := flag.String("start", viper.GetString("start_time"), "Start time for workflow run filtering (RFC3339)")
	endTimeFlag := flag.String("end", viper.GetString("end_time"), "End time for workflow run filtering (RFC3339)")
	iocNameFlag := flag.String("ioc-name", viper.GetString("ioc.name"), "IOC Logs to scan for (e.g. tj-actions/changed-files")
	iocDigestFlag := flag.String("ioc-digest", viper.GetString("ioc.digest"), "Malicious digest to search for in logs")
	iocPatternFlag := flag.String("ioc-pattern", viper.GetString("ioc.pattern"), "Regex pattern to search logs with")
	flag.Parse()

	if *targetFlag == "" {
		logger.Fatal("Target must be provided")
	}
	if *tokenFlag == "" {
		logger.Fatal("GITHUB_TOKEN or -token must be provided")
	}

	ic := &ioc.Config{
		Name:    *iocNameFlag,
		Digest:  *iocDigestFlag,
		Pattern: *iocPatternFlag,
	}

	findIOC, err := ioc.NewIOC(ic)
	if err != nil {
		logger.Fatalf("Failed to initialize IOC: %v", err)
	}

	globalTimeoutStr := viper.GetString("global_timeout")
	globalTimeout, err := time.ParseDuration(globalTimeoutStr)
	if err != nil {
		logger.Fatalf("Invalid global timeout: %v", err)
	}

	logger.With(*targetFlag)

	var cancel context.CancelFunc
	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()
	ctx = clog.WithLogger(ctx, logger)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *tokenFlag})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

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

	cache := file.LoadCache(logger, *cacheFileFlag, *cleanCacheFlag)
	cachedResults := make(map[string]bool)
	for _, result := range cache.Results {
		key := fmt.Sprintf("%s|%s", result.Repository, result.WorkflowFileName)
		cachedResults[key] = true
	}

	req := tjscan.Request{
		Cache:         cache,
		CacheFile:     *cacheFileFlag,
		CachedResults: cachedResults,
		Client:        client,
		EndTime:       endTime,
		IOC:           findIOC,
		StartTime:     startTime,
		Token:         *tokenFlag,
	}

	err = action.Scan(ctx, logger, &req, repos)
	if err != nil {
		logger.Errorf("Failed to scan Workflows in repos: %v", err)
	}

	cr := tjscan.Cache{Results: req.Cache.Results}
	file.WriteResults(logger, cr, *cacheFileFlag, *jsonOutputFlag, *csvOutputFlag)
	logger.Info("Processing complete")
}
