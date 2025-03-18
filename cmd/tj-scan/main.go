package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/egibs/tj-scan/pkg/cache"
	"github.com/egibs/tj-scan/pkg/logs"
	"github.com/egibs/tj-scan/pkg/output"
	tjscan "github.com/egibs/tj-scan/pkg/tj-scan"
	"github.com/egibs/tj-scan/pkg/util"
	wf "github.com/egibs/tj-scan/pkg/workflow"
	"github.com/google/go-github/v69/github"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

const resultsDir string = "results"

var logger *clog.Logger

func main() {
	logger = clog.New(slog.Default().Handler())
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetDefault("token", os.Getenv("GITHUB_TOKEN"))

	if err := viper.ReadInConfig(); err != nil {
		logger.Info("No config file found; using defaults and flags")
	}

	targetFlag := flag.String("target", viper.GetString("target"), "Organization name or owner/repository (e.g. octocat/Hello-World)")
	tokenFlag := flag.String("token", viper.GetString("token"), "GitHub Personal Access Token")
	cacheFileFlag := flag.String("cache", viper.GetString("cache_file"), "Path to JSON cache file")
	jsonOutputFlag := flag.String("json", viper.GetString("json_output"), "Path to final JSON output file")
	csvOutputFlag := flag.String("csv", viper.GetString("csv_output"), "Path to final CSV output file")
	startTimeFlag := flag.String("start", viper.GetString("start_time"), "Start time for workflow run filtering (RFC3339)")
	endTimeFlag := flag.String("end", viper.GetString("end_time"), "End time for workflow run filtering (RFC3339)")
	flag.Parse()

	if *targetFlag == "" {
		logger.Fatal("Target must be provided")
	}
	if *tokenFlag == "" {
		logger.Fatal("GITHUB_TOKEN or -token must be provided")
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
	if strings.Contains(*targetFlag, "/") {
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
	} else {
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

	var resultsMu sync.Mutex
	var results []tjscan.Result

	existingCache := cache.LoadExistingCache(logger, *cacheFileFlag)
	existingResultsMap := make(map[string]bool)
	for _, result := range existingCache.Results {
		key := fmt.Sprintf("%s|%s", result.Repository, result.WorkflowFileName)
		existingResultsMap[key] = true
	}

	maxConcurrency := viper.GetInt("max_concurrency")
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, repo := range repos {
		wg.Add(1)
		sem <- struct{}{}
		go func(repo *github.Repository) {
			defer func() {
				<-sem
				wg.Done()
			}()

			owner := repo.GetOwner().GetLogin()
			repoName := repo.GetName()
			logger.Infof("Processing repository: %s/%s", owner, repoName)

			opTimeout := viper.GetDuration("operation_timeout")
			repoCtx, repoCancel := context.WithTimeout(ctx, opTimeout*5)
			defer repoCancel()

			query := fmt.Sprintf("repo:%s/%s path:.github/workflows language:YAML", owner, repoName)

			var workflowPaths []string
			err := util.WithRetry(repoCtx, logger, func() error {
				var err error
				workflowPaths, err = wf.SearchWorkflowFiles(repoCtx, client, query)
				return err
			})
			if err != nil {
				logger.Errorf("Error searching workflows in %s/%s: %v", owner, repoName, err)
				return
			}

			logger.Infof("Found %d workflow files in %s/%s", len(workflowPaths), owner, repoName)

			wfSem := make(chan struct{}, 2)
			var wfWg sync.WaitGroup

			for _, wfPath := range workflowPaths {
				wfSem <- struct{}{}
				wfWg.Add(1)

				go func(wfPath string) {
					defer func() {
						<-wfSem
						wfWg.Done()
					}()

					wfFileName := filepath.Base(wfPath)
					repoKey := fmt.Sprintf("%s/%s", owner, repoName)
					cacheKey := fmt.Sprintf("%s|%s", repoKey, wfFileName)

					if existingResultsMap[cacheKey] {
						logger.Infof("Skipping already processed workflow %s in %s", wfFileName, repoKey)
						return
					}

					wfCtx, wfCancel := context.WithTimeout(ctx, opTimeout*2)
					defer wfCancel()

					var workflow *github.Workflow
					err := util.WithRetry(wfCtx, logger, func() error {
						var err error
						workflow, err = wf.GetWorkflowByPath(wfCtx, client, owner, repoName, wfPath)
						return err
					})
					if err != nil {
						logger.Errorf("Error retrieving workflow for %s in %s/%s: %v", wfPath, owner, repoName, err)
						return
					}

					workflowID := workflow.GetID()

					var runs []*github.WorkflowRun
					err = util.WithRetry(wfCtx, logger, func() error {
						var err error
						runs, err = wf.ListWorkflowRuns(wfCtx, logger, client, owner, repoName, workflowID, startTime, endTime)
						return err
					})
					if err != nil {
						logger.Errorf("Error listing runs for workflow %d in %s/%s: %v", workflowID, owner, repoName, err)
						return
					}

					logger.Infof("Found %d runs for workflow %s in %s/%s", len(runs), wfFileName, owner, repoName)

					runChan := make(chan struct{}, 2)
					var runWg sync.WaitGroup

					for _, run := range runs {
						runChan <- struct{}{}
						runWg.Add(1)

						go func(run *github.WorkflowRun) {
							defer func() {
								<-runChan
								runWg.Done()
							}()

							runID := run.GetID()
							runCtx, runCancel := context.WithTimeout(ctx, opTimeout)
							defer runCancel()

							var rc io.ReadCloser
							err := util.WithRetry(runCtx, logger, func() error {
								var err error
								rc, err = logs.DownloadRunLogs(runCtx, logger, owner, repoName, runID, *tokenFlag)
								return err
							})
							if err != nil {
								logger.Errorf("Failed to download logs for run %d after retries: %v", runID, err)
								return
							}

							func() {
								defer rc.Close()
								logText, err := logs.ExtractLogsFromZip(rc)
								if err != nil {
									logger.Errorf("Error extracting logs for run %d: %v", runID, err)
									return
								}
								encoded, decoded, lineInfo, found := logs.ScanLogData(logger, logText)
								if !found || encoded == "" {
									return
								}

								workflowUIURL := fmt.Sprintf("https://github.com/%s/%s/actions/workflows/%s",
									owner, repoName, url.PathEscape(wfFileName))

								workflowRunUIURL := fmt.Sprintf("https://github.com/%s/%s/actions/runs/%d",
									owner, repoName, runID)

								res := tjscan.Result{
									Repository:       fmt.Sprintf("%s/%s", owner, repoName),
									WorkflowFileName: wfFileName,
									WorkflowURL:      workflowUIURL,
									WorkflowRunURL:   workflowRunUIURL,
									Base64Data:       encoded,
									DecodedData:      decoded,
									LineLinkOrNum:    lineInfo,
								}

								resultsMu.Lock()
								results = append(results, res)
								resultsMu.Unlock()

								if len(results)%10 == 0 {
									output.WriteIntermediateResults(logger, filepath.Join(resultsDir, *cacheFileFlag), results)
								}
							}()
						}(run)
					}
					runWg.Wait()
				}(wfPath)
			}
			wfWg.Wait()
		}(repo)
	}
	wg.Wait()

	results = append(existingCache.Results, results...)

	cr := tjscan.Cache{Results: results}
	output.WriteOutputs(logger, cr, *cacheFileFlag, *jsonOutputFlag, *csvOutputFlag)
	logger.Info("Processing complete.")
}
