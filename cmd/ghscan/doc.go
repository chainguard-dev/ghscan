// Command ghscan scans GitHub Actions workflow run logs for indicators
// of compromise.
//
// Usage:
//
//	ghscan -target owner/repo -token $GITHUB_TOKEN \
//	  -start 2025-01-01T00:00:00Z -end 2025-01-08T00:00:00Z \
//	  [-cache results/cache.json] [-json out.json] [-csv out.csv] \
//	  [-ioc-name tj-actions/changed-files] \
//	  [-ioc-content "literal,strings"] [-ioc-pattern "regex"]
//
// The target may be either an `owner/repository` pair (single repo) or
// an organization name (every repository owned by the org is enumerated
// and scanned). A GitHub personal access token must be supplied via
// `-token` or the `GITHUB_TOKEN` environment variable.
//
// Configuration not exposed as flags is read from `config.yaml` in the
// current directory via viper. The cache, JSON, and CSV outputs are
// written once the scan completes.
//
// SIGINT and SIGTERM cancel the scan; in-flight HTTP and errgroup work
// observes the cancellation and unwinds.
package main
