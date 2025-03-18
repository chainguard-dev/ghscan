# tj-scan
Scan GitHub Workflow logs for IOCs from the tj-actions/changed-files breach.

This script will scan an organization's Workflow run logs for IOCs (double base64-encoded strings) and will attempt to decode them.

This script was adapated from a mess of Python code that was built to scan the entirety of GitHub so there may be quirks or bugs.

Since Workflows may no longer use the Action, this script just lists all Workflows and searches the logs during the period of time when the Action was compromised.

## Requirements

Create a fine-grained GitHub PAT that has the following scopes:
- `actions:read`
- `contents:read`

## Usage

```
-cache string
      Path to JSON cache file (default "cache.json")
-csv string
      Path to final CSV output file (default "final.csv")
-end string
      End time for workflow run filtering (RFC3339) (default "2025-03-16T00:00:00Z")
-json string
      Path to final JSON output file (default "final.json")
-start string
      Start time for workflow run filtering (RFC3339) (default "2025-03-14T00:00:00Z")
-target string
      Organization name or owner/repository (e.g. octocat/Hello-World)
-token string
      GitHub Personal Access Token
```

For example:
`go run cmd/tj-scan/main.go -token <GitHub PAT> -target [org|owner/repo] -csv="final.csv" -json="final.json"`

-or-

`make out/tjscan`

then

`./out/tjscan -token <GitHub PAT> -target [org|owner/repo] -csv="final.csv" -json="final.json"`


Results will be saved in the `results/` directory.
