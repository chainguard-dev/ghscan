# tj-scan
Scan GitHub Workflow logs for IOCs from the tj-actions/changed-files breach.

This script will scan either an organization's or a repository's Workflow run logs for IOCs (double base64-encoded strings) and will attempt to decode them.

This script was adapated from a mess of Python code that was built to scan the entirety of GitHub so there may be quirks or bugs.

Since Workflows may no longer use the Action, this script just lists all Workflows and searches the logs during the period of time when the Action was compromised.

## Requirements

- An `octo-sts` trust policy located in `.github/chainguard` that allows `actions:read` and `contents:read`
    - For more information, check out the `octo-sts` [docs](https://github.com/octo-sts/app?tab=readme-ov-file#the-trust-policy)
- [chainctl](https://edu.chainguard.dev/chainguard/administration/how-to-install-chainctl/) installed

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
`export GITHUB_TOKEN=$(chainctl auth octo-sts --identity ephemerality --scope chainguard-dev/tj-scan)`

`go run cmd/tj-scan/main.go -token ${GITHUB_TOKEN} -target [org|owner/repo] -csv="final.csv" -json="final.json"`

-or-

`make out/tjscan`

then

`./out/tjscan -token ${GITHUB_TOKEN} -target [org|owner/repo] -csv="final.csv" -json="final.json"`

Results will be saved in the `results/` directory.

Note: `GITHUB_TOKEN=...` can also be used instead of `-token`.
