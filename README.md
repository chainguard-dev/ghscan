# tj-scan
Scan GitHub Workflow logs for IOCs from the tj-actions/changed-files breach.

Notes:
- This script should not be seen as a universal detector of compromise; rather, a single result likely indicates that other Workflow runs in the search window were also compromised
  - If the script detects base64 content in a Workflow's run logs as well as consecutive empty lines (no secrets leaked from the compromised action), then only the base64 data will be returned
- This script will scan either an organization's or a repository's Workflow run logs for IOCs (double base64-encoded strings) and will attempt to decode them
- This script was adapated from a mess of Python code that was built to scan the entirety of GitHub so there may be quirks or bugs
- Since Workflows may no longer use the Action, this script just lists all Workflows and searches the logs during the period of time when the Action was compromised
- This script is intended to be run using a short-lived GitHub Token from `octo-sts`

## Requirements

- [chainctl](https://edu.chainguard.dev/chainguard/administration/how-to-install-chainctl) installed to handle ephemeral authentication

## Example `octo-sts` trust policy

The ID required for the trust policy can be retrieved with:
```sh
$ chainctl auth status -o json | jq .identity | tr -d '"'
```

The policy can file will look something like this:
```yaml
issuer: https://issuer.enforce.dev
# Use ONE of subject or subject_pattern
subject: <ID from above>
subject_pattern: (<ID from above>)
claim_pattern:
  email: ".*@chainguard.dev"

permissions:
  actions: read
  contents: read
```

## Usage

```
-cache string
      Path to JSON cache file (default "cache.json")
-clean-cache
      Reset the findings cache
-csv string
      Path to final CSV output file
-end string
      End time for workflow run filtering (RFC3339) (default "2025-03-16T00:00:00Z")
-json string
      Path to final JSON output file
-start string
      Start time for workflow run filtering (RFC3339) (default "2025-03-14T00:00:00Z")
-target string
      Organization name or owner/repository (e.g. octocat/Hello-World)
-token string
      GitHub Personal Access Token
```

For example:
```sh
$ chainctl auth octo-sts --scope chainguard-dev/tj-scan --identity ephemerality -- go run cmd/tj-scan/main.go -target owner/repo -json="final.json" -csv="final.csv"
2025/03/18 11:27:59 INFO Found 1 repositories to scan
2025/03/18 11:27:59 INFO No existing cache found at cache.json, starting fresh
```

Results will be saved in the `results/` directory.
