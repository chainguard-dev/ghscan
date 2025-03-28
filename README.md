# ghscan
Scan GitHub Workflow logs for IOCs via strings or regex.

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

The policy file will look something like this:
```yaml
issuer: https://issuer.enforce.dev
# Use ONE of subject or subject_pattern
subject: <ID from above>
subject_pattern: (<ID from above>)
claim_pattern:
  email: ".*@domain.com"

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
-ioc-content string
      Comma-separated string(s) to search for in logs
-ioc-name string
      IOC Logs to scan for (e.g. tj-actions/changed-files (default "tj-actions/changed-files")
-ioc-pattern string
      Regex pattern to search logs with
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
$ chainctl auth octo-sts --scope chainguard-dev/ghscan --identity ephemerality -- go run cmd/ghscan/main.go -target owner/repo -json="final.json" -csv="final.csv"
2025/03/18 11:27:59 INFO Found 1 repositories to scan
2025/03/18 11:27:59 INFO No existing cache found at cache.json, starting fresh
```

Custom IOC configuration can be provided with the flags documented above or added to `config.yaml`:
```yaml
ioc:
  name: "custom-ioc-name"
  content: "0e58ed8671d6b60d0890c21b07f8835ace038e67,example-string,example-string2"
  pattern: "(?:^|\\s+)([A-Za-z0-9+/]{40,}={0,3})"
```

`name` is a reference to the IOC
`content` is the string or strings to search for in the Workflow logs
`pattern` is an optional regex pattern to search for in the Workflow logs

Results will be saved in the `results/` directory.
