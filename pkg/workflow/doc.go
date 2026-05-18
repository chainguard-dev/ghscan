// Package workflow implements the GitHub-side workflow, run, and log
// retrieval primitives ghscan uses to feed the IOC matcher.
//
// Public surface:
//
//   - [SearchWorkflowFiles] paginates the search API for workflow
//     YAML files in a target repository.
//   - [GetWorkflowByPath] / [ListWorkflowRuns] resolve a workflow and
//     enumerate its runs in chunked time windows so very long lookback
//     ranges do not exceed per-page caps.
//   - [GetLogs] fetches the run-level log archive, falling back to the
//     per-job logs API when the run-level endpoint returns 404 or 410.
//   - [ExtractLogs] decodes the zip archive returned by the logs API
//     into a single concatenated string.
//   - [ParseLogs] runs the IOC matcher over the extracted log text
//     and emits one [Finding] per run with deduplicated line, encoded,
//     and decoded blocks.
//
// Invariants:
//
//   - Concurrent per-job fetches are bounded by perJobFanOutLimit so
//     the package never violates the upstream 100-request secondary
//     concurrency limit.
//   - The bloom-prefiltered matcher reports every real substring
//     match of any configured IOC; false negatives are impossible.
//   - Cancelled runs with no jobs short-circuit early and never error.
package workflow
