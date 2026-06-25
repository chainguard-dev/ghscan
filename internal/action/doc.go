// Package action orchestrates the per-repository, per-workflow, and
// per-run scanning fan-out that ghscan performs against the GitHub
// REST API.
//
// Public surface:
//
//   - [Scan] is the top-level entry point. It walks every supplied
//     repository, lists workflow files, lists workflow runs in the
//     caller's time window, and dispatches log scanning across a
//     bounded errgroup. Each repository runs against a shallow per-repo
//     clone of the request so result slices never alias across
//     goroutines; the per-repo result slice is merged back into the
//     caller's cache under a mutex once the repository finishes.
//
// Persistence:
//
//   - The caller is responsible for writing the final cache once Scan
//     returns (see pkg/file.WriteResults). Scan does not perform any
//     intermediate flushes.
//
// Invariants:
//
//   - Concurrency at every fan-out site is bounded by fanOutLimit (32),
//     which sits well below GitHub's documented 100-request secondary
//     rate-limit ceiling.
//   - The shared *ghscan.Request must not be mutated by per-repo
//     workers; each goroutine takes a shallow per-repo clone with a
//     fresh ghscan.Cache.
package action
