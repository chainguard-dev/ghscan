// Package ghscan defines the core data shapes shared across the scan
// pipeline: the [Request] passed into [github.com/chainguard-dev/ghscan/internal/action.Scan],
// the [Result] emitted for every finding, and the [Cache] that buffers
// results for incremental persistence.
//
// Public surface:
//
//   - [Request] carries the GitHub clients, IOC matcher, time window,
//     and per-run cache state. It is constructed once in main and
//     shallow-cloned per repository inside the scanner.
//   - [Result] is the canonical finding shape. [Result.IsEmpty]
//     identifies records with no extracted log content so they can be
//     skipped during CSV emission.
//   - [Cache] is the on-disk JSON envelope wrapping a slice of Result.
//
// The package also exposes [ResultsDir] -- the directory under which
// cache, JSON, and CSV outputs are written.
package ghscan
