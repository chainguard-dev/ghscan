// Package file persists ghscan findings to disk and reads them back
// across runs.
//
// Public surface:
//
//   - [LoadCache] decodes the JSON findings cache. Cancelled contexts
//     and unreadable files yield an empty cache rather than an error so
//     callers can always proceed with a fresh scan.
//   - [WriteCache] is the streaming intermediate writer used by the
//     Scanner. It writes to a temp file and renames atomically; calls
//     are serialized via a package-level mutex so concurrent writers
//     against the same on-disk path never observe a torn file.
//   - [WriteResults] is the final-output writer that emits the cache,
//     a JSON output file, and a CSV output file in one pass.
//
// Invariants:
//
//   - Every write performs MkdirAll on the parent directory before
//     opening the file.
//   - WriteCache uses a tmp+rename pattern so readers either see the
//     previous full file or the new full file, never a partial write.
//   - All concurrent WriteCache calls targeting the same path are
//     serialized; this preserves the rename-atomicity invariant when
//     multiple per-repo goroutines race to flush intermediate results.
package file
