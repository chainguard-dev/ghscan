package action_test

import (
	"log/slog"
	"testing"

	"github.com/chainguard-dev/clog"
	"go.uber.org/goleak"
)

// TestMain enforces the invariant that every package containing
// a fan-out site finishes its tests with no leaked goroutines. The
// errgroup dispatch sites in this package must all unwind before the
// test binary exits.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// newSilentLogger returns a clog.Logger backed by the default slog
// handler. Used by tests in this package that need a non-nil logger.
func newSilentLogger() *clog.Logger {
	return clog.New(slog.Default().Handler())
}

// chdirTemp redirects ghscan.ResultsDir into a per-test temp directory
// by chdir'ing to a fresh TempDir before any WriteCache call resolves
// the relative path.
func chdirTemp(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}
