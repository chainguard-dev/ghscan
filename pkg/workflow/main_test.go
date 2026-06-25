package workflow_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain enforces the invariant that every package containing
// a fan-out site finishes its tests with no leaked goroutines. The
// per-job log fetch in getPerJobLogs spawns up to perJobFanOutLimit
// workers via errgroup; goleak catches any that fail to terminate.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
