package file_test

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain enforces the no-leaked-goroutine invariant. WriteCache and
// LoadCache are synchronous, but the concurrent-write regression test
// spawns N=64 goroutines that must all unwind before TestMain exits.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
