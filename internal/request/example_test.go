package request_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/request"
)

// ExampleWithRetryN shows the canonical retry shape with an explicit
// retry budget: pass an operation closure that captures the call site's
// response, and WithRetryN will invoke it repeatedly under exponential
// backoff until it succeeds or the budget is exhausted.
func ExampleWithRetryN() {
	logger := clog.New(slog.Default().Handler())

	var attempts atomic.Int32
	err := request.WithRetryN(context.Background(), logger, 5, func() error {
		n := attempts.Add(1)
		if n < 3 {
			return errors.New("transient")
		}
		return nil
	})
	fmt.Println(err == nil, attempts.Load() >= 3)
	// Output:
	// true true
}
