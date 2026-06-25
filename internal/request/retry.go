package request

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v86/github"
)

// maxRetryAfter caps the Retry-After hint honored from server responses
// so an upstream that emits a hostile or oversized value cannot stall
// the scanner indefinitely. Mirrors the cap used for typed rate-limit
// errors below.
const maxRetryAfter = 30 * time.Second

// Permanent wraps err so WithRetryN treats it as non-retryable and
// returns the inner error immediately without emitting the
// "Operation failed (attempt N/M)" warn line. Use this for terminal
// signals such as workflow.ErrRunHasNoLogs where the caller should
// short-circuit rather than retry.
func Permanent(err error) error {
	return backoff.Permanent(err)
}

// WithRetryN runs operation under exponential-backoff retry with an
// explicit maxRetries budget. Setting maxRetries=0 means a single
// attempt with no retries.
//
// Rate-limit / abuse-rate-limit errors from go-github are honored via
// [backoff.RetryAfter] so the retry schedule respects the server's
// reset window. The "max retries exceeded" gate runs BEFORE the
// typed-error inspection so a perpetually rate-limited operation
// terminates after exactly maxRetries+1 attempts and not one extra.
func WithRetryN(ctx context.Context, logger *clog.Logger, maxRetries int, operation func() error) error {
	attempt := 0

	wrappedOperation := func() (any, error) {
		if ctx.Err() != nil {
			return nil, backoff.Permanent(ctx.Err())
		}

		attempt++
		err := operation()
		if err == nil {
			return nil, nil
		}

		// A pre-wrapped PermanentError signals a terminal condition the
		// caller already decided is non-retryable. Pass it through to the
		// backoff library (which unwraps and returns the inner error)
		// without emitting the per-attempt warn line.
		var permErr *backoff.PermanentError
		if errors.As(err, &permErr) {
			return nil, err
		}

		if attempt > maxRetries {
			return nil, backoff.Permanent(fmt.Errorf("max retries exceeded: %w", err))
		}

		if ctx.Err() == context.DeadlineExceeded {
			return nil, backoff.Permanent(fmt.Errorf("operation timed out: %w", err))
		}

		if d, ok := rateLimitHint(err, attempt); ok {
			logger.Warnf("Hit rate limit, waiting %v before retry", d)
			return nil, backoff.RetryAfter(int(d.Seconds()))
		}

		logger.Warnf("Operation failed (attempt %d/%d): %v", attempt, maxRetries+1, err)
		return nil, err
	}

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 1 * time.Second
	b.MaxInterval = 10 * time.Second

	_, err := backoff.Retry(ctx, wrappedOperation, backoff.WithBackOff(b))
	return err
}

// rateLimitHint returns a positive backoff duration when err indicates
// a rate-limit or secondary-rate-limit condition reported by go-github.
// Matching is keyed off concrete error types so arbitrary 403 responses
// whose body merely mentions "rate limit" do not enter this branch.
// Three error shapes are recognized:
//
//   - *github.RateLimitError       primary rate limit
//   - *github.AbuseRateLimitError  abuse / secondary rate limit (typed)
//   - *github.ErrorResponse        secondary rate limit (header-only)
//
// For the typed errors we fall back to a per-attempt schedule capped at
// maxRetryAfter. For *github.ErrorResponse we honor a Retry-After
// header (delta-seconds only) when present and otherwise return false
// so the standard exponential-backoff schedule runs.
func rateLimitHint(err error, attempt int) (time.Duration, bool) {
	var rateLimitErr *github.RateLimitError
	var abuseLimitErr *github.AbuseRateLimitError
	if errors.As(err, &rateLimitErr) || errors.As(err, &abuseLimitErr) {
		return min(5*time.Second*time.Duration(attempt), maxRetryAfter), true
	}

	var errResp *github.ErrorResponse
	if !errors.As(err, &errResp) || errResp == nil || errResp.Response == nil {
		return 0, false
	}
	hdr := errResp.Response.Header.Get("Retry-After")
	if hdr == "" {
		return 0, false
	}
	secs, parseErr := strconv.Atoi(hdr)
	if parseErr != nil || secs <= 0 {
		return 0, false
	}
	d := min(time.Duration(secs)*time.Second, maxRetryAfter)
	return d, true
}
