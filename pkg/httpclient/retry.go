package httpclient

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Default retry policy constants. These are tunable per-Client via
// [WithMaxRetries], [WithRetryBaseDelay], and [WithRetryCap].
const (
	defaultMaxRetries     = 3
	defaultRetryBaseDelay = 500 * time.Millisecond
	defaultRetryCap       = 30 * time.Second
)

// retryClock is the time source used by the retry loop. Tests override
// it via [SetRetryClock] (export_test.go) to drive deterministic timing
// without sleeping in real time.
var retryClock retryClocker = realRetryClock{}

type retryClocker interface {
	now() time.Time
	sleep(ctx context.Context, d time.Duration) error
}

type realRetryClock struct{}

func (realRetryClock) now() time.Time { return time.Now() }

func (realRetryClock) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// WithMaxRetries overrides the maximum number of retry attempts
// performed by [Client.DoWithRetry] and [Client.GetWithRetry]. A value
// of 0 disables retry entirely. Negative values are clamped to 0.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n < 0 {
			n = 0
		}
		c.maxRetries = n
		c.maxRetriesSet = true
	}
}

// WithRetryBaseDelay overrides the base delay used for full-jitter
// exponential backoff. Non-positive values fall back to the default.
func WithRetryBaseDelay(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.retryBase = d
		}
	}
}

// WithRetryCap overrides the maximum exponential-backoff sleep. Sleeps
// derived from a Retry-After header are NOT capped — callers that
// expose this client to untrusted servers should add their own bound.
// Non-positive values fall back to the default.
func WithRetryCap(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.retryCap = d
		}
	}
}

// shouldRetry reports whether status is in the retryable set: 429,
// 5xx (502/503/504), or 403 with a Retry-After header. A 403 without
// Retry-After is treated as an authorization failure and not retried.
func shouldRetry(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return true
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusForbidden:
		return resp.Header.Get("Retry-After") != ""
	}
	return false
}

// parseRetryAfter parses a Retry-After header value. It accepts both
// integer-seconds and HTTP-date forms per RFC 7231. Returns 0 and
// false on parse failure or empty input.
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil {
		if secs < 0 {
			return 0, false
		}
		// cap defends 32-bit Duration overflow
		if secs > 86400 {
			return 24 * time.Hour, true
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0, true
		}
		return d, true
	}
	return 0, false
}

// jitterDelay returns a uniformly random duration in [0, exp]
// where exp = min(cap, base * 2^attempt). attempt starts at 0.
// math/rand/v2 is used because the jitter source does not need
// cryptographic strength; predictability of retry sleeps is not a
// security boundary here.
func jitterDelay(attempt int, base, capDur time.Duration) time.Duration {
	if base <= 0 {
		base = defaultRetryBaseDelay
	}
	if capDur <= 0 {
		capDur = defaultRetryCap
	}
	// Clamp attempt to avoid overflow at large attempt counts. 30 is
	// already past every reasonable max-retry value.
	if attempt > 30 {
		attempt = 30
	}
	exp := base << attempt
	if exp <= 0 || exp > capDur {
		exp = capDur
	}
	return time.Duration(rand.Int64N(int64(exp))) // #nosec G404 -- jitter for retry backoff is not a security boundary
}

// GetWithRetry is the retrying counterpart of [Client.Get]. See
// [Client.DoWithRetry] for retry semantics.
func (c *Client) GetWithRetry(ctx context.Context, url string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("httpclient: build request: %w", err)
	}
	return c.DoWithRetry(ctx, req)
}

// DoWithRetry executes req with retry-on-transient-failure semantics:
//
//   - 429, 502, 503, 504: always retried.
//   - 403 with Retry-After header: retried (treated as secondary rate
//     limit per GitHub docs).
//   - 403 without Retry-After: NOT retried (assumed authorization
//     failure).
//   - Network errors from [Client.Do]: retried.
//
// Retry-After header values (integer seconds or HTTP-date) are honored
// verbatim. Otherwise a full-jitter exponential backoff is used:
// sleep ∈ [0, min(cap, base * 2^attempt)).
//
// The retry loop honors ctx.Done() between attempts and returns the
// context error if the deadline expires mid-backoff. The maximum
// number of attempts (initial + retries) is `1 + maxRetries`.
//
// Preconditions:
//
//   - Retry-After is honored verbatim with no upper bound; total stall
//     time is bounded only by ctx. Callers passing requests to
//     untrusted servers MUST set a ctx deadline.
//   - req must be replayable: GET requests are safe; non-GET requests
//     must have req.GetBody set.
//
// On exhaustion, the final response (or error) is returned to the
// caller unmodified.
func (c *Client) DoWithRetry(ctx context.Context, req *http.Request) ([]byte, *http.Response, error) {
	if req == nil {
		return nil, nil, errors.New("httpclient: nil request")
	}
	maxRetries := c.maxRetries
	if !c.maxRetriesSet {
		maxRetries = defaultMaxRetries
	}
	base := c.retryBase
	if base <= 0 {
		base = defaultRetryBaseDelay
	}
	capDur := c.retryCap
	if capDur <= 0 {
		capDur = defaultRetryCap
	}

	var (
		body    []byte
		resp    *http.Response
		err     error
		attempt int
	)
	for attempt = 0; attempt <= maxRetries; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			if err == nil {
				err = ctxErr
			}
			return body, resp, err
		}

		body, resp, err = c.Do(ctx, req)
		// Network error path.
		if err != nil {
			if attempt == maxRetries {
				return body, resp, err
			}
			sleep := jitterDelay(attempt, base, capDur)
			if sleepErr := retryClock.sleep(ctx, sleep); sleepErr != nil {
				return body, resp, sleepErr
			}
			continue
		}

		// Status-code path. shouldRetry returns false when resp is nil,
		// but the analyzer cannot follow that across the helper; the
		// explicit guard below makes the precondition local.
		if !shouldRetry(resp) || attempt == maxRetries {
			return body, resp, err
		}
		if resp == nil {
			return body, resp, err
		}

		// Decide sleep duration: prefer Retry-After, else jitter.
		var sleep time.Duration
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), retryClock.now()); ok {
			sleep = d
		} else {
			sleep = jitterDelay(attempt, base, capDur)
		}
		if sleepErr := retryClock.sleep(ctx, sleep); sleepErr != nil {
			return body, resp, sleepErr
		}
	}
	return body, resp, err
}
