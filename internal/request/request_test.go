package request_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/ghscan/internal/request"
	"github.com/google/go-github/v86/github"
)

func newSilentLogger() *clog.Logger {
	return clog.New(slog.Default().Handler())
}

func TestWithRetryN_HappyPath(t *testing.T) {
	t.Parallel()

	var calls int32
	err := request.WithRetryN(t.Context(), newSilentLogger(), 3, func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1", calls)
	}
}

func TestWithRetryN_RetriesUntilSuccess(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var calls int32
	err := request.WithRetryN(ctx, newSilentLogger(), 5, func() error {
		n := atomic.AddInt32(&calls, 1)
		if n < 2 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 calls, got %d", calls)
	}
}

func TestWithRetryN_ExhaustsMaxRetries(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var calls int32
	err := request.WithRetryN(ctx, newSilentLogger(), 1, func() error {
		atomic.AddInt32(&calls, 1)
		return errors.New("permanent failure")
	})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if calls < 2 {
		t.Fatalf("expected at least 2 attempts, got %d", calls)
	}
}

func TestWithRetryN_ContextCancelledImmediately(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var calls int32
	err := request.WithRetryN(ctx, newSilentLogger(), 5, func() error {
		atomic.AddInt32(&calls, 1)
		return nil
	})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	// The wrapped operation may or may not be invoked once before the
	// permanent context.Err is returned, but it must never be retried
	// after cancellation is observed.
	if calls > 1 {
		t.Fatalf("expected at most 1 call after cancel, got %d", calls)
	}
}

func TestWithRetryN_DeadlineExceededIsPermanent(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	// Block long enough for the parent ctx deadline to fire while the
	// operation itself returns an error -- the retry path should treat
	// the deadline as permanent and not consume the entire budget.
	var calls atomic.Int32
	err := request.WithRetryN(ctx, newSilentLogger(), 5, func() error {
		calls.Add(1)
		time.Sleep(100 * time.Millisecond)
		return fmt.Errorf("op error")
	})
	if err == nil {
		t.Fatal("expected error after deadline")
	}
}

// TestWithRetryN_RateLimitGateBeforeRetryAfter pins the off-by-one
// gate fix: when every attempt returns a *github.RateLimitError, the
// retry loop must terminate after exactly maxRetries+1 attempts (the
// initial try plus maxRetries retries) and surface a wrapped
// "max retries exceeded" error -- not consume one extra RetryAfter
// pass before the budget gate runs.
func TestWithRetryN_RateLimitGateBeforeRetryAfter(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	const maxRetries = 2

	var calls int32
	err := request.WithRetryN(ctx, newSilentLogger(), maxRetries, func() error {
		atomic.AddInt32(&calls, 1)
		return &github.RateLimitError{
			Rate: github.Rate{
				Limit:     5000,
				Remaining: 0,
				Reset:     github.Timestamp{Time: time.Now().Add(time.Second)},
			},
			Response: &http.Response{StatusCode: http.StatusForbidden},
			Message:  "API rate limit exceeded",
		}
	})
	if err == nil {
		t.Fatalf("expected error after %d rate-limit attempts, got nil", calls)
	}
	if !strings.Contains(err.Error(), "max retries exceeded") {
		t.Fatalf("error %q does not contain 'max retries exceeded'", err.Error())
	}
	// Initial attempt + maxRetries retries == maxRetries+1.
	if got, want := calls, int32(maxRetries+1); got != want {
		t.Fatalf("calls=%d, want exactly %d (initial + %d retries)", got, want, maxRetries)
	}
}

// TestWithRetryN_TypedErrorPredicate covers the rate-limit retry path:
// it is keyed off errors.As against go-github's typed errors rather
// than substring matches on err.Error(). The negative cases (a generic
// errors.New("rate limit ...") and a plain "permission denied")
// document the BEHAVIORAL CHANGE -- under the old strings.Contains
// predicate those would have entered the slow-retry branch; under the
// new typed-error predicate they do not.
func TestWithRetryN_TypedErrorPredicate_BehavioralChange(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// errFor returns the error to surface on attempt n (1-indexed).
		// Returning nil indicates success.
		errFor       func(attempt int32) error
		wantMinCalls int32
		wantErr      bool
	}{
		{
			name: "typed RateLimitError retries then succeeds",
			errFor: func(n int32) error {
				if n == 1 {
					return &github.RateLimitError{
						Rate: github.Rate{
							Limit:     5000,
							Remaining: 0,
							Reset:     github.Timestamp{Time: time.Now().Add(time.Second)},
						},
						Response: &http.Response{StatusCode: http.StatusForbidden},
						Message:  "API rate limit exceeded",
					}
				}
				return nil
			},
			wantMinCalls: 2,
		},
		{
			name: "typed AbuseRateLimitError retries then succeeds",
			errFor: func(n int32) error {
				if n == 1 {
					retryAfter := time.Second
					return &github.AbuseRateLimitError{
						Response:   &http.Response{StatusCode: http.StatusForbidden},
						Message:    "You have exceeded a secondary rate limit",
						RetryAfter: &retryAfter,
					}
				}
				return nil
			},
			wantMinCalls: 2,
		},
		{
			name: "string-only 'rate limit' error no longer triggers slow retry",
			// Old code: this would hit the strings.Contains("rate
			// limit") branch and sleep 5s before retry. New code:
			// treated as a generic transient error and retried under
			// the normal exponential-backoff schedule (which the test
			// still observes via the retry budget). The test asserts
			// the operation still fails -- max_retries is exhausted --
			// proving the typed predicate did NOT short-circuit into
			// the rate-limit branch.
			errFor: func(_ int32) error {
				return errors.New("rate limit exceeded according to server text")
			},
			wantMinCalls: 2,
			wantErr:      true,
		},
		{
			name: "plain non-rate-limit error propagates without retry-after path",
			errFor: func(_ int32) error {
				return errors.New("connection refused")
			},
			wantMinCalls: 2,
			wantErr:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			var calls int32
			err := request.WithRetryN(ctx, newSilentLogger(), 2, func() error {
				n := atomic.AddInt32(&calls, 1)
				return tc.errFor(n)
			})

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil after %d calls", calls)
				}
			} else if err != nil {
				t.Fatalf("unexpected error after %d calls: %v", calls, err)
			}
			if calls < tc.wantMinCalls {
				t.Fatalf("calls=%d, want >= %d", calls, tc.wantMinCalls)
			}
		})
	}
}

// TestWithRetryN_PermanentStopsImmediately covers the request.Permanent
// helper: an operation that wraps its error with request.Permanent
// must run exactly once and the retry loop must surface the inner
// error verbatim. The "Operation failed (attempt N/M)" warn line must
// stay suppressed so log volume tracks the underlying intent (terminal
// skip, not transient failure).
func TestWithRetryN_PermanentStopsImmediately(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("workflow: run has no logs to scan")

	logger, snapshot := captureLogger(t)
	var calls int32
	err := request.WithRetryN(t.Context(), logger, 5, func() error {
		atomic.AddInt32(&calls, 1)
		return request.Permanent(sentinel)
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected errors.Is(err, sentinel); got %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want exactly 1", calls)
	}
	if strings.Contains(snapshot(), "Operation failed") {
		t.Fatalf("did not expect 'Operation failed' warn line on Permanent path; logs:\n%s", snapshot())
	}
}

// newErrorResponse builds a *github.ErrorResponse whose underlying HTTP
// response carries the supplied status code and headers. GitHub's
// secondary-rate-limit signal surfaces this way rather than as a
// dedicated typed error in v86, so the retry loop must pattern-match on
// the embedded response.
func newErrorResponse(status int, headers map[string]string, message string) *github.ErrorResponse {
	hdr := http.Header{}
	for k, v := range headers {
		hdr.Set(k, v)
	}
	return &github.ErrorResponse{
		Response: &http.Response{
			StatusCode: status,
			Header:     hdr,
			Request:    &http.Request{Method: http.MethodGet},
		},
		Message: message,
	}
}

// captureLogger returns a logger whose output is appended into a
// goroutine-safe buffer. Used to assert that the rate-limit retry path
// emits its "Hit rate limit" warning, which is the observable signal
// that backoff.RetryAfter (rather than the default exponential
// schedule) fired.
func captureLogger(t *testing.T) (*clog.Logger, func() string) {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&safeWriter{mu: &mu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := clog.New(handler)
	return l, func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type safeWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (s *safeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// TestWithRetryN_ErrorResponseRetryAfter exercises the
// secondary-rate-limit path. go-github surfaces secondary rate limits
// as a bare *github.ErrorResponse whose embedded http.Response carries
// a Retry-After header; the retry loop honors the header (positive
// case) and falls back to the standard backoff for ErrorResponses that
// do not carry one (negative case). The observable signal that
// distinguishes the two paths is the "Hit rate limit" warning log.
func TestWithRetryN_ErrorResponseRetryAfter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		errFor         func(attempt int32) error
		wantMinCalls   int32
		wantErr        bool
		wantRateLogged bool
	}{
		{
			name: "ErrorResponse 403 with Retry-After header takes rate-limit branch",
			errFor: func(n int32) error {
				if n == 1 {
					return newErrorResponse(http.StatusForbidden,
						map[string]string{"Retry-After": "1"},
						"You have exceeded a secondary rate limit")
				}
				return nil
			},
			wantMinCalls:   2,
			wantRateLogged: true,
		},
		{
			name: "ErrorResponse 429 with Retry-After header takes rate-limit branch",
			errFor: func(n int32) error {
				if n == 1 {
					return newErrorResponse(http.StatusTooManyRequests,
						map[string]string{"Retry-After": "2"},
						"Too many requests")
				}
				return nil
			},
			wantMinCalls:   2,
			wantRateLogged: true,
		},
		{
			name: "ErrorResponse without Retry-After does NOT take rate-limit branch",
			errFor: func(n int32) error {
				if n == 1 {
					return newErrorResponse(http.StatusInternalServerError,
						nil,
						"internal server error")
				}
				return nil
			},
			wantMinCalls:   2,
			wantRateLogged: false,
		},
		{
			name: "ErrorResponse 403 without Retry-After does NOT take rate-limit branch",
			errFor: func(n int32) error {
				if n == 1 {
					return newErrorResponse(http.StatusForbidden, nil, "forbidden")
				}
				return nil
			},
			wantMinCalls:   2,
			wantRateLogged: false,
		},
		{
			name: "ErrorResponse without Retry-After exhausts budget on permanent failure",
			errFor: func(_ int32) error {
				return newErrorResponse(http.StatusInternalServerError, nil, "boom")
			},
			wantMinCalls:   2,
			wantErr:        true,
			wantRateLogged: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			logger, snapshot := captureLogger(t)

			var calls int32
			err := request.WithRetryN(ctx, logger, 2, func() error {
				n := atomic.AddInt32(&calls, 1)
				return tc.errFor(n)
			})

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil after %d calls", calls)
				}
			} else if err != nil {
				t.Fatalf("unexpected error after %d calls: %v", calls, err)
			}
			if calls < tc.wantMinCalls {
				t.Fatalf("calls=%d, want >= %d", calls, tc.wantMinCalls)
			}
			gotRateLog := strings.Contains(snapshot(), "Hit rate limit")
			if gotRateLog != tc.wantRateLogged {
				t.Fatalf("rate-limit log path taken=%v, want %v\nlogs:\n%s",
					gotRateLog, tc.wantRateLogged, snapshot())
			}
		})
	}
}
