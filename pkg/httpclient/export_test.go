package httpclient

import (
	"context"
	"net/http"
	"time"
)

// CheckRedirect exposes the package-internal redirect guard for tests
// in the external _test package.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	return redirectGuard(req, via)
}

// FakeClock is a deterministic [retryClocker] for tests. now() returns
// a fixed instant; sleep records the requested duration and returns
// immediately. ctx cancellation is honored so cancel-mid-retry tests
// still observe ctx.Err.
type FakeClock struct {
	NowVal time.Time
	Sleeps []time.Duration
}

// Now returns the fake current instant.
func (f *FakeClock) Now() time.Time { return f.NowVal }

// Sleep records the requested sleep and returns ctx.Err if cancelled.
func (f *FakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.Sleeps = append(f.Sleeps, d)
	return nil
}

// fakeClockAdapter exists only to satisfy the unexported retryClocker
// interface in test code while keeping FakeClock's API exported.
type fakeClockAdapter struct{ inner *FakeClock }

func (a fakeClockAdapter) now() time.Time { return a.inner.Now() }

func (a fakeClockAdapter) sleep(ctx context.Context, d time.Duration) error {
	return a.inner.Sleep(ctx, d)
}

// SetRetryClock replaces the retry-loop clock used by DoWithRetry. It
// returns a restore function the caller defers to revert to the real
// clock. Tests that mutate the clock must run serially.
func SetRetryClock(f *FakeClock) func() {
	prev := retryClock
	retryClock = fakeClockAdapter{inner: f}
	return func() { retryClock = prev }
}

// ParseRetryAfterForTest exposes parseRetryAfter to the external test
// package for table-driven coverage.
func ParseRetryAfterForTest(h string, now time.Time) (time.Duration, bool) {
	return parseRetryAfter(h, now)
}
