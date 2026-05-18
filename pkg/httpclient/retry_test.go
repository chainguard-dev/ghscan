package httpclient_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/ghscan/pkg/httpclient"
)

// retryTestClient builds a client wired to ts and a deterministic
// FakeClock so retry sleep durations can be asserted without real
// time. Tests using this helper are NOT t.Parallel() because they
// share the package-level retryClock.
func retryTestClient(t *testing.T, ts *httptest.Server, opts ...httpclient.Option) (*httpclient.Client, *httpclient.FakeClock) {
	t.Helper()
	clock := &httpclient.FakeClock{NowVal: time.Unix(1_700_000_000, 0)}
	t.Cleanup(httpclient.SetRetryClock(clock))
	c := newTestClient(t, ts, opts...)
	return c, clock
}

func TestDoWithRetry_RetryAfterIntegerHonored(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	c, clock := retryTestClient(t, ts)
	body, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil resp")
	}
	closeBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Errorf("body: got %q want ok", body)
	}
	if calls.Load() != 2 {
		t.Errorf("calls: got %d want 2", calls.Load())
	}
	if len(clock.Sleeps) != 1 || clock.Sleeps[0] != 2*time.Second {
		t.Errorf("sleeps: got %v want [2s]", clock.Sleeps)
	}
}

func TestDoWithRetry_RetryAfterHTTPDateHonored(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			// 5 seconds in the future relative to FakeClock.NowVal.
			future := time.Unix(1_700_000_005, 0).UTC()
			w.Header().Set("Retry-After", future.Format(http.TimeFormat))
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	c, clock := retryTestClient(t, ts)
	_, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	closeBody(t, resp)
	if calls.Load() != 2 {
		t.Errorf("calls: got %d want 2", calls.Load())
	}
	if len(clock.Sleeps) != 1 {
		t.Fatalf("sleeps: got %v want one entry", clock.Sleeps)
	}
	if clock.Sleeps[0] != 5*time.Second {
		t.Errorf("sleep[0]: got %v want 5s", clock.Sleeps[0])
	}
}

func TestDoWithRetry_5xxBackoffUntilSuccess(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	c, clock := retryTestClient(t, ts,
		httpclient.WithRetryBaseDelay(10*time.Millisecond),
		httpclient.WithRetryCap(time.Second),
	)
	_, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	closeBody(t, resp)
	if calls.Load() != 3 {
		t.Errorf("calls: got %d want 3", calls.Load())
	}
	if len(clock.Sleeps) != 2 {
		t.Errorf("sleeps: got %d want 2", len(clock.Sleeps))
	}
	// Each sleep must fall within the jittered exponential window.
	// attempt 0: [0, 10ms); attempt 1: [0, 20ms).
	if clock.Sleeps[0] >= 10*time.Millisecond {
		t.Errorf("sleep[0] %v not in [0,10ms)", clock.Sleeps[0])
	}
	if clock.Sleeps[1] >= 20*time.Millisecond {
		t.Errorf("sleep[1] %v not in [0,20ms)", clock.Sleeps[1])
	}
}

func TestDoWithRetry_403WithRetryAfterIsRetried(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	c, clock := retryTestClient(t, ts)
	_, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	closeBody(t, resp)
	if calls.Load() != 2 {
		t.Errorf("calls: got %d want 2", calls.Load())
	}
	if len(clock.Sleeps) != 1 || clock.Sleeps[0] != time.Second {
		t.Errorf("sleeps: got %v want [1s]", clock.Sleeps)
	}
}

func TestDoWithRetry_403WithoutRetryAfterIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(ts.Close)

	c, _ := retryTestClient(t, ts)
	_, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil resp")
	}
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d want 403", resp.StatusCode)
	}
	if calls.Load() != 1 {
		t.Errorf("calls: got %d want 1 (no retry)", calls.Load())
	}
}

func TestDoWithRetry_MaxAttemptsCap(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)

	c, _ := retryTestClient(t, ts,
		httpclient.WithMaxRetries(2),
		httpclient.WithRetryBaseDelay(time.Millisecond),
	)
	_, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil resp")
	}
	closeBody(t, resp)
	// 1 initial + 2 retries = 3 total.
	if calls.Load() != 3 {
		t.Errorf("calls: got %d want 3", calls.Load())
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status: got %d want 503", resp.StatusCode)
	}
}

func TestDoWithRetry_DisabledByZero(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(ts.Close)

	c, _ := retryTestClient(t, ts, httpclient.WithMaxRetries(0))
	_, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	closeBody(t, resp)
	if calls.Load() != 1 {
		t.Errorf("calls: got %d want 1", calls.Load())
	}
}

func TestDoWithRetry_NoRetryOn200(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	c, clock := retryTestClient(t, ts)
	_, resp, err := c.GetWithRetry(t.Context(), ts.URL+"/")
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	closeBody(t, resp)
	if calls.Load() != 1 {
		t.Errorf("calls: got %d want 1", calls.Load())
	}
	if len(clock.Sleeps) != 0 {
		t.Errorf("sleeps: got %v want []", clock.Sleeps)
	}
}

func TestDoWithRetry_ContextCanceledMidRetry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(ts.Close)

	// Real clock: ctx must propagate to the timer.
	ctx, cancel := context.WithCancel(t.Context())
	c := newTestClient(t, ts, httpclient.WithRetryBaseDelay(time.Hour))

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, resp, err := c.GetWithRetry(ctx, ts.URL+"/")
	closeBody(t, resp)
	if err == nil {
		t.Fatal("expected ctx error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err: got %v want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("retry loop did not abort promptly: %v", elapsed)
	}
}

func TestParseRetryAfter_TableDriven(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name   string
		header string
		want   time.Duration
		wantOk bool
	}{
		{name: "empty", header: "", want: 0, wantOk: false},
		{name: "integer seconds", header: "5", want: 5 * time.Second, wantOk: true},
		{name: "zero seconds", header: "0", want: 0, wantOk: true},
		{name: "negative seconds rejected", header: "-1", want: 0, wantOk: false},
		{name: "garbage rejected", header: "soon", want: 0, wantOk: false},
		{name: "http date future", header: time.Unix(1_700_000_010, 0).UTC().Format(http.TimeFormat), want: 10 * time.Second, wantOk: true},
		{name: "http date past clamps to 0", header: time.Unix(1_699_999_990, 0).UTC().Format(http.TimeFormat), want: 0, wantOk: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := httpclient.ParseRetryAfterForTest(tc.header, now)
			if ok != tc.wantOk {
				t.Errorf("ok: got %v want %v", ok, tc.wantOk)
			}
			if got != tc.want {
				t.Errorf("dur: got %v want %v", got, tc.want)
			}
		})
	}
}
