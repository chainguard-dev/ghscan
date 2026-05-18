package httpclient_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/ghscan/pkg/httpclient"
	"golang.org/x/time/rate"
)

// newTestClient returns a Client whose underlying http.Client uses the
// supplied test server's transport and a permissive CheckRedirect so
// httptest URLs (http://127.0.0.1:NNN) aren't rejected by the prod
// allowlist. Tests that exercise the prod redirect guard construct
// their own Client without WithHTTPClient.
func newTestClient(t *testing.T, ts *httptest.Server, opts ...httpclient.Option) *httpclient.Client {
	t.Helper()
	hc := &http.Client{
		Timeout:       5 * time.Second,
		Transport:     ts.Client().Transport,
		CheckRedirect: nil, // tests use server-relative redirects only
	}
	all := append([]httpclient.Option{
		httpclient.WithHTTPClient(hc),
		httpclient.WithRateLimit(rate.Inf, 10),
	}, opts...)
	return httpclient.New(all...)
}

func TestGet_FreshFetch_SetsDefaultHeaders(t *testing.T) {
	t.Parallel()

	var got http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(ts.Close)

	c := newTestClient(t, ts)
	body, resp, err := c.Get(t.Context(), ts.URL+"/runs")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil resp")
	}
	closeBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("body: got %q", string(body))
	}
	for _, h := range []string{"User-Agent", "X-Github-Api-Version", "Accept"} {
		if got.Get(h) == "" {
			t.Errorf("header %s missing", h)
		}
	}
	if !strings.HasPrefix(got.Get("User-Agent"), "ghscan/") {
		t.Errorf("user-agent prefix: got %q", got.Get("User-Agent"))
	}
	if got.Get("X-Github-Api-Version") != "2026-03-10" {
		t.Errorf("api version: got %q want 2026-03-10", got.Get("X-Github-Api-Version"))
	}
	if got.Get("Accept") != "application/vnd.github+json" {
		t.Errorf("accept: got %q", got.Get("Accept"))
	}
}

func TestGet_ETagCache_Returns304AsCachedBody(t *testing.T) {
	t.Parallel()

	const etag = `"abc123"`
	const body = `{"cached":true}`
	var calls atomic.Int32
	var sawIfNoneMatch atomic.Bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if inm := r.Header.Get("If-None-Match"); inm != "" {
			sawIfNoneMatch.Store(true)
			if inm == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("ETag", etag)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)

	c := newTestClient(t, ts)
	first, resp1, err := c.Get(t.Context(), ts.URL+"/cached")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	closeBody(t, resp1)
	if string(first) != body {
		t.Fatalf("first body: got %q", string(first))
	}

	second, resp, err := c.Get(t.Context(), ts.URL+"/cached")
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil resp")
	}
	closeBody(t, resp)
	if !sawIfNoneMatch.Load() {
		t.Error("server never saw If-None-Match")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("synthetic status: got %d want 200", resp.StatusCode)
	}
	if string(second) != body {
		t.Errorf("cached body: got %q want %q", string(second), body)
	}
	if calls.Load() != 2 {
		t.Errorf("server calls: got %d want 2", calls.Load())
	}
}

func TestGet_OversizedBody_ReturnsErrBodyTooLarge(t *testing.T) {
	t.Parallel()

	payload := strings.Repeat("x", 4096)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	t.Cleanup(ts.Close)

	c := newTestClient(t, ts, httpclient.WithMaxBodyBytes(128))
	_, resp, err := c.Get(t.Context(), ts.URL+"/big")
	closeBody(t, resp)
	if !errors.Is(err, httpclient.ErrBodyTooLarge) {
		t.Fatalf("expected ErrBodyTooLarge, got %v", err)
	}
}

func TestGet_ContextCanceled_ReturnsPromptly(t *testing.T) {
	t.Parallel()

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	c := newTestClient(t, ts)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, resp, err := c.Get(ctx, ts.URL+"/slow")
	closeBody(t, resp)
	if err == nil {
		t.Fatal("expected context error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Get took too long after cancel: %v", elapsed)
	}
}

func TestGet_RetryAfterHeaderHonored(t *testing.T) {
	t.Parallel()

	// Retries are implemented in an outer layer; this test pins the
	// observable behavior: the 403 status and Retry-After header are
	// surfaced to the caller untouched, so the outer retry layer can
	// act on them.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"rate limited"}`)
	}))
	t.Cleanup(ts.Close)

	c := newTestClient(t, ts)
	_, resp, err := c.Get(t.Context(), ts.URL+"/limited")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil resp")
	}
	closeBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d want 403", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") != "1" {
		t.Errorf("Retry-After: got %q", resp.Header.Get("Retry-After"))
	}
}

func TestGet_429Surfaced(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(ts.Close)

	c := newTestClient(t, ts)
	_, resp, err := c.Get(t.Context(), ts.URL+"/burst")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil resp")
	}
	closeBody(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status: got %d want 429", resp.StatusCode)
	}
}

func TestRedirect_Blocked_NonAllowedHost(t *testing.T) {
	t.Parallel()

	// One server redirects to evil.com; the prod CheckRedirect must
	// block it. We use a Client without WithHTTPClient so the prod
	// guard runs.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "https://evil.com/", http.StatusFound)
	}))
	t.Cleanup(ts.Close)

	c := httpclient.New(
		httpclient.WithRateLimit(rate.Inf, 10),
		httpclient.WithHTTPClient(&http.Client{
			Timeout:       2 * time.Second,
			Transport:     ts.Client().Transport,
			CheckRedirect: nil, // forces New() to install prod guard
		}),
	)
	_, resp, err := c.Get(t.Context(), ts.URL+"/evil")
	closeBody(t, resp)
	if err == nil {
		t.Fatal("expected redirect block")
	}
	if !strings.Contains(err.Error(), "redirect blocked") {
		t.Errorf("error %v does not mention redirect block", err)
	}
}

func TestRedirect_Allowed_GitHubHost(t *testing.T) {
	t.Parallel()

	// The CheckRedirect itself, exercised directly, accepts api.github.com.
	req := &http.Request{URL: mustURL(t, "https://api.github.com/repos/x/y")}
	if err := httpclient.CheckRedirect(req, nil); err != nil {
		t.Errorf("api.github.com should be allowed: %v", err)
	}
	req2 := &http.Request{URL: mustURL(t, "https://pipelinesghubeus1.actions.githubusercontent.com/foo")}
	if err := httpclient.CheckRedirect(req2, nil); err != nil {
		t.Errorf("actions log host should be allowed: %v", err)
	}
	req3 := &http.Request{URL: mustURL(t, "https://objects.githubusercontent.com/foo")}
	if err := httpclient.CheckRedirect(req3, nil); err != nil {
		t.Errorf("objects.githubusercontent.com should be allowed: %v", err)
	}
}

func TestRedirect_Blocked_HTTPScheme(t *testing.T) {
	t.Parallel()

	req := &http.Request{URL: mustURL(t, "http://api.github.com/")}
	if err := httpclient.CheckRedirect(req, nil); err == nil {
		t.Error("http scheme must be blocked")
	}
}

func TestReadAllBounded_ExactBoundary(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		max     int64
		wantErr bool
		wantLen int
	}{
		{name: "under cap", input: "abc", max: 10, wantErr: false, wantLen: 3},
		{name: "at cap", input: "abcdefghij", max: 10, wantErr: false, wantLen: 10},
		{name: "over cap", input: "abcdefghijk", max: 10, wantErr: true, wantLen: 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf, err := httpclient.ReadAllBounded(strings.NewReader(tc.input), tc.max)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if len(buf) != tc.wantLen {
				t.Errorf("len=%d want %d", len(buf), tc.wantLen)
			}
		})
	}
}

func TestSingleflight_DedupsConcurrentGets(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	gate := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		<-gate
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(ts.Close)

	c := newTestClient(t, ts)
	const n = 8
	errs := make(chan error, n)
	for range n {
		go func() {
			_, resp, err := c.Get(t.Context(), ts.URL+"/sf")
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			errs <- err
		}()
	}
	// Give goroutines time to coalesce on the singleflight key.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	for range n {
		if err := <-errs; err != nil {
			t.Errorf("Get: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls: got %d want 1 (singleflight dedup failed)", got)
	}
}

// mustURL parses a URL or fails the test.
func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// closeBody satisfies the bodyclose linter without producing real I/O —
// the [httpclient.Client] has already drained and reassigned resp.Body
// to [http.NoBody] before returning.
func closeBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp == nil || resp.Body == nil {
		return
	}
	_ = resp.Body.Close()
}
