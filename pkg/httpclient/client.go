package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// version is the User-Agent suffix until ghscan adopts a real version
// package. May be replaced with a build-info read in the future.
const version = "dev"

// apiVersion is the X-GitHub-Api-Version date stamp ghscan pins to.
// Verified against https://docs.github.com/en/rest/overview/api-versions
// on 2026-05-10.
const apiVersion = "2026-03-10"

// defaultMaxBodyBytes caps any single response body. The 50 MiB
// ceiling accommodates large workflow log archives without leaving
// unbounded memory exposure on a malicious or misconfigured peer.
const defaultMaxBodyBytes int64 = 50 * 1024 * 1024

// defaultETagCacheSize is the LRU capacity for cached ETag responses.
const defaultETagCacheSize = 10000

// defaultRateInterval / defaultRateBurst translate GitHub's documented
// 5,000 requests/hour authenticated quota into a token bucket. Burst of
// 5 keeps small bursts smooth while staying clear of the documented
// 100-request secondary concurrency limit.
const (
	defaultRateInterval = 720 * time.Millisecond
	defaultRateBurst    = 5
)

// allowedHostsExact lists hosts that are matched character-for-character
// by [redirectGuard]. The github.com (UI) entry was removed after
// deleting the HTML-scraping fallback in pkg/workflow; only the REST
// API host and its actions-log CDN buckets need to be reachable.
var allowedHostsExact = map[string]struct{}{
	"api.github.com":                {},
	"objects.githubusercontent.com": {},
}

// allowedHostSuffix permits any host whose name ends with this suffix
// (e.g. pipelines.actions.githubusercontent.com,
// pipelinesghubeus1.actions.githubusercontent.com,
// productionresultssa9.blob.core.windows.net is NOT covered — only the
// actions log subdomains).
const allowedHostSuffix = ".actions.githubusercontent.com"

// ErrBodyTooLarge is returned by [ReadAllBounded] and [Client.Get] /
// [Client.Do] when the response body exceeds the configured cap.
var ErrBodyTooLarge = errors.New("httpclient: response body exceeds max bytes")

// ErrRedirectBlocked is returned when the server attempts to redirect
// us to a scheme or host that is not on the allowlist.
var ErrRedirectBlocked = errors.New("httpclient: redirect blocked by allowlist")

// cacheEntry is the value stored in the ETag LRU.
type cacheEntry struct {
	etag   string
	body   []byte
	header http.Header
}

// Client is a shared, hardened HTTP client for GitHub API access.
//
// All exported methods are safe for concurrent use.
type Client struct {
	httpClient   *http.Client
	limiter      *rate.Limiter
	etagCache    *lru.Cache[string, cacheEntry]
	sf           singleflight.Group
	userAgent    string
	apiVersion   string
	accept       string
	maxBodyBytes int64

	// Retry policy (consumed by DoWithRetry / GetWithRetry).
	// maxRetriesSet records whether WithMaxRetries was applied so a
	// caller-supplied 0 (disable) is distinguishable from "use default".
	maxRetries    int
	maxRetriesSet bool
	retryBase     time.Duration
	retryCap      time.Duration

	// limiterMu guards adjustments derived from response headers so we
	// never race rate.Limiter SetLimit/SetBurst against an in-flight
	// Wait.
	limiterMu sync.Mutex
}

// Option configures a [Client].
type Option func(*Client)

// WithUserAgent overrides the default User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		if ua != "" {
			c.userAgent = ua
		}
	}
}

// WithMaxBodyBytes overrides the per-response body cap. A non-positive
// value falls back to the default.
func WithMaxBodyBytes(n int64) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxBodyBytes = n
		}
	}
}

// WithRateLimit overrides the token-bucket rate limiter. A
// non-positive burst falls back to the default.
func WithRateLimit(r rate.Limit, burst int) Option {
	return func(c *Client) {
		if burst <= 0 {
			burst = defaultRateBurst
		}
		c.limiter = rate.NewLimiter(r, burst)
	}
}

// WithETagCacheSize overrides the LRU capacity used for ETag caching.
// A non-positive size falls back to the default.
func WithETagCacheSize(n int) Option {
	return func(c *Client) {
		if n <= 0 {
			n = defaultETagCacheSize
		}
		cache, err := lru.New[string, cacheEntry](n)
		if err == nil {
			c.etagCache = cache
		}
	}
}

// WithHTTPClient swaps the underlying [*http.Client]. This is intended
// for tests that need to inject [httptest.NewServer] transports; the
// supplied client's [http.Client.CheckRedirect] is preserved when
// non-nil so test-only allowlists can be installed.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// New constructs a [Client] with safe defaults for the GitHub API.
func New(opts ...Option) *Client {
	transport := &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		MaxConnsPerHost:     32,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	c := &Client{
		userAgent:    fmt.Sprintf("ghscan/%s", version),
		apiVersion:   apiVersion,
		accept:       "application/vnd.github+json",
		maxBodyBytes: defaultMaxBodyBytes,
		limiter:      rate.NewLimiter(rate.Every(defaultRateInterval), defaultRateBurst),
	}

	cache, _ := lru.New[string, cacheEntry](defaultETagCacheSize)
	c.etagCache = cache

	c.httpClient = &http.Client{
		Timeout:       60 * time.Second,
		Transport:     transport,
		CheckRedirect: redirectGuard,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Ensure even caller-supplied http.Clients carry our redirect guard
	// unless the caller has explicitly installed their own. Tests that
	// inject a non-default CheckRedirect are honored.
	if c.httpClient.CheckRedirect == nil {
		c.httpClient.CheckRedirect = redirectGuard
	}

	return c
}

// redirectGuard enforces the scheme + host allowlist on every redirect
// hop. The 10-hop default ceiling from net/http is preserved by the
// length comparison.
func redirectGuard(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("httpclient: stopped after 10 redirects")
	}
	if req.URL == nil {
		return ErrRedirectBlocked
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q", ErrRedirectBlocked, req.URL.Scheme)
	}
	host := req.URL.Hostname()
	if _, ok := allowedHostsExact[host]; ok {
		return nil
	}
	if strings.HasSuffix(host, allowedHostSuffix) && host != allowedHostSuffix[1:] {
		return nil
	}
	return fmt.Errorf("%w: host %q", ErrRedirectBlocked, host)
}

// CloseIdleConnections closes any idle keep-alive connections held by
// the underlying [*http.Client]. It mirrors [http.Client.CloseIdleConnections]
// and is safe to call from tests that must reap persistConn goroutines
// before [goleak] verification.
func (c *Client) CloseIdleConnections() {
	if c == nil || c.httpClient == nil {
		return
	}
	c.httpClient.CloseIdleConnections()
}

// Get performs an HTTP GET. It is shorthand for constructing a
// [http.Request] and calling [Client.Do].
func (c *Client) Get(ctx context.Context, url string) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("httpclient: build request: %w", err)
	}
	return c.Do(ctx, req)
}

// Do executes a single HTTP request honoring the rate limiter, ETag
// cache and singleflight deduplication. Only GET responses participate
// in caching and deduplication; other methods bypass both.
//
// The caller receives the (decoded, capped) response body and the
// [*http.Response] minus its Body, which has already been drained and
// closed. If a cached body is returned, [http.Response.StatusCode] is
// 200 and the response Header is the cached header.
func (c *Client) Do(ctx context.Context, req *http.Request) ([]byte, *http.Response, error) {
	if req == nil {
		return nil, nil, errors.New("httpclient: nil request")
	}
	c.applyDefaultHeaders(req)

	if req.Method != http.MethodGet {
		return c.executeOnce(ctx, req)
	}

	key := canonicalKey(req)

	// singleflight collapses duplicate in-flight GETs to the same URL.
	v, err, _ := c.sf.Do(key, func() (any, error) {
		if c.etagCache != nil {
			if entry, ok := c.etagCache.Get(key); ok {
				if req.Header.Get("If-None-Match") == "" && entry.etag != "" {
					req.Header.Set("If-None-Match", entry.etag)
				}
			}
		}
		body, resp, err := c.executeOnce(ctx, req) //nolint:bodyclose // executeOnce drains and replaces resp.Body with http.NoBody before returning.
		if err != nil {
			return nil, err
		}
		return &result{body: body, resp: resp}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	r, ok := v.(*result)
	if !ok || r == nil {
		return nil, nil, errors.New("httpclient: internal: singleflight returned unexpected type")
	}
	return r.body, r.resp, nil
}

type result struct {
	body []byte
	resp *http.Response
}

func (c *Client) applyDefaultHeaders(req *http.Request) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if req.Header.Get("X-GitHub-Api-Version") == "" {
		req.Header.Set("X-GitHub-Api-Version", c.apiVersion)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", c.accept)
	}
}

func (c *Client) executeOnce(ctx context.Context, req *http.Request) ([]byte, *http.Response, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, nil, fmt.Errorf("httpclient: rate limiter: %w", err)
	}

	// SSRF mitigations live in (a) the URL allowlist enforced by
	// redirectGuard on every redirect, (b) the scheme/host pinning
	// callers do at the request layer, and (c) the body cap below.
	resp, err := c.httpClient.Do(req) // #nosec G107,G704 -- SSRF mitigations: redirect allowlist + caller-validated URLs
	if err != nil {
		return nil, nil, fmt.Errorf("httpclient: do: %w", err)
	}
	// http.Client.Do guarantees resp != nil when err == nil; the
	// defensive check makes that contract explicit for static analyzers
	// that cannot model the net/http documentation directly.
	if resp == nil {
		return nil, nil, errors.New("httpclient: nil response with nil error")
	}

	c.reconcileRateLimit(resp)

	key := canonicalKey(req)

	// 304 Not Modified — return cached body if available.
	if resp.StatusCode == http.StatusNotModified && req.Method == http.MethodGet && c.etagCache != nil {
		if entry, ok := c.etagCache.Get(key); ok {
			// Drain anything the server may have sent, ignoring it.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxBodyBytes))
			_ = resp.Body.Close()
			synth := &http.Response{
				Status:     "200 OK (httpclient cache)",
				StatusCode: http.StatusOK,
				Proto:      resp.Proto,
				ProtoMajor: resp.ProtoMajor,
				ProtoMinor: resp.ProtoMinor,
				Header:     entry.header.Clone(),
				Body:       http.NoBody,
				Request:    req,
			}
			return entry.body, synth, nil
		}
	}

	body, readErr := ReadAllBounded(resp.Body, c.maxBodyBytes)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, nil, readErr
	}

	// Detach the body — callers see []byte; resp.Body has been drained.
	resp.Body = http.NoBody

	if req.Method == http.MethodGet && resp.StatusCode == http.StatusOK && c.etagCache != nil {
		if etag := resp.Header.Get("ETag"); etag != "" {
			c.etagCache.Add(key, cacheEntry{
				etag:   etag,
				body:   append([]byte(nil), body...),
				header: resp.Header.Clone(),
			})
		}
	}

	return body, resp, nil
}

// reconcileRateLimit consults the X-RateLimit-Remaining and
// X-RateLimit-Reset response headers to back off the local limiter
// when GitHub reports quota pressure.
func (c *Client) reconcileRateLimit(resp *http.Response) {
	if resp == nil || resp.Header == nil {
		return
	}
	remainingStr := resp.Header.Get("X-RateLimit-Remaining")
	resetStr := resp.Header.Get("X-RateLimit-Reset")
	if remainingStr == "" || resetStr == "" {
		return
	}
	remaining, err := strconv.Atoi(remainingStr)
	if err != nil || remaining > 5 {
		return
	}
	resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
	if err != nil {
		return
	}
	reset := time.Unix(resetUnix, 0)
	wait := time.Until(reset)
	if wait <= 0 || wait > time.Hour {
		return
	}

	// Reserve enough tokens to stall the limiter until reset. We hold
	// limiterMu so a concurrent SetLimit and a Wait can't interleave.
	c.limiterMu.Lock()
	defer c.limiterMu.Unlock()
	r := c.limiter.ReserveN(time.Now(), c.limiter.Burst())
	if !r.OK() {
		return
	}
	// Cancel any reservation longer than wait so we don't over-delay.
	if r.Delay() > wait {
		r.Cancel()
	}
}

// canonicalKey returns the cache/singleflight key for a request.
func canonicalKey(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	return req.URL.String()
}

// ReadAllBounded reads from r until io.EOF or until maxBytes+1 bytes
// have been read, whichever comes first. If maxBytes is non-positive,
// [defaultMaxBodyBytes] is used.
//
// If the limit is exceeded, [ErrBodyTooLarge] is returned along with
// the bytes read up to the cap.
func ReadAllBounded(r io.Reader, maxBytes int64) ([]byte, error) {
	if r == nil {
		return nil, errors.New("httpclient: nil reader")
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxBodyBytes
	}
	// Read maxBytes+1 so we can detect overflow precisely.
	limited := io.LimitReader(r, maxBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return buf, fmt.Errorf("httpclient: read body: %w", err)
	}
	if int64(len(buf)) > maxBytes {
		return buf[:maxBytes], ErrBodyTooLarge
	}
	return buf, nil
}
