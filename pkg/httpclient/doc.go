// Package httpclient provides a hardened HTTP client tailored to the
// GitHub REST API surface that ghscan consumes (Actions runs, jobs,
// and log artifact downloads).
//
// The client centralizes:
//
//   - A locked-down [http.Transport] (TLS >= 1.2, capped idle connections).
//   - A scheme/host allowlist enforced via [http.Client.CheckRedirect] so
//     redirects can never escape api.github.com or its log-serving CDN
//     hostnames.
//   - Default request headers (User-Agent, Accept,
//     X-GitHub-Api-Version) applied if the caller has not already set
//     them.
//   - Token-bucket rate limiting using [golang.org/x/time/rate],
//     reconciled from response X-RateLimit-Remaining /
//     X-RateLimit-Reset headers.
//   - An ETag cache backed by [github.com/hashicorp/golang-lru/v2]
//     that transparently returns cached bodies on HTTP 304.
//   - In-flight request deduplication via
//     [golang.org/x/sync/singleflight] keyed by the canonical URL.
//   - Body size capping via [ReadAllBounded].
//
// Retry layering:
//
//   - [Client.Get] performs a single HTTP attempt. For raw response
//     retry on 403/429/5xx with Retry-After honoring, callers should
//     use [Client.DoWithRetry], which inspects the [*http.Response]
//     status code and headers directly.
//   - For go-github SDK calls (which return typed envelopes such as
//     [github.com/google/go-github/v86/github.RateLimitError]) callers
//     should use [github.com/chainguard-dev/ghscan/internal/request.WithRetryN]
//     instead. The two retry layers are deliberately split: SDK-level
//     errors carry structured metadata that a raw response loop cannot
//     observe, and raw responses carry headers that the SDK envelope
//     hides.
package httpclient
