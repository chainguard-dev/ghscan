// Package request wraps GitHub API calls in an exponential-backoff
// retry loop that honors context cancellation, rate-limit errors, and
// a caller-supplied max-retry budget.
//
// Public surface:
//
//   - [WithRetryN] runs the supplied operation under
//     [github.com/cenkalti/backoff/v5] with a 1s initial interval and
//     a 10s cap. The retry budget is passed explicitly by the caller
//     so this package depends on no global configuration state.
//
// Retry layering:
//
//   - This package's [WithRetryN] is the right tool for go-github SDK
//     calls. The SDK surfaces typed envelopes such as
//     [github.com/google/go-github/v86/github.RateLimitError] and
//     [github.com/google/go-github/v86/github.AbuseRateLimitError]
//     that this loop inspects. Secondary rate limits surface as a
//     plain [github.com/google/go-github/v86/github.ErrorResponse]
//     whose embedded HTTP response carries a Retry-After header; that
//     case is honored as well, capped at 30 seconds.
//   - For raw [*net/http.Response] retry semantics (status code
//     403/429/5xx with Retry-After honoring) callers should use
//     [github.com/chainguard-dev/ghscan/pkg/httpclient.Client.DoWithRetry]
//     instead. The two retry layers are deliberately split: SDK-level
//     errors carry structured metadata that a raw response loop cannot
//     observe, and raw responses carry headers that the SDK envelope
//     hides.
//
// Invariants:
//
//   - Context cancellation is propagated as a permanent error so the
//     backoff loop unwinds immediately.
//   - DeadlineExceeded is treated as permanent: a stuck operation
//     does not consume the entire retry budget.
//   - Rate-limit detection is keyed off concrete error types (and the
//     Retry-After header on [github.com/google/go-github/v86/github.ErrorResponse]),
//     never substring matches on the error string.
package request
