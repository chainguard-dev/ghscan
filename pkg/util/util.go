package util

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cenkalti/backoff"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/viper"
)

func TryBase64Decode(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(decoded) {
		return "", fmt.Errorf("decoded content is not valid UTF8")
	}
	doubleDecoded, err := base64.StdEncoding.DecodeString(string(decoded))
	if err != nil {
		return "", err
	}
	return string(doubleDecoded), nil
}

func WithRetry(ctx context.Context, logger *clog.Logger, operation func() error) error {
	maxRetries := viper.GetInt("max_retries")
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 1 * time.Second
	b.MaxInterval = 10 * time.Second
	b.MaxElapsedTime = 2 * time.Minute

	var attempt int
	return backoff.Retry(func() error {
		attempt++
		err := operation()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return backoff.Permanent(fmt.Errorf("operation timed out: %w", err))
			}

			if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "403") {
				retryAfter := min(5*time.Second*time.Duration(attempt), 30*time.Second)
				logger.Warnf("Hit rate limit, waiting %v before retry", retryAfter)
				time.Sleep(retryAfter)
			} else {
				logger.Warnf("Operation failed (attempt %d/%d): %v", attempt, maxRetries+1, err)
			}
		}

		return err
	}, backoff.WithMaxRetries(backoff.WithContext(b, ctx), uint64(maxRetries))) // #nosec G115 // ignore Type conversion which leads to integer overflow
}
