package util

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cenkalti/backoff/v5"
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
	var attempt int

	wrappedOperation := func() (interface{}, error) {
		if ctx.Err() != nil {
			return nil, backoff.Permanent(ctx.Err())
		}

		attempt++
		err := operation()
		if err != nil {
			if attempt > maxRetries {
				return nil, backoff.Permanent(fmt.Errorf("max retries exceeded: %w", err))
			}

			if ctx.Err() == context.DeadlineExceeded {
				return nil, backoff.Permanent(fmt.Errorf("operation timed out: %w", err))
			}

			if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "403") {
				retryAfter := min(5*time.Second*time.Duration(attempt), 30*time.Second)
				logger.Warnf("Hit rate limit, waiting %v before retry", retryAfter)
				return nil, backoff.RetryAfter(int(retryAfter.Seconds()))
			}

			logger.Warnf("Operation failed (attempt %d/%d): %v", attempt, maxRetries+1, err)
		}
		return nil, err
	}

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 1 * time.Second
	b.MaxInterval = 10 * time.Second

	_, err := backoff.Retry(ctx, wrappedOperation, backoff.WithBackOff(b))
	return err
}
