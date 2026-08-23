package spa

import (
	"fmt"
	"math"
	"time"
)

// RetryClient wraps a Client with exponential backoff retry logic.
type RetryClient struct {
	client     *Client
	maxRetries int
	baseDelay  time.Duration
}

// NewRetryClient creates a retry-capable SPA client. maxRetries defaults to 3,
// baseDelay defaults to 1s. Delay doubles on each attempt (1s, 2s, 4s, ...).
func NewRetryClient(secret string, maxRetries int, baseDelay time.Duration) *RetryClient {
	if maxRetries == 0 {
		maxRetries = 3
	}
	if baseDelay == 0 {
		baseDelay = 1 * time.Second
	}
	return &RetryClient{
		client:     NewClient(secret, 3*time.Second),
		maxRetries: maxRetries,
		baseDelay:  baseDelay,
	}
}

// Wake sends a SPA wake-up with retries. Returns the first successful result
// or the last error after all attempts are exhausted.
func (rc *RetryClient) Wake(gatewayAddr string) (*Result, error) {
	var lastErr error
	for attempt := 0; attempt <= rc.maxRetries; attempt++ {
		if attempt > 0 {
			delay := rc.baseDelay * time.Duration(math.Pow(2, float64(attempt-1)))
			time.Sleep(delay)
		}
		result, err := rc.client.Wake(gatewayAddr)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all %d attempts failed: %w", rc.maxRetries+1, lastErr)
}
