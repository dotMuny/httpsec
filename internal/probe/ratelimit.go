package probe

import (
	"context"
	"sync"
	"time"
)

// Limiter enforces a minimum interval between requests to the same host.
//
// This is deliberately the simplest thing that satisfies the responsible-use
// requirement: httpsec makes a fixed, small number of requests per target, so
// a token bucket would add configuration surface without changing behaviour.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     map[string]time.Time
}

// NewLimiter returns a limiter allowing at most rate requests per second per
// host. A rate of zero or less disables limiting.
func NewLimiter(rate float64) *Limiter {
	l := &Limiter{next: make(map[string]time.Time)}
	if rate > 0 {
		l.interval = time.Duration(float64(time.Second) / rate)
	}
	return l
}

// Wait blocks until the caller may make a request to host, or until ctx is
// done.
func (l *Limiter) Wait(ctx context.Context, host string) error {
	if l == nil || l.interval <= 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := time.Now()
	at, ok := l.next[host]
	if !ok || at.Before(now) {
		at = now
	}
	l.next[host] = at.Add(l.interval)
	l.mu.Unlock()

	delay := time.Until(at)
	if delay <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
