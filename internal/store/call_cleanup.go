package store

import (
	"context"
	"time"
)

// StartCallCleanup runs the call-record retention job at local midnight.
// The logger is called when a cleanup query fails; a failed run is retried at
// the next midnight without affecting request handling.
func (s *Store) StartCallCleanup(ctx context.Context, logger func(string, ...any)) {
	go func() {
		for {
			now := time.Now()
			timer := time.NewTimer(time.Until(nextLocalMidnight(now)))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			if _, err := s.DeleteExpiredCalls(ctx, time.Now()); err != nil && logger != nil {
				logger("call record cleanup failed: %v", err)
			}
		}
	}()
}

func nextLocalMidnight(now time.Time) time.Time {
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
}
