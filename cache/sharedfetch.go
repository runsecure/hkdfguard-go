package cache

import (
	"context"
	"sync"
)

// sharedFetches runs at most one fetch per key at a time: a lookup that misses while a fetch of the
// same key is running waits for that fetch instead of starting another, so a burst of lookups for
// an uncached name costs the source one call. A RemoteCache keys by the secret being fetched, so
// every key of one secret shares it; a Source-backed store keys by the name.
//
// The fetch runs with the context of the lookup that started it. A waiter whose own context ends
// stops waiting with that context's error; a waiter whose shared fetch failed only because the
// starter's context ended starts a fetch of its own, since nothing was wrong with the source. The
// zero value is ready to use.
type sharedFetches struct {
	mu      sync.Mutex
	running map[string]*fetch
}

// fetch is one running fetch, which every lookup that joined it waits on.
type fetch struct {
	done      chan struct{}
	populated bool
	err       error
	cancelled bool // failed because the starter's context ended
}

// do runs run for key, or waits for the run already in progress for it, and returns what that run
// reported: whether it stored anything, and its error.
func (s *sharedFetches) do(ctx context.Context, key string, run func(ctx context.Context) (bool, error)) (bool, error) {
	for {
		s.mu.Lock()
		if s.running == nil {
			s.running = map[string]*fetch{}
		}
		running := s.running[key]
		if running == nil {
			f := &fetch{done: make(chan struct{})}
			s.running[key] = f
			s.mu.Unlock()
			return s.run(ctx, key, f, run)
		}
		s.mu.Unlock()

		select {
		case <-running.done:
			if running.cancelled && ctx.Err() == nil {
				continue // cancelled by the lookup that started it, not this one: fetch again
			}
			return running.populated, running.err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

// run makes fetch f, then releases every lookup waiting on it, whatever the outcome.
func (s *sharedFetches) run(ctx context.Context, key string, f *fetch, run func(ctx context.Context) (bool, error)) (populated bool, err error) {
	defer func() {
		f.populated, f.err = populated, err
		f.cancelled = err != nil && ctx.Err() != nil
		s.mu.Lock()
		delete(s.running, key)
		s.mu.Unlock()
		close(f.done)
	}()
	return run(ctx)
}
