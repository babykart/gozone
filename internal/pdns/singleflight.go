package pdns

import (
	"fmt"
	"sync"
)

// call represents an in-flight or completed deduplicated call.
type call struct {
	done chan struct{} // closed when the leader's fn returns
	val  any
	err  error
}

// singleFlight deduplicates concurrent calls with the same key so that only the
// leader invokes fn; followers wait for and share the leader's result. This is
// the cache-miss thundering-herd mitigation (m44): N concurrent reads of a cold
// cache key produce a single PowerDNS call rather than N.
//
// It is a minimal hand-rolled equivalent of golang.org/x/sync/singleflight,
// kept internal to avoid adding a dependency (the project deliberately vendors
// a minimal module set). The mutex is held only to register/look up/deregister
// a call — never while fn runs — so a slow leader on one key never blocks an
// unrelated key.
type singleFlight struct {
	mu       sync.Mutex
	inflight map[string]*call
}

// Do executes fn for key exactly once among concurrent callers; followers
// receive the leader's result verbatim. A panic inside fn is recovered and
// surfaced as an error to the leader and all followers, so a buggy fetch
// cannot deadlock followers on an unclosed done channel.
func (g *singleFlight) Do(key string, fn func() (any, error)) (any, error) {
	g.mu.Lock()
	if g.inflight == nil {
		g.inflight = make(map[string]*call)
	}
	if c, ok := g.inflight[key]; ok {
		g.mu.Unlock()
		<-c.done
		return c.val, c.err
	}
	c := &call{done: make(chan struct{})}
	g.inflight[key] = c
	g.mu.Unlock()

	// Run fn with a recover so the done channel is always closed.
	func() {
		defer func() {
			if r := recover(); r != nil {
				c.val, c.err = nil, fmt.Errorf("singleflight: recovered panic: %v", r)
			}
			close(c.done)
			g.mu.Lock()
			delete(g.inflight, key)
			g.mu.Unlock()
		}()
		c.val, c.err = fn()
	}()
	return c.val, c.err
}
