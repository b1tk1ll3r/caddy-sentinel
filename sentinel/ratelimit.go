package sentinel

import (
	"crypto/sha256"
	"hash/maphash"
	"sort"
	"sync"
	"time"
)

// rateLimiter implements a sliding-window (two fixed windows, weighted)
// counter keyed by arbitrary strings. It is sharded to reduce contention.
type rateLimiter struct {
	seed   maphash.Seed
	shards [64]rlShard
}

type rlShard struct {
	mu sync.Mutex
	m  map[string]*rlEntry
}

type rlEntry struct {
	windowStart int64 // unix nanos of current window start
	curr, prev  int
	window      int64 // window length in nanos
	lastSeen    int64
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{seed: maphash.MakeSeed()}
	for i := range rl.shards {
		rl.shards[i].m = make(map[string]*rlEntry)
	}
	return rl
}

// allow registers one event for key and reports whether it is within limit
// events per window. It also returns the estimated current count and the
// seconds until a slot frees up (for Retry-After).
func (rl *rateLimiter) allow(key string, limit int, window time.Duration, now time.Time) (bool, int, int) {
	if limit <= 0 || window <= 0 {
		return true, 0, 0
	}
	// fixed-size keys: paths and header values are attacker-controlled
	sum := sha256.Sum256([]byte(key))
	key = string(sum[:16])
	sh := &rl.shards[maphash.String(rl.seed, key)%uint64(len(rl.shards))]
	n := now.UnixNano()
	w := int64(window)

	sh.mu.Lock()
	defer sh.mu.Unlock()
	e := sh.m[key]
	if e == nil || e.window != w {
		if e == nil && len(sh.m) >= maxRLEntriesPerShard {
			sh.evict(n)
		}
		e = &rlEntry{windowStart: n - n%w, window: w}
		sh.m[key] = e
	}
	// roll windows
	start := n - n%w
	switch {
	case start == e.windowStart:
	case start-e.windowStart == w:
		e.prev, e.curr, e.windowStart = e.curr, 0, start
	default:
		e.prev, e.curr, e.windowStart = 0, 0, start
	}
	e.lastSeen = n
	elapsed := float64(n-e.windowStart) / float64(w)
	estimate := float64(e.prev)*(1-elapsed) + float64(e.curr)
	if int(estimate) >= limit {
		retry := int((w - (n - e.windowStart)) / int64(time.Second))
		if retry < 1 {
			retry = 1
		}
		return false, int(estimate), retry
	}
	e.curr++
	return true, int(estimate) + 1, 0
}

// maxRLEntriesPerShard bounds memory (64 shards ≈ 3.2 M keys, ~300 MB worst case).
const maxRLEntriesPerShard = 50000

// evict makes room in a full shard: expired entries first, otherwise the
// least recently seen eighth. Called with sh.mu held.
func (sh *rlShard) evict(n int64) {
	for k, e := range sh.m {
		if n-e.lastSeen > 2*e.window {
			delete(sh.m, k)
		}
	}
	if len(sh.m) < maxRLEntriesPerShard {
		return
	}
	seen := make([]int64, 0, len(sh.m))
	for _, e := range sh.m {
		seen = append(seen, e.lastSeen)
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })
	cut := seen[len(seen)/8]
	for k, e := range sh.m {
		if e.lastSeen <= cut {
			delete(sh.m, k)
		}
	}
}

// gc removes entries that have not been seen for two windows.
func (rl *rateLimiter) gc(now time.Time) {
	n := now.UnixNano()
	for i := range rl.shards {
		sh := &rl.shards[i]
		sh.mu.Lock()
		for k, e := range sh.m {
			if n-e.lastSeen > 2*e.window {
				delete(sh.m, k)
			}
		}
		sh.mu.Unlock()
	}
}

func (rl *rateLimiter) size() int {
	t := 0
	for i := range rl.shards {
		rl.shards[i].mu.Lock()
		t += len(rl.shards[i].m)
		rl.shards[i].mu.Unlock()
	}
	return t
}
