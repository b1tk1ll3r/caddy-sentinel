package sentinel

// Crawler handling: AI and SEO crawlers can be blocked or slowed down per
// policy, and requests that pretend to be a search engine bot are checked
// by reverse DNS (PTR) plus forward confirmation, the method Google, Bing,
// Apple and others document for verifying their crawlers.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/b1tk1ll3r/caddy-sentinel/sentinel/protocol"
)

// ---------------------------------------------------------------- verification

type botVerdict struct {
	ok      bool
	host    string
	expires time.Time
}

type botVerifier struct {
	mu       sync.Mutex
	cache    map[string]botVerdict // ip|name -> verdict
	inflight map[string]chan struct{}
	resolver *net.Resolver
}

func newBotVerifier() *botVerifier {
	return &botVerifier{cache: map[string]botVerdict{}, inflight: map[string]chan struct{}{}, resolver: net.DefaultResolver}
}

// verify checks that addr belongs to the search engine. It returns
// ok=false only for a definite mismatch; resolver failures fail open.
func (v *botVerifier) verify(addr netip.Addr, b *protocol.BotClass) (ok bool, host string) {
	if len(b.Domains) == 0 || !addr.IsValid() {
		return true, ""
	}
	key := addr.String() + "|" + b.Name
	for {
		v.mu.Lock()
		if d, hit := v.cache[key]; hit && time.Now().Before(d.expires) {
			v.mu.Unlock()
			return d.ok, d.host
		}
		if ch, busy := v.inflight[key]; busy {
			v.mu.Unlock()
			<-ch
			continue
		}
		ch := make(chan struct{})
		v.inflight[key] = ch
		if len(v.cache) > 20000 { // keep memory bounded
			now := time.Now()
			for k, d := range v.cache {
				if now.After(d.expires) {
					delete(v.cache, k)
				}
			}
			if len(v.cache) > 20000 {
				v.cache = map[string]botVerdict{}
			}
		}
		v.mu.Unlock()

		d := v.lookup(addr, b)
		v.mu.Lock()
		v.cache[key] = d
		delete(v.inflight, key)
		close(ch)
		v.mu.Unlock()
		return d.ok, d.host
	}
}

func (v *botVerifier) lookup(addr netip.Addr, b *protocol.BotClass) botVerdict {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	names, err := v.resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return botVerdict{ok: false, host: "kein PTR-Eintrag", expires: time.Now().Add(6 * time.Hour)}
		}
		// DNS not available: let the request through, ask again soon
		return botVerdict{ok: true, host: "", expires: time.Now().Add(time.Minute)}
	}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		match := false
		for _, d := range b.Domains {
			if strings.HasSuffix(n, d) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		ips, err := v.resolver.LookupNetIP(ctx, "ip", n)
		if err != nil {
			return botVerdict{ok: true, host: n, expires: time.Now().Add(time.Minute)}
		}
		for _, ip := range ips {
			if ip.Unmap() == addr.Unmap() {
				return botVerdict{ok: true, host: n, expires: time.Now().Add(24 * time.Hour)}
			}
		}
	}
	host := ""
	if len(names) > 0 {
		host = strings.TrimSuffix(names[0], ".")
	}
	return botVerdict{ok: false, host: host, expires: time.Now().Add(6 * time.Hour)}
}
