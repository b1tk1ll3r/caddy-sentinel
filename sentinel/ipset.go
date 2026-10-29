package sentinel

import (
	"net/netip"
	"strings"
)

// ipSet is an immutable set of IPs and prefixes with an optional value per entry.
type ipSet[T any] struct {
	exact    map[netip.Addr]T
	prefixes []prefixEntry[T]
}

type prefixEntry[T any] struct {
	p netip.Prefix
	v T
}

func newIPSet[T any]() *ipSet[T] {
	return &ipSet[T]{exact: map[netip.Addr]T{}}
}

// add parses an IP or CIDR. Invalid entries are ignored and reported via ok=false.
func (s *ipSet[T]) add(entry string, v T) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		if err != nil {
			return false
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.IsSingleIP() {
			s.exact[p.Addr()] = v
			return true
		}
		s.prefixes = append(s.prefixes, prefixEntry[T]{p, v})
		return true
	}
	a, err := netip.ParseAddr(entry)
	if err != nil {
		return false
	}
	s.exact[a.Unmap()] = v
	return true
}

func (s *ipSet[T]) lookup(a netip.Addr) (T, bool) {
	var zero T
	if s == nil || !a.IsValid() {
		return zero, false
	}
	if v, ok := s.exact[a]; ok {
		return v, true
	}
	for _, e := range s.prefixes {
		if e.p.Contains(a) {
			return e.v, true
		}
	}
	return zero, false
}

func (s *ipSet[T]) empty() bool {
	return s == nil || (len(s.exact) == 0 && len(s.prefixes) == 0)
}

func parseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		// may contain a zone or port
		if ap, err2 := netip.ParseAddrPort(s); err2 == nil {
			return ap.Addr().Unmap()
		}
		return netip.Addr{}
	}
	return a.Unmap()
}
