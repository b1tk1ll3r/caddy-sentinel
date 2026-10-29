// Package iprange provides an immutable IP range set with O(log n) lookups,
// used for large lists such as threat-intelligence feeds.
package iprange

import (
	"bufio"
	"io"
	"net/netip"
	"sort"
	"strings"
)

// Set is an immutable set of IP ranges.
type Set struct {
	v4 []r32
	v6 []r128
}

type r32 struct{ lo, hi uint32 }

type u128 struct{ hi, lo uint64 }

type r128 struct{ lo, hi u128 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }

func (a u128) inc() u128 {
	if a.lo == ^uint64(0) {
		return u128{a.hi + 1, 0}
	}
	return u128{a.hi, a.lo + 1}
}

func addr128(a netip.Addr) u128 {
	b := a.As16()
	var h, l uint64
	for i := 0; i < 8; i++ {
		h = h<<8 | uint64(b[i])
		l = l<<8 | uint64(b[i+8])
	}
	return u128{h, l}
}

func addr32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Parse reads one IP/CIDR per line ("#" and ";" start comments;
// anything after the first whitespace is ignored, so most blocklist formats
// such as Spamhaus DROP or FireHOL netsets work as-is).
func Parse(r io.Reader) (*Set, int) {
	var v4 []r32
	var v6 []r128
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if i := strings.IndexAny(line, " \t;#,"); i > 0 {
			line = line[:i]
		}
		var p netip.Prefix
		var err error
		if strings.Contains(line, "/") {
			p, err = netip.ParsePrefix(line)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(line)
			if err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil {
			continue
		}
		p = p.Masked()
		a := p.Addr()
		if a.Is4In6() {
			a = a.Unmap()
			p = netip.PrefixFrom(a, p.Bits()-96)
		}
		if a.Is4() {
			lo := addr32(a)
			hi := lo | (^uint32(0) >> uint(p.Bits()))
			if p.Bits() == 0 {
				hi = ^uint32(0)
			}
			v4 = append(v4, r32{lo, hi})
		} else {
			lo := addr128(a)
			bits := p.Bits()
			hi := lo
			// set host bits
			if bits < 64 {
				hi.hi |= ^uint64(0) >> uint(bits)
				hi.lo = ^uint64(0)
			} else if bits < 128 {
				hi.lo |= ^uint64(0) >> uint(bits-64)
			}
			v6 = append(v6, r128{lo, hi})
		}
	}
	rs := &Set{v4: merge32(v4), v6: merge128(v6)}
	return rs, len(v4) + len(v6)
}

func merge32(in []r32) []r32 {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].lo < in[j].lo })
	out := []r32{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi || (last.hi != ^uint32(0) && r.lo == last.hi+1) {
			if r.hi > last.hi {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func merge128(in []r128) []r128 {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].lo.less(in[j].lo) })
	out := []r128{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if !last.hi.less(r.lo) || last.hi.inc() == r.lo {
			if last.hi.less(r.hi) {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *Set) Contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		x := addr32(a)
		i := sort.Search(len(s.v4), func(i int) bool { return s.v4[i].hi >= x })
		return i < len(s.v4) && s.v4[i].lo <= x
	}
	x := addr128(a)
	i := sort.Search(len(s.v6), func(i int) bool { return !s.v6[i].hi.less(x) })
	return i < len(s.v6) && !x.less(s.v6[i].lo)
}

func (s *Set) Size() int {
	if s == nil {
		return 0
	}
	return len(s.v4) + len(s.v6)
}
