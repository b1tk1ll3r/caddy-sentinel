package core

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// noMetadataDialer is the dialer for monitors and feeds: internal services
// stay reachable (that is what monitors are for), but link-local addresses
// – cloud metadata services with instance credentials (169.254.169.254,
// fd00:ec2::254) – never. Checked at connect time, after DNS and on every
// redirect.
func noMetadataDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			a, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			if blockedTarget(a.Unmap()) {
				return fmt.Errorf("Ziel %s ist gesperrt (link-lokal/Metadaten-Dienst)", a)
			}
			return nil
		},
	}
}

var metadataV6 = netip.MustParseAddr("fd00:ec2::254")

func blockedTarget(a netip.Addr) bool {
	return a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a == metadataV6 || a.IsUnspecified()
}

// guardedProxy is http.ProxyFromEnvironment with the same target check as
// noMetadataDialer: behind a proxy the dialer only sees the proxy, so the
// target host is resolved and checked here (for every request, redirects
// included). If the name does not resolve locally (proxy-only networks),
// the proxy decides – except for well-known metadata names.
func guardedProxy(req *http.Request) (*url.URL, error) {
	p, err := http.ProxyFromEnvironment(req)
	if err != nil || p == nil {
		return p, err
	}
	host := strings.TrimSuffix(strings.ToLower(req.URL.Hostname()), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		if blockedTarget(a.Unmap()) {
			return nil, fmt.Errorf("Ziel %s ist gesperrt (link-lokal/Metadaten-Dienst)", a)
		}
		return p, nil
	}
	if host == "metadata" || host == "metadata.google.internal" || host == "instance-data" || strings.HasPrefix(host, "instance-data.") {
		return nil, fmt.Errorf("Ziel %s ist gesperrt (Metadaten-Dienst)", host)
	}
	ips, err := net.DefaultResolver.LookupNetIP(req.Context(), "ip", host)
	if err == nil {
		for _, a := range ips {
			if blockedTarget(a.Unmap()) {
				return nil, fmt.Errorf("Ziel %s (%s) ist gesperrt (link-lokal/Metadaten-Dienst)", host, a)
			}
		}
	}
	return p, nil
}
