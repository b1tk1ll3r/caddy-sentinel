package sentinel

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("sentinel", parseHandlerCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("sentinel", httpcaddyfile.After, "tracing")
	httpcaddyfile.RegisterGlobalOption("sentinel", parseGlobalOption)
}

// UnmarshalCaddyfile parses:
//
//	sentinel [<policy>]
//	sentinel {
//	    policy <id>
//	}
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	if d.NextArg() {
		h.Policy = d.Val()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "policy":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.Policy = d.Val()
		default:
			return d.Errf("unknown sentinel subdirective %q", d.Val())
		}
	}
	return nil
}

func parseHandlerCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var s Handler
	err := s.UnmarshalCaddyfile(h.Dispenser)
	return &s, err
}

// parseGlobalOption parses:
//
//	sentinel {
//	    panel       <url>
//	    token       <token>
//	    token_file  <path>
//	    cache_file  <path>
//	    fail_closed
//	}
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := new(App)
	d.Next()
	if d.NextArg() {
		app.Panel = d.Val()
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "panel":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Panel = d.Val()
		case "token":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Token = d.Val()
		case "token_file":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.TokenFile = d.Val()
		case "cache_file":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.CacheFile = d.Val()
		case "fail_closed":
			app.FailClosed = true
		case "geoip_country":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.GeoIPCountry = d.Val()
		case "geoip_asn":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.GeoIPASN = d.Val()
		case "remote":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Remote = d.Val()
		case "caddyfile":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Caddyfile = d.Val()
		case "admin":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Admin = d.Val()
		default:
			return nil, d.Errf("unknown sentinel option %q", d.Val())
		}
	}
	raw, err := json.Marshal(app)
	if err != nil {
		return nil, err
	}
	return httpcaddyfile.App{Name: "sentinel", Value: caddyconfig.JSON(json.RawMessage(raw), nil)}, nil
}

var _ caddyfile.Unmarshaler = (*Handler)(nil)
