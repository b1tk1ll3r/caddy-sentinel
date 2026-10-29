// Custom Caddy build including the Sentinel module.
// Build: see ../build.sh (or: go build -o caddy .)
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/b1tk1ll3r/caddy-sentinel/sentinel"
)

func main() {
	caddycmd.Main()
}
