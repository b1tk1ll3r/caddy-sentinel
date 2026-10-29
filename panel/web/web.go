// Package web embeds the frontend (plain ES modules, no build step).
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var dist embed.FS

// FS returns the static files.
func FS() fs.FS {
	sub, _ := fs.Sub(dist, "static")
	return sub
}
