package server

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var dist embed.FS

func StaticFiles() http.FileSystem {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return http.FS(dist)
	}
	return http.FS(sub)
}
