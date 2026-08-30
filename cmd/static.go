// Static file serving for the embedded web assets: aggressive browser caching
// with directory listings disabled.
package cmd

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

// fileServer serves static files with browser caching and directory listing
// disabled (m9). Static files are embedded at build time so they can be
// cached aggressively.
func fileServer(r chi.Router, path string, root http.FileSystem) {
	fs := http.StripPrefix(path, http.FileServer(noDirListing{root}))
	r.Get(path+"/*", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fs.ServeHTTP(w, r)
	})
}

// noDirListing wraps an http.FileSystem so that directory requests return 404
// instead of a file listing. Regular file access is unaffected.
type noDirListing struct {
	http.FileSystem
}

func (nd noDirListing) Open(name string) (http.File, error) {
	f, err := nd.FileSystem.Open(name)
	if err != nil {
		return nil, err
	}
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if stat.IsDir() {
		_ = f.Close()
		return nil, os.ErrNotExist
	}
	return f, nil
}
