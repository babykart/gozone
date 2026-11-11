// Static file serving for the embedded web assets: day-long browser caching
// on successful responses only, with directory listings disabled. Error
// responses (404s and other failures) deliberately carry no Cache-Control so
// a file that appears later — or is fixed by a deploy — is not masked by a
// cached negative response.
package cmd

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

// staticCacheControl is the Cache-Control value applied to cacheable static
// responses: embedded assets change only on deploy, and css/js are
// cache-busted by the assetVersion template func, so a day-long max-age is
// safe for successes.
const staticCacheControl = "public, max-age=86400"

// fileServer serves static files with browser caching on successful
// responses only and directory listing disabled (m9). Static files are
// embedded at build time so they can be cached aggressively; the cache
// header is applied by cacheableHeaderWriter at commit time rather than
// eagerly, so failures (404s, 5xx) never carry it.
func fileServer(r chi.Router, path string, root http.FileSystem) {
	fs := http.StripPrefix(path, http.FileServer(noDirListing{root}))
	r.Get(path+"/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(&cacheableHeaderWriter{ResponseWriter: w}, r)
	})
}

// cacheableHeaderWriter applies the static cache header only when the
// FileServer commits a cacheable response: an eager header would stamp 404s
// (missing files) and other failures with a day-long negative cache.
type cacheableHeaderWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

// WriteHeader stamps the cache header on cacheable statuses: 200 fresh
// content, 304 revalidations, 206 range responses. The wroteHeader flag
// guards against duplicate header sets when WriteHeader is called more than
// once (the extra call is swallowed, mirroring net/http's superfluous-call
// handling).
func (w *cacheableHeaderWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	switch status {
	case http.StatusOK, http.StatusNotModified, http.StatusPartialContent:
		w.Header().Set("Cache-Control", staticCacheControl)
	}
	w.ResponseWriter.WriteHeader(status)
}

// Write covers the Write-implies-200 path: http.FileServer always calls
// WriteHeader explicitly (serveContent), but a handler that writes the body
// first would otherwise lose the header. Forwarding an explicit 200 here is
// equivalent to the implicit one and keeps wroteHeader accurate.
func (w *cacheableHeaderWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
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
