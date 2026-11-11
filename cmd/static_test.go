package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestFileServer_CacheControlAndNoDirListing verifies that static files get a
// Cache-Control header and that directory listing is disabled (m9).
func TestFileServer_CacheControlAndNoDirListing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}
	os.Mkdir(filepath.Join(dir, "css"), 0755)
	if err := os.WriteFile(filepath.Join(dir, "css", "style.css"), []byte("body{}"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	r := chi.NewRouter()
	fileServer(r, "/static", http.Dir(dir))

	// Regular file: 200 + Cache-Control header.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("file request: expected 200, got %d", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("Cache-Control: got %q, want %q", cc, "public, max-age=86400")
	}

	// File in subdirectory: still served (dir listing block must not break
	// normal file access).
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/static/css/style.css", nil)
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("subdirectory file request: expected 200, got %d", w2.Code)
	}

	// Directory listing: 404, not a file listing.
	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/static/", nil)
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Errorf("directory listing: expected 404, got %d", w3.Code)
	}

	// Directory without trailing slash: also 404 (no redirect to listing).
	w4 := httptest.NewRecorder()
	req4 := httptest.NewRequest(http.MethodGet, "/static/css", nil)
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusNotFound {
		t.Errorf("directory without slash: expected 404, got %d", w4.Code)
	}
}

// TestFileServer_CacheControlSuccessOnly verifies the static cache header is
// applied only to cacheable success statuses: a 404 (missing file or blocked
// directory listing) must NOT carry Cache-Control, otherwise browsers and
// shared caches store the negative response for a day.
func TestFileServer_CacheControlSuccessOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log(1)"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	r := chi.NewRouter()
	fileServer(r, "/static", http.Dir(dir))

	const wantCC = "public, max-age=86400"

	tests := []struct {
		name     string
		target   string
		header   http.Header // extra request headers, may be nil
		wantCode int
		wantCC   string // expected Cache-Control response header ("" = absent)
	}{
		{"missing file 404 carries no cache header", "/static/missing.js", nil, http.StatusNotFound, ""},
		{"directory 404 carries no cache header", "/static/", nil, http.StatusNotFound, ""},
		{"existing file 200 gets cache header", "/static/app.js", nil, http.StatusOK, wantCC},
		{"range request 206 gets cache header", "/static/app.js", http.Header{"Range": []string{"bytes=0-3"}}, http.StatusPartialContent, wantCC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			for k, v := range tt.header {
				req.Header[k] = v
			}
			r.ServeHTTP(w, req)
			if w.Code != tt.wantCode {
				t.Errorf("status: got %d, want %d", w.Code, tt.wantCode)
			}
			if cc := w.Header().Get("Cache-Control"); cc != tt.wantCC {
				t.Errorf("Cache-Control: got %q, want %q", cc, tt.wantCC)
			}
		})
	}
}

// TestCacheableHeaderWriter_WriteImpliesOK covers the Write-implies-200 path:
// a handler that writes the body without an explicit WriteHeader still gets
// the cache header, and a later explicit WriteHeader must not re-apply it.
func TestCacheableHeaderWriter_WriteImpliesOK(t *testing.T) {
	w := httptest.NewRecorder()
	cw := &cacheableHeaderWriter{ResponseWriter: w}

	// Write without WriteHeader: implied 200, header applied once.
	if _, err := cw.Write([]byte("body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("after implied-200 write: Cache-Control = %q, want %q", cc, "public, max-age=86400")
	}

	// A late explicit WriteHeader (e.g. a superfluous call) must not clobber
	// the committed response or re-apply the header.
	cw.WriteHeader(http.StatusInternalServerError)
	if w.Code != http.StatusOK {
		t.Errorf("late WriteHeader changed status: got %d, want 200", w.Code)
	}

	// Non-cacheable status: no header.
	w2 := httptest.NewRecorder()
	cw2 := &cacheableHeaderWriter{ResponseWriter: w2}
	cw2.WriteHeader(http.StatusNotFound)
	if cc := w2.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("404: Cache-Control = %q, want empty", cc)
	}
	// Duplicate WriteHeader on a non-cacheable status must not re-apply either.
	cw2.WriteHeader(http.StatusNotFound)
	if cc := w2.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("duplicate 404 WriteHeader: Cache-Control = %q, want empty", cc)
	}
}
