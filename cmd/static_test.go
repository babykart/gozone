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
