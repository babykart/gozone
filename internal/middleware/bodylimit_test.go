package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBodyLimit_AllowsUnderDefault(t *testing.T) {
	handler := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("unexpected read error: %v", err)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20-1)))
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("body under limit: expected 200, got %d", w.Code)
	}
}

func TestBodyLimit_BlocksOverDefault(t *testing.T) {
	var reachedHandler bool
	handler := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedHandler = true
		_, err := io.ReadAll(r.Body)
		if err == nil {
			t.Error("expected read error for oversized body, got nil")
		}
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20+100)))
	handler.ServeHTTP(w, r)

	if !reachedHandler {
		t.Error("handler should be reached; MaxBytesReader defers the error to Read")
	}
}

func TestBodyLimit_ImportGetsLargerLimit(t *testing.T) {
	// 5 MiB — under the 10 MiB import limit but well over the 1 MiB default.
	bodySize := 5 << 20
	handler := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("unexpected read error for import-sized body: %v", err)
			return
		}
		if n != int64(bodySize) {
			t.Errorf("read %d bytes, expected %d", n, bodySize)
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/1/import", bytes.NewReader(bytes.Repeat([]byte("x"), bodySize)))
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("import-sized body should be allowed on /import, got %d", w.Code)
	}
}

func TestBodyLimit_GetRequestNoBody(t *testing.T) {
	handler := BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("GET with no body: expected 200, got %d", w.Code)
	}
}
