package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apperrors "github.com/babykart/gozone/internal/errors"
)

func TestErrorHandler_RecoversFromPanic(t *testing.T) {
	handler := ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestErrorHandler_APIPanicReturnsJSON(t *testing.T) {
	handler := ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("api crash")
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "INTERNAL_ERROR" {
		t.Errorf("expected INTERNAL_ERROR, got %v", body["error"])
	}
}

func TestErrorHandler_NoPanicPassesThrough(t *testing.T) {
	handler := ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTeapot {
		t.Errorf("expected 418, got %d", w.Code)
	}
}

func TestWriteAppError_APIRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)

	WriteAppError(w, r, apperrors.NotFound("zone not found"))

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var body map[string]interface{}
	json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND, got %v", body["error"])
	}
}

func TestWriteAppError_WebRequest(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)

	WriteAppError(w, r, apperrors.Forbidden("admin only"))

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct == "application/json" {
		t.Error("expected text/plain for web request, got application/json")
	}
}

func TestIsAPIRequest(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		accept  string
		wantAPI bool
	}{
		{"api path", "/api/v1/zones", "", true},
		{"web path with json accept", "/dashboard", "application/json", true},
		{"web path with html accept", "/dashboard", "text/html", false},
		{"web path no accept", "/zones", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.url, nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if got := isAPIRequest(r); got != tt.wantAPI {
				t.Errorf("isAPIRequest(%q) = %v, want %v", tt.url, got, tt.wantAPI)
			}
		})
	}
}
