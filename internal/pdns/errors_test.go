package pdns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/models"
)

func TestHTTPError_TypedSentinels(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantErr   error
		wantPlain bool
	}{
		{"not found", http.StatusNotFound, ErrNotFound, false},
		{"bad request", http.StatusBadRequest, ErrValidation, false},
		{"unprocessable", http.StatusUnprocessableEntity, ErrValidation, false},
		{"conflict", http.StatusConflict, ErrConflict, false},
		{"unauthorized", http.StatusUnauthorized, ErrUnauthorized, false},
		{"forbidden", http.StatusForbidden, ErrUnauthorized, false},
		{"internal", http.StatusInternalServerError, nil, true},
		{"service unavailable", http.StatusServiceUnavailable, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := httpError(tt.status, []byte(`{"error":"boom"}`))
			if tt.wantPlain {
				for _, sentinel := range []error{ErrNotFound, ErrValidation, ErrConflict, ErrUnauthorized} {
					if errors.Is(err, sentinel) {
						t.Errorf("expected plain error, but matches %v", sentinel)
					}
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected error to match %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestClient_GetZone_TypedErrors(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr error
	}{
		{"not found", http.StatusNotFound, ErrNotFound},
		{"bad request", http.StatusBadRequest, ErrValidation},
		{"unprocessable", http.StatusUnprocessableEntity, ErrValidation},
		{"conflict", http.StatusConflict, ErrConflict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(`{"error":"x"}`))
			}))
			defer srv.Close()

			client := NewClient(&config.PowerDNSConfig{APIURL: srv.URL, APIKey: "k", ServerID: "localhost"})
			_, err := client.GetZone(context.Background(), "test.")
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestClient_GetZone_NetworkError(t *testing.T) {
	client := NewClient(&config.PowerDNSConfig{APIURL: "http://127.0.0.1:1", APIKey: "k", ServerID: "localhost"})
	_, err := client.GetZone(context.Background(), "test.")
	if err == nil {
		t.Fatal("expected error")
	}
	// Network errors must not be classified as NotFound.
	if errors.Is(err, ErrNotFound) {
		t.Errorf("network error should not match ErrNotFound: %v", err)
	}
}

func TestClient_ListRecords_TypedNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Not Found"}`))
	}))
	defer srv.Close()

	client := NewClient(&config.PowerDNSConfig{APIURL: srv.URL, APIKey: "k", ServerID: "localhost"})
	_, err := client.ListRecords(context.Background(), "missing.")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestClient_CreateRecord_TypedValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":"Could not parse"}`))
	}))
	defer srv.Close()

	client := NewClient(&config.PowerDNSConfig{APIURL: srv.URL, APIKey: "k", ServerID: "localhost"})
	err := client.CreateRecord(context.Background(), "test.", models.RRSet{})
	if !errors.Is(err, ErrValidation) {
		t.Errorf("expected ErrValidation, got %v", err)
	}
}

func TestClient_DeleteZone_TypedNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Not Found"}`))
	}))
	defer srv.Close()

	client := NewClient(&config.PowerDNSConfig{APIURL: srv.URL, APIKey: "k", ServerID: "localhost"})
	err := client.DeleteZone(context.Background(), "missing.")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
