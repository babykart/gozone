package pdns

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestHTTPError_LuaUpdatesDisabled(t *testing.T) {
	body := []byte(`{"error":"Undefined but needed argument: 'enable-lua-record-updates'"}`)
	err := httpError(http.StatusInternalServerError, body)
	if !errors.Is(err, ErrLuaUpdatesDisabled) {
		t.Errorf("expected error to match ErrLuaUpdatesDisabled, got %v", err)
	}

	// A plain 500 without the magic string should stay a plain error.
	err = httpError(http.StatusInternalServerError, []byte(`{"error":"database is down"}`))
	if errors.Is(err, ErrLuaUpdatesDisabled) {
		t.Errorf("expected plain 500 not to match ErrLuaUpdatesDisabled, got %v", err)
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
	err := client.CreateRecords(context.Background(), "test.", []models.RRSet{{}})
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

// TestHTTPError_CleanMessage (m46) verifies that the raw PowerDNS JSON body is
// not pasted into the error string: the human-readable "error" field is used
// instead, and non-JSON bodies fall back to the HTTP status text rather than
// being dumped verbatim.
func TestHTTPError_CleanMessage(t *testing.T) {
	// Standard JSON error: the "error" field is surfaced, not the JSON wrapper.
	err := httpError(http.StatusUnprocessableEntity, []byte(`{"error":"Zone 'example.com.' already exists"}`))
	got := err.Error()
	if want := "Zone 'example.com.' already exists"; !strings.Contains(got, want) {
		t.Errorf("expected extracted message %q in error, got %q", want, got)
	}
	if strings.Contains(got, `{"error":`) || strings.Contains(got, `"error":"`) {
		t.Errorf("raw JSON leaked into error message (m46): %q", got)
	}

	// Non-JSON body (e.g. an HTML page from a misconfigured proxy): must fall
	// back to the HTTP status text, never dump the body.
	err = httpError(http.StatusBadGateway, []byte(`<html><body>502 Bad Gateway</body></html>`))
	got = err.Error()
	if strings.Contains(got, "<html>") {
		t.Errorf("non-JSON body leaked into error message (m46): %q", got)
	}
	if want := http.StatusText(http.StatusBadGateway); !strings.Contains(got, want) {
		t.Errorf("expected status text %q in error, got %q", want, got)
	}

	// Empty body: status text fallback (unchanged behaviour).
	err = httpError(http.StatusNotFound, nil)
	if want := http.StatusText(http.StatusNotFound); !strings.Contains(err.Error(), want) {
		t.Errorf("expected status text %q for empty body, got %q", want, err.Error())
	}
}

func TestExtractErrorMessage(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"json error field", `{"error":"boom"}`, "boom"},
		{"json error trimmed", `{"error":"  spaced  "}`, "spaced"},
		{"json no error field", `{"other":"x"}`, ""},
		{"invalid json", `not json`, ""},
		{"empty", ``, ""},
		{"html body", `<html>nope</html>`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractErrorMessage([]byte(tc.body)); got != tc.want {
				t.Errorf("extractErrorMessage(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
