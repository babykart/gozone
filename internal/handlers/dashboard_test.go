package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

func TestDashboard(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGetRecentActivityLogs_Empty(t *testing.T) {
	h := newTestHandler(t)

	logs := h.getRecentActivityLogs(10)
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}

func TestDashboard_ServerStats(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"uptime","type":"StatisticItem","value":"3600"},{"name":"questions","type":"StatisticItem","value":"12345"},{"name":"packetcache-hit","type":"StatisticItem","value":"5000"},{"name":"packetcache-miss","type":"StatisticItem","value":"100"},{"name":"query-cache-hit","type":"StatisticItem","value":"8000"},{"name":"query-cache-miss","type":"StatisticItem","value":"200"},{"name":"qsize-q","type":"StatisticItem","value":"0"}]`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with server stats, got %d", w.Code)
	}
}

func TestDashboard_GetStatisticsError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/statistics") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal server error"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/zones") {
			w.Write([]byte(`[]`))
			return
		}
		w.Write([]byte(`{"id":"localhost","type":"Server","url":"/api/v1/servers/localhost","daemon_type":"authoritative","version":"4.9.0","config_url":"/api/v1/servers/localhost/config","zones_url":"/api/v1/servers/localhost/zones"}`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even when PDNS statistics fail, got %d", w.Code)
	}
}

func TestValToString(t *testing.T) {
	tests := []struct {
		input interface{}
		want  string
	}{
		{nil, ""},
		{"hello", "hello"},
		{"", ""},
		{float64(3600), "3600"},
		{float64(3.14), "3.14"},
		{float64(0), "0"},
		{true, "true"},
		{false, "false"},
		{[]int{1, 2, 3}, "[1 2 3]"},
	}
	for _, tt := range tests {
		got := valToString(tt.input)
		if got != tt.want {
			t.Errorf("valToString(%v): got %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestDashboard_NumericStats(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"uptime","type":"StatisticItem","value":3600},{"name":"questions","type":"StatisticItem","value":12345}]`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r = r.WithContext(ctx)
	h.Dashboard(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with numeric stats, got %d", w.Code)
	}
}
