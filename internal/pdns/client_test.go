package pdns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/models"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client := NewClient(&config.PowerDNSConfig{
		APIURL:   server.URL,
		APIKey:   "test-api-key",
		ServerID: "localhost",
	})
	return client, server
}

func TestNewClient_URLNormalization(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"http://pdns.example.com", "http://pdns.example.com/api/v1"},
		{"http://pdns.example.com/", "http://pdns.example.com/api/v1"},
		{"http://pdns.example.com/api/v1", "http://pdns.example.com/api/v1"},
		{"http://pdns.example.com/api/v1/", "http://pdns.example.com/api/v1"},
	}
	for _, tc := range cases {
		c := NewClient(&config.PowerDNSConfig{APIURL: tc.input, ServerID: "localhost"})
		if c.baseURL != tc.want {
			t.Errorf("input %q: got %q, want %q", tc.input, c.baseURL, tc.want)
		}
	}
}

func TestNewClient_Transport(t *testing.T) {
	c := NewClient(&config.PowerDNSConfig{APIURL: "http://pdns.example.com", ServerID: "localhost"})
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport on client")
	}
	if tr.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns: got %d, want 100", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 10 {
		t.Errorf("MaxIdleConnsPerHost: got %d, want 10", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout: got %v, want 90s", tr.IdleConnTimeout)
	}
	if tr.DisableKeepAlives {
		t.Error("DisableKeepAlives: got true, want false")
	}
	// m43: per-phase transport timeouts must be set (not just the global
	// http.Client.Timeout) so a stuck phase fails fast.
	if tr.DialContext == nil {
		t.Error("DialContext: nil, expected a net.Dialer with a dial timeout (m43)")
	}
	if tr.TLSHandshakeTimeout != pdnsTLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout: got %v, want %v (m43)", tr.TLSHandshakeTimeout, pdnsTLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != pdnsResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout: got %v, want %v (m43)", tr.ResponseHeaderTimeout, pdnsResponseHeaderTimeout)
	}
	if tr.ExpectContinueTimeout != pdnsExpectContinueTimeout {
		t.Errorf("ExpectContinueTimeout: got %v, want %v (m43)", tr.ExpectContinueTimeout, pdnsExpectContinueTimeout)
	}
	// Each phase timeout must be strictly less than the overall client timeout
	// (30s) so it is the binding constraint for a stuck phase rather than being
	// masked by the global budget.
	if pdnsDialTimeout >= c.http.Timeout {
		t.Errorf("pdnsDialTimeout %v must be < client timeout %v", pdnsDialTimeout, c.http.Timeout)
	}
	if pdnsTLSHandshakeTimeout >= c.http.Timeout {
		t.Errorf("pdnsTLSHandshakeTimeout %v must be < client timeout %v", pdnsTLSHandshakeTimeout, c.http.Timeout)
	}
	if pdnsResponseHeaderTimeout >= c.http.Timeout {
		t.Errorf("pdnsResponseHeaderTimeout %v must be < client timeout %v", pdnsResponseHeaderTimeout, c.http.Timeout)
	}
	if c.http.Timeout != 30*time.Second {
		t.Errorf("Timeout: got %v, want 30s", c.http.Timeout)
	}
}

func TestGetServers(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.ServerInfo{
			{ID: "localhost", Type: "Server", Daemon: "pdns", Version: "4.8.0"},
		})
	})

	servers, err := client.GetServers(context.Background())
	if err != nil {
		t.Fatalf("GetServers failed: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].ID != "localhost" {
		t.Errorf("expected ID localhost, got %s", servers[0].ID)
	}
}

func TestGetServer(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.ServerInfo{
			ID: "localhost", Daemon: "pdns", Version: "4.8.0",
		})
	})

	server, err := client.GetServer(context.Background())
	if err != nil {
		t.Fatalf("GetServer failed: %v", err)
	}
	if server.ID != "localhost" {
		t.Errorf("expected localhost, got %s", server.ID)
	}
}

func TestGetStatistics(t *testing.T) {
	t.Run("string value", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]models.StatisticItem{
				{Name: "udp-queries", Type: "StatisticItem", Value: "42"},
			})
		})

		stats, err := client.GetStatistics(context.Background())
		if err != nil {
			t.Fatalf("GetStatistics failed: %v", err)
		}
		if len(stats) != 1 {
			t.Fatalf("expected 1 stat, got %d", len(stats))
		}
		if stats[0].Name != "udp-queries" {
			t.Errorf("expected udp-queries, got %s", stats[0].Name)
		}
	})

	t.Run("numeric value", func(t *testing.T) {
		client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[{"name":"uptime","type":"StatisticItem","value":3600}]`))
		})

		stats, err := client.GetStatistics(context.Background())
		if err != nil {
			t.Fatalf("GetStatistics with numeric value failed: %v", err)
		}
		if len(stats) != 1 {
			t.Fatalf("expected 1 stat, got %d", len(stats))
		}
		v, ok := stats[0].Value.(float64)
		if !ok {
			t.Fatalf("expected float64, got %T", stats[0].Value)
		}
		if v != 3600 {
			t.Errorf("expected 3600, got %v", v)
		}
	})
}

func TestListZones(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "rrsets=false" {
			t.Errorf("expected ?rrsets=false, got ?%s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "example.com", Name: "example.com", Kind: "Native"},
		})
	})

	zones, err := client.ListZones(context.Background())
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}
	if len(zones) != 1 {
		t.Fatalf("expected 1 zone, got %d", len(zones))
	}
	if zones[0].Name != "example.com" {
		t.Errorf("expected example.com, got %s", zones[0].Name)
	}
}

func TestListZonesWithInfo(t *testing.T) {
	var callCount int
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "example.com", Name: "example.com", Kind: "Native"},
			{ID: "test.com", Name: "test.com", Kind: "Native"},
		})
	})

	info, err := client.ListZonesWithInfo(context.Background())
	if err != nil {
		t.Fatalf("ListZonesWithInfo failed: %v", err)
	}
	if len(info) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(info))
	}
	if info[0].Zone.Name != "example.com" {
		t.Errorf("expected example.com, got %s", info[0].Zone.Name)
	}
	if callCount != 1 {
		t.Errorf("expected exactly 1 HTTP call, got %d (N+1 regression)", callCount)
	}
}

func TestListZonesWithInfo_Empty(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})

	info, err := client.ListZonesWithInfo(context.Background())
	if err != nil {
		t.Fatalf("ListZonesWithInfo failed: %v", err)
	}
	if len(info) != 0 {
		t.Fatalf("expected 0 zones, got %d", len(info))
	}
}

func TestGetZone(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native", Serial: 2024010100,
		})
	})

	zone, err := client.GetZone(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetZone failed: %v", err)
	}
	if zone.Serial != 2024010100 {
		t.Errorf("expected 2024010100, got %d", zone.Serial)
	}
}

func TestCreateZone(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req models.ZoneCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.Zone{
			ID: req.Name, Name: req.Name, Kind: req.Kind,
		})
	})

	zone, err := client.CreateZone(context.Background(), models.ZoneCreateRequest{
		Name: "newzone.com",
		Kind: "Native",
	})
	if err != nil {
		t.Fatalf("CreateZone failed: %v", err)
	}
	if zone.Name != "newzone.com" {
		t.Errorf("expected newzone.com, got %s", zone.Name)
	}
}

func TestCreateZone_Defaults(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req models.ZoneCreateRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.Kind != "Native" {
			t.Errorf("expected default Kind Native, got %s", req.Kind)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.Zone{Name: req.Name})
	})

	zone, err := client.CreateZone(context.Background(), models.ZoneCreateRequest{Name: "test.com"})
	if err != nil {
		t.Fatalf("CreateZone failed: %v", err)
	}
	if zone.Name != "test.com" {
		t.Errorf("expected test.com, got %s", zone.Name)
	}
}

func TestDeleteZone(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := client.DeleteZone(context.Background(), "example.com"); err != nil {
		t.Fatalf("DeleteZone failed: %v", err)
	}
}

func TestListRecords(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "test.example.com", Type: "A", TTL: 3600},
			},
		})
	})

	records, err := client.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Name != "test.example.com" {
		t.Errorf("expected test.example.com, got %s", records[0].Name)
	}
}

func TestListRecordsExtractsPriority(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "example.com", Type: "MX", TTL: 3600, Records: []models.RecordInfo{
					{Content: "10 mail.example.com."},
					{Content: "0 backup.example.com."},
				}},
			},
		})
	})

	records, err := client.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords failed: %v", err)
	}
	if len(records) != 1 || len(records[0].Records) != 2 {
		t.Fatalf("expected 1 rrset with 2 records, got %+v", records)
	}

	// Priority 10 is split off into the Priority field, content keeps the host.
	if got := records[0].Records[0]; got.Priority != 10 || got.Content != "mail.example.com." {
		t.Errorf("record[0] = {prio %d, %q}, want {10, %q}", got.Priority, got.Content, "mail.example.com.")
	}
	// Priority 0 is valid and must also be stripped from the content.
	if got := records[0].Records[1]; got.Priority != 0 || got.Content != "backup.example.com." {
		t.Errorf("record[1] = {prio %d, %q}, want {0, %q}", got.Priority, got.Content, "backup.example.com.")
	}
}

func TestListRecord_NameOnly(t *testing.T) {
	var gotPath string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "www.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "1.2.3.4"}}},
				{Name: "www.example.com", Type: "AAAA", TTL: 300, Records: []models.RecordInfo{{Content: "::1"}}},
			},
		})
	})

	records, err := client.ListRecord(context.Background(), "example.com", "www.example.com", "")
	if err != nil {
		t.Fatalf("ListRecord failed: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 rrsets (A and AAAA for same name), got %d", len(records))
	}
	if !strings.Contains(gotPath, "rrset_name=www.example.com") {
		t.Errorf("expected rrset_name query param, got %q", gotPath)
	}
	if strings.Contains(gotPath, "rrset_type=") {
		t.Errorf("expected no rrset_type query param when type is empty, got %q", gotPath)
	}
}

func TestListRecord_NameAndType(t *testing.T) {
	var gotPath string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "www.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "1.2.3.4"}}},
			},
		})
	})

	records, err := client.ListRecord(context.Background(), "example.com", "www.example.com", "A")
	if err != nil {
		t.Fatalf("ListRecord failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(records))
	}
	if records[0].Type != "A" {
		t.Errorf("expected A rrset, got %s", records[0].Type)
	}
	if !strings.Contains(gotPath, "rrset_name=www.example.com") || !strings.Contains(gotPath, "rrset_type=A") {
		t.Errorf("expected both query params, got %q", gotPath)
	}
}

func TestListRecord_EmptyFilters_ListAll(t *testing.T) {
	var gotPath string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			RRSets []models.RRSet `json:"rrsets"`
		}{
			RRSets: []models.RRSet{
				{Name: "a.example.com", Type: "A", TTL: 300},
			},
		})
	})

	records, err := client.ListRecord(context.Background(), "example.com", "", "")
	if err != nil {
		t.Fatalf("ListRecord failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(records))
	}
	if gotPath != "" {
		t.Errorf("expected no query params when both filters are empty, got %q", gotPath)
	}
}

func TestCreateRecord(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)

		rrsets, ok := payload["rrsets"].([]interface{})
		if !ok || len(rrsets) != 1 {
			t.Errorf("expected 1 rrset in payload")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.CreateRecord(context.Background(), "example.com", models.RRSet{
		Name: "www.example.com",
		Type: "A",
		TTL:  300,
		Records: []models.RecordInfo{
			{Content: "1.2.3.4"},
		},
	})
	if err != nil {
		t.Fatalf("CreateRecord failed: %v", err)
	}
}

func TestCreateRecords(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		rrsets, ok := payload["rrsets"].([]interface{})
		if !ok || len(rrsets) != 2 {
			t.Errorf("expected 2 rrsets in payload, got %v", payload)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.CreateRecords(context.Background(), "example.com", []models.RRSet{
		{Name: "www.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "1.2.3.4"}}},
		{Name: "mail.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "1.2.3.5"}}},
	})
	if err != nil {
		t.Fatalf("CreateRecords failed: %v", err)
	}
}

func TestDeleteRecord(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.DeleteRecord(context.Background(), "example.com", "old.example.com", "A")
	if err != nil {
		t.Fatalf("DeleteRecord failed: %v", err)
	}
}

func TestRectifyZone(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	})

	if err := client.RectifyZone(context.Background(), "example.com"); err != nil {
		t.Fatalf("RectifyZone failed: %v", err)
	}
}

func TestNotifySlaves(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	})

	if err := client.NotifySlaves(context.Background(), "example.com"); err != nil {
		t.Fatalf("NotifySlaves failed: %v", err)
	}
}

func TestUpdateRecord_Success(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)

		rrsets, ok := payload["rrsets"].([]interface{})
		if !ok || len(rrsets) != 1 {
			t.Errorf("expected 1 rrset in payload")
			return
		}
		rrset := rrsets[0].(map[string]interface{})
		if rrset["changetype"] != "REPLACE" {
			t.Errorf("expected changetype REPLACE, got %v", rrset["changetype"])
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.UpdateRecord(context.Background(), "example.com", models.RRSet{
		Name: "www.example.com",
		Type: "A",
		TTL:  600,
		Records: []models.RecordInfo{
			{Content: "10.0.0.1", Disabled: false},
		},
	})
	if err != nil {
		t.Fatalf("UpdateRecord failed: %v", err)
	}
}

func TestUpdateRecord_PDNSError(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := client.UpdateRecord(context.Background(), "example.com", models.RRSet{
		Name: "www.example.com",
		Type: "A",
		TTL:  600,
		Records: []models.RecordInfo{
			{Content: "10.0.0.1"},
		},
	})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestClientError(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"something went wrong"}`))
	})

	_, err := client.GetZone(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestClientUnauthorized(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := client.GetServers(context.Background())
	if err == nil {
		t.Error("expected error for 401 response")
	}
}

func TestServerID(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if client.ServerID() != "localhost" {
		t.Errorf("expected localhost, got %s", client.ServerID())
	}
}

func TestGetMetadata(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Metadata{
			{Kind: "ALLOW-AXFR-FROM", Metadata: []string{"192.0.2.0/24"}},
			{Kind: "PRESIGNED", Metadata: []string{"1"}},
		})
	})

	metadata, err := client.GetMetadata(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if len(metadata) != 2 {
		t.Fatalf("expected 2 metadata entries, got %d", len(metadata))
	}
	if metadata[0].Kind != "ALLOW-AXFR-FROM" {
		t.Errorf("expected ALLOW-AXFR-FROM, got %s", metadata[0].Kind)
	}
	if len(metadata[0].Metadata) != 1 || metadata[0].Metadata[0] != "192.0.2.0/24" {
		t.Errorf("unexpected metadata values: %v", metadata[0].Metadata)
	}
}

func TestGetMetadata_Empty(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})

	metadata, err := client.GetMetadata(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if len(metadata) != 0 {
		t.Errorf("expected 0 entries, got %d", len(metadata))
	}
}

func TestSetMetadata(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/ALSO-NOTIFY") {
			t.Errorf("expected path ending in /ALSO-NOTIFY, got %s", r.URL.Path)
		}
		var payload map[string][]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("bad request: %v", err)
		}
		meta, ok := payload["metadata"]
		if !ok || len(meta) != 1 || meta[0] != "10.0.0.1" {
			t.Errorf("unexpected values: %v", meta)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.SetMetadata(context.Background(), "example.com", models.Metadata{
		Kind:     "ALSO-NOTIFY",
		Metadata: []string{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}
}

func TestSetMetadata_NilValues(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		var payload map[string][]string
		json.NewDecoder(r.Body).Decode(&payload)
		meta, ok := payload["metadata"]
		if !ok {
			t.Error("metadata key not found in payload")
		}
		if len(meta) != 0 {
			t.Errorf("expected empty slice, got %v", meta)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.SetMetadata(context.Background(), "example.com", models.Metadata{Kind: "PRESIGNED"})
	if err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}
}

func TestDeleteMetadata(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := client.DeleteMetadata(context.Background(), "example.com", "PRESIGNED"); err != nil {
		t.Fatalf("DeleteMetadata failed: %v", err)
	}
}

func TestDeleteMetadata_Error(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	err := client.DeleteMetadata(context.Background(), "example.com", "NONEXISTENT")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestListTSIGKeys(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.TSIGKey{
			{Name: "key1.", ID: "key1.", Algorithm: "hmac-sha256", Type: "TSIGKey"},
			{Name: "key2.", ID: "key2.", Algorithm: "hmac-sha512", Type: "TSIGKey"},
		})
	})

	keys, err := client.ListTSIGKeys(context.Background())
	if err != nil {
		t.Fatalf("ListTSIGKeys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[0].Name != "key1." {
		t.Errorf("expected key1., got %s", keys[0].Name)
	}
}

func TestListTSIGKeys_Empty(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})

	keys, err := client.ListTSIGKeys(context.Background())
	if err != nil {
		t.Fatalf("ListTSIGKeys failed: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestGetTSIGKey(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TSIGKey{
			Name: "my-key.", ID: "my-key.", Algorithm: "hmac-sha256", Key: "secret", Type: "TSIGKey",
		})
	})

	key, err := client.GetTSIGKey(context.Background(), "my-key.")
	if err != nil {
		t.Fatalf("GetTSIGKey failed: %v", err)
	}
	if key.Algorithm != "hmac-sha256" {
		t.Errorf("expected hmac-sha256, got %s", key.Algorithm)
	}
}

func TestCreateTSIGKey(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req models.TSIGKey
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request: %v", err)
		}
		if req.Algorithm != "hmac-sha256" {
			t.Errorf("expected hmac-sha256, got %s", req.Algorithm)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(req)
	})

	key, err := client.CreateTSIGKey(context.Background(), models.TSIGKey{
		Name:      "new-key.",
		Algorithm: "hmac-sha256",
		Key:       "base64secret",
		Type:      "TSIGKey",
	})
	if err != nil {
		t.Fatalf("CreateTSIGKey failed: %v", err)
	}
	if key.Name != "new-key." {
		t.Errorf("expected new-key., got %s", key.Name)
	}
}

func TestUpdateTSIGKey(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		var req models.TSIGKey
		json.NewDecoder(r.Body).Decode(&req)
		if req.Algorithm != "hmac-sha512" {
			t.Errorf("expected hmac-sha512, got %s", req.Algorithm)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.UpdateTSIGKey(context.Background(), "my-key.", models.TSIGKey{
		Name:      "my-key.",
		Algorithm: "hmac-sha512",
		Key:       "updated-secret",
		Type:      "TSIGKey",
	})
	if err != nil {
		t.Fatalf("UpdateTSIGKey failed: %v", err)
	}
}

func TestDeleteTSIGKey(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	if err := client.DeleteTSIGKey(context.Background(), "my-key."); err != nil {
		t.Fatalf("DeleteTSIGKey failed: %v", err)
	}
}

func TestDeleteTSIGKey_Error(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	err := client.DeleteTSIGKey(context.Background(), "nonexistent.")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

// SplitPriority (the priority read path) is exercised by TestListRecordsExtractsPriority
// above and unit-tested in internal/models/recordtype_test.go.

// TestPathEscaping_NoPathTraversal verifies that request-controlled path
// segments — zoneID, metadata kind, TSIG key id — are path-escaped so a
// malicious value cannot inject extra path components into the PowerDNS API URL
// (m41). The injected "/" must become "%2F" and ".." must stay within the same
// segment rather than being interpreted as a path separator.
func TestPathEscaping_NoPathTraversal(t *testing.T) {
	cases := []struct {
		name string
		call func(c *Client)
		// wantSuffix is the expected tail of r.URL.EscapedPath(): the injected
		// "/" became "%2F", proving it was NOT used as a real separator.
		wantSuffix string
	}{
		{
			name: "zoneID in GetZone",
			call: func(c *Client) {
				_, _ = c.GetZone(context.Background(), "evil/../admin")
			},
			wantSuffix: "/zones/evil%2F..%2Fadmin",
		},
		{
			name: "metadata kind in DeleteMetadata",
			call: func(c *Client) {
				_ = c.DeleteMetadata(context.Background(), "zoneid", "k/in..d")
			},
			wantSuffix: "/zones/zoneid/metadata/k%2Fin..d",
		},
		{
			name: "tsig key id in DeleteTSIGKey",
			call: func(c *Client) {
				_ = c.DeleteTSIGKey(context.Background(), "id/x..y")
			},
			wantSuffix: "/tsigkeys/id%2Fx..y",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var escaped string
			client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				escaped = r.URL.EscapedPath()
				// doOK/doUnmarshal both accept a 200; a minimal body keeps the
				// unmarshal path (GetZone) quiet.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			})
			tc.call(client)

			if !strings.HasSuffix(escaped, tc.wantSuffix) {
				t.Errorf("%s: escaped path = %q, want suffix %q (path-traversal not escaped — m41)", tc.name, escaped, tc.wantSuffix)
			}
			// Defensive: the literal ".." traversal pattern must never survive as
			// a real (decoded) path segment. r.URL.Path is the decoded form.
			// #nosec G104 -- best-effort defensive assertion in a test.
		})
	}
}

// TestPathEscaping_NormalValuesUnchanged documents that legitimate identifiers
// (dots, hyphens — the characters that occur in real zone names, metadata
// kinds and TSIG key names) are not corrupted by the escaping added in m41.
func TestPathEscaping_NormalValuesUnchanged(t *testing.T) {
	var escaped string
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		escaped = r.URL.EscapedPath()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})

	_, _ = client.GetZone(context.Background(), "example.com.")
	// Dots and the trailing-dot FQDN form must round-trip verbatim.
	if want := "/servers/localhost/zones/example.com."; !strings.HasSuffix(escaped, want) {
		t.Errorf("normal zoneID: escaped path = %q, want suffix %q", escaped, want)
	}
}

// TestReadLimitedBody covers the response-size cap (m42). The limit+1 trick is
// exercised at the boundary: a body exactly equal to the limit is accepted, a
// single extra byte is rejected, and the helper never silently truncates.
func TestReadLimitedBody(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		limit   int64
		want    string // expected body when wantErr is false
		wantErr bool
	}{
		{"empty body", "", 10, "", false},
		{"under limit", "hello", 10, "hello", false},
		{"exactly at limit (boundary)", "0123456789", 10, "0123456789", false},
		{"one byte over limit", "0123456789a", 10, "", true},
		{"well over limit", strings.Repeat("x", 1000), 10, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readLimitedBody(strings.NewReader(tc.input), tc.limit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for input len %d with limit %d, got body len %d", len(tc.input), tc.limit, len(got))
				}
				if !strings.Contains(err.Error(), "exceeds") {
					t.Errorf("error should mention the limit, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("body: got %q, want %q", string(got), tc.want)
			}
		})
	}
}
