package pdns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

	servers, err := client.GetServers()
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

	server, err := client.GetServer()
	if err != nil {
		t.Fatalf("GetServer failed: %v", err)
	}
	if server.ID != "localhost" {
		t.Errorf("expected localhost, got %s", server.ID)
	}
}

func TestGetStatistics(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.StatisticItem{
			{Name: "udp-queries", Type: "StatisticItem", Value: "42"},
		})
	})

	stats, err := client.GetStatistics()
	if err != nil {
		t.Fatalf("GetStatistics failed: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("expected 1 stat, got %d", len(stats))
	}
	if stats[0].Name != "udp-queries" {
		t.Errorf("expected udp-queries, got %s", stats[0].Name)
	}
}

func TestListZones(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "example.com", Name: "example.com", Kind: "Native"},
		})
	})

	zones, err := client.ListZones()
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

func TestGetZone(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native", Serial: 2024010100,
		})
	})

	zone, err := client.GetZone("example.com")
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

	zone, err := client.CreateZone(models.ZoneCreateRequest{
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

	zone, err := client.CreateZone(models.ZoneCreateRequest{Name: "test.com"})
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

	if err := client.DeleteZone("example.com"); err != nil {
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

	records, err := client.ListRecords("example.com")
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

	err := client.CreateRecord("example.com", models.RRSet{
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

func TestDeleteRecord(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		var payload map[string]interface{}
		json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusNoContent)
	})

	err := client.DeleteRecord("example.com", "old.example.com", "A")
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

	if err := client.RectifyZone("example.com"); err != nil {
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

	if err := client.NotifySlaves("example.com"); err != nil {
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

	err := client.UpdateRecord("example.com", models.RRSet{
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

	err := client.UpdateRecord("example.com", models.RRSet{
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

	_, err := client.GetZone("nonexistent")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestClientUnauthorized(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := client.GetServers()
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
