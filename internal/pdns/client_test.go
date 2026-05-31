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

func TestListZonesWithInfo(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" && r.URL.Path == "/api/v1/servers/localhost/zones" {
			json.NewEncoder(w).Encode([]models.Zone{
				{ID: "example.com", Name: "example.com", Kind: "Native"},
				{ID: "test.com", Name: "test.com", Kind: "Native"},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name": "example.com",
				"kind": "Native",
				"rrsets": []map[string]interface{}{
					{"name": "example.com", "type": "SOA", "ttl": 3600},
					{"name": "www.example.com", "type": "A", "ttl": 3600},
				},
			})
		}
	})

	info, err := client.ListZonesWithInfo()
	if err != nil {
		t.Fatalf("ListZonesWithInfo failed: %v", err)
	}
	if len(info) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(info))
	}
	if info[0].Zone.Name != "example.com" {
		t.Errorf("expected example.com, got %s", info[0].Zone.Name)
	}
	if info[0].RecordCount != 2 {
		t.Errorf("expected 2 records, got %d", info[0].RecordCount)
	}
}

func TestListZonesWithInfo_Empty(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})

	info, err := client.ListZonesWithInfo()
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

	metadata, err := client.GetMetadata("example.com")
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

	metadata, err := client.GetMetadata("example.com")
	if err != nil {
		t.Fatalf("GetMetadata failed: %v", err)
	}
	if len(metadata) != 0 {
		t.Errorf("expected 0 entries, got %d", len(metadata))
	}
}

func TestSetMetadata(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		var req models.Metadata
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad request: %v", err)
		}
		if req.Kind != "ALSO-NOTIFY" {
			t.Errorf("expected ALSO-NOTIFY, got %s", req.Kind)
		}
		if len(req.Metadata) != 1 || req.Metadata[0] != "10.0.0.1" {
			t.Errorf("unexpected values: %v", req.Metadata)
		}
		w.WriteHeader(http.StatusCreated)
	})

	err := client.SetMetadata("example.com", models.Metadata{
		Kind:     "ALSO-NOTIFY",
		Metadata: []string{"10.0.0.1"},
	})
	if err != nil {
		t.Fatalf("SetMetadata failed: %v", err)
	}
}

func TestSetMetadata_NilValues(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var req models.Metadata
		json.NewDecoder(r.Body).Decode(&req)
		if req.Metadata == nil {
			t.Error("metadata should not be nil")
		}
		if len(req.Metadata) != 0 {
			t.Errorf("expected empty slice, got %v", req.Metadata)
		}
		w.WriteHeader(http.StatusCreated)
	})

	err := client.SetMetadata("example.com", models.Metadata{Kind: "PRESIGNED"})
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

	if err := client.DeleteMetadata("example.com", "PRESIGNED"); err != nil {
		t.Fatalf("DeleteMetadata failed: %v", err)
	}
}

func TestDeleteMetadata_Error(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	err := client.DeleteMetadata("example.com", "NONEXISTENT")
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

	keys, err := client.ListTSIGKeys()
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

	keys, err := client.ListTSIGKeys()
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

	key, err := client.GetTSIGKey("my-key.")
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

	key, err := client.CreateTSIGKey(models.TSIGKey{
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

	err := client.UpdateTSIGKey("my-key.", models.TSIGKey{
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

	if err := client.DeleteTSIGKey("my-key."); err != nil {
		t.Fatalf("DeleteTSIGKey failed: %v", err)
	}
}

func TestDeleteTSIGKey_Error(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	err := client.DeleteTSIGKey("nonexistent.")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}
