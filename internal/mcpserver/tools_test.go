package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// richPDNS serves zone lists, zone details and RRSets so the read tools have
// non-trivial data to return, and captures writes into sent.
func richPDNS(t *testing.T, sent *[]models.RRSet) testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case p == "/api/v1/servers/localhost/zones" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode([]models.Zone{
				{ID: "example.com.", Name: "example.com.", Kind: "Native", DNSSEC: true},
			})
		case p == "/api/v1/servers/localhost/zones" && r.Method == http.MethodPost:
			var req models.ZoneCreateRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode zone create: %v", err)
			}
			json.NewEncoder(w).Encode(models.Zone{ID: req.Name, Name: req.Name, Kind: req.Kind})
		case p == "/api/v1/servers/localhost/statistics" && r.Method == http.MethodGet:
			w.Write([]byte(`[{"name":"uptime","type":"string","value":"10s"}]`)) // #nosec G104 -- test helper
		case strings.HasPrefix(p, "/api/v1/servers/localhost/zones/") && r.Method == http.MethodGet:
			// The PowerDNS zone endpoint returns the zone object WITH its
			// rrsets array: GetZone decodes the zone fields, ListRecords
			// decodes the rrsets of the same body, and a ?rrset_name= query
			// filters server-side.
			filtered := r.URL.Query().Get("rrset_name") != ""
			rrsets := []models.RRSet{
				{Name: "example.com.", Type: "SOA", TTL: 3600, Records: []models.RecordInfo{{Content: "ns1.example.com. hostmaster.example.com. 2024010100 3600 900 1209600 3600"}}},
				{Name: "example.com.", Type: "NS", TTL: 3600, Records: []models.RecordInfo{{Content: "ns1.example.com."}}},
				{Name: "www.example.com.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "192.0.2.1"}}},
				{Name: "example.com.", Type: "MX", TTL: 3600, Records: []models.RecordInfo{{Content: "mail.example.com.", Priority: 10}}},
			}
			if filtered {
				rrsets = rrsets[2:3]
			}
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com.", Name: "example.com.", Kind: "Native", Serial: 42},
				RRSets: rrsets,
			})
		case strings.HasPrefix(p, "/api/v1/servers/localhost/zones/") && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode PATCH: %v", err)
			}
			*sent = append(*sent, payload.RRSets...)
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func TestReadTools_EndToEnd(t *testing.T) {
	session, db := newMCPTestEnv(t, true, richPDNS(t, &[]models.RRSet{}))
	grantZoneToMCPUser(t, db, "example.com.")
	ctx := context.Background()

	call := func(name string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.IsError {
			t.Fatalf("%s failed: %s", name, resultText(res))
		}
		return res
	}

	// get_zone
	res := call("get_zone", map[string]any{"zone": "example.com."})
	var zone struct {
		Zone models.Zone `json:"zone"`
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &zone); err != nil || zone.Zone.Serial != 42 {
		t.Fatalf("get_zone structured output wrong: %s (%v)", b, err)
	}

	// list_records with a bare-label name filter.
	res = call("list_records", map[string]any{"zone": "example.com.", "name": "www", "type": "a"})
	var records struct {
		Records []models.RRSet `json:"records"`
	}
	b, _ = json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &records); err != nil || len(records.Records) != 1 || records.Records[0].Name != "www.example.com." {
		t.Fatalf("list_records structured output wrong: %s (%v)", b, err)
	}

	// get_stats
	res = call("get_stats", nil)
	var stats struct {
		ZoneCount int `json:"zone_count"`
	}
	b, _ = json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &stats); err != nil || stats.ZoneCount != 1 {
		t.Fatalf("get_stats structured output wrong: %s (%v)", b, err)
	}

	// list_record_types
	res = call("list_record_types", nil)
	var types struct {
		Types []string `json:"types"`
	}
	b, _ = json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &types); err != nil || len(types.Types) < 9 {
		t.Fatalf("list_record_types structured output wrong: %s (%v)", b, err)
	}

	// list_records validation: type without name is an argument error.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_records",
		Arguments: map[string]any{"zone": "example.com.", "type": "A"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(resultText(res), "requires 'name'") {
		t.Fatalf("type-without-name must be a validation error, got %q", resultText(res))
	}
}

func TestWriteTools_AdminEndToEnd(t *testing.T) {
	var sent []models.RRSet
	session, db := newMCPTestEnvAs(t, false, richPDNS(t, &sent), "admin")
	ctx := context.Background()

	call := func(name string, args map[string]any) *mcp.CallToolResult {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.IsError {
			t.Fatalf("%s failed: %s", name, resultText(res))
		}
		return res
	}

	// update_record: REPLACE with normalisation + comment purge.
	call("update_record", map[string]any{
		"zone": "example.com.", "name": "www", "type": "A", "ttl": 600,
		"records":        []map[string]any{{"content": "203.0.113.5"}},
		"clear_comments": true,
	})
	if len(sent) == 0 {
		t.Fatal("update_record must PATCH")
	}
	last := sent[len(sent)-1]
	if last.Name != "www.example.com." || last.TTL != 600 || len(last.Records) != 1 || last.Records[0].Content != "203.0.113.5" {
		t.Fatalf("update_record PATCH wrong: %+v", last)
	}

	// create_zone then delete_zone as admin.
	call("create_zone", map[string]any{"name": "NewZone.Example.COM", "nameservers": []string{"ns1.example.com"}})
	if _, err := db.Exec(`DELETE FROM activity_logs WHERE action='create_zone'`); err != nil {
		t.Fatal(err)
	}
	var details string
	if err := db.QueryRow(`SELECT details FROM activity_logs WHERE action='create_zone'`).Scan(&details); err == nil {
		// deleted above; recreate by calling again is unnecessary — assert via the delete below
		_ = details
	}
	call("delete_zone", map[string]any{"zone": "newzone.example.com."})
	if err := db.QueryRow(`SELECT details FROM activity_logs WHERE action='delete_zone'`).Scan(&details); err != nil {
		t.Fatalf("delete_zone audit row: %v", err)
	}
	if !strings.Contains(details, "via MCP") {
		t.Fatalf("delete_zone audit must carry via MCP, got %q", details)
	}

	// delete_record with friendlier name forms.
	sent = nil
	call("delete_record", map[string]any{"zone": "example.com.", "name": "www", "type": "a"})
	if err := db.QueryRow(`SELECT details FROM activity_logs WHERE action='delete_record'`).Scan(&details); err != nil {
		t.Fatalf("delete_record audit row: %v", err)
	}
	// The audit text carries the canonicalised name and uppercased type.
	if !strings.Contains(details, "Deleted A record www.example.com.") {
		t.Fatalf("delete_record audit must be canonical, got %q", details)
	}
}

func TestCreateZone_AdminSuccessAuditsViaMCP(t *testing.T) {
	var sent []models.RRSet
	session, db := newMCPTestEnvAs(t, false, richPDNS(t, &sent), "admin")
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "create_zone",
		Arguments: map[string]any{
			"name":        "Created.Example.COM",
			"nameservers": []string{"NS1.Example.COM"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("admin create_zone failed: %s", resultText(res))
	}
	var zoneOut struct {
		Zone models.Zone `json:"zone"`
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &zoneOut); err != nil {
		t.Fatal(err)
	}
	var details string
	if err := db.QueryRow(`SELECT details FROM activity_logs WHERE action='create_zone'`).Scan(&details); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !strings.Contains(details, "via MCP") {
		t.Fatalf("create_zone audit must carry via MCP, got %q", details)
	}
}
