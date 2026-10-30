package mcpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
	"github.com/babykart/gozone/internal/testutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// apiKeyRoundTripper injects the API key header on every client request,
// mirroring how a real MCP client passes its GoZone key.
type apiKeyRoundTripper struct {
	key string
	rt  http.RoundTripper
}

func (a *apiKeyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("X-API-Key", a.key)
	return a.rt.RoundTrip(r)
}

// hashKey replicates the middleware's key hashing for seeding.
func hashKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// seedAPIKeyScope seeds an API key with an explicit scope, so tests can drive
// the per-request server selection from either side of the mcp:read/mcp:write
// split.
func seedAPIKeyScope(t *testing.T, db *database.DB, userID int64, scope models.APIKeyScope) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key := "gz-test-" + hex.EncodeToString(raw)
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO api_keys (user_id, key_hash, description, scope) VALUES (?, ?, 'test key', ?)`,
		userID, hashKey(key), scope); err != nil {
		t.Fatal(err)
	}
	return key
}

// newMCPTestEnv wires a full MCP endpoint over a mock PowerDNS: a chi router
// with the production authentication middleware (APIKeyAuth), the dnsops
// service, and an httptest.Server a real SDK client can connect to.
func newMCPTestEnv(t *testing.T, readOnly bool, pdnsHandler testutil.PDNSHandlerFunc) (*mcp.ClientSession, *database.DB) {
	return newMCPTestEnvAs(t, readOnly, pdnsHandler, "user")
}

// newMCPTestEnvAs is newMCPTestEnv with a chosen role for the seeded key
// owner ("user" or "admin").
func newMCPTestEnvAs(t *testing.T, readOnly bool, pdnsHandler testutil.PDNSHandlerFunc, role string) (*mcp.ClientSession, *database.DB) {
	return newMCPTestEnvWithScope(t, readOnly, pdnsHandler, role, models.ScopeMCPWrite)
}

// newMCPTestEnvWithScope is newMCPTestEnvAs with a chosen API key scope.
func newMCPTestEnvWithScope(t *testing.T, readOnly bool, pdnsHandler testutil.PDNSHandlerFunc, role string, scope models.APIKeyScope) (*mcp.ClientSession, *database.DB) {
	t.Helper()
	if pdnsHandler == nil {
		pdnsHandler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodGet {
				w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}
	pdnsSrv, pdnsClient := testutil.NewTestPDNSServer(t, pdnsHandler)
	t.Cleanup(func() { pdnsSrv.Close() })
	db := testutil.NewTestDB(t)
	ops := dnsops.New(db, pdnsClient)

	cfg := &config.MCPConfig{Enabled: true, Path: "/mcp", ReadOnly: readOnly}
	handler := New(ops, cfg, "test-version")

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(db, models.SurfaceMCP))
		r.Handle("/mcp", handler)
	})
	httpSrv := httptest.NewServer(r)
	t.Cleanup(httpSrv.Close)

	userID := testutil.SeedTestUser(t, db, "mcpuser", "pass", role, true)
	key := seedAPIKeyScope(t, db, userID, scope)

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-test-client", Version: "1.0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: httpSrv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: &apiKeyRoundTripper{
			key: key,
			rt:  http.DefaultTransport,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("connect MCP client: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return session, db
}

func toolNames(tools []*mcp.Tool) map[string]bool {
	m := make(map[string]bool, len(tools))
	for _, t := range tools {
		m[t.Name] = true
	}
	return m
}

// grantZoneToMCPUser gives the seeded non-admin user a group grant on zoneID.
func grantZoneToMCPUser(t *testing.T, db *database.DB, zoneID string) {
	t.Helper()
	var userID int64
	if err := db.QueryRow(`SELECT id FROM users WHERE username='mcpuser'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	groupID, err := db.ExecReturnID(context.Background(), `INSERT INTO zone_groups (name) VALUES ('mcpgroup')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO zone_group_members (group_id, user_id) VALUES (?, ?)`, groupID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO zone_group_zones (group_id, zone_id) VALUES (?, ?)`, groupID, zoneID); err != nil {
		t.Fatal(err)
	}
}

func TestToolsList_ReadOnlyFiltering(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := toolNames(res.Tools)
	for _, want := range []string{"list_zones", "get_zone", "list_records", "get_stats", "list_record_types", "export_zone"} {
		if !names[want] {
			t.Errorf("read-only server must list %s; got %v", want, res.Tools)
		}
	}
	for _, banned := range []string{"create_record", "update_record", "delete_record", "create_zone", "delete_zone"} {
		if names[banned] {
			t.Errorf("read-only server must NOT list %s", banned)
		}
	}
}

func TestToolsList_WriteToolsWhenOptedIn(t *testing.T) {
	session, _ := newMCPTestEnv(t, false, nil)
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := toolNames(res.Tools)
	for _, want := range []string{"create_record", "update_record", "delete_record", "create_zone", "delete_zone"} {
		if !names[want] {
			t.Errorf("read_only=false must list %s", want)
		}
	}
}

func TestListZones_NonAdminSeesGrantedZonesOnly(t *testing.T) {
	pdnsHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "a.example.", Name: "a.example.", Kind: "Native"},
			{ID: "b.example.", Name: "b.example.", Kind: "Native"},
		})
	}
	session, db := newMCPTestEnv(t, true, pdnsHandler)

	// Grant the seeded user access to one of the two zones.
	grantZoneToMCPUser(t, db, "a.example.")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_zones"})
	if err != nil {
		t.Fatalf("CallTool list_zones: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_zones failed: %+v", res.Content)
	}
	var out struct {
		Zones []models.Zone `json:"zones"`
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode structured output: %v (%s)", err, b)
	}
	if len(out.Zones) != 1 || out.Zones[0].ID != "a.example." {
		t.Fatalf("non-admin must see only the granted zone, got %+v", out.Zones)
	}
}

func resultText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestGetZone_UngrantedUserForbidden(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no PowerDNS call expected for a refused tool call, got %s %s", r.Method, r.URL.Path)
	})
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "get_zone",
		Arguments: map[string]any{"zone": "guarded.example."},
	})
	if err != nil {
		t.Fatalf("CallTool get_zone: %v", err)
	}
	if !res.IsError {
		t.Fatalf("ungranted get_zone must be a tool error, got %+v", res.Content)
	}
	if text := resultText(res); !strings.HasPrefix(text, "FORBIDDEN:") {
		t.Fatalf("error text must carry the stable FORBIDDEN code, got %q", text)
	}
}

func TestCreateRecord_WritesNormalizeMergeAndAudit(t *testing.T) {
	var sent []models.RRSet
	existing := []models.RRSet{
		{Name: "mail.example.com.", Type: "MX", TTL: 3600, Records: []models.RecordInfo{{Content: "10 mail.example.com."}}},
	}
	pdnsHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(struct {
				RRSets []models.RRSet `json:"rrsets"`
			}{RRSets: existing})
		case http.MethodPatch, http.MethodPut:
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode PATCH: %v", err)
			}
			sent = append(sent, payload.RRSets...)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}
	session, db := newMCPTestEnv(t, false, pdnsHandler)
	grantZoneToMCPUser(t, db, "example.com.")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "create_record",
		Arguments: map[string]any{
			"zone": "example.com.",
			"name": "mail",
			"type": "mx",
			"records": []map[string]any{
				{"content": "backup.example.com", "priority": 20},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool create_record: %v", err)
	}
	if res.IsError {
		t.Fatalf("create_record failed: %s", resultText(res))
	}

	if len(sent) != 1 {
		t.Fatalf("expected one PATCH, got %d", len(sent))
	}
	patch := sent[0]
	if patch.Name != "mail.example.com." {
		t.Errorf("patch name = %q, want mail.example.com. (canonicalised from the bare label)", patch.Name)
	}
	if patch.Type != "MX" {
		t.Errorf("patch type = %q, want MX (uppercased)", patch.Type)
	}
	if len(patch.Records) != 2 {
		t.Fatalf("patch must merge with the existing sibling, got %d records", len(patch.Records))
	}
	found := false
	for _, rec := range patch.Records {
		if rec.Content == "20 backup.example.com." {
			found = true
			if rec.Priority != 0 {
				t.Errorf("priority must be embedded in the content (wire form), got priority=%d", rec.Priority)
			}
		}
	}
	if !found {
		t.Errorf("new record not normalised on the wire: %+v", patch.Records)
	}

	// The audit trail must attribute the write to MCP.
	var details string
	if err := db.QueryRow(`SELECT details FROM activity_logs WHERE action='create_record' AND zone_id='example.com.'`).Scan(&details); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !strings.Contains(details, "via MCP") {
		t.Fatalf("audit details must carry the via MCP label, got %q", details)
	}
}

// TestWriteTools_EmptyRecordsRejected pins the regression where a write tool
// called with records: [] panicked inside the SDK's goroutine (crashing the
// whole process) when no RRSet existed yet: the empty list must now be
// rejected at validation, and the session must stay usable afterwards.
func TestWriteTools_EmptyRecordsRejected(t *testing.T) {
	session, db := newMCPTestEnv(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no PowerDNS call expected for an empty-records submission, got %s %s", r.Method, r.URL.Path)
	})
	grantZoneToMCPUser(t, db, "example.com.")
	ctx := context.Background()

	for _, tool := range []string{"create_record", "update_record"} {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: tool,
			Arguments: map[string]any{
				"zone": "example.com.", "name": "www", "type": "A", "ttl": 300,
				"records": []map[string]any{},
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if !res.IsError {
			t.Fatalf("%s with records: [] must be a tool error, got %+v", tool, res.Content)
		}
		if text := resultText(res); !strings.HasPrefix(text, "VALIDATION_ERROR:") {
			t.Fatalf("%s error text must carry the stable VALIDATION_ERROR code, got %q", tool, text)
		}
	}

	// The session (and with it the process) must have survived the calls.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_record_types"})
	if err != nil {
		t.Fatalf("session must remain usable: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_record_types after rejection failed: %s", resultText(res))
	}
}

// TestRecoverMiddleware_KeepsServerAlive proves the receiving-side recover
// middleware: a panicking tool handler must come back as an isError result
// with the stable INTERNAL_ERROR code, and the server must keep answering
// subsequent calls. The SDK runs handlers in its own goroutines, so without
// this middleware the panic would terminate the process.
func TestRecoverMiddleware_KeepsServerAlive(t *testing.T) {
	type testIn struct{}
	type testOut struct {
		Message string `json:"message"`
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "gozone-test", Version: "test"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "boom", Title: "Boom"}, func(_ context.Context, _ *mcp.CallToolRequest, _ testIn) (*mcp.CallToolResult, testOut, error) {
		panic("kaboom")
	})
	mcp.AddTool(srv, &mcp.Tool{Name: "ping", Title: "Ping"}, func(_ context.Context, _ *mcp.CallToolRequest, _ testIn) (*mcp.CallToolResult, testOut, error) {
		return &mcp.CallToolResult{}, testOut{Message: "pong"}, nil
	})
	srv.AddReceivingMiddleware(recoverMiddleware)

	httpSrv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{Stateless: true}))
	t.Cleanup(httpSrv.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "recover-test-client", Version: "1.0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: httpSrv.URL}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "boom"})
	if err != nil {
		t.Fatalf("CallTool boom: %v", err)
	}
	if !res.IsError {
		t.Fatalf("panicking tool must return an isError result, got %+v", res.Content)
	}
	if text := resultText(res); !strings.HasPrefix(text, "INTERNAL_ERROR:") {
		t.Fatalf("error text must carry the stable INTERNAL_ERROR code, got %q", text)
	}

	res, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "ping"})
	if err != nil {
		t.Fatalf("server must keep answering after a recovered panic: %v", err)
	}
	if res.IsError {
		t.Fatalf("ping after recovered panic failed: %s", resultText(res))
	}
}

// TestCreateRecord_ZoneArgCanonicalized pins the zone-argument
// canonicalisation: a write submitted as "Example.com" must authorize,
// lock, PATCH and audit under the canonical "example.com." — the same key
// the web and REST transports use — instead of taking a second lock and an
// inconsistent audit zone_id.
func TestCreateRecord_ZoneArgCanonicalized(t *testing.T) {
	var sent []models.RRSet
	var patchPath string
	pdnsHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
			return
		}
		patchPath = r.URL.Path
		var payload struct {
			RRSets []models.RRSet `json:"rrsets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode PATCH: %v", err)
		}
		sent = append(sent, payload.RRSets...)
		w.WriteHeader(http.StatusNoContent)
	}
	session, db := newMCPTestEnv(t, false, pdnsHandler)
	grantZoneToMCPUser(t, db, "example.com.")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "create_record",
		Arguments: map[string]any{
			"zone":    "Example.com",
			"name":    "www",
			"type":    "A",
			"records": []map[string]any{{"content": "192.0.2.1"}},
		},
	})
	if err != nil {
		t.Fatalf("CallTool create_record: %v", err)
	}
	if res.IsError {
		t.Fatalf("create_record failed: %s", resultText(res))
	}

	if !strings.HasSuffix(patchPath, "/zones/example.com.") {
		t.Errorf("PATCH must target the canonical zone ID, got path %q", patchPath)
	}
	if len(sent) != 1 || sent[0].Name != "www.example.com." {
		t.Fatalf("record name must be canonicalised against the zone, got %+v", sent)
	}
	// The audit trail must key on the canonical zone ID.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM activity_logs WHERE action='create_record' AND zone_id='example.com.'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit must record zone_id=example.com., got %d matching rows", count)
	}
}

// TestGetZone_ZoneArgCaseInsensitiveForGrantedUser pins the authorization
// side of the canonicalisation: a user granted "example.com." must reach the
// zone with "Example.COM" (case-insensitive DNS), not be fail-closed into a
// spurious FORBIDDEN.
func TestGetZone_ZoneArgCaseInsensitiveForGrantedUser(t *testing.T) {
	session, db := newMCPTestEnv(t, true, richPDNS(t, &[]models.RRSet{}))
	grantZoneToMCPUser(t, db, "example.com.")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "get_zone",
		Arguments: map[string]any{"zone": "Example.COM"},
	})
	if err != nil {
		t.Fatalf("CallTool get_zone: %v", err)
	}
	if res.IsError {
		t.Fatalf("granted user passing a mixed-case zone ID must not be refused, got %s", resultText(res))
	}
	var out struct {
		Zone models.Zone `json:"zone"`
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode structured output: %v (%s)", err, b)
	}
	if out.Zone.ID != "example.com." {
		t.Fatalf("expected the granted zone, got %+v", out.Zone)
	}
}

func TestCreateZone_NonAdminForbidden(t *testing.T) {
	session, db := newMCPTestEnv(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no PowerDNS call expected for a refused tool call, got %s %s", r.Method, r.URL.Path)
	})
	_ = db
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "create_zone",
		Arguments: map[string]any{
			"name":        "new.example.com",
			"nameservers": []string{"ns1.example.com"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool create_zone: %v", err)
	}
	if !res.IsError || !strings.HasPrefix(resultText(res), "FORBIDDEN:") {
		t.Fatalf("non-admin create_zone must fail with FORBIDDEN, got isError=%v text=%q", res.IsError, resultText(res))
	}
}

// TestCreateZone_SlaveRequiresMasters pins the Slave contract on the MCP
// surface: the tool accepts masters and forwards them, refuses a Slave
// without masters, and refuses a hostname as a master address.
func TestCreateZone_SlaveRequiresMasters(t *testing.T) {
	var sent models.ZoneCreateRequest
	session, db := newMCPTestEnvAs(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			json.NewDecoder(r.Body).Decode(&sent)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(models.Zone{ID: sent.Name, Name: sent.Name, Kind: sent.Kind})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}, "admin")
	_ = db

	call := func(args map[string]any) *mcp.CallToolResult {
		res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "create_zone", Arguments: args})
		if err != nil {
			t.Fatalf("CallTool create_zone: %v", err)
		}
		return res
	}

	// Slave without masters is refused before any PowerDNS call.
	res := call(map[string]any{"name": "slave.example.com", "kind": "Slave", "nameservers": []string{}})
	if !res.IsError || !strings.HasPrefix(resultText(res), "VALIDATION_ERROR:") || !strings.Contains(resultText(res), "at least one master") {
		t.Fatalf("Slave without masters must fail with VALIDATION_ERROR, got isError=%v text=%q", res.IsError, resultText(res))
	}

	// A hostname as master is refused.
	res = call(map[string]any{"name": "slave.example.com", "kind": "Slave", "nameservers": []string{}, "masters": []string{"ns1.example.com."}})
	if !res.IsError || !strings.Contains(resultText(res), "invalid master") {
		t.Fatalf("a hostname as master must fail with VALIDATION_ERROR, got isError=%v text=%q", res.IsError, resultText(res))
	}

	// Slave with valid masters is created and they are forwarded.
	res = call(map[string]any{"name": "slave.example.com", "kind": "Slave", "nameservers": []string{}, "masters": []string{"192.0.2.53"}})
	if res.IsError {
		t.Fatalf("Slave with a valid master must succeed, got %q", resultText(res))
	}
	if len(sent.Masters) != 1 || sent.Masters[0] != "192.0.2.53" {
		t.Errorf("masters not forwarded to PowerDNS: %+v", sent.Masters)
	}
}

func TestUnauthenticatedRequestRejected(t *testing.T) {
	// A bare HTTP POST without an API key must be refused by the middleware
	// before any MCP handling: 401 JSON envelope — the same gate as /api/v1.
	pdnsSrv, pdnsClient := testutil.NewTestPDNSServer(t, nil)
	defer pdnsSrv.Close()
	db := testutil.NewTestDB(t)
	handler := New(dnsops.New(db, pdnsClient), &config.MCPConfig{Enabled: true, Path: "/mcp", ReadOnly: true}, "test")

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(db, models.SurfaceMCP))
		r.Handle("/mcp", handler)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request without an API key must get 401, got %d", resp.StatusCode)
	}
}

func TestOriginGuard(t *testing.T) {
	guard := newOriginGuard([]string{"https://claude.ai"})
	allowed := guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// No Origin (agent/CLI client): passes.
	w := httptest.NewRecorder()
	allowed.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("no Origin header must pass, got %d", w.Code)
	}

	// Allowed origin: passes.
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Origin", "https://claude.ai")
	allowed.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("allowed Origin must pass, got %d", w.Code)
	}

	// Disallowed origin: 403, fail-closed.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Origin", "https://evil.example")
	allowed.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("disallowed Origin must be rejected with 403, got %d", w.Code)
	}

	// Empty allow-list: every Origin-bearing request is rejected.
	closed := newOriginGuard(nil).Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Origin", "https://claude.ai")
	closed.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("empty allow-list must reject all Origins, got %d", w.Code)
	}
}

func TestMapServiceError(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		notFoundCode string
		wantCode     string
	}{
		{"forbidden", dnsops.ErrForbidden, codeZoneNotFound, "FORBIDDEN"},
		{"zone fetch not found", &dnsops.StageError{Stage: dnsops.StageFetch, Err: pdns.ErrNotFound}, codeZoneNotFound, "ZONE_NOT_FOUND"},
		{"patch not found", &dnsops.StageError{Stage: dnsops.StagePatch, Err: pdns.ErrNotFound}, codeRecordNotFound, "RECORD_NOT_FOUND"},
		{"zone access fault", &dnsops.StageError{Stage: dnsops.StageZoneAccess, Err: pdns.ErrNotFound}, codeZoneNotFound, "INTERNAL_ERROR"},
		// Zone operations (GetZone, ListRecords, ListZones, CreateZone,
		// DeleteZone) return the typed PowerDNS error unwrapped: it must
		// map to the same codes as the StageError-wrapped record paths,
		// with notFoundCode as the per-tool default.
		{"unwrapped not found, zone default", pdns.ErrNotFound, codeZoneNotFound, "ZONE_NOT_FOUND"},
		{"unwrapped not found, record default", pdns.ErrNotFound, codeRecordNotFound, "RECORD_NOT_FOUND"},
		{"unwrapped conflict", pdns.ErrConflict, codeZoneNotFound, "CONFLICT"},
		{"unwrapped validation", pdns.ErrValidation, codeZoneNotFound, "VALIDATION_ERROR"},
		{"unwrapped unauthorized", pdns.ErrUnauthorized, codeZoneNotFound, "UPSTREAM_AUTH_ERROR"},
		{"unwrapped lua disabled", pdns.ErrLuaUpdatesDisabled, codeZoneNotFound, "LUA_UPDATES_DISABLED"},
	}
	for _, c := range cases {
		te, _ := mapServiceError(c.err, c.notFoundCode)
		if te == nil || te.code != c.wantCode {
			t.Errorf("%s: got %v, want code %s", c.name, te, c.wantCode)
		}
	}
	// Unknown errors keep their cause for server-side logging while the
	// client sees a generic internal error.
	te, cause := mapServiceError(errors.New("boom: dsn=secret"), codeZoneNotFound)
	if te.code != "INTERNAL_ERROR" {
		t.Errorf("unknown error must map to INTERNAL_ERROR, got %s", te.code)
	}
	if strings.Contains(te.msg, "dsn") {
		t.Errorf("internal detail leaked into the client-facing message: %q", te.msg)
	}
	if cause == nil {
		t.Error("unknown error must return its cause for logging")
	}
}

// TestFail pins the write-tool failure funnel: a non-nil service error must
// always produce a tool error carrying the mapped code, so a caller can
// return unconditionally instead of testing the mapping result.
func TestFail(t *testing.T) {
	cases := []struct {
		name         string
		err          error
		notFoundCode string
		wantPrefix   string
	}{
		{"forbidden", dnsops.ErrForbidden, codeZoneNotFound, "FORBIDDEN:"},
		{"unwrapped not found", pdns.ErrNotFound, codeZoneNotFound, "ZONE_NOT_FOUND:"},
		{"unknown", errors.New("boom: dsn=secret"), codeZoneNotFound, "INTERNAL_ERROR:"},
	}
	for _, c := range cases {
		err := fail("some_tool", c.err, c.notFoundCode)
		if err == nil || !strings.HasPrefix(err.Error(), c.wantPrefix) {
			t.Errorf("%s: fail() = %v, want a tool error prefixed %q", c.name, err, c.wantPrefix)
		}
	}
}

// TestZoneTools_UnwrappedPDNSErrorsMapToStableCodes pins the REST↔MCP error
// parity for zone operations end to end: the service returns the PowerDNS
// error unwrapped there, and a 404/409 from the mock must surface as
// ZONE_NOT_FOUND/CONFLICT (the codes the migrate_record prompt tells agents
// to branch on), not INTERNAL_ERROR.
func TestZoneTools_UnwrappedPDNSErrorsMapToStableCodes(t *testing.T) {
	session, _ := newMCPTestEnvAs(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodPost: // create_zone
			w.WriteHeader(http.StatusConflict)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}, "admin")
	ctx := context.Background()

	cases := []struct {
		tool     string
		args     map[string]any
		wantCode string
	}{
		{"get_zone", map[string]any{"zone": "missing.example."}, "ZONE_NOT_FOUND"},
		{"delete_zone", map[string]any{"zone": "missing.example."}, "ZONE_NOT_FOUND"},
		{"create_zone", map[string]any{"name": "conflict.example.com", "nameservers": []string{"ns1.example.com"}}, "CONFLICT"},
	}
	for _, c := range cases {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: c.tool, Arguments: c.args})
		if err != nil {
			t.Fatalf("%s: %v", c.tool, err)
		}
		if !res.IsError {
			t.Fatalf("%s must be a tool error, got %+v", c.tool, res.Content)
		}
		if text := resultText(res); !strings.HasPrefix(text, c.wantCode+":") {
			t.Fatalf("%s error text must carry the stable %s code, got %q", c.tool, c.wantCode, text)
		}
	}
}

// TestToolsList_ScopeBoundedToolSet locks the per-request server selection:
// the tools/list answer follows the API key's scope, not just mcp.read_only.
// mcp:read never sees the write tools even when read_only=false; mcp:write
// sees them only when read_only=false.
func TestToolsList_ScopeBoundedToolSet(t *testing.T) {
	writeTools := []string{"create_record", "update_record", "delete_record", "create_zone", "delete_zone"}

	t.Run("mcp read never sees write tools", func(t *testing.T) {
		session, _ := newMCPTestEnvWithScope(t, false, nil, "user", models.ScopeMCPRead)
		res, err := session.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		names := toolNames(res.Tools)
		for _, banned := range writeTools {
			if names[banned] {
				t.Errorf("mcp:read key with read_only=false must NOT list %s", banned)
			}
		}
		if !names["list_zones"] || !names["export_zone"] {
			t.Errorf("mcp:read key must keep the read tools, got %v", res.Tools)
		}
	})

	t.Run("mcp write sees write tools when read_only false", func(t *testing.T) {
		session, _ := newMCPTestEnvWithScope(t, false, nil, "user", models.ScopeMCPWrite)
		res, err := session.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		names := toolNames(res.Tools)
		for _, want := range writeTools {
			if !names[want] {
				t.Errorf("mcp:write key with read_only=false must list %s", want)
			}
		}
	})

	t.Run("read only wins over mcp write", func(t *testing.T) {
		session, _ := newMCPTestEnvWithScope(t, true, nil, "user", models.ScopeMCPWrite)
		res, err := session.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		names := toolNames(res.Tools)
		for _, banned := range writeTools {
			if names[banned] {
				t.Errorf("mcp.read_only=true must hide %s even from an mcp:write key", banned)
			}
		}
	})
}

// TestRequireWriteScope_Guard is the unit test of the defence-in-depth guard:
// a write tool handler context carrying any scope other than mcp:write (or no
// scope at all) is refused with the stable FORBIDDEN text.
func TestRequireWriteScope_Guard(t *testing.T) {
	mkctx := func(scope models.APIKeyScope, withScope bool) context.Context {
		ctx := context.Background()
		if withScope {
			ctx = context.WithValue(ctx, middleware.APIKeyScopeContextKey, scope)
		}
		return ctx
	}

	if terr := requireWriteScope(mkctx(models.ScopeMCPWrite, true)); terr != nil {
		t.Errorf("mcp:write context must pass the guard, got %v", terr)
	}
	for _, tc := range []struct {
		name      string
		scope     models.APIKeyScope
		withScope bool
	}{
		{"mcp read", models.ScopeMCPRead, true},
		{"api write", models.ScopeAPIWrite, true},
		{"api read", models.ScopeAPIRead, true},
		{"no scope", "", false},
	} {
		terr := requireWriteScope(mkctx(tc.scope, tc.withScope))
		if terr == nil {
			t.Errorf("%s: guard must refuse", tc.name)
			continue
		}
		if terr.code != codeForbidden || terr.msg != "API key scope does not allow write operations" {
			t.Errorf("%s: guard must answer FORBIDDEN with the stable text, got %q %q", tc.name, terr.code, terr.msg)
		}
	}
}
