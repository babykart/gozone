package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/mcpserver"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/testutil"
)

func TestBuildTargetURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://gozone.example", "https://gozone.example/mcp"},
		{"https://gozone.example/", "https://gozone.example/mcp"},
		{"http://localhost:8080", "http://localhost:8080/mcp"},
		{"https://gozone.example/agent", "https://gozone.example/agent"},
		{"https://gozone.example/agent/", "https://gozone.example/agent/"},
	}
	for _, c := range cases {
		got, err := buildTargetURL(c.in)
		if err != nil || got != c.want {
			t.Errorf("buildTargetURL(%q) = (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "ftp://x", "not a url"} {
		if _, err := buildTargetURL(bad); err == nil {
			t.Errorf("buildTargetURL(%q) must fail", bad)
		}
	}
}

func TestExtractSSEMessages(t *testing.T) {
	body := "event: message\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n" +
		"\n" +
		": keep-alive\n" +
		"\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":2}\n" +
		"\n"
	got := extractSSEMessages(strings.NewReader(body))
	if len(got) != 2 || got[0] != `{"jsonrpc":"2.0","id":1,"result":{}}` || got[1] != `{"jsonrpc":"2.0","id":2}` {
		t.Fatalf("unexpected SSE extraction: %q", got)
	}
}

func newTestBridge(t *testing.T, handler http.HandlerFunc, key string) (*stdioBridge, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &stdioBridge{
		endpoint: srv.URL + "/mcp",
		apiKey:   key,
		client:   srv.Client(),
	}, srv
}

func runBridge(t *testing.T, b *stdioBridge, input string) string {
	t.Helper()
	var out bytes.Buffer
	if err := b.Run(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("bridge run: %v", err)
	}
	return out.String()
}

func TestStdioBridge_JSONResponse(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "sekret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"echo":true}}`) // #nosec G104 -- test helper
	}, "sekret")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n\n")
	if !strings.Contains(out, `"echo":true`) {
		t.Fatalf("expected the JSON response echoed on stdout, got %q", out)
	}
}

func TestStdioBridge_SSEResponse(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":1}}\n\n") // #nosec G104 -- test helper
	}, "k")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`+"\n")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"ok":1`) {
		t.Fatalf("expected one extracted SSE message, got %q", out)
	}
}

func TestStdioBridge_NotificationNoOutput(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}, "k")

	out := runBridge(t, b, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	if strings.TrimSpace(out) != "" {
		t.Fatalf("notification must produce no output, got %q", out)
	}
}

func TestStdioBridge_UpstreamError(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"unauthorized"}`) // #nosec G104 -- test helper
	}, "bad-key")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":42,"method":"tools/list"}`+"\n")
	var resp struct {
		ID    int `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("output is not a JSON-RPC error: %q (%v)", out, err)
	}
	if resp.ID != 42 || resp.Error.Code != -32000 || !strings.Contains(resp.Error.Message, "401") {
		t.Fatalf("wrong error mapping: %+v", resp)
	}
}

func TestStdioBridge_MalformedLine(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("malformed lines must not reach the endpoint")
	}, "k")

	out := runBridge(t, b, "this is not json\n")
	if !strings.Contains(out, "-32700") {
		t.Fatalf("malformed line must yield a parse error, got %q", out)
	}
}

// TestStdioBridge_EndToEndAgainstRealServer drives the bridge against the
// production mcpserver handler behind APIKeyAuth: the same wiring the CLI
// exposes as `gozone mcp stdio`.
func TestStdioBridge_EndToEndAgainstRealServer(t *testing.T) {
	pdnsSrv, pdnsClient := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones") {
			json.NewEncoder(w).Encode([]map[string]any{})
			return
		}
		w.Write([]byte(`{"rrsets":[]}`)) // #nosec G104 -- test helper
	})
	defer pdnsSrv.Close()
	db := testutil.NewTestDB(t)

	userID := testutil.SeedTestUser(t, db, "bridgeuser", "pass", "user", true)
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key := "bridge-" + hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(key))
	if _, err := db.Exec(`INSERT INTO api_keys (user_id, key_hash, description) VALUES (?, ?, 'bridge test')`,
		userID, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(db))
		r.Handle("/mcp", mcpserver.New(dnsops.New(db, pdnsClient), &config.MCPConfig{Enabled: true, Path: "/mcp", ReadOnly: true}, "test"))
	})
	httpSrv := httptest.NewServer(r)
	defer httpSrv.Close()

	bridge := &stdioBridge{endpoint: httpSrv.URL + "/mcp", apiKey: key, client: httpSrv.Client()}
	out := runBridge(t, bridge,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`+"\n"+
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"+
			`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`+"\n")

	if !strings.Contains(out, `"gozone"`) {
		t.Fatalf("initialize response must name the gozone server, got %q", out)
	}
	if !strings.Contains(out, `"list_zones"`) {
		t.Fatalf("tools/list response must include list_zones, got %q", out)
	}
	if !strings.Contains(out, `"export_zone"`) {
		t.Fatalf("tools/list response must include export_zone, got %q", out)
	}

	// Wrong key: the middleware's 401 must surface as a JSON-RPC error.
	bad := &stdioBridge{endpoint: httpSrv.URL + "/mcp", apiKey: "wrong", client: httpSrv.Client()}
	out = runBridge(t, bad, `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`+"\n")
	if !strings.Contains(out, "upstream HTTP 401") {
		t.Fatalf("bad key must surface the 401, got %q", out)
	}
}

func TestMCPStdioCmd_MissingURLAndKey(t *testing.T) {
	if _, err := buildTargetURL(""); err == nil {
		t.Fatal("empty url must fail")
	}
	// The env guard lives in the RunE; pin its message shape via the flag
	// defaults so operators get an actionable error.
	cmd := newMCPStdioCmd()
	if env := cmd.Flags().Lookup("api-key-env"); env == nil || env.DefValue != "GOZONE_API_KEY" {
		t.Fatalf("api-key-env must default to GOZONE_API_KEY, got %+v", env)
	}
}
