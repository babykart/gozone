package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/mcpserver"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func TestBuildTargetURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://gozone.example", "https://gozone.example/mcp"},
		{"https://gozone.example/", "https://gozone.example/mcp"},
		{"http://localhost:8080", "http://localhost:8080/mcp"},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080/mcp"},
		{"http://[::1]:8080", "http://[::1]:8080/mcp"},
		{"https://gozone.example/agent", "https://gozone.example/agent"},
		{"https://gozone.example/agent/", "https://gozone.example/agent/"},
	}
	for _, c := range cases {
		got, err := buildTargetURL(c.in, false)
		if err != nil || got != c.want {
			t.Errorf("buildTargetURL(%q) = (%q, %v), want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "ftp://x", "not a url", "http:///mcp"} {
		if _, err := buildTargetURL(bad, false); err == nil {
			t.Errorf("buildTargetURL(%q) must fail", bad)
		}
	}

	// Cleartext HTTP to a non-loopback host would send the API key
	// unencrypted: refused without --insecure, allowed with it.
	if _, err := buildTargetURL("http://gozone.example", false); err == nil {
		t.Error("plaintext http:// to a remote host must be refused")
	} else if !strings.Contains(err.Error(), "--insecure") {
		t.Errorf("refusal must name the escape hatch, got %v", err)
	}
	if got, err := buildTargetURL("http://gozone.example", true); err != nil || got != "http://gozone.example/mcp" {
		t.Errorf("buildTargetURL(plaintext, insecure) = (%q, %v), want the remote endpoint", got, err)
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
	got, err := extractSSEMessages(strings.NewReader(body))
	if err != nil {
		t.Fatalf("clean stream must not error: %v", err)
	}
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

// TestStdioBridge_RelaysJSONRPCErrorBody pins the error-body relay: when the
// upstream answers a non-2xx whose body is the actual JSON-RPC error
// response (the SDK's protocol-level failures), the client must receive it
// verbatim — not a generic "upstream HTTP n" line that hides the code and
// message.
func TestStdioBridge_RelaysJSONRPCErrorBody(t *testing.T) {
	upstream := `{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"invalid params: unknown tool"}}`
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, upstream) // #nosec G104 -- test helper
	}, "k")

	out := strings.TrimSpace(runBridge(t, b, `{"jsonrpc":"2.0","id":5,"method":"tools/call"}`+"\n"))
	if out != upstream {
		t.Fatalf("the upstream JSON-RPC error body must be relayed verbatim, got %q", out)
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
	testutil.SeedTestAPIKeyScope(t, db, userID, key, nil, models.ScopeMCPWrite)

	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(db, models.SurfaceMCP, 0))
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

// TestMCPStdioCmd_EmptyAPIKeyFailsBeforeIO characterizes the RunE guard:
// when the --api-key-env variable resolves to an empty value, the command
// must fail with an actionable error BEFORE any network or stdin work. The
// referenced env var is deliberately never set (no t.Setenv): the guard
// fires purely on the empty lookup, so the test cannot hang on stdin or
// reach the 127.0.0.1:1 endpoint.
func TestMCPStdioCmd_EmptyAPIKeyFailsBeforeIO(t *testing.T) {
	// Pin the precondition: the env var must be empty even if the outer
	// environment happens to define it, so the guard fires deterministically
	// before any stdin/network work.
	t.Setenv("GOZONE_TEST_NO_SUCH_KEY", "")

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		"mcp", "stdio",
		"--url", "http://127.0.0.1:1/mcp",
		"--api-key-env", "GOZONE_TEST_NO_SUCH_KEY",
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("an empty API key must fail the command")
	}
	if !strings.Contains(err.Error(), "GOZONE_TEST_NO_SUCH_KEY") {
		t.Errorf("error must name the empty env var, got %v", err)
	}
	if !strings.Contains(err.Error(), "is empty") {
		t.Errorf("error must say the key is empty, got %v", err)
	}
}

func TestMCPStdioCmd_MissingURLAndKey(t *testing.T) {
	if _, err := buildTargetURL("", false); err == nil {
		t.Fatal("empty url must fail")
	}
	// The env guard lives in the RunE; pin its message shape via the flag
	// defaults so operators get an actionable error.
	cmd := newMCPStdioCmd()
	if env := cmd.Flags().Lookup("api-key-env"); env == nil || env.DefValue != "GOZONE_API_KEY" {
		t.Fatalf("api-key-env must default to GOZONE_API_KEY, got %+v", env)
	}
	if f := cmd.Flags().Lookup("insecure"); f == nil || f.DefValue != "false" {
		t.Fatalf("insecure must exist and default to false, got %+v", f)
	}
}

// TestStdioBridge_RedirectNotFollowed pins the credential-leak guard on the
// production bridge client: the API key travels in the X-API-Key header,
// which net/http does not strip on cross-host redirects, so following a 307 —
// e.g. to another host, possibly downgraded to http:// — would replay the
// credential to the redirect target. The client must refuse redirects; the
// 3xx then reaches relay()'s default branch and surfaces as a JSON-RPC error
// instead of a silent credential leak.
func TestStdioBridge_RedirectNotFollowed(t *testing.T) {
	var targetHits atomic.Int64
	var capturedKey atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		capturedKey.Store(r.Header.Get("X-API-Key"))
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"followed":true}}`) // #nosec G104 -- test helper
	}))
	t.Cleanup(target.Close)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/mcp")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	// Production client (not srv.Client()): the guard must live in the client
	// the RunE actually uses.
	b := &stdioBridge{
		endpoint: redirector.URL + "/mcp",
		apiKey:   "sekret",
		client:   newMCPBridgeClient(),
	}

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n")

	if targetHits.Load() != 0 {
		t.Fatalf("redirect target must never be contacted, got %d hits (key replay risk)", targetHits.Load())
	}
	if k := capturedKey.Load(); k != nil && k.(string) != "" {
		t.Fatalf("redirect target captured the API key: %q", k.(string))
	}
	var resp struct {
		ID    int `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("stdout must carry a JSON-RPC error, got %q: %v", out, err)
	}
	if resp.ID != 1 || resp.Error.Code != -32000 || !strings.Contains(resp.Error.Message, "HTTP 307") {
		t.Fatalf("expected id 1 / -32000 / HTTP 307, got id=%d code=%d msg=%q", resp.ID, resp.Error.Code, resp.Error.Message)
	}
}

// TestStdioBridge_PrettyJSONBodyStaysOneLine pins NDJSON framing: a JSON
// body with internal newlines (an intermediate proxy pretty-printing or
// indenting it, for instance) must still be relayed as ONE stdout line —
// stdout is newline-delimited, so splitting one value across lines corrupts
// the protocol stream.
func TestStdioBridge_PrettyJSONBodyStaysOneLine(t *testing.T) {
	body := "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"result\": {\"echo\": true}\n}"
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body) // #nosec G104 -- test helper
	}, "k")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")

	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("indented JSON body must stay one stdout line, got %d: %q", len(lines), out)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &value); err != nil {
		t.Fatalf("the single line must parse as JSON: %v (%q)", err, lines[0])
	}
	if !strings.Contains(lines[0], `"echo":true`) {
		t.Fatalf("compacted line must carry the result, got %q", lines[0])
	}
}

// TestStdioBridge_CompactJSONRoundTripsVerbatim is the regression twin of
// the pretty-body test: an already-compact JSON body must come out
// byte-identical (single line), not reformatted.
func TestStdioBridge_CompactJSONRoundTripsVerbatim(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"result":{"echo":true}}`
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body) // #nosec G104 -- test helper
	}, "k")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if out != body+"\n" {
		t.Fatalf("compact body must round-trip byte-identically, got %q", out)
	}
}

// TestStdioBridge_OverLimitJSONAnsweredNotRelayed pins the bounded read on
// the JSON-200 branch: an upstream body over bridgeMaxResponseBytes must
// NOT be relayed (it would be a truncated, unparseable value) — the bridge
// must answer the request with a -32603 error instead.
func TestStdioBridge_OverLimitJSONAnsweredNotRelayed(t *testing.T) {
	body := strings.Repeat("a", int(bridgeMaxResponseBytes)+1024)
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body) // #nosec G104 -- test helper
	}, "k")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")

	if len(out) > len(body)/2 {
		t.Fatalf("oversized body must not be relayed (stdout %d bytes)", len(out))
	}
	var resp struct {
		ID    int `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("stdout must carry a JSON-RPC error, got %q: %v", out, err)
	}
	if resp.ID != 1 || resp.Error.Code != -32603 {
		t.Fatalf("expected id 1 / -32603, got id=%d code=%d", resp.ID, resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "exceeds") || !strings.Contains(resp.Error.Message, "byte") {
		t.Fatalf("error must mention the byte limit, got %q", resp.Error.Message)
	}
}

// errReader fails every read with a fixed error, simulating a stream cut.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("kaboom") }

// TestExtractSSEMessages_ReportsStreamError pins the scanner-error
// contract: a mid-stream read failure surfaces as an error, and the
// complete messages extracted before the failure are still returned.
func TestExtractSSEMessages_ReportsStreamError(t *testing.T) {
	got, err := extractSSEMessages(io.MultiReader(strings.NewReader("data: {\"partial\":true}\n\n"), errReader{}))
	if err == nil {
		t.Fatal("a stream cut must surface as an error")
	}
	if len(got) != 1 || got[0] != `{"partial":true}` {
		t.Fatalf("the pre-error message must still be returned, got %q", got)
	}
}

// TestStdioBridge_SSEStreamCutAnswersRequest pins the user-visible half of
// the scanner-error fix: an upstream that dies mid-SSE-stream (partial data
// line, connection aborted) must still get the request an answer — without
// it the MCP client blocks until its own timeout.
func TestStdioBridge_SSEStreamCutAnswersRequest(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Unterminated payload: no blank line, then the connection is cut.
		io.WriteString(w, `data: {"jsonrpc":"2.0","id":1,"res`) // #nosec G104 -- test helper
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}, "k")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`+"\n")

	var resp struct {
		ID    int `json:"id"`
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("stdout must carry a JSON-RPC error, got %q: %v", out, err)
	}
	if resp.ID != 1 || resp.Error.Code != -32603 {
		t.Fatalf("expected id 1 / -32603, got id=%d code=%d", resp.ID, resp.Error.Code)
	}
}

// TestStdioBridge_SSEErrorAfterCompleteAnswerNoDuplicate pins the no-double
// answer rule: when the SSE stream delivers the complete response for the
// request id and THEN fails, the bridge relays the response and must NOT
// synthesize a second (-32603) response for the same id — JSON-RPC has no
// second response for a completed request.
func TestStdioBridge_SSEErrorAfterCompleteAnswerNoDuplicate(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n") // #nosec G104 -- test helper
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler) // cut the connection after the complete response
	}, "sekret")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`+"\n")
	lines := nonEmptyLines(out)
	if len(lines) != 1 {
		t.Fatalf("exactly one stdout message expected, got %d: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], `"ok":true`) || strings.Contains(lines[0], "-32603") {
		t.Fatalf("the real response must be the only message, got %q", lines[0])
	}
}

// TestStdioBridge_ExactLimitJSONRelayed locks the limit+1 boundary: a body
// of exactly bridgeMaxResponseBytes is valid and must be relayed (only
// limit+1 triggers the overflow answer).
func TestStdioBridge_ExactLimitJSONRelayed(t *testing.T) {
	prefix := `{"jsonrpc":"2.0","id":1,"result":{"pad":"`
	suffix := `"}}`
	fill := strings.Repeat("a", int(bridgeMaxResponseBytes)-len(prefix)-len(suffix))
	body := prefix + fill + suffix
	if int64(len(body)) != bridgeMaxResponseBytes {
		t.Fatalf("test setup: body must be exactly the limit, got %d", len(body))
	}
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body) // #nosec G104 -- test helper
	}, "sekret")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`+"\n")
	if strings.Contains(out, "-32603") || !strings.Contains(out, `"pad"`) {
		t.Fatalf("exact-limit body must be relayed verbatim, got %d bytes / prefix %q", len(out), firstLine(out))
	}
}

// TestExtractSSEMessages_CleanEOFWithoutTrailingBlankLineFlushes pins the
// framing rule: a stream that ends cleanly WITHOUT the final blank line
// still delivers its last complete data payload (flush at EOF), while a
// stream CUT (scanner error) drops unterminated data.
func TestExtractSSEMessages_CleanEOFWithoutTrailingBlankLineFlushes(t *testing.T) {
	got, err := extractSSEMessages(strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":7}\n"))
	if err != nil {
		t.Fatalf("clean EOF must not error: %v", err)
	}
	if len(got) != 1 || got[0] != `{"jsonrpc":"2.0","id":7}` {
		t.Fatalf("final event without trailing blank line must flush, got %q", got)
	}
}

// TestJSONIDEqual pins semantic JSON id equality: equal VALUES compare equal
// regardless of encoding ("a" == "\u0061", 1 == 1e0), different types or
// values do not, and big integers survive without float64 coercion.
func TestJSONIDEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		{"identical strings", `"a"`, `"a"`, true},
		{"escaped vs literal string", `"\u0061"`, `"a"`, true},
		{"number equal exact", `1`, `1`, true},
		{"number exponent form", `1`, `1e0`, true},
		{"number big integer", `12345678901234567890123`, `12345678901234567890123`, true},
		{"string vs number", `"1"`, `1`, false},
		{"different numbers", `1`, `2`, false},
		{"different strings", `"a"`, `"b"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jsonIDEqual(json.RawMessage(tc.a), json.RawMessage(tc.b)); got != tc.want {
				t.Fatalf("jsonIDEqual(%s, %s) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestStdioBridge_SSEErrorEscapedIDNoDuplicate extends the no-double-answer
// rule to semantically-equal-but-differently-encoded ids: the request carries
// id "\u0061" while the SSE response uses its decoded form "a". The two are
// the SAME id, so the stream error after the complete response must not
// synthesize a second response.
func TestStdioBridge_SSEErrorEscapedIDNoDuplicate(t *testing.T) {
	b, _ := newTestBridge(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":\"a\",\"result\":{\"ok\":true}}\n\n") // #nosec G104 -- test helper
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}, "sekret")

	out := runBridge(t, b, `{"jsonrpc":"2.0","id":"\u0061","method":"initialize","params":{}}`+"\n")
	lines := nonEmptyLines(out)
	if len(lines) != 1 {
		t.Fatalf("exactly one stdout message expected, got %d: %q", len(lines), out)
	}
	if !strings.Contains(lines[0], `"ok":true`) || strings.Contains(lines[0], "-32603") {
		t.Fatalf("the real response must be the only message, got %q", lines[0])
	}
}

func nonEmptyLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
