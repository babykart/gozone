// mcp.go defines the `gozone mcp` command tree: a namespace whose only
// subcommand today is `stdio`, a transport bridge for MCP clients that only
// speak the stdio transport. The bridge contains NO business logic: it
// relays line-delimited JSON-RPC from stdin to a remote GoZone `/mcp`
// endpoint over Streamable HTTP and writes the responses back on stdout.
package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/babykart/gozone/internal/logger"
)

// bridgeMaxResponseBytes caps how much of a single upstream JSON response
// the bridge reads into memory (the SSE scanner applies the same value as a
// PER-LINE limit, and the HTTP-error branch reads at most 1 MiB — the SSE
// aggregate is therefore not bounded by this constant alone). 32 MiB is
// generous for any MCP message.
const bridgeMaxResponseBytes int64 = 32 << 20

// newMCPCmd builds the `gozone mcp` namespace. Bare `gozone mcp` prints help,
// like the root command.
func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "mcp",
		Short:         "MCP (Model Context Protocol) utilities",
		Long:          "MCP (Model Context Protocol) utilities. `gozone mcp stdio` bridges a stdio-only MCP client to a remote GoZone /mcp endpoint over Streamable HTTP.",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(newMCPStdioCmd())
	return cmd
}

// newMCPStdioCmd builds `gozone mcp stdio`: read newline-delimited JSON-RPC
// on stdin, POST each message to the remote endpoint, write responses (JSON
// or SSE-extracted) back on stdout. Designed for MCP client configurations
// of the form:
//
//	gozone mcp stdio --url https://gozone.example --api-key-env GOZONE_API_KEY
func newMCPStdioCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stdio",
		Short: "Bridge stdio to a remote GoZone MCP endpoint",
		Long: `Bridge a stdio MCP client to a remote GoZone MCP endpoint.

Reads newline-delimited JSON-RPC 2.0 messages on stdin, forwards each one as
a Streamable HTTP POST to the remote /mcp endpoint (authenticated with the
API key found in the --api-key-env variable, sent as X-API-Key), and writes
each response message back on stdout. Notifications (messages without an id)
are forwarded but produce no output, matching MCP stdio semantics.

The remote GoZone server is stateless, so no session state is kept locally.
Logs go to stderr only — stdout is reserved for the protocol.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(c *cobra.Command, args []string) error {
			rawURL, _ := c.Flags().GetString("url")
			envName, _ := c.Flags().GetString("api-key-env")
			insecure, _ := c.Flags().GetBool("insecure")

			endpoint, err := buildTargetURL(rawURL, insecure)
			if err != nil {
				return err
			}
			if insecure && strings.HasPrefix(endpoint, "http://") {
				logger.Warn("mcp stdio bridge: --insecure sends the API key over cleartext HTTP — prefer https")
			}
			apiKey := strings.TrimSpace(os.Getenv(envName))
			if apiKey == "" {
				return fmt.Errorf("the %s environment variable is empty: set it to a GoZone API key (the bridge authenticates every request with it)", envName)
			}

			bridge := &stdioBridge{
				endpoint: endpoint,
				apiKey:   apiKey,
				client:   newMCPBridgeClient(),
			}
			return bridge.Run(context.Background(), os.Stdin, os.Stdout)
		},
	}
	cmd.Flags().String("url", "", "base URL of the remote GoZone (e.g. https://gozone.example) or the full endpoint URL (e.g. https://gozone.example/mcp); required")
	cmd.Flags().String("api-key-env", "GOZONE_API_KEY", "name of the environment variable holding the GoZone API key")
	cmd.Flags().Bool("insecure", false, "allow plaintext http:// to a non-loopback host (the API key travels unencrypted; prefer https)")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

// newMCPBridgeClient returns the HTTP client for the stdio bridge. Redirects
// are refused (http.ErrUseLastResponse): the GoZone API key travels in the
// X-API-Key header, which net/http does not strip on cross-host redirects, so
// following one — e.g. a 30x to another host, possibly downgraded to
// http:// — would replay the credential to the redirect target. The /mcp
// endpoint has no legitimate redirect use; a 3xx reaches relay()'s default
// branch and is reported to the MCP client as an upstream HTTP error.
func newMCPBridgeClient() *http.Client {
	return &http.Client{
		Timeout:       120 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// buildTargetURL normalises the --url flag: a base URL without a path gets
// the default /mcp endpoint appended; a URL that already carries a path is
// used verbatim. Non-HTTP(S) schemes are rejected.
//
// allowPlaintextRemote (--insecure) is the explicit opt-out for the
// cleartext guard: without it, an http:// URL may only target a loopback
// host — every request carries the API key in a header, so a plaintext
// remote URL would hand the credential to every hop on the way there.
func buildTargetURL(raw string, allowPlaintextRemote bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("--url is required (e.g. https://gozone.example)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid --url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid --url %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid --url %q: no host", raw)
	}
	if u.Scheme == "http" && !allowPlaintextRemote && !isLoopbackHost(u.Hostname()) {
		return "", fmt.Errorf("refusing to send the API key over cleartext HTTP to %q: use https, target a loopback host, or pass --insecure", u.Hostname())
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/mcp"
	}
	return u.String(), nil
}

// isLoopbackHost reports whether an URL hostname is local: the literal
// "localhost" or an IP in the loopback range (127.0.0.0/8, ::1).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// stdioBridge relays MCP JSON-RPC between an io.Reader (stdin) and a remote
// Streamable HTTP endpoint, writing response messages to an io.Writer
// (stdout). It is a transport only: it understands the message FRAMING (id
// present = request, absent = notification; SSE data extraction) but never
// the payload.
type stdioBridge struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

// jsonrpcEnvelope is the minimal shape the bridge needs: whether the message
// is a request (id present and non-null) and its method, for error reporting.
type jsonrpcEnvelope struct {
	ID     *json.RawMessage `json:"id"`
	Method string           `json:"method,omitempty"`
}

// Run pumps messages until the reader reaches EOF or the context is
// canceled. Messages are handled sequentially: stdio MCP clients wait for
// each response before sending the next request, and a single in-flight
// POST keeps the failure modes obvious.
func (b *stdioBridge) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Requests can carry large arguments (update_record with many records);
	// allow generous lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if err := b.relay(ctx, line, out); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// relay forwards one message and writes zero or more response lines.
func (b *stdioBridge) relay(ctx context.Context, line string, out io.Writer) error {
	var env jsonrpcEnvelope
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		writeJSONRPCError(out, nil, -32700, "parse error: not valid JSON-RPC")
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, strings.NewReader(line))
	if err != nil {
		if env.ID != nil {
			writeJSONRPCError(out, env.ID, -32603, "internal error: build request: "+err.Error())
		}
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-API-Key", b.apiKey)

	resp, err := b.client.Do(req)
	if err != nil {
		if env.ID != nil {
			writeJSONRPCError(out, env.ID, -32603, "transport error: "+err.Error())
		}
		logger.Warn("mcp stdio bridge: request failed", "error", err)
		return nil
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK && isEventStream(resp.Header.Get("Content-Type")):
		// SSE-framed response: each complete data: payload is one JSON-RPC
		// message. The stateless server sends exactly one per POST, but the
		// parser handles any count.
		messages, err := extractSSEMessages(resp.Body)
		// Relay whatever complete messages were extracted before the failure,
		// then make sure the request is never left unanswered: the MCP client
		// would otherwise block until its own timeout. A request that already
		// received its response must NOT be answered twice — JSON-RPC has no
		// second response for a completed id — so the synthetic error is
		// emitted only when no relayed message answered it.
		answered := false
		for _, msg := range messages {
			writeLine(out, msg)
			if !answered && messageAnswersID(msg, env.ID) {
				answered = true
			}
		}
		if err != nil {
			if env.ID != nil && !answered {
				writeJSONRPCError(out, env.ID, -32603, "internal error: "+err.Error())
			}
			logger.Warn("mcp stdio bridge: SSE stream error", "error", err)
		}
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(io.LimitReader(resp.Body, bridgeMaxResponseBytes+1))
		if err != nil {
			if env.ID != nil {
				writeJSONRPCError(out, env.ID, -32603, "internal error: read response: "+err.Error())
			}
			return nil
		}
		if int64(len(body)) > bridgeMaxResponseBytes {
			// The limit+1 read distinguishes an exactly-at-limit body from an
			// over-limit one: over the limit, the payload cannot be trusted
			// complete — answer the request instead of relaying a truncated
			// (therefore unparseable) JSON value.
			if env.ID != nil {
				writeJSONRPCError(out, env.ID, -32603, fmt.Sprintf("internal error: response exceeds %d-byte limit", bridgeMaxResponseBytes))
			}
			logger.Warn("mcp stdio bridge: upstream response over limit", "bytes", len(body))
			return nil
		}
		if trimmed := strings.TrimSpace(string(body)); trimmed != "" {
			writeLine(out, trimmed)
		}
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent:
		// Notification accepted: no output, matching stdio semantics.
	default:
		// Upstream refused (401 bad key, 403 origin, 404 disabled endpoint,
		// 5xx ...). The MCP server answers some protocol-level failures with
		// an HTTP error status whose body is the actual JSON-RPC error
		// response — relay that verbatim so the client sees the real code
		// and message instead of a generic status line. Anything else (e.g.
		// the middleware's plain JSON envelope) falls back to a synthesized
		// JSON-RPC error carrying the status.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			if msg, ok := jsonRPCErrorMessage(body); ok {
				writeLine(out, msg)
				logger.Warn("mcp stdio bridge: relayed upstream JSON-RPC error", "status", resp.StatusCode, "method", env.Method)
				return nil
			}
		}
		if env.ID != nil {
			writeJSONRPCError(out, env.ID, -32000, fmt.Sprintf("upstream HTTP %d from %s", resp.StatusCode, b.endpoint))
		}
		logger.Warn("mcp stdio bridge: upstream error", "status", resp.StatusCode, "method", env.Method)
	}
	return nil
}

// jsonRPCErrorMessage reports whether body is a complete JSON-RPC 2.0 error
// response (the shape the remote MCP server returns for protocol-level
// failures). Only such bodies are relayed verbatim; anything else might be
// an HTML error page or a non-RPC JSON envelope that would confuse the
// client's parser.
func jsonRPCErrorMessage(body []byte) (string, bool) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", false
	}
	var probe struct {
		JSONRPC string `json:"jsonrpc"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil || probe.JSONRPC != "2.0" || probe.Error == nil {
		return "", false
	}
	return trimmed, true
}

// isEventStream reports whether a Content-Type header names text/event-stream.
func isEventStream(ct string) bool {
	return strings.HasPrefix(ct, "text/event-stream")
}

// messageAnswersID reports whether a relayed JSON-RPC message is a RESPONSE
// (an id present, no method — server-initiated requests carry a method and
// notifications carry no id) matching the request id. The SSE error path
// uses it to synthesize a transport-error response only for requests the
// stream never answered: JSON-RPC has no second response for a completed id.
func messageAnswersID(msg string, id *json.RawMessage) bool {
	if id == nil {
		return false
	}
	var probe struct {
		ID     *json.RawMessage `json:"id"`
		Method string           `json:"method"`
	}
	if err := json.Unmarshal([]byte(msg), &probe); err != nil {
		return false
	}
	return probe.Method == "" && probe.ID != nil && jsonIDEqual(*probe.ID, *id)
}

// jsonIDEqual compares two raw JSON id values by semantic value, not byte
// encoding: JSON-RPC ids are equal when their decoded values are, so "a" and
// "\u0061" are the same id and 1 and 1e0 denote the same number. The Go SDK
// decodes and re-encodes ids on both sides, so equivalent-but-different
// encodings are realistic on the wire. Numbers compare exactly through
// big.Rat — float64 coercion would lose precision on 64-bit ids. Values that
// do not parse as JSON never compare equal.
func jsonIDEqual(a, b json.RawMessage) bool {
	av, aok := decodeJSONID(a)
	bv, bok := decodeJSONID(b)
	if !aok || !bok {
		return false
	}
	return jsonValueEqual(av, bv)
}

func decodeJSONID(raw json.RawMessage) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

func jsonValueEqual(a, b any) bool {
	switch av := a.(type) {
	case json.Number:
		bn, ok := b.(json.Number)
		if !ok {
			return false
		}
		ar, aok := new(big.Rat).SetString(string(av))
		br, bok := new(big.Rat).SetString(string(bn))
		return aok && bok && ar.Cmp(br) == 0
	case string:
		bs, ok := b.(string)
		return ok && av == bs
	default:
		return a == b
	}
}

// extractSSEMessages reads an SSE body and returns every complete data
// payload (the JSON-RPC messages), dropping comments, events and keep-alives.
// A mid-stream read failure surfaces as an error; the complete messages
// extracted before it are still returned.
func extractSSEMessages(r io.Reader) ([]string, error) {
	var messages []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 32*1024*1024) // exports can be large
	var data []string
	flush := func() {
		if len(data) > 0 {
			payload := strings.Join(data, "\n")
			if strings.TrimSpace(payload) != "" {
				messages = append(messages, payload)
			}
			data = nil
		}
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
			// comment / keep-alive
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimPrefix(line, "data:")
			payload = strings.TrimPrefix(payload, " ")
			data = append(data, payload)
		default:
			// event:, id:, retry: — framing, not payload
		}
	}
	if err := scanner.Err(); err != nil {
		// The stream was cut: the pending data lines are an INCOMPLETE
		// message (no blank-line terminator), not a complete payload — drop
		// them instead of relaying a truncated JSON value.
		return messages, fmt.Errorf("reading SSE stream: %w", err)
	}
	flush()
	return messages, nil
}

// writeJSONRPCError writes one JSON-RPC error response. A nil id renders as
// null (parse errors arrive before the id is knowable).
func writeJSONRPCError(w io.Writer, id *json.RawMessage, code int, message string) {
	if id == nil {
		null := json.RawMessage("null")
		id = &null
	}
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      *id,
	}
	resp.Error.Code = code
	resp.Error.Message = message
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	writeLine(w, string(b))
}

// writeLine writes one newline-terminated message, ignoring write errors
// (a closed stdout means the client went away; the relay stops on the next
// scanner read anyway). A message that parses as JSON is compacted first:
// stdout is NDJSON, so internal newlines (an indented body relayed by an
// intermediate proxy, for instance) would split one JSON value across
// several lines and corrupt the protocol stream. Non-JSON payloads fail
// json.Compact and are written verbatim.
func writeLine(w io.Writer, msg string) {
	line := strings.TrimRight(msg, "\r\n")
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(line)); err == nil && compact.Len() > 0 {
		line = compact.String()
	}
	_, _ = io.WriteString(w, line+"\n")
}
