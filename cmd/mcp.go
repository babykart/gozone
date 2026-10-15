// mcp.go defines the `gozone mcp` command tree: a namespace whose only
// subcommand today is `stdio`, a transport bridge for MCP clients that only
// speak the stdio transport. The bridge contains NO business logic: it
// relays line-delimited JSON-RPC from stdin to a remote GoZone `/mcp`
// endpoint over Streamable HTTP and writes the responses back on stdout
// (MCP_PLAN.md Phase 5).
package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/babykart/gozone/internal/logger"
)

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

			endpoint, err := buildTargetURL(rawURL)
			if err != nil {
				return err
			}
			apiKey := strings.TrimSpace(os.Getenv(envName))
			if apiKey == "" {
				return fmt.Errorf("the %s environment variable is empty: set it to a GoZone API key (the bridge authenticates every request with it)", envName)
			}

			bridge := &stdioBridge{
				endpoint: endpoint,
				apiKey:   apiKey,
				client:   &http.Client{Timeout: 120 * time.Second},
			}
			return bridge.Run(context.Background(), os.Stdin, os.Stdout)
		},
	}
	cmd.Flags().String("url", "", "base URL of the remote GoZone (e.g. https://gozone.example) or the full endpoint URL (e.g. https://gozone.example/mcp); required")
	cmd.Flags().String("api-key-env", "GOZONE_API_KEY", "name of the environment variable holding the GoZone API key")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

// buildTargetURL normalises the --url flag: a base URL without a path gets
// the default /mcp endpoint appended; a URL that already carries a path is
// used verbatim. Non-HTTP(S) schemes are rejected.
func buildTargetURL(raw string) (string, error) {
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
	if u.Path == "" || u.Path == "/" {
		u.Path = "/mcp"
	}
	return u.String(), nil
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
		for _, msg := range extractSSEMessages(resp.Body) {
			writeLine(out, msg)
		}
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			if env.ID != nil {
				writeJSONRPCError(out, env.ID, -32603, "internal error: read response: "+err.Error())
			}
			return nil
		}
		if trimmed := strings.TrimSpace(string(body)); trimmed != "" {
			writeLine(out, trimmed)
		}
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent:
		// Notification accepted: no output, matching stdio semantics.
	default:
		// Upstream refused (401 bad key, 403 origin, 404 disabled endpoint,
		// 5xx ...). Requests get a JSON-RPC error carrying the status so the
		// client can surface it; notifications are logged only.
		if env.ID != nil {
			writeJSONRPCError(out, env.ID, -32000, fmt.Sprintf("upstream HTTP %d from %s", resp.StatusCode, b.endpoint))
		}
		logger.Warn("mcp stdio bridge: upstream error", "status", resp.StatusCode, "method", env.Method)
	}
	return nil
}

// isEventStream reports whether a Content-Type header names text/event-stream.
func isEventStream(ct string) bool {
	return strings.HasPrefix(ct, "text/event-stream")
}

// extractSSEMessages reads an SSE body and returns every complete data
// payload (the JSON-RPC messages), dropping comments, events and keep-alives.
func extractSSEMessages(r io.Reader) []string {
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
	flush()
	return messages
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
// scanner read anyway).
func writeLine(w io.Writer, msg string) {
	_, _ = io.WriteString(w, strings.TrimRight(msg, "\r\n")+"\n")
}
