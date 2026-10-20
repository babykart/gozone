package mcpserver

import (
	"context"
	"net/http"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// New builds the MCP endpoint handler: an SDK Streamable HTTP server over
// the dnsops service, wrapped in the Origin guard. The caller mounts it
// behind the same middleware stack as /api/v1 (IP rate limit → API key
// auth → per-key rate limit); the authenticated user reaches the tool
// handlers through the request context (the SDK derives handler contexts
// from the HTTP request context, so middleware-injected values propagate).
//
// version is the resolved build version, advertised in the initialize
// result.
//
// The server is selected per request from the API key's scope: an mcp:write
// key reaches the server with the write tools registered, every other case
// (mcp:read, no scope, wiring error) gets the read-only server — fail-closed.
// When cfg.MCP.ReadOnly is true no write server exists at all: write tools
// are not registered and do not appear in tools/list, per the recommended
// first-deployment posture (mcp.read_only also wins over an mcp:write key).
// A write tool that somehow still runs is stopped by the per-handler
// requireWriteScope guard (defence in depth).
func New(ops *dnsops.Service, cfg *config.MCPConfig, version string) http.Handler {
	if version == "" {
		version = "dev"
	}
	readSrv := buildServer(ops, version, false)
	writeSrv := readSrv
	if !cfg.ReadOnly {
		writeSrv = buildServer(ops, version, true)
	}

	streamable := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		if scope, ok := middleware.APIKeyScopeFromContext(r.Context()); ok && scope == models.ScopeMCPWrite {
			return writeSrv
		}
		return readSrv
	}, &mcp.StreamableHTTPOptions{
		// Stateless: each request is authenticated independently by its API
		// key; no Mcp-Session-Id is retained, keeping the endpoint valid
		// behind a load balancer across replicas.
		Stateless: true,
	})

	return newOriginGuard(cfg.AllowedOrigins).Wrap(streamable)
}

// buildServer assembles one MCP server instance: the read tools, the write
// tools when withWrite, the resources and prompts (always registered), and
// the panic-to-INTERNAL_ERROR receiving middleware. The SDK runs tool
// handlers in its own goroutines, outside any HTTP recovery middleware.
func buildServer(ops *dnsops.Service, version string, withWrite bool) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "gozone",
		Title:   "GoZone DNS",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "Manage PowerDNS zones and records through GoZone. " +
			"Access is scoped to the API key's user: zone operations require a group grant (or an admin key). " +
			"The API key's scope bounds the tool set: mcp:read exposes read-only tools, mcp:write adds the write tools.",
	})

	registerReadTools(srv, ops)
	if withWrite {
		registerWriteTools(srv, ops)
	}
	registerResources(srv, ops)
	registerPrompts(srv)
	srv.AddReceivingMiddleware(recoverMiddleware)
	return srv
}

// requireWriteScope is the defence-in-depth guard at the top of every write
// tool handler: even if a write tool reached a handler outside the
// mcp:write-selected server (wiring bug, future transport), it refuses with
// a stable FORBIDDEN text instead of writing. The per-request server
// selection in New is the primary control; this guard is the backstop.
func requireWriteScope(ctx context.Context) *toolError {
	if scope, ok := middleware.APIKeyScopeFromContext(ctx); ok && scope == models.ScopeMCPWrite {
		return nil
	}
	return &toolError{code: codeForbidden, msg: "API key scope does not allow write operations"}
}

// userFromContext extracts the acting user (set by middleware.APIKeyAuth)
// from a tool-handler context. A missing user is a wiring bug (the endpoint
// must be mounted behind APIKeyAuth): tools fail closed with UNAUTHORIZED
// instead of running as an anonymous actor.
func userFromContext(ctx context.Context) (*models.User, *toolError) {
	if user, ok := ctx.Value(middleware.UserContextKey).(*models.User); ok && user != nil {
		return user, nil
	}
	return nil, &toolError{code: codeUnauthorized, msg: "no authenticated user; the MCP endpoint requires an API key"}
}
