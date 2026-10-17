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
// read_only comes from cfg.MCP.ReadOnly: when true the write tools are not
// registered at all (they do not even appear in tools/list), per the
// recommended first-deployment posture.
func New(ops *dnsops.Service, cfg *config.MCPConfig, version string) http.Handler {
	if version == "" {
		version = "dev"
	}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "gozone",
		Title:   "GoZone DNS",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "Manage PowerDNS zones and records through GoZone. " +
			"Access is scoped to the API key's user: zone operations require a group grant (or an admin key).",
	})

	registerReadTools(srv, ops)
	if !cfg.ReadOnly {
		registerWriteTools(srv, ops)
	}
	registerResources(srv, ops)
	registerPrompts(srv)
	srv.AddReceivingMiddleware(recoverMiddleware)

	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return srv
	}, &mcp.StreamableHTTPOptions{
		// Stateless: each request is authenticated independently by its API
		// key; no Mcp-Session-Id is retained, keeping the endpoint valid
		// behind a load balancer across replicas.
		Stateless: true,
	})

	return newOriginGuard(cfg.AllowedOrigins).Wrap(streamable)
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
