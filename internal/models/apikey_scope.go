package models

import "strings"

// APIKeyScope bounds what an API key may do. A scope both pins the transport
// surface (REST /api/v1 or MCP /mcp) and caps the access level. Scopes only
// restrict: they never grant rights the owning user does not have.
type APIKeyScope string

const (
	// ScopeAPIRead allows safe methods (GET/HEAD) on /api/v1 only.
	ScopeAPIRead APIKeyScope = "api:read"
	// ScopeAPIWrite allows reads and writes on /api/v1, still bounded by the
	// user's role and zone access.
	ScopeAPIWrite APIKeyScope = "api:write"
	// ScopeMCPRead allows MCP read-only tools, resources and prompts.
	ScopeMCPRead APIKeyScope = "mcp:read"
	// ScopeMCPWrite additionally allows MCP write tools (only effective when
	// mcp.read_only is false).
	ScopeMCPWrite APIKeyScope = "mcp:write"
)

// APIKeySurface is the transport surface an API key is bound to.
type APIKeySurface string

const (
	// SurfaceAPI is the REST API surface (/api/v1).
	SurfaceAPI APIKeySurface = "api"
	// SurfaceMCP is the MCP surface (/mcp and the stdio bridge).
	SurfaceMCP APIKeySurface = "mcp"
)

// ParseAPIKeyScope is a strict allow-list: any value outside the four known
// scopes is rejected. Matching is case-insensitive.
func ParseAPIKeyScope(s string) (APIKeyScope, bool) {
	scope := APIKeyScope(strings.ToLower(s))
	switch scope {
	case ScopeAPIRead, ScopeAPIWrite, ScopeMCPRead, ScopeMCPWrite:
		return scope, true
	default:
		return "", false
	}
}

// Surface returns the transport surface the scope grants access to.
func (s APIKeyScope) Surface() APIKeySurface {
	if s == ScopeMCPRead || s == ScopeMCPWrite {
		return SurfaceMCP
	}
	return SurfaceAPI
}

// CanWrite reports whether the scope allows write operations on its surface.
// Write implies read.
func (s APIKeyScope) CanWrite() bool {
	return s == ScopeAPIWrite || s == ScopeMCPWrite
}
