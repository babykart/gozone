// Package mcpserver exposes GoZone's DNS operations as MCP (Model Context
// Protocol) tools over Streamable HTTP, for AI agents (Claude Code, Claude
// Desktop, remote MCP connectors). It is a thin transport over the dnsops
// service layer: every guarantee — API-key authentication (mounted by the
// caller, same stack as /api/v1), zone authorization, admin gates, per-zone
// write locks, content normalisation, audit trail, rate limiting — is
// enforced by the same code the REST API uses (MCP_PLAN.md).
//
// The server is stateless (StreamableHTTPOptions.Stateless): every HTTP
// request is authenticated independently by its API key, which keeps the
// endpoint compatible with multi-instance deployments behind a load
// balancer.
package mcpserver

import (
	"errors"
	"fmt"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/pdns"
)

// Stable tool-error codes. They reuse the REST API's ErrCode* vocabulary so
// an operator reading logs from both transports sees one set of codes.
const (
	codeUnauthorized = "UNAUTHORIZED"
	codeForbidden    = "FORBIDDEN"
	codeInternal     = "INTERNAL_ERROR"
)

// toolError is a tool-level error: the MCP client receives its Error() text
// in the result content with isError=true. The text always starts with the
// stable code ("ZONE_NOT_FOUND: zone not found") so an agent can branch on
// it programmatically, and never carries internal detail (DSN, stack, raw
// PowerDNS response) — the full cause is logged server-side by toolErrorAt.
type toolError struct {
	code string
	msg  string
}

func (e *toolError) Error() string { return e.code + ": " + e.msg }

func toolErrorf(code, format string, args ...any) *toolError {
	return &toolError{code: code, msg: fmt.Sprintf(format, args...)}
}

// mapServiceError translates a dnsops service error into a tool error with a
// stable code. Unknown causes collapse to a generic INTERNAL_ERROR: the
// client must not see internals; the cause is returned so the caller can log
// it server-side.
func mapServiceError(err error) (*toolError, error) {
	var se *dnsops.StageError
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, dnsops.ErrForbidden):
		return &toolError{code: codeForbidden, msg: "you do not have access to this zone, or the operation requires an admin API key"}, nil
	case errors.As(err, &se) && se.Stage == dnsops.StageZoneAccess:
		return &toolError{code: codeInternal, msg: "zone access check failed; try again later"}, nil
	case errors.As(err, &se) && se.Stage == dnsops.StageFetch && errors.Is(se.Err, pdns.ErrNotFound):
		return &toolError{code: "ZONE_NOT_FOUND", msg: "zone not found"}, nil
	case errors.As(err, &se) && errors.Is(se.Err, pdns.ErrNotFound):
		return &toolError{code: "RECORD_NOT_FOUND", msg: "record not found"}, nil
	case errors.As(err, &se) && errors.Is(se.Err, pdns.ErrValidation):
		return &toolError{code: "VALIDATION_ERROR", msg: "PowerDNS rejected the change as invalid"}, nil
	case errors.As(err, &se) && errors.Is(se.Err, pdns.ErrConflict):
		return &toolError{code: "CONFLICT", msg: "PowerDNS reported a conflict for the requested change"}, nil
	case errors.As(err, &se) && errors.Is(se.Err, pdns.ErrUnauthorized):
		return &toolError{code: "UPSTREAM_AUTH_ERROR", msg: "GoZone's PowerDNS credentials are invalid; contact the administrator"}, nil
	case errors.As(err, &se) && errors.Is(se.Err, pdns.ErrLuaUpdatesDisabled):
		return &toolError{code: "LUA_UPDATES_DISABLED", msg: "LUA record updates are disabled on the PowerDNS server"}, nil
	default:
		// Internal/unexpected: generic message to the client, full cause
		// back to the caller for server-side logging.
		return &toolError{code: codeInternal, msg: "internal error"}, err
	}
}
