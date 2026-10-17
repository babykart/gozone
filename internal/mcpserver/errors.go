// Package mcpserver exposes GoZone's DNS operations as MCP (Model Context
// Protocol) tools over Streamable HTTP, for AI agents (Claude Code, Claude
// Desktop, remote MCP connectors). It is a thin transport over the dnsops
// service layer: every guarantee — API-key authentication (mounted by the
// caller, same stack as /api/v1), zone authorization, admin gates, per-zone
// write locks, content normalisation, audit trail, rate limiting — is
// enforced by the same code the REST API uses.
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
	codeUnauthorized   = "UNAUTHORIZED"
	codeForbidden      = "FORBIDDEN"
	codeInternal       = "INTERNAL_ERROR"
	codeZoneNotFound   = "ZONE_NOT_FOUND"
	codeRecordNotFound = "RECORD_NOT_FOUND"
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

// fail maps a service error with the tool's not-found default code, logs
// the cause server-side and returns the tool error for the SDK to pack
// into an isError result. It is the single funnel for tool calls whose
// service method already failed: the mapping never yields a nil tool error
// for a non-nil input, so the caller unconditionally returns instead of
// falling through to its success path — the pattern this replaces could
// fall through on a nil mapping and dereference a nil result.
func fail(tool string, err error, notFoundCode string) error {
	te, cause := mapServiceError(err, notFoundCode)
	if te == nil {
		// Unreachable for a non-nil err (mapServiceError returns nil only
		// for nil input); kept so the helper is total.
		te = &toolError{code: codeInternal, msg: "internal error"}
		cause = err
	}
	return callTool(tool, te, cause)
}

// mapServiceError translates a dnsops service error into a tool error with a
// stable code, mirroring the REST API's pdnsErrorStatus(err, notFoundCode):
// typed PowerDNS errors are recognised whether or not the service wrapped
// them in a StageError, so both transports report the same codes (a missing
// zone on get_zone/delete_zone is ZONE_NOT_FOUND, a conflicting create is
// CONFLICT, ...). notFoundCode is the caller's default for ErrNotFound —
// zone-scoped tools pass codeZoneNotFound, record-write tools pass
// codeRecordNotFound (a StageFetch 404 is always a missing zone: the fetch
// stage addresses the zone itself). Unknown causes collapse to a generic
// INTERNAL_ERROR: the client must not see internals; the cause is returned
// so the caller can log it server-side.
func mapServiceError(err error, notFoundCode string) (*toolError, error) {
	var se *dnsops.StageError
	switch {
	case err == nil:
		return nil, nil
	case errors.Is(err, dnsops.ErrForbidden):
		return &toolError{code: codeForbidden, msg: "you do not have access to this zone, or the operation requires an admin API key"}, nil
	case errors.As(err, &se) && se.Stage == dnsops.StageZoneAccess:
		return &toolError{code: codeInternal, msg: "zone access check failed; try again later"}, nil
	case errors.As(err, &se) && se.Stage == dnsops.StageFetch && errors.Is(se.Err, pdns.ErrNotFound):
		return &toolError{code: codeZoneNotFound, msg: "zone not found"}, nil
	case errors.Is(err, pdns.ErrNotFound):
		return &toolError{code: notFoundCode, msg: "not found"}, nil
	case errors.Is(err, pdns.ErrValidation):
		return &toolError{code: "VALIDATION_ERROR", msg: "PowerDNS rejected the change as invalid"}, nil
	case errors.Is(err, pdns.ErrConflict):
		return &toolError{code: "CONFLICT", msg: "PowerDNS reported a conflict for the requested change"}, nil
	case errors.Is(err, pdns.ErrUnauthorized):
		return &toolError{code: "UPSTREAM_AUTH_ERROR", msg: "GoZone's PowerDNS credentials are invalid; contact the administrator"}, nil
	case errors.Is(err, pdns.ErrLuaUpdatesDisabled):
		return &toolError{code: "LUA_UPDATES_DISABLED", msg: "LUA record updates are disabled on the PowerDNS server"}, nil
	default:
		// Internal/unexpected: generic message to the client, full cause
		// back to the caller for server-side logging.
		return &toolError{code: codeInternal, msg: "internal error"}, err
	}
}
