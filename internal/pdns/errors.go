package pdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Sentinel errors returned by the PowerDNS client so callers can distinguish
// not-found, validation/conflict and transient failures without parsing
// error strings.
var (
	// ErrNotFound indicates the requested resource does not exist on the
	// PowerDNS server (HTTP 404).
	ErrNotFound = errors.New("resource not found")

	// ErrValidation indicates the request was rejected by PowerDNS because of
	// invalid data (HTTP 400 or 422).
	ErrValidation = errors.New("validation failed")

	// ErrConflict indicates the request could not be fulfilled because of a
	// conflicting resource, such as a zone that already exists (HTTP 409).
	ErrConflict = errors.New("resource conflict")

	// ErrUnauthorized indicates the request was rejected because of
	// authentication or authorization issues (HTTP 401 or 403).
	ErrUnauthorized = errors.New("unauthorized")

	// ErrLuaUpdatesDisabled indicates that the PowerDNS server refused the
	// operation because the enable-lua-record-updates configuration setting is
	// not enabled (HTTP 500 with a specific message).
	ErrLuaUpdatesDisabled = errors.New("LUA record updates disabled")
)

// httpError builds a typed sentinel error from a non-2xx HTTP status code and
// the response body. The returned error is always non-nil and unwraps to one
// of the sentinel errors above.
//
// The user-facing message is extracted from PowerDNS's JSON error body
// ({"error": "..."}) so callers never paste raw JSON into a response (m46). The
// raw body is still consulted for substring-based detection (e.g. the
// enable-lua-record-updates marker).
func httpError(status int, body []byte) error {
	raw := string(body)
	detail := extractErrorMessage(body)
	if detail == "" {
		detail = http.StatusText(status)
	}

	switch {
	case status == http.StatusNotFound:
		return fmt.Errorf("%w: status %d: %s", ErrNotFound, status, detail)
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: status %d: %s", ErrValidation, status, detail)
	case status == http.StatusConflict:
		return fmt.Errorf("%w: status %d: %s", ErrConflict, status, detail)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%w: status %d: %s", ErrUnauthorized, status, detail)
	case status == http.StatusInternalServerError && strings.Contains(strings.ToLower(raw), "enable-lua-record-updates"):
		return fmt.Errorf("%w: status %d: %s", ErrLuaUpdatesDisabled, status, detail)
	default:
		return fmt.Errorf("unexpected status %d: %s", status, detail)
	}
}

// extractErrorMessage parses a PowerDNS error body and returns the
// human-readable message. PowerDNS emits errors as {"error": "..."}; that field
// is returned verbatim (trimmed). If the body is not JSON or has no "error"
// field, the return is empty so the caller falls back to the HTTP status text —
// never the raw body — keeping user-facing error strings clean (m46).
func extractErrorMessage(body []byte) string {
	var v struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	return strings.TrimSpace(v.Error)
}
