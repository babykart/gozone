package pdns

import (
	"errors"
	"fmt"
	"net/http"
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
)

// httpError builds a typed sentinel error from a non-2xx HTTP status code and
// the response body. The returned error is always non-nil and unwraps to one
// of the sentinel errors above.
func httpError(status int, body []byte) error {
	msg := string(body)
	if msg == "" {
		msg = http.StatusText(status)
	}

	switch {
	case status == http.StatusNotFound:
		return fmt.Errorf("%w: status %d: %s", ErrNotFound, status, msg)
	case status == http.StatusBadRequest || status == http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: status %d: %s", ErrValidation, status, msg)
	case status == http.StatusConflict:
		return fmt.Errorf("%w: status %d: %s", ErrConflict, status, msg)
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%w: status %d: %s", ErrUnauthorized, status, msg)
	default:
		return fmt.Errorf("unexpected status %d: %s", status, msg)
	}
}
