package handlers

import (
	"errors"
	"net/http"

	"github.com/babykart/gozone/internal/pdns"
)

// pdnsPageStatus maps a PowerDNS failure to an HTTP status and a generic,
// category-level message for an HTML page. The raw upstream error is never
// rendered: it may quote SQL fragments or internal paths on a backend
// failure. notFoundMsg names the 404 case ("Zone not found", "Record not
// found") so a vanished zone does not masquerade as a server fault (500) —
// and a server fault does not masquerade as a missing zone (404).
func pdnsPageStatus(err error, notFoundMsg string) (int, string) {
	switch {
	case errors.Is(err, pdns.ErrNotFound):
		return http.StatusNotFound, notFoundMsg
	case errors.Is(err, pdns.ErrUnauthorized):
		return http.StatusBadGateway, "PowerDNS rejected the operation: its API credentials configured on this server are invalid."
	case errors.Is(err, pdns.ErrValidation):
		return http.StatusBadRequest, "PowerDNS rejected the request as invalid."
	case errors.Is(err, pdns.ErrConflict):
		return http.StatusConflict, "PowerDNS reported a conflict for the requested change."
	default:
		return http.StatusInternalServerError, "The request failed. See the server logs for details."
	}
}
