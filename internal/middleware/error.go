package middleware

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
	"strings"

	chimw "github.com/go-chi/chi/v5/middleware"

	apperrors "github.com/babykart/gozone/internal/errors"
	"github.com/babykart/gozone/internal/logger"
)

// ErrorHandler is the single panic-recovery middleware for the request
// goroutine. It replaces chi's Recoverer (m8) and adds structured logging
// with a full stack trace plus API-aware error responses.
//
// For JSON API requests (those with /api/ in the path or Accept: application/json),
// errors are returned as JSON with standardized codes. For web UI requests,
// a generic error message is returned as plain text.
//
// This middleware should be placed after chi's Logger and before
// route handlers in the middleware chain.
func ErrorHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered",
					"panic", rec,
					"path", r.URL.Path,
					"request_id", chimw.GetReqID(r.Context()),
					"stack", string(debug.Stack()),
				)

				if isAPIRequest(r) {
					respondJSON(w, http.StatusInternalServerError, apperrors.Internal("internal server error"))
				} else {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// WriteAppError writes an *apperrors.AppError as the HTTP response.
//
// For API requests, the error is serialized as JSON. For web UI
// requests, the error message is sent as plain text with the
// appropriate status code.
func WriteAppError(w http.ResponseWriter, r *http.Request, err *apperrors.AppError) {
	if isAPIRequest(r) {
		respondJSON(w, err.Code, err)
	} else {
		http.Error(w, err.Message, err.Code)
	}
}

// isAPIRequest returns true for API endpoint requests.
func isAPIRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	return r.Header.Get("Accept") == "application/json"
}

// apiErrorEnvelope mirrors the JSON error envelope used across the REST API
// ({"error","code","message"} with a STRING code, e.g. "UNAUTHORIZED") so
// middleware-level rejections blend in with the handler-level writeAPIError
// responses. Declared here rather than shared with the handlers package
// because middleware cannot import handlers (the reverse dependency already
// exists); the shape is pinned by tests on both sides. Note the code is
// deliberately not apperrors.AppError's serialized form, whose Code field is
// an int — a numeric code would introduce a third shape on the API surface.
type apiErrorEnvelope struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeAPIErrorEnvelope writes the API JSON error envelope. Middlewares
// mounted on both web and API routes use this for their rejections when
// isAPIRequest(r) holds, and plain text otherwise — an API client then never
// receives text/plain where every other endpoint answers JSON.
func writeAPIErrorEnvelope(w http.ResponseWriter, status int, code, label string) {
	respondJSON(w, status, apiErrorEnvelope{Error: label, Code: code, Message: label})
}

// respondJSON writes a JSON response with the given status code.
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) // #nosec G104
}
