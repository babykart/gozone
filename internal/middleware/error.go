package middleware

import (
	"encoding/json"
	"net/http"

	apperrors "github.com/babykart/gozone/internal/errors"
	"github.com/babykart/gozone/internal/logger"
)

// ErrorHandler is a middleware that recovers from panics and returns
// structured error responses.
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
				logger.Error("panic recovered", "panic", rec, "path", r.URL.Path, "request_id", r.Header.Get("X-Request-Id"))

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
	if len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api" {
		return true
	}
	return r.Header.Get("Accept") == "application/json"
}

// respondJSON writes a JSON response with the given status code.
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data) // #nosec G104
}
