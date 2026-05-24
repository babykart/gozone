// Package errors defines custom error types with HTTP status codes for
// consistent error handling across the GoZone application.
package errors

import "net/http"

// AppError is a custom error that carries an HTTP status code.
type AppError struct {
	Code    int    `json:"code"`
	Name    string `json:"error"`
	Message string `json:"message"`
}

// Error returns the error message.
func (e *AppError) Error() string {
	return e.Message
}

// New creates an AppError with the given status code, name, and message.
func New(status int, name, message string) *AppError {
	return &AppError{Code: status, Name: name, Message: message}
}

// NotFound creates a 404 Not Found error.
func NotFound(message string) *AppError {
	if message == "" {
		message = "resource not found"
	}
	return New(http.StatusNotFound, "NOT_FOUND", message)
}

// BadRequest creates a 400 Bad Request error.
func BadRequest(message string) *AppError {
	if message == "" {
		message = "bad request"
	}
	return New(http.StatusBadRequest, "BAD_REQUEST", message)
}

// Unauthorized creates a 401 Unauthorized error.
func Unauthorized(message string) *AppError {
	if message == "" {
		message = "unauthorized"
	}
	return New(http.StatusUnauthorized, "UNAUTHORIZED", message)
}

// Forbidden creates a 403 Forbidden error.
func Forbidden(message string) *AppError {
	if message == "" {
		message = "forbidden"
	}
	return New(http.StatusForbidden, "FORBIDDEN", message)
}

// Internal creates a 500 Internal Server Error.
func Internal(message string) *AppError {
	if message == "" {
		message = "internal server error"
	}
	return New(http.StatusInternalServerError, "INTERNAL_ERROR", message)
}

// ValidationError creates a 400 validation error.
func ValidationError(message string) *AppError {
	if message == "" {
		message = "validation error"
	}
	return New(http.StatusBadRequest, "VALIDATION_ERROR", message)
}
