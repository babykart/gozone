// Package errors defines custom error types with HTTP status codes for
// consistent error handling across the GoZone application.
//
// Import this package with an alias (e.g. "apperrors") to avoid shadowing the
// standard library errors package.
package errors

import (
	"errors"
	"net/http"
)

// AppError is a custom error that carries an HTTP status code and an optional
// underlying cause. It implements the standard error wrapping interface so it
// works with errors.Is and errors.As.
type AppError struct {
	Code    int    `json:"code"`
	Name    string `json:"error"`
	Message string `json:"message"`
	Cause   error  `json:"-"`
}

// Error returns the error message.
func (e *AppError) Error() string {
	return e.Message
}

// Unwrap returns the underlying cause, if any. This makes AppError compatible
// with errors.Is and errors.As.
func (e *AppError) Unwrap() error {
	return e.Cause
}

// New creates an AppError with the given status code, name, and message.
func New(status int, name, message string) *AppError {
	return &AppError{Code: status, Name: name, Message: message}
}

// Wrap creates an AppError that wraps an underlying cause. The wrapped error
// can be inspected with errors.Is/As.
func Wrap(cause error, status int, name, message string) *AppError {
	return &AppError{Code: status, Name: name, Message: message, Cause: cause}
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

// InternalWrap creates a 500 Internal Server Error wrapping an underlying cause.
func InternalWrap(cause error, message string) *AppError {
	if message == "" {
		message = "internal server error"
	}
	return Wrap(cause, http.StatusInternalServerError, "INTERNAL_ERROR", message)
}

// ValidationError creates a 400 validation error.
func ValidationError(message string) *AppError {
	if message == "" {
		message = "validation error"
	}
	return New(http.StatusBadRequest, "VALIDATION_ERROR", message)
}

// Is reports whether any error in err's chain matches target. It is a thin
// wrapper around the standard library errors.Is for callers that only import
// this package.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target, and if one is
// found, sets target to that error value and returns true. It is a thin wrapper
// around the standard library errors.As.
func As(err error, target any) bool {
	return errors.As(err, target)
}
