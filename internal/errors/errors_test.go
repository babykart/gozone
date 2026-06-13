package errors

import (
	"errors"
	"net/http"
	"testing"
)

func TestAppError_Error(t *testing.T) {
	err := NotFound("zone not found")
	if err.Error() != "zone not found" {
		t.Errorf("expected 'zone not found', got %q", err.Error())
	}
}

func TestWrap_Unwrap(t *testing.T) {
	cause := errors.New("underlying failure")
	appErr := Wrap(cause, http.StatusBadGateway, "BAD_GATEWAY", "gateway error")

	if appErr.Cause != cause {
		t.Errorf("expected cause %v, got %v", cause, appErr.Cause)
	}
	if !errors.Is(appErr, cause) {
		t.Error("expected errors.Is to find the underlying cause")
	}
}

func TestInternalWrap(t *testing.T) {
	cause := errors.New("db connection lost")
	err := InternalWrap(cause, "database error")

	if err.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", err.Code)
	}
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the wrapped database cause")
	}
}

func TestUnwrap_NilCause(t *testing.T) {
	err := NotFound("zone not found")
	if err.Unwrap() != nil {
		t.Errorf("expected nil cause, got %v", err.Unwrap())
	}
}

func TestAs_TargetsAppError(t *testing.T) {
	cause := errors.New("root cause")
	wrapped := Wrap(cause, http.StatusConflict, "CONFLICT", "conflict")

	var appErr *AppError
	if !errors.As(wrapped, &appErr) {
		t.Fatal("expected errors.As to match *AppError")
	}
	if appErr.Name != "CONFLICT" {
		t.Errorf("expected CONFLICT, got %s", appErr.Name)
	}
}

func TestNotFound(t *testing.T) {
	err := NotFound("zone not found")
	if err.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", err.Code)
	}
	if err.Name != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND, got %s", err.Name)
	}
}

func TestNotFound_DefaultMessage(t *testing.T) {
	err := NotFound("")
	if err.Message != "resource not found" {
		t.Errorf("expected default message, got %q", err.Message)
	}
}

func TestBadRequest(t *testing.T) {
	err := BadRequest("invalid input")
	if err.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", err.Code)
	}
	if err.Name != "BAD_REQUEST" {
		t.Errorf("expected BAD_REQUEST, got %s", err.Name)
	}
}

func TestUnauthorized(t *testing.T) {
	err := Unauthorized("invalid token")
	if err.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", err.Code)
	}
	if err.Name != "UNAUTHORIZED" {
		t.Errorf("expected UNAUTHORIZED, got %s", err.Name)
	}
}

func TestForbidden(t *testing.T) {
	err := Forbidden("admin required")
	if err.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", err.Code)
	}
	if err.Name != "FORBIDDEN" {
		t.Errorf("expected FORBIDDEN, got %s", err.Name)
	}
}

func TestInternal(t *testing.T) {
	err := Internal("db error")
	if err.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", err.Code)
	}
	if err.Name != "INTERNAL_ERROR" {
		t.Errorf("expected INTERNAL_ERROR, got %s", err.Name)
	}
}

func TestInternal_DefaultMessage(t *testing.T) {
	err := Internal("")
	if err.Message != "internal server error" {
		t.Errorf("expected default message, got %q", err.Message)
	}
}

func TestValidationError(t *testing.T) {
	err := ValidationError("invalid domain name")
	if err.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", err.Code)
	}
	if err.Name != "VALIDATION_ERROR" {
		t.Errorf("expected VALIDATION_ERROR, got %s", err.Name)
	}
}
