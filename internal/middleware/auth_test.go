package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/babykart/gozone/internal/models"
)

var testSecret = []byte("test-secret-key-123456")

func TestGenerateAndParseToken(t *testing.T) {
	user := &models.User{
		ID:       1,
		Username: "testuser",
		Role:     "admin",
	}

	token, err := GenerateToken(user, testSecret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	claims, err := ParseToken(token, testSecret)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if claims.UserID != 1 {
		t.Errorf("expected UserID 1, got %d", claims.UserID)
	}
	if claims.Username != "testuser" {
		t.Errorf("expected Username testuser, got %s", claims.Username)
	}
	if claims.Role != "admin" {
		t.Errorf("expected Role admin, got %s", claims.Role)
	}
}

func TestParseToken_InvalidSignature(t *testing.T) {
	user := &models.User{ID: 1, Username: "u", Role: "user"}
	token, err := GenerateToken(user, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseToken(token, []byte("wrong-secret"))
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestParseToken_Expired(t *testing.T) {
	user := &models.User{ID: 1, Username: "u", Role: "user"}
	token, err := GenerateToken(user, testSecret, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseToken(token, testSecret)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestGenerateToken_Expired(t *testing.T) {
	user := &models.User{ID: 1, Username: "u", Role: "user"}

	// Negative duration means token is already expired
	token, err := GenerateToken(user, testSecret, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseToken(token, testSecret)
	if err == nil {
		t.Error("expected expired token")
	}
}

func TestGenerateToken_ValidDuration(t *testing.T) {
	user := &models.User{ID: 1, Username: "u", Role: "user"}

	token, err := GenerateToken(user, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseToken(token, testSecret)
	if err != nil {
		t.Errorf("expected valid token: %v", err)
	}
}

func TestGetUser(t *testing.T) {
	user := &models.User{ID: 1, Username: "test", Role: "admin"}

	// With user in context
	ctx := context.WithValue(context.Background(), UserContextKey, user)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(ctx)

	got := GetUser(r)
	if got == nil {
		t.Fatal("expected user, got nil")
	}
	if got.ID != 1 {
		t.Errorf("expected ID 1, got %d", got.ID)
	}

	// Without user in context
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	got2 := GetUser(r2)
	if got2 != nil {
		t.Error("expected nil user")
	}
}

func TestRequireAdmin(t *testing.T) {
	admin := &models.User{ID: 1, Username: "admin", Role: "admin"}
	regular := &models.User{ID: 2, Username: "user", Role: "user"}

	tests := []struct {
		name       string
		user       *models.User
		wantStatus int
	}{
		{"admin allowed", admin, http.StatusOK},
		{"user forbidden", regular, http.StatusForbidden},
		{"nil user", nil, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.user != nil {
				ctx := context.WithValue(r.Context(), UserContextKey, tt.user)
				r = r.WithContext(ctx)
			}

			handler := RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			handler.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
}
