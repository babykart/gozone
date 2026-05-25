package middleware

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/database"
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
	db, err := database.New(&config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	})
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

func newTestAuthDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(&config.DatabaseConfig{
		Driver: "sqlite3",
		DSN:    ":memory:",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedTestUser(t *testing.T, db *database.DB, username, role string, enabled bool) int64 {
	t.Helper()
	enabledVal := 0
	if enabled {
		enabledVal = 1
	}
	result, err := db.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, ?)`,
		username, username+"@test.local", "$2a$12$test", role, enabledVal,
	)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	return id
}

func seedTestAPIKey(t *testing.T, db *database.DB, userID int64, keyHash string, expiresAt *time.Time) {
	t.Helper()
	var expires interface{}
	if expiresAt != nil {
		expires = *expiresAt
	}
	_, err := db.Exec(
		`INSERT INTO api_keys (user_id, key_hash, description, expires_at) VALUES (?, ?, ?, ?)`,
		userID, keyHash, "test key", expires,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAPIKeyAuth_XAPIKeyHeader(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "apiuser", "user", true)
	seedTestAPIKey(t, db, userID, "test-api-key", nil)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r)
		if user == nil {
			t.Fatal("expected user in context")
		}
		if user.ID != userID {
			t.Errorf("expected user ID %d, got %d", userID, user.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "test-api-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
}

func TestAPIKeyAuth_AuthorizationBearer(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "beareruser", "user", true)
	seedTestAPIKey(t, db, userID, "bearer-key", nil)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r)
		if user == nil {
			t.Fatal("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("Authorization", "Bearer bearer-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
}

func TestAPIKeyAuth_XAPIKeyPrecedence(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "precedence", "user", true)
	seedTestAPIKey(t, db, userID, "header-key", nil)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "header-key")
	r.Header.Set("Authorization", "Bearer bearer-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAPIKeyAuth_MissingKey(t *testing.T) {
	db := newTestAuthDB(t)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	assertJSONError(t, w, "unauthorized")
}

func TestAPIKeyAuth_UnknownKey(t *testing.T) {
	db := newTestAuthDB(t)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "nonexistent-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	assertJSONError(t, w, "unauthorized")
}

func TestAPIKeyAuth_ExpiredKey(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "expireduser", "user", true)
	past := time.Now().Add(-time.Hour)
	seedTestAPIKey(t, db, userID, "expired-key", &past)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "expired-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	assertJSONError(t, w, "api_key_expired")
}

func TestAPIKeyAuth_LastUsedAtUpdated(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "lastused", "user", true)
	seedTestAPIKey(t, db, userID, "used-key", nil)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "used-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var lastUsed sql.NullTime
	err := db.QueryRow("SELECT last_used_at FROM api_keys WHERE key_hash = ?", "used-key").Scan(&lastUsed)
	if err != nil {
		t.Fatalf("query last_used_at: %v", err)
	}
	if !lastUsed.Valid {
		t.Error("expected last_used_at to be set")
	}
	if time.Since(lastUsed.Time) > 5*time.Second {
		t.Error("last_used_at too far in the past")
	}
}

func TestAPIKeyAuth_DisabledUser(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "disableduser", "user", false)
	seedTestAPIKey(t, db, userID, "disabled-key", nil)

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "disabled-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	assertJSONError(t, w, "unauthorized")
}

func TestAPIKeyAuth_NonExistentUser(t *testing.T) {
	db := newTestAuthDB(t)

	// Disable FK to insert an orphan key referencing a non-existent user
	db.Exec("PRAGMA foreign_keys = OFF")
	_, err := db.Exec(
		`INSERT INTO api_keys (user_id, key_hash, description) VALUES (?, ?, ?)`,
		9999, "orphan-key", "orphan",
	)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec("PRAGMA foreign_keys = ON")

	mw := APIKeyAuth(db)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "orphan-key")
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	assertJSONError(t, w, "unauthorized")
}

func assertJSONError(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != want {
		t.Errorf("expected error %q, got %q", want, body["error"])
	}
}

func TestAuth_SuccessViaCookie(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "cookieuser", "user", true)

	token, err := GenerateToken(&models.User{ID: userID, Username: "cookieuser", Role: "user"}, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r)
		if user == nil {
			t.Fatal("expected user in context")
		}
		if user.Username != "cookieuser" {
			t.Errorf("expected cookieuser, got %s", user.Username)
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: token})
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuth_SuccessViaAuthorizationBearer(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "bearerweb", "user", true)

	token, err := GenerateToken(&models.User{ID: userID, Username: "bearerweb", Role: "user"}, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r)
		if user == nil {
			t.Fatal("expected user in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuth_CookiePreferredOverHeader(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "cookie-pref", "user", true)

	cookieToken, err := GenerateToken(&models.User{ID: userID, Username: "cookie-pref", Role: "user"}, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	headerToken, err := GenerateToken(&models.User{ID: userID, Username: "other", Role: "user"}, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUser(r)
		if user == nil {
			t.Fatal("expected user in context")
		}
		if user.Username != "cookie-pref" {
			t.Errorf("expected cookie user 'cookie-pref', got %s", user.Username)
		}
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: cookieToken})
	r.Header.Set("Authorization", "Bearer "+headerToken)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestAuth_InvalidTokenClearsCookie(t *testing.T) {
	db := newTestAuthDB(t)

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: "invalid-token"})
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	setCookie := w.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Error("expected Set-Cookie header to be present")
	}
	if !strings.Contains(setCookie, "gozone_session=") {
		t.Error("expected Set-Cookie to contain gozone_session")
	}
}

func TestAuth_ExpiredTokenClearsCookie(t *testing.T) {
	db := newTestAuthDB(t)
	seedTestUser(t, db, "expired-web", "user", true)

	token, err := GenerateToken(&models.User{ID: 1, Username: "expired-web", Role: "user"}, testSecret, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for expired token")
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: token})
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	setCookie := w.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Error("expected Set-Cookie header to be present")
	}
	if !strings.Contains(setCookie, "gozone_session=") {
		t.Error("expected Set-Cookie to contain gozone_session")
	}
}

func TestAuth_UserNotFoundAfterValidToken(t *testing.T) {
	db := newTestAuthDB(t)
	// Don't create user — token references non-existent user
	token, err := GenerateToken(&models.User{ID: 99999, Username: "ghost", Role: "user"}, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for non-existent user")
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: token})
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

func TestAuth_DisabledUserRejected(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "disabled-web", "user", false)

	token, err := GenerateToken(&models.User{ID: userID, Username: "disabled-web", Role: "user"}, testSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	mw := Auth(db, testSecret)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for disabled user")
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: constants.SessionCookieName, Value: token})
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

func TestLoadUser_Success(t *testing.T) {
	db := newTestAuthDB(t)
	userID := seedTestUser(t, db, "load-ok", "admin", true)

	user, err := loadUser(db, userID)
	if err != nil {
		t.Fatalf("loadUser failed: %v", err)
	}
	if user.Username != "load-ok" {
		t.Errorf("expected load-ok, got %s", user.Username)
	}
	if user.Role != "admin" {
		t.Errorf("expected admin, got %s", user.Role)
	}
	if !user.Enabled {
		t.Error("expected user to be enabled")
	}
}

func TestLoadUser_NotFound(t *testing.T) {
	db := newTestAuthDB(t)

	_, err := loadUser(db, 99999)
	if err == nil {
		t.Error("expected error for non-existent user")
	}
}

func TestLoadUser_DisabledConversion(t *testing.T) {
	db := newTestAuthDB(t)
	seedTestUser(t, db, "conv-user", "user", false)

	user, err := loadUser(db, 1)
	if err != nil {
		t.Fatalf("loadUser failed: %v", err)
	}
	if user.Enabled {
		t.Error("expected user to be disabled (enabled=0 converted to false)")
	}
}
