package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/dyndns"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

func seedIntegrationUser(t *testing.T, h *Handler, username, password, role string, enabled bool) int64 {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatal(err)
	}
	enabledVal := 0
	if enabled {
		enabledVal = 1
	}
	result, err := h.DB.Exec(
		`INSERT INTO users (username, email, password_hash, role, enabled) VALUES (?, ?, ?, ?, ?)`,
		username, username+"@test.local", string(hash), role, enabledVal,
	)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	return id
}

func seedIntegrationAPIKey(t *testing.T, h *Handler, userID int64, keyHash string) {
	t.Helper()
	_, err := h.DB.Exec(
		`INSERT INTO api_keys (user_id, key_hash, description) VALUES (?, ?, ?)`,
		userID, keyHash, "integration test key",
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_CompleteWebFlow(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":"example.com","name":"example.com","kind":"Native"}]`))
	})
	defer pdnsSrv.Close()

	userID := seedIntegrationUser(t, h, "intuser", "secret123", "admin", true)

	t.Run("login", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := "username=intuser&password=secret123"
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("expected 303 redirect, got %d", w.Code)
		}

		setCookie := w.Header().Get("Set-Cookie")
		if setCookie == "" || !strings.Contains(setCookie, constants.SessionCookieName) {
			t.Fatal("expected gozone_session cookie to be set")
		}
	})

	t.Run("authenticated request via user context", func(t *testing.T) {
		user := &models.User{ID: userID, Username: "intuser", Role: "admin"}
		ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
		r = r.WithContext(ctx)
		h.Dashboard(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("logout", func(t *testing.T) {
		user := &models.User{ID: userID, Username: "intuser", Role: "admin"}
		ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/logout", nil)
		r = r.WithContext(ctx)
		h.Logout(w, r)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303 redirect, got %d", w.Code)
		}

		setCookie := w.Header().Get("Set-Cookie")
		if !strings.Contains(setCookie, constants.SessionCookieName) {
			t.Error("expected gozone_session cookie to be cleared")
		}
	})
}

func TestIntegration_CompleteAPIFlow(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":"example.com","name":"example.com","kind":"Native"}]`))
	})
	defer pdnsSrv.Close()

	userID := seedIntegrationUser(t, h, "apiuser", "apipass", "user", true)
	seedIntegrationAPIKey(t, h, userID, "my-integration-api-key")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	r.Header.Set("X-API-Key", "my-integration-api-key")
	h.APIListZones(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var zones []models.Zone
	if err := json.NewDecoder(w.Body).Decode(&zones); err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 {
		t.Errorf("expected 1 zone, got %d", len(zones))
	}
}

func TestIntegration_UnauthenticatedAccess(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	defer pdnsSrv.Close()

	seedIntegrationUser(t, h, "validuser", "validpass", "user", true)

	t.Run("login succeeds with valid credentials", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := "username=validuser&password=validpass"
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303, got %d", w.Code)
		}
		if w.Header().Get("Set-Cookie") == "" {
			t.Error("expected Set-Cookie header")
		}
	})

	t.Run("login fails with wrong password", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := "username=validuser&password=wrongpass"
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303 redirect to /login?error=..., got %d", w.Code)
		}
	})

	t.Run("login fails with unknown user", func(t *testing.T) {
		w := httptest.NewRecorder()
		body := "username=unknown&password=any"
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Login(w, r)

		if w.Code != http.StatusSeeOther {
			t.Errorf("expected 303 redirect, got %d", w.Code)
		}
	})
}

func TestIntegration_NonAdminBlockedFromAdminEndpoints(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{"CreateZone", h.CreateZone},
		{"DeleteZone", h.DeleteZone},
		{"CreateUser", h.CreateUser},
		{"UpdateUser", h.UpdateUser},
		{"DeleteUser", h.DeleteUser},
		{"ListUsers", h.ListUsers},
		{"CreateUserPage", h.CreateUserPage},
		{"EditUserPage", h.EditUserPage},
		{"RectifyZone", h.RectifyZone},
		{"NotifyZone", h.NotifyZone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &models.User{ID: 2, Username: "regular", Role: "user"}
			ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.SetPathValue("zone_id", "example.com")
			r.SetPathValue("user_id", "3")
			r = r.WithContext(ctx)
			middleware.RequireAdmin(http.HandlerFunc(tt.handler)).ServeHTTP(w, r)

			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403, got %d", w.Code)
			}
		})
	}
}

func TestIntegration_DynDNSBasicAuthFlow(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones") && !strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode([]models.Zone{
				{ID: "example.com.", Name: "example.com", Kind: "Native"},
			})
			return
		}
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer pdnsSrv.Close()

	_ = seedIntegrationUser(t, h, "dyndnsuser", "dyndnspass", "user", true)

	dyndnsH := dyndns.NewHandler(h.DB, h.PDNS, "")

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/nic/update?hostname=www.example.com&myip=1.2.3.4", nil)
	r.SetBasicAuth("dyndnsuser", "dyndnspass")
	dyndnsH.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "good 1.2.3.4") {
		t.Errorf("expected 'good 1.2.3.4', got %q", w.Body.String())
	}
}
