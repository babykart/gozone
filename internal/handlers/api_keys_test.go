package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/constants"
	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func TestCreateAPIKey_SetsFlashCookieNotQueryString(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "description=test-key"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/profile/api-keys/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateAPIKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "flash=created") {
		t.Errorf("expected location to contain flash=created, got %s", location)
	}
	if strings.Contains(location, "new_key=") {
		t.Errorf("location must not contain the raw API key, got %s", location)
	}

	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == constants.NewAPIKeyCookieName && c.Value != "" {
			found = true
			if c.Path != "/profile/api-keys" {
				t.Errorf("expected cookie path /profile/api-keys, got %s", c.Path)
			}
			if !c.HttpOnly {
				t.Error("expected flash cookie to be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("expected new_api_key flash cookie to be set")
	}
}

func TestListAPIKeys_ReadsAndClearsFlashCookie(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/profile/api-keys?flash=created", nil)
	r.AddCookie(&http.Cookie{
		Name:  constants.NewAPIKeyCookieName,
		Value: "gozone_secret_key_123",
		Path:  "/profile/api-keys",
	})
	r = r.WithContext(ctx)
	h.ListAPIKeys(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "NewKey=gozone_secret_key_123") {
		t.Errorf("expected response to contain the new key, got %s", body)
	}

	cookies := w.Result().Cookies()
	var cleared bool
	for _, c := range cookies {
		if c.Name == constants.NewAPIKeyCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("expected new_api_key cookie to be cleared")
	}
}

func TestListAPIKeys_PaginationAndSearch(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	for i, desc := range []string{"alpha-key", "beta-key", "gamma-other"} {
		_, err := h.DB.Exec(
			`INSERT INTO api_keys (user_id, description, key_hash, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
			1, desc, fmt.Sprintf("hash%d", i),
		)
		if err != nil {
			t.Fatalf("seed api key: %v", err)
		}
	}

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/profile/api-keys?search=key&PerPage=1&Page=2", nil)
	r = r.WithContext(ctx)
	h.ListAPIKeys(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "beta-key") {
		t.Errorf("expected page 2 to contain beta-key, body: %s", body)
	}
	if strings.Contains(body, "alpha-key") {
		t.Errorf("did not expect alpha-key on page 2, body: %s", body)
	}
	if strings.Contains(body, "gamma-other") {
		t.Errorf("did not expect gamma-other after filtering by 'key', body: %s", body)
	}
	if !strings.Contains(body, "PageInfo=") || !strings.Contains(body, "Search=key") {
		t.Errorf("expected pagination info in response, body: %s", body)
	}
}

func seedAPIKey(t *testing.T, db *database.DB, userID int64, desc, hash string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO api_keys (user_id, description, key_hash, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		userID, desc, hash,
	)
	if err != nil {
		t.Fatalf("seed api key: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestBulkDeleteAPIKeys_Success(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	a := seedAPIKey(t, h.DB, 1, "alpha", "h1")
	b := seedAPIKey(t, h.DB, 1, "beta", "h2")
	c := seedAPIKey(t, h.DB, 1, "gamma", "h3")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Delete a and b; c is sent twice (dedupe) but c itself must survive.
	body := fmt.Sprintf("key_id=%d&key_id=%d&key_id=%d", a, b, b)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/profile/api-keys/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteAPIKeys(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Deleted int      `json:"deleted"`
		Failed  []string `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Deleted != 2 || len(resp.Failed) != 0 {
		t.Errorf("expected deleted=2 failed=[], got %+v", resp)
	}

	var remaining int
	h.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE user_id=1").Scan(&remaining)
	if remaining != 1 {
		t.Errorf("expected 1 remaining key (gamma), got %d", remaining)
	}
	var gammaCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE id=?", c).Scan(&gammaCount)
	if gammaCount != 1 {
		t.Errorf("gamma key should still exist, got count=%d", gammaCount)
	}

	var logCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_api_key'").Scan(&logCount)
	if logCount != 2 {
		t.Errorf("expected 2 delete_api_key logs, got %d", logCount)
	}
}

func TestBulkDeleteAPIKeys_RejectsNotOwned(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	// A second user owns a key the admin must not be able to delete.
	testutil.SeedTestUser(t, h.DB, "other", "other", "user", true)
	mine := seedAPIKey(t, h.DB, 1, "mine", "h1")
	theirs := seedAPIKey(t, h.DB, 2, "theirs", "h2")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := fmt.Sprintf("key_id=%d&key_id=%d", mine, theirs)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/profile/api-keys/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteAPIKeys(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (best-effort), got %d", w.Code)
	}
	var resp struct {
		Deleted int      `json:"deleted"`
		Failed  []string `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Deleted != 1 {
		t.Errorf("expected deleted=1, got %d", resp.Deleted)
	}
	if len(resp.Failed) != 1 || resp.Failed[0] != fmt.Sprintf("%d", theirs) {
		t.Errorf("expected failed=[%d], got %+v", theirs, resp.Failed)
	}

	// The other user's key must still be present.
	var theirCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE id=?", theirs).Scan(&theirCount)
	if theirCount != 1 {
		t.Errorf("other user's key must not be deleted, got count=%d", theirCount)
	}
}

func TestBulkDeleteAPIKeys_NoSelection(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/profile/api-keys/bulk-delete", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteAPIKeys(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty selection, got %d", w.Code)
	}
}

func TestDeleteAPIKey_OwnKey(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	id := seedAPIKey(t, h.DB, 1, "mine", "h1")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := fmt.Sprintf("key_id=%d", id)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/profile/api-keys/delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteAPIKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "flash=deleted") {
		t.Errorf("expected flash=deleted redirect, got %s", loc)
	}

	var remaining int
	h.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE id=?", id).Scan(&remaining)
	if remaining != 0 {
		t.Errorf("expected key deleted, remaining=%d", remaining)
	}
	var logCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_api_key'").Scan(&logCount)
	if logCount != 1 {
		t.Errorf("expected 1 delete_api_key log, got %d", logCount)
	}
}

// TestDeleteAPIKey_NotFoundAndForbiddenCollapsed guards REVIEW.md M-2: a
// nonexistent key id and a foreign user's key id must yield the identical
// ?error=not_found redirect so the handler is not an IDOR existence oracle
// (the prior ?error=forbidden branch leaked key-id existence regardless of
// ownership). Mirrors the BulkDeleteAPIKeys ownership-scoped DELETE pattern.
func TestDeleteAPIKey_NotFoundAndForbiddenCollapsed(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	testutil.SeedTestUser(t, h.DB, "other", "other", "user", true)
	theirs := seedAPIKey(t, h.DB, 2, "theirs", "h2")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	cases := []struct {
		name  string
		keyID string
	}{
		{"nonexistent id", "999999"},
		{"foreign-owned id", fmt.Sprintf("%d", theirs)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := "key_id=" + tc.keyID
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/profile/api-keys/delete", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r = r.WithContext(ctx)
			h.DeleteAPIKey(w, r)

			if w.Code != http.StatusSeeOther {
				t.Fatalf("expected 303, got %d", w.Code)
			}
			loc := w.Header().Get("Location")
			if !strings.Contains(loc, "error=not_found") {
				t.Errorf("expected error=not_found, got %s", loc)
			}
			if strings.Contains(loc, "error=forbidden") {
				t.Errorf("error=forbidden must not be emitted (existence oracle), got %s", loc)
			}
		})
	}

	// The foreign key must survive both attempts.
	var theirCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM api_keys WHERE id=?", theirs).Scan(&theirCount)
	if theirCount != 1 {
		t.Errorf("foreign key must survive, count=%d", theirCount)
	}
	// No delete_api_key log should have been written for the failed attempts.
	var logCount int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_api_key'").Scan(&logCount)
	if logCount != 0 {
		t.Errorf("expected 0 delete logs for failed attempts, got %d", logCount)
	}
}

// TestListAPIKeys_AllowListsFlashErrorCodes guards REVIEW.md L-1: the ?flash
// and ?error query params are validated against a server-side allow-list
// (flash=created|deleted, error=not_found) so a crafted link such as
// ?flash=Your+account+compromised cannot inject arbitrary text into the page.
// Valid codes pass through; crafted codes are dropped at the handler trust
// boundary.
func TestListAPIKeys_AllowListsFlashErrorCodes(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Valid codes flow through to the template.
	r := httptest.NewRequest(http.MethodGet, "/profile/api-keys?flash=created&error=not_found", nil)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ListAPIKeys(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Flash=created") {
		t.Errorf("expected Flash=created in body, got %s", body)
	}
	if !strings.Contains(body, "Error=not_found") {
		t.Errorf("expected Error=not_found in body, got %s", body)
	}

	// Crafted codes are dropped — a phishing link cannot inject arbitrary text.
	r2 := httptest.NewRequest(http.MethodGet, "/profile/api-keys?flash=Your+account+compromised&error=evil_code", nil)
	r2 = r2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	h.ListAPIKeys(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}
	body2 := w2.Body.String()
	for _, needle := range []string{"compromised", "evil_code", "Flash=Your", "Error=evil"} {
		if strings.Contains(body2, needle) {
			t.Errorf("unknown flash/error code leaked into body: %q in %s", needle, body2)
		}
	}
}
