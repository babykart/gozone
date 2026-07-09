package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

func TestListTSIGKeys(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]models.TSIGKey{
			{Name: "key1.", ID: "key1.", Algorithm: "hmac-sha256", Type: "TSIGKey"},
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/tsigkeys", nil)
	r = r.WithContext(ctx)
	h.ListTSIGKeys(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListTSIGKeys_Empty(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/tsigkeys", nil)
	r = r.WithContext(ctx)
	h.ListTSIGKeys(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListTSIGKeys_PaginationAndSearch(t *testing.T) {
	keys := []models.TSIGKey{
		{Name: "alpha-key.", ID: "alpha-key.", Algorithm: "hmac-sha256", Type: "TSIGKey"},
		{Name: "beta-key.", ID: "beta-key.", Algorithm: "hmac-sha256", Type: "TSIGKey"},
		{Name: "gamma-other.", ID: "gamma-other.", Algorithm: "hmac-sha256", Type: "TSIGKey"},
	}
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keys)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/tsigkeys?search=key&PerPage=1&Page=2", nil)
	r = r.WithContext(ctx)
	h.ListTSIGKeys(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "beta-key.") {
		t.Errorf("expected page 2 to contain beta-key, body: %s", body)
	}
	if strings.Contains(body, "alpha-key.") {
		t.Errorf("did not expect alpha-key on page 2, body: %s", body)
	}
	if strings.Contains(body, "gamma-other") {
		t.Errorf("did not expect gamma-other after filtering by 'key', body: %s", body)
	}
	if !strings.Contains(body, "PageInfo=") || !strings.Contains(body, "Search=key") {
		t.Errorf("expected pagination info in response, body: %s", body)
	}
}

func TestCreateTSIGKeyPage(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/tsigkeys/new", nil)
	r = r.WithContext(ctx)
	h.CreateTSIGKeyPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCreateTSIGKey_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req models.TSIGKey
			json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(req)
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=my-key.&algorithm=hmac-sha256&key=c2VjcmV0"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateTSIGKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_tsigkey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestCreateTSIGKey_EmptyName(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/create", strings.NewReader("name=&algorithm=hmac-sha256&key=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateTSIGKey(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Key name is required") {
		t.Error("expected 'Key name is required' in error page")
	}
}

func TestCreateTSIGKey_EmptyAlgorithm(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/create", strings.NewReader("name=test-key.&algorithm=&key=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateTSIGKey(w, r)

	if !strings.Contains(w.Body.String(), "Algorithm is required") {
		t.Error("expected 'Algorithm is required' in error page")
	}
}

// TestCreateTSIGKey_InvalidAlgorithm is the m33 regression test: an
// unsupported TSIG algorithm must be rejected before reaching PowerDNS.
func TestCreateTSIGKey_InvalidAlgorithm(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/create", strings.NewReader("name=test-key.&algorithm=plaintext&key=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateTSIGKey(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid algorithm") {
		t.Error("expected 'Invalid algorithm' in error page")
	}
}

func TestCreateTSIGKey_EmptyKey(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req models.TSIGKey
			json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(req)
		}
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/create", strings.NewReader("name=test-key.&algorithm=hmac-sha256&key="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateTSIGKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	// Verify activity log was created
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_tsigkey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestCreateTSIGKey_NonAdmin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 2, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/create", strings.NewReader("name=test.&algorithm=hmac-sha256&key=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	middleware.RequireAdmin(http.HandlerFunc(h.CreateTSIGKey)).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestEditTSIGKeyPage(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.TSIGKey{
			Name: "my-key.", ID: "my-key.", Algorithm: "hmac-sha256", Key: "secret", Type: "TSIGKey",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/tsigkeys/my-key./edit", nil)
	r.SetPathValue("key_id", "my-key.")
	r = r.WithContext(ctx)
	h.EditTSIGKeyPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// I-1: the key material must never be rendered in the edit form.
	body := w.Body.String()
	if strings.Contains(body, "secret") {
		t.Errorf("TSIG key material leaked into edit page: %s", body)
	}
	if !strings.Contains(body, "Key=") || !strings.Contains(body, "Alg=hmac-sha256") {
		t.Errorf("expected blank key + algorithm in edit page, got: %s", body)
	}
}

func TestUpdateTSIGKey_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "algorithm=hmac-sha256&key=updated-secret"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/my-key./update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("key_id", "my-key.")
	r = r.WithContext(ctx)
	h.UpdateTSIGKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='update_tsigkey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

// TestUpdateTSIGKey_BlankKeyKeepsCurrent is the I-1 regression test: an empty
// key material on submit must keep the current secret. PowerDNS's PUT replaces
// the whole resource, so the handler re-fetches the existing material and
// forwards it back unchanged (no rotation, no exposure).
func TestUpdateTSIGKey_BlankKeyKeepsCurrent(t *testing.T) {
	var putBody string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(models.TSIGKey{
				Name: "my-key.", ID: "my-key.", Algorithm: "hmac-sha256",
				Key: "preserved-secret", Type: "TSIGKey",
			})
		case http.MethodPut:
			buf := make([]byte, r.ContentLength)
			r.Body.Read(buf)
			putBody = string(buf)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Empty key material → keep current.
	body := "algorithm=hmac-sha256&key="
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/my-key./update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("key_id", "my-key.")
	r = r.WithContext(ctx)
	h.UpdateTSIGKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(putBody, "preserved-secret") {
		t.Errorf("expected PUT to forward existing key material, got body: %s", putBody)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='update_tsigkey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestUpdateTSIGKey_EmptyAlgorithm(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/my-key./update", strings.NewReader("algorithm=&key=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("key_id", "my-key.")
	r = r.WithContext(ctx)
	h.UpdateTSIGKey(w, r)

	if !strings.Contains(w.Body.String(), "Algorithm is required") {
		t.Error("expected 'Algorithm is required' in error page")
	}
}

// TestUpdateTSIGKey_InvalidAlgorithm is the m33 regression test for the update
// path: an unsupported TSIG algorithm must be rejected before reaching PowerDNS.
func TestUpdateTSIGKey_InvalidAlgorithm(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/my-key./update", strings.NewReader("algorithm=plaintext&key=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("key_id", "my-key.")
	r = r.WithContext(ctx)
	h.UpdateTSIGKey(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid algorithm") {
		t.Error("expected 'Invalid algorithm' in error page")
	}
}

func TestDeleteTSIGKey_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/delete", strings.NewReader("key_id=my-key."))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteTSIGKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_tsigkey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestDeleteTSIGKey_EmptyID(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/delete", strings.NewReader("key_id="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteTSIGKey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

func TestDeleteTSIGKey_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/delete", strings.NewReader("key_id=my-key."))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteTSIGKey(w, r)

	if !strings.Contains(w.Body.String(), "Failed to delete TSIG key") {
		t.Error("expected 'Failed to delete TSIG key' in error page")
	}
}

func TestBulkDeleteTSIGKeys_Success(t *testing.T) {
	var deletedPaths []string
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletedPaths = append(deletedPaths, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: 1, Username: "admin", Role: "admin"})

	// Three selected, one duplicated — dedupe must collapse it to 3 deletes.
	body := "key_id=a-key.&key_id=b-key.&key_id=c-key.&key_id=a-key."
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteTSIGKeys(w, r)

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
	if resp.Deleted != 3 || len(resp.Failed) != 0 {
		t.Errorf("expected deleted=3 failed=[], got %+v", resp)
	}
	if len(deletedPaths) != 3 {
		t.Errorf("expected 3 PDNS DELETE calls, got %d (%v)", len(deletedPaths), deletedPaths)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_tsigkey'").Scan(&count)
	if count != 3 {
		t.Errorf("expected 3 delete_tsigkey activity logs, got %d", count)
	}
}

func TestBulkDeleteTSIGKeys_PartialFailure(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if strings.Contains(r.URL.Path, "boom-key.") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: 1, Username: "admin", Role: "admin"})

	body := "key_id=ok-key.&key_id=boom-key."
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/bulk-delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteTSIGKeys(w, r)

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
	if resp.Deleted != 1 || len(resp.Failed) != 1 || resp.Failed[0] != "boom-key." {
		t.Errorf("expected deleted=1 failed=[boom-key.], got %+v", resp)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_tsigkey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 delete_tsigkey activity log (success only), got %d", count)
	}
}

func TestBulkDeleteTSIGKeys_NoSelection(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("PDNS should not be called for an empty selection")
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: 1, Username: "admin", Role: "admin"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsigkeys/bulk-delete", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.BulkDeleteTSIGKeys(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty selection, got %d", w.Code)
	}
}

func TestGenerateTSIGSecret(t *testing.T) {
	key1, err := generateTSIGSecret()
	if err != nil {
		t.Fatalf("generateTSIGSecret failed: %v", err)
	}
	if len(key1) == 0 {
		t.Fatal("secret should not be empty")
	}

	// Verify valid base64
	decoded, err := base64.StdEncoding.DecodeString(key1)
	if err != nil {
		t.Fatalf("secret is not valid base64: %v", err)
	}
	if len(decoded) != 64 {
		t.Errorf("expected 64 bytes, got %d", len(decoded))
	}

	// Verify randomness
	key2, err := generateTSIGSecret()
	if err != nil {
		t.Fatalf("generateTSIGSecret failed: %v", err)
	}
	if key1 == key2 {
		t.Error("two generated secrets should be different")
	}
}

func TestGenerateTSIGSecret_DeterministicCheck(t *testing.T) {
	key, err := generateTSIGSecret()
	if err != nil {
		t.Fatalf("generateTSIGSecret failed: %v", err)
	}
	// Verify it has the expected length for base64-encoded 64 bytes
	// 64 bytes → base64 → 88 chars (including padding)
	if len(key) != 88 {
		t.Errorf("expected 88-char base64 key (64 bytes), got %d chars", len(key))
	}
}
