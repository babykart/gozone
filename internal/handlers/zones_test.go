package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
	"github.com/babykart/gozone/internal/testutil"
)

func TestListZones(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers/localhost/zones" {
			w.Write([]byte(`[{"id":"example.com","name":"example.com","kind":"Native"}]`))
		} else {
			w.Write([]byte(`[]`))
		}
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones", nil)
	r = r.WithContext(ctx)
	h.ListZones(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListZones_Empty(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones", nil)
	r = r.WithContext(ctx)
	h.ListZones(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCreateZonePage(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/new", nil)
	r = r.WithContext(ctx)
	h.CreateZonePage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCreateZone_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.Zone{ID: "newzone.com", Name: "newzone.com", Kind: "Native"})
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=newzone.com&kind=Native"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateZone(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	// Activity log should exist
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_zone'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

// TestCreateZone_NormalizesNameAndNameservers is the regression test for the
// bug where a zone name or nameserver entered without a trailing dot (e.g.
// "example.com") was forwarded to PowerDNS as-is, causing a PDNS error. The
// handler must canonicalise both the zone name and each nameserver to
// lowercase + trailing dot before sending the request.
func TestCreateZone_NormalizesNameAndNameservers(t *testing.T) {
	var sent models.ZoneCreateRequest
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&sent)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(models.Zone{ID: sent.Name, Name: sent.Name, Kind: sent.Kind})
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=Example.COM&kind=Native&nameservers=ns1.example.com,ns2.example.com"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateZone(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d (%s)", w.Code, w.Body.String())
	}
	if sent.Name != "example.com." {
		t.Errorf("PDNS received name=%q, want %q (lowercase + trailing dot)", sent.Name, "example.com.")
	}
	if len(sent.Nameservers) != 2 {
		t.Fatalf("expected 2 nameservers, got %d", len(sent.Nameservers))
	}
	if sent.Nameservers[0] != "ns1.example.com." {
		t.Errorf("PDNS received ns[0]=%q, want %q", sent.Nameservers[0], "ns1.example.com.")
	}
	if sent.Nameservers[1] != "ns2.example.com." {
		t.Errorf("PDNS received ns[1]=%q, want %q", sent.Nameservers[1], "ns2.example.com.")
	}
}

func TestCreateZone_NonAdmin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/create", strings.NewReader("name=test.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	middleware.RequireAdmin(http.HandlerFunc(h.CreateZone)).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCreateZone_EmptyName(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/create", strings.NewReader("name="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.CreateZone(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestDeleteZone_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/delete", strings.NewReader("zone_id=example.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteZone(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_zone'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestDeleteZone_NonAdmin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/delete", strings.NewReader("zone_id=example.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	middleware.RequireAdmin(http.HandlerFunc(h.DeleteZone)).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestDeleteZone_EmptyID(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/delete", strings.NewReader("zone_id="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = r.WithContext(ctx)
	h.DeleteZone(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
}

func TestViewZone(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.ViewZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// panicMetadata wraps a ZoneService and panics on GetMetadata. Used by
// TestViewZone_GoroutinePanicRecovery to verify the defer/recover guards.
type panicMetadata struct {
	pdns.ZoneService
}

func (p *panicMetadata) GetMetadata(ctx context.Context, zoneID string) ([]models.Metadata, error) {
	panic("simulated PDNS client panic")
}

// TestViewZone_GoroutinePanicRecovery is the M-BIZ3 regression test: a panic
// in any of the PDNS goroutines must be recovered, not crash the process.
// Here GetMetadata panics; ViewZone ignores metadata errors so the page must
// still render successfully. Without the recover in the goroutine this test
// would crash the test runner.
func TestViewZone_GoroutinePanicRecovery(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	// Wrap the PDNS client so GetMetadata panics. All other methods delegate
	// to the real client.
	h.PDNS = &panicMetadata{ZoneService: h.PDNS}

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.ViewZone(w, r)

	// The panic must be recovered — ViewZone should still render the page.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (panic recovered), got %d", w.Code)
	}
}

func TestRectifyZone_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/rectify", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.RectifyZone(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='rectify_zone'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestRectifyZone_NonAdmin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 2, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/rectify", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	middleware.RequireAdmin(http.HandlerFunc(h.RectifyZone)).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestRectifyZone_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/rectify", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.RectifyZone(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Rectify failed") {
		t.Error("expected 'Rectify failed' in error page")
	}
}

func TestNotifyZone_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/notify", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.NotifyZone(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}
}

func TestNotifyZone_NonAdmin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 2, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/notify", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	middleware.RequireAdmin(http.HandlerFunc(h.NotifyZone)).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestNotifyZone_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/notify", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.NotifyZone(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Notify failed") {
		t.Error("expected 'Notify failed' in error page")
	}
}

func TestCreateMetadata_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		}
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "kind=ALSO-NOTIFY&values=10.0.0.1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateMetadata(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_metadata'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestCreateMetadata_MultiLineValues(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req models.Metadata
			json.NewDecoder(r.Body).Decode(&req)
			if len(req.Metadata) != 2 {
				t.Errorf("expected 2 values, got %d", len(req.Metadata))
			}
			w.WriteHeader(http.StatusCreated)
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
		}
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "kind=ALLOW-AXFR-FROM&values=192.0.2.0%2F24%0A2001%3Adb8%3A%3A%2F32"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateMetadata(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
}

func TestCreateMetadata_EmptyKind(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/create", strings.NewReader("kind=&values=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateMetadata(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Metadata kind is required") {
		t.Error("expected 'Metadata kind is required' in error page")
	}
}

func TestCreateMetadata_EmptyValues(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/create", strings.NewReader("kind=SOA-EDIT&values="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateMetadata(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "At least one value is required") {
		t.Error("expected 'At least one value is required' in error page")
	}
}

func TestCreateMetadata_NonAdmin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 2, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/create", strings.NewReader("kind=NSEC3PARAM&values=test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	middleware.RequireAdmin(http.HandlerFunc(h.CreateMetadata)).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestDeleteMetadata_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/delete", strings.NewReader("kind=PRESIGNED"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.DeleteMetadata(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_metadata'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestDeleteMetadata_EmptyKind(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/delete", strings.NewReader("kind="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.DeleteMetadata(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Metadata kind is required") {
		t.Error("expected 'Metadata kind is required' in error page")
	}
}

func TestDeleteMetadata_NonAdmin(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 2, Username: "user", Role: "user"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/delete", strings.NewReader("kind=PRESIGNED"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	middleware.RequireAdmin(http.HandlerFunc(h.DeleteMetadata)).ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestCreateMetadata_PDNSError(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/metadata/create", strings.NewReader("kind=SOA-EDIT&values=INCREASE"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateMetadata(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to set metadata") {
		t.Error("expected 'Failed to set metadata' in error page")
	}
}

func TestPaginate(t *testing.T) {
	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	// Page 1 of 10
	paged, info := paginate(items, 1, 10)
	if len(paged) != 10 || info.TotalPages != 2 || info.Current != 1 || info.Total != 15 {
		t.Errorf("page 1: len=%d pages=%d current=%d total=%d", len(paged), info.TotalPages, info.Current, info.Total)
	}
	if paged[0] != 1 || paged[9] != 10 {
		t.Errorf("page 1 items: got %v", paged)
	}

	// Page 2 of 10
	paged, info = paginate(items, 2, 10)
	if len(paged) != 5 || info.Current != 2 || info.TotalPages != 2 {
		t.Errorf("page 2: len=%d pages=%d current=%d", len(paged), info.TotalPages, info.Current)
	}
	if paged[0] != 11 || paged[4] != 15 {
		t.Errorf("page 2 items: got %v", paged)
	}

	// Page below 1 → clamped to 1
	paged, info = paginate(items, 0, 10)
	if info.Current != 1 || len(paged) != 10 {
		t.Errorf("page 0 clamps to 1: current=%d len=%d", info.Current, len(paged))
	}

	// Page beyond total → clamped to last
	paged, info = paginate(items, 99, 10)
	if info.Current != 2 || len(paged) != 5 {
		t.Errorf("page 99 clamps to 2: current=%d len=%d", info.Current, len(paged))
	}

	// Empty slice
	paged, info = paginate([]int{}, 1, 10)
	if len(paged) != 0 || info.TotalPages != 0 || info.Total != 0 {
		t.Errorf("empty: len=%d pages=%d total=%d", len(paged), info.TotalPages, info.Total)
	}

	// Exact multiple
	paged, info = paginate([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 1, 5)
	if len(paged) != 5 || info.TotalPages != 2 || info.Current != 1 {
		t.Errorf("exact multiple page 1: len=%d pages=%d", len(paged), info.TotalPages)
	}

	// perPage = 0 → all items
	paged, info = paginate(items, 1, 0)
	if len(paged) != 15 || info.TotalPages != 1 || info.Current != 1 {
		t.Errorf("perPage=0: len=%d pages=%d current=%d", len(paged), info.TotalPages, info.Current)
	}

	// single item
	paged, info = paginate([]int{42}, 1, 10)
	if len(paged) != 1 || info.TotalPages != 1 || info.Total != 1 {
		t.Errorf("single: len=%d pages=%d total=%d", len(paged), info.TotalPages, info.Total)
	}
}

func TestPageInfoFromTotal(t *testing.T) {
	info := pageInfoFromTotal(15, 1, 10)
	if info.Current != 1 || info.PerPage != 10 || info.TotalPages != 2 || info.Total != 15 {
		t.Errorf("pageInfoFromTotal(15,1,10) = %+v", info)
	}

	info = pageInfoFromTotal(15, 2, 10)
	if info.Current != 2 || info.TotalPages != 2 {
		t.Errorf("pageInfoFromTotal(15,2,10) = %+v", info)
	}

	// Page clamped below / above.
	info = pageInfoFromTotal(5, 0, 2)
	if info.Current != 1 {
		t.Errorf("pageInfoFromTotal clamps below 1: %+v", info)
	}

	info = pageInfoFromTotal(5, 99, 2)
	if info.Current != 3 {
		t.Errorf("pageInfoFromTotal clamps above total: %+v", info)
	}

	// perPage 0 means one page.
	info = pageInfoFromTotal(100, 5, 0)
	if info.PerPage != 0 || info.TotalPages != 1 {
		t.Errorf("pageInfoFromTotal(100,5,0) = %+v", info)
	}
}

func TestBuildSearchLikeWhere(t *testing.T) {
	clause, args := buildSearchLikeWhere("  ", "name")
	if clause != "" || len(args) != 0 {
		t.Errorf("empty search should return empty clause, got %q %v", clause, args)
	}

	clause, args = buildSearchLikeWhere("Foo", "name", "description")
	if !strings.Contains(clause, "LOWER(name) LIKE ?") || !strings.Contains(clause, "LOWER(description) LIKE ?") {
		t.Errorf("expected LIKE clauses, got %q", clause)
	}
	if len(args) != 2 || args[0] != "%foo%" || args[1] != "%foo%" {
		t.Errorf("expected two lower-case wildcard args, got %v", args)
	}
}

func TestListZones_Pagination(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers/localhost/zones" {
			// Return 15 zones
			zones := make([]models.Zone, 15)
			for i := range zones {
				zones[i] = models.Zone{
					ID:   fmt.Sprintf("zone%d.com", i+1),
					Name: fmt.Sprintf("zone%d.com", i+1),
					Kind: "Native",
				}
			}
			json.NewEncoder(w).Encode(zones)
		} else {
			w.Write([]byte(`[]`))
		}
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Page 1
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones?Page=1", nil)
	r = r.WithContext(ctx)
	h.ListZones(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("page 1: expected 200, got %d", w.Code)
	}

	// Page 2
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/zones?Page=2", nil)
	r2 = r2.WithContext(ctx)
	h.ListZones(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("page 2: expected 200, got %d", w2.Code)
	}

	// Default page (no param) should be page 1
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest(http.MethodGet, "/zones", nil)
	r3 = r3.WithContext(ctx)
	h.ListZones(w3, r3)
	if w3.Code != http.StatusOK {
		t.Errorf("default page: expected 200, got %d", w3.Code)
	}
}

// TestParsePaginationParams_QueryNames guards the query-parameter names against
// the case-mismatch bug where the template/JS emit "Page"/"PerPage" (and
// "logPage"/"logPerPage") but the parser read lower-case names, so changing the
// per-page selector only refreshed the page with no effect.
func TestParsePaginationParams_QueryNames(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/zones?Page=3&PerPage=25", nil)
	if page, perPage := parsePaginationParams(r, 10); page != 3 || perPage != 25 {
		t.Errorf("records: got page=%d perPage=%d, want 3 and 25", page, perPage)
	}

	// PerPage=0 means "All" and must be honored (not replaced by the default).
	rAll := httptest.NewRequest(http.MethodGet, "/zones?PerPage=0", nil)
	if _, perPage := parsePaginationParams(rAll, 10); perPage != 0 {
		t.Errorf("records PerPage=0: got perPage=%d, want 0", perPage)
	}

	// Missing params fall back to defaults.
	rDefault := httptest.NewRequest(http.MethodGet, "/zones", nil)
	if page, perPage := parsePaginationParams(rDefault, 10); page != 1 || perPage != 10 {
		t.Errorf("records default: got page=%d perPage=%d, want 1 and 10", page, perPage)
	}

	// Activity-log params are independent and use the "log" prefix.
	rLog := httptest.NewRequest(http.MethodGet, "/zones/x?logPage=4&logPerPage=50", nil)
	if page, perPage := parseLogPaginationParams(rLog, 10); page != 4 || perPage != 50 {
		t.Errorf("log: got page=%d perPage=%d, want 4 and 50", page, perPage)
	}
}

func TestListZones_Search(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers/localhost/zones" {
			json.NewEncoder(w).Encode([]models.Zone{
				{ID: "test1.com", Name: "test1.com", Kind: "Native"},
				{ID: "example.net", Name: "example.net", Kind: "Native"},
				{ID: "example.org", Name: "example.org", Kind: "Native"},
			})
		} else {
			w.Write([]byte(`[]`))
		}
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones?search=example", nil)
	r = r.WithContext(ctx)
	h.ListZones(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListZones_Search_NoResults(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers/localhost/zones" {
			json.NewEncoder(w).Encode([]models.Zone{
				{ID: "test1.com", Name: "test1.com", Kind: "Native"},
			})
		} else {
			w.Write([]byte(`[]`))
		}
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones?search=nonexistent", nil)
	r = r.WithContext(ctx)
	h.ListZones(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestListZones_Search_CaseInsensitive(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/servers/localhost/zones" {
			json.NewEncoder(w).Encode([]models.Zone{
				{ID: "EXAMPLE.com", Name: "EXAMPLE.com", Kind: "Native"},
			})
		} else {
			w.Write([]byte(`[]`))
		}
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Search with lowercase should match uppercase zone name
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones?search=example", nil)
	r = r.WithContext(ctx)
	h.ListZones(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestViewZone_ParallelPDNSCalls(t *testing.T) {
	var active atomic.Int32
	var maxConcurrent atomic.Int32

	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		cur := active.Add(1)
		for {
			prev := maxConcurrent.Load()
			if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
				break
			}
		}
		// Hold the request open briefly so concurrent goroutines can overlap.
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.ViewZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if got := maxConcurrent.Load(); got < 2 {
		t.Errorf("expected ≥ 2 concurrent PDNS calls, got %d — calls may be sequential", got)
	}
}

func TestGetZoneActivityLogs_UsernamePopulated(t *testing.T) {
	h := newTestHandler(t)
	testutil.SeedTestUser(t, h.DB, "alice", "alice@example.com", "alice", false)

	h.DB.Exec(
		"INSERT INTO activity_logs (user_id, zone_id, action, details) VALUES (?, ?, 'create_record', ?)",
		1, "example.com", "Created A record www -> 1.2.3.4",
	)

	logs, total := h.getZoneActivityLogs("example.com", 1, 10)
	if len(logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logs))
	}
	if total != 1 {
		t.Errorf("expected total 1, got %d", total)
	}
	if logs[0].Username != "alice" {
		t.Errorf("expected Username 'alice', got %q", logs[0].Username)
	}
}

func TestViewZone_RecordsSearch(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/records") {
			// This is a separate zone request, not used
		}
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com?search=www", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.ViewZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestViewZone_SearchAt(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		if strings.HasSuffix(path, "/metadata") {
			w.Write([]byte(`[]`))
			return
		}
		if strings.HasSuffix(path, "/cryptokeys") {
			w.Write([]byte(`[]`))
			return
		}
		if strings.Contains(path, "/servers/localhost") && !strings.Contains(path, "/zones/") {
			w.Write([]byte(`{"id":"localhost","type":"Server","version":"4.9.0"}`))
			return
		}
		w.Write([]byte(`{
			"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100,
			"rrsets":[
				{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com. hostmaster.example.com. 1 10800 3600 604800 3600","disabled":false}]},
				{"name":"example.com.","type":"NS","ttl":3600,"records":[{"content":"ns1.example.com.","disabled":false}]},
				{"name":"example.com.","type":"A","ttl":300,"records":[{"content":"192.0.2.1","disabled":false}]},
				{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"192.0.2.2","disabled":false}]}
			]
		}`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com.?search=@", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = r.WithContext(ctx)
	h.ViewZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "192.0.2.1") {
		t.Error("@ search should return apex A record content")
	}
	if strings.Contains(body, "192.0.2.2") {
		t.Error("@ search should not return www subdomain records")
	}
}

func TestViewZone_SortOrder(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		if strings.HasSuffix(path, "/metadata") {
			w.Write([]byte(`[]`))
			return
		}
		if strings.HasSuffix(path, "/cryptokeys") {
			w.Write([]byte(`[]`))
			return
		}
		if strings.Contains(path, "/servers/localhost") && !strings.Contains(path, "/zones/") {
			w.Write([]byte(`{"id":"localhost","type":"Server","version":"4.9.0"}`))
			return
		}
		w.Write([]byte(`{
			"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100,
			"rrsets":[
				{"name":"www.example.com.","type":"A","ttl":300,"records":[{"content":"192.0.2.2","disabled":false}]},
				{"name":"example.com.","type":"NS","ttl":3600,"records":[{"content":"ns2.example.com.","disabled":false}]},
				{"name":"example.com.","type":"MX","ttl":600,"records":[{"content":"mx.example.com.","priority":10,"disabled":false}]},
				{"name":"example.com.","type":"SOA","ttl":3600,"records":[{"content":"ns1.example.com. hostmaster.example.com. 1 10800 3600 604800 3600","disabled":false}]},
				{"name":"admin.example.com.","type":"A","ttl":300,"records":[{"content":"192.0.2.3","disabled":false}]}
			]
		}`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com.", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = r.WithContext(ctx)
	h.ViewZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()

	soaIdx := strings.Index(body, "hostmaster.example.com.")
	nsIdx := strings.Index(body, "ns2.example.com.")
	mxIdx := strings.Index(body, "mx.example.com.")
	wwwIdx := strings.Index(body, "192.0.2.2")
	adminIdx := strings.Index(body, "192.0.2.3")

	if soaIdx < 0 || nsIdx < 0 || mxIdx < 0 || wwwIdx < 0 || adminIdx < 0 {
		t.Fatal("some expected records missing from output")
	}

	if soaIdx > nsIdx {
		t.Error("SOA should appear before NS")
	}
	if mxIdx > adminIdx {
		t.Error("apex MX should appear before admin/www (alpha subdomains)")
	}
}

func TestSortZoneRecords(t *testing.T) {
	zoneName := "example.com."
	records := []models.RRSet{
		{Name: "www.example.com.", Type: "A"},
		{Name: "example.com.", Type: "NS"},
		{Name: "example.com.", Type: "SOA"},
		{Name: "example.com.", Type: "A"},
		{Name: "ns1.example.com.", Type: "NS"},
		{Name: "example.com.", Type: "MX"},
	}

	sortZoneRecords(records, zoneName)

	expected := []struct {
		name string
		typ  string
	}{
		{"example.com.", "SOA"},
		{"example.com.", "NS"},
		{"ns1.example.com.", "NS"},
		{"example.com.", "A"},
		{"example.com.", "MX"},
		{"www.example.com.", "A"},
	}

	if len(records) != len(expected) {
		t.Fatalf("expected %d records, got %d", len(expected), len(records))
	}
	for i, want := range expected {
		if records[i].Name != want.name || records[i].Type != want.typ {
			t.Errorf("record %d: expected %s %s, got %s %s",
				i, want.name, want.typ, records[i].Name, records[i].Type)
		}
	}
}

func TestSortZoneRecords_TwoNS(t *testing.T) {
	// Regression for the strict-weak-ordering bug: comparing two NS records
	// must not return true in both directions.
	zoneName := "example.com."
	records := []models.RRSet{
		{Name: "ns2.example.com.", Type: "NS"},
		{Name: "ns1.example.com.", Type: "NS"},
	}

	sortZoneRecords(records, zoneName)

	if records[0].Name != "ns1.example.com." || records[1].Name != "ns2.example.com." {
		t.Errorf("expected ns1 before ns2, got %v", records)
	}
}

func TestSortZoneRecords_TwoSOA(t *testing.T) {
	zoneName := "example.com."
	records := []models.RRSet{
		{Name: "example.com.", Type: "SOA"},
		{Name: "example.com.", Type: "SOA"},
	}

	// Should not panic from invalid comparator.
	sortZoneRecords(records, zoneName)

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

// TestFlattenRecords is the regression test for the "10 lines not respected"
// bug: pagination used to count RRSets (one SOA + one NS = 2 items) instead
// of individual record rows (1 SOA + 10 NS = 11 rows), so all 11 rows landed
// on a single page of 10. flattenRecords expands RRSets into rows so that
// paginate counts what the user actually sees.
func TestFlattenRecords(t *testing.T) {
	rrsets := []models.RRSet{
		{
			Name: "example.com.",
			Type: "SOA",
			TTL:  3600,
			Records: []models.RecordInfo{
				{Content: "ns1.example.com. hostmaster 1 10800 3600 604800 3600"},
			},
		},
		{
			Name: "example.com.",
			Type: "NS",
			TTL:  3600,
			Records: []models.RecordInfo{
				{Content: "ns1.example.com."},
				{Content: "ns2.example.com."},
				{Content: "ns3.example.com."},
				{Content: "ns4.example.com."},
				{Content: "ns5.example.com."},
				{Content: "ns6.example.com."},
				{Content: "ns7.example.com."},
				{Content: "ns8.example.com."},
				{Content: "ns9.example.com."},
				{Content: "ns10.example.com."},
			},
		},
	}

	rows := flattenRecords(rrsets)

	if len(rows) != 11 {
		t.Fatalf("expected 11 flattened rows (1 SOA + 10 NS), got %d", len(rows))
	}

	// First row must carry the SOA RRset metadata + the single SOA record.
	if rows[0].Name != "example.com." || rows[0].Type != "SOA" {
		t.Errorf("row 0: expected SOA, got %s %s", rows[0].Name, rows[0].Type)
	}
	if rows[0].Record.Content == "" {
		t.Errorf("row 0: expected non-empty SOA content")
	}

	// Rows 1–10 must carry the NS RRset metadata + individual NS records.
	for i := 1; i <= 10; i++ {
		if rows[i].Type != "NS" {
			t.Errorf("row %d: expected NS, got %s", i, rows[i].Type)
		}
		if rows[i].Record.Content == "" {
			t.Errorf("row %d: expected non-empty NS content", i)
		}
	}

	// With perPage=10, page 1 must contain exactly 10 rows (the SOA +
	// 9 NS records), not the entire zone.
	paged, info := paginate(rows, 1, 10)
	if len(paged) != 10 {
		t.Fatalf("page 1: expected 10 rows, got %d", len(paged))
	}
	if info.Total != 11 || info.TotalPages != 2 {
		t.Errorf("expected total=11 totalPages=2, got total=%d totalPages=%d", info.Total, info.TotalPages)
	}

	// Page 2 must contain the remaining NS record.
	paged2, info2 := paginate(rows, 2, 10)
	if len(paged2) != 1 {
		t.Fatalf("page 2: expected 1 row, got %d", len(paged2))
	}
	if paged2[0].Record.Content != "ns10.example.com." {
		t.Errorf("page 2: expected ns10, got %s", paged2[0].Record.Content)
	}
	_ = info2
}

// TestFlattenRecords_Empty ensures no panic on an empty RRset slice and that
// the result is a non-nil empty slice (so {{if .Records}} works in the
// template).
func TestFlattenRecords_Empty(t *testing.T) {
	rows := flattenRecords(nil)
	if rows == nil {
		t.Fatal("expected non-nil empty slice")
	}
	if len(rows) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(rows))
	}
}
