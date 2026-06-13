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
	r := httptest.NewRequest(http.MethodGet, "/zones?page=1", nil)
	r = r.WithContext(ctx)
	h.ListZones(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("page 1: expected 200, got %d", w.Code)
	}

	// Page 2
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodGet, "/zones?page=2", nil)
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

	logs := h.getZoneActivityLogs("example.com")
	if len(logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(logs))
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
