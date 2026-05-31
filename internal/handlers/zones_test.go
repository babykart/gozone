package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (render error), got %d", w.Code)
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
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

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
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
	if len(paged) != 0 || info.TotalPages != 0 {
		t.Errorf("perPage=0: len=%d pages=%d", len(paged), info.TotalPages)
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
