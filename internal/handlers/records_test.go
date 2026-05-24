package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
)

func TestCreateRecordPage(t *testing.T) {
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
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com/records/new", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateRecordPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCreateRecordPage_ZoneNotFound(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/nonexistent/records/new", nil)
	r.SetPathValue("zone_id", "nonexistent")
	r = r.WithContext(ctx)
	h.CreateRecordPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
	}
}

func TestCreateRecord_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com&type=A&content=1.2.3.4&ttl=300"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_record'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestCreateRecord_EmptyFields(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Empty name should redirect back
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/create", strings.NewReader("name=&type=A&content=&ttl="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
}

func TestUpdateRecord_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com&type=A&content=5.6.7.8&ttl=600"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.UpdateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}
}

func TestDeleteRecord_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(models.Zone{
			ID: "example.com", Name: "example.com", Kind: "Native",
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com&type=A"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/delete", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.DeleteRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected redirect 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_record'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestEditRecordPage_Success(t *testing.T) {
	var callCount int
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			models.Zone
			RRSets []models.RRSet `json:"rrsets"`
		}{
			Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
			RRSets: []models.RRSet{
				{
					Name: "www.example.com",
					Type: "A",
					TTL:  300,
					Records: []models.RecordInfo{
						{Name: "www.example.com", Type: "A", Content: "1.2.3.4", Disabled: false},
					},
				},
			},
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com/records/edit?name=www.example.com&type=A", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.EditRecordPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Edit Record") {
		t.Errorf("expected 'Edit Record' in rendered page, got: %s", w.Body.String())
	}
}

func TestEditRecordPage_ZoneNotFound(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"Not found"}`))
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/nonexistent/records/edit?name=www&type=A", nil)
	r.SetPathValue("zone_id", "nonexistent")
	r = r.WithContext(ctx)
	h.EditRecordPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Zone not found") {
		t.Error("expected 'Zone not found' error message")
	}
}

func TestEditRecordPage_RecordNotFound(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			models.Zone
			RRSets []models.RRSet `json:"rrsets"`
		}{
			Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
			RRSets: []models.RRSet{},
		})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com/records/edit?name=www.example.com&type=A", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.EditRecordPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Record not found") {
		t.Error("expected 'Record not found' error message")
	}
}

func TestEditRecordPage_RecordRetrievalError(t *testing.T) {
	var callCount int
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(models.Zone{
				ID: "example.com", Name: "example.com", Kind: "Native",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com/records/edit?name=www.example.com&type=A", nil)
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.EditRecordPage(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (error page), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to fetch records") {
		t.Errorf("expected 'Failed to fetch records' error message, got: %s", w.Body.String())
	}
}
