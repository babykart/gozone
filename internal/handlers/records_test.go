package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
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

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
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

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

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

func TestCreateRecord_LogsOldNewSnapshot(t *testing.T) {
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
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{{Name: "www.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "1.2.3.4", Disabled: false}}}},
			})
			return
		}
		json.NewEncoder(w).Encode(models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"})
	})
	defer pdnsSrv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com&type=A&content=5.6.7.8&ttl=600&original_content=1.2.3.4&original_priority=0"
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

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

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

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
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

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
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

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to fetch records") {
		t.Errorf("expected 'Failed to fetch records' error message, got: %s", w.Body.String())
	}
}

func TestInlineUpdateRecord_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPatch {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{{Name: "www.example.com", Type: "A", TTL: 300, Records: []models.RecordInfo{{Content: "10.0.0.1", Disabled: false}}}},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com&type=A&content=10.0.0.2&ttl=3600&priority=0&disabled=false&original_content=10.0.0.1&original_priority=0"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/inline-update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.InlineUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp)
	}
}

func TestInlineUpdateRecord_EmptyContent(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com&type=A&content=&ttl=3600"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/inline-update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.InlineUpdateRecord(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestInlineUpdateRecord_InvalidType(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com&type=INVALID&content=test&ttl=3600"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/inline-update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.InlineUpdateRecord(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestInlineUpdateRecord_PreservesSiblingRecords(t *testing.T) {
	var patchedRRSet []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{
					{
						Name: "example.com.",
						Type: "MX",
						TTL:  3600,
						Records: []models.RecordInfo{
							{Content: "10 mail1.example.com.", Priority: 0, Disabled: false},
							{Content: "20 mail2.example.com.", Priority: 0, Disabled: false},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.Unmarshal(body, &payload)
			patchedRRSet = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=example.com&type=MX&content=mail3.example.com&ttl=3600&priority=30&disabled=false&original_content=mail2.example.com.&original_priority=20"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/inline-update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.InlineUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}

	records := patchedRRSet[0].Records
	if len(records) != 2 {
		t.Fatalf("expected 2 records preserved, got %d", len(records))
	}

	found1, found2 := false, false
	for _, rec := range records {
		if strings.Contains(rec.Content, "mail1.example.com") {
			found1 = true
		}
		if strings.Contains(rec.Content, "mail3.example.com") {
			found2 = true
		}
	}
	if !found1 {
		t.Errorf("original record mail1 not preserved in PATCH body")
	}
	if !found2 {
		t.Errorf("updated record mail3 not found in PATCH body")
	}
}

func TestUpdateRecord_PreservesSiblingRecords(t *testing.T) {
	var patchedRRSet []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{
					{
						Name: "example.com.",
						Type: "MX",
						TTL:  3600,
						Records: []models.RecordInfo{
							{Content: "10 mx1.example.com.", Priority: 0, Disabled: false},
							{Content: "20 mx2.example.com.", Priority: 0, Disabled: false},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.Unmarshal(body, &payload)
			patchedRRSet = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=example.com&type=MX&content=mx3.example.com&ttl=3600&priority=30&original_content=mx2.example.com.&original_priority=20"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.UpdateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect 303, got %d: %s", w.Code, w.Body.String())
	}

	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}

	records := patchedRRSet[0].Records
	if len(records) != 2 {
		t.Fatalf("expected 2 records preserved, got %d", len(records))
	}

	found1, found2 := false, false
	for _, rec := range records {
		if strings.Contains(rec.Content, "mx1.example.com") {
			found1 = true
		}
		if strings.Contains(rec.Content, "mx3.example.com") {
			found2 = true
		}
	}
	if !found1 {
		t.Errorf("original record mx1 not preserved in PATCH body")
	}
	if !found2 {
		t.Errorf("updated record mx3 not found in PATCH body")
	}
}

func TestBatchCreateRecords_Success(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{},
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www&type=A&content=10.0.0.1&name=mail&type=A&content=10.0.0.2"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_record'").Scan(&count)
	if count != 2 {
		t.Errorf("expected 2 activity logs, got %d", count)
	}

	var emptyNew int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_record' AND new_value = ''").Scan(&emptyNew)
	if emptyNew != 0 {
		t.Errorf("expected 0 logs with empty new_value, got %d", emptyNew)
	}
}

func TestBatchCreateRecords_MX(t *testing.T) {
	type patchBody struct {
		RRSets []models.RRSet `json:"rrsets"`
	}
	var body patchBody

	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{},
			})
			return
		}
		if r.Method == "PATCH" {
			json.NewDecoder(r.Body).Decode(&body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	formBody := "name=mail&type=MX&content=mail.example.com.&priority=10&ttl=600"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(formBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d: %s", w.Code, w.Body.String())
	}

	if len(body.RRSets) != 1 {
		t.Fatalf("expected 1 rrset, got %d", len(body.RRSets))
	}
	rs := body.RRSets[0]
	if rs.Name != "mail.example.com." || rs.Type != "MX" {
		t.Errorf("unexpected rrset: name=%s type=%s", rs.Name, rs.Type)
	}
	if rs.TTL != 600 {
		t.Errorf("expected TTL 600, got %d", rs.TTL)
	}
	if len(rs.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rs.Records))
	}
	if rs.Records[0].Content != "10 mail.example.com." {
		t.Errorf("expected content '10 mail.example.com.', got %q", rs.Records[0].Content)
	}
	if rs.Records[0].Priority != 0 {
		t.Errorf("expected priority 0 (omitted), got %d", rs.Records[0].Priority)
	}
}

func TestBatchCreateRecords_SRV(t *testing.T) {
	type patchBody struct {
		RRSets []models.RRSet `json:"rrsets"`
	}
	var body patchBody

	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{},
			})
			return
		}
		if r.Method == "PATCH" {
			json.NewDecoder(r.Body).Decode(&body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	formBody := "name=_sip._tcp&type=SRV&content=5 5060 sip.example.com.&priority=10&ttl=3600"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(formBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303 redirect, got %d: %s", w.Code, w.Body.String())
	}

	if len(body.RRSets) != 1 {
		t.Fatalf("expected 1 rrset, got %d (%+v)", len(body.RRSets), body)
	}
	rs := body.RRSets[0]
	if rs.Type != "SRV" {
		t.Errorf("expected SRV, got %s", rs.Type)
	}
	if len(rs.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(rs.Records))
	}
	if rs.Records[0].Content != "10 5 5060 sip.example.com." {
		t.Errorf("expected content '10 5 5060 sip.example.com.', got %q", rs.Records[0].Content)
	}
	if rs.Records[0].Priority != 0 {
		t.Errorf("expected priority 0 (omitted), got %d", rs.Records[0].Priority)
	}
}

func TestCreateRecord_MergesWithExistingRRSet(t *testing.T) {
	var patchedRRSet []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{
					{
						Name: "example.com.",
						Type: "MX",
						TTL:  300,
						Records: []models.RecordInfo{
							{Content: "10 smtp.example.com.", Priority: 0, Disabled: false},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.Unmarshal(body, &payload)
			patchedRRSet = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=example.com&type=MX&content=smtp.example.com.&ttl=300&priority=50"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.CreateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", w.Code, w.Body.String())
	}

	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}

	records := patchedRRSet[0].Records
	if len(records) != 2 {
		t.Fatalf("expected 2 records (original + new), got %d", len(records))
	}

	found10, found50 := false, false
	for _, rec := range records {
		if strings.Contains(rec.Content, "10 smtp.example.com") {
			found10 = true
		}
		if strings.Contains(rec.Content, "50 smtp.example.com") {
			found50 = true
		}
	}
	if !found10 {
		t.Error("original MX 10 record not preserved")
	}
	if !found50 {
		t.Error("new MX 50 record not found in PATCH body")
	}
}

func TestBatchCreateRecords_MergesWithExistingRRSet(t *testing.T) {
	var patchedRRSet []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{
					{
						Name: "example.com.",
						Type: "MX",
						TTL:  300,
						Records: []models.RecordInfo{
							{Content: "10 smtp.example.com.", Priority: 0, Disabled: false},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.Unmarshal(body, &payload)
			patchedRRSet = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=example.com&type=MX&content=smtp.example.com.&priority=50&ttl=300"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", w.Code, w.Body.String())
	}

	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}

	records := patchedRRSet[0].Records
	if len(records) != 2 {
		t.Fatalf("expected 2 records (original + new), got %d", len(records))
	}

	found10, found50 := false, false
	for _, rec := range records {
		if strings.Contains(rec.Content, "10 smtp.example.com") {
			found10 = true
		}
		if strings.Contains(rec.Content, "50 smtp.example.com") {
			found50 = true
		}
	}
	if !found10 {
		t.Error("original MX 10 record not preserved")
	}
	if !found50 {
		t.Error("new MX 50 record not found in PATCH body")
	}
}

func TestBatchCreateRecords_PDNSError_NoLogs(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www&type=A&content=10.0.0.1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_record'").Scan(&count)
	if count != 0 {
		t.Errorf("expected 0 activity logs on PDNS error, got %d", count)
	}
}

func TestBatchCreateRecords_LuaUpdatesDisabled(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"rrsets":[]}`))
			return
		}
		if r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"Undefined but needed argument: 'enable-lua-record-updates'"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=localhosr&type=A&content=127.0.0.1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for LUA update disabled, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "enable-lua-record-updates") {
		t.Errorf("expected user-facing message with enable-lua-record-updates, got %s", w.Body.String())
	}
}

func TestBatchCreateRecords_EmptyRecords(t *testing.T) {
	h := newTestHandler(t)

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "At least one record is required") {
		t.Error("expected error message")
	}
}

func TestBatchCreateRecords_MismatchedArrays(t *testing.T) {
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{},
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	// Two "name" values but a single "type"/"content": the parallel arrays are
	// unbalanced. This used to index types[1]/contents[1] out of range and panic.
	body := "name=www&name=mail&type=A&content=10.0.0.1"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d (%s)", w.Code, w.Body.String())
	}
	// Only the first index is complete, so exactly one record is created.
	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_record'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log, got %d", count)
	}
}

func TestPrepareRecordContent(t *testing.T) {
	tests := []struct {
		name          string
		recordType    string
		content       string
		priority      int
		wantContent   string
		wantRecordPri int
	}{
		// MX: priority embedding, no existing prefix (form: 1 token)
		{"MX_new", "MX", "mail.example.com.", 10, "10 mail.example.com.", 0},
		// MX: strip existing priority prefix from PDNS then re-embed (2 tokens)
		{"MX_update", "MX", "10 mail.example.com.", 20, "20 mail.example.com.", 0},
		// MX: priority=0
		{"MX_zero", "MX", "mail.example.com.", 0, "0 mail.example.com.", 0},
		// SRV: new form record (3 tokens: weight port target) — do NOT strip weight
		{"SRV_new", "SRV", "5 5060 sip.example.com.", 10, "10 5 5060 sip.example.com.", 0},
		// SRV: update from PDNS (4 tokens: priority weight port target) — strip old priority
		{"SRV_update", "SRV", "10 5 5060 sip.example.com.", 5, "5 5 5060 sip.example.com.", 0},
		// Non-MX/SRV: pass through unchanged
		{"A", "A", "192.0.2.1", 0, "192.0.2.1", 0},
		{"CNAME", "CNAME", "target.example.com.", 0, "target.example.com.", 0},
		// TXT: already quoted — pass through unchanged
		{"TXT_quoted", "TXT", "\"v=spf1 -all\"", 0, "\"v=spf1 -all\"", 0},
		// TXT: unquoted — add surrounding quotes
		{"TXT_unquoted", "TXT", "v=spf1 -all", 0, "\"v=spf1 -all\"", 0},
		// SPF: unquoted — add surrounding quotes
		{"SPF_unquoted", "SPF", "v=spf1 -all", 0, "\"v=spf1 -all\"", 0},
		// SPF: already quoted — pass through
		{"SPF_quoted", "SPF", "\"v=spf1 -all\"", 0, "\"v=spf1 -all\"", 0},
		// TXT: empty — no quoting
		{"TXT_empty", "TXT", "", 0, "", 0},
		{"NS", "NS", "ns1.example.com.", 0, "ns1.example.com.", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotContent, gotPrio := prepareRecordContent(tt.recordType, tt.content, tt.priority)
			if gotContent != tt.wantContent {
				t.Errorf("content = %q, want %q", gotContent, tt.wantContent)
			}
			if gotPrio != tt.wantRecordPri {
				t.Errorf("recordInfo priority = %d, want %d", gotPrio, tt.wantRecordPri)
			}
		})
	}
}

func TestNormalizeRecordName(t *testing.T) {
	zone := "example.com."
	tests := []struct {
		name, zoneName, want string
	}{
		{"www", zone, "www.example.com."},
		{"@", zone, "example.com."},
		{"", zone, "example.com."},
		{"example.com.", zone, "example.com."},
		{"example.com", zone, "example.com."},
		{"EXAMPLE.COM.", zone, "example.com."},
		{"www.example.com.", zone, "www.example.com."},
		{"www.example.com", zone, "www.example.com."},
		{"mail.example.com.", zone, "mail.example.com."},
		{"other.com.", zone, "other.com."},
		{"other.com", zone, "other.com.example.com."},
		{"localhost", zone, "localhost.example.com."},
		{"WWW.Example.com", zone, "www.example.com."},
		{"WWW", zone, "www.example.com."},
		{"Example.Com", "EXAMPLE.COM.", "example.com."},
	}

	for _, tc := range tests {
		result := normalizeRecordName(tc.name, tc.zoneName)
		if result != tc.want {
			t.Errorf("normalizeRecordName(%q, %q) = %q, want %q", tc.name, tc.zoneName, result, tc.want)
		}
	}
}

func TestParseComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []models.Comment
	}{
		{"empty", "", nil},
		{"whitespace_only", "   \n   \n", nil},
		{"single_line", "managed by ops", []models.Comment{{Content: "managed by ops"}}},
		{"multi_line", "first\nsecond\nthird", []models.Comment{{Content: "first"}, {Content: "second"}, {Content: "third"}}},
		{"trims_whitespace", "  hello  \n  world  ", []models.Comment{{Content: "hello"}, {Content: "world"}}},
		{"skips_blank_lines", "first\n\n   \nsecond\n", []models.Comment{{Content: "first"}, {Content: "second"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseComments(tc.input)
			if len(got) != len(tc.want) {
				t.Fatalf("parseComments(%q) returned %d comments, want %d: %+v", tc.input, len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Content != tc.want[i].Content {
					t.Errorf("comment[%d] = %q, want %q", i, got[i].Content, tc.want[i].Content)
				}
			}
		})
	}
}

func TestBuildCommentsFromLines(t *testing.T) {
	tests := []struct {
		name     string
		existing []models.Comment
		newLines []string
		want     []models.Comment
	}{
		{
			name:     "no_existing_no_new",
			existing: nil,
			newLines: nil,
			want:     nil,
		},
		{
			name:     "no_existing_with_new",
			existing: nil,
			newLines: []string{"first"},
			want:     []models.Comment{{Content: "first"}},
		},
		{
			name:     "existing_preserved_when_no_new",
			existing: []models.Comment{{Content: "old"}},
			newLines: nil,
			want:     nil,
		},
		{
			name:     "existing_appended_with_new",
			existing: []models.Comment{{Content: "old"}},
			newLines: []string{"new"},
			want:     []models.Comment{{Content: "old"}, {Content: "new"}},
		},
		{
			name:     "multiple_new_lines",
			existing: []models.Comment{{Content: "old"}},
			newLines: []string{"new1", "new2"},
			want:     []models.Comment{{Content: "old"}, {Content: "new1"}, {Content: "new2"}},
		},
		{
			name:     "blank_new_lines_skipped",
			existing: []models.Comment{{Content: "old"}},
			newLines: []string{"", "  ", "new"},
			want:     []models.Comment{{Content: "old"}, {Content: "new"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildCommentsFromLines(tc.existing, tc.newLines...)
			if len(got) != len(tc.want) {
				t.Fatalf("returned %d comments, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Content != tc.want[i].Content {
					t.Errorf("comment[%d] = %q, want %q", i, got[i].Content, tc.want[i].Content)
				}
			}
		})
	}
}

func TestCreateRecord_SendsComment(t *testing.T) {
	var patchedRRSet []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"})
			return
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.Unmarshal(body, &payload)
			patchedRRSet = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www&type=A&content=1.2.3.4&ttl=300&comment=managed+by+ops"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./records/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com.")
	r = r.WithContext(ctx)
	h.CreateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", w.Code, w.Body.String())
	}

	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}
	comments := patchedRRSet[0].Comments
	if len(comments) != 1 || comments[0].Content != "managed by ops" {
		t.Errorf("expected one comment 'managed by ops', got %+v", comments)
	}
}

func TestCreateRecord_NoComment_OmitsField(t *testing.T) {
	var patchedRRSet []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"})
			return
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var payload map[string]json.RawMessage
			json.Unmarshal(body, &payload)
			json.Unmarshal(payload["rrsets"], &patchedRRSet)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www&type=A&content=1.2.3.4&ttl=300"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./records/create", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com.")
	r = r.WithContext(ctx)
	h.CreateRecord(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", w.Code)
	}

	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}
	if len(patchedRRSet[0].Comments) != 0 {
		t.Errorf("expected no comments in PATCH body, got %+v", patchedRRSet[0].Comments)
	}
}

func TestInlineUpdateRecord_AppendsComment(t *testing.T) {
	var patchedRRSet []models.RRSet
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{
					{
						Name: "www.example.com.",
						Type: "A",
						TTL:  300,
						Records: []models.RecordInfo{
							{Content: "10.0.0.1", Disabled: false},
						},
						Comments: []models.Comment{{Content: "existing comment"}},
					},
				},
			})
			return
		}
		if r.Method == http.MethodPatch {
			body, _ := io.ReadAll(r.Body)
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.Unmarshal(body, &payload)
			patchedRRSet = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com.&type=A&content=10.0.0.2&ttl=300&priority=0&disabled=false&original_content=10.0.0.1&original_priority=0&comment=existing+comment%0Anew+comment"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./records/inline-update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com.")
	r = r.WithContext(ctx)
	h.InlineUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}
	comments := patchedRRSet[0].Comments
	if len(comments) != 2 {
		t.Fatalf("expected 2 comments (existing + new), got %d: %+v", len(comments), comments)
	}
	if comments[0].Content != "existing comment" {
		t.Errorf("first comment = %q, want existing comment", comments[0].Content)
	}
	if comments[1].Content != "new comment" {
		t.Errorf("second comment = %q, want new comment", comments[1].Content)
	}
}

func TestInlineUpdateRecord_NoComment_PreservesExisting(t *testing.T) {
	var patchedRRSet []models.RRSet
	var rawBody []byte
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{
					{
						Name: "www.example.com.",
						Type: "A",
						TTL:  300,
						Records: []models.RecordInfo{
							{Content: "10.0.0.1", Disabled: false},
						},
						Comments: []models.Comment{{Content: "existing comment"}},
					},
				},
			})
			return
		}
		if r.Method == http.MethodPatch {
			rawBody, _ = io.ReadAll(r.Body)
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.Unmarshal(rawBody, &payload)
			patchedRRSet = payload.RRSets
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	body := "name=www.example.com.&type=A&content=10.0.0.2&ttl=300&priority=0&disabled=false&original_content=10.0.0.1&original_priority=0"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./records/inline-update", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com.")
	r = r.WithContext(ctx)
	h.InlineUpdateRecord(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// The PATCH body must NOT contain a `comments` key so that PowerDNS keeps
	// the existing comments untouched.
	if strings.Contains(string(rawBody), `"comments"`) {
		t.Errorf("PATCH body should not contain 'comments' key when no new comment is provided, got: %s", rawBody)
	}
	if len(patchedRRSet) != 1 {
		t.Fatalf("expected 1 patched RRSet, got %d", len(patchedRRSet))
	}
	if len(patchedRRSet[0].Comments) != 0 {
		t.Errorf("expected empty Comments slice in unmarshalled RRSet, got %+v", patchedRRSet[0].Comments)
	}
}

func TestBatchCreateRecords_SendsCommentsPerRow(t *testing.T) {
	type patchBody struct {
		RRSets []models.RRSet `json:"rrsets"`
	}
	var body patchBody

	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone:   models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{},
			})
			return
		}
		if r.Method == "PATCH" {
			json.NewDecoder(r.Body).Decode(&body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	formBody := "name=www&type=A&content=10.0.0.1&comment=first+row&name=mail&type=A&content=10.0.0.2&comment=second+row"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(formBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", w.Code, w.Body.String())
	}

	if len(body.RRSets) != 2 {
		t.Fatalf("expected 2 rrsets, got %d", len(body.RRSets))
	}

	gotComments := make(map[string]string)
	for _, rr := range body.RRSets {
		if len(rr.Comments) == 1 {
			gotComments[rr.Name+" "+rr.Type] = rr.Comments[0].Content
		}
	}
	if gotComments["www.example.com. A"] != "first row" {
		t.Errorf("expected 'first row' comment for www, got %q", gotComments["www.example.com. A"])
	}
	if gotComments["mail.example.com. A"] != "second row" {
		t.Errorf("expected 'second row' comment for mail, got %q", gotComments["mail.example.com. A"])
	}
}

func TestBatchCreateRecords_PreservesExistingComments(t *testing.T) {
	type patchBody struct {
		RRSets []models.RRSet `json:"rrsets"`
	}
	var body patchBody

	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/") {
			json.NewEncoder(w).Encode(struct {
				models.Zone
				RRSets []models.RRSet `json:"rrsets"`
			}{
				Zone: models.Zone{ID: "example.com", Name: "example.com", Kind: "Native"},
				RRSets: []models.RRSet{
					{
						Name: "www.example.com.",
						Type: "A",
						TTL:  300,
						Records: []models.RecordInfo{
							{Content: "10.0.0.1", Disabled: false},
						},
						Comments: []models.Comment{{Content: "existing"}},
					},
				},
			})
			return
		}
		if r.Method == "PATCH" {
			json.NewDecoder(r.Body).Decode(&body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	ctx := context.WithValue(context.Background(), middleware.UserContextKey, user)

	formBody := "name=www.example.com.&type=A&content=10.0.0.2&ttl=300&comment=new"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/batch-create", strings.NewReader(formBody))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("zone_id", "example.com")
	r = r.WithContext(ctx)
	h.BatchCreateRecords(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", w.Code, w.Body.String())
	}

	if len(body.RRSets) != 1 {
		t.Fatalf("expected 1 rrset (merged), got %d", len(body.RRSets))
	}
	comments := body.RRSets[0].Comments
	if len(comments) != 2 {
		t.Fatalf("expected 2 comments (existing + new), got %d: %+v", len(comments), comments)
	}
	if comments[0].Content != "existing" {
		t.Errorf("first comment = %q, want 'existing'", comments[0].Content)
	}
	if comments[1].Content != "new" {
		t.Errorf("second comment = %q, want 'new'", comments[1].Content)
	}
}
