package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// pdnsZonesJSONHandler serves a PowerDNS zone list containing exactly the
// given zone IDs.
func pdnsZonesJSONHandler(zoneIDs ...string) testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := "["
		for i, id := range zoneIDs {
			if i > 0 {
				body += ","
			}
			body += `{"id":"` + id + `","name":"` + id + `","kind":"Native","url":"/api/v1/servers/localhost/zones/` + url.PathEscape(id) + `"}`
		}
		body += "]"
		w.Write([]byte(body))
	}
}

// seedGroupZoneGrant attaches a zone grant to a group.
func seedGroupZoneGrant(t *testing.T, h *Handler, groupID int64, zoneID string) {
	t.Helper()
	if _, err := h.DB.InsertIgnore(context.Background(), "zone_group_zones",
		[]string{"group_id", "zone_id"},
		[]string{"group_id", "zone_id"},
		groupID, zoneID,
	); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

func groupZoneGrantCount(t *testing.T, h *Handler, zoneID string) int {
	t.Helper()
	var n int
	if err := h.DB.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM zone_group_zones WHERE zone_id = ?", zoneID,
	).Scan(&n); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	return n
}

func TestReconcileGroupZones_RemovesOrphanedGrants(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsZonesJSONHandler("example.com.", "other.example."))
	defer srv.Close()

	gid := seedGroup(t, h, "ops", "")
	seedGroupZoneGrant(t, h, gid, "example.com.")
	seedGroupZoneGrant(t, h, gid, "other.example.")
	seedGroupZoneGrant(t, h, gid, "deleted.example.") // gone from PowerDNS

	deleted, err := h.ReconcileGroupZones(context.Background())
	if err != nil {
		t.Fatalf("ReconcileGroupZones: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 orphaned grant deleted, got %d", deleted)
	}
	if n := groupZoneGrantCount(t, h, "example.com."); n != 1 {
		t.Errorf("grant for an existing zone must survive, got %d rows", n)
	}
	if n := groupZoneGrantCount(t, h, "other.example."); n != 1 {
		t.Errorf("grant for an existing zone must survive, got %d rows", n)
	}
	if n := groupZoneGrantCount(t, h, "deleted.example."); n != 0 {
		t.Errorf("orphaned grant must be deleted, got %d rows", n)
	}

	// A second pass is a no-op.
	if deleted, err := h.ReconcileGroupZones(context.Background()); err != nil || deleted != 0 {
		t.Errorf("second reconciliation: deleted=%d err=%v, want 0/nil", deleted, err)
	}
}

func TestReconcileGroupZones_PDNSUnreachableKeepsGrants(t *testing.T) {
	// nil handler = 500 on every request: an unreachable PowerDNS must never
	// be interpreted as "all zones gone".
	h, srv := newTestHandlerWithPDNS(t, nil)
	defer srv.Close()

	gid := seedGroup(t, h, "ops", "")
	seedGroupZoneGrant(t, h, gid, "example.com.")

	if _, err := h.ReconcileGroupZones(context.Background()); err == nil {
		t.Fatal("expected an error when the zone list cannot be fetched")
	}
	if n := groupZoneGrantCount(t, h, "example.com."); n != 1 {
		t.Errorf("grants must be untouched when PowerDNS is unreachable, got %d rows", n)
	}
}

func TestReconcileGroupZones_NoGrantsIsNoop(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsZonesJSONHandler("example.com."))
	defer srv.Close()

	deleted, err := h.ReconcileGroupZones(context.Background())
	if err != nil {
		t.Fatalf("ReconcileGroupZones: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deletions with no grants, got %d", deleted)
	}
}

func TestEditGroupPage_ReconcilesOnView(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, pdnsZonesJSONHandler("example.com."))
	defer srv.Close()

	gid := seedGroup(t, h, "ops", "")
	seedGroupZoneGrant(t, h, gid, "example.com.")
	seedGroupZoneGrant(t, h, gid, "stale.example.")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/groups/"+strconv.FormatInt(gid, 10)+"/edit", nil)
	r.SetPathValue("group_id", strconv.FormatInt(gid, 10))
	r = withUserContext(r, user)
	h.EditGroupPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if n := groupZoneGrantCount(t, h, "stale.example."); n != 0 {
		t.Errorf("viewing the group edit page must drop orphaned grants, got %d rows", n)
	}
	if n := groupZoneGrantCount(t, h, "example.com."); n != 1 {
		t.Errorf("grant for an existing zone must survive, got %d rows", n)
	}
}

func TestEditGroupPage_PDNSUnreachableKeepsGrants(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, nil) // 500 on every request
	defer srv.Close()

	gid := seedGroup(t, h, "ops", "")
	seedGroupZoneGrant(t, h, gid, "example.com.")

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/groups/"+strconv.FormatInt(gid, 10)+"/edit", nil)
	r.SetPathValue("group_id", strconv.FormatInt(gid, 10))
	r = withUserContext(r, user)
	h.EditGroupPage(w, r)

	if n := groupZoneGrantCount(t, h, "example.com."); n != 1 {
		t.Errorf("grants must be untouched when PowerDNS is unreachable, got %d rows", n)
	}
}
