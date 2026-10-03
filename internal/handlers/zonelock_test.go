package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// TestZoneLocks_ExclusivePerZone verifies the locker's core contract: the
// critical section for one zone never runs concurrently with itself, while
// different zones hold independent mutexes.
func TestZoneLocks_ExclusivePerZone(t *testing.T) {
	var z zoneLocks

	var inside int32
	var violations int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				release := z.Lock("example.com.")
				if n := atomic.AddInt32(&inside, 1); n > 1 {
					atomic.AddInt32(&violations, 1)
				}
				time.Sleep(50 * time.Microsecond) // widen the window
				atomic.AddInt32(&inside, -1)
				release()
			}
		}()
	}
	wg.Wait()
	if violations > 0 {
		t.Errorf("critical section entered concurrently %d times for the same zone", violations)
	}

	// Independent zones: distinct mutexes, both usable right away.
	releaseA := z.Lock("a.example.")
	releaseB := z.Lock("b.example.")
	releaseA()
	releaseB()
}

// TestCreateRecord_ConcurrentSameZoneSerialized is the lost-update
// regression: two concurrent CreateRecord calls on the same RRSet used to
// interleave their fetches, and the second PATCH silently dropped the first
// record. The per-zone lock serializes the fetch→merge→PATCH sequences, so
// both records must survive. The mock PDNS keeps in-memory zone state and
// delays the fetch slightly to widen the interleave window that the lock
// closes.
func TestCreateRecord_ConcurrentSameZoneSerialized(t *testing.T) {
	var (
		mu     sync.Mutex
		rrsets = map[string][]models.RecordInfo{}
	)
	h, pdnsSrv := newTestHandlerWithPDNS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			// Widen the race window: without the zone lock, both concurrent
			// requests read the pre-mutation state here.
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
			out := make([]models.RRSet, 0, len(rrsets))
			for key, records := range rrsets {
				parts := strings.SplitN(key, "|", 2)
				out = append(out, models.RRSet{Name: parts[0], Type: parts[1], TTL: 3600, Records: records})
			}
			mu.Unlock()
			json.NewEncoder(w).Encode(struct {
				RRSets []models.RRSet `json:"rrsets"`
			}{RRSets: out}) // #nosec G104 -- test helper
			return
		}
		if r.Method == http.MethodPatch {
			var payload struct {
				RRSets []models.RRSet `json:"rrsets"`
			}
			json.NewDecoder(r.Body).Decode(&payload) // #nosec G104 -- test helper
			mu.Lock()
			for _, rr := range payload.RRSets {
				rrsets[rr.Name+"|"+rr.Type] = rr.Records
			}
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	defer pdnsSrv.Close()

	testutil.SeedTestUser(t, h.DB, "admin", "admin", "admin", true)
	ctx := context.WithValue(context.Background(), middleware.UserContextKey,
		&models.User{ID: 1, Username: "admin", Role: "admin"})

	post := func(content string) {
		body := "name=www&type=A&content=" + content + "&ttl=3600"
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/zones/example.com/records/create", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("zone_id", "example.com")
		h.CreateRecord(w, req.WithContext(ctx))
		if w.Code != http.StatusSeeOther {
			t.Errorf("create %s: expected 303, got %d (%s)", content, w.Code, w.Body.String())
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); post("192.0.2.1") }()
	go func() { defer wg.Done(); post("192.0.2.2") }()
	wg.Wait()

	mu.Lock()
	got := rrsets["www.example.com.|A"]
	mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("both concurrent records must survive, got %d: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, rec := range got {
		seen[rec.Content] = true
	}
	if !seen["192.0.2.1"] || !seen["192.0.2.2"] {
		t.Errorf("records were lost or corrupted, got %+v", got)
	}
}
