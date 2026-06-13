package pdns

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/babykart/gozone/internal/models"
)

func newCachedClient(t *testing.T, handler http.HandlerFunc) ZoneService {
	t.Helper()
	client, _ := newTestClient(t, handler)
	return NewCachedClient(client)
}

func TestCachedListZones_Hit(t *testing.T) {
	var calls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":"z1.","name":"z1.","kind":"Native","serial":0}]`))
	})

	ctx := context.Background()
	zones1, err := cached.ListZones(ctx)
	if err != nil {
		t.Fatalf("first ListZones: %v", err)
	}
	zones2, err := cached.ListZones(ctx)
	if err != nil {
		t.Fatalf("second ListZones: %v", err)
	}

	if len(zones1) != 1 || zones1[0].ID != "z1." {
		t.Error("unexpected zone list")
	}
	if len(zones2) != 1 {
		t.Error("unexpected cached zone list")
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 API call (second should hit cache), got %d", calls.Load())
	}
}

func TestCachedListZonesWithInfo_Hit(t *testing.T) {
	var calls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":"z1.","name":"z1.","kind":"Native","serial":0}]`))
	})

	ctx := context.Background()
	cached.ListZonesWithInfo(ctx)
	cached.ListZonesWithInfo(ctx)

	if calls.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", calls.Load())
	}
}

func TestCachedGetStatistics_Hit(t *testing.T) {
	var calls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"uptime","type":"StatisticItem","value":"3600"}]`))
	})

	ctx := context.Background()
	cached.GetStatistics(ctx)
	cached.GetStatistics(ctx)

	if calls.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", calls.Load())
	}
}

func TestCachedGetServer_Hit(t *testing.T) {
	var calls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"localhost","type":"Server","version":"4.9.0"}`))
	})

	ctx := context.Background()
	cached.GetServer(ctx)
	cached.GetServer(ctx)

	if calls.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", calls.Load())
	}
}

func TestCachedListTSIGKeys_Hit(t *testing.T) {
	var calls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"my-key.","algorithm":"hmac-sha256","type":"TSIGKey"}]`))
	})

	ctx := context.Background()
	cached.ListTSIGKeys(ctx)
	cached.ListTSIGKeys(ctx)

	if calls.Load() != 1 {
		t.Errorf("expected 1 API call, got %d", calls.Load())
	}
}

func TestCachedCreateZone_InvalidatesCache(t *testing.T) {
	var listCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones") {
			listCalls.Add(1)
			w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/zones") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"id":"new.","name":"new.","kind":"Native","serial":0}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctx := context.Background()

	cached.ListZones(ctx)
	cached.ListZonesWithInfo(ctx)
	if listCalls.Load() != 2 {
		t.Fatalf("expected 2 list calls to populate caches, got %d", listCalls.Load())
	}

	_, err := cached.CreateZone(ctx, models.ZoneCreateRequest{Name: "new."})
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}

	cached.ListZones(ctx)
	cached.ListZonesWithInfo(ctx)
	if listCalls.Load() != 4 {
		t.Errorf("expected 4 list calls after invalidation, got %d", listCalls.Load())
	}
}

func TestCachedDeleteZone_InvalidatesCache(t *testing.T) {
	var statCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "statistics") {
			statCalls.Add(1)
			w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/zones/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctx := context.Background()

	cached.GetStatistics(ctx)
	if statCalls.Load() != 1 {
		t.Fatalf("expected 1 stat call to populate cache, got %d", statCalls.Load())
	}

	if err := cached.DeleteZone(ctx, "test."); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	cached.GetStatistics(ctx)
	if statCalls.Load() != 2 {
		t.Errorf("expected 2 stat calls after invalidation, got %d", statCalls.Load())
	}
}

func TestCachedTSIGKey_InvalidatesCache(t *testing.T) {
	var listCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "tsigkeys") {
			listCalls.Add(1)
			w.Write([]byte(`[]`))
			return
		}
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "tsigkeys") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"name":"hk.","algorithm":"hmac-sha256","type":"TSIGKey"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctx := context.Background()

	cached.ListTSIGKeys(ctx)
	if listCalls.Load() != 1 {
		t.Fatalf("expected 1 TSIG list call to populate cache, got %d", listCalls.Load())
	}

	_, err := cached.CreateTSIGKey(ctx, models.TSIGKey{Name: "hk.", Algorithm: "hmac-sha256"})
	if err != nil {
		t.Fatalf("CreateTSIGKey: %v", err)
	}

	cached.ListTSIGKeys(ctx)
	if listCalls.Load() != 2 {
		t.Errorf("expected 2 TSIG list calls after invalidation, got %d", listCalls.Load())
	}
}

func TestCachedClientImplementsZoneService(t *testing.T) {
	var c ZoneService
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	c = NewCachedClient(client)
	if c.ServerID() != "localhost" {
		t.Errorf("unexpected server ID: %q", c.ServerID())
	}
}

func TestCached_UncachedPassthrough(t *testing.T) {
	var recordCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPatch {
			recordCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones/test.") && !strings.Contains(r.URL.RawQuery, "rrsets") {
			w.Write([]byte(`{"id":"test.","name":"test.","kind":"Native","serial":0}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})

	ctx := context.Background()

	cached.GetZone(ctx, "test.")
	cached.CreateRecord(ctx, "test.", models.RRSet{Name: "www.test.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "1.2.3.4"}}})
	if recordCalls.Load() != 1 {
		t.Errorf("expected 1 record create call, got %d", recordCalls.Load())
	}
}

func TestCachedInvalidateZoneCache(t *testing.T) {
	var listCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones") {
			listCalls.Add(1)
			w.Write([]byte(`[{"id":"z1.","name":"z1.","kind":"Native","serial":0}]`))
			return
		}
		w.Write([]byte(`[]`))
	})

	ctx := context.Background()

	// Populate caches
	cached.ListZones(ctx)
	cached.ListZonesWithInfo(ctx)
	if listCalls.Load() != 2 {
		t.Fatalf("expected 2 list calls to populate caches, got %d", listCalls.Load())
	}

	// Verify cache hit — no new call
	cached.ListZones(ctx)
	if listCalls.Load() != 2 {
		t.Errorf("expected cache hit, got %d calls", listCalls.Load())
	}

	// Invalidate and verify next reads are fresh
	cached.InvalidateZoneCache(ctx, "z1.")
	cached.ListZones(ctx)
	cached.ListZonesWithInfo(ctx)
	if listCalls.Load() != 4 {
		t.Errorf("expected 4 list calls after invalidation, got %d", listCalls.Load())
	}
}

func TestCachedRecordMutations_InvalidateZonesAndStats(t *testing.T) {
	var listCalls, statCalls, patchCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones"):
			listCalls.Add(1)
			w.Write([]byte(`[{"id":"test.","name":"test.","kind":"Native","serial":0}]`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "statistics"):
			statCalls.Add(1)
			w.Write([]byte(`[]`))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/test."):
			patchCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	ctx := context.Background()

	// Populate caches
	cached.ListZones(ctx)
	cached.ListZonesWithInfo(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 2 || statCalls.Load() != 1 {
		t.Fatalf("expected 2 list + 1 stat calls to populate caches, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// CreateRecord should invalidate zone list/info and stats caches
	if err := cached.CreateRecord(ctx, "test.", models.RRSet{Name: "www.test.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "1.2.3.4"}}}); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	cached.ListZones(ctx)
	cached.ListZonesWithInfo(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 4 || statCalls.Load() != 2 {
		t.Errorf("after CreateRecord expected list=4 stat=2, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// UpdateRecord should invalidate caches again
	if err := cached.UpdateRecord(ctx, "test.", models.RRSet{Name: "www.test.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "1.2.3.5"}}}); err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 5 || statCalls.Load() != 3 {
		t.Errorf("after UpdateRecord expected list=5 stat=3, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// DeleteRecord should invalidate caches again
	if err := cached.DeleteRecord(ctx, "test.", "www.test.", "A"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 6 || statCalls.Load() != 4 {
		t.Errorf("after DeleteRecord expected list=6 stat=4, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// CreateRecords should invalidate caches again
	if err := cached.CreateRecords(ctx, "test.", []models.RRSet{
		{Name: "www.test.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "1.2.3.4"}}},
	}); err != nil {
		t.Fatalf("CreateRecords: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 7 || statCalls.Load() != 5 {
		t.Errorf("after CreateRecords expected list=7 stat=5, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	if patchCalls.Load() != 4 {
		t.Errorf("expected 4 PATCH calls, got %d", patchCalls.Load())
	}
}

func TestCachedRecordMutation_ErrorDoesNotInvalidateCache(t *testing.T) {
	var listCalls, patchCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones"):
			listCalls.Add(1)
			w.Write([]byte(`[{"id":"test.","name":"test.","kind":"Native","serial":0}]`))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/zones/test."):
			patchCalls.Add(1)
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"error":"invalid record"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	ctx := context.Background()
	cached.ListZones(ctx)
	if listCalls.Load() != 1 {
		t.Fatalf("expected 1 list call, got %d", listCalls.Load())
	}

	err := cached.CreateRecord(ctx, "test.", models.RRSet{Name: "www.test.", Type: "A", TTL: 3600, Records: []models.RecordInfo{{Content: "bad"}}})
	if err == nil {
		t.Fatal("expected CreateRecord to fail")
	}

	cached.ListZones(ctx)
	if listCalls.Load() != 1 {
		t.Errorf("cache should not be invalidated on error, got %d list calls", listCalls.Load())
	}
}
