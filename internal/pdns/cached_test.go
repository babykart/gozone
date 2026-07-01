package pdns

import (
	"context"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestCachedClient_Close_StopsSweepGoroutines(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	})
	cached := NewCachedClient(client)

	before := runtime.NumGoroutine()
	cached.Close()

	// Wait briefly for goroutines to exit.
	time.Sleep(50 * time.Millisecond)

	after := runtime.NumGoroutine()
	if after >= before {
		t.Errorf("expected goroutine count to decrease after Close, got before=%d after=%d", before, after)
	}
}

func TestCachedHealthCheck_BypassesCache(t *testing.T) {
	var calls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		isServerInfo := r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/servers/localhost") && !strings.Contains(r.URL.Path, "/statistics")
		if !isServerInfo {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		calls.Add(1)
		if calls.Load() == 1 {
			w.Write([]byte(`{"server_id":"localhost","daemon_type":"authoritative","version":"4.8.0"}`))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"powerdns down"}`))
	})

	ctx := context.Background()

	// First call populates the 5-minute server cache
	info, err := cached.GetServer(ctx)
	if err != nil {
		t.Fatalf("first GetServer: %v", err)
	}
	if info.Version != "4.8.0" {
		t.Errorf("unexpected version: %q", info.Version)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected 1 API call, got %d", calls.Load())
	}

	// HealthCheck must bypass the cache and see the current failure
	err = cached.HealthCheck(ctx)
	if err == nil {
		t.Fatal("expected HealthCheck to fail after PDNS went down")
	}
	if calls.Load() != 2 {
		t.Errorf("expected 2 API calls (cache bypass), got %d", calls.Load())
	}

	// GetServer should still return the cached value
	info, err = cached.GetServer(ctx)
	if err != nil {
		t.Fatalf("cached GetServer after HealthCheck: %v", err)
	}
	if info.Version != "4.8.0" {
		t.Errorf("expected cached version 4.8.0, got %q", info.Version)
	}
	if calls.Load() != 2 {
		t.Errorf("expected still 2 API calls (cache hit), got %d", calls.Load())
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

func TestCachedZoneMutations_InvalidateZonesAndStats(t *testing.T) {
	var listCalls, statCalls, requestCalls atomic.Int64
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones"):
			listCalls.Add(1)
			w.Write([]byte(`[{"id":"test.","name":"test.","kind":"Native","serial":0}]`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "statistics"):
			statCalls.Add(1)
			w.Write([]byte(`[]`))
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/rectify"):
			requestCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/metadata/"):
			requestCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/metadata/"):
			requestCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cryptokeys"):
			requestCalls.Add(1)
			w.Write([]byte(`{"id":1,"keytype":"ksk","active":true,"algorithm":"ECDSA256"}`))
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/cryptokeys/"):
			requestCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/cryptokeys/"):
			requestCalls.Add(1)
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

	// RectifyZone invalidates caches
	if err := cached.RectifyZone(ctx, "test."); err != nil {
		t.Fatalf("RectifyZone: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 3 || statCalls.Load() != 2 {
		t.Errorf("after RectifyZone expected list=3 stat=2, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// SetMetadata invalidates caches
	if err := cached.SetMetadata(ctx, "test.", models.Metadata{Kind: "PRESIGNED", Metadata: []string{"1"}}); err != nil {
		t.Fatalf("SetMetadata: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 4 || statCalls.Load() != 3 {
		t.Errorf("after SetMetadata expected list=4 stat=3, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// DeleteMetadata invalidates caches
	if err := cached.DeleteMetadata(ctx, "test.", "PRESIGNED"); err != nil {
		t.Fatalf("DeleteMetadata: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 5 || statCalls.Load() != 4 {
		t.Errorf("after DeleteMetadata expected list=5 stat=4, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// CreateCryptokey invalidates caches
	if _, err := cached.CreateCryptokey(ctx, "test.", "ksk", true, "ECDSA256"); err != nil {
		t.Fatalf("CreateCryptokey: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 6 || statCalls.Load() != 5 {
		t.Errorf("after CreateCryptokey expected list=6 stat=5, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// ToggleCryptokey invalidates caches
	if err := cached.ToggleCryptokey(ctx, "test.", 1, false); err != nil {
		t.Fatalf("ToggleCryptokey: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 7 || statCalls.Load() != 6 {
		t.Errorf("after ToggleCryptokey expected list=7 stat=6, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	// DeleteCryptokey invalidates caches
	if err := cached.DeleteCryptokey(ctx, "test.", 1); err != nil {
		t.Fatalf("DeleteCryptokey: %v", err)
	}
	cached.ListZones(ctx)
	cached.GetStatistics(ctx)
	if listCalls.Load() != 8 || statCalls.Load() != 7 {
		t.Errorf("after DeleteCryptokey expected list=8 stat=7, got list=%d stat=%d", listCalls.Load(), statCalls.Load())
	}

	if requestCalls.Load() != 6 {
		t.Errorf("expected 6 mutation calls, got %d", requestCalls.Load())
	}
}

// TestCachedRead_SingleFlightCoalescesConcurrentMisses verifies m44: N
// concurrent reads of a cold cache key produce a single PowerDNS call rather
// than N. The leader's fetch is held open until all followers have piled up
// behind the single-flight, then released — without single-flight they would
// each have fired their own request.
func TestCachedRead_SingleFlightCoalescesConcurrentMisses(t *testing.T) {
	const N = 25
	var calls atomic.Int64
	leaderStarted := make(chan struct{})
	releaseLeader := make(chan struct{})
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones") {
			// Only the single-flight leader reaches here. Without single-flight
			// multiple goroutines would, and calls would exceed 1.
			if calls.Add(1) == 1 {
				close(leaderStarted)
				<-releaseLeader // hold the leader open so followers pile up
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"id":"z.","name":"z.","kind":"Native","serial":0}]`))
	})

	ctx := context.Background()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := cached.ListZones(ctx); err != nil {
				t.Errorf("ListZones: %v", err)
			}
		}()
	}
	close(start)    // fire all N readers concurrently
	<-leaderStarted // wait until the leader is inside the handler
	close(releaseLeader)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("expected exactly 1 PDNS call for %d concurrent misses (single-flight m44), got %d", N, got)
	}
}

// TestCachedRead_NoStaleRepopulationAfterInvalidation verifies m45: a read
// whose fetch is still in flight when an invalidation lands must NOT write its
// (now stale) result back to the cache. Without the generation guard the slow
// reader would repopulate the cache with stale data.
func TestCachedRead_NoStaleRepopulationAfterInvalidation(t *testing.T) {
	var listCalls atomic.Int64
	releaseStale := make(chan struct{})
	staleReturned := make(chan []models.Zone, 1)
	cached := newCachedClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/zones"):
			n := listCalls.Add(1)
			if n == 1 {
				<-releaseStale // hold the stale fetch open so invalidation lands mid-fetch
				w.Write([]byte(`[{"id":"stale.","name":"stale.","kind":"Native","serial":0}]`))
				return
			}
			w.Write([]byte(`[{"id":"fresh.","name":"fresh.","kind":"Native","serial":0}]`))
		case r.Method == http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	ctx := context.Background()

	// Reader A starts a slow "stale" fetch.
	go func() {
		z, _ := cached.ListZones(ctx)
		staleReturned <- z
	}()
	// Wait until A's fetch is actually in flight (it incremented listCalls).
	for listCalls.Load() < 1 {
		runtime.Gosched()
	}
	// An invalidation lands while A's fetch is still in flight.
	if err := cached.CreateRecord(ctx, "x.", models.RRSet{
		Name: "www.x.", Type: "A", TTL: 60, Records: []models.RecordInfo{{Content: "1.2.3.4"}},
	}); err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	// Release A; it returns stale data but must NOT have cached it.
	close(releaseStale)
	stale := <-staleReturned
	if len(stale) == 0 || stale[0].ID != "stale." {
		t.Fatalf("reader A should have received stale data, got %v", stale)
	}

	// Reader B reads after the invalidation: must fetch FRESH (stale not cached).
	zones, err := cached.ListZones(ctx)
	if err != nil {
		t.Fatalf("ListZones B: %v", err)
	}
	if len(zones) == 0 || zones[0].ID != "fresh." {
		t.Fatalf("reader B should see fresh data (stale was not cached — m45), got %v", zones)
	}
	if got := listCalls.Load(); got != 2 {
		t.Errorf("expected 2 list calls (stale fetch + fresh fetch), got %d — if 1, stale data poisoned the cache (m45)", got)
	}

	// Reader C: cache hit, still fresh, no new call.
	zones2, err := cached.ListZones(ctx)
	if err != nil {
		t.Fatalf("ListZones C: %v", err)
	}
	if len(zones2) == 0 || zones2[0].ID != "fresh." {
		t.Errorf("reader C should hit cache and see fresh data, got %v", zones2)
	}
	if got := listCalls.Load(); got != 2 {
		t.Errorf("reader C should hit cache (no new call), got %d", got)
	}
}
