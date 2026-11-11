package dnsops

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// mixedStatsFixture is a recognisable upstream statistics payload: one plain
// scalar, one ring and one map item. Ring/map items (per-client query rings,
// remote-server maps) expose internal traffic detail and must be withheld
// from users who are not DNS admins.
func mixedStatsFixture() []models.StatisticItem {
	return []models.StatisticItem{
		{Name: "uptime", Type: "StatisticItem", Value: "12345"},
		{Name: "queries", Type: "RingStatisticItem", Value: []interface{}{"example.com.", "other.example."}},
		{Name: "remotes", Type: "MapStatisticItem", Value: map[string]interface{}{"192.0.2.1": 42}},
	}
}

// newStatsTestService builds a Service whose mock PowerDNS serves the mixed
// stats fixture on /statistics and an empty zone list elsewhere.
func newStatsTestService(t *testing.T) *Service {
	t.Helper()
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/statistics") {
			json.NewEncoder(w).Encode(mixedStatsFixture()) // #nosec G104 -- test helper
			return
		}
		json.NewEncoder(w).Encode([]models.Zone{}) // #nosec G104 -- test helper
	})
	t.Cleanup(srv.Close)
	return New(testutil.NewTestDB(t), client)
}

func statNames(stats []models.StatisticItem) []string {
	names := make([]string, 0, len(stats))
	for _, s := range stats {
		names = append(names, s.Name)
	}
	return names
}

func hasStat(stats []models.StatisticItem, name string) bool {
	for _, s := range stats {
		if s.Name == name {
			return true
		}
	}
	return false
}

// TestStats_StripsRingAndMapForNonAdmin pins the info-leak fix: ring and map
// statistic items are only returned to DNS admins (admin/operator) or an
// in-process (nil) caller; plain users get the scalar statistics only. The
// keep-cases are service-level pass-through of whatever the ZoneService
// supplies — through the real client, rings are already excluded upstream
// by ?includerings=false.
func TestStats_StripsRingAndMapForNonAdmin(t *testing.T) {
	s := newStatsTestService(t)
	ctx := context.Background()

	userID := testutil.SeedTestUser(t, s.DB, "plainuser", "pass", "user", true)

	cases := []struct {
		name       string
		user       *models.User
		keepDetail bool
	}{
		{"user strips ring/map", &models.User{ID: userID, Role: "user"}, false},
		{"admin keeps everything", &models.User{ID: 9001, Role: "admin"}, true},
		{"operator keeps everything", &models.User{ID: 9002, Role: "operator"}, true},
		{"nil in-process caller keeps everything", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stats, _, err := s.Stats(ctx, tc.user)
			if err != nil {
				t.Fatalf("Stats: %v", err)
			}
			if !hasStat(stats, "uptime") {
				t.Errorf("scalar item \"uptime\" missing; got %v", statNames(stats))
			}
			if tc.keepDetail {
				if !hasStat(stats, "queries") || !hasStat(stats, "remotes") {
					t.Errorf("ring/map items must be kept for %v; got %v", tc.user, statNames(stats))
				}
				return
			}
			if hasStat(stats, "queries") || hasStat(stats, "remotes") {
				t.Errorf("ring/map items leaked to a plain user; got %v", statNames(stats))
			}
		})
	}
}

// TestStats_StatisticsFailureKeepsZoneCount pins the degradation boundary of
// the composite: a failed statistics call is reported (StageStatistics) and
// yields no statistics, but the authorized zone count is still computed — it
// depends only on the zone list and the zone-access lookup, which stay fatal
// (the count is unknowable when they fail) and take precedence over the
// degradable statistics failure.
func TestStats_StatisticsFailureKeepsZoneCount(t *testing.T) {
	srv, client := testutil.NewTestPDNSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/statistics") {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal server error"}`))
			return
		}
		json.NewEncoder(w).Encode([]models.Zone{
			{ID: "a.example.", Name: "a.example.", Kind: "Native"},
			{ID: "b.example.", Name: "b.example.", Kind: "Native"},
		})
	})
	t.Cleanup(srv.Close)
	s := New(testutil.NewTestDB(t), client)

	stats, zoneCount, err := s.Stats(context.Background(), &models.User{ID: 1, Role: "admin"})
	var se *StageError
	if !errors.As(err, &se) || se.Stage != StageStatistics {
		t.Fatalf("want StageError(StageStatistics), got %v", err)
	}
	if stats != nil {
		t.Errorf("expected no statistics, got %v", statNames(stats))
	}
	if zoneCount != 2 {
		t.Errorf("statistics failure must not zero the zone count: got %d, want 2", zoneCount)
	}
}

// TestFilterStatsForUser_FreshSliceNoMutation pins the second half of the
// fix: filtering must allocate a fresh result slice and never mutate the
// input slice, which may be the shared cached backing array from the cached
// client — an in-place filter would corrupt every other caller's result.
func TestFilterStatsForUser_FreshSliceNoMutation(t *testing.T) {
	input := mixedStatsFixture()
	before := statNames(input)

	user := &models.User{ID: 1, Role: "user"}
	got := filterStatsForUser(input, user)
	if len(got) != 1 || got[0].Name != "uptime" {
		t.Fatalf("user sees %v, want only the uptime scalar", statNames(got))
	}
	if !slices.Equal(statNames(input), before) {
		t.Fatalf("input slice mutated by filtering: %v", statNames(input))
	}
	if &got[0] == &input[0] {
		t.Fatal("filtered result aliases the input slice; filtering must allocate a fresh slice")
	}

	// A DNS admin gets the items the service was handed, untouched.
	admin := filterStatsForUser(input, &models.User{ID: 2, Role: "admin"})
	if !slices.Equal(statNames(admin), before) {
		t.Fatalf("admin items changed: %v", statNames(admin))
	}
}
