package dnsops

import (
	"context"
	"errors"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
)

// The "operator" role is a DNS administrator: it must pass the same
// service-layer gates as "admin" — requireAdmin, authorizeZone and the
// zone-list filters — so every transport (REST, web, MCP) treats it
// identically at the one place the invariant lives. These tests pin that
// parity, and as guard rails that plain "user" accounts and a nil caller
// stay fail-closed.

func TestOperatorRequireAdmin(t *testing.T) {
	cases := []struct {
		name    string
		user    *models.User
		wantErr error
	}{
		{"operator is DNS-admin", &models.User{ID: 2, Username: "op", Role: "operator"}, nil},
		{"admin control", &models.User{ID: 1, Username: "admin", Role: "admin"}, nil},
		{"nil user control (in-process caller)", nil, nil},
		{"plain user still denied", &models.User{ID: 3, Username: "plain", Role: "user"}, ErrForbidden},
	}
	for _, tc := range cases {
		if err := requireAdmin(tc.user); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: requireAdmin(%+v) = %v, want %v", tc.name, tc.user, err, tc.wantErr)
		}
	}
}

// TestOperatorAuthorizeZone: an operator must pass the service-level
// zone-scoped gate with NO group grant (CanAccessZone is only for plain
// users); a plain user without a grant stays denied.
func TestOperatorAuthorizeZone(t *testing.T) {
	db := testutil.NewTestDB(t)
	opID := testutil.SeedTestUser(t, db, "opzone", "pass", "operator", true)
	plainID := testutil.SeedTestUser(t, db, "plainzone", "pass", "user", true)
	adminID := testutil.SeedTestUser(t, db, "adminzone", "pass", "admin", true)
	s := New(db, nil) // authorizeZone never touches PowerDNS
	ctx := context.Background()

	// Operator passes without any grant (DNS-admin parity).
	op := &models.User{ID: opID, Username: "opzone", Role: "operator"}
	if err := s.authorizeZone(ctx, op, "ungranted.example."); err != nil {
		t.Errorf("operator without grant: authorizeZone() = %v, want nil", err)
	}

	// Admin control.
	admin := &models.User{ID: adminID, Username: "adminzone", Role: "admin"}
	if err := s.authorizeZone(ctx, admin, "ungranted.example."); err != nil {
		t.Errorf("admin control: authorizeZone() = %v, want nil", err)
	}

	// Guard rail: a plain user with no grant stays denied (fail-closed).
	plain := &models.User{ID: plainID, Username: "plainzone", Role: "user"}
	if err := s.authorizeZone(ctx, plain, "ungranted.example."); !errors.Is(err, ErrForbidden) {
		t.Errorf("plain user without grant: authorizeZone() = %v, want ErrForbidden", err)
	}
}

// TestOperatorFilterZonesForUser: an operator sees the full zone list with
// no grants; plain and nil users keep their fail-closed behaviour.
func TestOperatorFilterZonesForUser(t *testing.T) {
	db := testutil.NewTestDB(t)
	opID := testutil.SeedTestUser(t, db, "opfilter", "pass", "operator", true)
	plainID := testutil.SeedTestUser(t, db, "plainfilter", "pass", "user", true)
	ctx := context.Background()
	zones := []models.Zone{
		{ID: "a.example.", Name: "a.example.", Kind: "Native"},
		{ID: "b.example.", Name: "b.example.", Kind: "Native"},
	}

	// Operator sees every zone without grants (DNS-admin parity).
	op := &models.User{ID: opID, Username: "opfilter", Role: "operator"}
	got, err := FilterZonesForUser(ctx, db, op, zones)
	if err != nil || len(got) != 2 {
		t.Fatalf("operator: got (%v, %v), want (all 2 zones, nil)", got, err)
	}

	// Guard rail: a plain user with no grants still sees nothing.
	plain := &models.User{ID: plainID, Username: "plainfilter", Role: "user"}
	got, err = FilterZonesForUser(ctx, db, plain, zones)
	if err != nil || len(got) != 0 {
		t.Fatalf("plain user: got (%v, %v), want (empty, nil)", got, err)
	}

	// Guard rail: nil user still fails closed to an empty list, no error.
	got, err = FilterZonesForUser(ctx, db, nil, zones)
	if err != nil || len(got) != 0 {
		t.Fatalf("nil user: got (%v, %v), want (empty, nil)", got, err)
	}
}

// TestOperatorFilterZonesWithInfoForUser: same parity over the
// ZoneWithInfo shape used by the list-zones-with-statistics path.
func TestOperatorFilterZonesWithInfoForUser(t *testing.T) {
	db := testutil.NewTestDB(t)
	opID := testutil.SeedTestUser(t, db, "opinfo", "pass", "operator", true)
	plainID := testutil.SeedTestUser(t, db, "plaininfo", "pass", "user", true)
	ctx := context.Background()
	zones := []models.ZoneWithInfo{
		{Zone: models.Zone{ID: "a.example.", Name: "a.example.", Kind: "Native"}},
		{Zone: models.Zone{ID: "b.example.", Name: "b.example.", Kind: "Native"}},
	}

	// Operator sees every zone without grants (DNS-admin parity).
	op := &models.User{ID: opID, Username: "opinfo", Role: "operator"}
	got, err := FilterZonesWithInfoForUser(ctx, db, op, zones)
	if err != nil || len(got) != 2 {
		t.Fatalf("operator: got (%v, %v), want (all 2 zones, nil)", got, err)
	}

	// Guard rail: a plain user with no grants still sees nothing.
	plain := &models.User{ID: plainID, Username: "plaininfo", Role: "user"}
	got, err = FilterZonesWithInfoForUser(ctx, db, plain, zones)
	if err != nil || len(got) != 0 {
		t.Fatalf("plain user: got (%v, %v), want (empty, nil)", got, err)
	}

	// Guard rail: nil user still fails closed to an empty list, no error.
	got, err = FilterZonesWithInfoForUser(ctx, db, nil, zones)
	if err != nil || len(got) != 0 {
		t.Fatalf("nil user: got (%v, %v), want (empty, nil)", got, err)
	}
}
