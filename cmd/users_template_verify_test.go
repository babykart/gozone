package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/handlers"
	"github.com/babykart/gozone/internal/models"
)

// TestUsersTemplateIsLocked verifies the real users.html template can evaluate
// .IsLocked on models.User values (regression: method dropped as "dead code"
// while the template still called it).
func TestUsersTemplateIsLocked(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	until := time.Now().UTC().Add(time.Hour)
	data := map[string]any{
		"Title":     "Users",
		"User":      &models.User{ID: 1, Role: "admin"},
		"Users":     []models.User{{ID: 2, Username: "locked", LockedUntil: &until}},
		"PageInfo":  &handlers.PageInfo{},
		"Search":    "",
		"CSRFToken": "test",
	}
	var sb strings.Builder
	if err := tmpl.ExecuteTemplate(&sb, "users.html", data); err != nil {
		t.Fatalf("ExecuteTemplate users.html: %v", err)
	}
	out := sb.String()
	if !strings.Contains(out, "badge-locked") {
		t.Errorf("expected locked badge in output")
	}
	if !strings.Contains(out, "Unlock") {
		t.Errorf("expected Unlock button in output")
	}
}
