package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPromptsListed(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	res, err := session.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	found := map[string]bool{}
	for _, p := range res.Prompts {
		found[p.Name] = true
	}
	if !found["audit_zone"] || !found["migrate_record"] {
		t.Fatalf("audit_zone and migrate_record must be listed, got %+v", res.Prompts)
	}
	// Both are pure instruction templates: available even in read-only mode.
	if len(res.Prompts) != 2 {
		t.Fatalf("expected exactly the two documented prompts, got %+v", res.Prompts)
	}
}

func TestGetPrompt_AuditZone(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	res, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{
		Name:      "audit_zone",
		Arguments: map[string]string{"zone": "example.com."},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(res.Messages) != 1 || res.Messages[0].Role != mcp.Role("user") {
		t.Fatalf("expected one user message, got %+v", res.Messages)
	}
	text := res.Messages[0].Content.(*mcp.TextContent).Text
	for want := range map[string]bool{
		"example.com.":  true, // the zone argument is embedded
		"list_records":  true, // instructions drive the read tools
		"SOA":           true,
		"CNAME":         true,
		"SPF":           true,
		"DMARC":         true,
		"Do NOT change": true, // audit is read-only: propose, never apply
	} {
		if !strings.Contains(text, want) {
			t.Errorf("audit_zone prompt missing %q", want)
		}
	}
}

func TestGetPrompt_MigrateRecord(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	res, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{
		Name: "migrate_record",
		Arguments: map[string]string{
			"zone": "example.com.",
			"name": "www",
			"type": "a",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	text := res.Messages[0].Content.(*mcp.TextContent).Text
	for want := range map[string]bool{
		"READ FIRST":    true, // read before write
		"update_record": true,
		"REPLACE":       true, // semantics called out
		"ROLLBACK":      true,
		"VERIFY":        true,
		`type A`:        true, // type uppercased
		`"www"`:         true,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("migrate_record prompt missing %q", want)
		}
	}
}

func TestGetPrompt_InvalidArguments(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	ctx := context.Background()

	cases := []struct {
		prompt string
		args   map[string]string
	}{
		{"audit_zone", map[string]string{"zone": "not a domain"}},
		{"migrate_record", map[string]string{"zone": "example.com.", "name": "www", "type": "BOGUS"}},
		{"migrate_record", map[string]string{"zone": "example.com.", "name": "bad name!", "type": "A"}},
	}
	for _, c := range cases {
		if _, err := session.GetPrompt(ctx, &mcp.GetPromptParams{Name: c.prompt, Arguments: c.args}); err == nil {
			t.Errorf("%s with %v must be rejected", c.prompt, c.args)
		}
	}
}
