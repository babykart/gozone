package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestResourcesListed(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	ctx := context.Background()

	res, err := session.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	found := false
	for _, r := range res.Resources {
		if r.URI == "gozone://record-types" && r.MIMEType == "application/json" {
			found = true
		}
	}
	if !found {
		t.Fatalf("gozone://record-types must be listed, got %+v", res.Resources)
	}

	tmpls, err := session.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	found = false
	for _, rt := range tmpls.ResourceTemplates {
		if rt.URITemplate == "gozone://zones/{zone}" && rt.MIMEType == "text/dns" {
			found = true
		}
	}
	if !found {
		t.Fatalf("gozone://zones/{zone} template must be listed, got %+v", tmpls.ResourceTemplates)
	}
}

func TestReadRecordTypesResource(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	res, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gozone://record-types"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) != 1 || res.Contents[0].MIMEType != "application/json" {
		t.Fatalf("unexpected contents: %+v", res.Contents)
	}
	var rules map[string]models.RecordTypeRule
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &rules); err != nil {
		t.Fatalf("record-types body is not valid JSON: %v", err)
	}
	if !rules["MX"].Priority || !rules["MX"].FQDNTarget {
		t.Errorf("MX rules wrong: %+v", rules["MX"])
	}
	if !rules["TXT"].Quoted {
		t.Errorf("TXT must be flagged quoted: %+v", rules["TXT"])
	}
	if got := rules["SOA"].FQDNFieldIndices; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("SOA FQDN field indices wrong: %v", got)
	}
}

func TestReadZoneResource_BINDExport(t *testing.T) {
	session, db := newMCPTestEnv(t, true, richPDNS(t, &[]models.RRSet{}))
	grantZoneToMCPUser(t, db, "example.com.")

	res, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gozone://zones/example.com."})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) != 1 || res.Contents[0].MIMEType != "text/dns" {
		t.Fatalf("unexpected contents: %+v", res.Contents)
	}
	zoneFile := res.Contents[0].Text
	for want := range map[string]bool{
		"$ORIGIN example.com.": true,
		"$TTL ":                true,
		"www IN A 192.0.2.1":   true,
	} {
		if !strings.Contains(zoneFile, want) {
			t.Errorf("zone file missing %q:\n%s", want, zoneFile)
		}
	}
}

func TestReadZoneResource_UngrantedUserRejected(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no PowerDNS call expected for a refused resource read, got %s %s", r.Method, r.URL.Path)
	})
	// No grant for the seeded user: the resource read must fail (protocol
	// error carrying the stable FORBIDDEN code) before any upstream call.
	_, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gozone://zones/example.com."})
	if err == nil {
		t.Fatal("ungranted resource read must fail")
	}
	if !strings.Contains(err.Error(), "FORBIDDEN") {
		t.Fatalf("error must carry the FORBIDDEN code, got %v", err)
	}
}

func TestReadZoneResource_InvalidURI(t *testing.T) {
	session, _ := newMCPTestEnv(t, true, nil)
	_, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gozone://zones/"})
	if err == nil {
		t.Fatal("empty zone in URI must fail")
	}
}

// TestReadZoneResource_ZoneURICanonicalised pins the resource-side zone
// canonicalisation: a URI spelled "Example.COM" (no trailing dot, mixed
// case) must address the same zone as "example.com." for authorization —
// not be fail-closed into a spurious FORBIDDEN.
func TestReadZoneResource_ZoneURICanonicalised(t *testing.T) {
	session, db := newMCPTestEnv(t, true, richPDNS(t, &[]models.RRSet{}))
	grantZoneToMCPUser(t, db, "example.com.")

	res, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "gozone://zones/Example.COM"})
	if err != nil {
		t.Fatalf("ReadResource with a non-canonical zone URI: %v", err)
	}
	if len(res.Contents) != 1 || !strings.Contains(res.Contents[0].Text, "$ORIGIN example.com.") {
		t.Fatalf("expected the granted zone's BIND export, got %+v", res.Contents)
	}
}

func TestTruncateResource(t *testing.T) {
	small := "$ORIGIN example.com.\nwww IN A 192.0.2.1\n"
	if got, truncated := truncateResource(small, "example.com.", "bind"); got != small || truncated {
		t.Fatalf("small body must pass through untruncated, got %q truncated=%v", got, truncated)
	}

	// Build a body over the limit out of complete lines.
	var sb strings.Builder
	line := "www IN A 192.0.2.1\n"
	for sb.Len() <= maxResourceBytes {
		sb.WriteString(line)
	}
	big := sb.String()

	// BIND: explicit comment banner naming the API-key-reachable REST route.
	got, truncated := truncateResource(big, "example.com.", "bind")
	if !truncated {
		t.Fatal("oversized body must report truncation")
	}
	if !strings.Contains(got, "TRUNCATED at") || !strings.Contains(got, "GET /api/v1/zones/example.com./export?format=bind") {
		t.Fatalf("truncation banner missing or incomplete:\n%q", got[len(got)-250:])
	}
	// The cut must not end mid-line: strip the banner lines and check the
	// remaining content ends with a newline.
	if i := strings.Index(got, "\n; ---"); i > 0 && !strings.HasSuffix(got[:i], "\n") {
		t.Fatalf("truncated content must end at a line boundary")
	}

	// CSV: line-aligned cut with NO in-band marker (CSV has no comment
	// syntax — a banner would corrupt the file); the flag is the signal.
	csvGot, truncated := truncateResource(big, "example.com.", "csv")
	if !truncated {
		t.Fatal("oversized CSV must report truncation")
	}
	if strings.Contains(csvGot, "TRUNCATED") {
		t.Fatalf("CSV cut must not carry an in-band banner, got tail %q", csvGot[len(csvGot)-120:])
	}
	if !strings.HasSuffix(csvGot, "\n") {
		t.Fatal("CSV cut must end at a line boundary")
	}
}

func TestZoneFromResourceURI(t *testing.T) {
	cases := []struct {
		uri, want string
		wantErr   bool
	}{
		{"gozone://zones/example.com.", "example.com.", false},
		{"gozone://zones/a.example.com.", "a.example.com.", false},
		{"gozone://zones/", "", true},
		{"gozone://zones/a/b", "", true},
		{"file:///etc/passwd", "", true},
	}
	for _, c := range cases {
		got, err := zoneFromResourceURI(c.uri)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q must be rejected", c.uri)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got (%q, %v), want %q", c.uri, got, err, c.want)
		}
	}
}
