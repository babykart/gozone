package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/models"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// maxResourceBytes caps the body of a resource response (MCP_PLAN.md §4:
// limit output sizes — an export of a very large zone must not be streamed
// unbounded into an agent's context). The truncation is explicit: a banner
// at the end names the exact REST endpoint serving the full export.
const maxResourceBytes = 1 << 20 // 1 MiB

// registerResources adds the MCP resources (MCP_PLAN.md §3.2). Resources
// are read-only, so they are registered regardless of mcp.read_only (which
// gates the write TOOLS only).
func registerResources(srv *mcp.Server, ops *dnsops.Service) {
	// gozone://record-types — static: supported types + normalisation rules.
	srv.AddResource(&mcp.Resource{
		URI:         "gozone://record-types",
		Name:        "record-types",
		Title:       "Supported record types and content rules",
		MIMEType:    "application/json",
		Description: "JSON map of every supported record type to its content normalisation rules: whether a separate priority field is embedded into the content (MX/SRV), whether the content is quoted on the wire (TXT/SPF), FQDN target handling and per-field indices. Read this before creating or updating records.",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		if _, terr := userFromContext(ctx); terr != nil {
			return nil, terr
		}
		b, err := json.MarshalIndent(models.RecordTypeRules(), "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal record-type rules: %w", err)
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      req.Params.URI,
			MIMEType: "application/json",
			Text:     string(b),
		}}}, nil
	})

	// gozone://zones/{zone} — template: full BIND export of one zone, so a
	// client can attach the whole zone as context.
	srv.AddResourceTemplate(&mcp.ResourceTemplate{
		Name:        "zone-export",
		Title:       "Zone file (BIND export)",
		URITemplate: "gozone://zones/{zone}",
		MIMEType:    "text/dns",
		Description: "The complete zone as an RFC 1035 BIND zone file ($ORIGIN, $TTL, sorted records; disabled records omitted). {zone} is the canonical zone ID from list_zones (e.g. gozone://zones/example.com.). Access requires a group grant on the zone (or an admin key).",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, terr
		}
		zone, err := zoneFromResourceURI(req.Params.URI)
		if err != nil {
			return nil, err
		}
		// Canonicalise like the zone-addressed tools: authorization and the
		// audit/share keys compare canonical IDs, so "Example.COM" in a URI
		// addresses the same zone as "example.com.".
		zone = dnsops.NormalizeZoneName(zone)

		// Both reads go through the service layer, which re-checks the zone
		// grant (fail-closed): the zone metadata and the record list each
		// authorize independently.
		zoneInfo, err := ops.GetZone(ctx, user, zone)
		if err != nil {
			return nil, resourceError("read gozone://zones", zone, err)
		}
		records, err := ops.ListRecords(ctx, user, zone, "", "")
		if err != nil {
			return nil, resourceError("read gozone://zones", zone, err)
		}

		text := truncateResource(dnsops.RenderZoneFile(zoneInfo, records), zone, "bind")
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      req.Params.URI,
			MIMEType: "text/dns",
			Text:     text,
		}}}, nil
	})
}

// zoneFromResourceURI extracts the zone ID from a gozone://zones/{zone} URI.
func zoneFromResourceURI(uri string) (string, error) {
	const prefix = "gozone://zones/"
	if !strings.HasPrefix(uri, prefix) {
		return "", toolErrorf("VALIDATION_ERROR", "unexpected resource URI %q: want gozone://zones/{zone}", uri)
	}
	zone, err := url.PathUnescape(strings.TrimPrefix(uri, prefix))
	if err != nil || zone == "" || strings.Contains(zone, "/") {
		return "", toolErrorf("VALIDATION_ERROR", "invalid zone in resource URI %q", uri)
	}
	return zone, nil
}

// truncateResource caps an export body at maxResourceBytes, cutting at the
// last complete line and appending an explicit banner that names the REST
// endpoint serving the full export, so the client can fall back. Content
// under the limit is returned unchanged.
func truncateResource(text, zone, format string) string {
	if len(text) <= maxResourceBytes {
		return text
	}
	cut := text[:maxResourceBytes]
	if i := strings.LastIndexByte(cut, '\n'); i > 0 {
		cut = cut[:i+1] // keep the trailing newline: the cut is line-aligned
	}
	slog.Warn("mcp export truncated", "zone", zone, "format", format, "limit_bytes", maxResourceBytes)
	return cut + fmt.Sprintf("\n; --- TRUNCATED at %d bytes (limit %d): fetch the full export via GET /zones/%s/export?format=%s ---\n",
		len(cut), maxResourceBytes, zone, format)
}

// resourceError maps a service failure for a resource read. Unlike tool
// calls (isError results), resource-read failures are protocol-level
// errors — the SDK converts the returned error into a JSON-RPC error whose
// message carries the stable code and no internal detail.
func resourceError(what, zone string, err error) error {
	te, cause := mapServiceError(err, codeZoneNotFound)
	if te == nil {
		return err
	}
	if cause == nil {
		cause = te
	}
	slog.Error("mcp resource failed", "what", what, "zone", zone, "code", te.code, "error", cause)
	return te
}
