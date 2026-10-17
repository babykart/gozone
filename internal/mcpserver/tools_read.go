package mcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callTool logs the mapped tool error's cause server-side and returns the
// tool error to the SDK (which packs it into an isError result). Every tool
// funnels its failures through it: the client sees code + safe message, the
// operator sees the full cause in the logs.
func callTool(tool string, terr *toolError, cause error) error {
	if cause == nil {
		cause = terr
	}
	slog.Error("mcp tool failed", "tool", tool, "code", terr.code, "error", cause)
	return terr
}

func readOnlyAnnotations() *mcp.ToolAnnotations {
	f := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:  true,
		OpenWorldHint: &f,
	}
}

func registerReadTools(srv *mcp.Server, ops *dnsops.Service) {
	// -- list_zones ------------------------------------------------------
	type listZonesIn struct{}
	type listZonesOut struct {
		Zones []models.Zone `json:"zones" jsonschema:"zones visible to the API key's user (admins see all; others see their group-granted zones)"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_zones",
		Title:       "List zones",
		Description: "List DNS zones. Admin keys see every zone; other keys see only the zones granted through zone groups. No pagination: PowerDNS serves bounded zone counts.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listZonesIn) (*mcp.CallToolResult, listZonesOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, listZonesOut{}, terr
		}
		zones, err := ops.ListZones(ctx, user)
		if te, cause := mapServiceError(err, codeZoneNotFound); te != nil {
			return nil, listZonesOut{}, callTool("list_zones", te, cause)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%d zone(s) visible", len(zones))}}}, listZonesOut{Zones: zones}, nil
	})

	// -- get_zone ---------------------------------------------------------
	type getZoneIn struct {
		Zone string `json:"zone" jsonschema:"zone ID; accepts any casing and an optional trailing dot (\"Example.COM\", \"example.com\") — canonicalised to the lowercase dotted form"`
	}
	type getZoneOut struct {
		Zone models.Zone `json:"zone"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_zone",
		Title:       "Get zone",
		Description: "Get one zone's details (kind, serial, DNSSEC state, masters). Use list_records for the zone's records.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in getZoneIn) (*mcp.CallToolResult, getZoneOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, getZoneOut{}, terr
		}
		zone, terr := canonicalZoneArg(in.Zone)
		if terr != nil {
			return nil, getZoneOut{}, terr
		}
		zoneInfo, err := ops.GetZone(ctx, user, zone)
		if te, cause := mapServiceError(err, codeZoneNotFound); te != nil {
			return nil, getZoneOut{}, callTool("get_zone", te, cause)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: zoneInfo.Name + " (" + zoneInfo.Kind + ")"}}}, getZoneOut{Zone: *zoneInfo}, nil
	})

	// -- list_records -----------------------------------------------------
	type listRecordsIn struct {
		Zone string `json:"zone" jsonschema:"zone ID; accepts any casing and an optional trailing dot (\"Example.COM\", \"example.com\") — canonicalised to the lowercase dotted form"`
		Name string `json:"name,omitempty" jsonschema:"optional record-name filter; accepts \"@\", a bare label (\"www\"), an FQDN without the trailing dot or a full FQDN"`
		Type string `json:"type,omitempty" jsonschema:"optional record type filter (e.g. A, CNAME), case-insensitive; requires name"`
	}
	type listRecordsOut struct {
		Records []models.RRSet `json:"records"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_records",
		Title:       "List records",
		Description: "List a zone's record sets (RRSets). Optionally filter by name (and type — type requires name). Each RRSet carries every record of that name+type; MX/SRV priorities appear in each record's priority field, TXT/SPF content is returned unquoted.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listRecordsIn) (*mcp.CallToolResult, listRecordsOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, listRecordsOut{}, terr
		}
		zone, terr := canonicalZoneArg(in.Zone)
		if terr != nil {
			return nil, listRecordsOut{}, terr
		}
		// Canonicalise the type filter (uppercase, trimmed) like the REST
		// GET: PowerDNS matches rrset_type against the stored uppercase
		// form, so a lowercase "mx" would silently match nothing.
		rrType := dnsops.CanonicalRecordType(in.Type)
		name := in.Name
		if rrType != "" && name == "" {
			return nil, listRecordsOut{}, toolErrorf("VALIDATION_ERROR", "the 'type' filter requires 'name'")
		}
		if name != "" {
			name = dnsops.NormalizeRecordName(name, zone)
		}
		records, err := ops.ListRecords(ctx, user, zone, name, rrType)
		if te, cause := mapServiceError(err, codeZoneNotFound); te != nil {
			return nil, listRecordsOut{}, callTool("list_records", te, cause)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%d record set(s)", len(records))}}}, listRecordsOut{Records: records}, nil
	})

	// -- get_stats --------------------------------------------------------
	type getStatsIn struct{}
	type getStatsOut struct {
		Statistics []models.StatisticItem `json:"statistics"`
		ZoneCount  int                    `json:"zone_count" jsonschema:"zones visible to the key's user"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_stats",
		Title:       "Get statistics",
		Description: "PowerDNS server statistics plus the zone count visible to the API key's user.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ getStatsIn) (*mcp.CallToolResult, getStatsOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, getStatsOut{}, terr
		}
		stats, zoneCount, err := ops.Stats(ctx, user)
		if te, cause := mapServiceError(err, codeZoneNotFound); te != nil {
			return nil, getStatsOut{}, callTool("get_stats", te, cause)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%d stat item(s), %d zone(s) visible", len(stats), zoneCount)}}}, getStatsOut{Statistics: stats, ZoneCount: zoneCount}, nil
	})

	// -- list_record_types ------------------------------------------------
	type listRecordTypesIn struct{}
	type listRecordTypesOut struct {
		Types []string `json:"types" jsonschema:"supported record type names"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list_record_types",
		Title:       "List record types",
		Description: "List the record types GoZone accepts for creation/updates. Content is validated per type; MX/SRV take a separate priority field, TXT/SPF content is quoted automatically, FQDN targets (CNAME, NS, ...) get their trailing dot added automatically.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ listRecordTypesIn) (*mcp.CallToolResult, listRecordTypesOut, error) {
		if _, terr := userFromContext(ctx); terr != nil {
			return nil, listRecordTypesOut{}, terr
		}
		types := dnsops.RecordTypes()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%d supported record types", len(types))}}}, listRecordTypesOut{Types: types}, nil
	})
	// -- export_zone ------------------------------------------------------
	type exportZoneIn struct {
		Zone   string `json:"zone" jsonschema:"zone ID; accepts any casing and an optional trailing dot (\"Example.COM\", \"example.com\") — canonicalised to the lowercase dotted form"`
		Format string `json:"format,omitempty" jsonschema:"output format: \"bind\" (default; RFC 1035 zone file) or \"csv\" (one row per record)"`
	}
	type exportZoneOut struct {
		Zone        string `json:"zone"`
		Format      string `json:"format" jsonschema:"bind or csv"`
		RecordCount int    `json:"record_count" jsonschema:"number of records in the export (disabled records included in csv, omitted in bind)"`
		Content     string `json:"content" jsonschema:"the export body; truncated with an explicit banner past 1 MiB"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "export_zone",
		Title:       "Export zone",
		Description: "Export a whole zone as an RFC 1035 BIND zone file (format=bind, the default — $ORIGIN/$TTL header, records sorted, disabled records omitted) or as CSV (one row per record, disabled records flagged). The gozone://zones/{zone} resource serves the same BIND content for context attachment. Output past 1 MiB is explicitly truncated with a banner naming the REST export endpoint.",
		Annotations: readOnlyAnnotations(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in exportZoneIn) (*mcp.CallToolResult, exportZoneOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, exportZoneOut{}, terr
		}
		zone, terr := canonicalZoneArg(in.Zone)
		if terr != nil {
			return nil, exportZoneOut{}, terr
		}
		format := strings.ToLower(strings.TrimSpace(in.Format))
		if format == "" {
			format = "bind"
		}
		if format != "bind" && format != "csv" {
			return nil, exportZoneOut{}, toolErrorf("VALIDATION_ERROR", "unknown format %q: use \"bind\" or \"csv\"", format)
		}

		// Both reads go through the service layer, which re-checks the zone
		// grant (fail-closed) before any PowerDNS call — same as the resource.
		zoneInfo, err := ops.GetZone(ctx, user, zone)
		if err != nil {
			if te, cause := mapServiceError(err, codeZoneNotFound); te != nil {
				return nil, exportZoneOut{}, callTool("export_zone", te, cause)
			}
		}
		records, err := ops.ListRecords(ctx, user, zone, "", "")
		if err != nil {
			if te, cause := mapServiceError(err, codeZoneNotFound); te != nil {
				return nil, exportZoneOut{}, callTool("export_zone", te, cause)
			}
		}

		recordCount := 0
		var body string
		if format == "csv" {
			body = dnsops.RenderZoneCSV(zoneInfo, records)
			for _, rr := range records {
				recordCount += len(rr.Records)
			}
		} else {
			body = dnsops.RenderZoneFile(zoneInfo, records)
			for _, rr := range records {
				for _, rec := range rr.Records {
					if !rec.Disabled {
						recordCount++
					}
				}
			}
		}
		truncated := len(body) > maxResourceBytes
		body = truncateResource(body, zone, format)

		summary := fmt.Sprintf("%s export of %s: %d record(s), %d bytes", strings.ToUpper(format), zone, recordCount, len(body))
		if truncated {
			summary += " (TRUNCATED at 1 MiB — banner names the REST endpoint for the full export)"
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: summary}}},
			exportZoneOut{Zone: zone, Format: format, RecordCount: recordCount, Content: body}, nil
	})
}

// canonicalZoneArg validates then canonicalises a zone argument (lowercase,
// trailing dot). Every zone-addressed tool funnels its argument through it,
// so the service's zone authorization, the per-zone write lock and the audit
// trail all key on the same canonical ID whatever form the client used
// ("example.com", "Example.COM.", "example.com.") — without it, two spellings
// of one zone take different locks and a granted user can be wrongly refused.
func canonicalZoneArg(zone string) (string, *toolError) {
	if err := validators.ValidateDomainName(zone); err != nil {
		return "", toolErrorf("VALIDATION_ERROR", "%s", err.Error())
	}
	return dnsops.NormalizeZoneName(zone), nil
}
