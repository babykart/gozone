package mcpserver

import (
	"context"
	"fmt"

	"github.com/babykart/gozone/internal/dnsops"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/validators"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// recordInput is one record of an RRSet submission. MX/SRV priority is a
// separate field (embedded into the content on the wire); TXT/SPF content is
// quoted automatically; FQDN targets get their trailing dot added.
type recordInput struct {
	Content  string `json:"content" jsonschema:"bare record content — no embedded priority, no surrounding quotes (e.g. \"192.0.2.1\"; for MX/SRV the target only, priority goes in its own field)"`
	Priority int    `json:"priority,omitempty" jsonschema:"MX/SRV priority (0-65535); ignored for other types"`
	Disabled bool   `json:"disabled,omitempty" jsonschema:"mark the record as disabled"`
}

func writeAnnotations(destructive, idempotent bool) *mcp.ToolAnnotations {
	f := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: &destructive,
		IdempotentHint:  idempotent,
		OpenWorldHint:   &f,
	}
}

// buildRRSet converts tool input into the models.RRSet the service expects.
func buildRRSet(zone, name, rrtype string, ttl int, records []recordInput) models.RRSet {
	rr := models.RRSet{
		Name:    name,
		Type:    rrtype,
		TTL:     ttl,
		Records: make([]models.RecordInfo, 0, len(records)),
	}
	for _, r := range records {
		rr.Records = append(rr.Records, models.RecordInfo{Content: r.Content, Priority: r.Priority, Disabled: r.Disabled})
	}
	return rr
}

func registerWriteTools(srv *mcp.Server, ops *dnsops.Service) {
	// -- create_record ----------------------------------------------------
	type createRecordIn struct {
		Zone    string        `json:"zone" jsonschema:"canonical zone ID as returned by list_zones (lowercase with trailing dot, e.g. \"example.com.\")"`
		Name    string        `json:"name" jsonschema:"record name; accepts \"@\" (apex), a bare label (\"www\"), an FQDN without the trailing dot or a full FQDN"`
		Type    string        `json:"type" jsonschema:"record type from list_record_types, case-insensitive"`
		TTL     int           `json:"ttl,omitempty" jsonschema:"TTL in seconds; 0/omitted inherits the existing RRSet TTL or defaults to 3600"`
		Records []recordInput `json:"records" jsonschema:"at least one record; existing sibling records of the same name+type are preserved (POST = append, not replace)"`
	}
	type writeOut struct {
		Message string `json:"message"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_record",
		Title:       "Create record",
		Description: "Append record(s) to a zone's RRSet. Existing records with the same name+type are preserved — to replace an RRSet use update_record. MX/SRV: give the priority in each record's priority field, the target in content. TXT/SPF: give the bare text, quoting is automatic.",
		Annotations: writeAnnotations(false, false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in createRecordIn) (*mcp.CallToolResult, writeOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, writeOut{}, terr
		}
		if terr := validateZoneArg(in.Zone); terr != nil {
			return nil, writeOut{}, terr
		}
		rrset := buildRRSet(in.Zone, in.Name, in.Type, in.TTL, in.Records)
		if err := dnsops.ValidateRecordSet(&rrset, in.Zone); err != nil {
			return nil, writeOut{}, toolErrorf("VALIDATION_ERROR", "%s", err.Error())
		}
		if err := ops.CreateRecord(ctx, user, in.Zone, rrset, dnsops.SourceMCP); err != nil {
			if te, cause := mapServiceError(err); te != nil {
				return nil, writeOut{}, callTool("create_record", te, cause)
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("created %s record %s (%d record(s) submitted)", rrset.Type, rrset.Name, len(in.Records))}}}, writeOut{Message: "record created"}, nil
	})

	// -- update_record ----------------------------------------------------
	type updateRecordIn struct {
		Zone          string        `json:"zone" jsonschema:"canonical zone ID as returned by list_zones (lowercase with trailing dot, e.g. \"example.com.\")"`
		Name          string        `json:"name" jsonschema:"record name; accepts \"@\" (apex), a bare label (\"www\"), an FQDN without the trailing dot or a full FQDN"`
		Type          string        `json:"type" jsonschema:"record type, case-insensitive"`
		TTL           int           `json:"ttl,omitempty" jsonschema:"TTL in seconds; 0/omitted keeps the RRSet's current TTL"`
		Records       []recordInput `json:"records" jsonschema:"the COMPLETE new record list — records not listed here are deleted (REPLACE semantics)"`
		ClearComments bool          `json:"clear_comments,omitempty" jsonschema:"drop all existing comments on the RRSet"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "update_record",
		Title:       "Update record",
		Description: "REPLACE an RRSet: the submitted record list becomes the whole set (idempotent; destructive — omitted records are removed). List the current records first if you only want to add one. ClearComments drops the RRSet's comments.",
		Annotations: writeAnnotations(true, true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in updateRecordIn) (*mcp.CallToolResult, writeOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, writeOut{}, terr
		}
		if terr := validateZoneArg(in.Zone); terr != nil {
			return nil, writeOut{}, terr
		}
		rrset := buildRRSet(in.Zone, in.Name, in.Type, in.TTL, in.Records)
		if in.ClearComments {
			rrset.Comments = &models.CommentPatch{Clear: true}
		}
		if err := dnsops.PrepareValidatedRecordSet(&rrset, in.Zone); err != nil {
			return nil, writeOut{}, toolErrorf("VALIDATION_ERROR", "%s", err.Error())
		}
		if err := ops.UpdateRecord(ctx, user, in.Zone, rrset, dnsops.SourceMCP); err != nil {
			if te, cause := mapServiceError(err); te != nil {
				return nil, writeOut{}, callTool("update_record", te, cause)
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("updated %s record %s (%d record(s) now in the set)", rrset.Type, rrset.Name, len(rrset.Records))}}}, writeOut{Message: "record updated"}, nil
	})

	// -- delete_record ----------------------------------------------------
	type deleteRecordIn struct {
		Zone string `json:"zone" jsonschema:"canonical zone ID as returned by list_zones (lowercase with trailing dot, e.g. \"example.com.\")"`
		Name string `json:"name" jsonschema:"record name; accepts \"@\" (apex), a bare label (\"www\"), an FQDN without the trailing dot or a full FQDN"`
		Type string `json:"type" jsonschema:"record type of the RRSet to delete, case-insensitive"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delete_record",
		Title:       "Delete record",
		Description: "Delete an entire RRSet (every record sharing the name+type). Idempotent: deleting a set that no longer exists succeeds.",
		Annotations: writeAnnotations(true, true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in deleteRecordIn) (*mcp.CallToolResult, writeOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, writeOut{}, terr
		}
		if terr := validateZoneArg(in.Zone); terr != nil {
			return nil, writeOut{}, terr
		}
		// Canonicalise exactly like the REST DELETE handler: uppercase type,
		// validate both, name expanded against the zone.
		rrType := dnsops.CanonicalRecordType(in.Type)
		if err := validators.ValidateRecordType(rrType); err != nil {
			return nil, writeOut{}, toolErrorf("VALIDATION_ERROR", "%s", err.Error())
		}
		if err := validators.ValidateRecordName(in.Name); err != nil {
			return nil, writeOut{}, toolErrorf("VALIDATION_ERROR", "%s", err.Error())
		}
		name := dnsops.NormalizeRecordName(in.Name, in.Zone)
		if err := ops.DeleteRecord(ctx, user, in.Zone, name, rrType, dnsops.SourceMCP); err != nil {
			if te, cause := mapServiceError(err); te != nil {
				return nil, writeOut{}, callTool("delete_record", te, cause)
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("deleted %s record %s", rrType, name)}}}, writeOut{Message: "record deleted"}, nil
	})

	// -- create_zone ------------------------------------------------------
	type createZoneIn struct {
		Name        string   `json:"name" jsonschema:"zone name, e.g. \"example.com\" (canonicalised: lowercased, trailing dot added)"`
		Kind        string   `json:"kind,omitempty" jsonschema:"Native (default), Master or Slave"`
		Nameservers []string `json:"nameservers" jsonschema:"nameserver hostnames for the initial NS records (Master/Native)"`
	}
	type createZoneOut struct {
		Zone    models.Zone `json:"zone"`
		Message string      `json:"message"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_zone",
		Title:       "Create zone",
		Description: "Create a new zone. ADMIN KEY REQUIRED. Name and nameservers are canonicalised (lowercase, trailing dot); omit kind for Native.",
		Annotations: writeAnnotations(false, false),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in createZoneIn) (*mcp.CallToolResult, createZoneOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, createZoneOut{}, terr
		}
		req, err := dnsops.ValidateZoneCreate(models.ZoneCreateRequest{Name: in.Name, Kind: in.Kind, Nameservers: in.Nameservers})
		if err != nil {
			return nil, createZoneOut{}, toolErrorf("VALIDATION_ERROR", "%s", err.Error())
		}
		zone, err := ops.CreateZone(ctx, user, req, dnsops.SourceMCP)
		if err != nil {
			if te, cause := mapServiceError(err); te != nil {
				return nil, createZoneOut{}, callTool("create_zone", te, cause)
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("created zone %s (%s)", zone.Name, zone.Kind)}}}, createZoneOut{Zone: *zone, Message: "zone created"}, nil
	})

	// -- delete_zone ------------------------------------------------------
	type deleteZoneIn struct {
		Zone string `json:"zone" jsonschema:"canonical zone ID as returned by list_zones (lowercase with trailing dot, e.g. \"example.com.\")"`
	}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delete_zone",
		Title:       "Delete zone",
		Description: "Delete a zone and purge its group grants. ADMIN KEY REQUIRED. Destructive and irrevocable.",
		Annotations: writeAnnotations(true, true),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in deleteZoneIn) (*mcp.CallToolResult, writeOut, error) {
		user, terr := userFromContext(ctx)
		if terr != nil {
			return nil, writeOut{}, terr
		}
		if terr := validateZoneArg(in.Zone); terr != nil {
			return nil, writeOut{}, terr
		}
		if err := ops.DeleteZone(ctx, user, in.Zone, dnsops.SourceMCP); err != nil {
			if te, cause := mapServiceError(err); te != nil {
				return nil, writeOut{}, callTool("delete_zone", te, cause)
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("deleted zone %s", in.Zone)}}}, writeOut{Message: "zone deleted"}, nil
	})
}
