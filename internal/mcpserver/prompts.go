package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/babykart/gozone/internal/validators"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerPrompts adds the MCP prompts (MCP_PLAN.md §3.3): ready-made
// instruction templates that guide an agent through a DNS review or a safe
// record replacement using the tools above. Prompts carry no data of their
// own — every fact they need is fetched through the tools, under the key's
// authorization — so they are registered regardless of mcp.read_only
// (a prompt can only instruct; the write tools still enforce the gate).
func registerPrompts(srv *mcp.Server) {
	// -- audit_zone -------------------------------------------------------
	srv.AddPrompt(&mcp.Prompt{
		Name:        "audit_zone",
		Title:       "Audit a DNS zone",
		Description: "Review one zone for common DNS misconfigurations: SOA sanity, apex NS, CNAME rules, TTL consistency, SPF/DMARC. Read-only: the agent gathers facts with list_records/get_zone and reports findings; it must propose, not apply, fixes.",
		Arguments: []*mcp.PromptArgument{{
			Name:        "zone",
			Description: `Canonical zone ID as returned by list_zones (lowercase with trailing dot, e.g. "example.com.").`,
			Required:    true,
		}},
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		zone := strings.TrimSpace(req.Params.Arguments["zone"])
		if err := validators.ValidateDomainName(zone); err != nil {
			return nil, toolErrorf("VALIDATION_ERROR", "invalid zone: %s", err.Error())
		}
		return &mcp.GetPromptResult{
			Description: "DNS audit of " + zone,
			Messages: []*mcp.PromptMessage{{
				Role: mcp.Role("user"),
				Content: &mcp.TextContent{Text: fmt.Sprintf(`Audit the DNS zone %s and report findings. Do NOT change anything: gather facts with the tools, analyse, then propose fixes for review.

Steps:
1. Call get_zone for %s (kind, serial, DNSSEC state).
2. Call list_records for %s and review every RRSet against this checklist:
   - SOA: exactly one, at the apex. Sane values: refresh >= retry, retry < expire, expire > refresh + retry, negative-TTL <= TTL. Flag a serial that looks stale only if you can corroborate it — do not guess.
   - NS: present at the apex, at least two distinct nameservers, each resolvable (name sanity only; you cannot query DNS from here).
   - CNAME: forbidden at the apex and alongside any other record type on the same name (RFC 1034 §3.6.2). Flag every violation.
   - TTL consistency: flag records that likely want a low TTL but have a high one (or the reverse), e.g. a migration candidate at 86400, or an apex record at 60 with no ongoing change. Note RRSet-level TTLs apply to every record of the set.
   - FQDN hygiene: MX/SRV/CNAME/NS/PTR targets must end with a trailing dot; flag any content PowerDNS may be storing in a non-canonical form.
   - SPF: at most one SPF record per name (RFC 7208 §3.2); warn if the "v=spf1" mechanism list exceeds ~10 DNS-lookups (include/a/mx/ptr).
   - DMARC: if any name sends mail (MX or SPF present), check a _dmarc record exists; report its absence as a recommendation, not an error.
3. Summarise as a table: check, status (OK / warning / error), details, suggested fix.
4. End with the proposed fixes only — no tool call that writes.`, zone, zone, zone)},
			}},
		}, nil
	})

	// -- migrate_record ---------------------------------------------------
	srv.AddPrompt(&mcp.Prompt{
		Name:        "migrate_record",
		Title:       "Safely replace a record",
		Description: "Guided replacement of one RRSet: read the current records, show the operator the before/after, apply with update_record (REPLACE semantics — every record to keep must be listed), then verify. Includes rollback instructions.",
		Arguments: []*mcp.PromptArgument{
			{
				Name:        "zone",
				Description: `Canonical zone ID as returned by list_zones (lowercase with trailing dot, e.g. "example.com.").`,
				Required:    true,
			},
			{
				Name:        "name",
				Description: `Record name; accepts "@", a bare label ("www"), an FQDN without the trailing dot or a full FQDN.`,
				Required:    true,
			},
			{
				Name:        "type",
				Description: "Record type of the RRSet to replace, case-insensitive.",
				Required:    true,
			},
		},
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		args := req.Params.Arguments
		zone := strings.TrimSpace(args["zone"])
		name := strings.TrimSpace(args["name"])
		rtype := strings.ToUpper(strings.TrimSpace(args["type"]))
		if err := validators.ValidateDomainName(zone); err != nil {
			return nil, toolErrorf("VALIDATION_ERROR", "invalid zone: %s", err.Error())
		}
		if err := validators.ValidateRecordName(name); err != nil {
			return nil, toolErrorf("VALIDATION_ERROR", "invalid name: %s", err.Error())
		}
		if err := validators.ValidateRecordType(rtype); err != nil {
			return nil, toolErrorf("VALIDATION_ERROR", "invalid type: %s", err.Error())
		}

		return &mcp.GetPromptResult{
			Description: "Safe migration of " + rtype + " " + name + " in " + zone,
			Messages: []*mcp.PromptMessage{{
				Role: mcp.Role("user"),
				Content: &mcp.TextContent{Text: fmt.Sprintf(`Replace the %s record "%s" in zone %s safely. Follow this procedure exactly.

1. READ FIRST: call list_records on %s filtered to name "%s" and type %s. Record the current TTL and EVERY record of the set (content, priority, disabled) — update_record is a REPLACE: any record you omit from the submission is deleted.
2. SHOW THE PLAN: present a before/after table to the operator (current records vs intended records) and the intended TTL. Wait for confirmation before writing.
3. PREPARE the payload using the same rules as create_record:
   - keep the TTL unless the operator asked to change it (0 keeps the current one);
   - MX/SRV: one "priority" field per record, the target alone in "content";
   - TXT/SPF: bare text in "content", quoting is automatic;
   - FQDN targets without the trailing dot are accepted and canonicalised.
4. APPLY with update_record on %s, name "%s", type %s, submitting the COMPLETE new record list (kept records first, then the replacements).
5. VERIFY: call list_records again on the same name+type and show the operator the diff against the plan.
6. ROLLBACK: if the verification disagrees with the plan, re-submit the exact record list captured in step 1 (same contents, priorities and TTL) with update_record, then report.

If any step fails with VALIDATION_ERROR, fix the payload and retry once; surface any other error code (FORBIDDEN, ZONE_NOT_FOUND, CONFLICT...) to the operator instead of improvising.`, rtype, name, zone, zone, name, rtype, zone, name, rtype)},
			}},
		}, nil
	})
}
