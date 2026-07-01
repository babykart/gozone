package models

import (
	"fmt"
	"strconv"
	"strings"
)

// recordTypeSpec describes how a DNS record type's human/form content maps to
// and from the PowerDNS wire representation. It is the single source of truth
// for the two type-dependent quirks GoZone has to handle:
//
//   - priority types (MX, SRV) carry a leading numeric priority in their wire
//     content, because PowerDNS rejects a separate "priority" element;
//   - quoted types (TXT, SPF) are stored wrapped in double quotes.
type recordTypeSpec struct {
	hasPriority bool
	quoted      bool
	// fqdnTarget indicates that the record content is (or ends with) a DNS
	// name that PowerDNS requires as a fully-qualified domain name with a
	// trailing dot. For CNAME/NS/PTR/ALIAS/DNAME the entire content is the
	// target. For MX/SRV/AFSDB/NAPTR the target is the last space-separated
	// field (for MX/SRV this is after the priority has been embedded by
	// JoinPriority).
	fqdnTarget bool
	// fqdnFieldIndices lists the zero-based indices of space-separated fields
	// that are DNS names requiring a trailing dot, for multi-field record
	// types where FQDNs are NOT in the last position. Used by SOA (mname,
	// rname = fields 0,1), RP (rmailbx, emailbx = fields 0,1), MINFO (same),
	// and NSEC (next_domain = field 0). When nil, no per-field normalisation
	// is applied.
	fqdnFieldIndices []int
	// wireFields is the number of space-separated fields the content has once
	// the priority is already embedded (PowerDNS read format). It distinguishes
	// form input ("weight port target" → 3 fields for SRV) from wire content
	// ("priority weight port target" → 4 fields) so JoinPriority does not strip
	// a priority that was never there. Zero when hasPriority is false.
	wireFields int
}

var recordTypeSpecs = map[string]recordTypeSpec{
	"MX":    {hasPriority: true, fqdnTarget: true, wireFields: 2},
	"SRV":   {hasPriority: true, fqdnTarget: true, wireFields: 4},
	"TXT":   {quoted: true},
	"SPF":   {quoted: true},
	"CNAME": {fqdnTarget: true},
	"DNAME": {fqdnTarget: true},
	"NS":    {fqdnTarget: true},
	"PTR":   {fqdnTarget: true},
	"ALIAS": {fqdnTarget: true},
	"AFSDB": {fqdnTarget: true},
	"NAPTR": {fqdnTarget: true},
	"SOA":   {fqdnFieldIndices: []int{0, 1}},
	"RP":    {fqdnFieldIndices: []int{0, 1}},
	"MINFO": {fqdnFieldIndices: []int{0, 1}},
	"NSEC":  {fqdnFieldIndices: []int{0}},
}

// specFor returns the spec for recordType, or the zero value (no priority, not
// quoted) for types with no special wire handling.
func specFor(recordType string) recordTypeSpec {
	return recordTypeSpecs[recordType]
}

// TypeHasPriority reports whether recordType carries a leading numeric priority
// in its PowerDNS wire content (MX, SRV).
func TypeHasPriority(recordType string) bool {
	return specFor(recordType).hasPriority
}

// TypeIsQuoted reports whether PowerDNS stores recordType content wrapped in
// double quotes (TXT, SPF).
func TypeIsQuoted(recordType string) bool {
	return specFor(recordType).quoted
}

// TypeIsFQDNTarget reports whether recordType's content is (or ends with) a
// DNS name that PowerDNS requires as a fully-qualified domain name with a
// trailing dot. This covers CNAME, NS, PTR, ALIAS (the entire content is the
// target) and MX, SRV (the target is the last space-separated field, after
// priority embedding).
func TypeIsFQDNTarget(recordType string) bool {
	return specFor(recordType).fqdnTarget
}

// EnsureTrailingDot appends a "." to content when it does not already end
// with one. PowerDNS rejects CNAME/NS/PTR/MX/SRV targets that lack the
// trailing dot; this normalisation is applied after priority embedding so
// that "10 mail.example.com" becomes "10 mail.example.com.".
func EnsureTrailingDot(content string) string {
	if content == "" || strings.HasSuffix(content, ".") {
		return content
	}
	return content + "."
}

// TypeHasFQDNFields reports whether recordType has specific space-separated
// fields that are DNS names requiring a trailing dot (SOA, RP, MINFO, NSEC).
// These types use per-field normalisation via EnsureTrailingDotFields rather
// than the whole-content EnsureTrailingDot, because their FQDN fields are not
// in the last position.
func TypeHasFQDNFields(recordType string) bool {
	return len(specFor(recordType).fqdnFieldIndices) > 0
}

// FQDNFieldIndices returns the zero-based indices of the space-separated
// fields that are DNS names requiring a trailing dot. Returns nil for types
// without per-field FQDN normalisation.
func FQDNFieldIndices(recordType string) []int {
	return specFor(recordType).fqdnFieldIndices
}

// EnsureTrailingDotFields normalises specific space-separated fields to end
// with a trailing dot. Indices are zero-based. Fields that already end with
// a dot are left unchanged. Fields outside the content range are skipped.
func EnsureTrailingDotFields(content string, indices []int) string {
	if len(indices) == 0 || content == "" {
		return content
	}
	fields := strings.Fields(content)
	for _, idx := range indices {
		if idx >= 0 && idx < len(fields) && !strings.HasSuffix(fields[idx], ".") {
			fields[idx] = fields[idx] + "."
		}
	}
	return strings.Join(fields, " ")
}

// SplitPriority detaches the leading priority from a priority-bearing record's
// PowerDNS wire content (the read direction). ok reports whether a priority was
// parsed; callers must rely on it rather than testing for a non-zero priority,
// since 0 is a valid priority and must still be stripped from the content. For
// non-priority types it returns (0, content, false).
func SplitPriority(recordType, content string) (priority int, rest string, ok bool) {
	if !TypeHasPriority(recordType) {
		return 0, content, false
	}
	parts := strings.SplitN(content, " ", 2)
	if len(parts) != 2 {
		return 0, content, false
	}
	prio, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, content, false
	}
	return prio, parts[1], true
}

// JoinPriority embeds priority into a priority-bearing record's content for the
// PowerDNS PATCH wire format (the write direction). If content already carries a
// priority (wire data fed back in) it is stripped first so the value is not
// duplicated. For non-priority types content is returned unchanged.
func JoinPriority(recordType string, priority int, content string) string {
	spec := specFor(recordType)
	if !spec.hasPriority {
		return content
	}
	tokens := strings.Fields(content)
	if len(tokens) >= spec.wireFields {
		// Only strip an already-embedded priority when the leading token is a
		// valid 16-bit unsigned integer (0-65535). strconv.Atoi would also
		// accept negative or out-of-range values like "-5" (m52), stripping a
		// token that was never a real priority.
		if _, err := strconv.ParseUint(tokens[0], 10, 16); err == nil {
			content = strings.Join(tokens[1:], " ")
		}
	}
	return fmt.Sprintf("%d %s", priority, content)
}

// QuoteContent wraps content in double quotes for quoted types (TXT, SPF) when
// it is not already quoted. Internal backslashes are doubled and double quotes
// are escaped so the resulting string is well-formed for PowerDNS wire format.
// Non-quoted types and empty content pass through. Only a leading double quote
// counts as "already quoted" — a single quote (') has no meaning in DNS wire
// format and is treated as a literal character (m51).
func QuoteContent(recordType, content string) string {
	if !TypeIsQuoted(recordType) || content == "" {
		return content
	}
	if strings.HasPrefix(content, `"`) {
		return content
	}
	// Escape backslashes FIRST, then double quotes — order matters so the
	// backslashes introduced by quote-escaping are not themselves doubled.
	escaped := strings.ReplaceAll(content, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// UnquoteContent removes one pair of surrounding double quotes from quoted types
// (TXT, SPF) and unescapes escaped internal quotes and backslashes, leaving
// other types and unquoted content unchanged.
func UnquoteContent(recordType, content string) string {
	if !TypeIsQuoted(recordType) {
		return content
	}
	if len(content) >= 2 && strings.HasPrefix(content, `"`) && strings.HasSuffix(content, `"`) {
		return unescapeQuotedContent(content[1 : len(content)-1])
	}
	return content
}

// unescapeQuotedContent reverses the escaping applied by QuoteContent:
// `\\` → `\` and `\"` → `"`. A single left-to-right scan is required because
// sequential strings.ReplaceAll would create false matches (e.g. `\\"`
// unescapes to `\"`, not `"`).
func unescapeQuotedContent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				b.WriteByte('\\')
				i++
			case '"':
				b.WriteByte('"')
				i++
			default:
				b.WriteByte(s[i])
			}
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
