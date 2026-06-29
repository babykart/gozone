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
	// trailing dot. For CNAME/NS/PTR/ALIAS the entire content is the target.
	// For MX/SRV the target is the last space-separated field, after the
	// priority has been embedded by JoinPriority.
	fqdnTarget bool
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
	"NS":    {fqdnTarget: true},
	"PTR":   {fqdnTarget: true},
	"ALIAS": {fqdnTarget: true},
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
		if _, err := strconv.Atoi(tokens[0]); err == nil {
			content = strings.Join(tokens[1:], " ")
		}
	}
	return fmt.Sprintf("%d %s", priority, content)
}

// QuoteContent wraps content in double quotes for quoted types (TXT, SPF) when
// it is not already quoted. Internal double quotes are escaped with a backslash
// so the resulting string is well-formed for PowerDNS. Non-quoted types and
// empty content pass through.
func QuoteContent(recordType, content string) string {
	if !TypeIsQuoted(recordType) || content == "" {
		return content
	}
	if strings.HasPrefix(content, `"`) || strings.HasPrefix(content, `'`) {
		return content
	}
	return `"` + strings.ReplaceAll(content, `"`, `\"`) + `"`
}

// UnquoteContent removes one pair of surrounding double quotes from quoted types
// (TXT, SPF) and unescapes escaped internal quotes, leaving other types and
// unquoted content unchanged.
func UnquoteContent(recordType, content string) string {
	if !TypeIsQuoted(recordType) {
		return content
	}
	if len(content) >= 2 && strings.HasPrefix(content, `"`) && strings.HasSuffix(content, `"`) {
		return strings.ReplaceAll(content[1:len(content)-1], `\"`, `"`)
	}
	return content
}
