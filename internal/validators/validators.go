// Package validators provides reusable input validation functions for
// domain names, DNS record names, DNS record types and contents, zone kinds,
// usernames, emails, and IP addresses.
package validators

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// rfc1035Label validates a single DNS label for use in a zone name or other
// strict-hostname context. RFC 1123 §2.1 relaxed the original RFC 1035
// restriction to allow labels starting with a digit. Labels must start and end
// with a letter or digit, contain only letters, digits, and hyphens, and be at
// most 63 characters long.
var rfc1035Label = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// dnsLabel validates a single DNS label allowing underscores and wildcards.
// This is appropriate for record names (e.g. DKIM selectors like
// "selector._domainkey") and record content targets where PowerDNS permits
// underscores. Wildcard "*" is allowed as a standalone label.
var dnsLabel = regexp.MustCompile(`^([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?|\*)$`)

// zoneKindWhitelist is the set of zone kinds accepted by the PowerDNS API.
var zoneKindWhitelist = map[string]bool{
	"Native":   true,
	"Master":   true,
	"Slave":    true,
	"Producer": true,
	"Consumer": true,
}

// ValidateDomainName checks that a domain name conforms to RFC 1035.
//
// Rules:
//   - Non-empty, maximum 253 characters total
//   - Dot-separated labels, each label ≤ 63 characters
//   - Each label matches: ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$
//   - Trailing dots are allowed (FQDN notation) and stripped before validation
//
// Returns nil if valid, an error describing the violation otherwise.
func ValidateDomainName(name string) error {
	name = strings.TrimSuffix(name, ".")

	if len(name) == 0 {
		return fmt.Errorf("domain name must not be empty")
	}
	if len(name) > 253 {
		return fmt.Errorf("domain name exceeds 253 characters")
	}

	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("domain name contains an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q exceeds 63 characters", label)
		}
		if !rfc1035Label.MatchString(label) {
			return fmt.Errorf("label %q does not match RFC 1035 format", label)
		}
	}

	return nil
}

// ValidateDNSName checks that a DNS name is structurally valid, allowing
// underscores and wildcard labels. It is suitable for record names and record
// targets (CNAME, MX, SRV, etc.) where underscores are permitted.
func ValidateDNSName(name string) error {
	name = strings.TrimSuffix(name, ".")

	if len(name) == 0 {
		return fmt.Errorf("DNS name must not be empty")
	}
	if len(name) > 253 {
		return fmt.Errorf("DNS name exceeds 253 characters")
	}

	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("DNS name contains an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q exceeds 63 characters", label)
		}
		if !dnsLabel.MatchString(label) {
			return fmt.Errorf("label %q contains invalid characters", label)
		}
	}

	return nil
}

// ValidateRecordName checks that a record name is valid within a zone.
//
// It accepts:
//   - "@" for the zone apex
//   - Relative names (e.g. "www", "mail")
//   - Absolute names ending with a dot (e.g. "www.example.com.")
//   - Labels containing underscores (DKIM, _dnslink, etc.)
//   - Wildcard "*" as a label
func ValidateRecordName(name string) error {
	if name == "" {
		return fmt.Errorf("record name must not be empty")
	}
	if name == "@" {
		return nil
	}
	return ValidateDNSName(name)
}

// ValidateZoneKind checks that the given zone kind is supported by PowerDNS.
func ValidateZoneKind(kind string) error {
	if kind == "" {
		return fmt.Errorf("zone kind must not be empty")
	}
	if !zoneKindWhitelist[kind] {
		return fmt.Errorf("unsupported zone kind %q", kind)
	}
	return nil
}

// recordTypeWhitelist is the set of valid DNS record types recognized by
// PowerDNS. See https://doc.powerdns.com/authoritative/http-api/rrtypes.html.
var recordTypeWhitelist = map[string]bool{
	"A": true, "AAAA": true, "AFSDB": true, "ALIAS": true, "CAA": true,
	"CERT": true, "CNAME": true, "DNAME": true, "DNSKEY": true, "DS": true,
	"HINFO": true, "KEY": true, "LOC": true, "MINFO": true, "MX": true,
	"NAPTR": true, "NS": true, "NSEC": true, "NSEC3": true, "NSEC3PARAM": true,
	"OPENPGPKEY": true, "PTR": true, "RP": true, "RRSIG": true, "SOA": true,
	"SPF": true, "SRV": true, "SSHFP": true, "TLSA": true, "TXT": true,
	"URI": true,
}

// ValidateRecordType checks that the given DNS record type is supported.
//
// The whitelist is kept in sync with GetRecordTypes() in the handlers package.
// Returns nil if the type is valid, an error otherwise.
func ValidateRecordType(recordType string) error {
	upper := strings.ToUpper(recordType)
	if upper == "" {
		return fmt.Errorf("record type must not be empty")
	}
	if !recordTypeWhitelist[upper] {
		return fmt.Errorf("unsupported record type %q", recordType)
	}
	return nil
}

// usernameRegex requires 3 to 32 characters: alphanumeric, underscores,
// and hyphens. Must start with a letter.
var usernameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{2,31}$`)

// ValidateUsername checks that a username meets the application rules.
//
// Rules:
//   - 3 to 32 characters
//   - Must start with a letter
//   - May contain letters, digits, periods, underscores, and hyphens
//
// Returns nil if valid, an error describing the violation otherwise.
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username must not be empty")
	}
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username %q is invalid: must be 3-32 characters, start with a letter, and contain only letters, digits, periods, underscores, and hyphens", username)
	}
	return nil
}

// emailRegex is a pragmatic check: user@host, with basic format validation.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidateEmail checks that an email address has a reasonable format.
//
// Rules:
//   - Non-empty, maximum 254 characters
//   - Contains exactly one @
//   - Local part and domain part pass basic structural checks
//
// Returns nil if valid, an error describing the violation otherwise.
func ValidateEmail(email string) error {
	if len(email) == 0 {
		return fmt.Errorf("email must not be empty")
	}
	if len(email) > 254 {
		return fmt.Errorf("email exceeds 254 characters")
	}
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("email %q has an invalid format", email)
	}

	parts := strings.SplitN(email, "@", 3)
	if len(parts) != 2 {
		return fmt.Errorf("email must contain exactly one @")
	}
	localPart := parts[0]
	domain := parts[1]

	if len(localPart) == 0 {
		return fmt.Errorf("email local part must not be empty")
	}
	if len(localPart) > 64 {
		return fmt.Errorf("email local part exceeds 64 characters")
	}
	if !utf8.ValidString(domain) {
		return fmt.Errorf("email domain contains invalid UTF-8")
	}

	return nil
}

// ValidateIPAddress checks that a string is a valid IPv4 or IPv6 address.
//
// Returns nil if valid, an error otherwise.
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address must not be empty")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("%q is not a valid IP address", ip)
	}
	return nil
}

// ValidateIPv4 checks that a string is a valid IPv4 address.
func ValidateIPv4(ip string) error {
	if ip == "" {
		return fmt.Errorf("IPv4 address must not be empty")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("%q is not a valid IPv4 address", ip)
	}
	return nil
}

// ValidateIPv6 checks that a string is a valid IPv6 address.
func ValidateIPv6(ip string) error {
	if ip == "" {
		return fmt.Errorf("IPv6 address must not be empty")
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return fmt.Errorf("%q is not a valid IPv6 address", ip)
	}
	return nil
}

// ValidateRecordContent validates a DNS record's content field based on its
// record type. Different record types have different content format requirements:
//
//   - A: IPv4 address
//   - AAAA: IPv6 address
//   - CNAME, ALIAS, NS, PTR: DNS name (underscores allowed)
//   - MX: priority + FQDN, or just FQDN (priority handled separately)
//   - TXT, SPF: free text (quoted strings allowed)
//   - SOA: 7+ fields with valid 32-bit unsigned serial/refresh/retry/expire/minimum
//
// Returns nil if valid, an error describing the violation otherwise.
func ValidateRecordContent(recordType, content string) error {
	if content == "" {
		return fmt.Errorf("content must not be empty")
	}

	switch strings.ToUpper(recordType) {
	case "A":
		return ValidateIPv4(content)
	case "AAAA":
		return ValidateIPv6(content)
	case "CNAME", "ALIAS", "NS", "PTR", "DNAME":
		return ValidateDNSName(content)
	case "MINFO":
		parts := strings.Fields(content)
		if len(parts) != 2 {
			return fmt.Errorf("MINFO content must have exactly 2 fields: rmailbx emailbx")
		}
		if err := ValidateDNSName(parts[0]); err != nil {
			return fmt.Errorf("MINFO rmailbx: %w", err)
		}
		if err := ValidateDNSName(parts[1]); err != nil {
			return fmt.Errorf("MINFO emailbx: %w", err)
		}
		return nil
	case "MX":
		// MX content can be "priority target" or just "target"
		// The priority is handled as a separate field, so content is the FQDN
		return ValidateDNSName(content)
	case "SOA":
		parts := strings.Fields(content)
		if len(parts) < 7 {
			return fmt.Errorf("SOA content requires at least 7 fields: mname rname serial refresh retry expire minimum")
		}
		if err := ValidateDNSName(strings.TrimSuffix(parts[0], ".")); err != nil {
			return fmt.Errorf("SOA mname: %w", err)
		}
		if err := ValidateDNSName(strings.TrimSuffix(parts[1], ".")); err != nil {
			return fmt.Errorf("SOA rname: %w", err)
		}
		soaFields := []struct {
			name  string
			value string
		}{
			{"serial", parts[2]},
			{"refresh", parts[3]},
			{"retry", parts[4]},
			{"expire", parts[5]},
			{"minimum", parts[6]},
		}
		for _, f := range soaFields {
			n, err := strconv.ParseUint(f.value, 10, 32)
			if err != nil {
				return fmt.Errorf("SOA %s %q is not a valid 32-bit unsigned integer", f.name, f.value)
			}
			if f.name == "serial" && n == 0 {
				return fmt.Errorf("SOA serial must be greater than 0")
			}
		}
		return nil
	case "SRV":
		parts := strings.Fields(content)
		if len(parts) < 3 {
			return fmt.Errorf("SRV content must have at least 3 fields: priority|weight port target")
		}
		return ValidateDNSName(parts[len(parts)-1])
	case "CAA":
		parts := strings.Fields(content)
		if len(parts) != 3 {
			return fmt.Errorf("CAA content must have exactly 3 fields: flags tag value")
		}
		flags, err := strconv.ParseUint(parts[0], 10, 8)
		if err != nil {
			return fmt.Errorf("CAA flags %q must be an 8-bit unsigned integer", parts[0])
		}
		if flags != 0 && flags != 128 {
			return fmt.Errorf("CAA flags %d is not supported; use 0 or 128", flags)
		}
		switch parts[1] {
		case "issue", "issuewild", "iodef":
			// valid tags
		default:
			return fmt.Errorf("CAA tag %q is not valid; use issue, issuewild or iodef", parts[1])
		}
		if parts[2] == "" {
			return fmt.Errorf("CAA value must not be empty")
		}
		return nil
	case "TXT", "SPF":
		return nil
	default:
		return nil
	}
}
