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
	"unicode"
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
//
// Per RFC 4592 a wildcard "*" is valid only as the leftmost label and must not
// appear elsewhere (m48): "*.*.example.com" and "foo.*.example.com" are
// rejected.
func ValidateDNSName(name string) error {
	name = strings.TrimSuffix(name, ".")

	if len(name) == 0 {
		return fmt.Errorf("DNS name must not be empty")
	}
	if len(name) > 253 {
		return fmt.Errorf("DNS name exceeds 253 characters")
	}

	labels := strings.Split(name, ".")
	for i, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("DNS name contains an empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q exceeds 63 characters", label)
		}
		if !dnsLabel.MatchString(label) {
			return fmt.Errorf("label %q contains invalid characters", label)
		}
		// RFC 4592: a wildcard label is valid only in the leftmost position.
		if label == "*" && i != 0 {
			return fmt.Errorf("wildcard label %q is only valid as the leftmost label", label)
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

// metadataKindWhitelist is the set of PowerDNS zone metadata kinds exposed in
// the UI. Kept in sync with GetMetadataKinds() in the handlers package.
var metadataKindWhitelist = map[string]bool{
	"ALLOW-AXFR-FROM":           true,
	"ALLOW-DNSUPDATE-FROM":      true,
	"ALSO-NOTIFY":               true,
	"AXFR-MASTER-TSIG":          true,
	"AXFR-SOURCE":               true,
	"FORWARD-DNSSEC":            true,
	"GSS-ACCEPTOR-PRINCIPAL":    true,
	"GSS-ALLOW-AXFR-PRINCIPALS": true,
	"IXFR":                      true,
	"LUA-AXFR-SCRIPT":           true,
	"NOTIFY-DNSUPDATE":          true,
	"NSEC3NARROW":               true,
	"NSEC3PARAM":                true,
	"PRESIGNED":                 true,
	"PUBLISH-CDNSKEY":           true,
	"PUBLISH-CDS":               true,
	"SOA-EDIT":                  true,
	"SOA-EDIT-API":              true,
	"SOA-EDIT-DNSUPDATE":        true,
	"TSIG-ALLOW-AXFR":           true,
	"TSIG-ALLOW-DNSUPDATE":      true,
}

// ValidateMetadataKind checks that the given PowerDNS zone metadata kind is
// supported. The whitelist is kept in sync with GetMetadataKinds() in the
// handlers package. Comparison is exact (canonical uppercase identifiers).
func ValidateMetadataKind(kind string) error {
	if kind == "" {
		return fmt.Errorf("metadata kind must not be empty")
	}
	if !metadataKindWhitelist[kind] {
		return fmt.Errorf("unsupported metadata kind %q", kind)
	}
	return nil
}

// dnssecAlgorithmWhitelist is the set of DNSSEC algorithm names supported by
// PowerDNS. Kept in sync with models.DNSSECAlgorithms().
var dnssecAlgorithmWhitelist = map[string]bool{
	"rsasha256": true,
	"rsasha512": true,
	"ecdsa256":  true,
	"ecdsa384":  true,
	"ed25519":   true,
	"ed448":     true,
}

// ValidateDNSSECAlgorithm checks that the given DNSSEC algorithm name is
// supported. Kept in sync with models.DNSSECAlgorithms(). Comparison is
// case-insensitive (algorithm names are conventionally lowercase); the
// canonical lowercase value is what reaches PowerDNS.
func ValidateDNSSECAlgorithm(algorithm string) error {
	if algorithm == "" {
		return fmt.Errorf("algorithm must not be empty")
	}
	if !dnssecAlgorithmWhitelist[strings.ToLower(algorithm)] {
		return fmt.Errorf("unsupported DNSSEC algorithm %q", algorithm)
	}
	return nil
}

// tsigAlgorithmWhitelist is the set of TSIG algorithms accepted by PowerDNS.
// Kept in sync with tsigAlgorithms() in the handlers package.
var tsigAlgorithmWhitelist = map[string]bool{
	"hmac-md5":    true,
	"hmac-sha1":   true,
	"hmac-sha256": true,
	"hmac-sha512": true,
}

// ValidateTSIGAlgorithm checks that the given TSIG algorithm is supported.
// Kept in sync with tsigAlgorithms() in the handlers package. Comparison is
// case-insensitive (algorithm names are conventionally lowercase).
func ValidateTSIGAlgorithm(algorithm string) error {
	if algorithm == "" {
		return fmt.Errorf("algorithm must not be empty")
	}
	if !tsigAlgorithmWhitelist[strings.ToLower(algorithm)] {
		return fmt.Errorf("unsupported TSIG algorithm %q", algorithm)
	}
	return nil
}

// MaxUsernameLength is the maximum length in bytes of a valid username, as
// enforced by usernameRegex. Exported so callers that need to reason about
// username validity (e.g. bounding the size of usernames used as rate-limit
// bucket keys) stay in sync with the validation rules.
const MaxUsernameLength = 32

// usernameRegex requires 3 to MaxUsernameLength characters: alphanumeric,
// underscores, and hyphens. Must start with a letter.
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

// roleWhitelist is the set of roles recognised by GoZone. Kept in sync with
// the user_create.html / user_edit.html role <select> options and
// models.User.IsAdmin.
var roleWhitelist = map[string]bool{
	"admin": true,
	"user":  true,
}

// ValidateRole checks that the given user role is one of the supported values
// ("admin" or "user"). Returns nil if valid, an error otherwise.
func ValidateRole(role string) error {
	if role == "" {
		return fmt.Errorf("role must not be empty")
	}
	if !roleWhitelist[role] {
		return fmt.Errorf("unsupported role %q", role)
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

// ValidateIPv4 checks that a string is a valid IPv4 address. IPv6 spellings
// are rejected wholesale, including the IPv4-mapped form: net.ParseIP's
// To4() is non-nil for "::ffff:192.0.2.1", so without the explicit colon
// check a mapped literal passed validation here and was only rejected later
// by PowerDNS, with a generic upstream error instead of a precise one.
func ValidateIPv4(ip string) error {
	if ip == "" {
		return fmt.Errorf("IPv4 address must not be empty")
	}
	if strings.Contains(ip, ":") {
		return fmt.Errorf("%q is not a valid IPv4 address", ip)
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

// hexString matches a non-empty hexadecimal string (digests, fingerprints,
// NSEC3 salts). Used to sanity-check opaque hex blob fields.
var hexString = regexp.MustCompile(`^[0-9A-Fa-f]+$`)

// base64String matches a non-empty standard-alphabet base64 string with
// optional trailing padding. Used to sanity-check opaque key/blob fields
// (DNSKEY/KEY public keys, RRSIG signatures, CERT/OPENPGPKEY payloads) without
// strict length decoding, which would risk false positives on legitimate keys.
var base64String = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

// validateUintField checks that s is a base-10 unsigned integer that fits in
// bits bits (e.g. 8, 16, 32). name is included in the error message.
func validateUintField(s, name string, bits int) error {
	if _, err := strconv.ParseUint(s, 10, bits); err != nil {
		return fmt.Errorf("%s %q is not a valid %d-bit unsigned integer", name, s, bits)
	}
	return nil
}

// validateRRSIGTime checks that s is a 14-digit RRSIG time stamp
// (YYYYMMDDHHMMSS per RFC 4034 §3.2). It does not validate the date itself,
// only the digit format, since PowerDNS enforces semantic validity.
func validateRRSIGTime(s, name string) error {
	if len(s) != 14 {
		return fmt.Errorf("RRSIG %s %q must be 14 digits (YYYYMMDDHHMMSS)", name, s)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return fmt.Errorf("RRSIG %s %q must be 14 digits (YYYYMMDDHHMMSS)", name, s)
		}
	}
	return nil
}

// ValidateRecordContent validates a DNS record's content field based on its
// record type. Different record types have different content format requirements:
//
//   - A: IPv4 address
//   - AAAA: IPv6 address
//   - CNAME, ALIAS, NS, PTR, DNAME: DNS name (underscores allowed)
//   - MX: priority + FQDN, or just FQDN (priority handled separately)
//   - TXT, SPF: free text (quoted strings allowed)
//   - SOA: exactly 7 fields with valid 32-bit unsigned serial/refresh/retry/expire/minimum, all > 0
//
// All other whitelisted record types (AFSDB, CERT, DNSKEY, DS, HINFO, KEY, LOC,
// NAPTR, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY, RP, RRSIG, SSHFP, TLSA, URI) are
// structurally validated (field count, numeric ranges, DNS-name fields, hex/base64
// blobs) so no whitelisted type is accepted without a content check (m47). The
// default therefore rejects unknown types rather than silently accepting them.
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
		if len(parts) != 7 {
			return fmt.Errorf("SOA content requires exactly 7 fields: mname rname serial refresh retry expire minimum")
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
			// All SOA timers and the serial must be strictly positive. A 0 value
			// for any of them is a misconfiguration (e.g. expire 0 expires the
			// zone immediately) — the check is applied uniformly rather than
			// only to the serial (m50).
			if n == 0 {
				return fmt.Errorf("SOA %s must be greater than 0", f.name)
			}
		}
		return nil
	case "SRV":
		// SRV content is "<weight> <port> <target>" with the priority carried
		// separately (validated via ValidateRecordPriority). A 4-field form with
		// the priority embedded is also tolerated.
		parts := strings.Fields(content)
		if len(parts) < 3 || len(parts) > 4 {
			return fmt.Errorf("SRV content must have 3 or 4 fields: [priority] weight port target")
		}
		// weight and port sit immediately before the target (last field); the
		// optional leading field is the priority.
		if err := validateUintField(parts[len(parts)-3], "SRV weight", 16); err != nil {
			return err
		}
		if err := validateUintField(parts[len(parts)-2], "SRV port", 16); err != nil {
			return err
		}
		if err := ValidateDNSName(parts[len(parts)-1]); err != nil {
			return fmt.Errorf("SRV target: %w", err)
		}
		return nil
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
	case "RP":
		// RFC 1183: <rmailbx> <emailbx> — two DNS names.
		parts := strings.Fields(content)
		if len(parts) != 2 {
			return fmt.Errorf("RP content must have exactly 2 fields: rmailbx emailbx")
		}
		if err := ValidateDNSName(parts[0]); err != nil {
			return fmt.Errorf("RP rmailbx: %w", err)
		}
		if err := ValidateDNSName(parts[1]); err != nil {
			return fmt.Errorf("RP emailbx: %w", err)
		}
		return nil
	case "AFSDB":
		// RFC 1183: <subtype> <hostname>.
		parts := strings.Fields(content)
		if len(parts) != 2 {
			return fmt.Errorf("AFSDB content must have exactly 2 fields: subtype hostname")
		}
		if err := validateUintField(parts[0], "AFSDB subtype", 16); err != nil {
			return err
		}
		if err := ValidateDNSName(parts[1]); err != nil {
			return fmt.Errorf("AFSDB hostname: %w", err)
		}
		return nil
	case "HINFO":
		// RFC 1035: <cpu> <os>. Tolerate quoted forms by requiring at least the
		// two fields be present.
		parts := strings.Fields(content)
		if len(parts) < 2 {
			return fmt.Errorf("HINFO content must have 2 fields: cpu os")
		}
		return nil
	case "NAPTR":
		// RFC 3403: <order> <pref> <flags> <service> <regexp> <replacement>.
		parts := strings.Fields(content)
		if len(parts) != 6 {
			return fmt.Errorf("NAPTR content must have exactly 6 fields: order preference flags service regexp replacement")
		}
		if err := validateUintField(parts[0], "NAPTR order", 16); err != nil {
			return err
		}
		if err := validateUintField(parts[1], "NAPTR preference", 16); err != nil {
			return err
		}
		if err := ValidateDNSName(parts[5]); err != nil {
			return fmt.Errorf("NAPTR replacement: %w", err)
		}
		return nil
	case "URI":
		// RFC 7553: <priority> <weight> <target>.
		parts := strings.Fields(content)
		if len(parts) < 3 {
			return fmt.Errorf("URI content must have at least 3 fields: priority weight target")
		}
		if err := validateUintField(parts[0], "URI priority", 16); err != nil {
			return err
		}
		if err := validateUintField(parts[1], "URI weight", 16); err != nil {
			return err
		}
		if strings.Trim(strings.Join(parts[2:], " "), `"`) == "" {
			return fmt.Errorf("URI target must not be empty")
		}
		return nil
	case "SSHFP":
		// RFC 4255: <algorithm> <fptype> <fingerprint>.
		parts := strings.Fields(content)
		if len(parts) != 3 {
			return fmt.Errorf("SSHFP content must have exactly 3 fields: algorithm fptype fingerprint")
		}
		if err := validateUintField(parts[0], "SSHFP algorithm", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[1], "SSHFP fptype", 8); err != nil {
			return err
		}
		if !hexString.MatchString(parts[2]) {
			return fmt.Errorf("SSHFP fingerprint must be a hexadecimal string")
		}
		return nil
	case "TLSA":
		// RFC 6698: <usage> <selector> <matchingtype> <certificate>.
		parts := strings.Fields(content)
		if len(parts) != 4 {
			return fmt.Errorf("TLSA content must have exactly 4 fields: usage selector matchingtype certificate")
		}
		for i, name := range []string{"usage", "selector", "matchingtype"} {
			if err := validateUintField(parts[i], "TLSA "+name, 8); err != nil {
				return err
			}
		}
		if !hexString.MatchString(parts[3]) {
			return fmt.Errorf("TLSA certificate data must be a hexadecimal string")
		}
		return nil
	case "DS":
		// RFC 4034: <keytag> <algorithm> <digesttype> <digest>.
		parts := strings.Fields(content)
		if len(parts) != 4 {
			return fmt.Errorf("DS content must have exactly 4 fields: keytag algorithm digesttype digest")
		}
		if err := validateUintField(parts[0], "DS keytag", 16); err != nil {
			return err
		}
		if err := validateUintField(parts[1], "DS algorithm", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[2], "DS digesttype", 8); err != nil {
			return err
		}
		if !hexString.MatchString(parts[3]) {
			return fmt.Errorf("DS digest must be a hexadecimal string")
		}
		return nil
	case "DNSKEY", "KEY":
		// RFC 4034/2535: <flags> <protocol> <algorithm> <publickey>.
		rt := strings.ToUpper(recordType)
		parts := strings.Fields(content)
		if len(parts) != 4 {
			return fmt.Errorf("%s content must have exactly 4 fields: flags protocol algorithm publickey", rt)
		}
		if err := validateUintField(parts[0], rt+" flags", 16); err != nil {
			return err
		}
		if err := validateUintField(parts[1], rt+" protocol", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[2], rt+" algorithm", 8); err != nil {
			return err
		}
		if !base64String.MatchString(parts[3]) {
			return fmt.Errorf("%s publickey must be a base64-encoded string", rt)
		}
		return nil
	case "CERT":
		// RFC 4398: <type> <keytag> <algorithm> <certificate>. The type field
		// may be a numeric value or a mnemonic; only the structured fields are
		// checked here (PowerDNS validates the type mnemonic).
		parts := strings.Fields(content)
		if len(parts) != 4 {
			return fmt.Errorf("CERT content must have exactly 4 fields: type keytag algorithm certificate")
		}
		if err := validateUintField(parts[1], "CERT keytag", 16); err != nil {
			return err
		}
		if err := validateUintField(parts[2], "CERT algorithm", 8); err != nil {
			return err
		}
		if !base64String.MatchString(parts[3]) {
			return fmt.Errorf("CERT certificate must be a base64-encoded string")
		}
		return nil
	case "OPENPGPKEY":
		// RFC 7929: a single base64-encoded transferable public key.
		if !base64String.MatchString(content) {
			return fmt.Errorf("OPENPGPKEY content must be a base64-encoded OpenPGP key")
		}
		return nil
	case "NSEC":
		// RFC 4034: <next> <type> [<type>...].
		parts := strings.Fields(content)
		if len(parts) < 2 {
			return fmt.Errorf("NSEC content must have at least 2 fields: next_domain type [type...]")
		}
		if err := ValidateDNSName(parts[0]); err != nil {
			return fmt.Errorf("NSEC next domain: %w", err)
		}
		return nil
	case "NSEC3":
		// RFC 5155: <hashalgo> <flags> <iterations> <salt> <hash> [type...].
		parts := strings.Fields(content)
		if len(parts) < 5 {
			return fmt.Errorf("NSEC3 content must have at least 5 fields: hashalgo flags iterations salt hash [type...]")
		}
		if err := validateUintField(parts[0], "NSEC3 hash algorithm", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[1], "NSEC3 flags", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[2], "NSEC3 iterations", 16); err != nil {
			return err
		}
		if parts[3] != "-" && !hexString.MatchString(parts[3]) {
			return fmt.Errorf(`NSEC3 salt must be a hexadecimal string or "-"`)
		}
		if parts[4] == "" {
			return fmt.Errorf("NSEC3 next hashed owner name must not be empty")
		}
		return nil
	case "NSEC3PARAM":
		// RFC 5155: <hashalgo> <flags> <iterations> <salt>.
		parts := strings.Fields(content)
		if len(parts) != 4 {
			return fmt.Errorf("NSEC3PARAM content must have exactly 4 fields: hashalgo flags iterations salt")
		}
		if err := validateUintField(parts[0], "NSEC3PARAM hash algorithm", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[1], "NSEC3PARAM flags", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[2], "NSEC3PARAM iterations", 16); err != nil {
			return err
		}
		if parts[3] != "-" && !hexString.MatchString(parts[3]) {
			return fmt.Errorf(`NSEC3PARAM salt must be a hexadecimal string or "-"`)
		}
		return nil
	case "RRSIG":
		// RFC 4034: <typecovered> <algorithm> <labels> <origttl>
		// <expiration> <inception> <keytag> <signer> <signature>.
		parts := strings.Fields(content)
		if len(parts) != 9 {
			return fmt.Errorf("RRSIG content must have exactly 9 fields: typecovered algorithm labels origttl expiration inception keytag signer signature")
		}
		if err := ValidateRecordType(parts[0]); err != nil {
			return fmt.Errorf("RRSIG typecovered: %w", err)
		}
		if err := validateUintField(parts[1], "RRSIG algorithm", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[2], "RRSIG labels", 8); err != nil {
			return err
		}
		if err := validateUintField(parts[3], "RRSIG origttl", 32); err != nil {
			return err
		}
		if err := validateRRSIGTime(parts[4], "expiration"); err != nil {
			return err
		}
		if err := validateRRSIGTime(parts[5], "inception"); err != nil {
			return err
		}
		if err := validateUintField(parts[6], "RRSIG keytag", 16); err != nil {
			return err
		}
		if err := ValidateDNSName(parts[7]); err != nil {
			return fmt.Errorf("RRSIG signer: %w", err)
		}
		if !base64String.MatchString(parts[8]) {
			return fmt.Errorf("RRSIG signature must be a base64-encoded string")
		}
		return nil
	case "LOC":
		// RFC 1876 has a complex coordinate format. Apply a minimal sanity
		// check — the content must contain numeric coordinates and a cardinal
		// direction (N/S/E/W) — so grossly malformed input is rejected without
		// risking false positives from full coordinate parsing.
		if !strings.ContainsAny(content, "0123456789") {
			return fmt.Errorf("LOC content must contain numeric coordinates")
		}
		if !strings.ContainsAny(strings.ToUpper(content), "NSEW") {
			return fmt.Errorf("LOC content must contain a cardinal direction (N, S, E or W)")
		}
		return nil
	default:
		return fmt.Errorf("content validation is not implemented for record type %q", recordType)
	}
}

// ValidateRecordPriority checks that a priority value is valid for the given
// record type. MX and SRV carry a 16-bit priority (0-65535); for those types
// the value is range-checked. The priority lives in RecordInfo.Priority (not in
// the content string), so it is validated separately from the content (m49).
// For all other record types the priority is not applicable and any value is
// accepted (it is ignored downstream by prepareRecordContent).
func ValidateRecordPriority(recordType string, priority int) error {
	switch strings.ToUpper(recordType) {
	case "MX", "SRV":
		if priority < 0 || priority > 65535 {
			return fmt.Errorf("%s priority %d is out of range (0-65535)", strings.ToUpper(recordType), priority)
		}
	}
	return nil
}

// PasswordPolicy describes the password complexity rules. It mirrors the
// config.PasswordConfig fields without importing config (which would create a
// cycle, since config imports validators). Callers convert via
// config.PasswordConfig.Policy().
type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	// MaxLength is the maximum password length in BYTES (0 disables the
	// check). Note the unit difference with MinLength, which counts runes:
	// bcrypt silently truncates at, and its Go implementation rejects
	// passwords beyond, 72 bytes, so the byte count is the one that matters
	// for hashing. A multi-byte passphrase can exceed the cap while still
	// being under it in characters.
	MaxLength int
}

// ValidatePassword checks a candidate password against the policy. A rule with
// a zero value is treated as disabled: a fully zero policy accepts any
// non-empty password. "Special" means any rune that is neither a letter nor a
// digit (punctuation, symbols, spaces). Length is measured in runes so
// multi-byte passwords are not penalised.
func ValidatePassword(password string, p PasswordPolicy) error {
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	if p.MinLength > 0 && utf8.RuneCountInString(password) < p.MinLength {
		return fmt.Errorf("password must be at least %d characters long", p.MinLength)
	}
	// Enforced in bytes (not runes, unlike MinLength) to mirror bcrypt's own
	// limit: hashing rejects anything longer than 72 bytes. Checking here
	// turns what would surface as an opaque "failed to hash" error into an
	// actionable validation message at every password-set site.
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		return fmt.Errorf("password must be at most %d bytes long (got %d)", p.MaxLength, len(password))
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if p.RequireUppercase && !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if p.RequireLowercase && !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if p.RequireDigit && !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if p.RequireSpecial && !hasSpecial {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}
