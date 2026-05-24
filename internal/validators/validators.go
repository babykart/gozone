// Package validators provides reusable input validation functions for
// domain names, DNS record types, usernames, emails, and IP addresses.
package validators

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"
)

// rfc1035Label is a single DNS label per RFC 1035 section 2.3.1:
// must start with a letter, end with a letter or digit, and contain only
// letters, digits, and hyphens in between. Maximum length: 63 characters.
var rfc1035Label = regexp.MustCompile(`^[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDomainName checks that a domain name conforms to RFC 1035.
//
// Rules:
//   - Non-empty, maximum 253 characters total
//   - Dot-separated labels, each label ≤ 63 characters
//   - Each label matches: ^[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$
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

// recordTypeWhitelist is the set of valid DNS record types recognized by
// PowerDNS. See https://doc.powerdns.com/authoritative/http-api/rrtypes.html.
var recordTypeWhitelist = map[string]bool{
	"A": true, "AAAA": true, "AFSDB": true, "ALIAS": true, "CAA": true,
	"CERT": true, "CNAME": true, "DNSKEY": true, "DS": true, "HINFO": true,
	"KEY": true, "LOC": true, "MX": true, "NAPTR": true, "NS": true,
	"NSEC": true, "NSEC3": true, "NSEC3PARAM": true, "OPENPGPKEY": true,
	"PTR": true, "RP": true, "RRSIG": true, "SOA": true, "SPF": true,
	"SRV": true, "SSHFP": true, "TLSA": true, "TXT": true, "URI": true,
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
var usernameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{2,31}$`)

// ValidateUsername checks that a username meets the application rules.
//
// Rules:
//   - 3 to 32 characters
//   - Must start with a letter
//   - May contain letters, digits, underscores, and hyphens
//
// Returns nil if valid, an error describing the violation otherwise.
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username must not be empty")
	}
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username %q is invalid: must be 3-32 characters, start with a letter, and contain only letters, digits, underscores, and hyphens", username)
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
// Returns nil if valid, an error otherwise. This is used by the DynDNS
// handler to validate the myip/ip parameter.
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
