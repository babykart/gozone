package validators

import (
	"strings"
	"testing"
)

func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{"simple domain", "example.com", false, ""},
		{"subdomain", "www.example.com", false, ""},
		{"deep subdomain", "a.b.c.d.example.com", false, ""},
		{"with trailing dot", "example.com.", false, ""},
		{"single label", "example", false, ""},
		{"label with hyphen", "my-host.example.com", false, ""},
		{"single char label", "a.b.com", false, ""},
		{"63 char label", strings.Repeat("a", 63) + ".com", false, ""},
		{"empty string", "", true, "must not be empty"},
		{"only dot", ".", true, "must not be empty"},
		{"empty label", "example..com", true, "empty label"},
		{"label >63 chars", strings.Repeat("a", 64) + ".com", true, "exceeds 63"},
		{"domain >253 chars", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".com", true, "exceeds 253"},
		{"label starts with digit", "123.example.com", false, ""},
		{"reverse dns class C", "192.in-addr.arpa", false, ""},
		{"reverse dns /24", "1.168.192.in-addr.arpa", false, ""},
		{"numeric only label", "1", false, ""},
		{"label starts with hyphen", "-host.example.com", true, "RFC 1035 format"},
		{"label ends with hyphen", "host-.example.com", true, "RFC 1035 format"},
		{"label with underscore", "my_host.example.com", true, "RFC 1035 format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomainName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateDomainName(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err)
				}
			}
		})
	}
}

func TestValidateRecordType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"A record", "A", false},
		{"AAAA record", "AAAA", false},
		{"CNAME record", "CNAME", false},
		{"DNAME record", "DNAME", false},
		{"MINFO record", "MINFO", false},
		{"MX record", "MX", false},
		{"TXT record", "TXT", false},
		{"SOA record", "SOA", false},
		{"lowercase a", "a", false},
		{"mixed case", "Cname", false},
		{"empty string", "", true},
		{"unsupported type", "FAKE", true},
		{"random string", "XYZ", true},
		{"numeric", "123", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecordType(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid username", "john_doe", false},
		{"shortest valid", "abc", false},
		{"with hyphen", "john-doe", false},
		{"with underscore", "john_doe", false},
		{"with period", "john.doe", false},
		{"with period hyphen underscore", "john.doe-2_test", false},
		{"with digits", "user123", false},
		{"max length", strings.Repeat("a", 32), false},
		{"start with letter", "a123", false},
		{"empty string", "", true},
		{"too short 2 chars", "ab", true},
		{"too long 33 chars", strings.Repeat("a", 33), true},
		{"starts with digit", "123abc", true},
		{"starts with hyphen", "-john", true},
		{"starts with underscore", "_john", true},
		{"starts with period", ".john", true},
		{"contains space", "john doe", true},
		{"contains special char", "john@doe", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUsername(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple email", "user@example.com", false},
		{"with subdomain", "user@mail.example.com", false},
		{"with plus", "user+tag@example.com", false},
		{"with dot", "first.last@example.com", false},
		{"empty string", "", true},
		{"no @", "userexample.com", true},
		{"no domain", "user@", true},
		{"no local part", "@example.com", true},
		{"multiple @", "user@domain@example.com", true},
		{"spaces", "user @example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv4 loopback", "127.0.0.1", false},
		{"valid IPv6", "2001:db8::1", false},
		{"valid IPv6 full", "2001:0db8:0000:0000:0000:0000:0000:0001", false},
		{"valid IPv6 loopback", "::1", false},
		{"empty string", "", true},
		{"invalid IPv4", "256.256.256.256", true},
		{"garbage", "not-an-ip", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPAddress(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPv4(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "192.168.1.1", false},
		{"loopback", "127.0.0.1", false},
		{"public", "8.8.8.8", false},
		{"empty", "", true},
		{"IPv6 fails", "2001:db8::1", true},
		// IPv4-mapped IPv6: net.ParseIP().To4() is non-nil for this form, so
		// the mapped literal used to pass here and travel all the way to
		// PowerDNS, which rejected the A record with a generic upstream
		// error. It must be refused at the validation boundary.
		{"IPv4-mapped IPv6 fails", "::ffff:192.0.2.1", true},
		{"out of range", "256.0.0.1", true},
		{"garbage", "not-an-ip", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPv4(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPv4(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPv6(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"loopback", "::1", false},
		{"short", "2001:db8::1", false},
		{"full", "2001:0db8:0000:0000:0000:0000:0000:0001", false},
		{"empty", "", true},
		{"IPv4 fails", "192.168.1.1", true},
		// The mirrored case: the IPv4-mapped form is also refused for AAAA
		// (To4() != nil) — pinned here so the two validators stay symmetric.
		{"IPv4-mapped IPv6 fails", "::ffff:192.0.2.1", true},
		{"garbage", "not-an-ip", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPv6(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPv6(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRecordContent(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		content    string
		wantErr    bool
	}{
		{"A valid", "A", "192.168.1.1", false},
		{"A invalid", "A", "not-an-ip", true},
		{"A empty", "A", "", true},
		{"AAAA valid", "AAAA", "2001:db8::1", false},
		{"AAAA invalid", "AAAA", "not-an-ip", true},
		{"CNAME valid", "CNAME", "target.example.com", false},
		{"CNAME with dot", "CNAME", "target.example.com.", false},
		{"CNAME invalid", "CNAME", "invalid label with spaces", true},
		{"DNAME valid", "DNAME", "target.example.com", false},
		{"DNAME with dot", "DNAME", "target.example.com.", false},
		{"DNAME invalid", "DNAME", "invalid label with spaces", true},
		{"MINFO valid", "MINFO", "admin.example.com txt.example.com", false},
		{"MINFO too few fields", "MINFO", "admin.example.com", true},
		{"MINFO too many fields", "MINFO", "a.example.com b.example.com extra", true},
		{"ALIAS valid", "ALIAS", "target.example.com", false},
		{"NS valid", "NS", "ns1.example.com", false},
		{"PTR valid", "PTR", "host.example.com", false},
		{"MX valid", "MX", "mail.example.com", false},
		{"MX invalid", "MX", "", true},
		{"SOA valid", "SOA", "ns1.example.com admin.example.com 2024010100 3600 900 604800 86400", false},
		{"SOA invalid missing fields", "SOA", "ns1.example.com admin.example.com", true},
		{"SRV valid", "SRV", "0 5 5060 sip.example.com", false},
		{"SRV invalid missing target", "SRV", "0 5", true},
		{"TXT any content", "TXT", "arbitrary text here", false},
		{"SPF any content", "SPF", "v=spf1 include:_spf.example.com ~all", false},
		{"CAA valid issue", "CAA", "0 issue ca.example.com", false},
		{"CAA valid issuewild", "CAA", "0 issuewild ca.example.com", false},
		{"CAA valid iodef", "CAA", "0 iodef mailto:admin@example.com", false},
		{"CAA valid critical flag", "CAA", "128 issue ca.example.com", false},
		{"CAA invalid too few fields", "CAA", "0 issue", true},
		{"CAA invalid too many fields", "CAA", "0 issue ca.example.com extra", true},
		{"CAA invalid flag", "CAA", "1 issue ca.example.com", true},
		{"CAA invalid tag", "CAA", "0 invalid ca.example.com", true},
		{"empty content", "A", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordContent(tt.recordType, tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecordContent(%q, %q) error = %v, wantErr = %v",
					tt.recordType, tt.content, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRecordContent_StructuredTypes covers the 17 record types that
// previously fell through to the default-accept case (m47). Each type is
// exercised with at least one valid example and one structurally invalid one.
func TestValidateRecordContent_StructuredTypes(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		content    string
		wantErr    bool
	}{
		// AFSDB: <subtype> <hostname>
		{"AFSDB valid", "AFSDB", "1 afsdb.example.com.", false},
		{"AFSDB too few fields", "AFSDB", "afsdb.example.com.", true},
		{"AFSDB subtype not numeric", "AFSDB", "abc afsdb.example.com.", true},
		{"AFSDB bad hostname", "AFSDB", "1 invalid host.", true},

		// HINFO: <cpu> <os>
		{"HINFO valid", "HINFO", `"x86" "linux"`, false},
		{"HINFO too few fields", "HINFO", "cpu", true},

		// NAPTR: <order> <pref> <flags> <service> <regexp> <replacement>
		{"NAPTR valid", "NAPTR", `100 50 "s" "z3950+tcp" "" _z3950._tcp.example.com.`, false},
		{"NAPTR too few fields", "NAPTR", `100 50 "s"`, true},
		{"NAPTR order not numeric", "NAPTR", `abc 50 "s" "svc" "" target.example.com.`, true},
		{"NAPTR bad replacement", "NAPTR", `100 50 "s" "svc" "" invalid host.`, true},

		// URI: <priority> <weight> <target>
		{"URI valid", "URI", `10 1 "https://example.com"`, false},
		{"URI too few fields", "URI", "10 1", true},
		{"URI priority not numeric", "URI", `xx 1 "https://example.com"`, true},

		// SSHFP: <algorithm> <fptype> <fingerprint(hex)>
		{"SSHFP valid", "SSHFP", "1 1 123456789abcdef0123456789abcdef0", false},
		{"SSHFP too few fields", "SSHFP", "1 1", true},
		{"SSHFP fingerprint not hex", "SSHFP", "1 1 nothex!", true},

		// TLSA: <usage> <selector> <matchingtype> <certificate(hex)>
		{"TLSA valid", "TLSA", "3 1 1 abcd1234ef", false},
		{"TLSA too few fields", "TLSA", "3 1", true},
		{"TLSA certificate not hex", "TLSA", "3 1 1 nothex!", true},

		// DS: <keytag> <algorithm> <digesttype> <digest(hex)>
		{"DS valid", "DS", "12345 8 2 abc123def456", false},
		{"DS too few fields", "DS", "12345 8", true},
		{"DS digest not hex", "DS", "12345 8 2 nothex!", true},
		{"DS algorithm too large", "DS", "12345 300 2 abc123", true},

		// DNSKEY: <flags> <protocol> <algorithm> <publickey(base64)>
		{"DNSKEY valid", "DNSKEY", "257 3 5 AwEAAcd3dummykey", false},
		{"DNSKEY too few fields", "DNSKEY", "257 3 5", true},
		{"DNSKEY publickey not base64", "DNSKEY", "257 3 5 not!base64!!", true},

		// KEY: same structure as DNSKEY
		{"KEY valid", "KEY", "256 3 5 AwEAAkey", false},
		{"KEY too few fields", "KEY", "256 3 5", true},

		// CERT: <type> <keytag> <algorithm> <certificate(base64)>
		{"CERT valid mnemonic", "CERT", "PGP 0 0 dGhpcw==", false},
		{"CERT valid numeric", "CERT", "1 0 0 dGhpcw==", false},
		{"CERT too few fields", "CERT", "PGP 0 0", true},
		{"CERT certificate not base64", "CERT", "PGP 0 0 not!b64!!", true},

		// OPENPGPKEY: single base64 blob
		{"OPENPGPKEY valid", "OPENPGPKEY", "dGhpcyBpcyBhIGtleQ==", false},
		{"OPENPGPKEY not base64", "OPENPGPKEY", "not!a!key!!", true},

		// NSEC: <next> <type> [<type>...]
		{"NSEC valid", "NSEC", "host.example.com. A RRSIG", false},
		{"NSEC too few fields", "NSEC", "host.example.com.", true},
		{"NSEC bad next domain", "NSEC", "bad!label. A", true},

		// NSEC3: <hashalgo> <flags> <iterations> <salt> <hash> [type...]
		{"NSEC3 valid", "NSEC3", "1 0 10 - ABCDEF A RRSIG", false},
		{"NSEC3 too few fields", "NSEC3", "1 0 10 -", true},
		{"NSEC3 salt not hex", "NSEC3", "1 0 10 nothex! ABCDEF A", true},

		// NSEC3PARAM: <hashalgo> <flags> <iterations> <salt>
		{"NSEC3PARAM valid", "NSEC3PARAM", "1 0 10 -", false},
		{"NSEC3PARAM valid hex salt", "NSEC3PARAM", "1 0 10 a1b2c3", false},
		{"NSEC3PARAM too few fields", "NSEC3PARAM", "1 0 10", true},
		{"NSEC3PARAM salt not hex", "NSEC3PARAM", "1 0 10 nothex!", true},

		// RRSIG: 9 fields
		{"RRSIG valid", "RRSIG", "A 8 2 3600 20251231235959 20250101000000 12345 example.com. c2lnbmF0dXJl==", false},
		{"RRSIG too few fields", "RRSIG", "A 8 2 3600", true},
		{"RRSIG bad typecovered", "RRSIG", "NOTATYPE 8 2 3600 20251231235959 20250101000000 12345 example.com. c2ln==", true},
		{"RRSIG bad expiration time", "RRSIG", "A 8 2 3600 badtime12chars 20250101000000 12345 example.com. c2ln==", true},
		{"RRSIG bad signer", "RRSIG", "A 8 2 3600 20251231235959 20250101000000 12345 bad signer. c2ln==", true},

		// LOC: minimal sanity check
		{"LOC valid", "LOC", "37 23 30.900 N 121 59 19.000 W 7m", false},
		{"LOC no digits", "LOC", "north east", true},
		{"LOC no cardinal", "LOC", "42 100", true},

		// RP: <rmailbx> <emailbx>
		{"RP valid", "RP", "admin.example.com txt.example.com", false},
		{"RP too few fields", "RP", "admin.example.com", true},
		{"RP bad mailbox", "RP", "bad mbox. txt.example.com", true},

		// default now rejects unknown types (m47 closure)
		{"unknown type rejected", "NOTAREALTYPE", "anything", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordContent(tt.recordType, tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecordContent(%q, %q) error = %v, wantErr = %v",
					tt.recordType, tt.content, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRecordContent_SRVNumericFields verifies that SRV weight and port
// are validated as 16-bit unsigned integers (0-65535), and that both the
// 3-field (weight port target) and 4-field (priority weight port target)
// forms are accepted (m49).
func TestValidateRecordContent_SRVNumericFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid 3-field", "5 5060 sip.example.com.", false},
		{"valid 4-field with priority", "10 5 5060 sip.example.com.", false},
		{"weight at max", "65535 5060 sip.example.com.", false},
		{"port at max", "5 65535 sip.example.com.", false},
		{"weight too large", "65536 5060 sip.example.com.", true},
		{"port too large", "5 65536 sip.example.com.", true},
		{"weight negative", "-1 5060 sip.example.com.", true},
		{"port not numeric", "5 abc sip.example.com.", true},
		{"weight not numeric", "abc 5060 sip.example.com.", true},
		{"too few fields", "5 5060", true},
		{"too many fields", "1 2 3 4 target.example.com.", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordContent("SRV", tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecordContent(SRV, %q) error = %v, wantErr = %v", tt.content, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRecordPriority verifies the MX/SRV priority range check (m49).
// Priority lives in RecordInfo.Priority, separate from the content string, so
// it is validated by ValidateRecordPriority rather than ValidateRecordContent.
func TestValidateRecordPriority(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
		priority   int
		wantErr    bool
	}{
		{"MX valid zero", "MX", 0, false},
		{"MX valid", "MX", 10, false},
		{"MX valid max", "MX", 65535, false},
		{"MX too large", "MX", 65536, true},
		{"MX negative", "MX", -1, true},
		{"SRV valid", "SRV", 10, false},
		{"SRV valid max", "SRV", 65535, false},
		{"SRV too large", "SRV", 70000, true},
		{"A ignores priority (non-applicable)", "A", 999, false},
		{"A zero", "A", 0, false},
		{"TXT ignores priority", "TXT", 50, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordPriority(tt.recordType, tt.priority)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecordPriority(%q, %d) error = %v, wantErr = %v",
					tt.recordType, tt.priority, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRecordType_AllWhitelisted(t *testing.T) {
	for _, rt := range []string{
		"A", "AAAA", "AFSDB", "ALIAS", "CAA", "CERT", "CNAME",
		"DNAME", "DNSKEY", "DS", "HINFO", "KEY", "LOC", "MINFO",
		"MX", "NAPTR", "NS", "NSEC", "NSEC3", "NSEC3PARAM",
		"OPENPGPKEY", "PTR", "RP", "RRSIG", "SOA", "SPF", "SRV",
		"SSHFP", "TLSA", "TXT", "URI",
	} {
		t.Run(rt, func(t *testing.T) {
			if err := ValidateRecordType(rt); err != nil {
				t.Errorf("ValidateRecordType(%q) unexpected error: %v", rt, err)
			}
		})
	}
}

func TestValidateDNSName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple domain", "example.com", false},
		{"subdomain", "www.example.com", false},
		{"with trailing dot", "example.com.", false},
		{"underscore label", "my_host.example.com", false},
		{"dkim selector", "selector._domainkey.example.com", false},
		{"dnslink", "_dnslink.example.com", false},
		{"wildcard", "*.example.com", false},
		{"single wildcard label", "*", false},
		{"wildcard with trailing dot", "*.example.com.", false},
		{"wildcard not leftmost (double)", "*.*.example.com", true},
		{"wildcard not leftmost (middle)", "foo.*.example.com", true},
		{"wildcard not leftmost (trailing)", "example.com.*", true},
		{"empty string", "", true},
		{"empty label", "example..com", true},
		{"label >63 chars", strings.Repeat("a", 64) + ".com", true},
		{"domain >253 chars", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".com", true},
		{"label starts with hyphen", "-host.example.com", true},
		{"label ends with hyphen", "host-.example.com", true},
		{"space in label", "invalid label.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDNSName(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRecordName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"apex", "@", false},
		{"relative", "www", false},
		{"relative underscore", "selector._domainkey", false},
		{"fqdn", "www.example.com.", false},
		{"wildcard", "*", false},
		{"dkim", "selector._domainkey.example.com", false},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecordName(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateZoneKind(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"Native", "Native", false},
		{"Master", "Master", false},
		{"Slave", "Slave", false},
		{"Producer", "Producer", false},
		{"Consumer", "Consumer", false},
		{"empty", "", true},
		{"invalid", "Forwarded", true},
		{"lowercase", "native", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateZoneKind(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateZoneKind(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRole(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"admin", "admin", false},
		{"user", "user", false},
		{"empty", "", true},
		{"invalid", "superadmin", true},
		{"uppercase", "Admin", true},
		{"whitespace", " user ", true},
		{"sql-ish", "user;--", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRole(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRole(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRecordContent_SOANumericFields(t *testing.T) {
	base := "ns1.example.com admin.example.com"
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid", base + " 2024010100 3600 900 604800 86400", false},
		{"zero serial", base + " 0 3600 900 604800 86400", true},
		{"negative serial", base + " -1 3600 900 604800 86400", true},
		{"non-numeric refresh", base + " 2024010100 abc 900 604800 86400", true},
		{"too large serial", base + " 4294967296 3600 900 604800 86400", true},
		{"max serial", base + " 4294967295 3600 900 604800 86400", false},
		// m50: the >0 check is applied to all timers, not just the serial.
		{"zero refresh", base + " 2024010100 0 900 604800 86400", true},
		{"zero retry", base + " 2024010100 3600 0 604800 86400", true},
		{"zero expire", base + " 2024010100 3600 900 0 86400", true},
		{"zero minimum", base + " 2024010100 3600 900 604800 0", true},
		// B-6: extra trailing fields are rejected locally rather than deferred
		// to a less-readable PowerDNS error.
		{"too many fields", base + " 2024010100 3600 900 604800 86400 extra", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRecordContent("SOA", tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRecordContent(SOA, %q) error = %v, wantErr = %v", tt.content, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRecordContent_UnderscoreTargets(t *testing.T) {
	for _, rt := range []string{"CNAME", "ALIAS", "NS", "PTR", "MX", "SRV"} {
		t.Run(rt, func(t *testing.T) {
			var content string
			switch rt {
			case "SRV":
				content = "0 5 5060 _sip._tcp.example.com"
			case "MX":
				content = "_mail.example.com"
			default:
				content = "_dnslink.example.com"
			}
			if err := ValidateRecordContent(rt, content); err != nil {
				t.Errorf("ValidateRecordContent(%q, %q) should allow underscores in target: %v", rt, content, err)
			}
		})
	}
}

func TestValidateMetadataKind(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"SOA-EDIT", "SOA-EDIT", false},
		{"ALLOW-AXFR-FROM", "ALLOW-AXFR-FROM", false},
		{"NSEC3PARAM", "NSEC3PARAM", false},
		{"empty", "", true},
		{"lowercase not accepted", "soa-edit", true},
		{"unsupported", "EVIL-KIND", true},
		{"random", "FOO", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMetadataKind(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMetadataKind(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDNSSECAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"ecdsa256", "ecdsa256", false},
		{"rsasha512", "rsasha512", false},
		{"ed25519", "ed25519", false},
		{"uppercase accepted", "ECDSA256", false},
		{"empty", "", true},
		{"unsupported", "rsa1024", true},
		{"random", "not-an-algo", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNSSECAlgorithm(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDNSSECAlgorithm(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTSIGAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"hmac-sha256", "hmac-sha256", false},
		{"hmac-md5", "hmac-md5", false},
		{"hmac-sha512", "hmac-sha512", false},
		{"uppercase accepted", "HMAC-SHA512", false},
		{"empty", "", true},
		{"unsupported", "hmac-sha9999", true},
		{"random", "plaintext", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTSIGAlgorithm(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTSIGAlgorithm(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	strict := PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}
	tests := []struct {
		name     string
		password string
		policy   PasswordPolicy
		wantErr  bool
	}{
		// Strict policy (the DefaultConfig values).
		{"strict valid", "Abcdef1!", strict, false},
		{"strict too short", "Ab1!", strict, true},
		{"strict no upper", "abcdef1!", strict, true},
		{"strict no lower", "ABCDEF1!", strict, true},
		{"strict no digit", "Abcdefg!", strict, true},
		{"strict no special", "Abcdefg1", strict, true},
		{"strict empty", "", strict, true},
		{"special can be space", "Abcdef1 ", strict, false},

		// Length is measured in runes (multi-byte safe).
		{"unicode length", "Äbcdef1!", strict, false}, // Ä + 7 = 8 runes

		// A fully zero policy accepts any non-empty password.
		{"zero policy short", "a", PasswordPolicy{}, false},
		{"zero policy empty", "", PasswordPolicy{}, true},

		// Selective policy: only min length.
		{"min length only ok", "abcdefgh", PasswordPolicy{MinLength: 8}, false},
		{"min length only fail", "abc", PasswordPolicy{MinLength: 8}, true},

		// MinLength 0 disables the length check even with class requires on.
		{"no min with classes", "aA1!", PasswordPolicy{RequireUppercase: true, RequireLowercase: true, RequireDigit: true, RequireSpecial: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password, tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePassword(%q) error = %v, wantErr = %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

// TestValidatePassword_MaxLengthBytes covers the byte-based maximum length.
// The unit is bytes, not runes (unlike MinLength), because bcrypt — the
// hashing backend — rejects passwords beyond 72 bytes; a multi-byte
// passphrase can be under the cap in characters while over it in bytes.
func TestValidatePassword_MaxLengthBytes(t *testing.T) {
	p := PasswordPolicy{MaxLength: 72}

	if err := ValidatePassword(strings.Repeat("a", 72), p); err != nil {
		t.Errorf("72 ASCII bytes must pass a MaxLength of 72, got %v", err)
	}
	err := ValidatePassword(strings.Repeat("a", 73), p)
	if err == nil || !strings.Contains(err.Error(), "at most 72 bytes") {
		t.Errorf("73 ASCII bytes must be rejected with a byte-based message, got %v", err)
	}

	// 40 two-byte runes = 80 bytes: under the cap in characters, over it in
	// bytes. The byte count is what bcrypt enforces, so the check must too.
	err = ValidatePassword(strings.Repeat("é", 40), p)
	if err == nil || !strings.Contains(err.Error(), "at most 72 bytes") {
		t.Errorf("40 two-byte runes (80 bytes) must be rejected in bytes, got %v", err)
	}
	// 36 two-byte runes = 72 bytes exactly: passes.
	if err := ValidatePassword(strings.Repeat("é", 36), p); err != nil {
		t.Errorf("36 two-byte runes (72 bytes) must pass, got %v", err)
	}

	// MaxLength = 0 disables the check entirely (relaxed-policy semantics).
	if err := ValidatePassword(strings.Repeat("a", 200), PasswordPolicy{}); err != nil {
		t.Errorf("MaxLength 0 must disable the byte check, got %v", err)
	}
}
