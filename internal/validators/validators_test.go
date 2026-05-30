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
		{"label starts with digit", "123.example.com", true, "RFC 1035 format"},
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
		{"with digits", "user123", false},
		{"max length", strings.Repeat("a", 32), false},
		{"start with letter", "a123", false},
		{"empty string", "", true},
		{"too short 2 chars", "ab", true},
		{"too long 33 chars", strings.Repeat("a", 33), true},
		{"starts with digit", "123abc", true},
		{"starts with hyphen", "-john", true},
		{"starts with underscore", "_john", true},
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
		{"CAA valid", "CAA", "0 issue ca.example.com", false},
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

func TestValidateRecordType_AllWhitelisted(t *testing.T) {
	for _, rt := range []string{
		"A", "AAAA", "AFSDB", "ALIAS", "CAA", "CERT", "CNAME",
		"DNSKEY", "DS", "HINFO", "KEY", "LOC", "MX", "NAPTR",
		"NS", "NSEC", "NSEC3", "NSEC3PARAM", "OPENPGPKEY", "PTR",
		"RP", "RRSIG", "SOA", "SPF", "SRV", "SSHFP", "TLSA",
		"TXT", "URI",
	} {
		t.Run(rt, func(t *testing.T) {
			if err := ValidateRecordType(rt); err != nil {
				t.Errorf("ValidateRecordType(%q) unexpected error: %v", rt, err)
			}
		})
	}
}
