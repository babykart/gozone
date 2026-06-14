package models

import "testing"

func TestTypeHasPriority(t *testing.T) {
	for _, tc := range []struct {
		rtype string
		want  bool
	}{
		{"MX", true},
		{"SRV", true},
		{"A", false},
		{"TXT", false},
		{"", false},
	} {
		if got := TypeHasPriority(tc.rtype); got != tc.want {
			t.Errorf("TypeHasPriority(%q) = %t, want %t", tc.rtype, got, tc.want)
		}
	}
}

func TestTypeIsQuoted(t *testing.T) {
	for _, tc := range []struct {
		rtype string
		want  bool
	}{
		{"TXT", true},
		{"SPF", true},
		{"MX", false},
		{"A", false},
		{"", false},
	} {
		if got := TypeIsQuoted(tc.rtype); got != tc.want {
			t.Errorf("TypeIsQuoted(%q) = %t, want %t", tc.rtype, got, tc.want)
		}
	}
}

func TestSplitPriority(t *testing.T) {
	tests := []struct {
		name     string
		rtype    string
		content  string
		wantPrio int
		wantRest string
		wantOK   bool
	}{
		{"MX with priority", "MX", "10 mail.example.com.", 10, "mail.example.com.", true},
		{"MX with priority zero", "MX", "0 mail.example.com.", 0, "mail.example.com.", true},
		{"MX without priority", "MX", "mail.example.com.", 0, "mail.example.com.", false},
		{"A is not a priority type", "A", "192.0.2.1", 0, "192.0.2.1", false},
		{"SRV with priority", "SRV", "5 5060 srv.example.com.", 5, "5060 srv.example.com.", true},
		{"SRV with priority zero", "SRV", "0 5 5060 srv.example.com.", 0, "5 5060 srv.example.com.", true},
		{"SRV full wire form", "SRV", "10 60 5060 big.example.com.", 10, "60 5060 big.example.com.", true},
		{"empty content", "MX", "", 0, "", false},
		{"non-numeric prefix", "MX", "mail 10", 0, "mail 10", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prio, rest, ok := SplitPriority(tt.rtype, tt.content)
			if ok != tt.wantOK {
				t.Errorf("ok = %t, want %t", ok, tt.wantOK)
			}
			if prio != tt.wantPrio {
				t.Errorf("priority = %d, want %d", prio, tt.wantPrio)
			}
			if rest != tt.wantRest {
				t.Errorf("rest = %q, want %q", rest, tt.wantRest)
			}
		})
	}
}

func TestJoinPriority(t *testing.T) {
	tests := []struct {
		name    string
		rtype   string
		prio    int
		content string
		want    string
	}{
		{"MX from form content", "MX", 10, "mail.example.com.", "10 mail.example.com."},
		{"MX priority zero", "MX", 0, "mail.example.com.", "0 mail.example.com."},
		{"MX strips embedded priority", "MX", 20, "10 mail.example.com.", "20 mail.example.com."},
		{"SRV from form content (3 fields)", "SRV", 10, "5 5060 srv.example.com.", "10 5 5060 srv.example.com."},
		{"SRV strips embedded priority (4 fields)", "SRV", 20, "10 5 5060 srv.example.com.", "20 5 5060 srv.example.com."},
		{"non-priority type unchanged", "A", 0, "192.0.2.1", "192.0.2.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := JoinPriority(tt.rtype, tt.prio, tt.content); got != tt.want {
				t.Errorf("JoinPriority(%q, %d, %q) = %q, want %q", tt.rtype, tt.prio, tt.content, got, tt.want)
			}
		})
	}
}

// TestPriorityRoundTrip checks that splitting then re-joining (and vice versa)
// is stable for both priority types, including a zero priority.
func TestPriorityRoundTrip(t *testing.T) {
	for _, wire := range []struct {
		rtype, content string
	}{
		{"MX", "10 mail.example.com."},
		{"MX", "0 mail.example.com."},
		{"SRV", "10 5 5060 srv.example.com."},
		{"SRV", "0 5 5060 srv.example.com."},
	} {
		prio, rest, ok := SplitPriority(wire.rtype, wire.content)
		if !ok {
			t.Fatalf("SplitPriority(%q, %q) reported no priority", wire.rtype, wire.content)
		}
		if got := JoinPriority(wire.rtype, prio, rest); got != wire.content {
			t.Errorf("round trip %q: got %q, want %q", wire.rtype, got, wire.content)
		}
	}
}

func TestQuoteContent(t *testing.T) {
	tests := []struct {
		name           string
		rtype, content string
		want           string
	}{
		{"TXT unquoted", "TXT", "v=spf1 mx ~all", `"v=spf1 mx ~all"`},
		{"TXT already double-quoted", "TXT", `"already"`, `"already"`},
		{"TXT single-quoted left alone", "TXT", `'already'`, `'already'`},
		{"SPF unquoted", "SPF", "v=spf1 -all", `"v=spf1 -all"`},
		{"TXT empty content", "TXT", "", ""},
		{"non-quoted type unchanged", "A", "192.0.2.1", "192.0.2.1"},
		{"TXT escapes internal quotes", "TXT", `foo"bar`, `"foo\"bar"`},
		{"TXT escapes multiple internal quotes", "TXT", `a"b"c`, `"a\"b\"c"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := QuoteContent(tt.rtype, tt.content); got != tt.want {
				t.Errorf("QuoteContent(%q, %q) = %q, want %q", tt.rtype, tt.content, got, tt.want)
			}
		})
	}
}

func TestUnquoteContent(t *testing.T) {
	tests := []struct {
		name           string
		rtype, content string
		want           string
	}{
		{"TXT quoted", "TXT", `"v=spf1 mx ~all"`, "v=spf1 mx ~all"},
		{"TXT unquoted unchanged", "TXT", "bare", "bare"},
		{"SPF quoted", "SPF", `"v=spf1 -all"`, "v=spf1 -all"},
		{"non-quoted type unchanged", "A", `"192.0.2.1"`, `"192.0.2.1"`},
		{"single quote char untouched", "TXT", `"`, `"`},
		{"TXT unescapes internal quotes", "TXT", `"foo\"bar"`, `foo"bar`},
		{"TXT unescapes multiple internal quotes", "TXT", `"a\"b\"c"`, `a"b"c`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UnquoteContent(tt.rtype, tt.content); got != tt.want {
				t.Errorf("UnquoteContent(%q, %q) = %q, want %q", tt.rtype, tt.content, got, tt.want)
			}
		})
	}
}

// TestQuoteRoundTrip checks quote then unquote returns the original content.
func TestQuoteRoundTrip(t *testing.T) {
	for _, rtype := range []string{"TXT", "SPF"} {
		for _, original := range []string{
			"v=spf1 include:_spf.example.com ~all",
			`foo"bar`,
			`a"b"c`,
			`"leading`,
		} {
			if got := UnquoteContent(rtype, QuoteContent(rtype, original)); got != original {
				t.Errorf("round trip %q %q: got %q, want %q", rtype, original, got, original)
			}
		}
	}
}
