package dnsops

import "testing"

// TestSanitizeCSVField_RoundTrip covers the formula-injection escaping
// convention: every value must come back byte-identical through
// RestoreCSVField, including the pathological leading-apostrophe cases the
// doubling rule exists for.
func TestSanitizeCSVField_RoundTrip(t *testing.T) {
	values := []string{
		"",
		"plain text",
		"192.0.2.1",
		"=1+1",
		"=cmd|'/c calc'!A1",
		"+SUM(A1:A9)",
		"-42",
		"@name",
		" =1",  // dangerous after leading spaces
		"\t=1", // dangerous after a tab
		" 'x",  // safe: quote comes before the dangerous char
		"'literal apostrophe",
		"'=1", // literal apostrophe followed by a dangerous char
		"''already doubled",
		"line one\n=2+2",     // dangerous second line
		"=1+1\nplain second", // dangerous first line
		"'a\n'b\n=a1",        // mixed escapes per line
		"mail.example.com.",
	}
	for _, v := range values {
		if got := RestoreCSVField(SanitizeCSVField(v)); got != v {
			t.Errorf("round trip of %q: got %q", v, got)
		}
	}
}

// TestSanitizeCSVField_Neutralizes pins the actual defence: every exported
// line whose first non-space character can trigger spreadsheet formula
// evaluation must carry the escape prefix.
func TestSanitizeCSVField_Neutralizes(t *testing.T) {
	tests := []struct{ in, want string }{
		{"=1+1", "'=1+1"},
		{"+SUM(A1:A9)", "'+SUM(A1:A9)"},
		{"-42", "'-42"},
		{"@ref", "'@ref"},
		{"  =1", "'  =1"},
		{"safe", "safe"},
		{"'apostrophe", "''apostrophe"},
		{"'a\n=b", "''a\n'=b"}, // leading apostrophe doubles; dangerous line escapes
	}
	for _, tc := range tests {
		if got := SanitizeCSVField(tc.in); got != tc.want {
			t.Errorf("SanitizeCSVField(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRestoreCSVField_LeavesForeignValues verifies the importer only strips
// the escape convention: a CSV authored elsewhere with a raw formula-looking
// cell keeps its value (it is stored verbatim; the NEXT export neutralizes
// it), and plain values with leading apostrophes are untouched. A doubled
// leading apostrophe is the convention's literal marker and collapses to a
// single one — a foreign file relying on ” must be authored knowing the
// convention.
func TestRestoreCSVField_LeavesForeignValues(t *testing.T) {
	tests := []struct{ in, want string }{
		{"=1+1", "=1+1"},          // foreign, unescaped: stored verbatim
		{"'hello", "'hello"},      // never an escape
		{"''doubled", "'doubled"}, // the literal-apostrophe marker
	}
	for _, tc := range tests {
		if got := RestoreCSVField(tc.in); got != tc.want {
			t.Errorf("RestoreCSVField(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
