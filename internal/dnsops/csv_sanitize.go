package dnsops

import "strings"

// CSV formula-injection neutralisation, applied by RenderZoneCSV to free-text
// cells (record content, comments) and reversed by the CSV importer.
//
// Spreadsheet applications (Excel, LibreOffice, …) evaluate a cell whose
// first non-space character is =, +, - or @ as a formula, even when the CSV
// field is quoted — so an exported TXT record or comment carrying such text
// would execute when an administrator opens the export. The defence prefixes
// a single quote (the spreadsheet text-marker); GoZone strips that prefix
// back off on import, keeping the export/import round trip lossless.
//
// Convention (per physical line of a possibly multiline cell):
//
//	export: lines whose first non-space character is one of = + - @ gain a
//	        leading '; lines already starting with ' gain a second one.
//	import: a leading "''" collapses to a single literal '; a leading '
//	        before a dangerous prefix is the export marker and is dropped.
//
//	A leading ' before anything else is left alone: values that never
//	needed neutralising pass through untouched.
const csvDangerousPrefixes = "=+-@"

func csvLineDangerous(line string) bool {
	t := strings.TrimLeft(line, " \t")
	if t == "" {
		return false
	}
	return strings.ContainsRune(csvDangerousPrefixes, rune(t[0]))
}

// SanitizeCSVField neutralizes formula triggers in one CSV cell. A comment
// cell may span several physical lines (embedded newlines inside the CSV
// quoting); each line is treated independently so a dangerous second line
// cannot hide behind a safe first one.
func SanitizeCSVField(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "'"):
			// A literal leading apostrophe: double it so the importer can
			// tell it apart from the escape marker.
			lines[i] = "'" + line
		case csvLineDangerous(line):
			lines[i] = "'" + line
		}
	}
	return strings.Join(lines, "\n")
}

// RestoreCSVField reverses SanitizeCSVField, line by line.
func RestoreCSVField(s string) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		rest, ok := strings.CutPrefix(line, "'")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(rest, "'"):
			// Doubled apostrophe: a literal one, kept.
			lines[i] = rest
		case csvLineDangerous(rest):
			// The export escape marker: drop it.
			lines[i] = rest
		}
		// A leading apostrophe before anything else was never an escape:
		// leave the line untouched.
	}
	return strings.Join(lines, "\n")
}
