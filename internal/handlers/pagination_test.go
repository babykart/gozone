package handlers

import (
	"html/template"
	"strings"
	"testing"

	"github.com/babykart/gozone/web"
)

// realPaginationSet parses the actual embedded pagination.html partial so the
// test pins the production behaviour (no test-template copy-paste that could
// drift away from the deployed template).
func realPaginationSet(t *testing.T) *template.Template {
	t.Helper()
	// The partial references {{define "pagination.html"}} and is invoked via
	// {{template "pagination.html" dict ...}} from the calling pages, so the
	// set must include a "base" define for {{template}} lookup to resolve. The
	// surrounding pages also call dict / add / sub / urlquery, so we register
	// them via the same FuncMap as production.
	funcs := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
		"urlquery": func(s string) string { return s },
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, nil
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, _ := values[i].(string)
				dict[key] = values[i+1]
			}
			return dict, nil
		},
	}
	tmpl := template.New("base").Funcs(funcs)
	if _, err := tmpl.ParseFS(web.FS, "templates/pagination.html"); err != nil {
		t.Fatalf("parse pagination.html: %v", err)
	}
	return tmpl
}

// TestPagination_PerPageSelect_VisibleWhenTotalPagesIsOne is the REVIEW.md
// mineur regression test: when every result fits on a single page, the
// per-page <select> must still render so the user can change the page size.
func TestPagination_PerPageSelect_VisibleWhenTotalPagesIsOne(t *testing.T) {
	tmpl := realPaginationSet(t)
	data := map[string]interface{}{
		"PageInfo": pageInfo(1, 10, 7),
		"Label":    "zones",
		"Prefix":   "",
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `class="per-page-select"`) {
		t.Errorf("per-page select must render even when TotalPages=1, got:\n%s", out)
	}
	if strings.Contains(out, `class="pagination"`) {
		t.Errorf("Previous/Next block must be hidden when TotalPages=1, got:\n%s", out)
	}
	if !strings.Contains(out, `data-action="per-page"`) {
		t.Errorf("per-page select must keep the per-page data-action for the JS handler, got:\n%s", out)
	}
}

// TestPagination_PerPageSelect_HiddenWhenTotalIsZero makes sure we don't
// surface a useless empty page-size selector on empty result sets.
func TestPagination_PerPageSelect_HiddenWhenTotalIsZero(t *testing.T) {
	tmpl := realPaginationSet(t)
	data := map[string]interface{}{
		"PageInfo": pageInfo(0, 10, 0),
		"Label":    "zones",
		"Prefix":   "",
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, `class="per-page-select"`) {
		t.Errorf("per-page select must be hidden when Total=0, got:\n%s", out)
	}
	if strings.Contains(out, `class="pagination"`) {
		t.Errorf("Previous/Next block must be hidden when Total=0, got:\n%s", out)
	}
}

// TestPagination_PaginationBlock_VisibleWhenMultiplePages keeps the
// original behaviour for the multi-page case so the fix does not regress.
func TestPagination_PaginationBlock_VisibleWhenMultiplePages(t *testing.T) {
	tmpl := realPaginationSet(t)
	data := map[string]interface{}{
		"PageInfo": pageInfo(2, 10, 47),
		"Label":    "zones",
		"Prefix":   "",
		"Search":   "example",
	}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "pagination.html", data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `class="pagination"`) {
		t.Errorf("Previous/Next block must render when TotalPages>1, got:\n%s", out)
	}
	if !strings.Contains(out, `class="per-page-select"`) {
		t.Errorf("per-page select must also render when TotalPages>1, got:\n%s", out)
	}
	if !strings.Contains(out, "Page 2 / 5") {
		t.Errorf("expected page info to render, got:\n%s", out)
	}
	if !strings.Contains(out, `search=example`) {
		t.Errorf("expected search term preserved in pagination links, got:\n%s", out)
	}
}

// pageInfo is a tiny helper that returns a map matching the shape the
// pagination partial expects.
func pageInfo(current, perPage, total int) map[string]interface{} {
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	return map[string]interface{}{
		"Current":    current,
		"PerPage":    perPage,
		"Total":      total,
		"TotalPages": totalPages,
	}
}
