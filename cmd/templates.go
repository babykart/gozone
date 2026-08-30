// HTML template loading: the embedded template set, its FuncMap, and the
// cache-busting asset version baked into it.
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/url"
	"strings"

	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/web"
)

// relativeName strips the zone suffix from a record name. The apex (zone name
// itself) is displayed as "@". For example, with zone "example.com.", the
// record "www.example.com." becomes "www" and "example.com." becomes "@".
//
// The comparison is case-insensitive (DNS names are), and the zone name is
// normalized to end with a dot before matching so callers may pass either
// "example.com" or "example.com.".
func relativeName(recordName, zoneName string) string {
	// Normalize the zone name: lowercase, ensure trailing dot.
	zone := strings.ToLower(zoneName)
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}

	record := strings.ToLower(recordName)

	// Apex: record name matches the zone name exactly.
	if record == zone {
		return "@"
	}

	// Sub-domain: record name ends with ".<zone>". The leading dot prevents
	// "notexample.com." from matching zone "example.com.".
	dotZone := "." + zone
	if len(record) > len(dotZone) && strings.HasSuffix(record, dotZone) {
		rel := recordName[:len(recordName)-len(dotZone)]
		return strings.TrimSuffix(rel, ".")
	}

	// Record is not in this zone; return as-is.
	return recordName
}

// staticAssetVersion returns a short content hash of the bundled JS/CSS so
// templates can append it as ?v=… to asset URLs. Deploying a new build changes
// the hash, which invalidates browser caches despite the 24h max-age served by
// fileServer (REVIEW.md L-16c). Computed from the embedded files, so it varies
// on every content change regardless of the version label.
func staticAssetVersion() string {
	h := sha256.New()
	for _, name := range []string{"static/js/theme.js", "static/js/app.js", "static/css/style.css"} {
		data, err := web.FS.ReadFile(name)
		if err != nil {
			// Embedded files: unreachable in practice. Fall back to the build
			// version so cache-busting still varies per release.
			return version
		}
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// templateFuncMap builds the FuncMap shared by the real templates and the
// handler-test stub set. assetVer is baked into the assetVersion func; see
// staticAssetVersion for the cache-busting rationale.
func templateFuncMap(assetVer string) template.FuncMap {
	return template.FuncMap{
		"add":          func(a, b int) int { return a + b },
		"sub":          func(a, b int) int { return a - b },
		"urlquery":     url.QueryEscape,
		"relativeName": relativeName,
		"assetVersion": func() string { return assetVer },
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict expects an even number of arguments")
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},
	}
}

// parseTemplates loads all HTML templates from the embedded filesystem.
func parseTemplates() (*template.Template, error) {
	assetVer := staticAssetVersion()
	tmpl, err := template.New("base").Funcs(templateFuncMap(assetVer)).ParseFS(web.FS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("load embedded templates: %w", err)
	}
	// template.New("base") registers an empty "base" template that only carries
	// the FuncMap; it has no parsed content and is not a renderable page, so
	// exclude it from the count to avoid an off-by-one.
	count := 0
	for _, t := range tmpl.Templates() {
		if t.Name() != "base" {
			count++
		}
	}
	logger.Info("templates loaded", "count", count)
	return tmpl, nil
}
