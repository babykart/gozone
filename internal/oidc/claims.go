package oidc

import (
	"encoding/json"
	"strings"
)

// ClaimStrings extracts string values from a raw claim set along a dotted path.
// It supports:
//   - top-level or nested object paths ("groups", "realm_access.roles");
//   - a JSON array of strings (["a","b"]);
//   - a single JSON string ("a" → ["a"]).
//
// An empty path, a nil map, a missing claim, or a non-string/non-array value
// yields nil. This lets the handler apply provider-agnostic role/group mapping
// without hard-coding each IdP's claim shape (Keycloak realm_access.roles,
// Authentik groups, Gitea teams, etc.).
func ClaimStrings(raw map[string]json.RawMessage, path string) []string {
	if path == "" || len(raw) == 0 {
		return nil
	}
	current := raw
	for _, key := range strings.Split(path, ".") {
		v, ok := current[key]
		if !ok {
			return nil
		}
		// Try array/string first; if it is a nested object, descend.
		if out, ok := decodeStringArray(v); ok {
			return out
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(v, &nested); err != nil {
			return nil
		}
		current = nested
	}
	return nil
}

// decodeStringArray decodes a JSON value into a string slice. Returns ok=false
// for anything that is not a string or array of strings.
func decodeStringArray(v json.RawMessage) ([]string, bool) {
	// Single string.
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return []string{s}, true
	}
	// Array of strings (skip non-string elements rather than failing, so a
	// heterogeneous array still yields its string members).
	var arr []json.RawMessage
	if err := json.Unmarshal(v, &arr); err != nil {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		var es string
		if err := json.Unmarshal(e, &es); err == nil {
			out = append(out, es)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
