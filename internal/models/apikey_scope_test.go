package models

import "testing"

func TestParseAPIKeyScope(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   APIKeyScope
		wantOK bool
	}{
		{"api read", "api:read", ScopeAPIRead, true},
		{"api write", "api:write", ScopeAPIWrite, true},
		{"mcp read", "mcp:read", ScopeMCPRead, true},
		{"mcp write", "mcp:write", ScopeMCPWrite, true},
		{"upper case", "API:WRITE", ScopeAPIWrite, true},
		{"mixed case", "Mcp:Read", ScopeMCPRead, true},
		{"empty", "", "", false},
		{"bare api", "api", "", false},
		{"bare mcp", "mcp", "", false},
		{"unknown admin", "mcp:admin", "", false},
		{"unknown surface", "grpc:read", "", false},
		{"trailing space", "api:read ", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseAPIKeyScope(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("ParseAPIKeyScope(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("ParseAPIKeyScope(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAPIKeyScopeSurface(t *testing.T) {
	tests := []struct {
		scope APIKeyScope
		want  APIKeySurface
	}{
		{ScopeAPIRead, SurfaceAPI},
		{ScopeAPIWrite, SurfaceAPI},
		{ScopeMCPRead, SurfaceMCP},
		{ScopeMCPWrite, SurfaceMCP},
		{"", SurfaceAPI},
		{"bogus", SurfaceAPI},
	}
	for _, tt := range tests {
		if got := tt.scope.Surface(); got != tt.want {
			t.Errorf("APIKeyScope(%q).Surface() = %q, want %q", tt.scope, got, tt.want)
		}
	}
}

func TestAPIKeyScopeCanWrite(t *testing.T) {
	tests := []struct {
		scope APIKeyScope
		want  bool
	}{
		{ScopeAPIRead, false},
		{ScopeAPIWrite, true},
		{ScopeMCPRead, false},
		{ScopeMCPWrite, true},
		{"", false},
		{"bogus", false},
	}
	for _, tt := range tests {
		if got := tt.scope.CanWrite(); got != tt.want {
			t.Errorf("APIKeyScope(%q).CanWrite() = %v, want %v", tt.scope, got, tt.want)
		}
	}
}
