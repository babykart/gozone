package models

import (
	"testing"
)

func TestUserIsAdmin(t *testing.T) {
	tests := []struct {
		user  User
		admin bool
	}{
		{User{Role: "admin"}, true},
		{User{Role: "user"}, false},
		{User{Role: ""}, false},
		{User{Role: "Admin"}, false}, // case-sensitive
	}

	for _, tt := range tests {
		got := tt.user.IsAdmin()
		if got != tt.admin {
			t.Errorf("User{Role: %q}.IsAdmin() = %v, want %v", tt.user.Role, got, tt.admin)
		}
	}
}
