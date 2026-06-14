package constants

import "testing"

func TestExported(t *testing.T) {
	if SessionCookieName != "gozone_session" {
		t.Errorf("SessionCookieName = %q, want gozone_session", SessionCookieName)
	}
	if NewAPIKeyCookieName != "gozone_new_api_key" {
		t.Errorf("NewAPIKeyCookieName = %q, want gozone_new_api_key", NewAPIKeyCookieName)
	}
	if DefaultBcryptCost != 12 {
		t.Errorf("DefaultBcryptCost = %d, want 12", DefaultBcryptCost)
	}
	if MaxOpenConns != 1 {
		t.Errorf("MaxOpenConns = %d, want 1", MaxOpenConns)
	}
}
