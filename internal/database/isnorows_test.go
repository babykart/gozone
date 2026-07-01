package database

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
)

// TestIsNoRows is the regression test for m18: the no-rows check must use
// errors.Is so that a driver or wrapper that layers an error around
// sql.ErrNoRows is still detected (a direct == comparison would miss it).
func TestIsNoRows(t *testing.T) {
	if !isNoRows(sql.ErrNoRows) {
		t.Error("isNoRows must detect an unwrapped sql.ErrNoRows")
	}
	if !isNoRows(fmt.Errorf("scan user: %w", sql.ErrNoRows)) {
		t.Error("isNoRows must detect a wrapped sql.ErrNoRows (regression for m18)")
	}
	if isNoRows(errors.New("connection refused")) {
		t.Error("isNoRows must not match unrelated errors")
	}
	if isNoRows(nil) {
		t.Error("isNoRows(nil) must be false")
	}
}
