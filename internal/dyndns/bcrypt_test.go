package dyndns

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCompareBcrypt_Valid(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), 4)
	if err != nil {
		t.Fatal(err)
	}

	if err := compareBcrypt(string(hash), "correct-password"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestCompareBcrypt_Invalid(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-password"), 4)
	if err != nil {
		t.Fatal(err)
	}

	if err := compareBcrypt(string(hash), "wrong-password"); err == nil {
		t.Error("expected error for wrong password")
	}
}

func TestCompareBcrypt_EmptyHash(t *testing.T) {
	if err := compareBcrypt("", "test"); err == nil {
		t.Error("expected error for empty hash")
	}
}
