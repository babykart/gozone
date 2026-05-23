package dyndns

import "golang.org/x/crypto/bcrypt"

// compareBcrypt compares a plaintext password against a bcrypt hash.
func compareBcrypt(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
