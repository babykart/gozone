package oidc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// stateTTL is how long an OIDC state token is considered valid. The whole
// redirect dance (GoZone → IdP → GoZone) should complete in seconds; 10 minutes
// allows for a user that hesitates on the IdP consent/login screen.
const stateTTL = 10 * time.Minute

// statePayload is the data carried inside the AES-256-GCM-encrypted state
// parameter. The token is opaque to the browser: confidentiality comes from
// AES-GCM and integrity from the GCM authentication tag (no separate HMAC is
// needed). Carrying the PKCE verifier and nonce here keeps the flow stateless
// — no server-side session store is needed — and the verifier/nonce are now
// unrecoverable to an attacker who only observes the state value (URL, server
// logs, Referer headers). AEAD also means a tampered or wrong-key token fails
// to decrypt, so the callback can treat any decryption error as a failed CSRF
// check.
type statePayload struct {
	Provider string `json:"p"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Exp      int64  `json:"e"`
}

// newStateToken builds an encrypted state token for the given provider,
// embedding a fresh random nonce and PKCE code verifier. It returns the opaque
// state string (to send to the IdP and match on callback) and the S256 code
// challenge (to include in the authorization request).
//
// The 32-byte key is the HKDF-derived OIDC state key (config.Server.OIDCStateKey),
// used directly as the AES-256 key. The token layout is
// base64url(nonce) + "." + base64url(ciphertext||tag); a fresh random nonce is
// drawn per token, which is safe for GCM at the volumes OIDC produces (the
// 96-bit nonce has a collision ceiling far above any deployment's token count).
func newStateToken(key []byte, provider string) (state, verifier, challenge, nonce string, err error) {
	verifier, err = randomCodeVerifier()
	if err != nil {
		return "", "", "", "", fmt.Errorf("generate pkce verifier: %w", err)
	}
	nonce, err = randomString(32)
	if err != nil {
		return "", "", "", "", fmt.Errorf("generate nonce: %w", err)
	}
	challenge = s256Challenge(verifier)

	payload := statePayload{
		Provider: provider,
		Nonce:    nonce,
		Verifier: verifier,
		Exp:      time.Now().Add(stateTTL).Unix(),
	}
	state, err = encryptState(key, payload)
	if err != nil {
		return "", "", "", "", err
	}
	return state, verifier, challenge, nonce, nil
}

// verifyStateToken decrypts and authenticates the state token and returns its
// payload. AES-GCM's authentication tag makes any tampering or key mismatch
// fail at decryption. An expired, tampered, or malformed token yields an error;
// the callback handler treats every error as a failed CSRF check and aborts
// the flow.
func verifyStateToken(key []byte, state string) (statePayload, error) {
	p, err := decryptState(key, state)
	if err != nil {
		return p, err
	}
	if time.Now().Unix() > p.Exp {
		return p, fmt.Errorf("state: expired")
	}
	return p, nil
}

// encryptState AES-256-GCM encrypts + authenticates the payload, returning
// base64url(nonce) + "." + base64url(ciphertext||tag).
func encryptState(key []byte, p statePayload) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("state: marshal payload: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("state: generate nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, body, nil)
	return base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ct), nil
}

// decryptState reverses encryptState. Any structural tampering, truncation, or
// key mismatch surfaces as a decryption error from gcm.Open.
func decryptState(key []byte, state string) (statePayload, error) {
	var p statePayload
	dot := byteIndex(state, '.')
	if dot < 0 {
		return p, fmt.Errorf("state: missing nonce")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(state[:dot])
	if err != nil {
		return p, fmt.Errorf("state: decode nonce: %w", err)
	}
	ct, err := base64.RawURLEncoding.DecodeString(state[dot+1:])
	if err != nil {
		return p, fmt.Errorf("state: decode payload: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return p, err
	}
	body, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return p, fmt.Errorf("state: invalid ciphertext")
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("state: unmarshal payload: %w", err)
	}
	return p, nil
}

// newGCM builds an AES-256-GCM AEAD from the 32-byte state key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("state: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("state: init gcm: %w", err)
	}
	return gcm, nil
}

// s256Challenge computes the S256 PKCE code challenge for a verifier:
// BASE64URL(SHA256(verifier)).
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomCodeVerifier generates a high-entropy PKCE code verifier (43-128 char
// URL-safe). We use 48 random bytes → 64 base64url chars.
func randomCodeVerifier() (string, error) {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomString returns n random bytes as a hex string.
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// byteIndex returns the index of the first occurrence of c in s, or -1.
func byteIndex(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
