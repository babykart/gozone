package oidc

import (
	"crypto/hmac"
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

// statePayload is the data carried inside the signed state parameter. The
// browser sees it (base64-encoded) but cannot tamper with it thanks to the
// appended HMAC. Carrying the PKCE verifier and nonce here keeps the flow
// stateless — no server-side session store is needed — while the verifier
// remains unusable to an attacker who only observes the state value (they
// still need it exchanged at the token endpoint, which requires the client
// secret).
type statePayload struct {
	Provider string `json:"p"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Exp      int64  `json:"e"`
}

// newStateToken builds a signed state token for the given provider, embedding a
// fresh random nonce and PKCE code verifier. It returns the opaque state
// string (to send to the IdP and match on callback) and the S256 code challenge
// (to include in the authorization request).
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
	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", "", "", fmt.Errorf("marshal state payload: %w", err)
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(enc))
	sig := hex.EncodeToString(mac.Sum(nil))
	state = enc + "." + sig
	return state, verifier, challenge, nonce, nil
}

// verifyStateToken validates the HMAC signature and expiry of a state token and
// returns its payload. It is constant-time in the HMAC comparison. An expired,
// tampered, or malformed token yields an error; the callback handler treats
// every error as a failed CSRF check and aborts the flow.
func verifyStateToken(key []byte, state string) (statePayload, error) {
	var p statePayload
	dot := byteIndex(state, '.')
	if dot < 0 {
		return p, fmt.Errorf("state: missing signature")
	}
	enc, sig := state[:dot], state[dot+1:]
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(enc))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return p, fmt.Errorf("state: invalid signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return p, fmt.Errorf("state: decode payload: %w", err)
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return p, fmt.Errorf("state: unmarshal payload: %w", err)
	}
	if time.Now().Unix() > p.Exp {
		return p, fmt.Errorf("state: expired")
	}
	return p, nil
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
