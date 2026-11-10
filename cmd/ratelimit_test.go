package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/babykart/gozone/internal/middleware"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/testutil"
	"github.com/babykart/gozone/internal/validators"
)

// TestAPIRateLimitRunsBeforeAuth guards the M-SEC2 fix: the IP-based rate
// limiter on /api/v1 must execute BEFORE the APIKeyAuth middleware so that a
// key-rotation flood is rejected with 429 without ever reaching the DB lookup
// (SELECT ... FROM api_keys). A regression that reverts the order would let an
// attacker exhaust the database with arbitrary keys.
//
// The test builds the same middleware composition used in run() — IP limiter,
// then a stand-in for APIKeyAuth that counts invocations, then the per-key
// limiter — and verifies the auth step is never called once the IP bucket is
// drained.
func TestAPIRateLimitRunsBeforeAuth(t *testing.T) {
	const ipLimit = 3
	ipLimiter := middleware.NewRateLimiter(ipLimit)
	t.Cleanup(ipLimiter.Close)
	keyLimiter := middleware.NewRateLimiter(100)
	t.Cleanup(keyLimiter.Close)

	var authCalls int32
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&authCalls, 1)
			next.ServeHTTP(w, r)
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Compose in the production order: IP limit -> auth -> key limit.
	stack := ipLimiter.Limit(middleware.ExtractIP)(authMiddleware(keyLimiter.Limit(middleware.ExtractAPIKey)(handler)))

	// Fire one more request than the IP bucket allows, all from the same source
	// address (httptest always sets RemoteAddr to "192.0.2.1:1234").
	for i := 0; i < ipLimit+1; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
		r.Header.Set("X-API-Key", "rotating-random-key")
		stack.ServeHTTP(w, r)
	}

	got := atomic.LoadInt32(&authCalls)
	if got != ipLimit {
		t.Errorf("auth middleware invoked %d times, want %d (IP limiter must block the last request BEFORE auth — M-SEC2 regression)",
			got, ipLimit)
	}
}

// TestLoginUsernameKey covers the m35 fix at the key-function level: an empty
// (or whitespace-only) username must map to a dedicated sentinel bucket rather
// than "" (which bypasses the per-username rate limiter), while real usernames
// are lowercased and trimmed. Over-long usernames (which cannot name a real
// account) also collapse onto the sentinel so the bucket map key stays bounded.
func TestLoginUsernameKey(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"empty body", "", emptyUsernameRateLimitKey},
		{"no username field", "foo=bar", emptyUsernameRateLimitKey},
		{"whitespace only", "username=%20%20%20", emptyUsernameRateLimitKey},
		{"simple", "username=admin", "admin"},
		{"uppercased", "username=ADMIN", "admin"},
		{"surrounding spaces", "username=+admin+", "admin"},
		// Exactly the maximum valid length: kept as its own key.
		{"max length username", "username=" + strings.Repeat("a", validators.MaxUsernameLength), strings.Repeat("a", validators.MaxUsernameLength)},
		// One byte past the maximum: cannot name a real account, shares the sentinel.
		{"over max length", "username=" + strings.Repeat("a", validators.MaxUsernameLength+1), emptyUsernameRateLimitKey},
		// Pathological payload: a kilobyte-long username collapses onto the sentinel.
		{"kilobyte username", "username=" + strings.Repeat("z", 1024), emptyUsernameRateLimitKey},
		// Multi-byte input is bounded by BYTES, not runes: 33 × 'é' is 33
		// runes but 66 bytes — one byte past the cap even though the rune
		// count is not — so it shares the sentinel. 10 × 'é' (20 bytes)
		// stays under the cap and keeps its own key.
		{"multi-byte over cap", "username=" + strings.Repeat("\u00e9", 33), emptyUsernameRateLimitKey},
		{"multi-byte under cap", "username=" + strings.Repeat("\u00e9", 10), strings.Repeat("\u00e9", 10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if got := loginUsernameKey(r); got != tt.want {
				t.Errorf("loginUsernameKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoginUsernameRateLimit_LongUsernamesShareBucket is the behavioural
// companion to the key-function table above: login attempts carrying many
// distinct over-long usernames must all consume the same shared bucket (and
// eventually hit 429) instead of allocating one bucket per distinct payload,
// which previously let an unauthenticated caller grow the limiter's memory
// with the request body as the only bound.
func TestLoginUsernameRateLimit_LongUsernamesShareBucket(t *testing.T) {
	const userLimit = 3
	limiter := middleware.NewRateLimiter(userLimit)
	t.Cleanup(limiter.Close)

	handler := limiter.Limit(loginUsernameKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// userLimit+1 distinct over-long usernames: they share the sentinel
	// bucket, so the last request must be 429.
	var lastCode int
	for i := 0; i < userLimit+1; i++ {
		body := "username=" + strings.Repeat("a", 64) + fmt.Sprint(i)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(w, r)
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("expected the last distinct over-long username to be rate-limited (shared bucket), got %d", lastCode)
	}
}

// TestLoginUsernameRateLimit_EmptyUsernameNotBypassed is the m35 behavioral
// regression test: empty-username login attempts must consume the per-username
// rate-limit bucket instead of bypassing the limiter.
func TestLoginUsernameRateLimit_EmptyUsernameNotBypassed(t *testing.T) {
	const userLimit = 3
	limiter := middleware.NewRateLimiter(userLimit)
	t.Cleanup(limiter.Close)

	handler := limiter.Limit(loginUsernameKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Fire userLimit+1 login POSTs with NO username. Before the fix every one
	// bypassed the limiter (key "" -> no bucket consumed) and all returned 200.
	// After the fix they share the <empty-username> bucket, so the last request
	// must be 429.
	var lastCode int
	for i := 0; i < userLimit+1; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(w, r)
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Errorf("after %d empty-username requests, expected the %dth to be 429, got %d (limiter bypassed — m35 regression)",
			userLimit, userLimit+1, lastCode)
	}
}

// TestHealthReadyRateLimit_BlocksBeforeOutboundWork pins the readiness wiring
// semantics: the per-IP limiter runs BEFORE the handler, so once the bucket is
// drained an anonymous flooder gets 429s and the handler — which performs a DB
// ping and an uncached outbound PowerDNS call per hit — is never invoked.
// Without the bound, every cheap request forced real outbound work (an
// amplification surface) and leaked dependency status to unauthenticated
// callers.
func TestHealthReadyRateLimit_BlocksBeforeOutboundWork(t *testing.T) {
	limiter := middleware.NewRateLimiter(healthReadyRateLimitPerMinute)
	t.Cleanup(limiter.Close)

	var handlerCalls int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&handlerCalls, 1)
		w.WriteHeader(http.StatusOK)
	})

	stack := limiter.Limit(middleware.ExtractIP)(handler)

	// httptest pins RemoteAddr to "192.0.2.1:1234", so every request draws
	// from the same per-IP bucket.
	var lastCode int
	for i := 0; i < healthReadyRateLimitPerMinute+5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		stack.ServeHTTP(w, r)
		lastCode = w.Code
	}

	if lastCode != http.StatusTooManyRequests {
		t.Errorf("request past the bucket must return 429, got %d", lastCode)
	}
	if got := atomic.LoadInt32(&handlerCalls); got != healthReadyRateLimitPerMinute {
		t.Errorf("handler invoked %d times, want exactly %d (the limiter must gate the outbound DB/PowerDNS work)",
			got, healthReadyRateLimitPerMinute)
	}
	if ra := lastRetryAfter(stack); ra == "" {
		t.Error("expected a Retry-After header on the 429 response")
	}
}

// lastRetryAfter drives one more request through the (drained) stack and
// returns its Retry-After header value, or "" when absent.
func lastRetryAfter(stack http.Handler) string {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	stack.ServeHTTP(w, r)
	return w.Header().Get("Retry-After")
}

// newLoginRequest builds a POST /login request whose form carries the given
// (already form-encoded) body and whose TCP source address is remoteAddr.
// ExtractIP resolves the IP from RemoteAddr (no context IP is set here), so
// remoteAddr controls which per-IP / per-pair bucket a request draws from.
func newLoginRequest(body, remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	return r
}

// TestLoginIPKey pins the exact per-IP family prefix. The family prefix is
// what keeps the per-IP bucket namespace disjoint from the per-username and
// per-(username,IP) families sharing the same rate_limit_counters table.
func TestLoginIPKey(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{"ipv4", "192.0.2.1:1234", "login:ip:192.0.2.1"},
		{"ipv6", "[2001:db8::1]:443", "login:ip:2001:db8::1"},
		{"ipv6 zone id", "[fe80::1%eth0]:1234", "login:ip:fe80::1%eth0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loginIPKey(newLoginRequest("", tt.remoteAddr)); got != tt.want {
				t.Errorf("loginIPKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoginUserIPKey pins the exact pair encoding
// "login:pair:" + byte-len(username) + ":" + username + "|" + ip. The
// byte-length prefix makes the encoding structurally injective: a crafted
// username such as "admin|192.0.2.1" can no longer reproduce the pair key of
// (admin, 192.0.2.1) — the attack that let one caller exhaust another user's
// bucket. The username part reuses loginUsernameKey verbatim (lowercased,
// trimmed, sentinel for empty/over-long), so casing and whitespace variants
// of the same attempt share a bucket.
func TestLoginUserIPKey(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		remoteAddr string
		want       string
	}{
		{"simple", "username=admin", "192.0.2.1:1234", "login:pair:5:admin|192.0.2.1"},
		{"uppercased folds", "username=ADMIN", "192.0.2.1:1234", "login:pair:5:admin|192.0.2.1"},
		{"surrounding spaces fold", "username=+admin+", "192.0.2.1:1234", "login:pair:5:admin|192.0.2.1"},
		{
			"empty username sentinel",
			"",
			"192.0.2.1:1234",
			"login:pair:" + fmt.Sprint(len(emptyUsernameRateLimitKey)) + ":" + emptyUsernameRateLimitKey + "|192.0.2.1",
		},
		{
			"over-long username sentinel",
			"username=" + strings.Repeat("a", validators.MaxUsernameLength+1),
			"192.0.2.1:1234",
			"login:pair:" + fmt.Sprint(len(emptyUsernameRateLimitKey)) + ":" + emptyUsernameRateLimitKey + "|192.0.2.1",
		},
		// Crafted username embedding the separator and a victim IP: the
		// length prefix (15) keeps it distinct from the victim's pair key
		// "login:pair:5:admin|192.0.2.1".
		{"crafted separator username", "username=admin|192.0.2.1", "10.0.0.1:9999", "login:pair:15:admin|192.0.2.1|10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loginUserIPKey(newLoginRequest(tt.body, tt.remoteAddr)); got != tt.want {
				t.Errorf("loginUserIPKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoginUserKey pins the new global per-username ceiling key. Unlike the
// pair key this one deliberately ignores the IP: it is the fleet-wide,
// much-higher ceiling on a single targeted username across all sources.
func TestLoginUserKey(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"simple", "username=admin", "login:user:admin"},
		{"uppercased folds", "username=ADMIN", "login:user:admin"},
		{"surrounding spaces fold", "username=+admin+", "login:user:admin"},
		{"empty username sentinel", "", "login:user:" + emptyUsernameRateLimitKey},
		{"over-long username sentinel", "username=" + strings.Repeat("a", validators.MaxUsernameLength+1), "login:user:" + emptyUsernameRateLimitKey},
		// An IP-shaped username must land in a DIFFERENT namespace than the
		// per-IP family (see TestLoginKeyFamiliesDisjoint).
		{"ip-shaped username", "username=192.0.2.1", "login:user:192.0.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loginUserKey(newLoginRequest(tt.body, "192.0.2.1:1234")); got != tt.want {
				t.Errorf("loginUserKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestLoginKeyFamiliesDisjoint guards the namespace fix: all login limiter
// families share one bucket_key namespace (the rate_limit_counters table),
// so the raw key material must never overlap. The regression: username
// "192.0.2.1" from any IP used to draw from the same bucket as a real client
// connecting from 192.0.2.1.
func TestLoginKeyFamiliesDisjoint(t *testing.T) {
	r := newLoginRequest("username=192.0.2.1", "192.0.2.1:1234")
	ip, pair, user := loginIPKey(r), loginUserIPKey(r), loginUserKey(r)

	if ip == user {
		t.Errorf("per-IP key %q collides with per-user key for an IP-shaped username", ip)
	}
	if ip == pair {
		t.Errorf("per-IP key %q collides with pair key", ip)
	}
	if pair == user {
		t.Errorf("pair key %q collides with per-user key", pair)
	}
	if !strings.HasPrefix(ip, "login:ip:") || !strings.HasPrefix(pair, "login:pair:") || !strings.HasPrefix(user, "login:user:") {
		t.Errorf("family prefixes wrong: ip=%q pair=%q user=%q", ip, pair, user)
	}

	// An attacker forging the victim's "username|ip" string as a username
	// must not land in the victim's pair bucket nor global bucket.
	victim := newLoginRequest("username=admin", "198.51.100.9:1234")
	attacker := newLoginRequest("username=admin|198.51.100.9", "198.51.100.9:1234")
	if got, want := loginUserIPKey(victim), "login:pair:5:admin|198.51.100.9"; got != want {
		t.Fatalf("victim pair key = %q, want %q", got, want)
	}
	if got := loginUserIPKey(attacker); got == loginUserIPKey(victim) {
		t.Errorf("attacker pair key %q collides with the victim pair bucket", got)
	}
	if got := loginUserKey(attacker); got == loginUserKey(victim) {
		t.Errorf("attacker global key %q collides with the victim global bucket", got)
	}
}

// TestLoginUserIPKey_Injectivity spot-checks that distinct (username, ip)
// attempts never map to the same pair key — the structural property the
// byte-length prefix exists to provide.
func TestLoginUserIPKey_Injectivity(t *testing.T) {
	type attempt struct {
		body       string
		remoteAddr string
	}
	attempts := []attempt{
		{"username=admin", "192.0.2.1:1234"},
		{"username=admin", "10.0.0.1:1234"},
		{"username=root", "192.0.2.1:1234"},
		// The crafted separator cases: same IP, separator-laden usernames.
		{"username=admin|192.0.2.1", "192.0.2.1:1234"},
		{"username=admin|192.0.2.1", "10.0.0.1:1234"},
		// Empty usernames collapse onto the sentinel pair bucket for the
		// SAME ip only. (The over-long username folds to the same sentinel
		// and is already asserted in TestLoginUserIPKey, so it is not part
		// of the uniqueness set.)
		{"", "192.0.2.1:1234"},
		{"", "10.0.0.1:1234"},
	}
	seen := map[string]attempt{}
	for _, a := range attempts {
		key := loginUserIPKey(newLoginRequest(a.body, a.remoteAddr))
		if prev, dup := seen[key]; dup {
			t.Errorf("pair key %q produced by both %+v and %+v", key, prev, a)
			continue
		}
		seen[key] = a
	}
}

// TestLoginRateLimitKeyCap pins the final-key hard cap: any composed key
// longer than 160 bytes folds to a family-prefixed sentinel, so a malformed
// or hostile RemoteAddr (unparseable fallback, IPv6 zone id, oversized
// garbage) can never overflow the bucket_key column (MySQL VARCHAR(191)) or
// grow the in-process map unboundedly. Sentinels stay under the cap and
// remain distinct per family.
func TestLoginRateLimitKeyCap(t *testing.T) {
	const capBytes = 160

	t.Run("ip family folds oversized remote addr", func(t *testing.T) {
		// No port: SplitHostPort fails, ExtractIP returns the raw
		// (200-byte) RemoteAddr verbatim.
		got := loginIPKey(newLoginRequest("", strings.Repeat("a", 200)))
		if got != "login:ip:<oversized-ip>" {
			t.Errorf("loginIPKey(oversized) = %q, want %q", got, "login:ip:<oversized-ip>")
		}
		if len(got) > capBytes {
			t.Errorf("folded key is %d bytes, must be <= %d", len(got), capBytes)
		}
	})

	t.Run("pair family folds oversized ipv6 zone id", func(t *testing.T) {
		r := newLoginRequest("username=admin", "[fe80::1%"+strings.Repeat("z", 200)+"]:1234")
		got := loginUserIPKey(r)
		if got != "login:pair:<oversized-key>" {
			t.Errorf("loginUserIPKey(oversized) = %q, want %q", got, "login:pair:<oversized-key>")
		}
		if len(got) > capBytes {
			t.Errorf("folded key is %d bytes, must be <= %d", len(got), capBytes)
		}
	})

	t.Run("family sentinels are distinct and prefixed", func(t *testing.T) {
		ipSentinel := loginIPKey(newLoginRequest("", strings.Repeat("a", 200)))
		pairSentinel := loginUserIPKey(newLoginRequest("username=admin", strings.Repeat("b", 200)))
		if ipSentinel == pairSentinel {
			t.Errorf("folded sentinels must stay family-distinct, both = %q", ipSentinel)
		}
	})

	t.Run("boundary 160 bytes is not folded", func(t *testing.T) {
		// "login:ip:" is 9 bytes: a 151-byte IP composes to exactly 160.
		ip := strings.Repeat("a", 151)
		got := loginIPKey(newLoginRequest("", ip+":1"))
		want := "login:ip:" + ip
		if got != want {
			t.Errorf("loginIPKey(151-byte ip) = %q, want un-folded %q", got, want)
		}
		if len(got) != capBytes {
			t.Errorf("boundary key length = %d, want exactly %d", len(got), capBytes)
		}
	})

	t.Run("normal keys never fold", func(t *testing.T) {
		r := newLoginRequest("username=admin", "[fe80::1%eth0]:1234")
		for name, key := range map[string]string{
			"ip":   loginIPKey(r),
			"pair": loginUserIPKey(r),
			"user": loginUserKey(r),
		} {
			if strings.Contains(key, "<oversized") {
				t.Errorf("%s key %q folded despite being short", name, key)
			}
			if len(key) > capBytes {
				t.Errorf("%s key is %d bytes, want <= %d", name, len(key), capBytes)
			}
		}
	})
}

// TestLoginPairRateLimit_CrossIPIsolation is the core regression for the
// attack this change fixes: the per-username limiter used to key on the
// username alone, so five attempts at "admin" from one attacker's IP
// exhausted the shared bucket and a legitimate admin logging in from their
// own IP got 429. With the (username, IP) pair key the attacker's bucket is
// their own.
func TestLoginPairRateLimit_CrossIPIsolation(t *testing.T) {
	const pairLimit = 5
	const attacker = "198.51.100.1:1234"
	const victim = "198.51.100.2:1234"

	type stack struct {
		post         func(body, remoteAddr string) int
		handlerCalls *int32
	}
	build := func(t *testing.T, chain func(http.Handler) http.Handler) *stack {
		t.Helper()
		var calls int32
		s := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&calls, 1)
			w.WriteHeader(http.StatusOK)
		}))
		return &stack{
			post: func(body, remoteAddr string) int {
				w := httptest.NewRecorder()
				s.ServeHTTP(w, newLoginRequest(body, remoteAddr))
				return w.Code
			},
			handlerCalls: &calls,
		}
	}
	assertIsolation := func(t *testing.T, s *stack) {
		t.Helper()
		// The attacker exhausts THEIR pair bucket.
		for i := 0; i < pairLimit; i++ {
			if code := s.post("username=admin", attacker); code != http.StatusOK {
				t.Fatalf("attempt %d from attacker: got %d, want 200", i+1, code)
			}
		}
		if code := s.post("username=admin", attacker); code != http.StatusTooManyRequests {
			t.Fatalf("attempt %d from attacker: got %d, want 429 (pair bucket exhausted)", pairLimit+1, code)
		}
		// The legitimate admin from another IP is unaffected.
		if code := s.post("username=admin", victim); code != http.StatusOK {
			t.Fatalf("victim request after attacker exhaustion: got %d, want 200 (cross-IP isolation broken)", code)
		}
		if got := atomic.LoadInt32(s.handlerCalls); got != pairLimit+1 {
			t.Errorf("handler invoked %d times, want %d", got, pairLimit+1)
		}
	}

	t.Run("in-memory chain", func(t *testing.T) {
		limiter := middleware.NewRateLimiter(pairLimit)
		t.Cleanup(limiter.Close)
		assertIsolation(t, build(t, limiter.Limit(loginUserIPKey)))
	})

	t.Run("db chain", func(t *testing.T) {
		db := testutil.NewTestDB(t)
		dbLimiter := middleware.NewDBRateLimiter(db, pairLimit)

		// Seed the attacker's pair bucket to the limit in BOTH the current
		// and the next fixed window instead of replaying the request loop:
		// the DB limiter derives the window from the clock on every request,
		// so a loop would flake when the minute boundary falls between the
		// last two attempts. Seeding both windows makes the 429 assertion
		// deterministic no matter when the test runs.
		attackerKey := loginUserIPKey(newLoginRequest("username=admin", attacker))
		window := time.Now().UTC().Truncate(time.Minute)
		for _, start := range []time.Time{window, window.Add(time.Minute)} {
			for i := 0; i < pairLimit; i++ {
				ok, err := db.HitRateLimit(context.Background(), attackerKey, start, pairLimit)
				if err != nil {
					t.Fatalf("seeding attacker bucket: %v", err)
				}
				if !ok {
					t.Fatalf("seeding attacker bucket: hit %d rejected within limit", i+1)
				}
			}
		}

		s := build(t, dbLimiter.Limit(loginUserIPKey))
		if code := s.post("username=admin", attacker); code != http.StatusTooManyRequests {
			t.Fatalf("attacker request with exhausted bucket: got %d, want 429", code)
		}
		// The legitimate admin from another IP is unaffected.
		if code := s.post("username=admin", victim); code != http.StatusOK {
			t.Fatalf("victim request after attacker exhaustion: got %d, want 200 (cross-IP isolation broken)", code)
		}
		if got := atomic.LoadInt32(s.handlerCalls); got != 1 {
			t.Errorf("handler invoked %d times, want 1 (only the victim request; the attacker's 429 never reaches the handler)", got)
		}
	})
}

// TestLoginGlobalRateLimit_Scoping pins the new global per-username ceiling:
// it must count attempts for the SAME username across DIFFERENT IPs (that is
// the point of the ceiling — it bounds distributed brute-force), while
// leaving other usernames untouched.
func TestLoginGlobalRateLimit_Scoping(t *testing.T) {
	const globalLimit = 3
	limiter := middleware.NewRateLimiter(globalLimit)
	t.Cleanup(limiter.Close)

	var handlerCalls int32
	stack := limiter.Limit(loginUserKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&handlerCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))

	post := func(body, remoteAddr string) int {
		w := httptest.NewRecorder()
		stack.ServeHTTP(w, newLoginRequest(body, remoteAddr))
		return w.Code
	}

	// globalLimit attempts at "admin" from distinct IPs: all allowed, and
	// together they exhaust the shared per-username budget.
	for i := 0; i < globalLimit; i++ {
		if code := post("username=admin", fmt.Sprintf("198.51.100.%d:1234", i+1)); code != http.StatusOK {
			t.Fatalf("attempt %d at admin from a fresh IP: got %d, want 200", i+1, code)
		}
	}
	if code := post("username=admin", "198.51.100.99:1234"); code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d at admin from yet another IP: got %d, want 429 (global ceiling ignored the IP spread)", globalLimit+1, code)
	}
	// A different username has its own global bucket.
	if code := post("username=root", "198.51.100.100:1234"); code != http.StatusOK {
		t.Fatalf("request for a different username: got %d, want 200 (global buckets must be per-username)", code)
	}
	if got := atomic.LoadInt32(&handlerCalls); got != globalLimit+1 {
		t.Errorf("handler invoked %d times, want %d", got, globalLimit+1)
	}
}

// newChangePasswordRequest builds a POST /change-password request carrying the
// given context user (mirroring what authMiddleware stores via
// middleware.UserContextKey) and the given TCP source address.
// changePasswordUserIPKey reads the user from the context and the IP via
// middleware.ExtractIP (RemoteAddr fallback, as in the unit tests for the
// login family), so this helper controls both halves of the pair key.
func newChangePasswordRequest(user *models.User, remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/change-password", nil)
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	if user != nil {
		r = r.WithContext(context.WithValue(r.Context(), middleware.UserContextKey, user))
	}
	return r
}

// TestChangePasswordUserIPKey pins the exact change-password pair encoding
// "chpw:pair:" + byte-length(username) + ":" + username + "|" + IP. Unlike the
// login family the username comes from the authenticated session
// (middleware.GetUser), not the form, and an empty (missing) user maps to ""
// — which RateLimiter.Limit treats as "skip this request" — rather than to a
// shared sentinel bucket.
func TestChangePasswordUserIPKey(t *testing.T) {
	alice := &models.User{Username: "alice"}
	tests := []struct {
		name       string
		user       *models.User
		remoteAddr string
		want       string
	}{
		{"simple", alice, "192.0.2.1:1234", "chpw:pair:5:alice|192.0.2.1"},
		{"ipv6", alice, "[2001:db8::1]:443", "chpw:pair:5:alice|2001:db8::1"},
		{"ipv6 zone id", alice, "[fe80::1%eth0]:1234", "chpw:pair:5:alice|fe80::1%eth0"},
		// The length prefix counts BYTES, not runes: "é" is one rune, two
		// bytes — the same injectivity property the login pair key pins.
		{"multi-byte length is bytes", &models.User{Username: "é"}, "192.0.2.1:1234", "chpw:pair:2:é|192.0.2.1"},
		// No authenticated user → "" → the limiter skips the request.
		{"no user skips", nil, "192.0.2.1:1234", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := changePasswordUserIPKey(newChangePasswordRequest(tt.user, tt.remoteAddr)); got != tt.want {
				t.Errorf("changePasswordUserIPKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestChangePasswordUserIPKey_OversizedFolds pins the 160-byte hard cap: the
// IP half is client-influenced (malformed RemoteAddr fallbacks, IPv6 zone
// ids), and every change-password family — in-process and cluster-wide —
// stores counters under these keys, so anything past the cap folds to the
// family-prefixed sentinel instead of being used verbatim.
func TestChangePasswordUserIPKey_OversizedFolds(t *testing.T) {
	// No port: SplitHostPort fails, ExtractIP returns the raw 200-byte
	// RemoteAddr verbatim, and the composed pair key exceeds the cap.
	r := newChangePasswordRequest(&models.User{Username: "alice"}, strings.Repeat("a", 200))
	got := changePasswordUserIPKey(r)
	if got != "chpw:pair:<oversized-key>" {
		t.Errorf("changePasswordUserIPKey(oversized) = %q, want %q", got, "chpw:pair:<oversized-key>")
	}
	if len(got) > loginMaxKeyBytes {
		t.Errorf("folded key is %d bytes, must be <= %d", len(got), loginMaxKeyBytes)
	}

	// Normal keys never fold and stay under the cap.
	normal := changePasswordUserIPKey(newChangePasswordRequest(&models.User{Username: "alice"}, "[fe80::1%eth0]:1234"))
	if strings.Contains(normal, "<oversized") {
		t.Errorf("normal key %q folded despite being short", normal)
	}
	if len(normal) > loginMaxKeyBytes {
		t.Errorf("normal key is %d bytes, want <= %d", len(normal), loginMaxKeyBytes)
	}
}

// TestChangePasswordUserGlobalKey pins the change-password global per-user
// family encoding "chpw:user:" + username. Unlike the pair key it ignores the
// source IP entirely — it is the fleet-wide ceiling on a single targeted
// account — and, like the pair key, an empty user maps to "" (skip).
func TestChangePasswordUserGlobalKey(t *testing.T) {
	alice := &models.User{Username: "alice"}

	got := changePasswordUserGlobalKey(newChangePasswordRequest(alice, "192.0.2.1:1234"))
	if want := "chpw:user:alice"; got != want {
		t.Errorf("changePasswordUserGlobalKey() = %q, want %q", got, want)
	}

	// IP-independent: same user from a different source draws the same key.
	again := changePasswordUserGlobalKey(newChangePasswordRequest(alice, "10.0.0.1:9999"))
	if again != got {
		t.Errorf("global key must ignore the IP: got %q and %q for the same user", got, again)
	}

	// The chpw families must stay disjoint from the login families sharing
	// the rate_limit_counters namespace, and from each other.
	pair := changePasswordUserIPKey(newChangePasswordRequest(alice, "192.0.2.1:1234"))
	if pair == got {
		t.Errorf("pair key %q collides with the global key", pair)
	}
	if !strings.HasPrefix(pair, "chpw:pair:") || !strings.HasPrefix(got, "chpw:user:") {
		t.Errorf("family prefixes wrong: pair=%q global=%q", pair, got)
	}

	if got := changePasswordUserGlobalKey(newChangePasswordRequest(nil, "192.0.2.1:1234")); got != "" {
		t.Errorf("changePasswordUserGlobalKey(nil user) = %q, want \"\" (skip)", got)
	}
}

// TestChangePasswordGlobalRateLimit_Scoping pins the global family behaviour
// at the limiter level (the router-level pair test isolates the pair family;
// driving both through one router would have the pair limiter fire first): 30
// attempts for one user across distinct IPs exhaust the IP-independent
// bucket, the 31st from yet another IP is 429, and a second user is
// unaffected.
func TestChangePasswordGlobalRateLimit_Scoping(t *testing.T) {
	const globalLimit = 30
	limiter := middleware.NewRateLimiter(globalLimit)
	t.Cleanup(limiter.Close)

	var handlerCalls int32
	stack := limiter.Limit(changePasswordUserGlobalKey)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&handlerCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))

	post := func(user *models.User, remoteAddr string) int {
		w := httptest.NewRecorder()
		stack.ServeHTTP(w, newChangePasswordRequest(user, remoteAddr))
		return w.Code
	}

	alice := &models.User{Username: "alice"}
	bob := &models.User{Username: "bob"}

	// globalLimit attempts for alice from distinct IPs (each pair would be
	// under the 5/min pair ceiling): all allowed, exhausting the shared
	// per-user budget.
	for i := 0; i < globalLimit; i++ {
		if code := post(alice, fmt.Sprintf("198.51.100.%d:1234", i+1)); code != http.StatusOK {
			t.Fatalf("attempt %d for alice from a fresh IP: got %d, want 200", i+1, code)
		}
	}
	if code := post(alice, "198.51.100.99:1234"); code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d for alice from yet another IP: got %d, want 429 (global ceiling must ignore the IP spread)", globalLimit+1, code)
	}
	// A different user has his own global bucket, even from the same IPs.
	if code := post(bob, "198.51.100.1:1234"); code != http.StatusOK {
		t.Fatalf("request for a different user: got %d, want 200 (global buckets must be per-user)", code)
	}
	if got := atomic.LoadInt32(&handlerCalls); got != globalLimit+1 {
		t.Errorf("handler invoked %d times, want %d", got, globalLimit+1)
	}
}
