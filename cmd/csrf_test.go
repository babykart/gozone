package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCSRFSecureCookieWriter verifies that csrfSecureCookieWriter dynamically
// adds the Secure attribute to the CSRF cookie based on the per-request HTTPS
// flag (REVIEW.md L-2). The session cookie already uses IsHTTPS(r) per-request;
// this wrapper brings the CSRF cookie in line so the two never disagree.
func TestCSRFSecureCookieWriter(t *testing.T) {
	// Helper: build a ResponseRecorder wrapped in csrfSecureCookieWriter,
	// set a CSRF cookie + a non-CSRF cookie, trigger the rewrite, and return
	// the parsed cookies.
	run := func(t *testing.T, https bool) (csrfCookie, otherCookie *http.Cookie) {
		t.Helper()
		rec := httptest.NewRecorder()
		w := &csrfSecureCookieWriter{ResponseWriter: rec, https: https}

		// Simulate what gorilla/csrf's cookieStore.Save does (csrf.Secure(false)
		// → no Secure attribute on the cookie).
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    "encoded-token-value",
			Path:     "/",
			HttpOnly: true,
		})
		// A non-CSRF cookie should never be touched.
		http.SetCookie(w, &http.Cookie{
			Name:  "other-cookie",
			Value: "other",
			Path:  "/",
		})

		w.WriteHeader(http.StatusOK)

		for _, c := range rec.Result().Cookies() {
			switch c.Name {
			case csrfCookieName:
				csrfCookie = c
			case "other-cookie":
				otherCookie = c
			}
		}
		if csrfCookie == nil {
			t.Fatal("CSRF cookie not found in response")
		}
		if otherCookie == nil {
			t.Fatal("other cookie not found in response")
		}
		return csrfCookie, otherCookie
	}

	t.Run("HTTPS adds Secure to CSRF cookie only", func(t *testing.T) {
		csrfCookie, otherCookie := run(t, true)
		if !csrfCookie.Secure {
			t.Errorf("CSRF cookie Secure = false, want true (HTTPS request — REVIEW.md L-2)")
		}
		if otherCookie.Secure {
			t.Errorf("other cookie should not have been modified (Secure = true)")
		}
	})

	t.Run("HTTP does not add Secure", func(t *testing.T) {
		csrfCookie, otherCookie := run(t, false)
		if csrfCookie.Secure {
			t.Errorf("CSRF cookie Secure = true, want false (HTTP request — plain-HTTP dev must work)")
		}
		if otherCookie.Secure {
			t.Errorf("other cookie should not have Secure flag")
		}
	})
}

// TestCSRFSecureCookieWriter_FlushAfterHandler covers the edge case where the
// handler returns without calling Write/WriteHeader (e.g. a handler that sets
// only a Location header via http.Redirect without calling WriteHeader).
// applySecureFlag must be called by the middleware's post-handler flush so the
// CSRF cookie still gets the Secure attribute.
func TestCSRFSecureCookieWriter_FlushAfterHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &csrfSecureCookieWriter{ResponseWriter: rec, https: true}

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "token",
		Path:     "/",
		HttpOnly: true,
	})

	// Simulate a handler that sets the cookie but never calls Write/WriteHeader.
	// The middleware calls applySecureFlag() after next.ServeHTTP returns.
	w.applySecureFlag()

	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("CSRF cookie not found")
	}
	if !csrfCookie.Secure {
		t.Errorf("CSRF cookie Secure = false, want true (post-handler flush failed)")
	}
}

// TestCSRFSecureCookieWriter_Idempotent verifies that applySecureFlag does not
// append duplicate "; Secure" attributes even if called multiple times.
func TestCSRFSecureCookieWriter_Idempotent(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &csrfSecureCookieWriter{ResponseWriter: rec, https: true}

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "token",
		Path:     "/",
		HttpOnly: true,
	})

	w.applySecureFlag()
	w.applySecureFlag() // second call should be a no-op
	w.applySecureFlag() // third call should also be a no-op

	var count int
	for _, c := range rec.Header()["Set-Cookie"] {
		if strings.HasPrefix(c, csrfCookieName+"=") {
			count = strings.Count(c, "Secure")
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 'Secure' attribute, got %d (not idempotent)", count)
	}
}

// TestCSRFSecureCookieWriter_WriteAndUnwrap covers the Write path (the plain
// handler path that writes a body without an explicit WriteHeader) and the
// Unwrap method that lets http.ResponseController reach the underlying writer.
func TestCSRFSecureCookieWriter_WriteAndUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	w := &csrfSecureCookieWriter{ResponseWriter: rec, https: true}
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "token", Path: "/"})

	if _, err := w.Write([]byte("body")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var secure bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			secure = c.Secure
		}
	}
	if !secure {
		t.Error("CSRF cookie Secure = false after Write, want true")
	}

	if uw, ok := w.Unwrap().(*httptest.ResponseRecorder); !ok || uw != rec {
		t.Error("Unwrap must return the wrapped ResponseWriter")
	}
}
