// CSRF cookie Secure-attribute rewriting. gorilla/csrf's Secure option is
// static, but GoZone serves plain HTTP and HTTPS side by side (dev vs behind a
// TLS-terminating proxy), so the attribute must follow the per-request
// effective-HTTPS resolution.
package cmd

import (
	"net/http"
	"strings"
)

// csrfCookieName is the default cookie name used by gorilla/csrf (the upstream
// constant is unexported). It identifies the CSRF Set-Cookie header for
// per-request Secure-attribute rewriting (REVIEW.md L-2).
const csrfCookieName = "_gorilla_csrf"

// csrfSecureCookieWriter wraps an http.ResponseWriter to dynamically set the
// Secure attribute on the CSRF cookie based on the per-request effective-HTTPS
// resolution (middleware.IsHTTPS).
//
// gorilla/csrf's csrf.Secure option is static — evaluated once at startup — so
// it cannot track the per-request TLS state that the session cookie uses. This
// wrapper closes that gap: the CSRF middleware is configured with
// csrf.Secure(false) so the library never writes the Secure attribute itself;
// this wrapper then appends "Secure" to the CSRF cookie's Set-Cookie header
// when the request is served over HTTPS, mirroring the session cookie's
// Secure: IsHTTPS(r) behaviour (REVIEW.md L-2).
//
// applySecureFlag is called lazily on the first Write/WriteHeader and again
// after the handler returns (to cover the no-body edge case). It is idempotent.
type csrfSecureCookieWriter struct {
	http.ResponseWriter
	https bool
	done  bool
}

// applySecureFlag scans the Set-Cookie headers and appends "; Secure" to the
// CSRF cookie when the request was served over HTTPS. It runs at most once.
func (w *csrfSecureCookieWriter) applySecureFlag() {
	if w.done {
		return
	}
	w.done = true
	if !w.https {
		return
	}
	// http.Header is a map[string][]string; indexing returns the actual slice,
	// so modifying elements in place updates the response headers.
	for i, c := range w.ResponseWriter.Header()["Set-Cookie"] {
		if strings.HasPrefix(c, csrfCookieName+"=") && !strings.Contains(c, "; Secure") {
			w.ResponseWriter.Header()["Set-Cookie"][i] = c + "; Secure"
		}
	}
}

func (w *csrfSecureCookieWriter) WriteHeader(status int) {
	w.applySecureFlag()
	w.ResponseWriter.WriteHeader(status)
}

func (w *csrfSecureCookieWriter) Write(b []byte) (int, error) {
	w.applySecureFlag()
	return w.ResponseWriter.Write(b)
}

// Unwrap allows http.ResponseController (Go 1.20+) to reach the underlying
// ResponseWriter through this wrapper.
func (w *csrfSecureCookieWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
