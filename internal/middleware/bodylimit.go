package middleware

import (
	"net/http"
	"strings"
)

// Body size limits (M-SEC3). The default cap protects every handler that
// buffers request bodies (json.NewDecoder(r.Body).Decode, r.ParseForm, …)
// from OOM via oversized requests. Zone import gets a larger allowance for
// BIND/CSV files.
const (
	DefaultBodyLimit int64 = 1 << 20  // 1 MiB
	ImportBodyLimit  int64 = 10 << 20 // 10 MiB
)

// BodyLimit wraps r.Body with http.MaxBytesReader to cap the number of bytes
// a client can send. The limit is 1 MiB by default; POST routes ending in
// "/import" (zone import) get 10 MiB for BIND/CSV zone files.
//
// When the limit is exceeded, the underlying read returns an error which the
// handler surfaces as a 400/413 — the server additionally closes the
// connection to stop the client streaming more data.
func BodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := DefaultBodyLimit
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/import") {
			limit = ImportBodyLimit
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}
