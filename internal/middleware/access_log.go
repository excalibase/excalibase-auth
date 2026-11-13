package middleware

import (
	"log"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// AccessLog logs method, path, status and duration. The query string is left
// out on purpose: it can carry emails and one-time tokens.
func AccessLog(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(wrapped, r)
			status := wrapped.Status()
			if status == 0 {
				status = http.StatusOK
			}
			logger.Printf("%s %s %d %dB %s", r.Method, r.URL.EscapedPath(), status, wrapped.BytesWritten(), time.Since(start))
		})
	}
}
