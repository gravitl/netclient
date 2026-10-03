package uiapi

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gravitl/netmaker/logger"
)

func uiLog(verbosity int, parts ...string) {
	logger.Log(verbosity, parts...)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" && rec.status < 400 {
			return
		}
		msg := fmt.Sprintf(
			"uiapi: %s %s -> %d (%s)",
			r.Method,
			r.URL.Path,
			rec.status,
			time.Since(start).Round(time.Millisecond),
		)
		if rec.status >= 400 {
			uiLog(0, msg)
			return
		}
		uiLog(1, msg)
	})
}
