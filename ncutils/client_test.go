package ncutils

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendRequestOnceDoesNotRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := SendRequestOnce(http.MethodGet, srv.URL, nil, nil, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout")
	}
	if hits.Load() != 1 {
		t.Fatalf("attempts = %d, want 1", hits.Load())
	}
	if time.Since(start) > time.Second {
		t.Fatalf("single attempt took %s", time.Since(start))
	}
}
