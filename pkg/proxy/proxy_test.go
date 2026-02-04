package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyCaching(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{Upstream: upstream.URL, CacheSize: 10, CacheTTLSeconds: 60})
	if err != nil {
		t.Fatalf("proxy init failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/test", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if upstreamCalls != 1 {
		t.Fatalf("expected upstream called once, got %d", upstreamCalls)
	}
	if p.Stats().CacheHits == 0 {
		t.Fatalf("expected cache hit")
	}
}

func TestProxyNoStore(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{Upstream: upstream.URL, CacheSize: 10, CacheTTLSeconds: 60})
	if err != nil {
		t.Fatalf("proxy init failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/test", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if upstreamCalls != 2 {
		t.Fatalf("expected upstream called twice, got %d", upstreamCalls)
	}
}
