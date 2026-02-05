package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestProxyMaxAgeZero(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Cache-Control", "max-age=0")
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

func TestProxyETagRevalidate(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.Header.Get("If-None-Match") == "\"v1\"" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Cache-Control", "max-age=1")
		w.Header().Set("ETag", "\"v1\"")
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

	time.Sleep(1100 * time.Millisecond)

	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if upstreamCalls != 2 {
		t.Fatalf("expected upstream called twice, got %d", upstreamCalls)
	}
	if w.Body.String() != "ok" {
		t.Fatalf("expected cached body, got %q", w.Body.String())
	}
}

func TestProxyVary(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Vary", "User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{Upstream: upstream.URL, CacheSize: 10, CacheTTLSeconds: 60})
	if err != nil {
		t.Fatalf("proxy init failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/test", nil)
	req.Header.Set("User-Agent", "A")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	req2 := httptest.NewRequest(http.MethodGet, "http://proxy.local/test", nil)
	req2.Header.Set("User-Agent", "B")
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req2)

	if upstreamCalls != 2 {
		t.Fatalf("expected upstream called twice, got %d", upstreamCalls)
	}
}

func TestProxyCallbacksAndClearCache(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	p, err := NewProxy(Config{Upstream: upstream.URL, CacheSize: 10, CacheTTLSeconds: 60, EnableGzip: true})
	if err != nil {
		t.Fatalf("proxy init failed: %v", err)
	}

	hits := 0
	misses := 0
	compresses := 0
	p.SetCallbacks(func() { hits++ }, func() { misses++ }, func() { compresses++ })

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/test", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if upstreamCalls != 1 {
		t.Fatalf("expected upstream called once, got %d", upstreamCalls)
	}
	if hits != 1 || misses != 1 {
		t.Fatalf("expected 1 hit and 1 miss, got %d/%d", hits, misses)
	}
	if compresses != 2 {
		t.Fatalf("expected compress called twice, got %d", compresses)
	}
	if p.Stats().Compresses != 2 {
		t.Fatalf("expected stats compresses 2, got %d", p.Stats().Compresses)
	}

	p.ClearCache()
	if p.Stats().CacheSize != 0 {
		t.Fatalf("expected cache cleared")
	}
}
