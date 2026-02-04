package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/proxy"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupProxyRouter(t *testing.T) *gin.Engine {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	proxyEngine, err := proxy.NewProxy(proxy.Config{
		Upstream:        upstream.URL,
		CacheSize:       10,
		CacheTTLSeconds: 60,
		EnableGzip:      false,
	})
	if err != nil {
		t.Fatalf("proxy init failed: %v", err)
	}
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		Proxy:   proxyEngine,
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)
	return router
}

func TestProxyEndpoints(t *testing.T) {
	router := setupProxyRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/proxy/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/proxy/cache/clear", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
