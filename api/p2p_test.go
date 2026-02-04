package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/p2p"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupP2PRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	table := routing.NewTable(nil)
	engine := p2p.NewEngine(p2p.Config{PeerID: "node-1"}, table, nil, func() {}, func() {})
	h := &Handlers{
		Routes:  table,
		P2P:     engine,
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)
	return router
}

func TestP2PEndpoints(t *testing.T) {
	router := setupP2PRouter()

	req := httptest.NewRequest(http.MethodGet, "/api/p2p/peers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/p2p/routes", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/p2p/reset", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
