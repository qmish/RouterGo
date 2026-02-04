package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupFirewallRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := firewall.NewEngineWithDefaults(nil, map[string]firewall.Action{
		"INPUT":   firewall.ActionDrop,
		"OUTPUT":  firewall.ActionAccept,
		"FORWARD": firewall.ActionDrop,
	})
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		Firewall: engine,
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)
	return router
}

func TestGetFirewallRules(t *testing.T) {
	router := setupFirewallRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/firewall", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestGetFirewallDefaults(t *testing.T) {
	router := setupFirewallRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/firewall/defaults", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("OUTPUT")) {
		t.Fatalf("expected defaults in response")
	}
}

func TestSetFirewallDefault(t *testing.T) {
	router := setupFirewallRouter()
	payload := map[string]any{
		"chain":  "INPUT",
		"action": "ACCEPT",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/firewall/defaults", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestResetFirewallStats(t *testing.T) {
	router := setupFirewallRouter()

	req := httptest.NewRequest(http.MethodGet, "/api/firewall/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resetReq := httptest.NewRequest(http.MethodPost, "/api/firewall/reset", nil)
	resetW := httptest.NewRecorder()
	router.ServeHTTP(resetW, resetReq)
	if resetW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resetW.Code)
	}
}
