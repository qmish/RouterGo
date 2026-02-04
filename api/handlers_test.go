package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/nat"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	RegisterRoutes(r, h)
	return r
}

func TestAddAndGetNAT(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"type":    "SNAT",
		"src_ip":  "10.0.0.0/8",
		"to_ip":   "203.0.113.10",
		"to_port": 40000,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/nat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/nat", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("203.0.113.10")) {
		t.Fatalf("expected nat rule in response")
	}
}

func TestAddAndGetQoS(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"name":           "voice",
		"protocol":       "UDP",
		"dst_port":       5060,
		"rate_limit_kbps": 512,
		"priority":       10,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/qos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/qos", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("voice")) {
		t.Fatalf("expected qos class in response")
	}
}
