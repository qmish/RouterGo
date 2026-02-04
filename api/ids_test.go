package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/ids"
	"router-go/pkg/nat"
	"router-go/pkg/network"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupIDSRouter() (*gin.Engine, *ids.Engine) {
	gin.SetMode(gin.TestMode)
	engine := ids.NewEngine(ids.Config{AlertLimit: 10})
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		IDS:     engine,
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)
	return router, engine
}

func TestAddAndGetIDSRules(t *testing.T) {
	router, _ := setupIDSRouter()

	payload := map[string]any{
		"name":      "sig",
		"action":    "DROP",
		"protocol":  "TCP",
		"src_cidr":  "10.0.0.0/8",
		"dst_port":  80,
		"payload_contains": "GET",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/ids/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/ids/rules", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("sig")) {
		t.Fatalf("expected rule in response")
	}
}

func TestUpdateAndDeleteIDSRule(t *testing.T) {
	router, _ := setupIDSRouter()
	payload := map[string]any{
		"name":     "sig",
		"action":   "ALERT",
		"protocol": "TCP",
		"dst_port": 80,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/ids/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	update := map[string]any{
		"action":   "DROP",
		"protocol": "TCP",
		"dst_port": 80,
		"priority": 10,
	}
	body, _ = json.Marshal(update)
	req = httptest.NewRequest(http.MethodPut, "/api/ids/rules/sig", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/ids/rules/sig", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestGetIDSAlerts(t *testing.T) {
	router, engine := setupIDSRouter()

	engine.AddRule(ids.Rule{
		Name:            "sig",
		Action:          ids.ActionDrop,
		Protocol:        "TCP",
		SrcNet:          &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},
		DstPort:         80,
		PayloadContains: "GET",
		Enabled:         true,
	})

	engine.Detect(network.Packet{
		Data: []byte("GET /"),
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			DstPort:  80,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/ids/alerts?type=SIGNATURE", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("SIGNATURE")) {
		t.Fatalf("expected alert in response")
	}
}
