package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/nat"
	"router-go/pkg/network"
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

func TestResetNATStats(t *testing.T) {
	table := nat.NewTable([]nat.Rule{
		{
			Type:  nat.TypeSNAT,
			ToIP:  net.ParseIP("203.0.113.10"),
		},
	})
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     table,
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	pkt := network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.1.2.3"),
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcPort:  1234,
			DstPort:  80,
		},
	}
	table.Apply(pkt)

	req := httptest.NewRequest(http.MethodPost, "/api/nat/reset", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	stats := table.RulesWithStats()
	if stats[0].Hits != 0 {
		t.Fatalf("expected hits reset to 0, got %d", stats[0].Hits)
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
		"name":            "voice",
		"protocol":        "UDP",
		"dst_port":        5060,
		"rate_limit_kbps": 512,
		"priority":        10,
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
