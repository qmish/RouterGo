package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net"
	"testing"
	"time"

	"router-go/internal/metrics"
	"router-go/internal/config"
	"router-go/pkg/ids"
	"router-go/pkg/ha"
	"router-go/pkg/firewall"
	"router-go/pkg/nat"
	"router-go/pkg/network"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.yaml.in/yaml/v3"
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

func TestDeleteNATRule(t *testing.T) {
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

	req = httptest.NewRequest(http.MethodDelete, "/api/nat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
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
	if bytes.Contains(w.Body.Bytes(), []byte("203.0.113.10")) {
		t.Fatalf("expected nat rule removed")
	}
}

func TestDeleteNATRuleNotFound(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodDelete, "/api/nat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUpdateNATRule(t *testing.T) {
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

	update := map[string]any{
		"old_type":   "SNAT",
		"old_src_ip": "10.0.0.0/8",
		"old_to_ip":  "203.0.113.10",
		"old_to_port": 40000,
		"type":       "SNAT",
		"src_ip":     "10.0.0.0/8",
		"to_ip":      "203.0.113.11",
		"to_port":    40001,
	}
	body, _ = json.Marshal(update)
	req = httptest.NewRequest(http.MethodPut, "/api/nat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
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
	if !bytes.Contains(w.Body.Bytes(), []byte("203.0.113.11")) {
		t.Fatalf("expected updated nat rule in response")
	}
}

func TestUpdateNATRuleNotFound(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	update := map[string]any{
		"old_type": "SNAT",
		"type":     "SNAT",
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPut, "/api/nat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
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

func TestDeleteQoSClass(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"name":      "voice",
		"protocol":  "UDP",
		"dst_port":  5060,
		"priority":  10,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/qos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	delPayload := map[string]any{"name": "voice"}
	body, _ = json.Marshal(delPayload)
	req = httptest.NewRequest(http.MethodDelete, "/api/qos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
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
	if bytes.Contains(w.Body.Bytes(), []byte("voice")) {
		t.Fatalf("expected qos class removed")
	}
}

func TestDeleteQoSClassNotFound(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	body, _ := json.Marshal(map[string]any{"name": "voice"})
	req := httptest.NewRequest(http.MethodDelete, "/api/qos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUpdateQoSClass(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"name":      "voice",
		"protocol":  "UDP",
		"dst_port":  5060,
		"priority":  10,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/qos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	update := map[string]any{
		"old_name":  "voice",
		"name":      "voice",
		"protocol":  "UDP",
		"dst_port":  5060,
		"priority":  20,
	}
	body, _ = json.Marshal(update)
	req = httptest.NewRequest(http.MethodPut, "/api/qos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
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
	var classes []qos.Class
	if err := json.Unmarshal(w.Body.Bytes(), &classes); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	found := false
	for _, cl := range classes {
		if cl.Name == "voice" && cl.Priority == 20 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected updated qos class in response")
	}
}

func TestUpdateQoSClassNotFound(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	body, _ := json.Marshal(map[string]any{"old_name": "voice", "name": "voice"})
	req := httptest.NewRequest(http.MethodPut, "/api/qos", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetRoutes(t *testing.T) {
	table := routing.NewTable(nil)
	_, dst, _ := net.ParseCIDR("10.10.0.0/16")
	table.Add(routing.Route{
		Destination: *dst,
		Gateway:     net.ParseIP("192.0.2.1"),
		Interface:   "eth0",
		Metric:      10,
	})
	h := &Handlers{
		Routes:  table,
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("10.10.0.0/16")) {
		t.Fatalf("expected route in response")
	}
}

func TestAddRoute(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"destination": "10.0.0.0/24",
		"gateway":     "192.0.2.1",
		"interface":   "eth0",
		"metric":      5,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("10.0.0.0/24")) {
		t.Fatalf("expected route in response")
	}
}

func TestAddRouteInvalid(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"destination": "bad",
		"gateway":     "192.0.2.1",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	payload = map[string]any{
		"destination": "10.0.0.0/24",
		"gateway":     "bad",
	}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDeleteRoute(t *testing.T) {
	table := routing.NewTable(nil)
	_, dst, _ := net.ParseCIDR("10.0.0.0/24")
	table.Add(routing.Route{
		Destination: *dst,
		Gateway:     net.ParseIP("192.0.2.1"),
		Interface:   "eth0",
		Metric:      5,
	})
	h := &Handlers{
		Routes:  table,
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"destination": "10.0.0.0/24",
		"gateway":     "192.0.2.1",
		"interface":   "eth0",
		"metric":      5,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodDelete, "/api/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("10.0.0.0/24")) {
		t.Fatalf("expected route to be removed")
	}
}

func TestDeleteRouteNotFound(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"destination": "10.0.0.0/24",
		"gateway":     "192.0.2.1",
		"interface":   "eth0",
		"metric":      5,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodDelete, "/api/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUpdateRoute(t *testing.T) {
	table := routing.NewTable(nil)
	_, dst, _ := net.ParseCIDR("10.0.0.0/24")
	table.Add(routing.Route{
		Destination: *dst,
		Gateway:     net.ParseIP("192.0.2.1"),
		Interface:   "eth0",
		Metric:      5,
	})
	h := &Handlers{
		Routes:  table,
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"old_destination": "10.0.0.0/24",
		"old_gateway":     "192.0.2.1",
		"old_interface":   "eth0",
		"old_metric":      5,
		"destination":     "10.0.1.0/24",
		"gateway":         "192.0.2.2",
		"interface":       "eth1",
		"metric":          10,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("10.0.1.0/24")) {
		t.Fatalf("expected updated route in response")
	}
}

func TestUpdateRouteNotFound(t *testing.T) {
	h := &Handlers{
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"old_destination": "10.0.0.0/24",
		"destination":     "10.0.1.0/24",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/routes", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetInterfaces(t *testing.T) {
	cfg := &config.Config{
		Interfaces: []config.InterfaceConfig{
			{Name: "eth0", IP: "10.0.0.1/24"},
			{Name: "wan0", IP: "203.0.113.10/32"},
		},
	}
	h := &Handlers{
		Routes:    routing.NewTable(nil),
		NAT:       nat.NewTable(nil),
		QoS:       qos.NewQueueManager(nil),
		Metrics:   metrics.NewWithRegistry(prometheus.NewRegistry()),
		ConfigMgr: config.NewManager(cfg, nil),
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/interfaces", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("eth0")) {
		t.Fatalf("expected interface in response")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("203.0.113.10/32")) {
		t.Fatalf("expected interface ip in response")
	}
}

func TestAddAndGetFirewallRules(t *testing.T) {
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		Firewall: firewall.NewEngine(nil),
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"chain":    "INPUT",
		"action":   "ACCEPT",
		"protocol": "TCP",
		"src_ip":   "10.0.0.0/8",
		"dst_port": 22,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/firewall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/firewall", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("INPUT")) {
		t.Fatalf("expected firewall rule in response")
	}
}

func TestDeleteFirewallRule(t *testing.T) {
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		Firewall: firewall.NewEngine(nil),
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"chain":    "INPUT",
		"action":   "ACCEPT",
		"protocol": "TCP",
		"src_ip":   "10.0.0.0/8",
		"dst_port": 22,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/firewall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/firewall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/firewall", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("INPUT")) {
		t.Fatalf("expected firewall rule removed")
	}
}

func TestDeleteFirewallRuleNotFound(t *testing.T) {
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		Firewall: firewall.NewEngine(nil),
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"chain":    "INPUT",
		"action":   "ACCEPT",
		"protocol": "TCP",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodDelete, "/api/firewall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestUpdateFirewallRule(t *testing.T) {
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		Firewall: firewall.NewEngine(nil),
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	payload := map[string]any{
		"chain":    "INPUT",
		"action":   "ACCEPT",
		"protocol": "TCP",
		"src_ip":   "10.0.0.0/8",
		"dst_port": 22,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/firewall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	update := map[string]any{
		"old_chain":    "INPUT",
		"old_action":   "ACCEPT",
		"old_protocol": "TCP",
		"old_src_ip":   "10.0.0.0/8",
		"old_dst_port": 22,
		"chain":        "INPUT",
		"action":       "DROP",
		"protocol":     "TCP",
		"src_ip":       "10.0.0.0/8",
		"dst_port":     22,
	}
	body, _ = json.Marshal(update)
	req = httptest.NewRequest(http.MethodPut, "/api/firewall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/firewall", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("DROP")) {
		t.Fatalf("expected updated rule in response")
	}
}

func TestUpdateFirewallRuleNotFound(t *testing.T) {
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		Firewall: firewall.NewEngine(nil),
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := setupRouter(h)

	update := map[string]any{
		"old_chain":    "INPUT",
		"old_action":   "ACCEPT",
		"old_protocol": "TCP",
		"chain":        "INPUT",
		"action":       "DROP",
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPut, "/api/firewall", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetHealth(t *testing.T) {
	h := &Handlers{}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"status":"ok"`)) {
		t.Fatalf("expected status ok in response")
	}
}

func TestGetConfigExportJSON(t *testing.T) {
	cfg := &config.Config{API: config.APIConfig{Address: ":9999"}}
	h := &Handlers{
		Routes:    routing.NewTable(nil),
		NAT:       nat.NewTable(nil),
		QoS:       qos.NewQueueManager(nil),
		Metrics:   metrics.NewWithRegistry(prometheus.NewRegistry()),
		ConfigMgr: config.NewManager(cfg, nil),
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/config/export?format=json", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var cfgOut config.Config
	if err := json.Unmarshal(w.Body.Bytes(), &cfgOut); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if cfgOut.API.Address != ":9999" {
		t.Fatalf("expected api address in response")
	}
}

func TestGetConfigExportYAML(t *testing.T) {
	cfg := &config.Config{API: config.APIConfig{Address: ":9999"}}
	h := &Handlers{
		Routes:    routing.NewTable(nil),
		NAT:       nat.NewTable(nil),
		QoS:       qos.NewQueueManager(nil),
		Metrics:   metrics.NewWithRegistry(prometheus.NewRegistry()),
		ConfigMgr: config.NewManager(cfg, nil),
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/config/export?format=yaml", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var cfgOut config.Config
	if err := yaml.Unmarshal(w.Body.Bytes(), &cfgOut); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	if cfgOut.API.Address != ":9999" {
		t.Fatalf("expected api address in response")
	}
}

func TestGetStats(t *testing.T) {
	table := routing.NewTable(nil)
	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	table.Add(routing.Route{
		Destination: *dst,
		Gateway:     net.ParseIP("192.0.2.1"),
		Interface:   "eth0",
		Metric:      10,
	})
	m := metrics.NewWithRegistry(prometheus.NewRegistry())
	m.IncPackets()
	m.IncRxPackets()
	m.IncTxPackets()
	m.IncIDSAlert()
	m.IncIDSDrop()
	m.IncConfigApply()
	m.IncConfigRollback()
	m.IncConfigApplyFailed()
	m.IncP2PPeer()
	m.IncP2PRouteSynced()
	m.IncProxyCacheHit()
	m.IncProxyCacheMiss()
	m.IncProxyCompress()
	m.IncDropReason("parse")
	m.IncQoSDrop("voice")

	h := &Handlers{
		Routes:  table,
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
		Metrics: m,
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
	if body["routes_count"] != float64(1) {
		t.Fatalf("expected routes_count 1, got %v", body["routes_count"])
	}
	if body["packets_total"] != float64(1) {
		t.Fatalf("expected packets_total 1, got %v", body["packets_total"])
	}
	if body["rx_packets_total"] != float64(1) || body["tx_packets_total"] != float64(1) {
		t.Fatalf("expected rx/tx packets 1, got %v/%v", body["rx_packets_total"], body["tx_packets_total"])
	}
	if body["ids_alerts_total"] != float64(1) || body["ids_drops_total"] != float64(1) {
		t.Fatalf("expected ids alerts/drops 1, got %v/%v", body["ids_alerts_total"], body["ids_drops_total"])
	}
	if body["config_apply_total"] != float64(1) || body["config_rollback_total"] != float64(1) || body["config_apply_failed_total"] != float64(1) {
		t.Fatalf("expected config totals 1, got %v/%v/%v", body["config_apply_total"], body["config_rollback_total"], body["config_apply_failed_total"])
	}
	if body["p2p_peers_total"] != float64(1) || body["p2p_routes_synced_total"] != float64(1) {
		t.Fatalf("expected p2p totals 1, got %v/%v", body["p2p_peers_total"], body["p2p_routes_synced_total"])
	}
	if body["proxy_cache_hits_total"] != float64(1) || body["proxy_cache_miss_total"] != float64(1) || body["proxy_compress_total"] != float64(1) {
		t.Fatalf("expected proxy totals 1, got %v/%v/%v", body["proxy_cache_hits_total"], body["proxy_cache_miss_total"], body["proxy_compress_total"])
	}

	dropsByReason, ok := body["drops_by_reason"].(map[string]any)
	if !ok || dropsByReason["parse"] != float64(1) {
		t.Fatalf("expected drops_by_reason parse=1, got %v", body["drops_by_reason"])
	}
	qosDrops, ok := body["qos_drops_by_class"].(map[string]any)
	if !ok || qosDrops["voice"] != float64(1) {
		t.Fatalf("expected qos_drops_by_class voice=1, got %v", body["qos_drops_by_class"])
	}
}

func TestGetMonitoringSummary(t *testing.T) {
	fw := firewall.NewEngine([]firewall.Rule{
		{Chain: "INPUT", Action: firewall.ActionAccept},
	})
	fw.Evaluate("INPUT", network.Packet{})
	natTable := nat.NewTable([]nat.Rule{{Type: nat.TypeSNAT}})
	q := qos.NewQueueManager([]qos.Class{{Name: "voice", Priority: 10}})
	m := metrics.NewWithRegistry(prometheus.NewRegistry())
	m.IncDrops()
	m.IncErrors()

	h := &Handlers{
		Routes:   routing.NewTable(nil),
		Firewall: fw,
		NAT:      natTable,
		QoS:      q,
		Metrics:  m,
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/monitoring/summary", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		FirewallChainHits map[string]uint64 `json:"firewall_chain_hits"`
		NATRules          int              `json:"nat_rules"`
		QoSClasses        int              `json:"qos_classes"`
		Drops             uint64           `json:"drops"`
		Errors            uint64           `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.FirewallChainHits["INPUT"] != 1 {
		t.Fatalf("expected INPUT hits 1, got %d", resp.FirewallChainHits["INPUT"])
	}
	if resp.NATRules != 1 {
		t.Fatalf("expected nat rules 1, got %d", resp.NATRules)
	}
	if resp.QoSClasses < 1 {
		t.Fatalf("expected qos classes >=1, got %d", resp.QoSClasses)
	}
	if resp.Drops != 1 || resp.Errors != 1 {
		t.Fatalf("expected drops/errors to be 1, got %d/%d", resp.Drops, resp.Errors)
	}
}

func TestResetIDS(t *testing.T) {
	engine := ids.NewEngine(ids.Config{})
	engine.AddRule(ids.Rule{
		Name:            "payload-rule",
		Action:          ids.ActionAlert,
		Protocol:        "TCP",
		PayloadContains: "malicious",
		Enabled:         true,
	})
	pkt := network.Packet{
		Data: []byte("malicious content"),
		Metadata: network.PacketMetadata{
			SrcIP:    net.ParseIP("10.0.0.10"),
			DstIP:    net.ParseIP("192.0.2.1"),
			Protocol: "TCP",
			SrcPort:  1234,
			DstPort:  80,
		},
	}
	engine.Detect(pkt)
	if len(engine.Alerts()) == 0 {
		t.Fatalf("expected alert before reset")
	}

	h := &Handlers{
		IDS:     engine,
		Metrics: metrics.NewWithRegistry(prometheus.NewRegistry()),
		Routes:  routing.NewTable(nil),
		NAT:     nat.NewTable(nil),
		QoS:     qos.NewQueueManager(nil),
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodPost, "/api/ids/reset", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(engine.Alerts()) != 0 {
		t.Fatalf("expected alerts cleared")
	}
}

func TestGetHAStatus(t *testing.T) {
	manager := ha.NewManager("node-1", 100, time.Second, time.Second, ":0", "224.0.0.252:5356", nil, "/api/ha/state", time.Second, nil, nil)
	h := &Handlers{
		HA: manager,
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/ha/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"node_id":"node-1"`)) {
		t.Fatalf("expected node_id in response")
	}
}

func TestGetHAState(t *testing.T) {
	_, srcNet, _ := net.ParseCIDR("10.0.0.0/8")
	_, dstNet, _ := net.ParseCIDR("192.168.0.0/16")
	fw := firewall.NewEngineWithDefaults([]firewall.Rule{
		{
			Chain:    "INPUT",
			Action:   firewall.ActionAccept,
			Protocol: "TCP",
			SrcNet:   srcNet,
			DstNet:   dstNet,
			DstPort:  22,
		},
	}, map[string]firewall.Action{"INPUT": firewall.ActionDrop})
	natTable := nat.NewTable([]nat.Rule{
		{
			Type:   nat.TypeSNAT,
			SrcNet: srcNet,
			ToIP:   net.ParseIP("203.0.113.10"),
		},
	})
	qosQueue := qos.NewQueueManager([]qos.Class{
		{
			Name:          "voice",
			Protocol:      "UDP",
			DstPort:       5060,
			RateLimitKbps: 512,
			Priority:      10,
		},
	})
	routes := routing.NewTable(nil)
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	routes.Add(routing.Route{
		Destination: *dst,
		Gateway:     net.ParseIP("192.168.1.254"),
		Interface:   "eth0",
		Metric:      100,
	})
	manager := ha.NewManager("node-1", 100, time.Second, time.Second, ":0", "224.0.0.252:5356", nil, "/api/ha/state", time.Second, nil, nil)
	h := &Handlers{
		HA:       manager,
		Firewall: fw,
		NAT:      natTable,
		QoS:      qosQueue,
		Routes:   routes,
	}
	router := setupRouter(h)

	req := httptest.NewRequest(http.MethodGet, "/api/ha/state", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var state ha.State
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(state.FirewallRules) != 1 || len(state.NATRules) != 1 || len(state.QoSClasses) == 0 || len(state.Routes) != 1 {
		t.Fatalf("unexpected state sizes: fw=%d nat=%d qos=%d routes=%d", len(state.FirewallRules), len(state.NATRules), len(state.QoSClasses), len(state.Routes))
	}
	if state.FirewallDefaults["INPUT"] != "DROP" {
		t.Fatalf("expected firewall default INPUT=DROP")
	}
	foundVoice := false
	for _, class := range state.QoSClasses {
		if class.Name == "voice" {
			foundVoice = true
			break
		}
	}
	if !foundVoice {
		t.Fatalf("expected voice class in QoS state")
	}
}

func TestApplyHAState(t *testing.T) {
	fw := firewall.NewEngine(nil)
	natTable := nat.NewTable(nil)
	qosQueue := qos.NewQueueManager(nil)
	routes := routing.NewTable(nil)

	applyCalled := false
	manager := ha.NewManager("node-1", 100, time.Second, time.Second, ":0", "224.0.0.252:5356", nil, "/api/ha/state", time.Second, nil, func(state ha.State) {
		applyCalled = true
	})
	h := &Handlers{
		HA:       manager,
		Firewall: fw,
		NAT:      natTable,
		QoS:      qosQueue,
		Routes:   routes,
	}
	router := setupRouter(h)

	state := ha.State{
		FirewallDefaults: map[string]string{"INPUT": "DROP"},
		FirewallRules: []ha.FirewallRule{
			{
				Chain:    "INPUT",
				Action:   "ACCEPT",
				Protocol: "TCP",
				SrcCIDR:  "10.0.0.0/8",
				DstCIDR:  "192.168.0.0/16",
				DstPort:  22,
			},
		},
		NATRules: []ha.NATRule{
			{
				Type:   "SNAT",
				SrcCIDR:"10.0.0.0/8",
				ToIP:   "203.0.113.10",
			},
		},
		QoSClasses: []ha.QoSClass{
			{
				Name:          "voice",
				Protocol:      "UDP",
				DstPort:       5060,
				RateLimitKbps: 512,
				Priority:      10,
			},
		},
		Routes: []ha.Route{
			{
				Destination: "0.0.0.0/0",
				Gateway:     "192.168.1.254",
				Interface:   "eth0",
				Metric:      100,
			},
		},
	}
	body, _ := json.Marshal(state)
	req := httptest.NewRequest(http.MethodPost, "/api/ha/state", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !applyCalled {
		t.Fatalf("expected manager ApplyState to be called")
	}
	if len(fw.Rules()) != 1 || fw.DefaultPolicies()["INPUT"] != firewall.ActionDrop {
		t.Fatalf("expected firewall rules/defaults applied")
	}
	if len(natTable.Rules()) != 1 {
		t.Fatalf("expected nat rules applied")
	}
	foundVoice := false
	for _, class := range qosQueue.Classes() {
		if class.Name == "voice" {
			foundVoice = true
			break
		}
	}
	if !foundVoice {
		t.Fatalf("expected qos class voice applied")
	}
	if len(routes.Routes()) != 1 {
		t.Fatalf("expected routes applied")
	}
}
