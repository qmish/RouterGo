package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/ids"
	"router-go/pkg/firewall"
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
