package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/metrics"
	"router-go/pkg/flow"
	"router-go/pkg/ids"
	"router-go/pkg/nat"
	"router-go/pkg/network"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupDashboardRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	flowEngine := flow.NewEngine()
	flowEngine.AddPacket(network.Packet{
		Metadata: network.PacketMetadata{
			SrcIP:  net.ParseIP("10.0.0.1"),
			DstIP:  net.ParseIP("1.1.1.1"),
			Length: 100,
		},
	})
	idsEngine := ids.NewEngine(ids.Config{AlertLimit: 10})
	idsEngine.AddRule(ids.Rule{
		Name:    "sig",
		Action:  ids.ActionAlert,
		Protocol: "TCP",
	})
	idsEngine.Detect(network.Packet{
		Metadata: network.PacketMetadata{
			Protocol: "TCP",
			SrcIP:    net.ParseIP("10.0.0.2"),
			DstIP:    net.ParseIP("1.1.1.1"),
		},
	})
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		IDS:      idsEngine,
		Flow:     flowEngine,
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)
	return router
}

func TestDashboardTopBandwidth(t *testing.T) {
	router := setupDashboardRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/top/bandwidth", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDashboardSessionsTree(t *testing.T) {
	router := setupDashboardRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/sessions/tree", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestDashboardAlerts(t *testing.T) {
	router := setupDashboardRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/alerts", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
