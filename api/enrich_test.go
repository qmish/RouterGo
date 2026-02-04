package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"router-go/internal/metrics"
	"router-go/pkg/enrich"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

type mockProvider struct {
	result any
}

func (m mockProvider) Lookup(_ context.Context, _ string) (any, error) {
	return m.result, nil
}

func TestEnrichIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := enrich.NewService(
		mockProvider{result: enrich.GeoInfo{Country: "RU"}},
		mockProvider{result: enrich.ASNInfo{ASN: "AS123"}},
		mockProvider{result: enrich.ThreatInfo{Score: 10}},
		time.Minute,
	)
	h := &Handlers{
		Routes:        routing.NewTable(nil),
		Enrich:        service,
		EnrichTimeout: time.Second,
		Metrics:       metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)

	req := httptest.NewRequest(http.MethodGet, "/api/enrich/ip?ip=1.1.1.1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if body := w.Body.String(); body == "" {
		t.Fatalf("expected response body")
	}
}
