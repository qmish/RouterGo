package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/observability"

	"github.com/gin-gonic/gin"
)

func TestGetAlerts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	alerts := observability.NewAlertStore(10)
	alerts.Add(observability.Alert{ID: "a", Type: observability.AlertDrops})
	handlers := &Handlers{Alerts: alerts}
	router := gin.New()
	router.GET("/api/observability/alerts", handlers.GetAlerts)

	req := httptest.NewRequest(http.MethodGet, "/api/observability/alerts", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
	var out []observability.Alert
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(out) != 1 || out[0].ID != "a" {
		t.Fatalf("unexpected alerts: %#v", out)
	}
}

func TestGetAlertsDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handlers := &Handlers{}
	router := gin.New()
	router.GET("/api/observability/alerts", handlers.GetAlerts)

	req := httptest.NewRequest(http.MethodGet, "/api/observability/alerts", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", resp.Code)
	}
}
