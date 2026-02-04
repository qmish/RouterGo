package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/config"
	"router-go/internal/metrics"
	"router-go/pkg/nat"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

func setupConfigRouter(health func(*config.Config) error) *gin.Engine {
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(&config.Config{}, health)
	h := &Handlers{
		Routes:   routing.NewTable(nil),
		NAT:      nat.NewTable(nil),
		QoS:      qos.NewQueueManager(nil),
		ConfigMgr: manager,
		Metrics:  metrics.NewWithRegistry(prometheus.NewRegistry()),
	}
	router := gin.New()
	RegisterRoutes(router, h)
	return router
}

func TestApplyConfigSuccess(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8080\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestApplyConfigHealthFail(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return errors.New("fail") })
	payload := map[string]any{
		"config_yaml": "selfheal:\n  enabled: true\napi:\n  address: :8080\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRollbackConfig(t *testing.T) {
	router := setupConfigRouter(func(*config.Config) error { return nil })
	payload := map[string]any{
		"config_yaml": "api:\n  address: :8080\n",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/config/apply", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	req = httptest.NewRequest(http.MethodPost, "/api/config/rollback", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/config/snapshots", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
