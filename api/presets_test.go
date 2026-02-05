package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"router-go/internal/config"
	"router-go/internal/presets"

	"github.com/gin-gonic/gin"
)

func TestGetPresets(t *testing.T) {
	store := setupPresetStore(t)
	h := &Handlers{
		Presets: store,
	}
	router := gin.New()
	RegisterRoutes(router, h)

	req := httptest.NewRequest(http.MethodGet, "/api/presets", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestPreviewPreset(t *testing.T) {
	store := setupPresetStore(t)
	base := &config.Config{
		Interfaces: []config.InterfaceConfig{{Name: "eth0", IP: "192.168.1.1/24"}},
		Routes:     []config.RouteConfig{{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "eth0", Metric: 100}},
	}
	h := &Handlers{
		Presets:   store,
		ConfigMgr: config.NewManager(base, nil),
	}
	router := gin.New()
	RegisterRoutes(router, h)

	req := httptest.NewRequest(http.MethodPost, "/api/presets/home/preview", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func setupPresetStore(t *testing.T) *presets.Store {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "home.json")
	data := []byte(`{
  "id": "home",
  "name": "Дом",
  "description": "Тестовый пресет",
  "settings": {
    "firewall": [
      {"chain": "INPUT", "action": "ACCEPT", "protocol": "ICMP"}
    ]
  }
}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write preset: %v", err)
	}
	store, err := presets.LoadStore(dir)
	if err != nil {
		t.Fatalf("load store: %v", err)
	}
	return store
}
