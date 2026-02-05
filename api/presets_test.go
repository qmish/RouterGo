package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestCreatePreset(t *testing.T) {
	store := setupPresetStore(t)
	h := &Handlers{
		Presets: store,
	}
	router := gin.New()
	RegisterRoutes(router, h)

	body := `{"id":"custom","name":"Custom","settings":{"firewall":[{"chain":"INPUT","action":"ACCEPT","protocol":"ICMP"}]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/presets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
	if _, ok := store.Get("custom"); !ok {
		t.Fatalf("expected preset to be saved")
	}
}

func TestPreviewPresetWithOverrides(t *testing.T) {
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

	body := `{"overrides":{"interface_name":"eth0","interface_ip":"192.168.10.1/24","default_gateway":"192.168.10.254"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/presets/home/preview", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestImportPresets(t *testing.T) {
	store := setupPresetStore(t)
	h := &Handlers{
		Presets: store,
	}
	router := gin.New()
	RegisterRoutes(router, h)

	body := `[{"id":"a","name":"A","settings":{}},{"id":"b","name":"B","settings":{}}]`
	req := httptest.NewRequest(http.MethodPost, "/api/presets/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if _, ok := store.Get("a"); !ok {
		t.Fatalf("expected preset a")
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
