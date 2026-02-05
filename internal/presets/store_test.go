package presets

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"router-go/internal/config"
)

func TestLoadStoreListAndGet(t *testing.T) {
	dir := t.TempDir()
	writePreset(t, dir, "home.json", `{
  "id": "home",
  "name": "Домашний роутер",
  "description": "Тестовый пресет",
  "settings": {
    "routes": [
      {"destination": "0.0.0.0/0", "gateway": "192.0.2.1", "interface": "eth0", "metric": 10}
    ]
  }
}`)

	store, err := LoadStore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 preset, got %d", len(list))
	}
	if list[0].ID != "home" {
		t.Fatalf("expected id home, got %q", list[0].ID)
	}
	_, ok := store.Get("home")
	if !ok {
		t.Fatalf("expected preset home to exist")
	}
}

func TestLoadStoreInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	writePreset(t, dir, "broken.json", `{`)

	_, err := LoadStore(dir)
	if err == nil {
		t.Fatalf("expected error for invalid json")
	}
}

func TestApplyPresetUpdatesConfig(t *testing.T) {
	base := &config.Config{
		Interfaces: []config.InterfaceConfig{
			{Name: "eth0", IP: "192.168.1.1/24"},
		},
		Routes: []config.RouteConfig{
			{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "eth0", Metric: 100},
		},
	}
	preset := Preset{
		ID:   "home",
		Name: "Дом",
		Settings: PresetSettings{
			Firewall: []config.FirewallRuleConfig{
				{Chain: "INPUT", Action: "ACCEPT", Protocol: "ICMP"},
			},
			NAT: []config.NATRuleConfig{
				{Type: "SNAT", SrcIP: "192.168.1.0/24", ToIP: "203.0.113.10"},
			},
		},
	}

	updated, summary, err := ApplyPreset(base, preset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.FirewallRulesAfter != 1 || summary.NATRulesAfter != 1 {
		t.Fatalf("expected firewall/nat counts to be updated")
	}
	if len(updated.Firewall) != 1 {
		t.Fatalf("expected firewall rules applied")
	}
	if len(updated.NAT) != 1 {
		t.Fatalf("expected nat rules applied")
	}
}

func TestApplyPresetInvalidCIDR(t *testing.T) {
	base := &config.Config{
		Interfaces: []config.InterfaceConfig{
			{Name: "eth0", IP: "192.168.1.1/24"},
		},
		Routes: []config.RouteConfig{
			{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "eth0", Metric: 100},
		},
	}
	preset := Preset{
		ID:   "bad",
		Name: "Bad",
		Settings: PresetSettings{
			Firewall: []config.FirewallRuleConfig{
				{Chain: "INPUT", Action: "ACCEPT", SrcIP: "not-cidr"},
			},
		},
	}

	_, _, err := ApplyPreset(base, preset)
	if err == nil {
		t.Fatalf("expected error for invalid cidr")
	}
}

func TestApplyPresetInvalidPorts(t *testing.T) {
	base := &config.Config{
		Interfaces: []config.InterfaceConfig{
			{Name: "eth0", IP: "192.168.1.1/24"},
		},
		Routes: []config.RouteConfig{
			{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "eth0", Metric: 100},
		},
	}
	preset := Preset{
		ID:   "bad-ports",
		Name: "Bad Ports",
		Settings: PresetSettings{
			Firewall: []config.FirewallRuleConfig{
				{Chain: "INPUT", Action: "ACCEPT", Protocol: "TCP", DstPort: 70000},
			},
		},
	}

	_, _, err := ApplyPreset(base, preset)
	if err == nil {
		t.Fatalf("expected error for invalid port")
	}
}

func TestApplyPresetInvalidProtocol(t *testing.T) {
	base := &config.Config{
		Interfaces: []config.InterfaceConfig{
			{Name: "eth0", IP: "192.168.1.1/24"},
		},
		Routes: []config.RouteConfig{
			{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "eth0", Metric: 100},
		},
	}
	preset := Preset{
		ID:   "bad-proto",
		Name: "Bad Proto",
		Settings: PresetSettings{
			QoS: []config.QoSClassConfig{
				{Name: "x", Protocol: "SCTP", DstPort: 443},
			},
		},
	}

	_, _, err := ApplyPreset(base, preset)
	if err == nil {
		t.Fatalf("expected error for invalid protocol")
	}
}

func TestStoreSavePreset(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadStore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	preset := Preset{
		ID:          "custom-1",
		Name:        "Мой пресет",
		Description: "User preset",
		Settings: PresetSettings{
			Firewall: []config.FirewallRuleConfig{
				{Chain: "INPUT", Action: "ACCEPT", Protocol: "ICMP"},
			},
		},
	}
	if err := store.Save(preset); err != nil {
		t.Fatalf("save preset: %v", err)
	}
	loaded, ok := store.Get("custom-1")
	if !ok {
		t.Fatalf("expected preset to be stored")
	}
	if loaded.Name != "Мой пресет" {
		t.Fatalf("unexpected name %q", loaded.Name)
	}
}

func TestStoreSaveInvalidID(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadStore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	preset := Preset{ID: "bad id"}
	if err := store.Save(preset); err == nil {
		t.Fatalf("expected error for invalid id")
	}
}

func TestUpdateFromURL(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadStore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
  {"id":"up-1","name":"Updated","settings":{"firewall":[{"chain":"INPUT","action":"ACCEPT","protocol":"ICMP"}]}}
]`))
	}))
	defer server.Close()

	updated, err := store.UpdateFromURL(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated != 1 {
		t.Fatalf("expected 1 updated preset, got %d", updated)
	}
	if _, ok := store.Get("up-1"); !ok {
		t.Fatalf("expected preset to be imported")
	}
}

func TestImportPresets(t *testing.T) {
	dir := t.TempDir()
	store, err := LoadStore(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	updated, err := store.Import([]Preset{
		{ID: "p1", Name: "P1"},
		{ID: "p2", Name: "P2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updated != 2 {
		t.Fatalf("expected 2 presets, got %d", updated)
	}
}

func writePreset(t *testing.T, dir string, name string, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write preset: %v", err)
	}
}
