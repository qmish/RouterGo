package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromBytesAppliesDefaults(t *testing.T) {
	data := []byte(`
interfaces:
  - name: eth0
routes:
  - destination: 0.0.0.0/0
    gateway: 192.0.2.1
    interface: eth0
security:
  enabled: true
  require_auth: false
`)
	cfg, err := LoadFromBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.API.Address != ":8080" {
		t.Fatalf("expected default api address, got %q", cfg.API.Address)
	}
	if cfg.Metrics.Address != ":9090" {
		t.Fatalf("expected default metrics address, got %q", cfg.Metrics.Address)
	}
	if cfg.Metrics.Path != "/metrics" {
		t.Fatalf("expected default metrics path, got %q", cfg.Metrics.Path)
	}
	if cfg.Performance.EgressBatchSize != 16 {
		t.Fatalf("expected default egress batch size, got %d", cfg.Performance.EgressBatchSize)
	}
	if cfg.Observability.TracesLimit != 1000 {
		t.Fatalf("expected default traces limit, got %d", cfg.Observability.TracesLimit)
	}
	if cfg.Logging.Level != "info" {
		t.Fatalf("expected default logging level, got %q", cfg.Logging.Level)
	}
	if cfg.P2P.ListenAddr != ":5355" {
		t.Fatalf("expected default p2p listen addr, got %q", cfg.P2P.ListenAddr)
	}
	if cfg.P2P.MulticastAddr != "224.0.0.251:5355" {
		t.Fatalf("expected default p2p multicast addr, got %q", cfg.P2P.MulticastAddr)
	}
	if cfg.P2P.SyncInterval != 10 {
		t.Fatalf("expected default p2p sync interval, got %d", cfg.P2P.SyncInterval)
	}
	if cfg.P2P.PeerTTLSeconds != 30 {
		t.Fatalf("expected default p2p peer ttl, got %d", cfg.P2P.PeerTTLSeconds)
	}
	if cfg.HA.StateEndpointPath != "/api/ha/state" {
		t.Fatalf("expected default ha state path, got %q", cfg.HA.StateEndpointPath)
	}
	if cfg.Security.RequireAuth != true {
		t.Fatalf("expected require_auth to be forced true when enabled")
	}
}

func TestLoadFromBytesRequiresInterfaceName(t *testing.T) {
	data := []byte(`
interfaces:
  - ip: 192.168.1.1/24
routes:
  - destination: 0.0.0.0/0
    gateway: 192.0.2.1
    interface: eth0
`)
	_, err := LoadFromBytes(data)
	if err == nil {
		t.Fatalf("expected error for missing interface name")
	}
}

func TestLoadFromBytesRequiresRouteDestination(t *testing.T) {
	data := []byte(`
interfaces:
  - name: eth0
routes:
  - gateway: 192.0.2.1
    interface: eth0
`)
	_, err := LoadFromBytes(data)
	if err == nil {
		t.Fatalf("expected error for missing route destination")
	}
}

func TestValidateWrapper(t *testing.T) {
	cfg := &Config{
		Interfaces: []InterfaceConfig{{Name: "eth0", IP: "192.168.1.1/24"}},
		Routes:     []RouteConfig{{Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "eth0"}},
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	data := []byte(`
interfaces:
  - name: eth0
routes:
  - destination: 0.0.0.0/0
    gateway: 192.0.2.1
    interface: eth0
`)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
