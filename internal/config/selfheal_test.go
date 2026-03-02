package config

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagerApplySuccess(t *testing.T) {
	base := &Config{SelfHeal: SelfHealConfig{Enabled: true}}
	mgr := NewManager(base, func(*Config) error { return nil })

	next := &Config{SelfHeal: SelfHealConfig{Enabled: true}}
	if err := mgr.Apply(next); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.Current() != next {
		t.Fatalf("expected current config updated")
	}
	if len(mgr.Snapshots()) != 1 {
		t.Fatalf("expected snapshot created")
	}
}

func TestManagerApplyRollbackOnFailure(t *testing.T) {
	base := &Config{SelfHeal: SelfHealConfig{Enabled: true}}
	mgr := NewManager(base, func(*Config) error { return errors.New("fail") })

	next := &Config{SelfHeal: SelfHealConfig{Enabled: true}}
	if err := mgr.Apply(next); err == nil {
		t.Fatalf("expected error")
	}
	if mgr.Current() != base {
		t.Fatalf("expected current config to remain base")
	}
	if len(mgr.Snapshots()) != 0 {
		t.Fatalf("expected no snapshots on failed plan")
	}
}

func TestManagerRollbackLast(t *testing.T) {
	base := &Config{SelfHeal: SelfHealConfig{Enabled: true}}
	mgr := NewManager(base, nil)
	next := &Config{SelfHeal: SelfHealConfig{Enabled: true}}
	_ = mgr.Apply(next)

	if err := mgr.RollbackLast(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mgr.Current() != base {
		t.Fatalf("expected rollback to base")
	}
}

func TestDefaultHealthCheckDisabled(t *testing.T) {
	cfg := &Config{
		SelfHeal: SelfHealConfig{
			Enabled:      false,
			HTTPCheckURL: "http://invalid",
		},
	}
	if err := DefaultHealthCheck(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultHealthCheckHTTPSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		SelfHeal: SelfHealConfig{
			Enabled:      true,
			HTTPCheckURL: server.URL,
		},
	}
	if err := DefaultHealthCheck(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultHealthCheckHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &Config{
		SelfHeal: SelfHealConfig{
			Enabled:      true,
			HTTPCheckURL: server.URL,
		},
	}
	if err := DefaultHealthCheck(cfg); err == nil {
		t.Fatalf("expected error on http failure")
	}
}

func TestDefaultHealthCheckPingGatewaySuccess(t *testing.T) {
	cfg := &Config{
		SelfHeal: SelfHealConfig{
			Enabled:     true,
			PingGateway: "127.0.0.1",
		},
	}
	if err := DefaultHealthCheck(cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDefaultHealthCheckPingGatewayFailure(t *testing.T) {
	cfg := &Config{
		SelfHeal: SelfHealConfig{
			Enabled:     true,
			PingGateway: "invalid-ip",
		},
	}
	if err := DefaultHealthCheck(cfg); err == nil {
		t.Fatalf("expected error on ping gateway failure")
	}
}

func TestManagerPlanSuccess(t *testing.T) {
	base := &Config{
		API: APIConfig{Address: ":8080"},
	}
	mgr := NewManager(base, func(*Config) error { return nil })
	next := &Config{
		API: APIConfig{Address: ":8081"},
	}

	plan, err := mgr.Plan(next)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.PlannedSnapshotID != 1 {
		t.Fatalf("expected snapshot id 1, got %d", plan.PlannedSnapshotID)
	}
	if len(plan.ChangedSections) == 0 {
		t.Fatalf("expected changed sections in plan")
	}
}

func TestManagerApplyWithPlanStale(t *testing.T) {
	base := &Config{API: APIConfig{Address: ":8080"}}
	mgr := NewManager(base, nil)

	plan1, err := mgr.Plan(&Config{API: APIConfig{Address: ":8081"}})
	if err != nil {
		t.Fatalf("plan1 failed: %v", err)
	}
	if err := mgr.ApplyWithPlan(&Config{API: APIConfig{Address: ":8081"}}, plan1); err != nil {
		t.Fatalf("apply1 failed: %v", err)
	}

	if err := mgr.ApplyWithPlan(&Config{API: APIConfig{Address: ":8082"}}, plan1); err == nil {
		t.Fatalf("expected stale plan error")
	}
}
