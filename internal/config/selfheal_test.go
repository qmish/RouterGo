package config

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	if mgr.Revision() != 1 {
		t.Fatalf("expected revision 1")
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
	if mgr.Revision() != 0 {
		t.Fatalf("expected revision 0 after rollback")
	}
	if len(mgr.Snapshots()) != 0 {
		t.Fatalf("expected snapshots stack to shrink after rollback")
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

func TestManagerApplyWithPlanStaleRevision(t *testing.T) {
	base := &Config{API: APIConfig{Address: ":8080"}}
	mgr := NewManager(base, nil)

	plan, err := mgr.Plan(&Config{API: APIConfig{Address: ":8081"}})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if err := mgr.Apply(&Config{API: APIConfig{Address: ":8082"}}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if err := mgr.ApplyWithPlan(&Config{API: APIConfig{Address: ":8081"}}, plan); err == nil {
		t.Fatalf("expected stale revision error")
	}
}

func TestManagerRollbackTwoSteps(t *testing.T) {
	base := &Config{API: APIConfig{Address: ":8080"}}
	mgr := NewManager(base, nil)

	cfg1 := &Config{API: APIConfig{Address: ":8081"}}
	cfg2 := &Config{API: APIConfig{Address: ":8082"}}
	if err := mgr.Apply(cfg1); err != nil {
		t.Fatalf("apply cfg1 failed: %v", err)
	}
	if err := mgr.Apply(cfg2); err != nil {
		t.Fatalf("apply cfg2 failed: %v", err)
	}
	if err := mgr.RollbackLast(); err != nil {
		t.Fatalf("rollback1 failed: %v", err)
	}
	if got := mgr.Current().API.Address; got != ":8081" {
		t.Fatalf("expected :8081 after first rollback, got %s", got)
	}
	if err := mgr.RollbackLast(); err != nil {
		t.Fatalf("rollback2 failed: %v", err)
	}
	if got := mgr.Current().API.Address; got != ":8080" {
		t.Fatalf("expected :8080 after second rollback, got %s", got)
	}
}

func TestManagerPersistAndLoad(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "config-state.json")
	base := &Config{API: APIConfig{Address: ":8080"}}
	mgr := NewManagerWithStore(base, nil, storePath)

	if err := mgr.Apply(&Config{API: APIConfig{Address: ":8081"}}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if err := mgr.Apply(&Config{API: APIConfig{Address: ":8082"}}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if err := mgr.RollbackLast(); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	restored := NewManagerWithStore(&Config{}, nil, storePath)
	if err := restored.LoadPersisted(); err != nil {
		t.Fatalf("load persisted failed: %v", err)
	}
	if got := restored.Current().API.Address; got != ":8081" {
		t.Fatalf("expected restored current :8081, got %s", got)
	}
	if restored.Revision() != 1 {
		t.Fatalf("expected restored revision 1, got %d", restored.Revision())
	}
	if len(restored.History()) == 0 {
		t.Fatalf("expected non-empty history")
	}
}

func TestManagerDiffRevisions(t *testing.T) {
	base := &Config{API: APIConfig{Address: ":8080"}}
	mgr := NewManager(base, nil)
	if err := mgr.Apply(&Config{API: APIConfig{Address: ":8081"}}); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	diff, err := mgr.DiffRevisions(0, 1)
	if err != nil {
		t.Fatalf("diff failed: %v", err)
	}
	if len(diff.ChangedSections) == 0 {
		t.Fatalf("expected changed sections")
	}
	foundAPI := false
	for _, s := range diff.ChangedSections {
		if s == "API" {
			foundAPI = true
			break
		}
	}
	if !foundAPI {
		t.Fatalf("expected API section to be changed")
	}
}

func TestManagerAuditTrailFields(t *testing.T) {
	base := &Config{API: APIConfig{Address: ":8080"}}
	mgr := NewManager(base, nil)

	next := &Config{API: APIConfig{Address: ":8081"}}
	plan, err := mgr.Plan(next)
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if err := mgr.ApplyWithMeta(next, plan, ChangeMeta{
		Actor:  "ops-user",
		Reason: "change api bind",
	}); err != nil {
		t.Fatalf("apply with meta failed: %v", err)
	}
	history := mgr.History()
	if len(history) == 0 {
		t.Fatalf("expected non-empty history")
	}
	last := history[len(history)-1]
	if last.Actor != "ops-user" {
		t.Fatalf("expected actor ops-user, got %s", last.Actor)
	}
	if last.Reason != "change api bind" {
		t.Fatalf("expected reason to be saved")
	}
	if len(last.ChangedSections) == 0 {
		t.Fatalf("expected changed sections to be saved")
	}
}
