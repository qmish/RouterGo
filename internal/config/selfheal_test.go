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
		t.Fatalf("expected rollback to base config")
	}
	if len(mgr.Snapshots()) < 2 {
		t.Fatalf("expected rollback snapshot")
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
