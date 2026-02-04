package config

import (
	"errors"
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
