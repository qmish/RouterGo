package observability

import (
	"testing"

	"router-go/internal/metrics"
)

func TestEvaluateAlertsThresholds(t *testing.T) {
	cfg := AlertsConfig{
		DropsThreshold:     10,
		ErrorsThreshold:    5,
		IDSAlertsThreshold: 3,
	}
	prev := metrics.Snapshot{
		Drops:     100,
		Errors:    10,
		IDSAlerts: 7,
	}
	curr := metrics.Snapshot{
		Drops:     111,
		Errors:    14,
		IDSAlerts: 10,
	}
	alerts := EvaluateAlerts(prev, curr, cfg)
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	if !hasAlertType(alerts, AlertDrops) {
		t.Fatalf("expected drops alert")
	}
	if !hasAlertType(alerts, AlertIDS) {
		t.Fatalf("expected ids alert")
	}
}

func TestAlertStoreLimit(t *testing.T) {
	store := NewAlertStore(2)
	store.Add(Alert{ID: "a"})
	store.Add(Alert{ID: "b"})
	store.Add(Alert{ID: "c"})
	latest := store.List()
	if len(latest) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(latest))
	}
	if latest[0].ID != "b" || latest[1].ID != "c" {
		t.Fatalf("unexpected alerts order: %#v", latest)
	}
}

func hasAlertType(alerts []Alert, typ AlertType) bool {
	for _, alert := range alerts {
		if alert.Type == typ {
			return true
		}
	}
	return false
}
