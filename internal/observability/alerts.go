package observability

import (
	"sync"
	"time"

	"router-go/internal/metrics"
)

type AlertType string

const (
	AlertDrops  AlertType = "drops"
	AlertErrors AlertType = "errors"
	AlertIDS    AlertType = "ids"
)

type Alert struct {
	ID        string    `json:"id"`
	Type      AlertType `json:"type"`
	Message   string    `json:"message"`
	Value     uint64    `json:"value"`
	Threshold uint64    `json:"threshold"`
	Timestamp int64     `json:"timestamp"`
}

type AlertsConfig struct {
	DropsThreshold     uint64
	ErrorsThreshold    uint64
	IDSAlertsThreshold uint64
}

type AlertStore struct {
	mu     sync.Mutex
	limit  int
	alerts []Alert
}

func NewAlertStore(limit int) *AlertStore {
	if limit <= 0 {
		limit = 1000
	}
	return &AlertStore{
		limit:  limit,
		alerts: make([]Alert, 0, limit),
	}
}

func (s *AlertStore) Add(alert Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, alert)
	if len(s.alerts) > s.limit {
		s.alerts = append([]Alert{}, s.alerts[len(s.alerts)-s.limit:]...)
	}
}

func (s *AlertStore) List() []Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Alert, 0, len(s.alerts))
	out = append(out, s.alerts...)
	return out
}

func (s *AlertStore) Limit() int {
	return s.limit
}

func EvaluateAlerts(prev metrics.Snapshot, curr metrics.Snapshot, cfg AlertsConfig) []Alert {
	out := make([]Alert, 0, 3)
	now := time.Now().Unix()
	if cfg.DropsThreshold > 0 {
		delta := uint64(0)
		if curr.Drops >= prev.Drops {
			delta = curr.Drops - prev.Drops
		}
		if delta >= cfg.DropsThreshold {
			out = append(out, Alert{
				ID:        newAlertID(),
				Type:      AlertDrops,
				Message:   "drops threshold exceeded",
				Value:     delta,
				Threshold: cfg.DropsThreshold,
				Timestamp: now,
			})
		}
	}
	if cfg.ErrorsThreshold > 0 {
		delta := uint64(0)
		if curr.Errors >= prev.Errors {
			delta = curr.Errors - prev.Errors
		}
		if delta >= cfg.ErrorsThreshold {
			out = append(out, Alert{
				ID:        newAlertID(),
				Type:      AlertErrors,
				Message:   "errors threshold exceeded",
				Value:     delta,
				Threshold: cfg.ErrorsThreshold,
				Timestamp: now,
			})
		}
	}
	if cfg.IDSAlertsThreshold > 0 {
		delta := uint64(0)
		if curr.IDSAlerts >= prev.IDSAlerts {
			delta = curr.IDSAlerts - prev.IDSAlerts
		}
		if delta >= cfg.IDSAlertsThreshold {
			out = append(out, Alert{
				ID:        newAlertID(),
				Type:      AlertIDS,
				Message:   "ids alerts threshold exceeded",
				Value:     delta,
				Threshold: cfg.IDSAlertsThreshold,
				Timestamp: now,
			})
		}
	}
	return out
}

func newAlertID() string {
	return time.Now().Format("20060102150405.000000000")
}
