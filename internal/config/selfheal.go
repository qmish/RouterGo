package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Snapshot struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason"`
	Config    *Config   `json:"config"`
}

type Manager struct {
	mu        sync.Mutex
	current   *Config
	snapshots []Snapshot
	nextID    int
	health    func(*Config) error
}

func NewManager(cfg *Config, health func(*Config) error) *Manager {
	return &Manager{
		current:   cfg,
		snapshots: nil,
		nextID:    1,
		health:    health,
	}
}

func (m *Manager) Current() *Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func (m *Manager) Snapshots() []Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Snapshot, 0, len(m.snapshots))
	out = append(out, m.snapshots...)
	return out
}

func (m *Manager) Apply(newCfg *Config) error {
	m.mu.Lock()
	prev := m.current
	snapshot := Snapshot{
		ID:        m.nextID,
		Timestamp: time.Now(),
		Reason:    "pre-apply",
		Config:    prev,
	}
	m.nextID++
	m.snapshots = append(m.snapshots, snapshot)
	m.current = newCfg
	health := m.health
	m.mu.Unlock()

	if health == nil || !newCfg.SelfHeal.Enabled {
		return nil
	}
	if err := health(newCfg); err != nil {
		_ = m.rollbackWithReason(err.Error())
		return fmt.Errorf("health check failed: %w", err)
	}
	return nil
}

func (m *Manager) RollbackLast() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.snapshots) == 0 {
		return errors.New("no snapshots")
	}
	last := m.snapshots[len(m.snapshots)-1]
	m.current = last.Config
	m.snapshots = append(m.snapshots, Snapshot{
		ID:        m.nextID,
		Timestamp: time.Now(),
		Reason:    "rollback",
		Config:    last.Config,
	})
	m.nextID++
	return nil
}

func (m *Manager) rollbackWithReason(reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.snapshots) == 0 {
		return errors.New("no snapshots")
	}
	last := m.snapshots[len(m.snapshots)-1]
	m.current = last.Config
	m.snapshots = append(m.snapshots, Snapshot{
		ID:        m.nextID,
		Timestamp: time.Now(),
		Reason:    "rollback: " + reason,
		Config:    last.Config,
	})
	m.nextID++
	return nil
}

func DefaultHealthCheck(cfg *Config) error {
	if !cfg.SelfHeal.Enabled {
		return nil
	}
	timeout := time.Duration(cfg.SelfHeal.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	if cfg.SelfHeal.PingGateway != "" {
		if err := pingGateway(cfg.SelfHeal.PingGateway, timeout); err != nil {
			return err
		}
	}
	if cfg.SelfHeal.HTTPCheckURL != "" {
		if err := httpCheck(cfg.SelfHeal.HTTPCheckURL, timeout); err != nil {
			return err
		}
	}
	return nil
}

func pingGateway(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(addr, "53"), timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func httpCheck(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	return nil
}
