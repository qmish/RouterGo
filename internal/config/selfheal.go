package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	history   []HistoryEntry
	nextID    int
	revision  int
	storePath string
	health    func(*Config) error
}

type ApplyPlan struct {
	Timestamp         time.Time `json:"timestamp"`
	PlannedSnapshotID int       `json:"planned_snapshot_id"`
	BaseRevision      int       `json:"base_revision"`
	TargetRevision    int       `json:"target_revision"`
	ChangedSections   []string  `json:"changed_sections"`
	Validation        string    `json:"validation"`
	HealthCheck       string    `json:"health_check"`
}

type SectionDiff struct {
	Section string `json:"section"`
	Before  any    `json:"before"`
	After   any    `json:"after"`
}

type ConfigDiff struct {
	FromRevision    int           `json:"from_revision"`
	ToRevision      int           `json:"to_revision"`
	ChangedSections []string      `json:"changed_sections"`
	SectionDiffs    []SectionDiff `json:"section_diffs"`
}

type HistoryEntry struct {
	ID              int       `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	Reason          string    `json:"reason"`
	Revision        int       `json:"revision"`
	Actor           string    `json:"actor"`
	ChangedSections []string  `json:"changed_sections,omitempty"`
}

type persistedState struct {
	Current   *Config        `json:"current"`
	Snapshots []Snapshot     `json:"snapshots"`
	History   []HistoryEntry `json:"history"`
	NextID    int            `json:"next_id"`
	Revision  int            `json:"revision"`
}

type ChangeMeta struct {
	Actor           string
	Reason          string
	ChangedSections []string
}

func NewManager(cfg *Config, health func(*Config) error) *Manager {
	return NewManagerWithStore(cfg, health, "")
}

func NewManagerWithStore(cfg *Config, health func(*Config) error, storePath string) *Manager {
	return &Manager{
		current:   cfg,
		snapshots: nil,
		history:   nil,
		nextID:    1,
		revision:  0,
		storePath: storePath,
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

func (m *Manager) History() []HistoryEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]HistoryEntry, 0, len(m.history))
	out = append(out, m.history...)
	return out
}

func (m *Manager) Revision() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.revision
}

func (m *Manager) DiffRevisions(fromRevision int, toRevision int) (ConfigDiff, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fromCfg, ok := m.configByRevisionLocked(fromRevision)
	if !ok {
		return ConfigDiff{}, fmt.Errorf("from revision %d not found", fromRevision)
	}
	toCfg, ok := m.configByRevisionLocked(toRevision)
	if !ok {
		return ConfigDiff{}, fmt.Errorf("to revision %d not found", toRevision)
	}

	fromMap, err := configToMap(fromCfg)
	if err != nil {
		return ConfigDiff{}, err
	}
	toMap, err := configToMap(toCfg)
	if err != nil {
		return ConfigDiff{}, err
	}

	seen := map[string]struct{}{}
	keys := make([]string, 0, len(fromMap)+len(toMap))
	for k := range fromMap {
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range toMap {
		if _, ok := seen[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	changedSections := make([]string, 0, len(keys))
	sectionDiffs := make([]SectionDiff, 0, len(keys))
	for _, key := range keys {
		before := fromMap[key]
		after := toMap[key]
		if reflect.DeepEqual(before, after) {
			continue
		}
		changedSections = append(changedSections, key)
		sectionDiffs = append(sectionDiffs, SectionDiff{
			Section: key,
			Before:  before,
			After:   after,
		})
	}

	return ConfigDiff{
		FromRevision:    fromRevision,
		ToRevision:      toRevision,
		ChangedSections: changedSections,
		SectionDiffs:    sectionDiffs,
	}, nil
}

func (m *Manager) Apply(newCfg *Config) error {
	plan, err := m.Plan(newCfg)
	if err != nil {
		return err
	}
	return m.ApplyWithPlan(newCfg, plan)
}

func (m *Manager) Plan(newCfg *Config) (ApplyPlan, error) {
	if newCfg == nil {
		return ApplyPlan{}, errors.New("new config is required")
	}

	if err := Validate(newCfg); err != nil {
		return ApplyPlan{}, fmt.Errorf("validation failed: %w", err)
	}

	m.mu.Lock()
	prev := m.current
	plannedSnapshotID := m.nextID
	baseRevision := m.revision
	health := m.health
	m.mu.Unlock()

	healthStatus := "skipped"
	if health != nil && newCfg.SelfHeal.Enabled {
		if err := health(newCfg); err != nil {
			return ApplyPlan{}, fmt.Errorf("health check failed: %w", err)
		}
		healthStatus = "ok"
	}

	return ApplyPlan{
		Timestamp:         time.Now(),
		PlannedSnapshotID: plannedSnapshotID,
		BaseRevision:      baseRevision,
		TargetRevision:    baseRevision + 1,
		ChangedSections:   changedSections(prev, newCfg),
		Validation:        "ok",
		HealthCheck:       healthStatus,
	}, nil
}

func (m *Manager) ApplyWithPlan(newCfg *Config, plan ApplyPlan) error {
	return m.ApplyWithMeta(newCfg, plan, ChangeMeta{})
}

func (m *Manager) ApplyWithMeta(newCfg *Config, plan ApplyPlan, meta ChangeMeta) error {
	if newCfg == nil {
		return errors.New("new config is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if plan.PlannedSnapshotID != 0 && m.nextID != plan.PlannedSnapshotID {
		return errors.New("stale config plan")
	}
	if plan.BaseRevision != m.revision {
		return errors.New("stale config revision")
	}

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
	m.revision++
	changed := meta.ChangedSections
	if len(changed) == 0 {
		changed = append([]string(nil), plan.ChangedSections...)
	}
	reason := strings.TrimSpace(meta.Reason)
	if reason == "" {
		reason = "apply"
	}
	m.history = append(m.history, HistoryEntry{
		ID:              snapshot.ID,
		Timestamp:       time.Now(),
		Reason:          reason,
		Revision:        m.revision,
		Actor:           normalizeActor(meta.Actor),
		ChangedSections: changed,
	})
	if err := m.persistLocked(); err != nil {
		return fmt.Errorf("persist failed: %w", err)
	}
	return nil
}

func (m *Manager) RollbackLast() error {
	return m.RollbackWithMeta(ChangeMeta{})
}

func (m *Manager) RollbackWithMeta(meta ChangeMeta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.snapshots) == 0 {
		return errors.New("no snapshots")
	}
	prev := m.current
	last := m.snapshots[len(m.snapshots)-1]
	m.current = last.Config
	m.snapshots = m.snapshots[:len(m.snapshots)-1]
	if m.revision > 0 {
		m.revision--
	}
	changed := meta.ChangedSections
	if len(changed) == 0 {
		changed = changedSections(prev, last.Config)
	}
	reason := strings.TrimSpace(meta.Reason)
	if reason == "" {
		reason = "rollback"
	}
	m.history = append(m.history, HistoryEntry{
		ID:              m.nextID,
		Timestamp:       time.Now(),
		Reason:          reason,
		Revision:        m.revision,
		Actor:           normalizeActor(meta.Actor),
		ChangedSections: changed,
	})
	m.nextID++
	if err := m.persistLocked(); err != nil {
		return fmt.Errorf("persist failed: %w", err)
	}
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

func changedSections(prev *Config, next *Config) []string {
	if next == nil {
		return nil
	}
	if prev == nil {
		return configSections(next)
	}

	prevMap, err := configToMap(prev)
	if err != nil {
		return nil
	}
	nextMap, err := configToMap(next)
	if err != nil {
		return nil
	}

	seen := map[string]struct{}{}
	keys := make([]string, 0, len(prevMap)+len(nextMap))
	for k := range prevMap {
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range nextMap {
		if _, ok := seen[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	changed := make([]string, 0, len(keys))
	for _, key := range keys {
		if !reflect.DeepEqual(prevMap[key], nextMap[key]) {
			changed = append(changed, key)
		}
	}
	return changed
}

func configSections(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	m, err := configToMap(cfg)
	if err != nil {
		return nil
	}
	sections := make([]string, 0, len(m))
	for k := range m {
		sections = append(sections, k)
	}
	sort.Strings(sections)
	return sections
}

func configToMap(cfg *Config) (map[string]any, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any)
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (m *Manager) LoadPersisted() error {
	if m.storePath == "" {
		return nil
	}
	data, err := os.ReadFile(m.storePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if state.Current != nil {
		m.current = state.Current
	}
	m.snapshots = append([]Snapshot(nil), state.Snapshots...)
	m.history = append([]HistoryEntry(nil), state.History...)
	if state.NextID > 0 {
		m.nextID = state.NextID
	}
	if state.Revision >= 0 {
		m.revision = state.Revision
	}
	return nil
}

func (m *Manager) persistLocked() error {
	if m.storePath == "" {
		return nil
	}
	state := persistedState{
		Current:   m.current,
		Snapshots: m.snapshots,
		History:   m.history,
		NextID:    m.nextID,
		Revision:  m.revision,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(m.storePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := m.storePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.storePath)
}

func (m *Manager) configByRevisionLocked(revision int) (*Config, bool) {
	if revision < 0 || revision > m.revision {
		return nil, false
	}
	if revision == m.revision {
		return m.current, true
	}
	if revision < len(m.snapshots) {
		return m.snapshots[revision].Config, true
	}
	return nil, false
}

func normalizeActor(actor string) string {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return "system"
	}
	return actor
}
