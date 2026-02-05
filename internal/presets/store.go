package presets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"router-go/internal/config"
)

type Preset struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Icon        string         `json:"icon,omitempty"`
	Settings    PresetSettings `json:"settings"`
	Extras      map[string]any `json:"extras,omitempty"`
}

type PresetSettings struct {
	Interfaces       []config.InterfaceConfig      `json:"interfaces,omitempty"`
	Routes           []config.RouteConfig          `json:"routes,omitempty"`
	Firewall         []config.FirewallRuleConfig   `json:"firewall,omitempty"`
	FirewallDefaults *config.FirewallDefaultsConfig `json:"firewall_defaults,omitempty"`
	NAT              []config.NATRuleConfig        `json:"nat,omitempty"`
	QoS              []config.QoSClassConfig       `json:"qos,omitempty"`
	IDS              *config.IDSConfig             `json:"ids,omitempty"`
}

type PresetSummary struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Icon        string `json:"icon,omitempty"`
}

type Store struct {
	mu      sync.Mutex
	dir     string
	presets map[string]Preset
}

func LoadStore(dir string) (*Store, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read presets dir: %w", err)
	}
	store := &Store{
		dir:     dir,
		presets: map[string]Preset{},
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read preset %s: %w", entry.Name(), err)
		}
		var preset Preset
		if err := json.Unmarshal(data, &preset); err != nil {
			return nil, fmt.Errorf("parse preset %s: %w", entry.Name(), err)
		}
		if preset.ID == "" {
			preset.ID = strings.TrimSuffix(entry.Name(), ".json")
		}
		if preset.Name == "" {
			preset.Name = preset.ID
		}
		store.presets[preset.ID] = preset
	}
	return store, nil
}

func (s *Store) List() []PresetSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PresetSummary, 0, len(s.presets))
	for _, preset := range s.presets {
		out = append(out, PresetSummary{
			ID:          preset.ID,
			Name:        preset.Name,
			Description: preset.Description,
			Icon:        preset.Icon,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *Store) Get(id string) (Preset, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	preset, ok := s.presets[id]
	return preset, ok
}

func (s *Store) Save(preset Preset) error {
	if preset.ID == "" {
		return fmt.Errorf("preset id is required")
	}
	if !validPresetID(preset.ID) {
		return fmt.Errorf("invalid preset id")
	}
	if preset.Name == "" {
		preset.Name = preset.ID
	}
	if preset.Description == "" {
		preset.Description = "Пользовательский пресет"
	}
	data, err := json.MarshalIndent(preset, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal preset: %w", err)
	}
	path := filepath.Join(s.dir, preset.ID+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write preset: %w", err)
	}
	s.mu.Lock()
	s.presets[preset.ID] = preset
	s.mu.Unlock()
	return nil
}

func (s *Store) Import(presets []Preset) (int, error) {
	if len(presets) == 0 {
		return 0, fmt.Errorf("no presets to import")
	}
	updated := 0
	for _, preset := range presets {
		if err := s.Save(preset); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

func (s *Store) UpdateFromURL(url string) (int, error) {
	if strings.TrimSpace(url) == "" {
		return 0, fmt.Errorf("update url is empty")
	}
	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch presets: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		return 0, fmt.Errorf("fetch presets: status %d", resp.StatusCode)
	}
	var raw any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return 0, fmt.Errorf("decode presets: %w", err)
	}
	presets, err := parsePresets(raw)
	if err != nil {
		return 0, err
	}
	return s.Import(presets)
}

func validPresetID(id string) bool {
	for _, r := range id {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func parsePresets(raw any) ([]Preset, error) {
	if raw == nil {
		return nil, fmt.Errorf("empty presets payload")
	}
	switch v := raw.(type) {
	case []any:
		return decodePresetSlice(v)
	case map[string]any:
		if value, ok := v["presets"]; ok {
			if list, ok := value.([]any); ok {
				return decodePresetSlice(list)
			}
		}
		return nil, fmt.Errorf("invalid presets payload")
	default:
		return nil, fmt.Errorf("invalid presets payload")
	}
}

func decodePresetSlice(list []any) ([]Preset, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("no presets to import")
	}
	out := make([]Preset, 0, len(list))
	for _, item := range list {
		data, err := json.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("encode preset: %w", err)
		}
		var preset Preset
		if err := json.Unmarshal(data, &preset); err != nil {
			return nil, fmt.Errorf("decode preset: %w", err)
		}
		out = append(out, preset)
	}
	return out, nil
}
