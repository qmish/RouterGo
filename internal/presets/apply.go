package presets

import (
	"encoding/json"
	"fmt"

	"router-go/internal/config"
)

type ApplySummary struct {
	RoutesBefore        int `json:"routes_before"`
	RoutesAfter         int `json:"routes_after"`
	FirewallRulesBefore int `json:"firewall_rules_before"`
	FirewallRulesAfter  int `json:"firewall_rules_after"`
	NATRulesBefore      int `json:"nat_rules_before"`
	NATRulesAfter       int `json:"nat_rules_after"`
	QoSClassesBefore    int `json:"qos_classes_before"`
	QoSClassesAfter     int `json:"qos_classes_after"`
}

func ApplyPreset(base *config.Config, preset Preset) (*config.Config, ApplySummary, error) {
	if base == nil {
		return nil, ApplySummary{}, fmt.Errorf("base config is nil")
	}
	next, err := cloneConfig(base)
	if err != nil {
		return nil, ApplySummary{}, err
	}
	if preset.Settings.Interfaces != nil {
		next.Interfaces = preset.Settings.Interfaces
	}
	if preset.Settings.Routes != nil {
		next.Routes = preset.Settings.Routes
	}
	if preset.Settings.Firewall != nil {
		next.Firewall = preset.Settings.Firewall
	}
	if preset.Settings.FirewallDefaults != nil {
		next.FirewallDefaults = *preset.Settings.FirewallDefaults
	}
	if preset.Settings.NAT != nil {
		next.NAT = preset.Settings.NAT
	}
	if preset.Settings.QoS != nil {
		next.QoS = preset.Settings.QoS
	}
	if preset.Settings.IDS != nil {
		next.IDS = *preset.Settings.IDS
	}
	if err := config.Validate(next); err != nil {
		return nil, ApplySummary{}, err
	}
	return next, summarize(base, next), nil
}

func summarize(before *config.Config, after *config.Config) ApplySummary {
	return ApplySummary{
		RoutesBefore:        len(before.Routes),
		RoutesAfter:         len(after.Routes),
		FirewallRulesBefore: len(before.Firewall),
		FirewallRulesAfter:  len(after.Firewall),
		NATRulesBefore:      len(before.NAT),
		NATRulesAfter:       len(after.NAT),
		QoSClassesBefore:    len(before.QoS),
		QoSClassesAfter:     len(after.QoS),
	}
}

func cloneConfig(cfg *config.Config) (*config.Config, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	var cloned config.Config
	if err := json.Unmarshal(data, &cloned); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cloned, nil
}
