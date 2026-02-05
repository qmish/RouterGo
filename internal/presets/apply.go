package presets

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

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
	if err := validatePresetSettings(preset.Settings); err != nil {
		return nil, ApplySummary{}, err
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

func validatePresetSettings(settings PresetSettings) error {
	for i, iface := range settings.Interfaces {
		if iface.Name == "" {
			return fmt.Errorf("interfaces[%d].name is required", i)
		}
		if iface.IP != "" {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(iface.IP)); err != nil {
				return fmt.Errorf("interfaces[%d].ip invalid", i)
			}
		}
	}
	for i, route := range settings.Routes {
		if strings.TrimSpace(route.Destination) == "" {
			return fmt.Errorf("routes[%d].destination is required", i)
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(route.Destination)); err != nil {
			return fmt.Errorf("routes[%d].destination invalid", i)
		}
		if gw := strings.TrimSpace(route.Gateway); gw != "" {
			if net.ParseIP(gw) == nil {
				return fmt.Errorf("routes[%d].gateway invalid", i)
			}
		}
		if strings.TrimSpace(route.Interface) == "" {
			return fmt.Errorf("routes[%d].interface is required", i)
		}
	}
	for i, rule := range settings.Firewall {
		if rule.SrcIP != "" {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(rule.SrcIP)); err != nil {
				return fmt.Errorf("firewall[%d].src_ip invalid", i)
			}
		}
		if rule.DstIP != "" {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(rule.DstIP)); err != nil {
				return fmt.Errorf("firewall[%d].dst_ip invalid", i)
			}
		}
	}
	for i, rule := range settings.NAT {
		if rule.SrcIP != "" {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(rule.SrcIP)); err != nil {
				return fmt.Errorf("nat[%d].src_ip invalid", i)
			}
		}
		if rule.DstIP != "" {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(rule.DstIP)); err != nil {
				return fmt.Errorf("nat[%d].dst_ip invalid", i)
			}
		}
		if rule.ToIP != "" && net.ParseIP(strings.TrimSpace(rule.ToIP)) == nil {
			return fmt.Errorf("nat[%d].to_ip invalid", i)
		}
	}
	return nil
}
