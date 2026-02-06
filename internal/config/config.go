package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Interfaces       []InterfaceConfig      `mapstructure:"interfaces"`
	Routes           []RouteConfig          `mapstructure:"routes"`
	Firewall         []FirewallRuleConfig   `mapstructure:"firewall"`
	FirewallDefaults FirewallDefaultsConfig `mapstructure:"firewall_defaults"`
	NAT              []NATRuleConfig        `mapstructure:"nat"`
	QoS              []QoSClassConfig       `mapstructure:"qos"`
	IDS              IDSConfig              `mapstructure:"ids"`
	SelfHeal         SelfHealConfig         `mapstructure:"selfheal"`
	Dashboard        DashboardConfig        `mapstructure:"dashboard"`
	P2P              P2PConfig              `mapstructure:"p2p"`
	Proxy            ProxyConfig            `mapstructure:"proxy"`
	Integrations     IntegrationsConfig     `mapstructure:"integrations"`
	Security         SecurityConfig         `mapstructure:"security"`
	HA               HAConfig               `mapstructure:"ha"`
	API              APIConfig              `mapstructure:"api"`
	Metrics          MetricsConfig          `mapstructure:"metrics"`
	Observability    ObservabilityConfig    `mapstructure:"observability"`
	Performance      PerformanceConfig      `mapstructure:"performance"`
	Logging          LoggingConfig          `mapstructure:"logging"`
	Presets          PresetsConfig          `mapstructure:"presets"`
	System           SystemConfig           `mapstructure:"system"`
}

type InterfaceConfig struct {
	Name string `mapstructure:"name"`
	IP   string `mapstructure:"ip"`
}

type RouteConfig struct {
	Destination string `mapstructure:"destination"`
	Gateway     string `mapstructure:"gateway"`
	Interface   string `mapstructure:"interface"`
	Metric      int    `mapstructure:"metric"`
}

type FirewallRuleConfig struct {
	Chain        string `mapstructure:"chain"`
	Action       string `mapstructure:"action"`
	Protocol     string `mapstructure:"protocol"`
	SrcIP        string `mapstructure:"src_ip"`
	DstIP        string `mapstructure:"dst_ip"`
	SrcPort      int    `mapstructure:"src_port"`
	DstPort      int    `mapstructure:"dst_port"`
	InInterface  string `mapstructure:"in_interface"`
	OutInterface string `mapstructure:"out_interface"`
}

type FirewallDefaultsConfig struct {
	Input   string `mapstructure:"input"`
	Output  string `mapstructure:"output"`
	Forward string `mapstructure:"forward"`
}

type NATRuleConfig struct {
	Type    string `mapstructure:"type"`
	SrcIP   string `mapstructure:"src_ip"`
	DstIP   string `mapstructure:"dst_ip"`
	SrcPort int    `mapstructure:"src_port"`
	DstPort int    `mapstructure:"dst_port"`
	ToIP    string `mapstructure:"to_ip"`
	ToPort  int    `mapstructure:"to_port"`
}

type QoSClassConfig struct {
	Name          string `mapstructure:"name"`
	Protocol      string `mapstructure:"protocol"`
	SrcPort       int    `mapstructure:"src_port"`
	DstPort       int    `mapstructure:"dst_port"`
	RateLimitKbps int    `mapstructure:"rate_limit_kbps"`
	Priority      int    `mapstructure:"priority"`
	MaxQueue      int    `mapstructure:"max_queue"`
	DropPolicy    string `mapstructure:"drop_policy"`
}

type IDSConfig struct {
	Enabled            bool   `mapstructure:"enabled"`
	WindowSeconds      int    `mapstructure:"window_seconds"`
	RateThreshold      int    `mapstructure:"rate_threshold"`
	PortScanThreshold  int    `mapstructure:"portscan_threshold"`
	UniqueDstThreshold int    `mapstructure:"unique_dst_threshold"`
	BehaviorAction     string `mapstructure:"behavior_action"`
	AlertLimit         int    `mapstructure:"alert_limit"`
	WhitelistSrc       []string `mapstructure:"whitelist_src"`
	WhitelistDst       []string `mapstructure:"whitelist_dst"`
}

type SelfHealConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	PingGateway    string `mapstructure:"ping_gateway"`
	HTTPCheckURL   string `mapstructure:"http_check_url"`
	TimeoutSeconds int    `mapstructure:"timeout_seconds"`
}

type DashboardConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	StaticDir string `mapstructure:"static_dir"`
}

type P2PConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	PeerID         string `mapstructure:"peer_id"`
	Discovery      bool   `mapstructure:"discovery"`
	ListenAddr     string `mapstructure:"listen_addr"`
	MulticastAddr  string `mapstructure:"multicast_addr"`
	SyncInterval   int    `mapstructure:"sync_interval"`
	PeerTTLSeconds int    `mapstructure:"peer_ttl_seconds"`
	PrivateKeyFile string `mapstructure:"private_key_file"`
	PublicKeyFile  string `mapstructure:"public_key_file"`
}

type ProxyConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	ListenAddr      string `mapstructure:"listen_addr"`
	H3Addr          string `mapstructure:"h3_addr"`
	Upstream        string `mapstructure:"upstream"`
	CacheSize       int    `mapstructure:"cache_size"`
	CacheTTLSeconds int    `mapstructure:"cache_ttl_seconds"`
	EnableGzip      bool   `mapstructure:"enable_gzip"`
	EnableBrotli    bool   `mapstructure:"enable_brotli"`
	EnableH3        bool   `mapstructure:"enable_h3"`
	HSTS            bool   `mapstructure:"hsts"`
	CertFile        string `mapstructure:"cert_file"`
	KeyFile         string `mapstructure:"key_file"`
}

type IntegrationsConfig struct {
	TimeoutSeconds int                 `mapstructure:"timeout_seconds"`
	GeoIP          GeoIPConfig         `mapstructure:"geoip"`
	ASN            ASNConfig           `mapstructure:"asn"`
	ThreatIntel    ThreatIntelConfig   `mapstructure:"threat_intel"`
	Logs           LogsConfig          `mapstructure:"logs"`
	Metrics        MetricsExportConfig `mapstructure:"metrics"`
}

type GeoIPConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	MMDBPath  string `mapstructure:"mmdb_path"`
	HTTPURL   string `mapstructure:"http_url"`
	HTTPToken string `mapstructure:"http_token"`
}

type ASNConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Token   string `mapstructure:"token"`
}

type ThreatIntelConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
}

type LogsConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	LokiURL    string `mapstructure:"loki_url"`
	ElasticURL string `mapstructure:"elastic_url"`
}

type MetricsExportConfig struct {
	Enabled         bool   `mapstructure:"enabled"`
	RemoteWriteURL  string `mapstructure:"remote_write_url"`
	IntervalSeconds int    `mapstructure:"interval_seconds"`
}

type SecurityConfig struct {
	Enabled       bool          `mapstructure:"enabled"`
	RequireAuth   bool          `mapstructure:"require_auth"`
	AllowedCIDRs  []string      `mapstructure:"allowed_cidrs"`
	Tokens        []TokenConfig `mapstructure:"tokens"`
	TLS           TLSConfig     `mapstructure:"tls"`
}

type TokenConfig struct {
	Role  string `mapstructure:"role"`
	Value string `mapstructure:"value"`
}

type TLSConfig struct {
	Enabled        bool   `mapstructure:"enabled"`
	CertFile       string `mapstructure:"cert_file"`
	KeyFile        string `mapstructure:"key_file"`
	ClientCAFile   string `mapstructure:"client_ca_file"`
	RequireClientCert bool `mapstructure:"require_client_cert"`
}

type HAConfig struct {
	Enabled            bool     `mapstructure:"enabled"`
	NodeID             string   `mapstructure:"node_id"`
	Priority           int      `mapstructure:"priority"`
	HeartbeatInterval  int      `mapstructure:"heartbeat_interval_seconds"`
	HoldSeconds        int      `mapstructure:"hold_seconds"`
	BindAddr           string   `mapstructure:"bind_addr"`
	MulticastAddr      string   `mapstructure:"multicast_addr"`
	Peers              []string `mapstructure:"peers"`
	StateSyncInterval  int      `mapstructure:"state_sync_interval_seconds"`
	StateEndpointPath  string   `mapstructure:"state_endpoint_path"`
	TLS               TLSConfig `mapstructure:"tls"`
}

type APIConfig struct {
	Address string `mapstructure:"address"`
}

type MetricsConfig struct {
	Address string `mapstructure:"address"`
	Path    string `mapstructure:"path"`
}

type PerformanceConfig struct {
	EgressBatchSize       int `mapstructure:"egress_batch_size"`
	EgressIdleSleepMillis int `mapstructure:"egress_idle_sleep_millis"`
}

type ObservabilityConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	TracesLimit  int    `mapstructure:"traces_limit"`
	PprofEnabled bool   `mapstructure:"pprof_enabled"`
	PprofPath    string `mapstructure:"pprof_path"`
	AlertsEnabled       bool   `mapstructure:"alerts_enabled"`
	AlertsLimit         int    `mapstructure:"alerts_limit"`
	AlertIntervalSeconds int   `mapstructure:"alert_interval_seconds"`
	DropsThreshold      uint64 `mapstructure:"drops_threshold"`
	ErrorsThreshold     uint64 `mapstructure:"errors_threshold"`
	IDSAlertsThreshold  uint64 `mapstructure:"ids_alerts_threshold"`
}

type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

type PresetsConfig struct {
	Dir       string `mapstructure:"dir"`
	UpdateURL string `mapstructure:"update_url"`
}

type SystemConfig struct {
	Timezone   string   `mapstructure:"timezone"`
	NTPServers []string `mapstructure:"ntp_servers"`
}

func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func LoadFromBytes(data []byte) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(string(data))); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.API.Address == "" {
		cfg.API.Address = ":8080"
	}
	if cfg.Metrics.Address == "" {
		cfg.Metrics.Address = ":9090"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
	if cfg.Performance.EgressBatchSize == 0 {
		cfg.Performance.EgressBatchSize = 16
	}
	if cfg.Performance.EgressIdleSleepMillis == 0 {
		cfg.Performance.EgressIdleSleepMillis = 2
	}
	if cfg.Observability.TracesLimit == 0 {
		cfg.Observability.TracesLimit = 1000
	}
	if cfg.Observability.PprofPath == "" {
		cfg.Observability.PprofPath = "/debug/pprof"
	}
	if cfg.Observability.AlertsLimit == 0 {
		cfg.Observability.AlertsLimit = 1000
	}
	if cfg.Observability.AlertIntervalSeconds == 0 {
		cfg.Observability.AlertIntervalSeconds = 10
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.IDS.WindowSeconds == 0 {
		cfg.IDS.WindowSeconds = 10
	}
	if cfg.IDS.RateThreshold == 0 {
		cfg.IDS.RateThreshold = 200
	}
	if cfg.IDS.PortScanThreshold == 0 {
		cfg.IDS.PortScanThreshold = 20
	}
	if cfg.IDS.UniqueDstThreshold == 0 {
		cfg.IDS.UniqueDstThreshold = 10
	}
	if cfg.IDS.BehaviorAction == "" {
		cfg.IDS.BehaviorAction = "ALERT"
	}
	if cfg.IDS.AlertLimit == 0 {
		cfg.IDS.AlertLimit = 1000
	}
	if cfg.SelfHeal.TimeoutSeconds == 0 {
		cfg.SelfHeal.TimeoutSeconds = 3
	}
	if cfg.Dashboard.StaticDir == "" {
		cfg.Dashboard.StaticDir = "web"
	}
	if cfg.P2P.ListenAddr == "" {
		cfg.P2P.ListenAddr = ":5355"
	}
	if cfg.P2P.MulticastAddr == "" {
		cfg.P2P.MulticastAddr = "224.0.0.251:5355"
	}
	if cfg.P2P.SyncInterval == 0 {
		cfg.P2P.SyncInterval = 10
	}
	if cfg.P2P.PeerTTLSeconds == 0 {
		cfg.P2P.PeerTTLSeconds = cfg.P2P.SyncInterval * 3
	}
	if cfg.P2P.PeerID == "" {
		cfg.P2P.PeerID = "node-1"
	}
	if cfg.Proxy.ListenAddr == "" {
		cfg.Proxy.ListenAddr = ":8081"
	}
	if cfg.Proxy.CacheSize == 0 {
		cfg.Proxy.CacheSize = 100
	}
	if cfg.Proxy.CacheTTLSeconds == 0 {
		cfg.Proxy.CacheTTLSeconds = 60
	}
	if cfg.Integrations.TimeoutSeconds == 0 {
		cfg.Integrations.TimeoutSeconds = 3
	}
	if cfg.Integrations.Metrics.IntervalSeconds == 0 {
		cfg.Integrations.Metrics.IntervalSeconds = 10
	}
	if cfg.Security.RequireAuth == false && cfg.Security.Enabled {
		cfg.Security.RequireAuth = true
	}
	if cfg.HA.HeartbeatInterval == 0 {
		cfg.HA.HeartbeatInterval = 2
	}
	if cfg.HA.HoldSeconds == 0 {
		cfg.HA.HoldSeconds = 6
	}
	if cfg.HA.BindAddr == "" {
		cfg.HA.BindAddr = ":5356"
	}
	if cfg.HA.MulticastAddr == "" {
		cfg.HA.MulticastAddr = "224.0.0.252:5356"
	}
	if cfg.HA.StateSyncInterval == 0 {
		cfg.HA.StateSyncInterval = 5
	}
	if cfg.HA.StateEndpointPath == "" {
		cfg.HA.StateEndpointPath = "/api/ha/state"
	}
	if cfg.HA.NodeID == "" {
		cfg.HA.NodeID = "node-1"
	}
	if cfg.Presets.Dir == "" {
		cfg.Presets.Dir = "presets"
	}
	if cfg.System.Timezone == "" {
		cfg.System.Timezone = "UTC"
	}
}

func validate(cfg *Config) error {
	for i, iface := range cfg.Interfaces {
		if iface.Name == "" {
			return fmt.Errorf("interface[%d].name is required", i)
		}
	}
	for i, route := range cfg.Routes {
		if route.Destination == "" {
			return fmt.Errorf("routes[%d].destination is required", i)
		}
	}
	return nil
}

func Validate(cfg *Config) error {
	return validate(cfg)
}
