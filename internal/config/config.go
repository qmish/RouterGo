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
	API              APIConfig              `mapstructure:"api"`
	Metrics          MetricsConfig          `mapstructure:"metrics"`
	Logging          LoggingConfig          `mapstructure:"logging"`
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

type APIConfig struct {
	Address string `mapstructure:"address"`
}

type MetricsConfig struct {
	Address string `mapstructure:"address"`
	Path    string `mapstructure:"path"`
}

type LoggingConfig struct {
	Level string `mapstructure:"level"`
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
