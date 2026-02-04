package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"router-go/api"
	"router-go/internal/config"
	"router-go/internal/logger"
	"router-go/internal/metrics"
	"router-go/internal/platform"
	"router-go/pkg/firewall"
	"router-go/pkg/enrich"
	"router-go/pkg/flow"
	"router-go/pkg/ids"
	"router-go/pkg/integrations/logs"
	"router-go/pkg/nat"
	"router-go/pkg/network"
	"router-go/pkg/p2p"
	"router-go/pkg/proxy"
	"router-go/pkg/qos"
	"router-go/pkg/routing"

	"github.com/gin-gonic/gin"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		panic(err)
	}

	log := logger.New(cfg.Logging.Level)
	if cfg.Integrations.Logs.Enabled {
		if hook := logs.NewLokiHook(cfg.Integrations.Logs.LokiURL); hook != nil {
			log.AddHook(hook)
		}
		if hook := logs.NewElasticHook(cfg.Integrations.Logs.ElasticURL); hook != nil {
			log.AddHook(hook)
		}
	}
	log.Info("config loaded", map[string]any{"path": *configPath})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	metricsSrv := metrics.New()
	go func() {
		if err := metrics.StartServer(ctx, cfg.Metrics); err != nil {
			log.Error("metrics server error", map[string]any{"err": err.Error()})
		}
	}()
	metrics.StartRemoteWrite(ctx, cfg.Integrations.Metrics, metricsSrv)

	routeTable := buildRoutes(cfg, log)
	firewallEngine := buildFirewall(cfg, log)
	idsEngine := buildIDS(cfg)
	natTable := buildNAT(cfg, log)
	qosQueue := buildQoSQueue(cfg)
	cfgManager := config.NewManager(cfg, config.DefaultHealthCheck)
	flowEngine := flow.NewEngine()
	p2pEngine := buildP2P(cfg, routeTable, metricsSrv, log, ctx)
	proxyEngine := buildProxy(cfg, metricsSrv, log, ctx)
	enrichSvc := buildEnrichService(cfg, log)

	router := gin.New()
	router.Use(gin.Recovery())
	if cfg.Dashboard.Enabled {
		router.Static("/dashboard", cfg.Dashboard.StaticDir)
	}
	handlers := &api.Handlers{
		Routes:    routeTable,
		Firewall:  firewallEngine,
		IDS:       idsEngine,
		NAT:       natTable,
		QoS:       qosQueue,
		Flow:      flowEngine,
		P2P:       p2pEngine,
		Proxy:     proxyEngine,
		Enrich:    enrichSvc,
		EnrichTimeout: time.Duration(cfg.Integrations.TimeoutSeconds) * time.Second,
		Security:  &cfg.Security,
		Log:       log,
		ConfigMgr: cfgManager,
		Metrics:   metricsSrv,
	}
	api.RegisterRoutes(router, handlers)

	go func() {
		if err := runAPIServer(ctx, router, cfg, log); err != nil {
			log.Error("api server error", map[string]any{"err": err.Error()})
		}
	}()

	startPacketLoop(ctx, cfg, log, metricsSrv, routeTable, firewallEngine, idsEngine, natTable, qosQueue, flowEngine)
	<-ctx.Done()
	log.Info("shutdown", nil)
}

func startPacketLoop(
	ctx context.Context,
	cfg *config.Config,
	log *logger.Logger,
	metricsSrv *metrics.Metrics,
	routes *routing.Table,
	firewallEngine *firewall.Engine,
	idsEngine *ids.Engine,
	natTable *nat.Table,
	qosQueue *qos.QueueManager,
	flowEngine *flow.Engine,
) {
	if len(cfg.Interfaces) == 0 {
		log.Warn("no interfaces configured", nil)
		return
	}

	localIPs := buildLocalIPs(cfg)
	io, err := platform.NewPacketIO(platform.Options{Interface: cfg.Interfaces[0]})
	if err != nil {
		log.Warn("packet io unavailable", map[string]any{"err": err.Error()})
		return
	}

	go runEgressLoop(ctx, io, qosQueue, log, metricsSrv)

	go func() {
		defer io.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			pkt, err := io.ReadPacket(ctx)
			if err != nil {
				metricsSrv.IncErrors()
				continue
			}
			metricsSrv.IncRxPackets()

			meta, err := network.ParseIPMetadata(pkt.Data)
			if err != nil {
				metricsSrv.IncErrors()
				metricsSrv.IncDropReason("parse")
				continue
			}
			pkt.Metadata = meta

			metricsSrv.IncPackets()
			metricsSrv.AddBytes(len(pkt.Data))
			processPacket(pkt, localIPs, routes, firewallEngine, idsEngine, natTable, qosQueue, metricsSrv, flowEngine)
		}
	}()
}

func processPacket(
	pkt network.Packet,
	localIPs []net.IP,
	routes *routing.Table,
	firewallEngine *firewall.Engine,
	idsEngine *ids.Engine,
	natTable *nat.Table,
	qosQueue *qos.QueueManager,
	metricsSrv *metrics.Metrics,
	flowEngine *flow.Engine,
) {
	_, _ = routes.Lookup(pkt.Metadata.DstIP)
	if flowEngine != nil {
		flowEngine.AddPacket(pkt)
	}
	if idsEngine != nil {
		res := idsEngine.Detect(pkt)
		if res.Alert != nil {
			metricsSrv.IncIDSAlert()
			metricsSrv.IncIDSAlertType(res.Alert.Type)
			metricsSrv.IncIDSAlertRule(res.Alert.Reason)
		}
		if res.Drop {
			metricsSrv.IncIDSDrop()
			metricsSrv.IncDropReason("ids")
			return
		}
	}
	pkt = natTable.Apply(pkt)
	chain := determineChain(pkt, localIPs)
	if firewallEngine.Evaluate(chain, pkt) != firewall.ActionAccept {
		metricsSrv.IncDropReason("firewall")
		return
	}
	if qosQueue == nil {
		return
	}
	ok, dropped, className := qosQueue.Enqueue(pkt)
	if dropped {
		metricsSrv.IncQoSDrop(className)
	}
	if !ok {
		return
	}
}

func runEgressLoop(ctx context.Context, io network.PacketIO, qosQueue *qos.QueueManager, log *logger.Logger, metricsSrv *metrics.Metrics) {
	if qosQueue == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if ok := dequeueAndWrite(qosQueue, io, metricsSrv); !ok {
			time.Sleep(2 * time.Millisecond)
		}
	}
}

func dequeueAndWrite(qosQueue *qos.QueueManager, io network.PacketIO, metricsSrv *metrics.Metrics) bool {
	pkt, ok := qosQueue.Dequeue()
	if !ok {
		return false
	}
	_ = io.WritePacket(context.Background(), pkt)
	if metricsSrv != nil {
		metricsSrv.IncTxPackets()
	}
	return true
}

func buildRoutes(cfg *config.Config, log *logger.Logger) *routing.Table {
	table := routing.NewTable(nil)
	for _, rc := range cfg.Routes {
		_, dst, err := net.ParseCIDR(rc.Destination)
		if err != nil {
			log.Warn("invalid route destination", map[string]any{"destination": rc.Destination})
			continue
		}
		gw := net.ParseIP(rc.Gateway)
		table.Add(routing.Route{
			Destination: *dst,
			Gateway:     gw,
			Interface:   rc.Interface,
			Metric:      rc.Metric,
		})
	}
	return table
}

func buildFirewall(cfg *config.Config, log *logger.Logger) *firewall.Engine {
	var rules []firewall.Rule
	for _, rc := range cfg.Firewall {
		var srcNet *net.IPNet
		if rc.SrcIP != "" {
			_, parsed, err := net.ParseCIDR(rc.SrcIP)
			if err != nil {
				log.Warn("invalid firewall src_ip", map[string]any{"src_ip": rc.SrcIP})
				continue
			}
			srcNet = parsed
		}

		var dstNet *net.IPNet
		if rc.DstIP != "" {
			_, parsed, err := net.ParseCIDR(rc.DstIP)
			if err != nil {
				log.Warn("invalid firewall dst_ip", map[string]any{"dst_ip": rc.DstIP})
				continue
			}
			dstNet = parsed
		}

		rules = append(rules, firewall.Rule{
			Chain:        rc.Chain,
			Action:       firewall.Action(rc.Action),
			Protocol:     rc.Protocol,
			SrcNet:       srcNet,
			DstNet:       dstNet,
			SrcPort:      rc.SrcPort,
			DstPort:      rc.DstPort,
			InInterface:  rc.InInterface,
			OutInterface: rc.OutInterface,
		})
	}
	defaults := map[string]firewall.Action{
		"INPUT":   parseFirewallAction(cfg.FirewallDefaults.Input, firewall.ActionDrop),
		"OUTPUT":  parseFirewallAction(cfg.FirewallDefaults.Output, firewall.ActionDrop),
		"FORWARD": parseFirewallAction(cfg.FirewallDefaults.Forward, firewall.ActionDrop),
	}
	return firewall.NewEngineWithDefaults(rules, defaults)
}

func buildNAT(cfg *config.Config, log *logger.Logger) *nat.Table {
	var rules []nat.Rule
	for _, rc := range cfg.NAT {
		var srcNet *net.IPNet
		if rc.SrcIP != "" {
			_, parsed, err := net.ParseCIDR(rc.SrcIP)
			if err != nil {
				log.Warn("invalid nat src_ip", map[string]any{"src_ip": rc.SrcIP})
				continue
			}
			srcNet = parsed
		}

		var dstNet *net.IPNet
		if rc.DstIP != "" {
			_, parsed, err := net.ParseCIDR(rc.DstIP)
			if err != nil {
				log.Warn("invalid nat dst_ip", map[string]any{"dst_ip": rc.DstIP})
				continue
			}
			dstNet = parsed
		}

		rules = append(rules, nat.Rule{
			Type:    nat.Type(rc.Type),
			SrcNet:  srcNet,
			DstNet:  dstNet,
			SrcPort: rc.SrcPort,
			DstPort: rc.DstPort,
			ToIP:    net.ParseIP(rc.ToIP),
			ToPort:  rc.ToPort,
		})
	}
	return nat.NewTable(rules)
}

func buildQoSQueue(cfg *config.Config) *qos.QueueManager {
	classes := make([]qos.Class, 0, len(cfg.QoS))
	for _, qc := range cfg.QoS {
		classes = append(classes, qos.Class{
			Name:          qc.Name,
			Protocol:      qc.Protocol,
			SrcPort:       qc.SrcPort,
			DstPort:       qc.DstPort,
			RateLimitKbps: qc.RateLimitKbps,
			Priority:      qc.Priority,
			MaxQueue:      qc.MaxQueue,
			DropPolicy:    qc.DropPolicy,
		})
	}
	return qos.NewQueueManager(classes)
}

func parseFirewallAction(value string, fallback firewall.Action) firewall.Action {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case string(firewall.ActionAccept):
		return firewall.ActionAccept
	case string(firewall.ActionDrop):
		return firewall.ActionDrop
	case string(firewall.ActionReject):
		return firewall.ActionReject
	default:
		return fallback
	}
}

func buildIDS(cfg *config.Config) *ids.Engine {
	if !cfg.IDS.Enabled {
		return nil
	}
	action := ids.Action(strings.ToUpper(strings.TrimSpace(cfg.IDS.BehaviorAction)))
	return ids.NewEngine(ids.Config{
		Window:             time.Duration(cfg.IDS.WindowSeconds) * time.Second,
		RateThreshold:      cfg.IDS.RateThreshold,
		PortScanThreshold:  cfg.IDS.PortScanThreshold,
		UniqueDstThreshold: cfg.IDS.UniqueDstThreshold,
		BehaviorAction:     action,
		AlertLimit:         cfg.IDS.AlertLimit,
		WhitelistSrc:       parseCIDRs(cfg.IDS.WhitelistSrc),
		WhitelistDst:       parseCIDRs(cfg.IDS.WhitelistDst),
	})
}

func buildP2P(cfg *config.Config, table *routing.Table, metricsSrv *metrics.Metrics, log *logger.Logger, ctx context.Context) *p2p.Engine {
	if !cfg.P2P.Enabled {
		return nil
	}
	pubKey, privKey := loadP2PKeys(cfg.P2P.PublicKeyFile, cfg.P2P.PrivateKeyFile, log)
	engine := p2p.NewEngine(p2p.Config{
		PeerID:        cfg.P2P.PeerID,
		Discovery:     cfg.P2P.Discovery,
		SyncInterval:  time.Duration(cfg.P2P.SyncInterval) * time.Second,
		PeerTTL:       time.Duration(cfg.P2P.PeerTTLSeconds) * time.Second,
		ListenAddr:    cfg.P2P.ListenAddr,
		MulticastAddr: cfg.P2P.MulticastAddr,
		PublicKey:     pubKey,
		PrivateKey:    privKey,
	}, table, nil, metricsSrv.IncP2PPeer, metricsSrv.IncP2PRouteSynced)

	if err := engine.Start(ctx); err != nil {
		log.Warn("p2p start failed", map[string]any{"err": err.Error()})
	}
	return engine
}

func buildProxy(cfg *config.Config, metricsSrv *metrics.Metrics, log *logger.Logger, ctx context.Context) *proxy.Proxy {
	if !cfg.Proxy.Enabled {
		return nil
	}
	engine, err := proxy.NewProxy(proxy.Config{
		ListenAddr:      cfg.Proxy.ListenAddr,
		H3Addr:          cfg.Proxy.H3Addr,
		Upstream:        cfg.Proxy.Upstream,
		CacheSize:       cfg.Proxy.CacheSize,
		CacheTTLSeconds: cfg.Proxy.CacheTTLSeconds,
		EnableGzip:      cfg.Proxy.EnableGzip,
		EnableBrotli:    cfg.Proxy.EnableBrotli,
		EnableH3:        cfg.Proxy.EnableH3,
		HSTS:            cfg.Proxy.HSTS,
		CertFile:        cfg.Proxy.CertFile,
		KeyFile:         cfg.Proxy.KeyFile,
	})
	if err != nil {
		log.Warn("proxy init failed", map[string]any{"err": err.Error()})
		return nil
	}
	engine.SetCallbacks(metricsSrv.IncProxyCacheHit, metricsSrv.IncProxyCacheMiss, metricsSrv.IncProxyCompress)

	go func() {
		if err := proxy.StartHTTPServer(ctx, cfg.Proxy.ListenAddr, engine); err != nil {
			log.Warn("proxy http server error", map[string]any{"err": err.Error()})
		}
	}()
	if cfg.Proxy.EnableH3 {
		go func() {
			if cfg.Proxy.CertFile == "" || cfg.Proxy.KeyFile == "" {
				log.Warn("proxy h3 cert/key missing", nil)
				return
			}
			if err := proxy.StartHTTP3Server(ctx, cfg.Proxy.H3Addr, cfg.Proxy.CertFile, cfg.Proxy.KeyFile, engine); err != nil {
				log.Warn("proxy h3 server error", map[string]any{"err": err.Error()})
			}
		}()
	}
	return engine
}

func buildEnrichService(cfg *config.Config, log *logger.Logger) *enrich.Service {
	timeout := time.Duration(cfg.Integrations.TimeoutSeconds) * time.Second
	var geoProvider enrich.Provider
	if cfg.Integrations.GeoIP.Enabled {
		if cfg.Integrations.GeoIP.MMDBPath != "" {
			if db, err := enrich.NewGeoIPMMDB(cfg.Integrations.GeoIP.MMDBPath); err == nil {
				geoProvider = db
			} else {
				log.Warn("geoip mmdb load failed", map[string]any{"err": err.Error()})
			}
		}
		if geoProvider == nil && cfg.Integrations.GeoIP.HTTPURL != "" {
			geoProvider = enrich.NewGeoIPHTTP(cfg.Integrations.GeoIP.HTTPURL, cfg.Integrations.GeoIP.HTTPToken, timeout)
		}
	}
	var asnProvider enrich.Provider
	if cfg.Integrations.ASN.Enabled {
		asnProvider = enrich.NewASNIPInfo(cfg.Integrations.ASN.Token, timeout)
	}
	var threatProvider enrich.Provider
	if cfg.Integrations.ThreatIntel.Enabled {
		threatProvider = enrich.NewThreatAbuseIPDB(cfg.Integrations.ThreatIntel.APIKey, timeout)
	}
	return enrich.NewService(geoProvider, asnProvider, threatProvider, 2*time.Minute)
}

func runAPIServer(ctx context.Context, router *gin.Engine, cfg *config.Config, log *logger.Logger) error {
	server := &http.Server{
		Addr:    cfg.API.Address,
		Handler: router,
	}
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()
	if cfg.Security.TLS.Enabled {
		tlsConfig, err := loadTLSConfig(cfg.Security.TLS, log)
		if err != nil {
			return err
		}
		server.TLSConfig = tlsConfig
		return server.ListenAndServeTLS(cfg.Security.TLS.CertFile, cfg.Security.TLS.KeyFile)
	}
	return server.ListenAndServe()
}

func loadTLSConfig(cfg config.TLSConfig, log *logger.Logger) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.ClientCAFile != "" {
		data, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("invalid client CA")
		}
		tlsConfig.ClientCAs = pool
		if cfg.RequireClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if log != nil && cfg.RequireClientCert {
		log.Info("mTLS enabled", map[string]any{"client_ca": cfg.ClientCAFile})
	}
	return tlsConfig, nil
}

func buildLocalIPs(cfg *config.Config) []net.IP {
	out := make([]net.IP, 0, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		ip, _, err := net.ParseCIDR(iface.IP)
		if err != nil {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func determineChain(pkt network.Packet, localIPs []net.IP) string {
	if isLocalIP(pkt.Metadata.DstIP, localIPs) {
		return "INPUT"
	}
	if isLocalIP(pkt.Metadata.SrcIP, localIPs) {
		return "OUTPUT"
	}
	return "FORWARD"
}

func isLocalIP(ip net.IP, localIPs []net.IP) bool {
	for _, local := range localIPs {
		if ip != nil && ip.Equal(local) {
			return true
		}
	}
	return false
}

func parseCIDRs(values []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, netw, err := net.ParseCIDR(value)
		if err != nil {
			continue
		}
		out = append(out, netw)
	}
	return out
}

func loadP2PKeys(pubPath string, privPath string, log *logger.Logger) (ed25519.PublicKey, ed25519.PrivateKey) {
	if pubPath == "" || privPath == "" {
		return nil, nil
	}
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		log.Warn("p2p public key read failed", map[string]any{"err": err.Error()})
		return nil, nil
	}
	privData, err := os.ReadFile(privPath)
	if err != nil {
		log.Warn("p2p private key read failed", map[string]any{"err": err.Error()})
		return nil, nil
	}
	pubRaw, err := hex.DecodeString(strings.TrimSpace(string(pubData)))
	if err != nil {
		log.Warn("p2p public key decode failed", map[string]any{"err": err.Error()})
		return nil, nil
	}
	privRaw, err := hex.DecodeString(strings.TrimSpace(string(privData)))
	if err != nil {
		log.Warn("p2p private key decode failed", map[string]any{"err": err.Error()})
		return nil, nil
	}
	return ed25519.PublicKey(pubRaw), ed25519.PrivateKey(privRaw)
}
