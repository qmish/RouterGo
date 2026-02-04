package main

import (
	"context"
	"flag"
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
	"router-go/pkg/nat"
	"router-go/pkg/network"
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
	log.Info("config loaded", map[string]any{"path": *configPath})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	metricsSrv := metrics.New()
	go func() {
		if err := metrics.StartServer(ctx, cfg.Metrics); err != nil {
			log.Error("metrics server error", map[string]any{"err": err.Error()})
		}
	}()

	routeTable := buildRoutes(cfg, log)
	firewallEngine := buildFirewall(cfg, log)
	natTable := buildNAT(cfg, log)
	qosQueue := buildQoSQueue(cfg)

	router := gin.New()
	router.Use(gin.Recovery())
	handlers := &api.Handlers{
		Routes:   routeTable,
		Firewall: firewallEngine,
		NAT:      natTable,
		QoS:      qosQueue,
		Metrics:  metricsSrv,
	}
	api.RegisterRoutes(router, handlers)

	go func() {
		if err := router.Run(cfg.API.Address); err != nil {
			log.Error("api server error", map[string]any{"err": err.Error()})
		}
	}()

	startPacketLoop(ctx, cfg, log, metricsSrv, routeTable, firewallEngine, natTable, qosQueue)
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
	natTable *nat.Table,
	qosQueue *qos.QueueManager,
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

	go runEgressLoop(ctx, io, qosQueue, log)

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

			meta, err := network.ParseIPMetadata(pkt.Data)
			if err != nil {
				metricsSrv.IncErrors()
				continue
			}
			pkt.Metadata = meta

			metricsSrv.IncPackets()
			metricsSrv.AddBytes(len(pkt.Data))
			processPacket(pkt, localIPs, routes, firewallEngine, natTable, qosQueue)
		}
	}()
}

func processPacket(
	pkt network.Packet,
	localIPs []net.IP,
	routes *routing.Table,
	firewallEngine *firewall.Engine,
	natTable *nat.Table,
	qosQueue *qos.QueueManager,
) {
	_, _ = routes.Lookup(pkt.Metadata.DstIP)
	pkt = natTable.Apply(pkt)
	chain := determineChain(pkt, localIPs)
	if firewallEngine.Evaluate(chain, pkt) != firewall.ActionAccept {
		return
	}
	if qosQueue == nil {
		return
	}
	qosQueue.Enqueue(pkt)
}

func runEgressLoop(ctx context.Context, io network.PacketIO, qosQueue *qos.QueueManager, log *logger.Logger) {
	if qosQueue == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if ok := dequeueAndWrite(qosQueue, io); !ok {
			time.Sleep(2 * time.Millisecond)
		}
	}
}

func dequeueAndWrite(qosQueue *qos.QueueManager, io network.PacketIO) bool {
	pkt, ok := qosQueue.Dequeue()
	if !ok {
		return false
	}
	_ = io.WritePacket(context.Background(), pkt)
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
