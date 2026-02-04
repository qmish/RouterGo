package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

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

	io, err := platform.NewPacketIO(platform.Options{Interface: cfg.Interfaces[0]})
	if err != nil {
		log.Warn("packet io unavailable", map[string]any{"err": err.Error()})
		return
	}

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
				metricsSrv.ErrorsTotal.Inc()
				continue
			}

			meta, err := network.ParseIPv4Metadata(pkt.Data)
			if err != nil {
				metricsSrv.ErrorsTotal.Inc()
				continue
			}
			pkt.Metadata = meta

			metricsSrv.PacketsTotal.Inc()
			metricsSrv.BytesTotal.Add(float64(len(pkt.Data)))
			processPacket(pkt, routes, firewallEngine, natTable, qosQueue)
		}
	}()
}

func processPacket(
	pkt network.Packet,
	routes *routing.Table,
	firewallEngine *firewall.Engine,
	natTable *nat.Table,
	qosQueue *qos.QueueManager,
) {
	_, _ = routes.Lookup(pkt.Metadata.DstIP)
	pkt = natTable.Apply(pkt)
	if firewallEngine.Evaluate("FORWARD", pkt) != firewall.ActionAccept {
		return
	}
	if qosQueue == nil {
		return
	}
	qosQueue.Enqueue(pkt)
	_, _ = qosQueue.Dequeue()
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
		"INPUT":   firewall.ActionDrop,
		"OUTPUT":  firewall.ActionDrop,
		"FORWARD": firewall.ActionDrop,
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
		})
	}
	return qos.NewQueueManager(classes)
}
