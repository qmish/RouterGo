package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"router-go/internal/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	PacketsTotal           prometheus.Counter
	BytesTotal             prometheus.Counter
	ErrorsTotal            prometheus.Counter
	DropsTotal             prometheus.Counter
	DropsByReason          *prometheus.CounterVec
	QoSDropsByClass        *prometheus.CounterVec
	RxPacketsTotal         prometheus.Counter
	TxPacketsTotal         prometheus.Counter
	IDSAlertsTotal         prometheus.Counter
	IDSDropsTotal          prometheus.Counter
	ConfigApplyTotal       prometheus.Counter
	ConfigRollbackTotal    prometheus.Counter
	ConfigApplyFailedTotal prometheus.Counter
	P2PPeersTotal          prometheus.Counter
	P2PRoutesSyncedTotal   prometheus.Counter
	ProxyCacheHitsTotal    prometheus.Counter
	ProxyCacheMissTotal    prometheus.Counter
	ProxyCompressTotal     prometheus.Counter
	packetsCount           atomic.Uint64
	bytesCount             atomic.Uint64
	errorsCount            atomic.Uint64
	dropsCount             atomic.Uint64
	rxPacketsCount         atomic.Uint64
	txPacketsCount         atomic.Uint64
	idsAlertsCount         atomic.Uint64
	idsDropsCount          atomic.Uint64
	configApplyCount       atomic.Uint64
	configRollbackCount    atomic.Uint64
	configApplyFailedCount atomic.Uint64
	p2pPeersCount          atomic.Uint64
	p2pRoutesSyncedCount   atomic.Uint64
	proxyCacheHitsCount    atomic.Uint64
	proxyCacheMissCount    atomic.Uint64
	proxyCompressCount     atomic.Uint64
	mu                     sync.Mutex
	dropsByReason          map[string]uint64
	qosDropsByClass        map[string]uint64
}

func New() *Metrics {
	return NewWithRegistry(prometheus.DefaultRegisterer)
}

func NewWithRegistry(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		PacketsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_packets_total",
			Help: "Total number of packets processed",
		}),
		BytesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_bytes_total",
			Help: "Total number of bytes processed",
		}),
		ErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_errors_total",
			Help: "Total number of processing errors",
		}),
		DropsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_drops_total",
			Help: "Total number of dropped packets",
		}),
		DropsByReason: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "router_drops_by_reason_total",
			Help: "Dropped packets by reason",
		}, []string{"reason"}),
		QoSDropsByClass: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "router_qos_drops_by_class_total",
			Help: "QoS dropped packets by class",
		}, []string{"class"}),
		RxPacketsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_rx_packets_total",
			Help: "Total number of packets received",
		}),
		TxPacketsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_tx_packets_total",
			Help: "Total number of packets transmitted",
		}),
		IDSAlertsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_ids_alerts_total",
			Help: "Total number of IDS alerts",
		}),
		IDSDropsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_ids_drops_total",
			Help: "Total number of IDS drops",
		}),
		ConfigApplyTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_config_apply_total",
			Help: "Total number of config apply operations",
		}),
		ConfigRollbackTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_config_rollback_total",
			Help: "Total number of config rollbacks",
		}),
		ConfigApplyFailedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_config_apply_failed_total",
			Help: "Total number of failed config applies",
		}),
		P2PPeersTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_p2p_peers_total",
			Help: "Total number of discovered P2P peers",
		}),
		P2PRoutesSyncedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_p2p_routes_synced_total",
			Help: "Total number of P2P routes synced",
		}),
		ProxyCacheHitsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_proxy_cache_hits_total",
			Help: "Total proxy cache hits",
		}),
		ProxyCacheMissTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_proxy_cache_miss_total",
			Help: "Total proxy cache misses",
		}),
		ProxyCompressTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "router_proxy_compress_total",
			Help: "Total proxy compression operations",
		}),
		dropsByReason:   map[string]uint64{},
		qosDropsByClass: map[string]uint64{},
	}
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	reg.MustRegister(
		m.PacketsTotal,
		m.BytesTotal,
		m.ErrorsTotal,
		m.DropsTotal,
		m.DropsByReason,
		m.QoSDropsByClass,
		m.RxPacketsTotal,
		m.TxPacketsTotal,
		m.IDSAlertsTotal,
		m.IDSDropsTotal,
		m.ConfigApplyTotal,
		m.ConfigRollbackTotal,
		m.ConfigApplyFailedTotal,
		m.P2PPeersTotal,
		m.P2PRoutesSyncedTotal,
		m.ProxyCacheHitsTotal,
		m.ProxyCacheMissTotal,
		m.ProxyCompressTotal,
	)
	return m
}

func (m *Metrics) IncPackets() {
	m.packetsCount.Add(1)
	m.PacketsTotal.Inc()
}

func (m *Metrics) AddBytes(n int) {
	if n < 0 {
		return
	}
	m.bytesCount.Add(uint64(n))
	m.BytesTotal.Add(float64(n))
}

func (m *Metrics) IncErrors() {
	m.errorsCount.Add(1)
	m.ErrorsTotal.Inc()
}

func (m *Metrics) IncDrops() {
	m.dropsCount.Add(1)
	m.DropsTotal.Inc()
}

func (m *Metrics) IncDropReason(reason string) {
	if reason == "" {
		return
	}
	m.IncDrops()
	m.DropsByReason.WithLabelValues(reason).Inc()
	m.mu.Lock()
	m.dropsByReason[reason]++
	m.mu.Unlock()
}

func (m *Metrics) IncQoSDrop(class string) {
	if class == "" {
		return
	}
	m.IncDropReason("qos")
	m.QoSDropsByClass.WithLabelValues(class).Inc()
	m.mu.Lock()
	m.qosDropsByClass[class]++
	m.mu.Unlock()
}

func (m *Metrics) IncRxPackets() {
	m.rxPacketsCount.Add(1)
	m.RxPacketsTotal.Inc()
}

func (m *Metrics) IncTxPackets() {
	m.txPacketsCount.Add(1)
	m.TxPacketsTotal.Inc()
}

func (m *Metrics) IncIDSAlert() {
	m.idsAlertsCount.Add(1)
	m.IDSAlertsTotal.Inc()
}

func (m *Metrics) IncIDSDrop() {
	m.idsDropsCount.Add(1)
	m.IDSDropsTotal.Inc()
}

func (m *Metrics) IncConfigApply() {
	m.configApplyCount.Add(1)
	m.ConfigApplyTotal.Inc()
}

func (m *Metrics) IncConfigRollback() {
	m.configRollbackCount.Add(1)
	m.ConfigRollbackTotal.Inc()
}

func (m *Metrics) IncConfigApplyFailed() {
	m.configApplyFailedCount.Add(1)
	m.ConfigApplyFailedTotal.Inc()
}

func (m *Metrics) IncP2PPeer() {
	m.p2pPeersCount.Add(1)
	m.P2PPeersTotal.Inc()
}

func (m *Metrics) IncP2PRouteSynced() {
	m.p2pRoutesSyncedCount.Add(1)
	m.P2PRoutesSyncedTotal.Inc()
}

func (m *Metrics) IncProxyCacheHit() {
	m.proxyCacheHitsCount.Add(1)
	m.ProxyCacheHitsTotal.Inc()
}

func (m *Metrics) IncProxyCacheMiss() {
	m.proxyCacheMissCount.Add(1)
	m.ProxyCacheMissTotal.Inc()
}

func (m *Metrics) IncProxyCompress() {
	m.proxyCompressCount.Add(1)
	m.ProxyCompressTotal.Inc()
}

type Snapshot struct {
	Packets           uint64
	Bytes             uint64
	Errors            uint64
	Drops             uint64
	DropsByReason     map[string]uint64
	QoSDropsByClass   map[string]uint64
	RxPackets         uint64
	TxPackets         uint64
	IDSAlerts         uint64
	IDSDrops          uint64
	ConfigApply       uint64
	ConfigRollback    uint64
	ConfigApplyFailed uint64
	P2PPeers          uint64
	P2PRoutesSynced   uint64
	ProxyCacheHits    uint64
	ProxyCacheMiss    uint64
	ProxyCompress     uint64
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	reasons := make(map[string]uint64, len(m.dropsByReason))
	for k, v := range m.dropsByReason {
		reasons[k] = v
	}
	qosDrops := make(map[string]uint64, len(m.qosDropsByClass))
	for k, v := range m.qosDropsByClass {
		qosDrops[k] = v
	}
	m.mu.Unlock()
	return Snapshot{
		Packets:           m.packetsCount.Load(),
		Bytes:             m.bytesCount.Load(),
		Errors:            m.errorsCount.Load(),
		Drops:             m.dropsCount.Load(),
		DropsByReason:     reasons,
		QoSDropsByClass:   qosDrops,
		RxPackets:         m.rxPacketsCount.Load(),
		TxPackets:         m.txPacketsCount.Load(),
		IDSAlerts:         m.idsAlertsCount.Load(),
		IDSDrops:          m.idsDropsCount.Load(),
		ConfigApply:       m.configApplyCount.Load(),
		ConfigRollback:    m.configRollbackCount.Load(),
		ConfigApplyFailed: m.configApplyFailedCount.Load(),
		P2PPeers:          m.p2pPeersCount.Load(),
		P2PRoutesSynced:   m.p2pRoutesSyncedCount.Load(),
		ProxyCacheHits:    m.proxyCacheHitsCount.Load(),
		ProxyCacheMiss:    m.proxyCacheMissCount.Load(),
		ProxyCompress:     m.proxyCompressCount.Load(),
	}
}

func StartServer(ctx context.Context, cfg config.MetricsConfig) error {
	mux := http.NewServeMux()
	mux.Handle(cfg.Path, promhttp.Handler())

	srv := &http.Server{
		Addr:    cfg.Address,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("metrics server: %w", err)
	}
	return nil
}
