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
	PacketsTotal    prometheus.Counter
	BytesTotal      prometheus.Counter
	ErrorsTotal     prometheus.Counter
	DropsTotal      prometheus.Counter
	DropsByReason   *prometheus.CounterVec
	QoSDropsByClass *prometheus.CounterVec
	RxPacketsTotal  prometheus.Counter
	TxPacketsTotal  prometheus.Counter
	IDSAlertsTotal  prometheus.Counter
	IDSDropsTotal   prometheus.Counter
	packetsCount    atomic.Uint64
	bytesCount      atomic.Uint64
	errorsCount     atomic.Uint64
	dropsCount      atomic.Uint64
	rxPacketsCount  atomic.Uint64
	txPacketsCount  atomic.Uint64
	idsAlertsCount  atomic.Uint64
	idsDropsCount   atomic.Uint64
	mu              sync.Mutex
	dropsByReason   map[string]uint64
	qosDropsByClass map[string]uint64
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

type Snapshot struct {
	Packets         uint64
	Bytes           uint64
	Errors          uint64
	Drops           uint64
	DropsByReason   map[string]uint64
	QoSDropsByClass map[string]uint64
	RxPackets       uint64
	TxPackets       uint64
	IDSAlerts       uint64
	IDSDrops        uint64
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
		Packets:         m.packetsCount.Load(),
		Bytes:           m.bytesCount.Load(),
		Errors:          m.errorsCount.Load(),
		Drops:           m.dropsCount.Load(),
		DropsByReason:   reasons,
		QoSDropsByClass: qosDrops,
		RxPackets:       m.rxPacketsCount.Load(),
		TxPackets:       m.txPacketsCount.Load(),
		IDSAlerts:       m.idsAlertsCount.Load(),
		IDSDrops:        m.idsDropsCount.Load(),
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
