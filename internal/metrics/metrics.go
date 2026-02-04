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
	PacketsTotal prometheus.Counter
	BytesTotal   prometheus.Counter
	ErrorsTotal  prometheus.Counter
	DropsTotal   prometheus.Counter
	DropsByReason *prometheus.CounterVec
	packetsCount atomic.Uint64
	bytesCount   atomic.Uint64
	errorsCount  atomic.Uint64
	dropsCount   atomic.Uint64
	mu           sync.Mutex
	dropsByReason map[string]uint64
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
		dropsByReason: map[string]uint64{},
	}
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	reg.MustRegister(m.PacketsTotal, m.BytesTotal, m.ErrorsTotal, m.DropsTotal, m.DropsByReason)
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

type Snapshot struct {
	Packets uint64
	Bytes   uint64
	Errors  uint64
	Drops   uint64
	DropsByReason map[string]uint64
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	reasons := make(map[string]uint64, len(m.dropsByReason))
	for k, v := range m.dropsByReason {
		reasons[k] = v
	}
	m.mu.Unlock()
	return Snapshot{
		Packets:       m.packetsCount.Load(),
		Bytes:         m.bytesCount.Load(),
		Errors:        m.errorsCount.Load(),
		Drops:         m.dropsCount.Load(),
		DropsByReason: reasons,
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
