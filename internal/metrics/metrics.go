package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"

	"router-go/internal/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	PacketsTotal prometheus.Counter
	BytesTotal   prometheus.Counter
	ErrorsTotal  prometheus.Counter
	packetsCount atomic.Uint64
	bytesCount   atomic.Uint64
	errorsCount  atomic.Uint64
}

func New() *Metrics {
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
	}
	prometheus.MustRegister(m.PacketsTotal, m.BytesTotal, m.ErrorsTotal)
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

type Snapshot struct {
	Packets uint64
	Bytes   uint64
	Errors  uint64
}

func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		Packets: m.packetsCount.Load(),
		Bytes:   m.bytesCount.Load(),
		Errors:  m.errorsCount.Load(),
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
