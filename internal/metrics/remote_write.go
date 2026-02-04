package metrics

import (
	"bytes"
	"context"
	"net/http"
	"time"

	"router-go/internal/config"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

func StartRemoteWrite(ctx context.Context, cfg config.MetricsExportConfig, m *Metrics) {
	if !cfg.Enabled || cfg.RemoteWriteURL == "" {
		return
	}
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	client := &http.Client{Timeout: 5 * time.Second}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sendSnapshot(ctx, client, cfg.RemoteWriteURL, m.Snapshot())
			}
		}
	}()
}

func sendSnapshot(ctx context.Context, client *http.Client, url string, snap Snapshot) {
	now := time.Now().UnixMilli()
	series := []prompb.TimeSeries{
		newSeries("router_packets_total", snap.Packets, now),
		newSeries("router_bytes_total", snap.Bytes, now),
		newSeries("router_drops_total", snap.Drops, now),
		newSeries("router_ids_alerts_total", snap.IDSAlerts, now),
		newSeries("router_proxy_cache_hits_total", snap.ProxyCacheHits, now),
	}
	req := &prompb.WriteRequest{Timeseries: series}
	data, err := req.Marshal()
	if err != nil {
		return
	}
	compressed := snappy.Encode(nil, data)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(compressed))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Content-Encoding", "snappy")
	httpReq.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	_, _ = client.Do(httpReq)
}

func newSeries(name string, value uint64, ts int64) prompb.TimeSeries {
	return prompb.TimeSeries{
		Labels: []prompb.Label{{Name: "__name__", Value: name}},
		Samples: []prompb.Sample{{Value: float64(value), Timestamp: ts}},
	}
}
