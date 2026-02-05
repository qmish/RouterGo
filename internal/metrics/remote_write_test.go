package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"router-go/internal/config"

	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/prompb"
)

func TestSendSnapshotRemoteWrite(t *testing.T) {
	got := make(chan *prompb.WriteRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if r.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Fatalf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Content-Encoding") != "snappy" {
			t.Fatalf("unexpected content-encoding: %s", r.Header.Get("Content-Encoding"))
		}
		raw, err := snappy.Decode(nil, body)
		if err != nil {
			t.Fatalf("snappy decode: %v", err)
		}
		var req prompb.WriteRequest
		if err := req.Unmarshal(raw); err != nil {
			t.Fatalf("unmarshal write request: %v", err)
		}
		got <- &req
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second}
	sendSnapshot(context.Background(), client, server.URL, Snapshot{
		Packets:        1,
		Bytes:          2,
		Drops:          3,
		IDSAlerts:      4,
		ProxyCacheHits: 5,
	})

	select {
	case req := <-got:
		if len(req.Timeseries) != 5 {
			t.Fatalf("expected 5 series, got %d", len(req.Timeseries))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for remote write")
	}
}

func TestStartRemoteWriteSends(t *testing.T) {
	got := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.MetricsExportConfig{
		Enabled:        true,
		RemoteWriteURL: server.URL,
		IntervalSeconds: 1,
	}
	StartRemoteWrite(ctx, cfg, NewWithRegistry(prometheus.NewRegistry()))

	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected remote write call")
	}
}

func TestStartRemoteWriteDisabled(t *testing.T) {
	got := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.MetricsExportConfig{
		Enabled:        false,
		RemoteWriteURL: server.URL,
		IntervalSeconds: 1,
	}
	StartRemoteWrite(ctx, cfg, NewWithRegistry(prometheus.NewRegistry()))

	select {
	case <-got:
		t.Fatalf("expected no remote write when disabled")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNewSeries(t *testing.T) {
	series := newSeries("router_packets_total", 42, 123)
	if len(series.Labels) != 1 || series.Labels[0].Value != "router_packets_total" {
		t.Fatalf("unexpected labels: %+v", series.Labels)
	}
	if len(series.Samples) != 1 || series.Samples[0].Value != 42 || series.Samples[0].Timestamp != 123 {
		t.Fatalf("unexpected samples: %+v", series.Samples)
	}
}

