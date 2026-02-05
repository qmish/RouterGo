package metrics

import (
	"context"
	"testing"

	"router-go/internal/config"
)

func TestStartServerInvalidAddr(t *testing.T) {
	cfg := config.MetricsConfig{
		Address: "bad:addr",
		Path:    "/metrics",
	}
	if err := StartServer(context.Background(), cfg); err == nil {
		t.Fatalf("expected error for invalid address")
	}
}
