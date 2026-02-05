package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"router-go/internal/observability"

	"github.com/gin-gonic/gin"
)

func TestTraceMiddlewareGeneratesID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := observability.NewStore(10)
	router := gin.New()
	router.Use(TraceMiddleware(store))
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
	traceID := resp.Header().Get("X-Trace-Id")
	if traceID == "" {
		t.Fatalf("expected trace id header")
	}
	traces := store.List()
	if len(traces) != 1 {
		t.Fatalf("expected 1 trace, got %d", len(traces))
	}
	if traces[0].ID != traceID {
		t.Fatalf("expected trace id %q, got %q", traceID, traces[0].ID)
	}
	if traces[0].Path != "/ping" || traces[0].Method != http.MethodGet {
		t.Fatalf("unexpected trace data: %#v", traces[0])
	}
}

func TestTraceMiddlewareRespectsProvidedID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := observability.NewStore(10)
	router := gin.New()
	router.Use(TraceMiddleware(store))
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Trace-Id", "test-123")
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	traceID := resp.Header().Get("X-Trace-Id")
	if traceID != "test-123" {
		t.Fatalf("expected trace id test-123, got %q", traceID)
	}
	traces := store.List()
	if len(traces) != 1 || traces[0].ID != "test-123" {
		t.Fatalf("unexpected trace data: %#v", traces)
	}
}

func TestGetTraces(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := observability.NewStore(10)
	store.Add(observability.Trace{ID: "t1", Method: "GET", Path: "/x", Status: 200})
	handlers := &Handlers{Observability: store}
	router := gin.New()
	router.GET("/api/observability/traces", handlers.GetTraces)

	req := httptest.NewRequest(http.MethodGet, "/api/observability/traces", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
	var out []observability.Trace
	if err := json.Unmarshal(resp.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(out) != 1 || out[0].ID != "t1" {
		t.Fatalf("unexpected traces: %#v", out)
	}
}

func TestGetTracesDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handlers := &Handlers{}
	router := gin.New()
	router.GET("/api/observability/traces", handlers.GetTraces)

	req := httptest.NewRequest(http.MethodGet, "/api/observability/traces", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", resp.Code)
	}
}
