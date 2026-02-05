package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"router-go/internal/config"
	"router-go/internal/logger"

	"github.com/gin-gonic/gin"
)

func TestRoleAllowed(t *testing.T) {
	tests := []struct {
		actual   string
		required string
		want     bool
	}{
		{"admin", "read", true},
		{"ops", "read", true},
		{"read", "ops", false},
		{"read", "read", true},
		{"ops", "admin", false},
		{"ADMIN", "read", true},
		{"unknown", "read", false},
	}

	for _, tc := range tests {
		if got := roleAllowed(tc.actual, tc.required); got != tc.want {
			t.Fatalf("roleAllowed(%q,%q)=%v, want %v", tc.actual, tc.required, got, tc.want)
		}
	}
}

func TestAuthMiddlewareDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.SecurityConfig{Enabled: false, RequireAuth: false}
	r := gin.New()
	r.Use(AuthMiddleware(cfg, nil))
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(200, gin.H{"role": c.GetString("role")})
	})

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddlewareMissingTokens(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.SecurityConfig{Enabled: true, RequireAuth: true}
	r := gin.New()
	r.Use(AuthMiddleware(cfg, nil))
	r.GET("/ok", func(c *gin.Context) { c.Status(200) })

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

func TestAuthMiddlewareAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.SecurityConfig{
		Enabled:     true,
		RequireAuth: true,
		Tokens: []config.TokenConfig{
			{Role: "ops", Value: "token-ops"},
		},
	}
	r := gin.New()
	r.Use(AuthMiddleware(cfg, nil))
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(200, gin.H{"role": c.GetString("role")})
	})

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("X-API-Key", "token-ops")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddlewareBearerToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.SecurityConfig{
		Enabled:     true,
		RequireAuth: true,
		Tokens: []config.TokenConfig{
			{Role: "admin", Value: "token-admin"},
		},
	}
	r := gin.New()
	r.Use(AuthMiddleware(cfg, nil))
	r.GET("/ok", func(c *gin.Context) { c.Status(200) })

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("Authorization", "Bearer token-admin")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestAuthMiddlewareSHA256Token(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sum := sha256.Sum256([]byte("secret-token"))
	cfg := config.SecurityConfig{
		Enabled:     true,
		RequireAuth: true,
		Tokens: []config.TokenConfig{
			{Role: "admin", Value: "sha256:" + hex.EncodeToString(sum[:])},
		},
	}
	r := gin.New()
	r.Use(AuthMiddleware(cfg, nil))
	r.GET("/ok", func(c *gin.Context) { c.Status(200) })

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("X-API-Key", "secret-token")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestRequireRoleForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("role", "read")
		c.Next()
	})
	r.Use(RequireRole(roleOps))
	r.GET("/ok", func(c *gin.Context) { c.Status(200) })

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestAuditMiddlewareLogsNonGet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.New("info")
	ch := make(chan map[string]any, 1)
	log.AddHook(func(entry map[string]any) { ch <- entry })

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("role", "ops")
		c.Next()
	})
	r.Use(AuditMiddleware(log))
	r.POST("/ok", func(c *gin.Context) { c.Status(201) })

	req := httptest.NewRequest(http.MethodPost, "/ok", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	select {
	case entry := <-ch:
		if entry["method"] != http.MethodPost {
			t.Fatalf("expected method POST, got %v", entry["method"])
		}
		if entry["path"] != "/ok" {
			t.Fatalf("expected path /ok, got %v", entry["path"])
		}
		switch v := entry["status"].(type) {
		case int:
			if v != 201 {
				t.Fatalf("expected status 201, got %v", entry["status"])
			}
		case float64:
			if v != 201 {
				t.Fatalf("expected status 201, got %v", entry["status"])
			}
		default:
			t.Fatalf("expected status 201, got %v", entry["status"])
		}
		if entry["role"] != "ops" {
			t.Fatalf("expected role ops, got %v", entry["role"])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected audit hook call")
	}
}
