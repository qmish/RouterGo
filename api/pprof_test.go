package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRegisterPprof(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	RegisterPprof(router, "/debug/pprof")

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "profile") {
		t.Fatalf("expected pprof index content")
	}
}
