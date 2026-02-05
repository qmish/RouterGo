package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) GetTraces(c *gin.Context) {
	if h.Observability == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "observability disabled"})
		return
	}
	c.JSON(http.StatusOK, h.Observability.List())
}

func (h *Handlers) GetAlerts(c *gin.Context) {
	if h.Alerts == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "alerts disabled"})
		return
	}
	c.JSON(http.StatusOK, h.Alerts.List())
}
