package api

import (
	"net/http"

	"router-go/pkg/ha"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) GetHAStatus(c *gin.Context) {
	if h.HA == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ha disabled"})
		return
	}
	c.JSON(http.StatusOK, h.HA.Status())
}

func (h *Handlers) GetHAState(c *gin.Context) {
	if h.HA == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ha disabled"})
		return
	}
	state := ha.BuildState(h.Firewall, h.NAT, h.QoS, h.Routes)
	c.JSON(http.StatusOK, state)
}

func (h *Handlers) ApplyHAState(c *gin.Context) {
	if h.HA == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "ha disabled"})
		return
	}
	var state ha.State
	if err := c.BindJSON(&state); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	ha.ApplyState(h.Firewall, h.NAT, h.QoS, h.Routes, state)
	if h.HA != nil {
		h.HA.ApplyState(state)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
