package api

import (
	"io"
	"net/http"
	"strings"

	"router-go/internal/presets"

	"github.com/gin-gonic/gin"
)

func (h *Handlers) GetPresets(c *gin.Context) {
	if h.Presets == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "presets not configured"})
		return
	}
	c.JSON(http.StatusOK, h.Presets.List())
}

func (h *Handlers) GetPreset(c *gin.Context) {
	if h.Presets == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "presets not configured"})
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	preset, ok := h.Presets.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "preset not found"})
		return
	}
	c.JSON(http.StatusOK, preset)
}

func (h *Handlers) PreviewPreset(c *gin.Context) {
	preset, ok := h.getPresetOrFail(c)
	if !ok {
		return
	}
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager not configured"})
		return
	}
	var req presetApplyRequest
	if err := c.ShouldBindJSON(&req); err != nil && err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	next, summary, err := presets.ApplyPresetWithOverrides(h.ConfigMgr.Current(), preset, req.Overrides)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"preset":  preset,
		"summary": summary,
		"config": next,
	})
}

func (h *Handlers) ApplyPreset(c *gin.Context) {
	preset, ok := h.getPresetOrFail(c)
	if !ok {
		return
	}
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager not configured"})
		return
	}
	var req presetApplyRequest
	if err := c.ShouldBindJSON(&req); err != nil && err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	next, summary, err := presets.ApplyPresetWithOverrides(h.ConfigMgr.Current(), preset, req.Overrides)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.ConfigMgr.Apply(next); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "summary": summary})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "summary": summary})
}

func (h *Handlers) CreatePreset(c *gin.Context) {
	if h.Presets == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "presets not configured"})
		return
	}
	var req presets.Preset
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if err := h.Presets.Save(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"status": "ok", "id": req.ID})
}

func (h *Handlers) ImportPresets(c *gin.Context) {
	if h.Presets == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "presets not configured"})
		return
	}
	var req []presets.Preset
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	updated, err := h.Presets.Import(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "updated": updated})
}

func (h *Handlers) UpdatePresets(c *gin.Context) {
	if h.Presets == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "presets not configured"})
		return
	}
	if h.ConfigMgr == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config manager not configured"})
		return
	}
	url := h.ConfigMgr.Current().Presets.UpdateURL
	updated, err := h.Presets.UpdateFromURL(url)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "updated": updated})
}

func (h *Handlers) getPresetOrFail(c *gin.Context) (presets.Preset, bool) {
	if h.Presets == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "presets not configured"})
		return presets.Preset{}, false
	}
	id := strings.TrimSpace(c.Param("id"))
	preset, ok := h.Presets.Get(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "preset not found"})
		return presets.Preset{}, false
	}
	return preset, true
}

type presetApplyRequest struct {
	Overrides presets.Overrides `json:"overrides"`
}
