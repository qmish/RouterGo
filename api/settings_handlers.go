package api

import (
	"bytes"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type VPNPeer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	LocalCIDR  string `json:"local_cidr"`
	RemoteCIDR string `json:"remote_cidr"`
	Endpoint   string `json:"endpoint"`
	PSK        string `json:"psk,omitempty"`
	Enabled    bool   `json:"enabled"`
}

type DHCPPool struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Subnet       string `json:"subnet"`
	RangeStart   string `json:"range_start"`
	RangeEnd     string `json:"range_end"`
	LeaseSeconds int    `json:"lease_seconds"`
}

func (h *Handlers) GetVPNPeers(c *gin.Context) {
	h.vpnMu.Lock()
	defer h.vpnMu.Unlock()
	out := make([]VPNPeer, 0, len(h.vpnPeers))
	out = append(out, h.vpnPeers...)
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) AddVPNPeer(c *gin.Context) {
	var req VPNPeer
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	if req.ID == "" || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id and name are required"})
		return
	}
	if !validCIDR(req.LocalCIDR) || !validCIDR(req.RemoteCIDR) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid cidr"})
		return
	}
	if strings.TrimSpace(req.Endpoint) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "endpoint is required"})
		return
	}
	h.vpnMu.Lock()
	defer h.vpnMu.Unlock()
	for _, peer := range h.vpnPeers {
		if peer.ID == req.ID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "id already exists"})
			return
		}
	}
	h.vpnPeers = append(h.vpnPeers, req)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) UpdateVPNPeer(c *gin.Context) {
	var req VPNPeer
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	if req.LocalCIDR != "" && !validCIDR(req.LocalCIDR) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid local_cidr"})
		return
	}
	if req.RemoteCIDR != "" && !validCIDR(req.RemoteCIDR) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remote_cidr"})
		return
	}
	h.vpnMu.Lock()
	defer h.vpnMu.Unlock()
	for i, peer := range h.vpnPeers {
		if peer.ID == req.ID {
			if strings.TrimSpace(req.Name) != "" {
				peer.Name = strings.TrimSpace(req.Name)
			}
			if strings.TrimSpace(req.LocalCIDR) != "" {
				peer.LocalCIDR = req.LocalCIDR
			}
			if strings.TrimSpace(req.RemoteCIDR) != "" {
				peer.RemoteCIDR = req.RemoteCIDR
			}
			if strings.TrimSpace(req.Endpoint) != "" {
				peer.Endpoint = strings.TrimSpace(req.Endpoint)
			}
			if req.PSK != "" {
				peer.PSK = req.PSK
			}
			peer.Enabled = req.Enabled
			h.vpnPeers[i] = peer
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "peer not found"})
}

func (h *Handlers) DeleteVPNPeer(c *gin.Context) {
	var req struct {
		ID string `json:"id"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	h.vpnMu.Lock()
	defer h.vpnMu.Unlock()
	for i, peer := range h.vpnPeers {
		if peer.ID == id {
			h.vpnPeers = append(h.vpnPeers[:i], h.vpnPeers[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "peer not found"})
}

func (h *Handlers) GetDHCPPools(c *gin.Context) {
	h.dhcpMu.Lock()
	defer h.dhcpMu.Unlock()
	out := make([]DHCPPool, 0, len(h.dhcpPools))
	out = append(out, h.dhcpPools...)
	c.JSON(http.StatusOK, out)
}

func (h *Handlers) AddDHCPPool(c *gin.Context) {
	var req DHCPPool
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Name = strings.TrimSpace(req.Name)
	if req.ID == "" || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id and name are required"})
		return
	}
	if !validCIDR(req.Subnet) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid subnet"})
		return
	}
	if !validIP(req.RangeStart) || !validIP(req.RangeEnd) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid range"})
		return
	}
	if !rangeInSubnet(req.Subnet, req.RangeStart, req.RangeEnd) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "range outside subnet"})
		return
	}
	h.dhcpMu.Lock()
	defer h.dhcpMu.Unlock()
	for _, pool := range h.dhcpPools {
		if pool.ID == req.ID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "id already exists"})
			return
		}
	}
	h.dhcpPools = append(h.dhcpPools, req)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handlers) UpdateDHCPPool(c *gin.Context) {
	var req DHCPPool
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	if req.Subnet != "" && !validCIDR(req.Subnet) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid subnet"})
		return
	}
	if req.RangeStart != "" && !validIP(req.RangeStart) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid range_start"})
		return
	}
	if req.RangeEnd != "" && !validIP(req.RangeEnd) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid range_end"})
		return
	}
	h.dhcpMu.Lock()
	defer h.dhcpMu.Unlock()
	for i, pool := range h.dhcpPools {
		if pool.ID == req.ID {
			if strings.TrimSpace(req.Name) != "" {
				pool.Name = strings.TrimSpace(req.Name)
			}
			if strings.TrimSpace(req.Subnet) != "" {
				pool.Subnet = strings.TrimSpace(req.Subnet)
			}
			if strings.TrimSpace(req.RangeStart) != "" {
				pool.RangeStart = strings.TrimSpace(req.RangeStart)
			}
			if strings.TrimSpace(req.RangeEnd) != "" {
				pool.RangeEnd = strings.TrimSpace(req.RangeEnd)
			}
			if pool.Subnet != "" && pool.RangeStart != "" && pool.RangeEnd != "" {
				if !rangeInSubnet(pool.Subnet, pool.RangeStart, pool.RangeEnd) {
					c.JSON(http.StatusBadRequest, gin.H{"error": "range outside subnet"})
					return
				}
			}
			if req.LeaseSeconds != 0 {
				pool.LeaseSeconds = req.LeaseSeconds
			}
			h.dhcpPools[i] = pool
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "pool not found"})
}

func (h *Handlers) DeleteDHCPPool(c *gin.Context) {
	var req struct {
		ID string `json:"id"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}
	h.dhcpMu.Lock()
	defer h.dhcpMu.Unlock()
	for i, pool := range h.dhcpPools {
		if pool.ID == id {
			h.dhcpPools = append(h.dhcpPools[:i], h.dhcpPools[i+1:]...)
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "pool not found"})
}

func validCIDR(value string) bool {
	_, _, err := net.ParseCIDR(strings.TrimSpace(value))
	return err == nil
}

func validIP(value string) bool {
	return net.ParseIP(strings.TrimSpace(value)) != nil
}

func rangeInSubnet(subnet string, start string, end string) bool {
	_, netw, err := net.ParseCIDR(subnet)
	if err != nil || netw == nil {
		return false
	}
	startIP := net.ParseIP(start)
	endIP := net.ParseIP(end)
	if startIP == nil || endIP == nil {
		return false
	}
	return netw.Contains(startIP) && netw.Contains(endIP) && !ipLess(endIP, startIP)
}

func ipLess(a net.IP, b net.IP) bool {
	a16 := a.To16()
	b16 := b.To16()
	if a16 == nil || b16 == nil {
		return false
	}
	return bytes.Compare(a16, b16) < 0
}
