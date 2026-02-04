package api

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.Engine, handlers *Handlers) {
	router.GET("/api/routes", handlers.GetRoutes)
	router.POST("/api/firewall", handlers.AddFirewallRule)
	router.GET("/api/stats", handlers.GetStats)
}
