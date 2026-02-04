package api

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.Engine, handlers *Handlers) {
	router.GET("/api/routes", handlers.GetRoutes)
	router.POST("/api/firewall", handlers.AddFirewallRule)
	router.GET("/api/stats", handlers.GetStats)
	router.GET("/api/nat", handlers.GetNAT)
	router.POST("/api/nat", handlers.AddNATRule)
	router.GET("/api/qos", handlers.GetQoS)
	router.POST("/api/qos", handlers.AddQoSClass)
}
