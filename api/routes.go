package api

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.Engine, handlers *Handlers) {
	router.GET("/api/routes", handlers.GetRoutes)
	router.POST("/api/firewall", handlers.AddFirewallRule)
	router.GET("/api/firewall", handlers.GetFirewallRules)
	router.GET("/api/firewall/defaults", handlers.GetFirewallDefaults)
	router.GET("/api/firewall/stats", handlers.GetFirewallStats)
	router.POST("/api/firewall/reset", handlers.ResetFirewallStats)
	router.POST("/api/firewall/defaults", handlers.SetFirewallDefault)
	router.GET("/api/stats", handlers.GetStats)
	router.GET("/api/ids/rules", handlers.GetIDSRules)
	router.POST("/api/ids/rules", handlers.AddIDSRule)
	router.GET("/api/ids/alerts", handlers.GetIDSAlerts)
	router.POST("/api/ids/reset", handlers.ResetIDS)
	router.POST("/api/config/apply", handlers.ApplyConfig)
	router.POST("/api/config/rollback", handlers.RollbackConfig)
	router.GET("/api/config/snapshots", handlers.GetConfigSnapshots)
	router.GET("/api/dashboard/top/bandwidth", handlers.GetDashboardTopBandwidth)
	router.GET("/api/dashboard/sessions/tree", handlers.GetDashboardSessionsTree)
	router.GET("/api/dashboard/alerts", handlers.GetDashboardAlerts)
	router.GET("/api/nat", handlers.GetNAT)
	router.POST("/api/nat/reset", handlers.ResetNATStats)
	router.POST("/api/nat", handlers.AddNATRule)
	router.GET("/api/qos", handlers.GetQoS)
	router.POST("/api/qos", handlers.AddQoSClass)
}
