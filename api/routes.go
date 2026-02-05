package api

import "github.com/gin-gonic/gin"

func RegisterRoutes(router *gin.Engine, handlers *Handlers) {
	router.GET("/health", handlers.GetHealth)

	apiGroup := router.Group("/api")
	if handlers.Observability != nil {
		apiGroup.Use(TraceMiddleware(handlers.Observability))
	}
	if handlers.Security != nil {
		apiGroup.Use(AuthMiddleware(*handlers.Security, handlers.Log))
		apiGroup.Use(AuditMiddleware(handlers.Log))
	}

	apiGroup.GET("/interfaces", RequireRole(roleRead), handlers.GetInterfaces)
	apiGroup.GET("/routes", RequireRole(roleRead), handlers.GetRoutes)
	apiGroup.POST("/routes", RequireRole(roleOps), handlers.AddRoute)
	apiGroup.DELETE("/routes", RequireRole(roleOps), handlers.DeleteRoute)
	apiGroup.PUT("/routes", RequireRole(roleOps), handlers.UpdateRoute)
	apiGroup.POST("/firewall", RequireRole(roleOps), handlers.AddFirewallRule)
	apiGroup.GET("/firewall", RequireRole(roleRead), handlers.GetFirewallRules)
	apiGroup.GET("/firewall/defaults", RequireRole(roleRead), handlers.GetFirewallDefaults)
	apiGroup.GET("/firewall/stats", RequireRole(roleRead), handlers.GetFirewallStats)
	apiGroup.POST("/firewall/reset", RequireRole(roleOps), handlers.ResetFirewallStats)
	apiGroup.POST("/firewall/defaults", RequireRole(roleOps), handlers.SetFirewallDefault)
	apiGroup.GET("/stats", RequireRole(roleRead), handlers.GetStats)
	apiGroup.GET("/ids/rules", RequireRole(roleRead), handlers.GetIDSRules)
	apiGroup.POST("/ids/rules", RequireRole(roleOps), handlers.AddIDSRule)
	apiGroup.PUT("/ids/rules/:name", RequireRole(roleOps), handlers.UpdateIDSRule)
	apiGroup.DELETE("/ids/rules/:name", RequireRole(roleOps), handlers.DeleteIDSRule)
	apiGroup.GET("/ids/alerts", RequireRole(roleRead), handlers.GetIDSAlerts)
	apiGroup.POST("/ids/reset", RequireRole(roleOps), handlers.ResetIDS)
	apiGroup.POST("/config/apply", RequireRole(roleOps), handlers.ApplyConfig)
	apiGroup.POST("/config/rollback", RequireRole(roleOps), handlers.RollbackConfig)
	apiGroup.GET("/config/snapshots", RequireRole(roleRead), handlers.GetConfigSnapshots)
	apiGroup.GET("/dashboard/top/bandwidth", RequireRole(roleRead), handlers.GetDashboardTopBandwidth)
	apiGroup.GET("/dashboard/sessions/tree", RequireRole(roleRead), handlers.GetDashboardSessionsTree)
	apiGroup.GET("/dashboard/alerts", RequireRole(roleRead), handlers.GetDashboardAlerts)
	apiGroup.GET("/observability/traces", RequireRole(roleRead), handlers.GetTraces)
	apiGroup.GET("/observability/alerts", RequireRole(roleRead), handlers.GetAlerts)
	apiGroup.GET("/p2p/peers", RequireRole(roleRead), handlers.GetP2PPeers)
	apiGroup.GET("/p2p/routes", RequireRole(roleRead), handlers.GetP2PRoutes)
	apiGroup.POST("/p2p/reset", RequireRole(roleOps), handlers.ResetP2P)
	apiGroup.GET("/proxy/stats", RequireRole(roleRead), handlers.GetProxyStats)
	apiGroup.POST("/proxy/cache/clear", RequireRole(roleOps), handlers.ClearProxyCache)
	apiGroup.GET("/enrich/ip", RequireRole(roleRead), handlers.GetEnrichIP)
	apiGroup.GET("/ha/status", RequireRole(roleRead), handlers.GetHAStatus)
	apiGroup.GET("/ha/state", RequireRole(roleRead), handlers.GetHAState)
	apiGroup.POST("/ha/state", RequireRole(roleOps), handlers.ApplyHAState)
	apiGroup.GET("/nat", RequireRole(roleRead), handlers.GetNAT)
	apiGroup.POST("/nat/reset", RequireRole(roleOps), handlers.ResetNATStats)
	apiGroup.POST("/nat", RequireRole(roleOps), handlers.AddNATRule)
	apiGroup.GET("/qos", RequireRole(roleRead), handlers.GetQoS)
	apiGroup.POST("/qos", RequireRole(roleOps), handlers.AddQoSClass)
	apiGroup.GET("/presets", RequireRole(roleRead), handlers.GetPresets)
	apiGroup.POST("/presets", RequireRole(roleOps), handlers.CreatePreset)
	apiGroup.POST("/presets/import", RequireRole(roleOps), handlers.ImportPresets)
	apiGroup.POST("/presets/update", RequireRole(roleOps), handlers.UpdatePresets)
	apiGroup.GET("/presets/:id", RequireRole(roleRead), handlers.GetPreset)
	apiGroup.POST("/presets/:id/preview", RequireRole(roleOps), handlers.PreviewPreset)
	apiGroup.POST("/presets/:id/apply", RequireRole(roleOps), handlers.ApplyPreset)
}
