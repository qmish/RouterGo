package api

import (
	"net/http/pprof"
	"strings"

	"github.com/gin-gonic/gin"
)

func RegisterPprof(router *gin.Engine, basePath string) {
	if basePath == "" {
		basePath = "/debug/pprof"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	group := router.Group(basePath)
	group.GET("/", gin.WrapF(pprof.Index))
	group.GET("/cmdline", gin.WrapF(pprof.Cmdline))
	group.GET("/profile", gin.WrapF(pprof.Profile))
	group.GET("/symbol", gin.WrapF(pprof.Symbol))
	group.POST("/symbol", gin.WrapF(pprof.Symbol))
	group.GET("/trace", gin.WrapF(pprof.Trace))
	group.GET("/allocs", gin.WrapH(pprof.Handler("allocs")))
	group.GET("/block", gin.WrapH(pprof.Handler("block")))
	group.GET("/goroutine", gin.WrapH(pprof.Handler("goroutine")))
	group.GET("/heap", gin.WrapH(pprof.Handler("heap")))
	group.GET("/mutex", gin.WrapH(pprof.Handler("mutex")))
	group.GET("/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))
}
