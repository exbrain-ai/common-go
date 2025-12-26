package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RegisterMetrics registers the standard Prometheus /metrics endpoint on the router.
// This endpoint exposes Prometheus metrics in standard format that can be scraped
// by any Prometheus-compatible monitoring system.
//
// Usage:
//   router := gin.New()
//   middleware.RegisterMetrics(router)
//   // Or with custom path:
//   middleware.RegisterMetricsWithPath(router, "/custom/metrics")
//
// The endpoint will be available at /metrics (or custom path) and can be scraped
// by Prometheus when the Kubernetes service has prometheus.io/scrape annotation.
func RegisterMetrics(router *gin.Engine) {
	RegisterMetricsWithPath(router, "/metrics")
}

// RegisterMetricsWithPath registers the Prometheus /metrics endpoint at a custom path.
// This is useful if you need to use a different path than the standard /metrics.
func RegisterMetricsWithPath(router *gin.Engine, path string) {
	router.GET(path, gin.WrapH(promhttp.Handler()))
}













