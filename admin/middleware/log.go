// Package middleware contains the shared Iris request middleware.
package middleware

import (
	"github.com/kataras/iris/v12"
	"log/slog"
	"time"
)

// HTTPLogger adapts the existing Admin request logger without logging request bodies.
func HTTPLogger(ctx iris.Context) {
	start := time.Now()
	ctx.Next()
	slog.Info("admin request", "method", ctx.Method(), "path", ctx.Path(), "status", ctx.GetStatusCode(), "duration", time.Since(start))
}
