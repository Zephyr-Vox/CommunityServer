package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// requestLogging returns Echo's request logger wired to a.logger with the
// [http] module. Each request is one prose line, e.g.
//
//	GET /api/v0/auth/status -> 200 (1.2ms) from 127.0.0.1
//
// Severity follows the response status: successful 2xx/3xx are routine Info,
// 4xx are Warn (client mistakes worth noticing), 5xx are Error.
func (a *App) requestLogging() echo.MiddlewareFunc {
	log := a.logger.With("module", "http")
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogMethod:   true,
		LogURIPath:  true,
		LogStatus:   true,
		LogLatency:  true,
		LogRemoteIP: true,
		LogValuesFunc: func(_ *echo.Context, v middleware.RequestLoggerValues) error {
			msg := fmt.Sprintf("%s %s -> %d (%s) from %s", v.Method, v.URIPath, v.Status, v.Latency, v.RemoteIP)
			if v.Error != nil {
				msg += ": " + v.Error.Error()
			}
			log.Log(context.Background(), requestLogLevel(v.Status), msg)
			return nil
		},
	})
}

// requestLogLevel maps a response status to the log level: successful
// 2xx/3xx are Info, client errors are Warn, server errors are Error.
func requestLogLevel(status int) slog.Level {
	switch {
	case status >= http.StatusOK && status < http.StatusBadRequest:
		return slog.LevelInfo
	case status >= http.StatusBadRequest && status < http.StatusInternalServerError:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}
