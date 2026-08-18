package auth

import (
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// IPRateLimit returns an independent per-IP rate limiter with the given
// requests per minute. Each call creates its own memory store, so separate
// public endpoints do not consume one another's budget.
func IPRateLimit(perMinute float64) echo.MiddlewareFunc {
	return middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(perMinute / 60.0))
}
