package auth

import (
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// LoginRateLimit returns a per-IP rate limiter with the given requests per
// minute. The burst is bounded by the per-second rate, so sustained bursts
// beyond the limit are rejected with 429.
func LoginRateLimit(perMinute float64) echo.MiddlewareFunc {
	return middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(perMinute / 60.0))
}
