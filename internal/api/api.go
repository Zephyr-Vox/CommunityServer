// Package api defines the uniform response envelope and the central error
// handler for every HTTP endpoint:
//
//	{"code": 0, "message": "", "data": {...}}
//
// code 0 with an empty message means success; data carries the DTO. Any
// non-zero code is a business error, message carries a short explanation,
// and data is null.
//
// Errors fall into two disjoint ranges: endpoint-specific business codes
// (1..999, numbered per handler from 1, repeatable across endpoints) and the
// shared global block (1000+, identical across every endpoint).
package api

import "github.com/labstack/echo/v5"

// CodeOK is the success code of every envelope.
const CodeOK = 0

// Envelope is the body of every response.
type Envelope struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// OK writes a success envelope. The HTTP status is supplied by the caller so
// 200/201 can differ while the body stays uniform.
func OK(c *echo.Context, status int, data any) error {
	return c.JSON(status, Envelope{Code: CodeOK, Message: "", Data: data})
}

// NoContent writes an empty response. 204 has no body, so there is nothing
// to wrap.
func NoContent(c *echo.Context, status int) error {
	return c.NoContent(status)
}
