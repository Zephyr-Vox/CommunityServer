// Package commandhttp writes durable HTTP command response metadata without
// coupling the transport-independent realtime package to Echo.
package commandhttp

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/realtime"
)

// SetStateCommandHeaders exposes one command ID and its exact state checkpoint
// to an HTTP response. Empty values are omitted for direct service callers.
func SetStateCommandHeaders(c *echo.Context, commandID int64, checkpoint realtime.Checkpoint, cursor string) {
	if commandID > 0 {
		c.Response().Header().Set("X-Zephyr-Command-ID", strconv.FormatInt(commandID, 10))
	}
	if cursor != "" {
		c.Response().Header().Set("X-Zephyr-State-Cursor", cursor)
	}
	if checkpoint.StreamEpoch != "" {
		c.Response().Header().Set("X-Zephyr-Stream-Epoch", checkpoint.StreamEpoch)
		c.Response().Header().Set("X-Zephyr-Geid", strconv.FormatUint(checkpoint.GEID, 10))
	}
}

// OK writes the canonical successful API envelope used by durable command
// persistence, so a same-epoch replay has the original response bytes.
func OK(c *echo.Context, status int, data any) error {
	body, err := realtime.CanonicalSuccessBody(data)
	if err != nil {
		return err
	}
	body, err = realtime.CanonicalJSON(body)
	if err != nil {
		return err
	}
	return c.Blob(status, echo.MIMEApplicationJSONCharsetUTF8, body)
}

// NoContent writes the empty 204 response used by durable command persistence.
func NoContent(c *echo.Context, status int) error {
	return c.NoContent(status)
}

// ReplayDurable writes a completed durable command exactly as its original
// success response. A replay from an earlier process epoch replaces obsolete
// checkpoint fields with the required full-sync signal.
func ReplayDurable(c *echo.Context, replay realtime.DurableReplay) error {
	if replay.Headers.ETag != "" {
		c.Response().Header().Set("ETag", replay.Headers.ETag)
	}
	if replay.Headers.ParentETag != "" {
		c.Response().Header().Set("X-Zephyr-Parent-ETag", replay.Headers.ParentETag)
	}
	if replay.Headers.Location != "" {
		c.Response().Header().Set("Location", replay.Headers.Location)
	}
	if replay.Headers.CacheControl != "" {
		c.Response().Header().Set("Cache-Control", replay.Headers.CacheControl)
	}
	if replay.Headers.Pragma != "" {
		c.Response().Header().Set("Pragma", replay.Headers.Pragma)
	}
	if replay.SyncRequired {
		c.Response().Header().Set("X-Zephyr-Command-ID", strconv.FormatInt(replay.CommandID, 10))
		c.Response().Header().Set("X-Zephyr-Sync-Required", "true")
	} else {
		SetStateCommandHeaders(c, replay.CommandID, replay.Checkpoint, replay.StateCursor)
	}
	if replay.Status == http.StatusNoContent {
		return c.NoContent(replay.Status)
	}
	return c.Blob(replay.Status, echo.MIMEApplicationJSONCharsetUTF8, replay.Body)
}

// ReplayRuntime writes a completed in-process command result byte-for-byte.
// Runtime retries use the same response envelope and checkpoint headers as
// durable commands, while their short-lived cache may also retain secrets such
// as a freshly-created voice session key.
func ReplayRuntime(c *echo.Context, result realtime.RuntimeCommandResult) error {
	if result.Headers.ETag != "" {
		c.Response().Header().Set("ETag", result.Headers.ETag)
	}
	if result.Headers.ParentETag != "" {
		c.Response().Header().Set("X-Zephyr-Parent-ETag", result.Headers.ParentETag)
	}
	if result.Headers.Location != "" {
		c.Response().Header().Set("Location", result.Headers.Location)
	}
	if result.Headers.CacheControl != "" {
		c.Response().Header().Set("Cache-Control", result.Headers.CacheControl)
	}
	if result.Headers.Pragma != "" {
		c.Response().Header().Set("Pragma", result.Headers.Pragma)
	}
	SetStateCommandHeaders(c, result.CommandID, result.Checkpoint, result.StateCursor)
	if result.Status == http.StatusNoContent {
		return c.NoContent(result.Status)
	}
	return c.Blob(result.Status, echo.MIMEApplicationJSONCharsetUTF8, result.Body)
}
