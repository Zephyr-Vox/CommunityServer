package oss

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
)

// GetHandler handles GET /:file for one bucket. The bucket is fixed at
// wiring time; the route parameter is validated as a single path segment.
// Success streams the raw file bytes (a binary response, not a JSON
// envelope); errors go through the central API error handler.
//
// Errors:
//   - 1004 not found: object missing or name invalid
//   - 1009 internal: unexpected server error
func (s *LocalObjectStorage) GetHandler(bucket string) (echo.HandlerFunc, error) {
	if err := validateComponent(bucket); err != nil {
		return nil, fmt.Errorf("oss: invalid bucket %q", bucket)
	}
	return func(c *echo.Context) error {
		name := c.Param("file")
		if err := validateComponent(name); err != nil {
			return api.NewError(api.CodeNotFound, http.StatusNotFound, "not found")
		}

		obj, rc, err := s.Open(c.Request().Context(), bucket, name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return api.NewError(api.CodeNotFound, http.StatusNotFound, "not found")
			}
			return err
		}
		defer rc.Close()

		c.Response().Header().Set(echo.HeaderContentType, obj.ContentType)
		c.Response().Header().Set(echo.HeaderContentLength, strconv.FormatInt(obj.Size, 10))
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		if rs, ok := rc.(io.ReadSeeker); ok {
			http.ServeContent(c.Response(), c.Request(), name, time.UnixMilli(obj.CreatedAt), rs)
			return nil
		}
		_, err = io.Copy(c.Response(), rc)
		return err
	}, nil
}
