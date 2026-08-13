package image

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/oss"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/store"
)

// UploadAvatarHandler handles POST /api/v0/me/avatar. The route must be
// mounted behind AuthN; no specific permission is required (self-service).
// Success returns the new avatar name; the client builds the full URL by
// joining the name with the public prefix, currently the fixed route
// /avatar/.
//
// Errors:
//   - 1 missing file: multipart field "file" is absent or unreadable
//   - 2 user not found: account deleted after the token was issued
//   - 3 image too large: source dimensions exceed the configured limit
//   - 1002 unauthorized: missing or invalid access token
//   - 1006 payload too large: request body exceeds the configured avatar limit
//   - 1007 unsupported media type: file is not a decodable image
//   - 1009 internal: unexpected server error
func UploadAvatarHandler(svc *AvatarService) echo.HandlerFunc {
	const (
		codeMissingFile   = 1
		codeUserNotFound  = 2
		codeImageTooLarge = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, svc.cfg.MaxUploadSize)

		file, err := c.FormFile("file")
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				return api.NewError(api.CodePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload too large")
			}
			return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
		}
		src, err := file.Open()
		if err != nil {
			return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
		}
		defer src.Close()

		// Sniff first as a cheap gate; the authoritative check is the decode
		// inside Transcode. The multipart header is never trusted.
		contentType, rest, err := oss.DetectContentType(src)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(contentType, "image/") {
			return api.NewError(api.CodeUnsupportedMedia, http.StatusUnsupportedMediaType, "unsupported media type")
		}

		name, err := svc.Upload(c.Request().Context(), p.UserID, rest)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrNotFound):
				return api.NewError(codeUserNotFound, http.StatusUnauthorized, "user not found")
			case errors.Is(err, ErrImageTooLarge):
				return api.NewError(codeImageTooLarge, http.StatusBadRequest, "image too large")
			case errors.Is(err, ErrNotAnImage):
				return api.NewError(api.CodeUnsupportedMedia, http.StatusUnsupportedMediaType, "unsupported media type")
			default:
				return err
			}
		}
		return api.OK(c, http.StatusOK, uploadResponse{Avatar: name})
	})
}

// DeleteAvatarHandler handles DELETE /api/v0/me/avatar. The route must be
// mounted behind AuthN; no specific permission is required. It is idempotent:
// a user without an avatar still gets 204.
//
// Errors:
//   - 1 user not found: account deleted after the token was issued
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: unexpected server error
func DeleteAvatarHandler(svc *AvatarService) echo.HandlerFunc {
	const codeUserNotFound = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		if err := svc.Reset(c.Request().Context(), p.UserID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return api.NewError(codeUserNotFound, http.StatusUnauthorized, "user not found")
			}
			return err
		}
		return api.NoContent(c, http.StatusNoContent)
	})
}
