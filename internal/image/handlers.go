package image

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
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
//   - 1008 rate limited: all avatar transcode slots are busy
//   - 1009 internal: unexpected server error
func UploadAvatarHandler(svc *AvatarService) echo.HandlerFunc {
	const (
		codeMissingFile   = 1
		codeUserNotFound  = 2
		codeImageTooLarge = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		// The selected part is passed straight into Upload. Before storage or
		// metadata commit, Upload drains the remainder through the same bounded
		// reader so trailing multipart data cannot bypass the request hard cap.
		c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, svc.cfg.MaxUploadSize)

		multipartReader, err := c.Request().MultipartReader()
		if err != nil {
			return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
		}
		for {
			part, nextErr := multipartReader.NextPart()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				if isMaxBytesError(nextErr) {
					return api.NewError(api.CodePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload too large")
				}
				return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
			}
			if part.FormName() == "file" {
				defer part.Close()
				name, err := svc.upload(c.Request().Context(), p.UserID, part, func() error {
					return drainMultipart(multipartReader, part)
				})
				if err != nil {
					switch {
					case errors.Is(err, store.ErrNotFound):
						return api.NewError(codeUserNotFound, http.StatusUnauthorized, "user not found")
					case errors.Is(err, ErrImageTooLarge):
						return api.NewError(codeImageTooLarge, http.StatusBadRequest, "image too large")
					case errors.Is(err, ErrTranscodeBusy):
						return api.NewError(api.CodeRateLimited, http.StatusTooManyRequests, "rate limited")
					case isMaxBytesError(err):
						return api.NewError(api.CodePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload too large")
					case errors.Is(err, errUnreadableMultipart):
						return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
					case errors.Is(err, ErrNotAnImage):
						return api.NewError(api.CodeUnsupportedMedia, http.StatusUnsupportedMediaType, "unsupported media type")
					default:
						return err
					}
				}
				return api.OK(c, http.StatusOK, uploadResponse{Avatar: name})
			}
			_ = part.Close()
		}
		return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
	})
}

var errUnreadableMultipart = errors.New("image: unreadable multipart body")

// drainMultipart consumes the selected part and every following part so the
// MaxBytesReader limit applies to the complete request before avatar commit.
func drainMultipart(reader *multipart.Reader, selected *multipart.Part) error {
	if _, err := io.Copy(io.Discard, selected); err != nil {
		if isMaxBytesError(err) {
			return err
		}
		return errors.Join(errUnreadableMultipart, err)
	}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if isMaxBytesError(err) {
				return err
			}
			return errors.Join(errUnreadableMultipart, err)
		}
		_, copyErr := io.Copy(io.Discard, part)
		closeErr := part.Close()
		if copyErr != nil {
			if isMaxBytesError(copyErr) {
				return copyErr
			}
			return errors.Join(errUnreadableMultipart, copyErr)
		}
		if closeErr != nil {
			return errors.Join(errUnreadableMultipart, closeErr)
		}
	}
}

// isMaxBytesError reports whether reading the bounded request body exceeded
// its configured limit.
func isMaxBytesError(err error) bool {
	_, ok := errors.AsType[*http.MaxBytesError](err)
	return ok
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
