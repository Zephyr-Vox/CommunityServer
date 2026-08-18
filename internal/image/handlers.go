package image

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
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
//   - 1008 rate limited: all avatar transcode slots are busy
//   - 1009 internal: unexpected server error
func UploadAvatarHandler(svc *AvatarService) echo.HandlerFunc {
	const (
		codeMissingFile   = 1
		codeUserNotFound  = 2
		codeImageTooLarge = 3
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		// The limit applies to every multipart part, including fields after file.
		// Read them all before Upload so a rejected request cannot mutate state.
		c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, svc.cfg.MaxUploadSize)

		multipartReader, err := c.Request().MultipartReader()
		if err != nil {
			return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
		}
		var file *os.File
		var filePath string
		defer func() {
			if file != nil {
				_ = file.Close()
			}
			if filePath != "" {
				_ = os.Remove(filePath)
			}
		}()
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
				// Stage only the selected file on disk. This keeps multipart input out
				// of memory while allowing the remaining request body to be verified.
				file, err = os.CreateTemp("", "zephyr-avatar-*")
				if err != nil {
					_ = part.Close()
					return err
				}
				filePath = file.Name()
				_, copyErr := io.Copy(file, part)
				closeErr := part.Close()
				if copyErr != nil {
					return uploadReadError(copyErr, codeMissingFile)
				}
				if closeErr != nil {
					return uploadReadError(closeErr, codeMissingFile)
				}
				break
			}
			_ = part.Close()
		}
		if file == nil {
			return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
		}
		// Consume every trailing part before touching object storage or metadata.
		if err := drainMultipart(multipartReader); err != nil {
			return uploadReadError(err, codeMissingFile)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return err
		}

		// Sniff first as a cheap gate; the authoritative check is the decode
		// inside Transcode. The multipart header is never trusted.
		contentType, rest, err := oss.DetectContentType(file)
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
			case errors.Is(err, ErrTranscodeBusy):
				return api.NewError(api.CodeRateLimited, http.StatusTooManyRequests, "rate limited")
			case isMaxBytesError(err):
				return api.NewError(api.CodePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload too large")
			case errors.Is(err, ErrNotAnImage):
				return api.NewError(api.CodeUnsupportedMedia, http.StatusUnsupportedMediaType, "unsupported media type")
			default:
				return err
			}
		}
		return api.OK(c, http.StatusOK, uploadResponse{Avatar: name})
	})
}

// isMaxBytesError reports whether reading the bounded request body exceeded
// its configured limit.
func isMaxBytesError(err error) bool {
	_, ok := errors.AsType[*http.MaxBytesError](err)
	return ok
}

// uploadReadError preserves the avatar endpoint's response contract for body
// read failures while distinguishing an exceeded body limit.
func uploadReadError(err error, missingFileCode int) error {
	if isMaxBytesError(err) {
		return api.NewError(api.CodePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload too large")
	}
	return api.NewError(missingFileCode, http.StatusBadRequest, "missing file")
}

// drainMultipart consumes all remaining parts so MaxBytesReader observes the
// complete request before avatar storage or metadata can be changed.
func drainMultipart(reader *multipart.Reader) error {
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(io.Discard, part)
		closeErr := part.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
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
