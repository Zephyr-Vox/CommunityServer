package image

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/commandhttp"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/realtime"
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
//   - 9 idempotency mismatch: the retry key belongs to another request
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
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		// Buffer the selected part and drain every following part through the same
		// bounded reader before image processing or storage starts. This keeps
		// trailing multipart data inside the request hard cap.
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
				fileName := part.FileName()
				contentType := part.Header.Get("Content-Type")
				data, readErr := io.ReadAll(part)
				if readErr != nil {
					_ = part.Close()
					if isMaxBytesError(readErr) {
						return api.NewError(api.CodePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload too large")
					}
					return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
				}
				if drainErr := drainMultipart(multipartReader, part); drainErr != nil {
					_ = part.Close()
					if isMaxBytesError(drainErr) {
						return api.NewError(api.CodePayloadTooLarge, http.StatusRequestEntityTooLarge, "payload too large")
					}
					return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
				}
				if closeErr := part.Close(); closeErr != nil {
					return api.NewError(codeMissingFile, http.StatusBadRequest, "missing file")
				}
				digest := sha256.Sum256(data)
				identity, err := realtime.NewHTTPCommandIdentity(p.UserID, http.MethodPost, "/api/v0/me/avatar", nil, nil, avatarIdentity{
					SHA256: hex.EncodeToString(digest[:]), Name: fileName, ContentType: contentType,
				})
				if err != nil {
					return err
				}
				ctx, state, replayed, err := prepareAvatarHTTPMutation(c, svc, key, identity)
				if err != nil {
					return err
				}
				if replayed {
					return nil
				}
				ctx = realtime.WithHTTPMutationResponseBuilder(ctx, func(value any) (realtime.HTTPMutationResponse, error) {
					name, ok := value.(string)
					if !ok {
						return realtime.HTTPMutationResponse{}, errors.New("image: invalid avatar response")
					}
					return realtime.HTTPMutationResponse{Status: http.StatusOK, Data: uploadResponse{Avatar: name}}, nil
				})
				name, err := svc.upload(ctx, p.UserID, bytes.NewReader(data))
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
				if state != nil && state.Replay != nil {
					return commandhttp.ReplayDurable(c, *state.Replay)
				}
				setAvatarStateHeaders(c, state)
				return commandhttp.OK(c, http.StatusOK, uploadResponse{Avatar: name})
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
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1002 unauthorized: missing or invalid access token
//   - 1009 internal: unexpected server error
func DeleteAvatarHandler(svc *AvatarService) echo.HandlerFunc {
	const codeUserNotFound = 1
	return rbacecho.WithPrincipal(func(c *echo.Context, p *rbac.Principal) error {
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		identity, err := realtime.NewHTTPCommandIdentity(p.UserID, http.MethodDelete, "/api/v0/me/avatar", nil, nil, struct{}{})
		if err != nil {
			return err
		}
		ctx, state, replayed, err := prepareAvatarHTTPMutation(c, svc, key, identity)
		if err != nil {
			return err
		}
		if replayed {
			return nil
		}
		ctx = realtime.WithHTTPMutationResponseBuilder(ctx, func(any) (realtime.HTTPMutationResponse, error) {
			return realtime.HTTPMutationResponse{Status: http.StatusNoContent}, nil
		})
		if err := svc.Reset(ctx, p.UserID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return api.NewError(codeUserNotFound, http.StatusUnauthorized, "user not found")
			}
			return err
		}
		if state != nil && state.Replay != nil {
			return commandhttp.ReplayDurable(c, *state.Replay)
		}
		setAvatarStateHeaders(c, state)
		return api.NoContent(c, http.StatusNoContent)
	})
}

// avatarIdentity is the canonical validated identity of one uploaded file.
// The content digest prevents reusing one retry key for different bytes.
type avatarIdentity struct {
	SHA256      string `json:"sha256"`
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
}

// idempotencyKey validates the single retry key required by avatar mutations.
func idempotencyKey(c *echo.Context) (string, error) {
	values := c.Request().Header.Values("Idempotency-Key")
	if len(values) != 1 || !realtime.IdempotencyKeyValid(values[0]) {
		return "", api.InvalidField("header.Idempotency-Key", "must be 16-64 characters using letters, digits, underscore, or hyphen")
	}
	return values[0], nil
}

// prepareAvatarHTTPMutation performs completed replay before image processing
// or object storage and attaches a request-local state carrier for new work.
func prepareAvatarHTTPMutation(c *echo.Context, svc *AvatarService, key string, identity realtime.HTTPCommandIdentity) (context.Context, *realtime.HTTPMutationState, bool, error) {
	if svc != nil && svc.prepareState == nil {
		return c.Request().Context(), nil, false, nil
	}
	if svc == nil || svc.prepareState == nil {
		return nil, nil, false, errors.New("image: avatar mutation runtime unavailable")
	}
	command, err := realtime.NewHTTPMutationCommand(identity, key)
	if err != nil {
		return nil, nil, false, err
	}
	ctx, replay, found, err := svc.prepareState(c.Request().Context(), command)
	if errors.Is(err, realtime.ErrIdempotencyMismatch) {
		return nil, nil, false, api.NewError(9, http.StatusConflict, "idempotency key reused with different request")
	}
	if err != nil {
		return nil, nil, false, err
	}
	if found {
		return nil, nil, true, commandhttp.ReplayDurable(c, replay)
	}
	state := &realtime.HTTPMutationState{}
	return realtime.WithHTTPMutationState(ctx, state), state, false, nil
}

// setAvatarStateHeaders exposes the exact publication checkpoint for an
// uploaded or reset avatar mutation.
func setAvatarStateHeaders(c *echo.Context, state *realtime.HTTPMutationState) {
	if state != nil {
		commandhttp.SetStateCommandHeaders(c, state.CommandID, state.Checkpoint, state.StateCursor)
	}
}
