package auth

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/validation"
)

// LoginHandler handles POST /api/v0/auth/login.
func LoginHandler(svc *AuthService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req loginRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}

		result, err := svc.Login(c.Request().Context(), req.Username, req.Password, req.DeviceID)
		if err != nil {
			switch {
			case errors.Is(err, ErrInvalidCredentials):
				return echo.ErrUnauthorized
			case errors.Is(err, ErrUserBanned):
				return echo.NewHTTPError(http.StatusForbidden, "user banned")
			default:
				return err
			}
		}

		return c.JSON(http.StatusOK, loginResponse{
			tokenResponse: tokenResponse{
				AccessToken:  result.AccessToken,
				RefreshToken: result.RefreshToken,
				ExpiresIn:    result.ExpiresIn,
			},
			User: newUserResponse(result.User),
		})
	}
}

// RefreshHandler handles POST /api/v0/auth/refresh.
func RefreshHandler(svc *AuthService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req refreshRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}

		pair, err := svc.Refresh(c.Request().Context(), req.RefreshToken)
		if err != nil {
			if errors.Is(err, ErrInvalidRefresh) {
				return echo.ErrUnauthorized
			}
			return err
		}
		return c.JSON(http.StatusOK, tokenResponse{
			AccessToken:  pair.AccessToken,
			RefreshToken: pair.RefreshToken,
			ExpiresIn:    pair.ExpiresIn,
		})
	}
}

// LogoutHandler handles POST /api/v0/auth/logout.
func LogoutHandler(svc *AuthService) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req logoutRequest
		if err := validation.Bind(c, &req); err != nil {
			return err
		}
		if err := svc.Logout(c.Request().Context(), req.RefreshToken); err != nil {
			return err
		}
		return c.NoContent(http.StatusNoContent)
	}
}
