package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrInvalidAccessClaims is returned when a signed token omits a required
	// identity claim or carries an invalid identity value.
	ErrInvalidAccessClaims = errors.New("auth: invalid access token claims")
)

// Claims is the access token payload. It deliberately carries only the user
// identity and login-session identity; roles and ban state are resolved
// server-side per request.
type Claims struct {
	jwt.RegisteredClaims
	UserID int64 `json:"uid"`
	// LoginSessionID binds the access token to one persisted login session.
	// WebSocket connection admission verifies that this session still belongs to
	// UserID before reserving a control connection.
	LoginSessionID int64 `json:"sid"`
	// Ver is the user's auth_version at signing time. Resolvers reject tokens
	// whose version is behind the current one, which is how password changes
	// revoke previously issued access tokens.
	Ver int64 `json:"ver"`
}

// Validate enforces the application claims that every access token must carry.
// jwt.Parser invokes it alongside RegisteredClaims time validation.
func (c Claims) Validate() error {
	if c.UserID <= 0 || c.LoginSessionID <= 0 || c.Ver < 0 || c.ExpiresAt == nil {
		return ErrInvalidAccessClaims
	}
	return nil
}

// SignAccess issues an HS256 access token for userID and loginSessionID valid
// for ttl. The session must already be persisted before calling this function.
func SignAccess(secret []byte, userID, authVersion, loginSessionID int64, ttl time.Duration, now time.Time) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID:         userID,
		LoginSessionID: loginSessionID,
		Ver:            authVersion,
	}
	if err := claims.Validate(); err != nil {
		return "", err
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// ParseAccess verifies the token signature and expiry and returns its claims.
func ParseAccess(secret []byte, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("auth: unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("auth: invalid token")
	}
	return claims, nil
}
