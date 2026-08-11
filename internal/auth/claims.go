package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the access token payload. It deliberately carries only the user
// identity; roles and ban state are resolved server-side per request.
type Claims struct {
	jwt.RegisteredClaims
	UserID int64 `json:"uid"`
	// Ver is the user's auth_version at signing time. Resolvers reject tokens
	// whose version is behind the current one, which is how password changes
	// revoke previously issued access tokens.
	Ver int64 `json:"ver"`
}

// SignAccess issues an HS256 access token for the user valid for ttl.
func SignAccess(secret []byte, userID, authVersion int64, ttl time.Duration, now time.Time) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		UserID: userID,
		Ver:    authVersion,
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
