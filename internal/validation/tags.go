package validation

import (
	"reflect"
	"regexp"

	"github.com/go-playground/validator/v10"
)

// Custom tag names registered by New. Each tag encodes one project-specific
// field rule that go-playground/validator does not express with built-ins.
const (
	// TagUsername checks the 3-32 character [a-zA-Z0-9_.-] username shape.
	TagUsername = "username"
	// TagPassword checks length 8-128 and requires both a letter and a digit.
	TagPassword = "password"
	// TagInviteCode checks the 8-character alphanumeric invite code shape.
	TagInviteCode = "invite_code"
	// TagActivationCode checks the 16-character base32 activation code shape.
	TagActivationCode = "activation_code"
)

var (
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,32}$`)
	// Codes are case-insensitive on input; services normalize to uppercase
	// before hashing, so lowercase hand-typed codes still redeem.
	inviteCodeRe     = regexp.MustCompile(`^[0-9A-Za-z]{8}$`)
	activationCodeRe = regexp.MustCompile(`^[A-Za-z2-7]{16}$`)
	letterRe         = regexp.MustCompile(`[a-zA-Z]`)
	digitRe          = regexp.MustCompile(`[0-9]`)
)

// validateUsername enforces TagUsername.
func validateUsername(fl validator.FieldLevel) bool {
	return isString(fl, usernameRe.MatchString)
}

// validatePassword enforces TagPassword: 8-128 characters with at least one
// letter and one digit.
func validatePassword(fl validator.FieldLevel) bool {
	return isString(fl, func(s string) bool {
		if len(s) < 8 || len(s) > 128 {
			return false
		}
		return letterRe.MatchString(s) && digitRe.MatchString(s)
	})
}

// validateInviteCode enforces TagInviteCode.
func validateInviteCode(fl validator.FieldLevel) bool {
	return isString(fl, inviteCodeRe.MatchString)
}

// validateActivationCode enforces TagActivationCode.
func validateActivationCode(fl validator.FieldLevel) bool {
	return isString(fl, activationCodeRe.MatchString)
}

// isString runs fn against the field value when the field is a string;
// non-string fields fail the rule.
func isString(fl validator.FieldLevel, fn func(string) bool) bool {
	f := fl.Field()
	return f.Kind() == reflect.String && fn(f.String())
}
