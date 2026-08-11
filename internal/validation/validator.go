// Package validation wires go-playground/validator into Echo for declarative
// request-shape checks. Rules that need a database lookup or cross-field
// semantics (role existence, expiry vs. now, invite availability) stay in the
// service layer; struct tags only describe shape.
package validation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v5"
)

// Custom tag names registered by New.
const (
	TagUsername       = "username"
	TagPassword       = "password"
	TagInviteCode     = "invite_code"
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

// Validator implements echo.Validator over go-playground/validator.
type Validator struct {
	v *validator.Validate
}

// FieldsError describes a 400 validation failure with one message per field.
// It implements HTTPStatusCoder and json.Marshaler so Echo's default error
// handler serializes it as {"error":"invalid request","fields":{...}}.
type FieldsError struct {
	Fields map[string]string
}

func (e *FieldsError) Error() string {
	return fmt.Sprintf("validation failed for %d field(s)", len(e.Fields))
}

func (e *FieldsError) StatusCode() int {
	return http.StatusBadRequest
}

func (e *FieldsError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Error  string            `json:"error"`
		Fields map[string]string `json:"fields"`
	}{
		Error:  "invalid request",
		Fields: e.Fields,
	})
}

// New builds a Validator with the project's custom tags registered. Field
// names in validation errors come from the json tag when present.
func New() *Validator {
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "" || name == "-" {
			return fld.Name
		}
		return name
	})
	_ = v.RegisterValidation(TagUsername, validateUsername)
	_ = v.RegisterValidation(TagPassword, validatePassword)
	_ = v.RegisterValidation(TagInviteCode, validateInviteCode)
	_ = v.RegisterValidation(TagActivationCode, validateActivationCode)
	return &Validator{v: v}
}

// Validate runs struct-tag validation and turns failures into a 400 whose
// body carries a per-field message map:
//
//	{"error":"invalid request","fields":{"username":"is required"}}
func (v *Validator) Validate(i any) error {
	if err := v.v.Struct(i); err != nil {
		var fieldErrs validator.ValidationErrors
		if errors.As(err, &fieldErrs) {
			fields := make(map[string]string, len(fieldErrs))
			for _, fe := range fieldErrs {
				fields[fe.Field()] = messageFor(fe)
			}
			return &FieldsError{Fields: fields}
		}
		return echo.ErrBadRequest
	}
	return nil
}

// Bind binds a request payload and validates it in one step. Malformed JSON
// and shape violations both yield 400.
func Bind(c *echo.Context, dst any) error {
	if err := c.Bind(dst); err != nil {
		return echo.ErrBadRequest
	}
	return c.Validate(dst)
}

func validateUsername(fl validator.FieldLevel) bool {
	return isString(fl, usernameRe.MatchString)
}

func validatePassword(fl validator.FieldLevel) bool {
	return isString(fl, func(s string) bool {
		if len(s) < 8 || len(s) > 128 {
			return false
		}
		return letterRe.MatchString(s) && digitRe.MatchString(s)
	})
}

func validateInviteCode(fl validator.FieldLevel) bool {
	return isString(fl, inviteCodeRe.MatchString)
}

func validateActivationCode(fl validator.FieldLevel) bool {
	return isString(fl, activationCodeRe.MatchString)
}

func isString(fl validator.FieldLevel, fn func(string) bool) bool {
	f := fl.Field()
	return f.Kind() == reflect.String && fn(f.String())
}

func messageFor(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "is required"
	case TagUsername:
		return "must be 3-32 characters using a-z, A-Z, 0-9, _, . or -"
	case TagPassword:
		return "must be 8-128 characters and contain at least one letter and one digit"
	case TagInviteCode:
		return "must be exactly 8 characters using 0-9, a-z or A-Z"
	case TagActivationCode:
		return "must be exactly 16 characters using a-z, A-Z or 2-7"
	case "min":
		return "must be at least " + fe.Param()
	case "max":
		return "must be at most " + fe.Param()
	case "len":
		return "must be exactly " + fe.Param() + " characters"
	default:
		return "is invalid"
	}
}
