// Package validation wires go-playground/validator into Echo for declarative
// request-shape checks. Rules that need a database lookup or cross-field
// semantics (role existence, expiry vs. now, invite availability) stay in the
// service layer; struct tags only describe shape.
package validation

import (
	"errors"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// Validator implements echo.Validator over go-playground/validator.
type Validator struct {
	v *validator.Validate
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

// Validate runs struct-tag validation. Failures come back as a FieldsError
// whose per-field messages the central api error handler folds into the
// envelope message.
func (v *Validator) Validate(i any) error {
	if err := v.v.Struct(i); err != nil {
		var fieldErrs validator.ValidationErrors
		if errors.As(err, &fieldErrs) {
			fields := make(map[string]string, len(fieldErrs))
			for _, fe := range fieldErrs {
				fields[fe.Field()] = messageFor(fe)
			}
			return &FieldsError{fields: fields}
		}
		return err
	}
	return nil
}
