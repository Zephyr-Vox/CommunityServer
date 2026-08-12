package validation

import "github.com/go-playground/validator/v10"

// messageFor translates one validation rule failure into a client-facing
// message. Messages are intentionally plain and stable so the frontend can
// show them verbatim under the offending field.
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
