package validation_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"zephyr.vox/server/ce/internal/validation"
)

type sampleRequest struct {
	Username string `json:"username" validate:"required,username"`
	Password string `json:"password" validate:"required,password"`
	Code     string `json:"code" validate:"omitempty,invite_code"`
}

func TestCustomTags(t *testing.T) {
	v := validation.New()
	tests := []struct {
		name  string
		field string
		value string
		want  bool
	}{
		{"username valid", "username", "alice_1", true},
		{"username dashes and dots", "username", "a.b-c_d", true},
		{"username too short", "username", "ab", false},
		{"username too long", "username", strings.Repeat("a", 33), false},
		{"username bad char", "username", "alice!", false},
		{"password valid", "password", "secret123", true},
		{"password letters only", "password", "secretword", false},
		{"password digits only", "password", "12345678", false},
		{"password too short", "password", "short1", false},
		{"password too long", "password", strings.Repeat("a", 128) + "1", false},
		{"invite code valid", "code", "AB12CD34", true},
		{"invite code lowercase", "code", "ab12cd34", true},
		{"invite code bad char", "code", "AB12CD3!", false},
		{"invite code short", "code", "ABC123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := sampleRequest{Username: "alice01", Password: "secret123", Code: "AB12CD34"}
			switch tt.field {
			case "username":
				req.Username = tt.value
			case "password":
				req.Password = tt.value
			case "code":
				req.Code = tt.value
			}
			err := v.Validate(&req)
			if (err == nil) != tt.want {
				t.Fatalf("Validate = %v, want valid=%v", err, tt.want)
			}
		})
	}
}

func TestActivationCodeTag(t *testing.T) {
	v := validation.New()
	type req struct {
		Code string `json:"code" validate:"required,activation_code"`
	}
	for name, code := range map[string]string{
		"valid":        "ABCDEFGHIJKLMNOP",
		"lowercase":    "abcdefghijklmnop",
		"zero char":    "ABCDEFGHIJKLMNO0",
		"short":        "ABCDEFGH",
		"invalid char": "ABCDEFGHIJKLMNO1",
	} {
		want := name == "valid" || name == "lowercase"
		err := v.Validate(&req{Code: code})
		if (err == nil) != want {
			t.Fatalf("%s: Validate = %v, want valid=%v", name, err, want)
		}
	}
}

func TestValidateReturnsFieldErrors(t *testing.T) {
	v := validation.New()
	err := v.Validate(&sampleRequest{Username: "x", Password: "secret", Code: "abc"})
	if err == nil {
		t.Fatal("want validation error")
	}
	var fe *validation.FieldsError
	if !errors.As(err, &fe) {
		t.Fatalf("error type = %T, want *validation.FieldsError", err)
	}
	if fe.StatusCode() != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", fe.StatusCode())
	}
	for _, field := range []string{"username", "password", "code"} {
		if fe.Fields()[field] == "" {
			t.Fatalf("fields[%q] missing: %v", field, fe.Fields())
		}
	}
}
