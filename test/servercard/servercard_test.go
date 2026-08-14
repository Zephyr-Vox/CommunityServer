package servercard_test

import (
	"strings"
	"testing"

	"zephyr.vox/server/ce/internal/servercard"
)

const testFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestNewPlainFormatsCanonicalURL(t *testing.T) {
	c, err := servercard.New("vox.example.com", 8745, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.String(); got != "zephyrvox://vox.example.com:8745?v=1" {
		t.Fatalf("String = %q", got)
	}
	if c.TLS() {
		t.Fatal("plain card must not report TLS")
	}
}

func TestNewPlainWithInvite(t *testing.T) {
	c, err := servercard.New("vox.example.com", 8745, "", "abc123", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.String(); got != "zephyrvox://vox.example.com:8745?v=1&invite=abc123" {
		t.Fatalf("String = %q", got)
	}
}

func TestNewTLSFormatsCanonicalURL(t *testing.T) {
	c, err := servercard.New("vox.example.com", 8745, testFP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "zephyrvoxs://vox.example.com:8745?v=1&fp=" + testFP
	if got := c.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	if !c.TLS() {
		t.Fatal("TLS card must report TLS")
	}
}

func TestNewTLSWithInvite(t *testing.T) {
	c, err := servercard.New("vox.example.com", 8745, testFP, "abc123", true)
	if err != nil {
		t.Fatal(err)
	}
	want := "zephyrvoxs://vox.example.com:8745?v=1&fp=" + testFP + "&invite=abc123"
	if got := c.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestNewNormalizesBracketedIPv6AndFingerprint(t *testing.T) {
	c, err := servercard.New("[::1]", 8745, strings.ToUpper(testFP), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "::1" {
		t.Fatalf("host = %q, want bare ::1", c.Host)
	}
	if c.Fingerprint != testFP {
		t.Fatalf("fingerprint = %q, want lowercase", c.Fingerprint)
	}
	want := "zephyrvoxs://[::1]:8745?v=1&fp=" + testFP
	if got := c.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestNewEscapesInvite(t *testing.T) {
	c, err := servercard.New("vox.example.com", 8745, "", "a/b c", false)
	if err != nil {
		t.Fatal(err)
	}
	want := "zephyrvox://vox.example.com:8745?v=1&invite=a%2Fb+c"
	if got := c.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestNewOmitsEmptyInvite(t *testing.T) {
	c, err := servercard.New("vox.example.com", 8745, testFP, "   ", true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Invite != "" {
		t.Fatalf("invite = %q, want empty after trim", c.Invite)
	}
	want := "zephyrvoxs://vox.example.com:8745?v=1&fp=" + testFP
	if got := c.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestNewRejectsInvalidCombinations(t *testing.T) {
	tests := []struct {
		name   string
		host   string
		port   int
		fp     string
		invite string
		tls    bool
	}{
		{"empty host", "", 8745, "", "", false},
		{"port zero", "vox.example.com", 0, "", "", false},
		{"port too large", "vox.example.com", 70000, "", "", false},
		{"tls without fp", "vox.example.com", 8745, "", "", true},
		{"plain with fp", "vox.example.com", 8745, testFP, "", false},
		{"host contains port", "vox.example.com:8745", 8745, "", "", false},
		{"malformed ipv6", "[::1", 8745, "", "", false},
		{"bad fp length", "vox.example.com", 8745, strings.Repeat("0", 63), "", true},
		{"bad fp chars", "vox.example.com", 8745, strings.Repeat("g", 64), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := servercard.New(tt.host, tt.port, tt.fp, tt.invite, tt.tls); err == nil {
				t.Fatal("New must reject this input")
			}
		})
	}
}
