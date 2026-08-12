package config

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

//go:embed default_app.toml
var defaultAppTOML []byte

// App is the validated server configuration loaded from zephyr.toml.
type App struct {
	JWTSecret        string
	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	LoginRateLimit   float64 // requests per minute
	RegistrationMode string  // "open" or "invite"
	Storage          StorageConfig
}

// StorageConfig configures the local object storage backend.
type StorageConfig struct {
	BaseDir string
}

type appConfig struct {
	JWTSecret string `mapstructure:"jwt_secret"`
	Storage   struct {
		BaseDir string `mapstructure:"base_dir"`
	} `mapstructure:"storage"`
	Auth struct {
		AccessTokenTTL   string  `mapstructure:"access_token_ttl"`
		RefreshTokenTTL  string  `mapstructure:"refresh_token_ttl"`
		LoginRateLimit   float64 `mapstructure:"login_rate_limit"`
		RegistrationMode string  `mapstructure:"registration_mode"`
	} `mapstructure:"auth"`
}

// LoadApp reads the server configuration from path. If the file does not
// exist, a default is generated with a fresh random JWT secret; existing files
// are never overwritten.
func LoadApp(path string) (*App, error) {
	if err := ensureDefaultAppFile(path); err != nil {
		return nil, err
	}

	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("config: read app %s: %w", path, err)
	}

	var cfg appConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: parse app %s: %w", path, err)
	}
	return newApp(cfg)
}

func newApp(cfg appConfig) (*App, error) {
	if len(cfg.JWTSecret) < 32 {
		return nil, errors.New("config: jwt_secret must be at least 32 characters")
	}
	accessTTL, err := time.ParseDuration(cfg.Auth.AccessTokenTTL)
	if err != nil || accessTTL <= 0 {
		return nil, fmt.Errorf("config: invalid access_token_ttl %q", cfg.Auth.AccessTokenTTL)
	}
	refreshTTL, err := time.ParseDuration(cfg.Auth.RefreshTokenTTL)
	if err != nil || refreshTTL <= 0 {
		return nil, fmt.Errorf("config: invalid refresh_token_ttl %q", cfg.Auth.RefreshTokenTTL)
	}
	if cfg.Auth.LoginRateLimit <= 0 {
		return nil, errors.New("config: login_rate_limit must be positive")
	}
	mode := cfg.Auth.RegistrationMode
	if mode == "" {
		mode = "invite"
	}
	if mode != "open" && mode != "invite" {
		return nil, errors.New(`config: registration_mode must be "open" or "invite"`)
	}
	if cfg.Storage.BaseDir == "" {
		return nil, errors.New("config: storage.base_dir must not be empty")
	}
	return &App{
		JWTSecret:        cfg.JWTSecret,
		AccessTokenTTL:   accessTTL,
		RefreshTokenTTL:  refreshTTL,
		LoginRateLimit:   cfg.Auth.LoginRateLimit,
		RegistrationMode: mode,
		Storage:          StorageConfig{BaseDir: cfg.Storage.BaseDir},
	}, nil
}

func ensureDefaultAppFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("config: stat app %s: %w", path, err)
	}

	secret, err := randomHex(32)
	if err != nil {
		return fmt.Errorf("config: generate jwt secret: %w", err)
	}
	content := strings.Replace(string(defaultAppTOML), `jwt_secret = ""`, fmt.Sprintf("jwt_secret = %q", secret), 1)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("config: create config dir: %w", err)
	}
	// 0600 because the file contains a signing secret.
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("config: write default app %s: %w", path, err)
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
