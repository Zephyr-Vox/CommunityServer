package config

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	Server           ServerConfig
	Storage          StorageConfig
	Avatar           AvatarConfig
	Log              LogConfig
}

const (
	// TLSModeOff disables TLS entirely: the control plane is plaintext and no
	// certificate is generated or loaded.
	TLSModeOff = "off"
	// TLSModeRequired serves TLS only; plaintext requests never connect.
	TLSModeRequired = "required"

	// defaultTLSCertValidYears is the auto-generated certificate lifetime.
	// It is an availability default, not a security claim: renewal reuses the
	// same private key, so key lifetime is controlled by rotation policy.
	defaultTLSCertValidYears = 10
)

// ServerConfig configures the listeners. HTTP binds today; voice_port is
// reserved for the future voice channel and is not used by the server yet
// (the transport — KCP, WebRTC, ... — is an implementation detail).
type ServerConfig struct {
	Host              string   // listen host, e.g. "0.0.0.0"
	HTTPPort          int      // HTTP/REST listener port
	VoicePort         int      // future voice channel listener port
	DBPath            string   // SQLite database file path
	TLSMode           string   // "off" or "required"
	TLSCert           string   // PEM certificate path; empty + empty key = auto mode
	TLSKey            string   // PEM private key path; empty + empty cert = auto mode
	TLSCertPath       string   // auto-mode certificate store path
	TLSCertValidYears int      // auto-mode certificate validity in years
	TLSCertExtraSANs  []string // additional DNS names / IPs appended to defaults
}

// StorageConfig configures the local object storage backend.
type StorageConfig struct {
	BaseDir string
}

// AvatarConfig configures avatar uploads and transcoding. All fields are
// operational parameters the administrator tunes per deployment; there are
// no hidden constants in the image package.
type AvatarConfig struct {
	MaxUploadSize           int64 // request body limit in bytes; default 10 MiB
	MaxDimension            int   // source image max side in pixels; rejects decompression bombs
	TargetSize              int   // output avatar side in pixels (square)
	Quality                 int   // JPEG quality, 0-100
	MaxConcurrentTranscodes int   // concurrent decode/encode pipelines; default 2
}

// LogConfig configures the human-readable log pipeline. Path empty means
// console-only output (no file persistence).
type LogConfig struct {
	Level       slog.Level // minimum level: Debug/Info/Warn/Error
	Path        string     // log directory; live file is zephyr.log
	ArchiveKeep int        // -1 keep all archives, 0 no archives, N keep newest N
}

type appConfig struct {
	JWTSecret string `mapstructure:"jwt_secret"`
	Server    struct {
		Host              string   `mapstructure:"host"`
		HTTPPort          int      `mapstructure:"http_port"`
		VoicePort         int      `mapstructure:"voice_port"`
		DBPath            string   `mapstructure:"db_path"`
		TLSMode           string   `mapstructure:"tls_mode"`
		TLSCert           string   `mapstructure:"tls_cert"`
		TLSKey            string   `mapstructure:"tls_key"`
		TLSCertPath       string   `mapstructure:"tls_cert_path"`
		TLSCertValidYears *int     `mapstructure:"tls_cert_valid_years"`
		TLSCertExtraSANs  []string `mapstructure:"tls_cert_extra_sans"`
	} `mapstructure:"server"`
	Storage struct {
		BaseDir string `mapstructure:"base_dir"`
	} `mapstructure:"storage"`
	Avatar struct {
		MaxUploadSize           *int64 `mapstructure:"max_upload_size"`
		MaxDimension            *int   `mapstructure:"max_dimension"`
		TargetSize              *int   `mapstructure:"target_size"`
		Quality                 *int   `mapstructure:"quality"`
		MaxConcurrentTranscodes *int   `mapstructure:"max_concurrent_transcodes"`
	} `mapstructure:"avatar"`
	Auth struct {
		AccessTokenTTL   string  `mapstructure:"access_token_ttl"`
		RefreshTokenTTL  string  `mapstructure:"refresh_token_ttl"`
		LoginRateLimit   float64 `mapstructure:"login_rate_limit"`
		RegistrationMode string  `mapstructure:"registration_mode"`
	} `mapstructure:"auth"`
	Log struct {
		Level       string  `mapstructure:"level"`
		Path        *string `mapstructure:"path"`
		ArchiveKeep *int    `mapstructure:"archive_keep"`
	} `mapstructure:"log"`
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

// newApp validates parsed configuration and builds its runtime representation.
func newApp(cfg appConfig) (*App, error) {
	accessTTL, refreshTTL, err := validateApp(cfg)
	if err != nil {
		return nil, err
	}
	logLevel, logPath, logKeep, err := validateLog(cfg)
	if err != nil {
		return nil, err
	}
	avatar, err := validateAvatar(cfg)
	if err != nil {
		return nil, err
	}
	serverCfg, err := validateServerTLS(cfg)
	if err != nil {
		return nil, err
	}
	mode := cfg.Auth.RegistrationMode
	if mode == "" {
		mode = "invite"
	}
	return &App{
		JWTSecret:        cfg.JWTSecret,
		AccessTokenTTL:   accessTTL,
		RefreshTokenTTL:  refreshTTL,
		LoginRateLimit:   cfg.Auth.LoginRateLimit,
		RegistrationMode: mode,
		Server:           serverCfg,
		Storage:          StorageConfig{BaseDir: cfg.Storage.BaseDir},
		Avatar:           avatar,
		Log: LogConfig{
			Level:       logLevel,
			Path:        logPath,
			ArchiveKeep: logKeep,
		},
	}, nil
}

// validateServerTLS fills TLS defaults and validates the [server] TLS block.
// It is separate from validateApp so basic listener checks stay readable and
// the TLS defaults are applied in exactly one place.
func validateServerTLS(cfg appConfig) (ServerConfig, error) {
	s := ServerConfig{
		Host:      cfg.Server.Host,
		HTTPPort:  cfg.Server.HTTPPort,
		VoicePort: cfg.Server.VoicePort,
		DBPath:    cfg.Server.DBPath,
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Server.TLSMode))
	if mode == "" {
		// Secure default: an existing hand-written config without tls_mode
		// must not silently downgrade to plaintext.
		mode = TLSModeRequired
	}
	if mode != TLSModeOff && mode != TLSModeRequired {
		return ServerConfig{}, errors.New(`config: server.tls_mode must be "off" or "required"`)
	}
	s.TLSMode = mode
	s.TLSCert = cfg.Server.TLSCert
	s.TLSKey = cfg.Server.TLSKey
	if mode == TLSModeOff {
		if s.TLSCert != "" || s.TLSKey != "" {
			return ServerConfig{}, errors.New("config: server.tls_cert and server.tls_key must be empty when tls_mode = off")
		}
	} else if (s.TLSCert == "") != (s.TLSKey == "") {
		return ServerConfig{}, errors.New("config: server.tls_cert and server.tls_key must both be set or both be empty")
	}

	path := strings.TrimSpace(cfg.Server.TLSCertPath)
	if path == "" {
		path = filepath.Join(filepath.Dir(s.DBPath), "tls")
	}
	s.TLSCertPath = path

	years := defaultTLSCertValidYears
	if cfg.Server.TLSCertValidYears != nil {
		years = *cfg.Server.TLSCertValidYears
	}
	if years < 1 || years > 100 {
		return ServerConfig{}, errors.New("config: server.tls_cert_valid_years must be 1-100")
	}
	s.TLSCertValidYears = years

	sans := make([]string, 0, len(cfg.Server.TLSCertExtraSANs))
	for _, san := range cfg.Server.TLSCertExtraSANs {
		san = strings.ToLower(strings.TrimSpace(san))
		if san == "" {
			continue
		}
		if net.ParseIP(san) != nil {
			sans = append(sans, san)
			continue
		}
		if !validDNSName(san) {
			return ServerConfig{}, errors.New("config: server.tls_cert_extra_sans contains an invalid DNS name")
		}
		sans = append(sans, san)
	}
	s.TLSCertExtraSANs = sans
	return s, nil
}

// validDNSName reports whether name is a valid DNS name for a certificate
// SAN: ASCII letters/digits/hyphens per label, labels 1-63 chars, total at
// most 253 chars, and at most one leftmost "*." wildcard. IP literals are
// handled by net.ParseIP before this is called.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
		if name == "" {
			return false
		}
	} else if strings.Contains(name, "*") {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !validDNSLabel(label) {
			return false
		}
	}
	return true
}

// validDNSLabel reports whether label is a valid ASCII DNS label.
func validDNSLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

// validateApp checks every config value and returns the parsed token TTLs.
// registration_mode is allowed to be empty here; newApp fills the default.
func validateApp(cfg appConfig) (accessTTL, refreshTTL time.Duration, err error) {
	if len(cfg.JWTSecret) < 32 {
		return 0, 0, errors.New("config: jwt_secret must be at least 32 characters")
	}
	accessTTL, err = time.ParseDuration(cfg.Auth.AccessTokenTTL)
	if err != nil || accessTTL <= 0 {
		return 0, 0, fmt.Errorf("config: invalid access_token_ttl %q", cfg.Auth.AccessTokenTTL)
	}
	refreshTTL, err = time.ParseDuration(cfg.Auth.RefreshTokenTTL)
	if err != nil || refreshTTL <= 0 {
		return 0, 0, fmt.Errorf("config: invalid refresh_token_ttl %q", cfg.Auth.RefreshTokenTTL)
	}
	if cfg.Auth.LoginRateLimit <= 0 {
		return 0, 0, errors.New("config: login_rate_limit must be positive")
	}
	mode := cfg.Auth.RegistrationMode
	if mode != "" && mode != "open" && mode != "invite" {
		return 0, 0, errors.New(`config: registration_mode must be "open" or "invite"`)
	}
	if cfg.Server.Host == "" {
		return 0, 0, errors.New("config: server.host must not be empty")
	}
	if cfg.Server.HTTPPort < 1 || cfg.Server.HTTPPort > 65535 {
		return 0, 0, errors.New("config: server.http_port must be 1-65535")
	}
	if cfg.Server.VoicePort < 1 || cfg.Server.VoicePort > 65535 {
		return 0, 0, errors.New("config: server.voice_port must be 1-65535")
	}
	if cfg.Server.DBPath == "" {
		return 0, 0, errors.New("config: server.db_path must not be empty")
	}
	if cfg.Storage.BaseDir == "" {
		return 0, 0, errors.New("config: storage.base_dir must not be empty")
	}
	return accessTTL, refreshTTL, nil
}

// validateAvatar parses the [avatar] section. Pointers distinguish "unset"
// (use the default) from an explicit invalid value: an explicit 0 or negative
// number is an error, an absent key keeps the default.
func validateAvatar(cfg appConfig) (AvatarConfig, error) {
	a := AvatarConfig{
		MaxUploadSize:           10 << 20, // 10 MiB
		MaxDimension:            2048,
		TargetSize:              256,
		Quality:                 85,
		MaxConcurrentTranscodes: 2,
	}
	if cfg.Avatar.MaxUploadSize != nil {
		if *cfg.Avatar.MaxUploadSize <= 0 {
			return AvatarConfig{}, errors.New("config: avatar.max_upload_size must be positive")
		}
		a.MaxUploadSize = *cfg.Avatar.MaxUploadSize
	}
	if cfg.Avatar.MaxDimension != nil {
		if *cfg.Avatar.MaxDimension <= 0 {
			return AvatarConfig{}, errors.New("config: avatar.max_dimension must be positive")
		}
		a.MaxDimension = *cfg.Avatar.MaxDimension
	}
	if cfg.Avatar.TargetSize != nil {
		if *cfg.Avatar.TargetSize <= 0 {
			return AvatarConfig{}, errors.New("config: avatar.target_size must be positive")
		}
		a.TargetSize = *cfg.Avatar.TargetSize
	}
	if cfg.Avatar.Quality != nil {
		if *cfg.Avatar.Quality < 0 || *cfg.Avatar.Quality > 100 {
			return AvatarConfig{}, errors.New("config: avatar.quality must be 0-100")
		}
		a.Quality = *cfg.Avatar.Quality
	}
	if cfg.Avatar.MaxConcurrentTranscodes != nil {
		if *cfg.Avatar.MaxConcurrentTranscodes < 1 || *cfg.Avatar.MaxConcurrentTranscodes > 32 {
			return AvatarConfig{}, errors.New("config: avatar.max_concurrent_transcodes must be 1-32")
		}
		a.MaxConcurrentTranscodes = *cfg.Avatar.MaxConcurrentTranscodes
	}
	return a, nil
}

// validateLog parses the [log] section, applying defaults when keys are
// absent. Pointers distinguish "unset" (default) from an explicit 0: an
// empty path means console-only and archive_keep = 0 means no archives.
func validateLog(cfg appConfig) (slog.Level, string, int, error) {
	levelName := cfg.Log.Level
	if levelName == "" {
		levelName = "info"
	}
	var level slog.Level
	switch levelName {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return 0, "", 0, fmt.Errorf(`config: log.level must be "debug", "info", "warn" or "error"`)
	}

	path := "./data/logs"
	if cfg.Log.Path != nil {
		path = *cfg.Log.Path
	}
	keep := 7
	if cfg.Log.ArchiveKeep != nil {
		keep = *cfg.Log.ArchiveKeep
	}
	if keep < -1 {
		return 0, "", 0, errors.New("config: log.archive_keep must be -1, 0, or a positive integer")
	}
	return level, path, keep, nil
}

// ensureDefaultAppFile creates path with a fresh secret when it is absent.
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

// randomHex returns n cryptographically random bytes encoded as hexadecimal.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
